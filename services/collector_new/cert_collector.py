"""
cert_collector.py – Fetch and parse CT log entries.

Supports both RFC 6962 (non-tiled) and Static CT API (tiled) logs.

Architecture
────────────

One asyncio Task per log drives its slices.  All tasks share a single
bounded asyncio.Queue and a fixed-size pool of parser workers.

  Fetcher task (one per log)
    ├─ non-tiled → GET /ct/v1/get-entries?start=N&end=M  (JSON)
    └─ tiled     → GET <monitoring_url>/tile/data/<N>[.p/<count>]  (binary)
         │
         ▼  await queue.put(batch)   ← blocks here when queue is full
  asyncio.Queue(maxsize=QUEUE_MAXSIZE)   ← BACKPRESSURE point
         │
         ▼  await queue.get()
  Parser workers × PARSER_WORKERS
    └─ asyncio.to_thread(parse_entries_bulk | parse_tile_data)
         └─ _print_certs()
         └─ write_queue.put(parsed)  ← blocks when queue is full
  asyncio.Queue(maxsize=WRITE_QUEUE_MAXSIZE)
         └─ _cert_writer_worker()
              └─ CertWriter.flush() → INSERT INTO ct_certs

Backpressure: if parsers are slower than fetchers, queue.put() blocks the
fetcher – no OOM, no crash.  Fetchers never build an unbounded in-memory
buffer.
"""

import asyncio
import math
import time

import aiohttp

from .models     import CTLog, CTLogSlice
from .config     import get_logger, BATCH_SIZE, USER_AGENT
from .database   import SliceWriter, CertWriter
from .cert_parser import parse_entries_bulk, parse_tile_data

logger = get_logger("CertCollector")

# ─────────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────────

QUEUE_MAXSIZE    = 64    # max pending parse batches before fetcher blocks
PARSER_WORKERS   = 4     # parallel parser coroutines (each uses to_thread)
HTTP_TIMEOUT     = aiohttp.ClientTimeout(total=30, connect=10)
FETCH_CONCURRENCY = 4    # parallel in-flight HTTP requests per log
IDLE_SLEEP       = 5.0   # seconds to wait when fully caught up
FLUSH_EVERY      = 50    # SliceWriter: DB flush interval (batches)

# How many parsed certs to buffer before flushing to ct_certs.
CERT_FLUSH_EVERY  = 500

# Max pending cert-write batches before the parser worker blocks.
# Keeps memory bounded when the DB write is slower than parsing.
WRITE_QUEUE_MAXSIZE = 32

# Tiled logs: entries per full data tile (fixed by the spec)
TILE_WIDTH       = 256


# ─────────────────────────────────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────────────────────────────────

async def collect_all_logs_dynamic(db, poll_interval: int = 30):
    """
    Manage one collector Task per active log.  Refreshes the log list every
    poll_interval seconds.  Shares one parse queue + worker pool globally.
    """
    log_tasks: dict[str, asyncio.Task] = {}

    # One shared parse queue and one shared write queue for ALL logs.
    # parse_queue: fetchers → parser workers (CPU-bound parsing)
    # write_queue: parser workers → cert writer worker (DB inserts)
    # Both are bounded so slow consumers apply backpressure to fast producers.
    parse_queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    write_queue: asyncio.Queue = asyncio.Queue(maxsize=WRITE_QUEUE_MAXSIZE)
    for _ in range(PARSER_WORKERS):
        asyncio.create_task(_parser_worker(parse_queue, write_queue))
    asyncio.create_task(_cert_writer_worker(write_queue, db))

    while True:
        def _get_logs():
            with db.Session() as session:
                return session.query(CTLog).all()

        logs    = await asyncio.to_thread(_get_logs)
        log_ids = {log.id for log in logs}

        for log in logs:
            if log.id not in log_tasks or log_tasks[log.id].done():
                log_tasks[log.id] = asyncio.create_task(
                    collect_log_forever(log, db=db, parse_queue=parse_queue),
                    name=f"collector-{log.id}",
                )

        for log_id in list(log_tasks):
            if log_id not in log_ids:
                log_tasks[log_id].cancel()
                del log_tasks[log_id]

        await asyncio.sleep(poll_interval)


async def collect_log_forever(
    log: CTLog,
    db=None,
    parse_queue: "asyncio.Queue | None" = None,
):
    """Drive all pending slices of one log, then poll for new work."""
    writer = SliceWriter(db, flush_every=FLUSH_EVERY) if db is not None else None
    stats  = {"fetched": 0, "start_time": time.monotonic()}

    connector = aiohttp.TCPConnector(limit=FETCH_CONCURRENCY, ttl_dns_cache=300)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as http:
        while True:
            made_progress = False
            slices = await db.get_pending_slices(log.id) if db is not None else []

            for slc in slices:
                if log.is_tiled:
                    await _drain_slice_tiled(
                        log, slc, http,
                        db=db, writer=writer,
                        parse_queue=parse_queue, stats=stats,
                    )
                else:
                    await _drain_slice_normal(
                        log, slc, http,
                        db=db, writer=writer,
                        parse_queue=parse_queue, stats=stats,
                    )
                made_progress = True

            if writer is not None:
                await writer.flush()

            if not made_progress:
                await asyncio.sleep(IDLE_SLEEP)


# ─────────────────────────────────────────────────────────────────────
# RFC 6962 (non-tiled) slice drainer
# ─────────────────────────────────────────────────────────────────────

async def _drain_slice_normal(
    log: CTLog,
    slc: CTLogSlice,
    http: aiohttp.ClientSession,
    db=None,
    writer: "SliceWriter | None" = None,
    parse_queue: "asyncio.Queue | None" = None,
    stats: "dict | None" = None,
):
    """
    Fetch all remaining entries in *slc* via GET /ct/v1/get-entries.

    Pipelines up to FETCH_CONCURRENCY requests at a time.
    Blocks on parse_queue.put() when the queue is full (backpressure).
    """
    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
    current   = slc.current_index

    while current < slc.slice_end:
        batch_end = min(current + BATCH_SIZE, slc.slice_end)
        await semaphore.acquire()

        async def _fetch_and_enqueue(start: int, end: int):
            try:
                entries = await _fetch_rfc6962_entries(http, log.url, start, end - 1)
                if entries:
                    if parse_queue is not None:
                        # ← backpressure: blocks when queue is full
                        await parse_queue.put(("rfc6962", entries, start, log.url))
                    _update_stats(stats, len(entries))
                    await _persist_progress(
                        writer, db, log, slc, end
                    )
                    slc.current_index = end
                    if end >= slc.slice_end:
                        slc.status = "done"
            except Exception as exc:
                logger.error(f"[{log.url}] normal fetch {start}-{end}: {exc}")
            finally:
                semaphore.release()

        asyncio.create_task(_fetch_and_enqueue(current, batch_end))
        current = batch_end

    # Drain semaphore – wait for all in-flight tasks
    for _ in range(FETCH_CONCURRENCY):
        await semaphore.acquire()


# ─────────────────────────────────────────────────────────────────────
# Static CT / tiled slice drainer
# ─────────────────────────────────────────────────────────────────────

async def _drain_slice_tiled(
    log: CTLog,
    slc: CTLogSlice,
    http: aiohttp.ClientSession,
    db=None,
    writer: "SliceWriter | None" = None,
    parse_queue: "asyncio.Queue | None" = None,
    stats: "dict | None" = None,
):
    """
    Fetch remaining entries in *slc* via Static CT data tiles.

    Tile index N covers entries [N*256, N*256+256).
    A partial tile at the end covers fewer entries.

    URL format:
      full tile:    <monitoring_url>/tile/data/<N>
      partial tile: <monitoring_url>/tile/data/<N>.p/<count>

    We determine whether a tile is full or partial by comparing the
    tile's entry range against slc.slice_end (which equals log_length
    for the last slice).
    """
    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
    current   = slc.current_index  # first un-fetched entry index

    # Iterate tile by tile
    while current < slc.slice_end:
        tile_idx        = current // TILE_WIDTH
        tile_start      = tile_idx * TILE_WIDTH
        tile_full_end   = tile_start + TILE_WIDTH
        tile_actual_end = min(tile_full_end, slc.slice_end)

        # Skip entries already collected within this tile
        if tile_start < current:
            # We're mid-tile on resume – re-fetch the whole tile but only
            # advance progress past what we already have.
            # Simpler than trying to seek within a binary blob.
            pass

        count_in_tile = tile_actual_end - tile_start
        is_partial    = count_in_tile < TILE_WIDTH

        await semaphore.acquire()

        async def _fetch_tile_and_enqueue(
            t_idx: int,
            t_start: int,
            t_end: int,
            partial_count: int,
            is_part: bool,
        ):
            try:
                tile_bytes = await _fetch_tiled_data_tile(
                    http, log.monitoring_url, t_idx,
                    partial_count if is_part else None,
                )
                if tile_bytes:
                    if parse_queue is not None:
                        await parse_queue.put(("tiled", tile_bytes, t_idx, log.monitoring_url))
                    _update_stats(stats, partial_count)
                    await _persist_progress(
                        writer, db, log, slc, t_end
                    )
                    slc.current_index = t_end
                    if t_end >= slc.slice_end:
                        slc.status = "done"
            except Exception as exc:
                logger.error(
                    f"[{log.monitoring_url}] tile fetch {t_idx}: {exc}"
                )
            finally:
                semaphore.release()

        asyncio.create_task(_fetch_tile_and_enqueue(
            tile_idx, tile_start, tile_actual_end,
            count_in_tile, is_partial,
        ))
        current = tile_actual_end

    for _ in range(FETCH_CONCURRENCY):
        await semaphore.acquire()


# ─────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────

async def _fetch_rfc6962_entries(
    http: aiohttp.ClientSession,
    log_url: str,
    start: int,
    end: int,   # inclusive
) -> "list[dict] | None":
    """GET /ct/v1/get-entries?start=N&end=M  →  list of entry dicts."""
    url = f"{log_url.rstrip('/')}/ct/v1/get-entries"
    try:
        async with http.get(url, params={"start": start, "end": end}) as resp:
            if resp.status != 200:
                logger.warning(f"[{log_url}] get-entries {start}-{end} → HTTP {resp.status}")
                return None
            data = await resp.json(content_type=None)
            return data.get("entries", [])
    except asyncio.TimeoutError:
        logger.warning(f"[{log_url}] get-entries {start}-{end} → timeout")
        return None
    except Exception as exc:
        logger.warning(f"[{log_url}] get-entries {start}-{end} → {exc}")
        return None


async def _fetch_tiled_data_tile(
    http: aiohttp.ClientSession,
    monitoring_url: str,
    tile_index: int,
    partial_count: "int | None" = None,
) -> "bytes | None":
    """
    Fetch one data tile from a Static CT log.

    tile_index     – 0-based tile number N
    partial_count  – if not None, fetch the partial tile with this many entries

    URL structure (c2sp.org/static-ct-api):
      Full tile:    <monitoring_url>/tile/data/<N>
      Partial tile: <monitoring_url>/tile/data/<N>.p/<count>

    The <N> component is split into 3-digit path segments for large indices:
      N=0        → "000"
      N=1000     → "003/976"  (split as "NNN/NNN")
      N=1000000  → "003/900/000"
    """
    path = _tile_path(tile_index)
    if partial_count is not None:
        url = f"{monitoring_url.rstrip('/')}/tile/data/{path}.p/{partial_count}"
    else:
        url = f"{monitoring_url.rstrip('/')}/tile/data/{path}"

    try:
        async with http.get(url) as resp:
            if resp.status == 404 and partial_count is None:
                # May be a partial tile that hasn't been promoted to full yet
                logger.debug(f"[{monitoring_url}] tile {tile_index} → 404, skipping")
                return None
            if resp.status != 200:
                logger.warning(
                    f"[{monitoring_url}] tile {tile_index} → HTTP {resp.status}"
                )
                return None
            return await resp.read()
    except asyncio.TimeoutError:
        logger.warning(f"[{monitoring_url}] tile {tile_index} → timeout")
        return None
    except Exception as exc:
        logger.warning(f"[{monitoring_url}] tile {tile_index} → {exc}")
        return None


def _tile_path(n: int) -> str:
    """
    Convert tile index N to the 3-digit-segment URL path.

    The Static CT spec (c2sp.org/tlog-tiles) encodes tile indices as
    a sequence of 3-digit decimal path components where EVERY segment
    (including the leading one) is zero-padded to exactly 3 digits:
      0        → "000"
      1        → "001"
      999      → "999"
      1000     → "001/000"
      999999   → "999/999"
      1000000  → "001/000/000"
    """
    digits = str(n)
    pad    = (-len(digits)) % 3   # leading zeros to reach a multiple of 3
    digits = "0" * pad + digits
    parts  = [digits[i:i+3] for i in range(0, len(digits), 3)]
    return "/".join(parts)


# ─────────────────────────────────────────────────────────────────────
# Progress persistence helper
# ─────────────────────────────────────────────────────────────────────

async def _persist_progress(
    writer: "SliceWriter | None",
    db,
    log: CTLog,
    slc: CTLogSlice,
    new_index: int,
) -> None:
    if writer is not None:
        writer.record(
            log_id=log.id,
            slice_start=slc.slice_start,
            current_index=new_index,
            slice_end=slc.slice_end,
        )
        await writer.flush_if_due()
    elif db is not None:
        await db.update_slice(
            log_id=log.id,
            slice_start=slc.slice_start,
            slice_end=slc.slice_end,
            current_index=new_index,
        )


def _update_stats(stats: "dict | None", count: int) -> None:
    if stats is None:
        return
    stats["fetched"] += count
    elapsed = time.monotonic() - stats["start_time"]
    if elapsed > 0:
        per_sec = stats["fetched"] / elapsed
        logger.debug(f"fetch rate: {per_sec:.0f}/s  ({stats['fetched']} total)")


# ─────────────────────────────────────────────────────────────────────
# Parser worker
# ─────────────────────────────────────────────────────────────────────

async def _parser_worker(parse_queue: asyncio.Queue, write_queue: asyncio.Queue):
    """
    Drain the parse queue.  Each item is a tuple:
      ("rfc6962", entries_list, start_index, log_url)
      ("tiled",   tile_bytes,   tile_index,  monitoring_url)

    After parsing, pushes (log_url, parsed_list) onto write_queue.
    If write_queue is full, blocks here – backpressure from slow DB writes
    flows back through the parser and then to the fetcher.
    """
    while True:
        item = await parse_queue.get()
        try:
            kind = item[0]
            if kind == "rfc6962":
                _, entries, start_index, log_url = item
                parsed = await asyncio.to_thread(
                    parse_entries_bulk, entries, start_index
                )
            elif kind == "tiled":
                _, tile_bytes, tile_index, log_url = item
                parsed = await asyncio.to_thread(
                    parse_tile_data, tile_bytes, tile_index
                )
            else:
                logger.error(f"Unknown queue item kind: {kind}")
                parsed = []

            _print_certs(parsed, log_url)

            if parsed:
                # ← backpressure: blocks when write_queue is full
                await write_queue.put((log_url, parsed))
        except Exception as exc:
            logger.error(f"Parser worker error: {exc}")
        finally:
            parse_queue.task_done()


# ─────────────────────────────────────────────────────────────────────
# Cert writer worker
# ─────────────────────────────────────────────────────────────────────

async def _cert_writer_worker(write_queue: asyncio.Queue, db) -> None:
    """
    Single worker that drains write_queue and persists certs to ct_certs.

    A single writer (not a pool) is intentional: ClickHouse bulk INSERTs
    are most efficient when batched, and a pool would just fragment batches
    across multiple concurrent connections for no benefit.

    CertWriter accumulates records in memory and issues one INSERT per
    CERT_FLUSH_EVERY certs (or when the queue drains between bursts).
    """
    if db is None:
        # No database – drain the queue silently
        while True:
            await write_queue.get()
            write_queue.task_done()
        return

    cert_writer = CertWriter(db, flush_every=CERT_FLUSH_EVERY)

    while True:
        log_url, certs = await write_queue.get()
        try:
            for cert in certs:
                cert_writer.record(cert, log_id=log_url)
            await cert_writer.flush_if_due()
        except Exception as exc:
            logger.error(f"Cert writer worker error: {exc}")
        finally:
            write_queue.task_done()


# ─────────────────────────────────────────────────────────────────────
# Printer
# ─────────────────────────────────────────────────────────────────────

def _print_certs(certs: "list[dict]", log_url: str) -> None:
    for cert in certs:
        dns = ", ".join(cert["dns_names"]) if cert["dns_names"] else "(none)"
        print(
            f"[{cert['index']:>10}] {cert['ct_entry_type']:<14}"
            f"  sha256={cert['fingerprint_sha256'][:16]}…"
            f"  dns={dns}"
            f"  issuer={cert['issuer'][:60]}"
            f"  valid={cert['not_before'][:10]} → {cert['not_after'][:10]}"
        )