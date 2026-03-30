import asyncio

import time as _time

import aiohttp

from services.shared.models import CTLog, CTLogSlice
from .config import BATCH_SIZE, USER_AGENT
from services.shared.logger import get_logger
from .database import SliceWriter, CertWriter
from .cert_parser import parse_entries_bulk, parse_tile_data
from . import metrics


logger = get_logger("CertCollector")

# ─────────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────────

# ── Tuned for an 8-core VM running 20–50 logs ────────────────────────
#
# Bottleneck analysis (8 cores, p95 parse latency >1s, ~47 active logs):
#
#   The parse step is CPU-bound (cryptography X.509 DER parsing).
#   asyncio.to_thread uses ThreadPoolExecutor — each worker gets a real
#   OS thread and the GIL is released during C-level crypto work, so
#   parallelism is genuine on multi-core hardware.
#
#   Rule of thumb: PARSER_WORKERS = total_cores - 2
#     • Leave 1 core for the asyncio event loop + HTTP I/O
#     • Leave 1 core for ClickHouse writes + OS overhead
#     • All remaining cores can parse in parallel
#
#   FETCH_CONCURRENCY = 2 per log: with 47 logs that's ~94 concurrent
#   HTTP requests, which is plenty without hammering CT servers.
#
#   QUEUE_MAXSIZE = PARSER_WORKERS * 2 so the queue never grows more
#   than two full batches ahead of the parsers — keeps memory bounded
#   and backpressure responsive.

QUEUE_MAXSIZE = 12  # PARSER_WORKERS x 2 — bounded backpressure
PARSER_WORKERS = 6  # 8 cores - 2 (event loop + DB writer)
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
FETCH_CONCURRENCY = 2  # 2 in-flight per log; 47 logs x 2 = ~94 concurrent
IDLE_SLEEP = 5.0  # seconds to wait when fully caught up
FLUSH_EVERY = 50  # SliceWriter: DB flush interval (batches)
CERT_FLUSH_EVERY = 500  # CertWriter: rows before flushing to ct_certs
WRITE_QUEUE_MAXSIZE = 12  # matches parse queue size
TILE_WIDTH = 256  # tiled logs: entries per full data tile (spec-fixed)


# ─────────────────────────────────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────────────────────────────────

async def collect_all_logs_dynamic(db, poll_interval: int = 30):
    log_tasks: dict[str, asyncio.Task] = {}

    parse_queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    write_queue: asyncio.Queue = asyncio.Queue(maxsize=WRITE_QUEUE_MAXSIZE)

    metrics.active_parser_workers.set(PARSER_WORKERS)
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
                    collect_log_forever(
                        log, db=db, parse_queue=parse_queue,
                    ),
                    name=f"collector-{log.id}",
                )

        for log_id in list(log_tasks):
            if log_id not in log_ids:
                log_tasks[log_id].cancel()
                del log_tasks[log_id]

        # Update live gauges every cycle
        metrics.parse_queue_depth.set(parse_queue.qsize())
        metrics.write_queue_depth.set(write_queue.qsize())
        metrics.active_collector_tasks.set(
            sum(1 for t in log_tasks.values() if not t.done())
        )

        await asyncio.sleep(poll_interval)


async def collect_log_forever(
    log: CTLog,
    db=None,
    parse_queue: "asyncio.Queue | None" = None
):
    """Drive all pending slices of one log, then poll for new work."""
    writer = SliceWriter(db, flush_every=FLUSH_EVERY) if db is not None else None
    stats  = {"fetched": 0, "start_time": _time.monotonic()}

    log_url_label = log.monitoring_url if log.is_tiled else log.url

    connector = aiohttp.TCPConnector(limit=FETCH_CONCURRENCY, ttl_dns_cache=300)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as http:
        while True:
            made_progress = False

            t0 = _time.monotonic()
            try:
                slices = await db.get_pending_slices(log.id) if db is not None else []
            except Exception as exc:
                logger.error(f"[{log_url_label}] get_pending_slices failed: {exc}")
                metrics.db_errors_total.labels(operation="get_pending_slices").inc()
                slices = []
            metrics.db_get_slices_duration_seconds.observe(_time.monotonic() - t0)

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
    """
    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
    current   = slc.current_index

    while current < slc.slice_end:
        batch_end = min(current + BATCH_SIZE, slc.slice_end)
        await semaphore.acquire()

        async def _fetch_and_enqueue(start: int, end: int):
            t0 = _time.monotonic()
            try:
                metrics.fetch_requests_total.labels(
                    log_url=log.url, fetch_type="rfc6962"
                ).inc()
                entries, n_bytes = await _fetch_rfc6962_entries(
                    http, log.url, start, end - 1
                )
                elapsed = _time.monotonic() - t0
                metrics.fetch_duration_seconds.labels(
                    log_url=log.url, fetch_type="rfc6962"
                ).observe(elapsed)

                if entries:
                    metrics.fetch_success_total.labels(
                        log_url=log.url, fetch_type="rfc6962"
                    ).inc()
                    metrics.entries_fetched_total.labels(log_url=log.url).inc(len(entries))
                    if n_bytes:
                        metrics.fetch_bytes_total.labels(
                            log_url=log.url, fetch_type="rfc6962"
                        ).inc(n_bytes)
                    if parse_queue is not None:
                        await parse_queue.put(("rfc6962", entries, start, log.url))
                    _update_stats(stats, len(entries))
                    await _persist_progress(writer, db, log, slc, end)
                    slc.current_index = end
                    metrics.log_progress_index.labels(log_url=log.url).set(end)
                    if end >= slc.slice_end:
                        slc.status = "done"
            except Exception as exc:
                logger.error(f"[{log.url}] normal fetch {start}-{end}: {exc}")
                metrics.fetch_errors_total.labels(
                    log_url=log.url, fetch_type="rfc6962", status_code="error"
                ).inc()
            finally:
                semaphore.release()

        asyncio.create_task(_fetch_and_enqueue(current, batch_end))
        current = batch_end

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
    Tile N covers entries [N*256, N*256+256).
    """
    semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
    current   = slc.current_index

    while current < slc.slice_end:
        tile_idx        = current // TILE_WIDTH
        tile_start      = tile_idx * TILE_WIDTH
        tile_full_end   = tile_start + TILE_WIDTH
        tile_actual_end = min(tile_full_end, slc.slice_end)
        count_in_tile   = tile_actual_end - tile_start
        is_partial      = count_in_tile < TILE_WIDTH


        # Skip partial tiles: only fetch full tiles
        if not is_partial:
            await semaphore.acquire()

            async def _fetch_tile_and_enqueue(
                t_idx: int,
                t_start: int,
                t_end: int,
                partial_count: int,
                is_part: bool,
            ):
                fetch_type = "tiled_full"
                t0 = _time.monotonic()
                try:
                    metrics.fetch_requests_total.labels(
                        log_url=log.monitoring_url, fetch_type=fetch_type
                    ).inc()
                    tile_bytes = await _fetch_tiled_data_tile(
                        http, log.monitoring_url, t_idx, None
                    )
                    elapsed = _time.monotonic() - t0
                    metrics.fetch_duration_seconds.labels(
                        log_url=log.monitoring_url, fetch_type=fetch_type
                    ).observe(elapsed)

                    if tile_bytes:
                        metrics.fetch_success_total.labels(
                            log_url=log.monitoring_url, fetch_type=fetch_type
                        ).inc()
                        metrics.entries_fetched_total.labels(
                            log_url=log.monitoring_url
                        ).inc(partial_count)
                        metrics.fetch_bytes_total.labels(
                            log_url=log.monitoring_url, fetch_type=fetch_type
                        ).inc(len(tile_bytes))
                        if parse_queue is not None:
                            await parse_queue.put(
                                ("tiled", tile_bytes, t_idx, log.monitoring_url)
                            )
                        _update_stats(stats, partial_count)
                        await _persist_progress(writer, db, log, slc, t_end)
                        slc.current_index = t_end
                        metrics.log_progress_index.labels(
                            log_url=log.monitoring_url
                        ).set(t_end)
                        if t_end >= slc.slice_end:
                            slc.status = "done"
                    else:
                        metrics.fetch_errors_total.labels(
                            log_url=log.monitoring_url,
                            fetch_type=fetch_type,
                            status_code="empty_or_skipped",
                        ).inc()
                except Exception as exc:
                    logger.error(f"[{log.monitoring_url}] tile fetch {t_idx}: {exc}")
                    metrics.fetch_errors_total.labels(
                        log_url=log.monitoring_url,
                        fetch_type=fetch_type,
                        status_code="error",
                    ).inc()
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
) -> "tuple[list[dict] | None, int]":
    """
    GET /ct/v1/get-entries?start=N&end=M
    Returns (entries_list_or_None, response_bytes).
    Records HTTP error metrics itself so callers don't double-count.
    """
    url = f"{log_url.rstrip('/')}/ct/v1/get-entries"
    try:
        async with http.get(url, params={"start": start, "end": end}) as resp:
            raw = await resp.read()
            if resp.status != 200:
                logger.warning(
                    f"[{log_url}] get-entries {start}-{end} → HTTP {resp.status}"
                )
                metrics.fetch_errors_total.labels(
                    log_url=log_url, fetch_type="rfc6962",
                    status_code=str(resp.status),
                ).inc()
                return None, 0
            import json
            data = json.loads(raw)
            return data.get("entries", []), len(raw)
    except asyncio.TimeoutError:
        logger.warning(f"[{log_url}] get-entries {start}-{end} → timeout")
        metrics.fetch_errors_total.labels(
            log_url=log_url, fetch_type="rfc6962", status_code="timeout"
        ).inc()
        return None, 0
    except Exception as exc:
        logger.warning(f"[{log_url}] get-entries {start}-{end} → {exc}")
        metrics.fetch_errors_total.labels(
            log_url=log_url, fetch_type="rfc6962", status_code="error"
        ).inc()
        return None, 0


async def _fetch_tiled_data_tile(
    http: aiohttp.ClientSession,
    monitoring_url: str,
    tile_index: int,
    partial_count: "int | None" = None,
) -> "bytes | None":
    """
    Fetch one data tile from a Static CT log.
    Full tile:    <monitoring_url>/tile/data/<path>
    Partial tile: <monitoring_url>/tile/data/<path>.p/<count>
    """
    path = _tile_path(tile_index)
    fetch_type = "tiled_partial" if partial_count is not None else "tiled_full"
    if partial_count is not None:
        url = f"{monitoring_url.rstrip('/')}/tile/data/{path}.p/{partial_count}"
    else:
        url = f"{monitoring_url.rstrip('/')}/tile/data/{path}"

    try:
        async with http.get(url) as resp:
            if resp.status == 404 and partial_count is None:
                logger.debug(f"[{monitoring_url}] tile {tile_index} → 404, skipping")
                return None
            if resp.status == 403 and partial_count is not None:
                # Sycamore returns 403 on the inaccessible partial tip tile – expected.
                logger.debug(
                    f"[{monitoring_url}] partial tile {tile_index}.p/{partial_count}"
                    f" → 403 (inaccessible), skipping"
                )
                return None
            if resp.status != 200:
                logger.warning(
                    f"[{monitoring_url}] tile {tile_index} → HTTP {resp.status} ({url})"
                )
                metrics.fetch_errors_total.labels(
                    log_url=monitoring_url,
                    fetch_type=fetch_type,
                    status_code=str(resp.status),
                ).inc()
                return None
            return await resp.read()
    except asyncio.TimeoutError:
        logger.warning(f"[{monitoring_url}] tile {tile_index} → timeout")
        metrics.fetch_errors_total.labels(
            log_url=monitoring_url, fetch_type=fetch_type, status_code="timeout"
        ).inc()
        return None
    except Exception as exc:
        logger.warning(f"[{monitoring_url}] tile {tile_index} → {exc}")
        metrics.fetch_errors_total.labels(
            log_url=monitoring_url, fetch_type=fetch_type, status_code="error"
        ).inc()
        return None


def _tile_path(n: int) -> str:
    """
    Convert tile index N to the x-prefixed 3-digit-segment URL path.
    Per the c2sp.org/tlog-tiles spec, all leading chunks get an "x" prefix:
      0        → "000"
      1000     → "x001/000"
      604015   → "x604/015"
      1234567  → "x001/x234/567"
    """
    s = f"{n:03d}"
    chunks: list[str] = []
    while s:
        chunks.append(s[-3:].zfill(3))
        s = s[:-3]
    chunks.reverse()
    parts = [f"x{c}" for c in chunks[:-1]] + [chunks[-1]]
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
    elapsed = _time.monotonic() - stats["start_time"]
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

    Pushes (log_url, parsed_list) onto write_queue.
    Blocks on write_queue.put() when it is full – backpressure from DB writes.
    """
    while True:
        item = await parse_queue.get()
        try:
            kind = item[0]
            t0 = _time.monotonic()

            if kind == "rfc6962":
                _, entries, start_index, log_url = item
                parsed = await asyncio.to_thread(
                    parse_entries_bulk, entries, start_index
                )
                elapsed = _time.monotonic() - t0
                metrics.parse_duration_seconds.labels(format="rfc6962").observe(elapsed)
                metrics.parse_batch_size.labels(format="rfc6962").observe(len(entries))
                failed = len(entries) - len(parsed)
                if failed > 0:
                    metrics.parse_errors_total.labels(
                        log_url=log_url, format="rfc6962"
                    ).inc(failed)

            elif kind == "tiled":
                _, tile_bytes, tile_index, log_url = item
                parsed = await asyncio.to_thread(
                    parse_tile_data, tile_bytes, tile_index
                )
                elapsed = _time.monotonic() - t0
                fmt = (
                    "tiled_sunlight"
                    if len(tile_bytes) >= 2 and not (tile_bytes[0] == 0 and tile_bytes[1] == 0)
                    else "tiled_sycamore"
                )
                metrics.parse_duration_seconds.labels(format=fmt).observe(elapsed)
                metrics.parse_batch_size.labels(format=fmt).observe(len(parsed))

            else:
                logger.error(f"Unknown queue item kind: {kind}")
                parsed = []

            # Per-cert counters
            for cert in parsed:
                metrics.certs_parsed_total.labels(
                    log_url=log_url,
                    ct_entry_type=cert.get("ct_entry_type", "unknown"),
                ).inc()
                issuer_o = metrics.extract_issuer_o(cert.get("issuer", ""))
                metrics.certs_by_issuer_total.labels(issuer=issuer_o).inc()

            if parsed:
                await write_queue.put((log_url, parsed))

        except Exception as exc:
            logger.error(f"Parser worker error: {exc}")
        finally:
            parse_queue.task_done()


# ─────────────────────────────────────────────────────────────────────
# Cert writer worker
# ─────────────────────────────────────────────────────────────────────

async def _cert_writer_worker(
    write_queue: asyncio.Queue,
    db,
) -> None:
    """
    Single worker that drains write_queue, persists certs to ClickHouse,
    and broadcasts filtered certs to Redis (multi-node) and/or WebSocket.
    """
    from .scoring import CertScoring
    from .util.score_config_loader import _load_scoring_config

    scorrer = CertScoring(**_load_scoring_config())

    if db is None:
        while True:
            await write_queue.get()
            write_queue.task_done()
        return

    cert_writer = CertWriter(db, flush_every=CERT_FLUSH_EVERY)
    last_log_url = ""

    while True:
        log_url, certs = await write_queue.get()
        last_log_url = log_url
        try:
            # ── Pipeline: score → write ──────────────
            #
            # 1. SCORE   – compute scripting_score only on surviving certs.
            # 2. WRITE   – buffer into CertWriter for ClickHouse INSERT.
            #
            # Certs that fail the filter are silently dropped; nothing is
            # written to the DB and nothing is broadcast for them.
            
            for cert in certs:
                cert["scripting_score"] = scorrer.score(cert)

            # Step 3: write to ClickHouse
            for cert in certs:
                cert_writer.record(cert, log_id=log_url)

            metrics.cert_writer_pending.set(len(cert_writer._pending))

            if len(cert_writer._pending) >= cert_writer._flush_every:
                n  = len(cert_writer._pending)
                t0 = _time.monotonic()
                await cert_writer.flush()
                elapsed = _time.monotonic() - t0
                metrics.db_cert_write_duration_seconds.observe(elapsed)
                metrics.db_cert_write_batch_size.observe(n)
                metrics.certs_written_total.labels(log_url=log_url).inc(n)
                metrics.cert_writer_pending.set(0)
            else:
                await cert_writer.flush_if_due()

        except Exception as exc:
            logger.error(f"Cert writer worker error: {exc}")
            metrics.cert_write_errors_total.labels(log_url=log_url).inc()
            metrics.db_errors_total.labels(operation="cert_flush").inc()
        finally:
            write_queue.task_done()

# ─────────────────────────────────────────────────────────────────────
# Dynamic log-list reassignment (called by WorkSubscriber in multi-node)
# ─────────────────────────────────────────────────────────────────────


class DynamicLogManager:
    """
    Wraps collect_all_logs_dynamic with the ability to replace the active
    log list on the fly when the WorkCoordinator pushes a new assignment.

    Usage
    ─────
        manager = DynamicLogManager(db, redis, ws, filter_manager)
        asyncio.create_task(manager.run())
        # Later, when WorkSubscriber calls on_assignment:
        manager.on_assignment(new_log_urls)
    """

    def __init__(
        self,
        db,
        poll_interval: int = 30,
    ) -> None:
        self._db              = db
        self._poll_interval   = poll_interval
        self._log_tasks: dict[str, asyncio.Task] = {}
        self._assigned_logs: list[str] = []
        self._assignment_event = asyncio.Event()

        # Shared queues and workers — created once, reused across reassignments
        self._parse_queue: asyncio.Queue | None = None
        self._write_queue: asyncio.Queue | None = None

    def on_assignment(self, logs: "list[str]") -> None:
        """
        Called (possibly from a sync context or different coroutine) when
        the WorkSubscriber receives a new log assignment.
        """
        self._assigned_logs = logs
        self._assignment_event.set()

    async def run(self) -> None:
        """Main loop: start workers once, then reconcile log tasks on assignment."""
        from .models import CTLog as _CTLog

        self._parse_queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self._write_queue = asyncio.Queue(maxsize=WRITE_QUEUE_MAXSIZE)

        metrics.active_parser_workers.set(PARSER_WORKERS)
        for _ in range(PARSER_WORKERS):
            asyncio.create_task(
                _parser_worker(self._parse_queue, self._write_queue)
            )
        asyncio.create_task(
            _cert_writer_worker(
                self._write_queue, self._db,
            )
        )

        while True:
            # Wait for an assignment (or the periodic poll interval)
            try:
                await asyncio.wait_for(
                    self._assignment_event.wait(),
                    timeout=self._poll_interval,
                )
                self._assignment_event.clear()
            except asyncio.TimeoutError:
                pass

            # Fetch current CTLog objects from DB for the assigned URLs
            assigned_urls = set(self._assigned_logs)
            existing_ids  = set(self._log_tasks.keys())

            def _get_logs():
                with self._db.Session() as session:
                    from .models import CTLog as _CTLog2
                    return session.query(_CTLog2).all()

            all_logs = await asyncio.to_thread(_get_logs)
            url_to_log = {}
            for log in all_logs:
                url = log.monitoring_url if log.is_tiled else log.url
                url_to_log[url] = log

            # Start tasks for newly assigned logs
            for url in assigned_urls:
                if url not in self._log_tasks or self._log_tasks[url].done():
                    log_obj = url_to_log.get(url)
                    if log_obj is None:
                        logger.warning("Assigned log URL not found in DB: %s", url)
                        continue
                    self._log_tasks[url] = asyncio.create_task(
                        collect_log_forever(
                            log_obj,
                            db=self._db,
                            parse_queue=self._parse_queue,
                        ),
                        name=f"collector-{log_obj.id}",
                    )

            # Cancel tasks for logs no longer assigned to this worker
            for url in list(self._log_tasks):
                if url not in assigned_urls:
                    self._log_tasks[url].cancel()
                    del self._log_tasks[url]

            # Update gauges
            metrics.parse_queue_depth.set(self._parse_queue.qsize())
            metrics.write_queue_depth.set(self._write_queue.qsize())
            metrics.active_collector_tasks.set(
                sum(1 for t in self._log_tasks.values() if not t.done())
            )