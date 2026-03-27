"""
database.py

Key design decisions for ClickHouse compatibility
--------------------------------------------------
ClickHouse does not support UPDATE/DELETE in the normal SQL sense.
ct_log_slices uses ReplacingMergeTree(updated_at) which deduplicates
on (id, slice_start) during background merges – NOT immediately on INSERT.

Because merges are lazy, we NEVER rely on ClickHouse to deduplicate
rows for us at query time.  Instead:

  - DatabaseManager keeps an in-process Python cache (_slice_cache) of
    every known (log_id, slice_start) pair.  ensure_slices() checks this
    cache before touching the DB – so a slice is inserted exactly ONCE
    for the lifetime of the process.

  - On startup (first call to ensure_slices for a log) the cache is
    cold-loaded from the DB using SELECT ... FINAL so we correctly resume
    after a restart.

  - Progress updates (current_index, status) are written to the DB as
    new INSERTs (the ReplacingMergeTree pattern) but the in-memory
    CTLogSlice objects owned by the collector tasks are the live source
    of truth during a run.  The DB rows are only read on startup.

This means ct_log_slices grows by exactly:
  N_slices_created  +  N_progress_updates_written

Progress updates are batched by SliceWriter (one INSERT per FLUSH_EVERY
batches) so the write rate is manageable.  Old rows are TTL-expired after
7 days; after a full merge only the latest row per (id, slice_start)
survives.
"""

from services.shared.logger import get_logger
from . import metrics
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from .models import Base, CTLog, CTLogSlice
import asyncio
import datetime
import sqlalchemy
import threading

logger = get_logger("CTStreamService.DatabaseManager")

# Size of each slice in CT log entries.
SLICE_SIZE = 500_000


class DatabaseManager:
    def __init__(self, db_url: str):
        self.engine = create_engine(
            db_url,
            echo=False,
            future=True,
            poolclass=QueuePool,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=1800,
        )
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

        # In-process cache: log_id -> set of slice_start values that exist in DB.
        # Populated lazily on first ensure_slices() call for each log.
        # Protected by a threading.Lock because to_thread workers may call it
        # concurrently.
        self._slice_cache: dict[str, set[int]] = {}
        self._slice_cache_loaded: set[str]     = set()   # logs already cold-loaded
        self._cache_lock                        = threading.Lock()

    # ------------------------------------------------------------------
    # Init / teardown
    # ------------------------------------------------------------------

    async def init(self):
        from .models import create_all_clickhouse_tables
        create_all_clickhouse_tables(self.engine)
        await self._auto_migrate_all_models()

    async def _auto_migrate_all_models(self):
        def _migrate():
            insp = sqlalchemy.inspect(self.engine)
            for table in Base.metadata.sorted_tables:
                table_name = table.name
                try:
                    db_columns = [col['name'] for col in insp.get_columns(table_name)]
                except Exception:
                    continue
                for col in table.columns:
                    if col.name not in db_columns:
                        ch_type = self._sa_type_to_clickhouse(col.type)
                        default = self._get_column_default(col)
                        alter = (
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {col.name} {ch_type}{default}"
                        )
                        with self.engine.connect() as conn:
                            conn.execute(text(alter))
                            conn.commit()
        await asyncio.to_thread(_migrate)

    def _sa_type_to_clickhouse(self, sa_type):
        if isinstance(sa_type, sqlalchemy.String):   return "String"
        if isinstance(sa_type, sqlalchemy.Integer):  return "Int32"
        if isinstance(sa_type, sqlalchemy.Boolean):  return "UInt8"
        if isinstance(sa_type, sqlalchemy.DateTime): return "DateTime"
        if isinstance(sa_type, sqlalchemy.Float):    return "Float64"
        return "String"

    def _get_column_default(self, col):
        if col.default is not None and col.default.arg is not None:
            val = col.default.arg
            if isinstance(val, bool):
                val = int(val)
            return f" DEFAULT {val}"
        return ""

    async def get_log_sources(self) -> list[CTLog]:
        def _query():
            with self.Session() as session:
                return session.query(CTLog).all()
        try:
            result = await asyncio.to_thread(_query)
            return result
        except Exception as exc:
            metrics.db_errors_total.labels(operation="get_logs").inc()
            raise


    # ------------------------------------------------------------------
    # Filter / settings helpers
    # ------------------------------------------------------------------

    def insert_setting(self, key: str, value: str) -> None:
        """Persist a key/value setting row to ct_settings (synchronous)."""
        import datetime as _dt
        now = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        def _run():
            with self.engine.connect() as conn:
                conn.execute(
                    text(
                        "INSERT INTO ct_settings (key, value, ts) "
                        "VALUES (:key, :value, :ts)"
                    ),
                    {"key": key, "value": value, "ts": now},
                )
                conn.commit()
        try:
            import threading
            if threading.current_thread() is threading.main_thread():
                # Called from sync context — run directly
                _run()
            else:
                _run()
        except Exception as exc:
            logger.error("insert_setting(%s) failed: %s", key, exc)

    def get_latest_setting(self, key: str) -> "str | None":
        """Return the most recent value for *key* from ct_settings, or None."""
        def _run():
            with self.engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT value FROM ct_settings "
                        "WHERE key = :key "
                        "ORDER BY ts DESC LIMIT 1"
                    ),
                    {"key": key},
                ).fetchall()
                return rows[0][0] if rows else None
        try:
            return _run()
        except Exception as exc:
            logger.error("get_latest_setting(%s) failed: %s", key, exc)
            return None

    async def get_latest_setting_async(self, key: str) -> "str | None":
        """Async wrapper for get_latest_setting."""
        return await asyncio.to_thread(self.get_latest_setting, key)

    def update_pool_metrics(self) -> None:
        """Push connection-pool gauges. Call periodically from the service loop."""
        try:
            pool = self.engine.pool
            metrics.db_pool_checked_out.set(pool.checkedout())
            metrics.db_pool_overflow.set(pool.overflow())
        except Exception:
            pass

    async def close(self):
        def _dispose():
            self.engine.dispose()
        await asyncio.to_thread(_dispose)

    # ------------------------------------------------------------------
    # Cache helpers  (always called from to_thread, so plain threading.Lock)
    # ------------------------------------------------------------------

    def _cold_load_cache(self, conn, log_id: str) -> None:
        """
        Load all existing slice_start values for log_id from ClickHouse into
        the in-process cache.  Called once per log per process lifetime.
        Uses FINAL to get the deduplicated view.
        """
        rows = conn.execute(
            text(
                "SELECT DISTINCT slice_start "
                "FROM ct_log_slices FINAL "
                "WHERE id = :lid"
            ),
            {"lid": log_id},
        ).fetchall()
        starts = {int(r[0]) for r in rows}
        with self._cache_lock:
            self._slice_cache.setdefault(log_id, set()).update(starts)
            self._slice_cache_loaded.add(log_id)
        logger.debug(
            f"[{log_id}] cache cold-loaded {len(starts)} existing slice(s)"
        )

    def _cache_has(self, log_id: str, slice_start: int) -> bool:
        with self._cache_lock:
            return slice_start in self._slice_cache.get(log_id, set())

    def _cache_add(self, log_id: str, slice_start: int) -> None:
        with self._cache_lock:
            self._slice_cache.setdefault(log_id, set()).add(slice_start)

    def _cache_loaded(self, log_id: str) -> bool:
        with self._cache_lock:
            return log_id in self._slice_cache_loaded

    # ------------------------------------------------------------------
    # Slice management
    # ------------------------------------------------------------------

    async def ensure_slices(self, log_id: str, log_length: int) -> None:
        """
        Create any missing slices for [0, log_length).

        A slice is inserted EXACTLY ONCE per (log_id, slice_start):
          1. On first call for this log we cold-load the cache from DB.
          2. Every subsequent call only checks the in-process cache –
             no DB read, no risk of duplicate inserts.

        This means even if LogLengthUpdater calls this every 30 s for
        200 logs the DB insert rate is O(new slices only), not O(all slices).
        """
        def _run():
            with self.engine.connect() as conn:
                # Cold-load once per log per process lifetime
                if not self._cache_loaded(log_id):
                    self._cold_load_cache(conn, log_id)

                to_add = []
                start = 0
                while start < log_length:
                    end = min(start + SLICE_SIZE, log_length)
                    if not self._cache_has(log_id, start):
                        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                        to_add.append({
                            "id":            log_id,
                            "slice_start":   start,
                            "slice_end":     end,
                            "current_index": start,
                            "worker_id":     "",
                            "status":        "pending",
                            "updated_at":    now,
                        })
                        # Add to cache immediately so concurrent callers
                        # don't race and double-insert
                        self._cache_add(log_id, start)
                    start = end

                if to_add:
                    conn.execute(
                        text(
                            "INSERT INTO ct_log_slices "
                            "(id, slice_start, slice_end, current_index, "
                            " worker_id, status, updated_at) VALUES "
                            "(:id, :slice_start, :slice_end, :current_index, "
                            " :worker_id, :status, :updated_at)"
                        ),
                        to_add,
                    )
                    conn.commit()
                    logger.info(
                        f"[{log_id}] Inserted {len(to_add)} new slice(s) "
                        f"(log_length={log_length})"
                    )
                    metrics.slices_created_total.labels(log_id=log_id).inc(len(to_add))

        t0 = __import__('time').monotonic()
        try:
            await asyncio.to_thread(_run)
        except Exception as exc:
            metrics.db_errors_total.labels(operation="ensure_slices").inc()
            raise
        finally:
            metrics.db_ensure_slices_duration_seconds.observe(__import__('time').monotonic() - t0)

    async def get_pending_slices(self, log_id: str) -> list[CTLogSlice]:
        """
        Return all slices that still have work remaining, ordered by slice_start.

        Uses FINAL so ClickHouse deduplicates before returning results.
        This is only called once per log on (re)start of a collector task;
        after that the in-memory CTLogSlice objects are the live source of truth.
        """
        def _run():
            with self.engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT id, slice_start, slice_end, current_index, "
                        "       worker_id, status, updated_at "
                        "FROM ct_log_slices FINAL "
                        "WHERE id = :lid AND status != 'done' "
                        "ORDER BY slice_start"
                    ),
                    {"lid": log_id},
                ).fetchall()

            slices = []
            for r in rows:
                slices.append(CTLogSlice(
                    id=r[0],
                    slice_start=r[1],
                    slice_end=r[2],
                    current_index=r[3],
                    worker_id=r[4],
                    status=r[5],
                    updated_at=r[6],
                ))
            return slices

        import time as _t
        t0 = _t.monotonic()
        try:
            result = await asyncio.to_thread(_run)
            return result
        except Exception as exc:
            metrics.db_errors_total.labels(operation="get_pending_slices").inc()
            raise
        finally:
            metrics.db_get_slices_duration_seconds.observe(_t.monotonic() - t0)

    async def update_slice(
        self,
        log_id: str,
        slice_start: int,
        slice_end: int,
        current_index: int,
        worker_id: str = "",
    ) -> None:
        """
        Persist slice progress as a new INSERT row.
        ReplacingMergeTree will keep only the latest row per (id, slice_start)
        after background merges.
        """
        status = "done" if current_index >= slice_end else "active"
        now    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        def _run():
            with self.engine.connect() as conn:
                conn.execute(
                    text(
                        "INSERT INTO ct_log_slices "
                        "(id, slice_start, slice_end, current_index, "
                        " worker_id, status, updated_at) VALUES "
                        "(:id, :slice_start, :slice_end, :current_index, "
                        " :worker_id, :status, :updated_at)"
                    ),
                    {
                        "id":            log_id,
                        "slice_start":   slice_start,
                        "slice_end":     slice_end,
                        "current_index": current_index,
                        "worker_id":     worker_id,
                        "status":        status,
                        "updated_at":    now,
                    },
                )
                conn.commit()

        await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# SliceWriter – batches progress INSERTs to reduce DB round-trips
# ---------------------------------------------------------------------------

class SliceWriter:
    """
    Accumulates slice progress updates in memory and flushes them as a single
    bulk INSERT every FLUSH_EVERY calls (or on explicit flush()).

    Because the in-memory CTLogSlice objects are the live source of truth, the
    DB rows written here are only needed for crash recovery on restart.
    Reducing flush frequency directly reduces ct_log_slices row growth.

    Recommended FLUSH_EVERY values:
      - Backfill (fast, many entries): 50-100  → few hundred rows/slice total
      - Live tail (slow, few entries): 5-10    → more frequent persistence
    """

    def __init__(self, db_manager: DatabaseManager, flush_every: int = 50):
        self._db          = db_manager
        self._flush_every = flush_every
        self._pending: dict[tuple[str, int], dict] = {}
        self._call_count: int = 0

    def record(
        self,
        log_id: str,
        slice_start: int,
        current_index: int,
        slice_end: int,
        worker_id: str = "",
    ) -> None:
        """Stage an update in memory.  Last write for a given key wins."""
        status = "done" if current_index >= slice_end else "active"
        self._pending[(log_id, slice_start)] = {
            "id":            log_id,
            "slice_start":   slice_start,
            "slice_end":     slice_end,
            "current_index": current_index,
            "worker_id":     worker_id,
            "status":        status,
        }
        self._call_count += 1

    async def flush_if_due(self) -> None:
        if self._call_count >= self._flush_every:
            await self.flush()

    async def flush(self) -> None:
        if not self._pending:
            return

        snapshot          = list(self._pending.values())
        self._pending.clear()
        self._call_count  = 0

        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        for row in snapshot:
            row["updated_at"] = now

        def _write():
            with self._db.engine.connect() as conn:
                conn.execute(
                    text(
                        "INSERT INTO ct_log_slices "
                        "(id, slice_start, slice_end, current_index, "
                        " worker_id, status, updated_at) VALUES "
                        "(:id, :slice_start, :slice_end, :current_index, "
                        " :worker_id, :status, :updated_at)"
                    ),
                    snapshot,
                )
                conn.commit()

        import time as _t
        t0 = _t.monotonic()
        try:
            await asyncio.to_thread(_write)
            elapsed = _t.monotonic() - t0
            metrics.db_slice_write_duration_seconds.observe(elapsed)
            metrics.slice_progress_flushes_total.inc()
            metrics.slice_progress_rows_total.inc(len(snapshot))
            logger.debug(
                f"SliceWriter: flushed {len(snapshot)} slice(s) in one INSERT."
            )
        except Exception as exc:
            metrics.db_errors_total.labels(operation="slice_flush").inc()
            raise


# ---------------------------------------------------------------------------
# CertWriter – batches ct_certs INSERTs off the hot path
# ---------------------------------------------------------------------------

class CertWriter:
    """
    Accumulates parsed cert dicts in memory and flushes them as a single
    bulk INSERT into ct_certs every FLUSH_EVERY certs (or on explicit flush).

    Design goals
    ────────────
    - Never block the parser workers: record() is synchronous and instant.
    - Amortise ClickHouse round-trips: one INSERT per flush covers many rows.
    - Keep memory bounded: flush_every caps the in-memory buffer size.
    - dns_names is Array(String) in ClickHouse.  SQLAlchemy parameterised
      queries pass Python lists natively via clickhouse-sqlalchemy, so we
      store them as-is in the pending list and let the driver serialise them.

    Usage
    ─────
        writer = CertWriter(db_manager, flush_every=500)
        writer.record(cert_dict, log_id="abc123")
        await writer.flush_if_due()
        await writer.flush()   # force-flush at end of batch / shutdown
    """

    # SQL that lets ClickHouse generate id and ts via their DEFAULT expressions.
    # We never supply id (UUID auto-generated) or ts (DEFAULT now64(3)).
    _INSERT_SQL = text(
        "INSERT INTO ct_certs "
        "(log, subject, issuer, not_before, not_after, serial_number, "
        " dns_names, fingerprint_sha256, ct_entry_type, format, scripting_score) "
        "VALUES "
        "(:log, :subject, :issuer, :not_before, :not_after, :serial_number, "
        " :dns_names, :fingerprint_sha256, :ct_entry_type, :format, :scripting_score)"
    )

    def __init__(self, db_manager: "DatabaseManager", flush_every: int = 500):
        self._db          = db_manager
        self._flush_every = flush_every
        self._pending: list[dict] = []

    def record(self, cert: "dict", log_id: str) -> None:
        """
        Stage one parsed cert dict for the next flush.  Never touches the DB.

        Expected cert keys (from cert_parser):
          index, ct_entry_type, timestamp_ms, subject, issuer,
          not_before, not_after, serial_number, dns_names, fingerprint_sha256
        """
        self._pending.append({
            "log":                log_id,
            "subject":            cert.get("subject", ""),
            "issuer":             cert.get("issuer", ""),
            # not_before / not_after come as ISO-8601 strings from the parser.
            # ClickHouse DateTime64 accepts 'YYYY-MM-DD HH:MM:SS[.fff]' strings.
            "not_before":         cert["not_before"].replace("T", " ").replace("+00:00", ""),
            "not_after":          cert["not_after"].replace("T", " ").replace("+00:00", ""),
            "serial_number":      cert.get("serial_number", ""),
            # dns_names is Array(String) – pass as Python list; clickhouse-sqlalchemy
            # serialises it correctly.
            "dns_names":          cert.get("dns_names") or [],
            "fingerprint_sha256": cert.get("fingerprint_sha256", ""),
            "ct_entry_type":      cert.get("ct_entry_type", ""),
            "format":             "",   # reserved for future use
            "scripting_score":    0,
        })

    async def flush_if_due(self) -> None:
        if len(self._pending) >= self._flush_every:
            await self.flush()

    async def flush(self) -> None:
        """Bulk-INSERT all pending certs in one round-trip, then clear the buffer."""
        if not self._pending:
            return

        snapshot      = self._pending
        self._pending = []

        def _write():
            with self._db.engine.connect() as conn:
                conn.execute(self._INSERT_SQL, snapshot)
                conn.commit()

        import time as _t
        t0 = _t.monotonic()
        try:
            await asyncio.to_thread(_write)
            logger.debug(f"CertWriter: inserted {len(snapshot)} cert(s).")
        except Exception as exc:
            logger.error(f"CertWriter: flush failed ({len(snapshot)} certs): {exc}")
            metrics.db_errors_total.labels(operation="cert_flush").inc()
            # Put them back so they aren't silently lost.
            self._pending = snapshot + self._pending