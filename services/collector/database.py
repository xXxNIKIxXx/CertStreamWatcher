"""Async database manager for persisting parsed certificate metadata (ClickHouse).

Uses clickhouse-connect (HTTP protocol) with buffered batch inserts for
maximum throughput.  Rows are accumulated in memory and flushed in bulk
via a single INSERT, dramatically reducing HTTP round-trips.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from typing import List, Optional

from .config import get_logger, DB_DSN, DB_FLUSH_INTERVAL

logger = get_logger("CTStreamService.Database")

try:
    import clickhouse_connect
    _ch_available = True
except ImportError:
    _ch_available = False


def _parse_clickhouse_dsn(dsn: str) -> dict:
    """Extract host, port, user, password, database from a clickhouse:// DSN.

    The collector DSN uses port 9000 (native) by convention, but
    clickhouse-connect needs the HTTP port (8123).  We auto-remap 9000->8123.
    """
    from urllib.parse import urlparse

    parsed = urlparse(dsn)
    port = parsed.port or 8123
    if port == 9000:
        port = 8123
    return {
        "host": parsed.hostname or "clickhouse",
        "port": port,
        "username": parsed.username or "default",
        "password": parsed.password or "",
        "database": parsed.path.lstrip("/") or "certstream",
    }


class DatabaseManager:
    """Manages a ClickHouse HTTP client with buffered batch inserts."""

    CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS ct_certs (
    id          UUID DEFAULT generateUUIDv4(),
    log         String,
    subject     String,
    issuer      String,
    not_before  DateTime64(3, 'UTC'),
    not_after   DateTime64(3, 'UTC'),
    serial_number String,
    dns_names   Array(String),
    fingerprint_sha256 String,
    ts          DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (ts, fingerprint_sha256)
PARTITION BY toYYYYMM(ts)
"""

    # Settings table for persisted configuration (append-only; latest by ts)
    CREATE_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS ct_settings (
    key String,
    value String,
    ts DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (key, ts)
"""

    # Columns we actively insert — id & ts use ClickHouse DEFAULT values
    _INSERT_COLUMNS = [
        "log", "subject", "issuer", "not_before", "not_after",
        "serial_number", "dns_names", "fingerprint_sha256",
    ]

    def __init__(self, metrics=None) -> None:
        self._client = None
        self._metrics = metrics
        self._buffer: List[list] = []
        self._lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None

    @property
    def available(self) -> bool:
        return self._client is not None

    async def init(self) -> None:
        """Create the HTTP client, ensure the table, start background flusher."""
        if not _ch_available:
            logger.warning("clickhouse-connect not available; DB writes disabled")
            if self._metrics:
                self._metrics.db_available.set(0)
            return

        try:
            params = _parse_clickhouse_dsn(DB_DSN)
            client = clickhouse_connect.get_client(**params)
            await asyncio.to_thread(client.command, self.CREATE_TABLE_SQL)
            await asyncio.to_thread(client.command, self.CREATE_SETTINGS_SQL)
            self._client = client
            logger.info(
                "ClickHouse HTTP client created (%s:%s/%s)",
                params["host"], params["port"], params["database"],
            )
            if self._metrics:
                self._metrics.db_available.set(1)
                self._metrics.db_pool_size.set(1)
            # Start periodic background flush
            self._flush_task = asyncio.create_task(self._periodic_flush())
        except Exception:
            logger.exception("Failed to initialize ClickHouse client")
            self._client = None
            if self._metrics:
                self._metrics.db_available.set(0)

    def buffer_cert(self, cert: dict) -> None:
        """Add a parsed certificate to the insert buffer (non-blocking).

        Rows accumulate until flush() is called (explicitly after each
        batch, or automatically by the periodic background task).
        """
        if not self._client:
            return

        if self._metrics:
            self._metrics.db_writes_total.inc()

        not_before_val = self._to_datetime(cert.get("not_before"))
        not_after_val = self._to_datetime(cert.get("not_after"))
        dns_names = cert.get("dns_names") or []
        if isinstance(dns_names, str):
            dns_names = json.loads(dns_names)

        row = [
            cert.get("log") or "",
            cert.get("subject") or "",
            cert.get("issuer") or "",
            not_before_val or datetime(1970, 1, 1),
            not_after_val or datetime(1970, 1, 1),
            cert.get("serial_number") or "",
            dns_names,
            cert.get("fingerprint_sha256") or "",
        ]
        self._buffer.append(row)

    async def flush(self) -> None:
        """Flush all buffered rows to ClickHouse in a single INSERT."""
        if not self._client:
            return

        async with self._lock:
            if not self._buffer:
                return
            rows = self._buffer
            self._buffer = []

            count = len(rows)
            t0 = time.monotonic()
            try:
                await asyncio.to_thread(
                    self._client.insert,
                    "ct_certs",
                    rows,
                    column_names=self._INSERT_COLUMNS,
                )
                elapsed = time.monotonic() - t0
                logger.debug(
                    "Flushed %d rows to ClickHouse in %.3fs",
                    count, elapsed,
                )
                if self._metrics:
                    self._metrics.db_write_duration_seconds.observe(elapsed)
                    self._metrics.db_batch_size.observe(count)
            except Exception:
                logger.exception("Batch insert failed (%d rows)", count)
                if self._metrics:
                    self._metrics.db_write_errors_total.inc()
                    self._metrics.db_write_duration_seconds.observe(
                        time.monotonic() - t0
                    )

    async def _periodic_flush(self) -> None:
        """Background task: flush the buffer every DB_FLUSH_INTERVAL seconds."""
        while True:
            await asyncio.sleep(DB_FLUSH_INTERVAL)
            try:
                await self.flush()
            except Exception:
                logger.exception("Periodic flush error")

    async def close(self) -> None:
        """Cancel the flusher, flush remaining rows, and close the client."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final flush
        try:
            await self.flush()
        except Exception:
            logger.exception("Final flush failed")
        if self._client:
            try:
                self._client.close()
            except Exception:
                logger.exception("Error closing ClickHouse client")
            self._client = None
            if self._metrics:
                self._metrics.db_available.set(0)

    # ------------------------------------------------------------------
    # Settings helpers
    # ------------------------------------------------------------------

    def insert_setting(self, key: str, value: str) -> None:
        """Insert a settings row. Synchronous helper used by FilterManager.

        This method is intentionally synchronous since callers may call it
        from non-async code paths.
        """
        if not self._client:
            return
        try:
            # clickhouse-connect supports insert with column names
            self._client.insert(
                "ct_settings",
                [[key, value]],
                column_names=["key", "value"],
            )
            if self._metrics:
                self._metrics.db_writes_total.inc()
        except Exception:
            logger.exception("Failed to insert setting %s", key)

    def get_latest_setting(self, key: str) -> Optional[str]:
        """Return the latest value for `key` or None.

        This executes a synchronous query on the underlying client.
        """
        if not self._client:
            return None
        try:
            rows = self._client.query(
                f"SELECT value FROM ct_settings WHERE key = '{key}' ORDER BY ts DESC LIMIT 1"
            )
            # clickhouse-connect returns list of dict-like rows
            if rows and len(rows) > 0:
                return rows[0]["value"]
        except Exception:
            logger.exception("Failed to query latest setting %s", key)
        return None
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_datetime(value) -> Optional[datetime]:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except Exception:
                return None
        return value if isinstance(value, datetime) else None
