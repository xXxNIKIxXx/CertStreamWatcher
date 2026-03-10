"""Async ClickHouse database manager with buffered batch inserts.

Rows are accumulated in memory and flushed in bulk via a single INSERT,
dramatically reducing HTTP round-trips.  The ``scripting_score`` field
produced by the scoring step is persisted alongside each certificate.
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
    _CH_AVAILABLE = True
except ImportError:
    _CH_AVAILABLE = False


def _parse_dsn(dsn: str) -> dict:
    """Extract connection params from a ``clickhouse://`` DSN.

    clickhouse-connect uses the HTTP port (8123); auto-remap 9000 → 8123
    for convenience.
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
    """ClickHouse HTTP client with an in-memory write buffer."""

    # ------------------------------------------------------------------ #
    # Schema                                                               #
    # ------------------------------------------------------------------ #

    _CREATE_CERTS_SQL = """
CREATE TABLE IF NOT EXISTS ct_certs (
    id                 UUID DEFAULT generateUUIDv4(),
    log                String,
    subject            String,
    issuer             String,
    not_before         DateTime64(3, 'UTC'),
    not_after          DateTime64(3, 'UTC'),
    serial_number      String,
    dns_names          Array(String),
    fingerprint_sha256 String,
    ct_entry_type      String,
    format             String,
    scripting_score    Int32 DEFAULT 0,
    ts                 DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (ts, fingerprint_sha256)
PARTITION BY toYYYYMM(ts)
"""

    _CREATE_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS ct_settings (
    key   String,
    value String,
    ts    DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (key, ts)
"""

    # Columns written on every INSERT (id / ts use ClickHouse defaults)
    _COLUMNS = [
        "log", "subject", "issuer", "not_before", "not_after",
        "serial_number", "dns_names", "fingerprint_sha256",
        "ct_entry_type", "format", "scripting_score",
    ]

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def __init__(self, metrics=None) -> None:
        self._client = None
        self._client_params: dict | None = None
        self._metrics = metrics
        self._buffer: List[list] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None

    @property
    def available(self) -> bool:
        return self._client is not None

    async def init(self) -> None:
        """Connect to ClickHouse, create tables, and start the buffer flusher."""
        if not _CH_AVAILABLE:
            logger.warning("clickhouse-connect not installed; DB writes disabled")
            self._set_available(0)
            return

        try:
            params = _parse_dsn(DB_DSN)
            self._client_params = params
            client = clickhouse_connect.get_client(**params)

            await asyncio.to_thread(client.command, self._CREATE_CERTS_SQL)
            await asyncio.to_thread(client.command, self._CREATE_SETTINGS_SQL)
            await asyncio.to_thread(self._migrate_columns, client)

            self._client = client
            logger.info(
                "ClickHouse connected (%s:%s/%s)",
                params["host"], params["port"], params["database"],
            )
            self._set_available(1)
            if self._metrics:
                self._metrics.db_pool_size.set(1)
            self._flush_task = asyncio.create_task(self._periodic_flush())

        except Exception:
            logger.exception("Failed to initialise ClickHouse client")
            self._client = None
            self._set_available(0)

    async def close(self) -> None:
        """Cancel the flusher, flush remaining rows, then close the client."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        await self.flush()

        if self._client:
            try:
                self._client.close()
            except Exception:
                logger.exception("Error closing ClickHouse client")
            self._client = None
            self._set_available(0)

    # ------------------------------------------------------------------ #
    # Write path                                                           #
    # ------------------------------------------------------------------ #

    def buffer_cert(self, cert: dict) -> None:
        """Append a parsed + scored certificate to the in-memory write buffer."""
        if not self._client:
            return

        if self._metrics:
            self._metrics.db_writes_total.inc()

        dns_names = cert.get("dns_names") or []
        if isinstance(dns_names, str):
            dns_names = json.loads(dns_names)

        row = [
            cert.get("log") or "",
            cert.get("subject") or "",
            cert.get("issuer") or "",
            self._to_datetime(cert.get("not_before")) or datetime(1970, 1, 1),
            self._to_datetime(cert.get("not_after")) or datetime(1970, 1, 1),
            cert.get("serial_number") or "",
            dns_names,
            cert.get("fingerprint_sha256") or "",
            cert.get("ct_entry_type") or "",
            cert.get("format") or "",
            int(cert.get("scripting_score") or 0),
        ]
        self._buffer.append(row)

        if self._metrics:
            try:
                self._metrics.db_buffer_size.set(len(self._buffer))
            except Exception:
                pass

    async def flush(self) -> None:
        """Flush all buffered rows to ClickHouse in a single INSERT."""
        if not self._client:
            return

        async with self._lock:
            if not self._buffer:
                return
            rows, self._buffer = self._buffer, []

            if self._metrics:
                try:
                    self._metrics.db_buffer_size.set(0)
                except Exception:
                    pass

            t0 = time.monotonic()
            try:
                params = self._client_params or {}
                columns = self._COLUMNS

                def _insert(params, rows, columns):
                    tmp = clickhouse_connect.get_client(**params)
                    try:
                        tmp.insert("ct_certs", rows, column_names=columns)
                    finally:
                        try:
                            tmp.close()
                        except Exception:
                            pass

                await asyncio.to_thread(_insert, params, rows, columns)
                elapsed = time.monotonic() - t0
                logger.debug("Flushed %d rows in %.3fs", len(rows), elapsed)
                if self._metrics:
                    self._metrics.db_write_duration_seconds.observe(elapsed)
                    self._metrics.db_batch_size.observe(len(rows))

            except Exception:
                logger.exception("Batch insert failed (%d rows)", len(rows))
                if self._metrics:
                    self._metrics.db_write_errors_total.inc()
                    self._metrics.db_write_duration_seconds.observe(
                        time.monotonic() - t0
                    )

    # ------------------------------------------------------------------ #
    # Settings helpers                                                     #
    # ------------------------------------------------------------------ #

    def insert_setting(self, key: str, value: str) -> None:
        """Persist a settings key/value pair (synchronous)."""
        if not self._client and not self._client_params:
            return
        try:
            self._client.insert(
                "ct_settings", [[key, value]], column_names=["key", "value"]
            )
            if self._metrics:
                self._metrics.db_writes_total.inc()
        except Exception:
            logger.exception("Failed to insert setting %s", key)

    def get_latest_setting(self, key: str) -> Optional[str]:
        """Return the most recent value for *key*, or ``None`` (synchronous)."""
        if not self._client and not self._client_params:
            return None
        try:
            rows = self._client.query(
                f"SELECT value FROM ct_settings "
                f"WHERE key = '{key}' ORDER BY ts DESC LIMIT 1"
            )
            items = list(rows) if rows else []
            if not items:
                return None
            row = items[0]
            if hasattr(row, "get"):
                return row.get("value")
            if isinstance(row, (list, tuple)):
                return row[0] if row else None
            return row
        except Exception:
            logger.exception("Failed to query latest setting %s", key)
            return None

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    async def _periodic_flush(self) -> None:
        while True:
            await asyncio.sleep(DB_FLUSH_INTERVAL)
            try:
                await self.flush()
            except Exception:
                logger.exception("Periodic flush error")

    def _set_available(self, value: int) -> None:
        if self._metrics:
            self._metrics.db_available.set(value)

    @staticmethod
    def _migrate_columns(client) -> None:
        """Add any columns that were introduced after initial deployment."""
        try:
            result = client.query(
                "SELECT name FROM system.columns WHERE table = 'ct_certs'"
            )
            existing = {row[0] for row in list(result)}
        except Exception:
            existing = set()

        migrations = [
            ("ct_entry_type",   "ALTER TABLE ct_certs ADD COLUMN IF NOT EXISTS ct_entry_type String"),
            ("format",          "ALTER TABLE ct_certs ADD COLUMN IF NOT EXISTS format String"),
            ("scripting_score", "ALTER TABLE ct_certs ADD COLUMN IF NOT EXISTS scripting_score Int32 DEFAULT 0"),
        ]
        for col, sql in migrations:
            if col not in existing:
                try:
                    client.command(sql)
                    logger.info("Migration applied: added column %s", col)
                except Exception:
                    logger.warning("Migration skipped for column %s", col)

    @staticmethod
    def _to_datetime(value) -> Optional[datetime]:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except Exception:
                return None
        return value if isinstance(value, datetime) else None
