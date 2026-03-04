"""Async database access layer for the API service (ClickHouse backend)."""

from __future__ import annotations

import time
from typing import Any, Optional
from urllib.parse import urlparse

from .config import get_logger, DB_DSN

logger = get_logger("CertStreamAPI.Database")

try:
    import clickhouse_connect
    _ch_available = True
except ImportError:
    _ch_available = False


def _parse_dsn(dsn: str) -> dict:
    """Parse a clickhouse:// DSN into clickhouse_connect.get_client kwargs."""
    parsed = urlparse(dsn)
    port = parsed.port or 8123
    if port == 9000:   # remap native port to HTTP
        port = 8123
    return {
        "host": parsed.hostname or "clickhouse",
        "port": port,
        "username": parsed.username or "default",
        "password": parsed.password or "",
        "database": (parsed.path or "/certstream").lstrip("/") or "certstream",
    }


class DatabasePool:
    """ClickHouse async client wrapper with fetch / fetchrow / fetchval helpers."""

    def __init__(self, metrics=None) -> None:
        self._client = None
        self._metrics = metrics

    @property
    def available(self) -> bool:
        return self._client is not None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        if not _ch_available:
            logger.warning("clickhouse_connect not installed – database unavailable")
            if self._metrics:
                self._metrics.db_available.set(0)
            return
        try:
            kwargs = _parse_dsn(DB_DSN)
            self._client = await clickhouse_connect.get_async_client(**kwargs)
            await self._client.ping()
            logger.info(
                "Connected to ClickHouse at %s:%s/%s",
                kwargs["host"], kwargs["port"], kwargs["database"],
            )
            if self._metrics:
                self._metrics.db_available.set(1)
                self._metrics.db_pool_size.set(1)
        except Exception:
            logger.exception("Failed to connect to ClickHouse")
            self._client = None
            if self._metrics:
                self._metrics.db_available.set(0)

    async def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            logger.info("ClickHouse client closed")
            if self._metrics:
                self._metrics.db_available.set(0)

    # ------------------------------------------------------------------
    # Query helpers – return list[dict] for uniform row access
    # ------------------------------------------------------------------

    async def fetch(
        self,
        query: str,
        params: dict | None = None,
        *,
        endpoint: str = "unknown",
    ) -> list[dict]:
        if not self._client:
            return []
        t0 = time.monotonic()
        try:
            result = await self._client.query(query, parameters=params or {})
            elapsed = time.monotonic() - t0
            if self._metrics:
                self._metrics.db_query_duration.labels(endpoint=endpoint).observe(elapsed)
                self._metrics.db_queries_total.labels(endpoint=endpoint).inc()
            cols = list(result.column_names)
            return [dict(zip(cols, row)) for row in result.result_rows]
        except Exception:
            logger.exception("Query failed: %.120s", query)
            if self._metrics:
                self._metrics.db_query_errors.labels(endpoint=endpoint).inc()
            return []

    async def fetchrow(
        self,
        query: str,
        params: dict | None = None,
        *,
        endpoint: str = "unknown",
    ) -> dict | None:
        rows = await self.fetch(query, params, endpoint=endpoint)
        return rows[0] if rows else None

    async def fetchval(
        self,
        query: str,
        params: dict | None = None,
        *,
        endpoint: str = "unknown",
    ) -> Any:
        row = await self.fetchrow(query, params, endpoint=endpoint)
        if row is None:
            return None
        return next(iter(row.values()))

    async def command(self, query: str) -> Any:
        """Execute a DDL / non-SELECT statement."""
        if not self._client:
            return None
        return await self._client.command(query)
