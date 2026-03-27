"""Shared ClickHouse connection helper for the Dashboard service."""

import logging
import os
from urllib.parse import urlparse

import clickhouse_connect

logger = logging.getLogger(__name__)

DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse://default:@clickhouse:8123/certstream",
)

# Ensure the table exists even if the collector hasn't started yet.
_CREATE_TABLE_SQL = """
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

# Ensure settings table exists for persisted configuration
_CREATE_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS ct_settings (
    key String,
    value String,
    ts DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (key, ts)
"""

_table_ensured = False


def _parse_dsn(dsn: str) -> dict:
    """Parse a ``clickhouse://`` DSN into ``clickhouse_connect.get_client`` kwargs."""
    parsed = urlparse(dsn)
    return {
        "host": parsed.hostname or "clickhouse",
        "port": int(parsed.port or 8123),
        "username": parsed.username or "default",
        "password": parsed.password or "",
        "database": (parsed.path or "/certstream").lstrip("/") or "certstream",
    }


def get_client(*, connect_timeout: int = 3):
    """Return a short-lived ``clickhouse_connect`` client.

    Each call opens a fresh HTTP session – fine for the dashboard's
    low-frequency queries.  Callers should use it inside a try/except.

    On first call the ``ct_certs`` table is created if it doesn't exist.
    """
    global _table_ensured
    kwargs = _parse_dsn(DB_DSN)
    client = clickhouse_connect.get_client(
        **kwargs,
        connect_timeout=connect_timeout,
    )
    if not _table_ensured:
        try:
            client.command(_CREATE_TABLE_SQL)
            try:
                client.command(_CREATE_SETTINGS_SQL)
            except Exception:
                logger.warning("Could not ensure ct_settings table", exc_info=True)
            _table_ensured = True
            logger.info("ct_certs table ensured in ClickHouse")
        except Exception:
            logger.warning("Could not ensure ct_certs table", exc_info=True)
    return client


def insert_setting(key: str, value: str) -> None:
    client = get_client()
    try:
        client.insert("ct_settings", [[key, value]], column_names=["key", "value"])
    finally:
        try:
            client.close()
        except Exception:
            pass


def get_latest_setting(key: str) -> str | None:
    client = get_client()
    try:
        res = client.query(f"SELECT value FROM ct_settings WHERE key = '{key}' ORDER BY ts DESC LIMIT 1")
        # clickhouse-connect may return a QueryResult or a list-like; handle both
        try:
            # QueryResult has attributes like .result_set or .rows
            if hasattr(res, "result_set"):
                rows = res.result_set
            elif hasattr(res, "rows"):
                rows = res.rows
            else:
                rows = res
        except Exception:
            rows = res

        # rows may be a QueryResult, list of tuples, or list of dicts
        if not rows:
            return None
        # If rows is a QueryResult-like with first() method
        if hasattr(rows, "first"):
            first = rows.first()
            if isinstance(first, dict):
                return first.get("value")
            if isinstance(first, (list, tuple)) and len(first) > 0:
                return first[0]
        # If rows is list-like
        try:
            first = rows[0]
            if isinstance(first, dict):
                return first.get("value")
            if isinstance(first, (list, tuple)) and len(first) > 0:
                return first[0]
        except Exception:
            pass
    except Exception:
        logger.exception("Failed to fetch latest setting %s", key)
    finally:
        try:
            client.close()
        except Exception:
            pass
    return None

# Import shared SQLAlchemy models for future use
from shared.models import Base, CTLog, CTLogSlice, CTLogSource, CTLogOperator, CTCert, CTSetting
