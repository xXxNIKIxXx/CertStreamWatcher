"""Configuration for the CertStream API service."""

import os

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse://default:@clickhouse:8123/certstream",
)
DB_MIN_POOL = int(os.getenv("CT_DB_MIN_POOL", "2"))
DB_MAX_POOL = int(os.getenv("CT_DB_MAX_POOL", "10"))

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
API_HOST = os.getenv("CT_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("CT_API_PORT", "8080"))
API_WORKERS = int(os.getenv("CT_API_WORKERS", "1"))
PROMETHEUS_PORT = int(os.getenv("CT_API_PROM_PORT", "9090"))

# ---------------------------------------------------------------------------
# Pagination defaults
# ---------------------------------------------------------------------------
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
