"""Configuration constants for the CertStream collector service.

All tunables can be overridden via environment variables.
"""

import os
import logging

# CT log list endpoint
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Polling / batching knobs
BATCH_SIZE = int(os.getenv("CT_BATCH_SIZE", "500"))
POLL_INTERVAL = 2          # seconds between idle poll cycles
BACKFILL_DELAY = 2         # seconds between backfill cycles

# Network
WEBSOCKET_PORT = 8765

# Database
DB_FLUSH_INTERVAL = 5      # seconds between periodic DB flushes
DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse://default:@clickhouse:8123/certstream",
)


# SINGLE_NODE disables Redis and sharding, uses only WebSocket for events
SINGLE_NODE = os.getenv("SINGLE_NODE", "0").strip().lower() in ("1", "true", "yes")
REDIS_URL = os.getenv("CT_REDIS_URL") or None
REDIS_DISABLED = SINGLE_NODE or (os.getenv("CT_REDIS_DISABLE", "0").strip() == "1")

# Worker sharding
if SINGLE_NODE:
    WORKER_INDEX = 0
    WORKER_COUNT = 1
else:
    WORKER_INDEX = int(os.getenv("CT_WORKER_INDEX", "0"))
    WORKER_COUNT = int(os.getenv("CT_WORKER_COUNT", "1"))

# Observability
PROMETHEUS_PORT = 8000


def get_logger(name: str) -> logging.Logger:
    """Return a named logger with a standard format.

    Sets ``propagate = False`` to prevent duplicate output when both the
    named logger and the root logger have handlers attached.
    """
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    log.propagate = False

    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        log.addHandler(handler)
    return log
