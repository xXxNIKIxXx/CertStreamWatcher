"""Configuration constants for the CertStream collector service."""

import os
import logging

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
BATCH_SIZE = 500
POLL_INTERVAL = 2
BACKFILL_DELAY = 2
WEBSOCKET_PORT = 8765
DB_FLUSH_INTERVAL = 5
WORKER_INDEX = int(os.getenv("CT_WORKER_INDEX", "0"))
WORKER_COUNT = int(os.getenv("CT_WORKER_COUNT", "1"))

DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse://default:@clickhouse:8123/certstream",
)
REDIS_URL = os.getenv("CT_REDIS_URL") or None

PROMETHEUS_PORT = 8000


def get_logger(name: str) -> logging.Logger:
    """Create and configure a logger with a standard format."""
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s"
                " %(name)s: %(message)s"
            )
        )
        log.addHandler(handler)
    return log
