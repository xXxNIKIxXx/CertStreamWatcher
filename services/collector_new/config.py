"""Configuration constants for the CertStream collector service.

All tunables can be overridden via environment variables.
"""

import os
import logging
from colorama import Fore, Style, init as colorama_init


colorama_init(autoreset=True)

# Polling / batching knobs
BATCH_SIZE = int(os.getenv("CT_BATCH_SIZE", "265"))
POLL_INTERVAL = 2          # seconds between idle poll cycles
BACKFILL_DELAY = 2         # seconds between backfill cycles

# Network
WEBSOCKET_PORT = 8765

DB = os.getenv(
    "CT_DB_DSN",
    "clickhouse+http://default:@localhost:8123/certstream"
)

# Database
DB_FLUSH_INTERVAL = 5      # seconds between periodic DB flushes
DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse://default:@clickhouse:8123/certstream",
)


# SINGLE_NODE disables Redis and sharding, uses only WebSocket for events
REDIS_URL = os.getenv("CT_REDIS_URL") or None
REDIS_DISABLED = (os.getenv("CT_REDIS_DISABLE", "0").strip() == "1")

# Worker sharding
if REDIS_DISABLED:
    WORKER_INDEX = 0
    WORKER_COUNT = 1
else:
    WORKER_INDEX = int(os.getenv("CT_WORKER_INDEX", "0"))
    WORKER_COUNT = int(os.getenv("CT_WORKER_COUNT", "1"))

# Observability
PROMETHEUS_PORT = 8000

LEVEL_COLORS = {
    "DEBUG": Fore.CYAN,
    "INFO": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

DEFAULT_FMT = "%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s"
DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"

USER_AGENT = "Mozilla/5.0 (compatible; CertStreamWatcher/1.0; spam44@gmail.com)"

class ColorFormatter(logging.Formatter):
    """Formatter that optionally adds color to the levelname.

    The default format is a conventional log line:
    2025-11-16 12:34:56 INFO app.modules.song:35 - Message
    """

    def __init__(self, use_color: bool | None = None, fmt: str | None = None, datefmt: str | None = None):
        self.use_color = bool(use_color)
        self._fmt = fmt or DEFAULT_FMT
        self.datefmt = datefmt or DEFAULT_DATEFMT
        super().__init__(fmt=self._fmt, datefmt=self.datefmt)

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        if self.use_color:
            color = LEVEL_COLORS.get(levelname, "")
            levelname_colored = f"{color}{levelname}{Style.RESET_ALL}"
        else:
            levelname_colored = levelname

        record.levelname = levelname_colored
        # Keep using the underlying formatter to produce the final string
        return super().format(record)


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
        handler.setFormatter(ColorFormatter(use_color=True))
        log.addHandler(handler)
    return log
