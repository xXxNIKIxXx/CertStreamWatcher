"""Configuration constants for the CertStream collector service.

All tunables can be overridden via environment variables.
"""

import os
import logging
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# CT log list (Google's public list)
LOG_LIST_URL = os.getenv(
    "CT_LOG_LIST_URL",
    "https://www.gstatic.com/ct/log_list/v3/log_list.json",
)

# Polling / batching knobs
BATCH_SIZE      = int(os.getenv("CT_BATCH_SIZE", "265"))
POLL_INTERVAL   = 2      # seconds between idle poll cycles
BACKFILL_DELAY  = 2      # seconds between backfill cycles



# Database
DB_FLUSH_INTERVAL = 5
DB_DSN = os.getenv(
    "CT_DB_DSN",
    "clickhouse+http://default:@localhost:8123/certstream",
)
DB = DB_DSN   # alias used by new collector


SINGLE_NODE    = os.getenv("SINGLE_NODE", "0").strip().lower() in ("1", "true", "yes")
# Redis config removed: all load balancing is now via worker index and DB polling.
if SINGLE_NODE:
    WORKER_INDEX = 0
    WORKER_COUNT = 1
else:
    WORKER_INDEX = int(os.getenv("CT_WORKER_INDEX", "0"))
    WORKER_COUNT = int(os.getenv("CT_WORKER_COUNT", "1"))

# Observability
PROMETHEUS_PORT = int(os.getenv("CT_PROMETHEUS_PORT", "8001"))

USER_AGENT = "Mozilla/5.0 (compatible; CertStreamWatcher/1.0 (+n@f.de))"

# ── Logging ────────────────────────────────────────────────────────────

LEVEL_COLORS = {
    "DEBUG":    Fore.CYAN,
    "INFO":     Fore.GREEN,
    "WARNING":  Fore.YELLOW,
    "ERROR":    Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}

DEFAULT_FMT    = "%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s"
DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


class ColorFormatter(logging.Formatter):
    def __init__(self, use_color: bool = True, fmt=None, datefmt=None):
        self.use_color = use_color
        super().__init__(fmt=fmt or DEFAULT_FMT, datefmt=datefmt or DEFAULT_DATEFMT)

    def format(self, record: logging.LogRecord) -> str:
        if self.use_color:
            color = LEVEL_COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger.  propagate=False prevents duplicate console output."""
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    log.propagate = False
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(ColorFormatter(use_color=True))
        log.addHandler(h)
    return log
