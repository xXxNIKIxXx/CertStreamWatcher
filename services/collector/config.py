"""Configuration constants for the CertStream collector service.

All tunables can be overridden via environment variables.
"""

import os
from services.shared.config import DB_DSN

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
DB = DB_DSN   # alias used by new collector


SINGLE_NODE    = os.getenv("SINGLE_NODE", "1").strip().lower() in ("1", "true", "yes")
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
