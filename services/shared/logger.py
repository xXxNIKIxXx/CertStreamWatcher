import logging
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

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