import logging
import sys
import json
import os
from datetime import datetime
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


DEFAULT_FMT = "%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s"
DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"


LEVEL_COLORS = {
    "DEBUG": Fore.CYAN,
    "INFO": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "CRITICAL": Fore.MAGENTA,
}


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


class JsonFormatter(logging.Formatter):
    """Formatter that outputs logs as JSON for structured logging.

    This format is ideal for log aggregation tools like Grafana Alloy/Loki
    because it makes the log level, timestamp, and other fields easily parseable.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "file": record.pathname,
            "line": record.lineno,
            "function": record.funcName,
            "message": record.getMessage(),
        }

        # Add exception info if present (e.g., from logger.exception())
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            log_data["level"] = "ERROR"  # Ensure exception logs are marked as ERROR

        # Add any extra fields that were passed to the logger
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        return json.dumps(log_data, ensure_ascii=False)


def configure_logging(app=None, level: str | int = None, use_color: bool | None = None):
    """Configure root logging for the app.

    - Clears existing root handlers to avoid duplicate output (useful during reloads).
    - Adds a stream handler with a readable formatter and optional colors.
    - Honors `app.config['LOG_LEVEL']` if provided.
    - Ensures Flask and Werkzeug loggers use the same handler/format so messages look consistent.
    - Uses JSON formatting in Docker/production for proper log parsing in Grafana.
    """
    root = logging.getLogger()

    # Allow passing app or reading configuration from Flask app
    if app is not None:
        cfg_level = app.config.get("LOG_LEVEL")
        if cfg_level:
            level = cfg_level

    if level is None:
        level = logging.INFO

    # Normalize level
    if isinstance(level, str):
        level = logging.getLevelName(level.upper())

    # Clear existing handlers to keep output tidy on dev reloads
    for h in list(root.handlers):
        root.removeHandler(h)

    # Use stderr for logs so they behave like typical applications/servers
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    # Use JSON logging in Docker/production environments for proper Grafana parsing
    # Detect if running in Docker by checking for common Docker env vars or /.dockerenv
    use_json = os.path.exists("/.dockerenv") or os.getenv("DOCKER_CONTAINER") == "true"

    if use_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(ColorFormatter(use_color=use_color))

    root.setLevel(level)
    root.addHandler(handler)

    # Make Flask and Werkzeug use the same handler/format so their messages look like normal logs.
    for name in ("flask.app", "flask", "werkzeug"):
        logger = logging.getLogger(name)
        # remove their handlers to avoid duplicated messages
        for h in list(logger.handlers):
            logger.removeHandler(h)
        logger.addHandler(handler)
        logger.setLevel(level)
        # Prevent double-printing via propagation; handler is already attached
        logger.propagate = False

    # Small confirmation
    root.debug("Logging configured (level=%s, format=%s)",
               logging.getLevelName(root.level),
               "JSON" if use_json else "colored")


def log_request_info():
    """Helper to log incoming request details for debugging."""
    from flask import request
    logger = logging.getLogger("app.request")
    logger.info(
        "Incoming request: method=%s path=%s remote_addr=%s user_agent=%s",
        request.method,
        request.path,
        request.remote_addr,
        request.user_agent.string
    )