import logging


def get_logger(name: str) -> logging.Logger:
    """Create and configure a logger with a standard format."""
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s"
            )
        )
        log.addHandler(handler)
    return log
