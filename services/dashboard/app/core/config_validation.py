import logging

logger = logging.getLogger(__name__)


def validate_required_config(app):
    """Validate keys listed in `app.config['REQUIRED']`.

    If any required key is missing or empty, log a critical error and raise
    a RuntimeError to abort application startup.
    """
    required = app.config.get("REQUIRED") or []
    missing = []
    for key in required:
        val = app.config.get(key)
        if val is None or (isinstance(val, str) and val.strip() == ""):
            missing.append(key)

    if missing:
        msg = ", ".join(missing)
        logger.critical("Missing required configuration keys: %s", msg)
        raise RuntimeError(f"Missing required configuration keys: {msg}")
