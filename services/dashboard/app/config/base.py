import os


class BaseConfig:
    """Base configuration. Sensitive values should come from environment.

    The `REQUIRED` list declares keys that must be present (non-empty) in
    `app.config` at startup; the app will abort with a critical log if any
    of these are missing.
    """

    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    FLASK_ENV = os.getenv("FLASK_ENV")

    LOG_LEVEL = os.getenv("LOG_LEVEL", "Info")
    LOG_FILE = os.getenv("LOG_FILE")

    SECRET_KEY = os.getenv("SECRET_KEY")

    # Keys that must be present for the application to run.
    REQUIRED = [
        "SECRET_KEY"
    ]
