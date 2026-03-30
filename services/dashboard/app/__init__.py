# coding=utf-8
"""
Flask Application Factory.

This module contains the application factory for creating and configuring
the Flask application instance. It handles initialization of database,
OAuth, logging, blueprints, and other core components.
"""

# Standard library imports
import logging
import os
from importlib import import_module
from pathlib import Path

# Real-time socket server

# Third-party imports
from flask import (
    Flask,
    Response
)
# Local imports
from .core.config_validation import validate_required_config
from .core.errors import register_error_handlers
from .core.logging import configure_logging
from .core.metrics import init_metrics
from .modules.loader import register_blueprints

from services.dashboard.app.core import clickhouse 

logger = logging.getLogger(__name__)


def get_config_class(env_name):
    """
    Dynamically load and return the configuration class for the
    specified environment.

    Args:
        env_name (str): The environment name (e.g., 'development',
            'production', 'test').

    Returns:
        class: The configuration class for the specified environment.

    Raises:
        ValueError: If no config class is found for the given
            environment.
    """
    try:
        module = import_module(f"services.dashboard.app.config.{env_name}.{env_name}")
        logger.info(f"Loaded config module: services.dashboard.app.config.{env_name}.{env_name}")
        return getattr(module, f"{env_name.capitalize()}Config")
    except (ModuleNotFoundError, AttributeError):
        raise ValueError(f"No config class found for environment '{env_name}'")

# Table definitions for operator/log structure
_CREATE_OPERATORS_SQL = """
CREATE TABLE IF NOT EXISTS ct_log_operators (
    id UUID DEFAULT generateUUIDv4(),
    name String,
    email Array(String),
    added_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree()
ORDER BY (added_at, id)
PARTITION BY toYYYYMM(added_at)
"""

_CREATE_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS ct_logs (
    id UUID DEFAULT generateUUIDv4(),
    operator_id UUID,
    description String,
    log_id String,
    key String,
    url String,
    mmd Int32,
    state String,
    temporal_interval_start DateTime64(3, 'UTC'),
    temporal_interval_end DateTime64(3, 'UTC'),
    current_index UInt64 DEFAULT 0,
    log_length UInt64 DEFAULT 0,
    status String,
    added_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree()
ORDER BY (added_at, id)
PARTITION BY toYYYYMM(added_at)
"""

def ensure_tables():
    client = clickhouse.get_client()
    client.command(_CREATE_OPERATORS_SQL)
    client.command(_CREATE_LOGS_SQL)


def create_app():
    """
    Create and configure the Flask application instance.

    This factory function initializes all components including:
    - Logging configuration
    - Database connections and migrations
    - OAuth authentication
    - Blueprint registration
    - Error handlers
    - Monitoring tools (Sentry, Prometheus, etc.)

    Returns:
        Flask: A configured Flask application instance.
    """
    app = Flask(__name__)

    
    configure_logging(
        app,
        level=os.getenv("LOG_LEVEL", "Info"),
        use_color=True
    )

    try:
        from .core.logging import JsonFormatter
        project_root = Path(__file__).resolve().parents[1]
        logs_dir = project_root / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / os.getenv("LOG_FILE", "CertStreamWatcher.log")

        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(JsonFormatter())

        root_logger = logging.getLogger()
        root_logger.addHandler(fh)

        for logger_name in ("flask.app", "flask", "werkzeug"):
            logger_child = logging.getLogger(logger_name)
            logger_child.addHandler(fh)

        logger.info(f"File logging enabled: {log_file}")
    except Exception:
        logger.exception("Failed to set up file logging")

    config_class = get_config_class(os.getenv("FLASK_ENV"))
    app.config.from_object(config_class)
    validate_required_config(app)
    logger.info(f"App configured for environment: {os.getenv('FLASK_ENV')}")

    # Prometheus metrics instrumentation
    init_metrics(app)


    logger.info("Registering blueprints...")
    register_blueprints(app)
    # Register alerts blueprint explicitly
    try:
        from app.modules.alerts.views import bp as alerts_bp
        app.register_blueprint(alerts_bp)
        logger.info("Alerts blueprint registered at /alerts")
    except Exception as e:
        logger.error(f"Failed to register alerts blueprint: {e}")
    logger.info("Blueprints registered.")

    @app.route("/robots.txt")
    def robots_txt():
        """
        Serve robots.txt file to prevent search engine indexing.

        Returns:
            Response: A text/plain response disallowing all web crawlers.
        """
        return Response("User-agent: *\nDisallow: /", mimetype="text/plain")

    def _import_models_recursive(base_path, parent_module=""):
        """
        Recursively import models from all modules.

        This ensures SQLAlchemy's metadata contains all models when
        running database migrations with `flask db migrate
        --autogenerate`.

        Args:
            base_path (Path): The base directory path to search for
                modules.
            parent_module (str): The parent module path for building
                full module names.
        """
        import pkgutil
        import importlib
        for item in pkgutil.iter_modules([str(base_path)]):
            module_name = item.name
            if module_name == "loader":
                continue
            if parent_module:
                full_module_path = f"{parent_module}.{module_name}"
            else:
                full_module_path = f"app.modules.{module_name}"
            module_dir = base_path / module_name
            try:
                importlib.import_module(f"{full_module_path}.models")
                logger.info(f"Imported models for module: {full_module_path}")
            except ModuleNotFoundError:
                pass
            if module_dir.is_dir() and (module_dir / "__init__.py").exists():
                _import_models_recursive(module_dir, full_module_path)
    try:
        import services.dashboard.app.modules as modules_pkg
        modules_path = Path(modules_pkg.__path__[0])
        _import_models_recursive(modules_path)
    except Exception:
        logger.exception("Failed to import module models for migrations")



    # logger.info("Initializing database...")
    # migrate.init_app(app, db, render_as_batch=True)
    # logger.info("Database migration initialized.")
    # db.init_app(app)
    # logger.info("Database initialized.")

    # with app.app_context():
    #     logger.info("Creating database tables if not exist...")
    #     db.create_all()
    #     logger.info("Database tables ensured.")

    register_error_handlers(app)

    with app.app_context():
        try:
            ensure_tables()
            logger.info("Database tables ensured.")
        except Exception:
            logger.exception("Failed to ensure database tables")

    return app
