import importlib
import pkgutil
import logging
import traceback
from pathlib import Path

from services.dashboard.app import modules

logger = logging.getLogger(__name__)


def _try_register(app, module_path, submodule):
    """
    Try to register a blueprint from a module path.
    Args:
        app: Flask application
        module_path: Dot-separated module path (e.g., 'songbook.songs' or 'song')
        submodule: The submodule to import ('controller' or 'views')
    Returns:
        bool: True if successfully registered, False otherwise
    Raises:
        ImportError: Re-raised with full traceback if the module exists but fails to import
    """
    full_import_path = f"services.dashboard.app.modules.{module_path}.{submodule}"
    module_logger = logging.getLogger(f"services.dashboard.app.modules.{module_path}")

    try:
        mod = importlib.import_module(full_import_path)
    except ModuleNotFoundError as exc:
        # Only silently skip if the module itself doesn't exist (i.e. no controller/views file).
        # If the module *does* exist but has a broken import inside it, we must surface the error.
        if exc.name == full_import_path:
            module_logger.debug("No %s module for %s", submodule, module_path)
            return False
        # A dependency inside the module is missing — log the full traceback and re-raise.
        tb = traceback.format_exc()
        module_logger.error(
            "Import error in %s.%s (missing dependency: %s):\n%s",
            module_path, submodule, exc.name, tb,
        )
        raise
    except Exception:
        tb = traceback.format_exc()
        module_logger.error(
            "Error importing %s.%s:\n%s",
            module_path, submodule, tb,
        )
        raise

    if hasattr(mod, "bp"):
        bp = mod.bp
        if bp.url_prefix is None:
            url_prefix = "/" + module_path.replace(".", "/")
            bp.url_prefix = url_prefix
            module_logger.info(
                "Auto-configured url_prefix '%s' for %s.%s",
                url_prefix, module_path, submodule,
            )

        app.register_blueprint(bp)
        module_logger.info(
            "Registered blueprint: %s.%s at %s",
            module_path, submodule, bp.url_prefix,
        )
        return True
    else:
        module_logger.warning("No 'bp' in %s.%s", module_path, submodule)
        return False


def _discover_modules(base_path, parent_module=""):
    """
    Recursively discover all modules in the modules directory.
    Args:
        base_path: Path to search for modules
        parent_module: Parent module path (dot-separated)
    Yields:
        str: Module paths (dot-separated, e.g., 'song', 'songbook.songs')
    """
    for item in pkgutil.iter_modules([str(base_path)]):
        module_name = item.name
        if module_name == "loader":
            continue
        full_module_path = f"{parent_module}.{module_name}" if parent_module else module_name
        module_dir = base_path / module_name
        has_blueprint = (
            (module_dir / "controller.py").exists() or
            (module_dir / "views.py").exists()
        )
        if has_blueprint:
            yield full_module_path
        if module_dir.is_dir() and (module_dir / "__init__.py").exists():
            yield from _discover_modules(module_dir, full_module_path)


def register_blueprints(app):
    """
    Recursively discover and register all blueprints in the modules directory.
    The folder structure defines the base route automatically.
    For each module, both controller.py and views.py can be registered if they exist.
    They will share the same url_prefix based on the folder structure.

    Modules that fail to import are logged and skipped so
    that the remaining modules can still load.
    """
    modules_path = Path(modules.__path__[0])
    for module_path in _discover_modules(modules_path):
        found = False
        for sub in ("controller", "views"):
            try:
                if _try_register(app, module_path, sub):
                    found = True
            except Exception:
                logger.error(
                    "Skipping %s.%s due to import error.",
                    module_path, sub,
                )

        if not found:
            logger.warning(
                "No blueprint found for module '%s'. "
                "Expected at least one of app.modules.%s.controller "
                "or .views defining 'bp'.",
                module_path, module_path,
            )