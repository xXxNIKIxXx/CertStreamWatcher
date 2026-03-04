import importlib
import pkgutil
import logging
from pathlib import Path

from app import modules

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
    """
    full_import_path = f"app.modules.{module_path}.{submodule}"
    try:
        mod = importlib.import_module(full_import_path)
    except ModuleNotFoundError:
        # module-specific logger for clearer output
        logging.getLogger(f"app.modules.{module_path}").debug(
            "No %s module for %s", submodule, module_path
        )
        return False
    except Exception:
        logging.getLogger(f"app.modules.{module_path}").exception(
            "Error importing %s.%s", module_path, submodule
        )
        return False

    module_logger = logging.getLogger(f"app.modules.{module_path}")
    if hasattr(mod, "bp"):
        # Automatically set url_prefix based on folder path if not already set
        bp = mod.bp
        if bp.url_prefix is None:
            # Convert module path to URL path (e.g., 'songbook.songs' -> '/songbook/songs')
            url_prefix = "/" + module_path.replace(".", "/")
            bp.url_prefix = url_prefix
            module_logger.info(
                "Auto-configured url_prefix '%s' for %s.%s",
                url_prefix,
                module_path,
                submodule,
            )

        app.register_blueprint(bp)
        module_logger.info(
            "Registered blueprint: %s.%s at %s",
            module_path,
            submodule,
            bp.url_prefix,
        )
        return True
    else:
        module_logger.warning(
            "No 'bp' in %s.%s",
            module_path,
            submodule,
        )
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
        # Skip the loader module itself
        if module_name == "loader":
            continue
        # Build the full module path
        if parent_module:
            full_module_path = f"{parent_module}.{module_name}"
        else:
            full_module_path = module_name
        module_dir = base_path / module_name
        # Check if this module has controller.py or views.py
        has_blueprint = (
            (module_dir / "controller.py").exists() or
            (module_dir / "views.py").exists()
        )
        if has_blueprint:
            yield full_module_path
        # Recursively search subdirectories if this is a package
        if module_dir.is_dir() and (module_dir / "__init__.py").exists():
            yield from _discover_modules(module_dir, full_module_path)


def register_blueprints(app):
    """
    Recursively discover and register all blueprints in the modules directory.
    The folder structure defines the base route automatically.
    For each module, both controller.py and views.py can be registered if they exist.
    They will share the same url_prefix based on the folder structure.
    """
    modules_path = Path(modules.__path__[0])
    for module_path in _discover_modules(modules_path):
        found = False
        import_errors = []
        # Register both controller and views if they exist (don't break after first)
        for sub in ("controller", "views"):
            try:
                if _try_register(app, module_path, sub):
                    found = True
                    # Don't break - allow both to be registered
            except Exception as exc:  # pragma: no cover - defensive
                # capture exception details for diagnostics
                import traceback

                tb = traceback.format_exc()
                import_errors.append((sub, str(exc), tb))

        if not found:
            # Build a helpful error message including any import traceback
            msg = (
                f"No blueprint found for module '{module_path}'. "
                "Expected at least one of app.modules.{module_path}.controller "
                "or .views defining 'bp'."
            )
            if import_errors:
                details = []
                for sub, err, tb in import_errors:
                    details.append(f"Submodule '{sub}' import error: {err}\n{tb}")
                msg += "\n" + "\n".join(details)
            logger.warning(msg)  # Changed from raise to warning to continue loading other modules
