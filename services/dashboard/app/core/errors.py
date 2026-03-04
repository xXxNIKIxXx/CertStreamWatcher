import logging
from flask import render_template, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """Register global error handlers for user-friendly pages."""

    @app.errorhandler(404)
    def handle_not_found(err):
        app.logger.info("404 Not Found at path %s", request.path)
        return (
            render_template(
                "error.html",
                error_message="Die angeforderte Seite wurde nicht gefunden.",
                status_code=404,
                path=request.path,
            ),
            404,
        )

    @app.errorhandler(Exception)
    def handle_exception(err):
        # HTTPExceptions carry an HTTP status code; treat others as 500.
        if isinstance(err, HTTPException):
            status_code = err.code or 500
            description = err.description or "Es ist ein Fehler aufgetreten."
            app.logger.warning(
                "HTTP error %s on path %s: %s", status_code, request.path, description
            )
            return (
                render_template(
                    "error.html",
                    error_message=description,
                    status_code=status_code,
                    path=request.path,
                ),
                status_code,
            )

        # Non-HTTP exceptions are treated as 500 and logged with stacktrace.
        app.logger.exception("Unhandled exception on path %s", request.path)
        return (
            render_template(
                "error.html",
                error_message=(
                    "Es ist ein unerwarteter Fehler aufgetreten. "
                    "Bitte versuchen Sie es erneut oder wenden Sie sich an den Support."
                ),
                status_code=500,
                path=request.path,
            ),
            500,
        )
