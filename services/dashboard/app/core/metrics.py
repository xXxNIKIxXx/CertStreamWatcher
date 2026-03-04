"""Prometheus metrics for the CertStreamWatcher dashboard (Flask app).

Exposes a ``/metrics`` endpoint via the ``prometheus_client`` WSGI app
and registers request-level instrumentation as Flask before/after hooks.
"""

import logging
import time

from flask import Flask, request

logger = logging.getLogger(__name__)

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    PROM_AVAILABLE = True
except ImportError:
    PROM_AVAILABLE = False

# ---------------------------------------------------------------------------
# Module-level registry & metrics (created once on import)
# ---------------------------------------------------------------------------

if PROM_AVAILABLE:
    # ---- Build / service info ----
    APP_INFO = Info(
        "ct_dashboard", "Dashboard service build information"
    )
    APP_INFO.info({"service": "dashboard"})

    # ---- HTTP request metrics ----
    REQUEST_COUNT = Counter(
        "ct_dashboard_http_requests_total",
        "Total HTTP requests received by the dashboard",
        ["method", "endpoint", "status"],
    )
    REQUEST_DURATION = Histogram(
        "ct_dashboard_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "endpoint"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    REQUEST_IN_PROGRESS = Gauge(
        "ct_dashboard_http_requests_in_progress",
        "HTTP requests currently being processed",
        ["method", "endpoint"],
    )
    RESPONSE_SIZE = Histogram(
        "ct_dashboard_http_response_size_bytes",
        "HTTP response body size in bytes",
        ["method", "endpoint"],
        buckets=(100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000),
    )

    # ---- SocketIO / real-time ----
    SOCKETIO_CONNECTIONS = Gauge(
        "ct_dashboard_socketio_connections",
        "Current number of SocketIO client connections",
    )
    SOCKETIO_EVENTS_EMITTED = Counter(
        "ct_dashboard_socketio_events_emitted_total",
        "Total SocketIO events emitted to clients",
        ["event"],
    )

    # ---- Certificate buffer (in-memory from Redis subscriber) ----
    CERT_BUFFER_SIZE = Gauge(
        "ct_dashboard_cert_buffer_size",
        "Number of certificates held in the in-memory ring buffer",
    )
    REDIS_SUBSCRIBER_STATUS = Gauge(
        "ct_dashboard_redis_subscriber_up",
        "Whether the Redis cert subscriber is alive"
        " (1=yes, 0=no)",
    )

    # ---- Database query metrics (dashboard-side reads) ----
    DB_QUERY_COUNT = Counter(
        "ct_dashboard_db_queries_total",
        "Total database queries executed by the dashboard",
        ["endpoint"],
    )
    DB_QUERY_DURATION = Histogram(
        "ct_dashboard_db_query_duration_seconds",
        "Time spent executing dashboard database queries",
        ["endpoint"],
        buckets=(0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    DB_QUERY_ERRORS = Counter(
        "ct_dashboard_db_query_errors_total",
        "Failed database queries on the dashboard",
        ["endpoint"],
    )


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------


def init_metrics(app: Flask) -> None:
    """Register Prometheus instrumentation hooks and ``/metrics`` endpoint."""
    if not PROM_AVAILABLE:
        logger.warning(
            "prometheus_client not installed; "
            "dashboard metrics disabled"
        )
        return

    # -- before / after hooks for automatic request instrumentation --------

    @app.before_request
    def _start_timer():
        request._prom_start = time.monotonic()
        endpoint = request.endpoint or "unknown"
        REQUEST_IN_PROGRESS.labels(
            method=request.method, endpoint=endpoint
        ).inc()

    @app.after_request
    def _record_metrics(response):
        endpoint = request.endpoint or "unknown"
        status = str(response.status_code)
        method = request.method

        # Duration
        start = getattr(request, "_prom_start", None)
        if start is not None:
            elapsed = time.monotonic() - start
            REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(
                elapsed
            )

        # Counter
        REQUEST_COUNT.labels(
            method=method, endpoint=endpoint, status=status
        ).inc()

        # In-progress (decrement)
        REQUEST_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()

        # Response size
        content_length = response.content_length
        if content_length is not None:
            RESPONSE_SIZE.labels(method=method, endpoint=endpoint).observe(
                content_length
            )

        return response

    # -- /metrics endpoint served by prometheus_client WSGI app ------------

    @app.route("/metrics")
    def prometheus_metrics():
        """Expose Prometheus metrics at ``/metrics``."""
        from flask import Response as FlaskResponse

        # Delegate to the prometheus_client WSGI app
        body = generate_latest()
        return FlaskResponse(body, mimetype=CONTENT_TYPE_LATEST)

    logger.info("Prometheus metrics enabled at /metrics")
