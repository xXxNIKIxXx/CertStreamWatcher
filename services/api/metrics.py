"""Prometheus metrics for the CertStream API service."""

from __future__ import annotations

from .config import PROMETHEUS_PORT

from services.shared.logger import get_logger

logger = get_logger(__name__)

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        start_http_server
    )

    PROM_AVAILABLE = True
except ImportError:
    PROM_AVAILABLE = False


# ---------------------------------------------------------------------------
# No-op fallback
# ---------------------------------------------------------------------------

class _NoopMetric:
    """No-op stand-in when prometheus_client is not installed."""

    def inc(self, *_a, **_kw):
        pass

    def dec(self, *_a, **_kw):
        pass

    def set(self, *_a, **_kw):
        pass

    def labels(self, **_kw):
        return self

    def time(self):
        import contextlib
        return contextlib.nullcontext()

    def observe(self, *_a, **_kw):
        pass

    def info(self, *_a, **_kw):
        pass


# ---------------------------------------------------------------------------
# Metrics manager
# ---------------------------------------------------------------------------

class ApiMetrics:
    """Prometheus metrics for the REST API."""

    def __init__(self) -> None:
        self._noop = _NoopMetric()
        if PROM_AVAILABLE:
            self._start_server()
            self._register()
        else:
            logger.warning("prometheus_client not available; metrics disabled")
            self._register_noops()

    # -- server -----------------------------------------------------------

    def _start_server(self) -> None:
        try:
            start_http_server(PROMETHEUS_PORT)
            logger.info("Prometheus metrics server on :%s", PROMETHEUS_PORT)
        except Exception as exc:
            logger.warning("Could not start Prometheus metrics server: %s", exc)

    # -- real metrics -----------------------------------------------------

    def _register(self) -> None:
        # Build info
        self.build_info = Info("ct_api", "API service build information")
        self.build_info.info({"service": "api"})

        # HTTP request metrics
        self.http_requests_total = Counter(
            "ct_api_http_requests_total",
            "Total HTTP requests handled by the API",
            ["method", "endpoint", "status"],
        )
        self.http_request_duration = Histogram(
            "ct_api_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "endpoint"],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
        )
        self.http_requests_in_progress = Gauge(
            "ct_api_http_requests_in_progress",
            "HTTP requests currently in flight",
            ["method", "endpoint"],
        )
        self.http_response_size = Histogram(
            "ct_api_http_response_size_bytes",
            "HTTP response body size",
            ["method", "endpoint"],
            buckets=(100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000),
        )

    # -- no-ops -----------------------------------------------------------

    def _register_noops(self) -> None:
        self.build_info = self._noop
        self.http_requests_total = self._noop
        self.http_request_duration = self._noop
        self.http_requests_in_progress = self._noop
        self.http_response_size = self._noop
