"""Prometheus metrics definitions and no-op fallbacks."""

from .config import get_logger, PROMETHEUS_PORT

logger = get_logger("CTStreamService.Metrics")

try:
    from prometheus_client import (
        start_http_server,
        Counter,
        Gauge,
        Histogram,
        Info,
    )

    PROM_AVAILABLE = True
except Exception:
    PROM_AVAILABLE = False


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
        """Return a context manager that does nothing."""
        import contextlib

        return contextlib.nullcontext()

    def observe(self, *_a, **_kw):
        pass

    def info(self, *_a, **_kw):
        pass


class MetricsManager:
    """Encapsulates all Prometheus metrics used by the collector."""

    def __init__(self) -> None:
        self._noop = _NoopMetric()

        if PROM_AVAILABLE:
            self._start_server()
            self._register_metrics()
        else:
            logger.warning("prometheus_client not available; metrics disabled")
            self._register_noops()

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------

    def _start_server(self) -> None:
        try:
            start_http_server(PROMETHEUS_PORT)
            logger.info(
                "Prometheus metrics server started on :%s",
                PROMETHEUS_PORT,
            )
        except Exception as exc:
            logger.warning(
                "Could not start Prometheus metrics server: %s",
                exc,
            )

    # ------------------------------------------------------------------
    # Real metrics
    # ------------------------------------------------------------------

    def _register_metrics(self) -> None:
        # ---- Build info ----
        self.build_info = Info(
            "ct_collector", "Collector service build information"
        )
        self.build_info.info({"service": "collector"})

        # ---- General counters ----
        self.entries_processed = Counter(
            "ct_entries_processed_total", "Total CT log entries processed"
        )
        self.parse_failures = Counter(
            "ct_parse_failures_total", "Certificate parse failures"
        )
        self.extraction_failures = Counter(
            "ct_extraction_failures_total", "Certificate extraction failures"
        )
        self.poll_errors = Counter(
            "ct_poll_errors_total", "Errors while polling CT logs"
        )
        self.skipped_logs = Counter(
            "ct_skipped_unresolvable_logs_total",
            "CT logs skipped due to DNS resolution failure",
        )
        self.parse_successes = Counter(
            "ct_entries_parsed_success_total",
            "Successfully parsed CT entries",
        )

        # ---- Gauges ----
        self.active_clients = Gauge(
            "ct_websocket_active_clients",
            "Currently connected WebSocket clients",
        )
        self.total_logs = Gauge(
            "ct_total_logs", "Number of CT logs being monitored"
        )

        # ---- Histograms ----
        self.parse_duration = Histogram(
            "ct_cert_parse_seconds",
            "Time spent parsing a single certificate (seconds)",
            buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
        )

        # ---- Per-log counters / gauges ----
        self.certs_by_log = Counter(
            "ct_certs_processed_by_log_total",
            "Certificates successfully processed per CT log",
            ["log"],
        )
        self.extraction_failures_by_log = Counter(
            "ct_extraction_failures_by_log_total",
            "Extraction failures per CT log",
            ["log"],
        )
        self.parse_failures_by_log = Counter(
            "ct_parse_failures_by_log_total",
            "Parse failures per CT log",
            ["log"],
        )
        self.last_index = Gauge(
            "ct_log_last_index",
            "Last processed tree index per CT log",
            ["log"],
        )

        # ---- Entry / leaf classification ----
        self.skipped_entry_type = Counter(
            "ct_skipped_entry_type_total",
            "Skipped entries by entry_type",
            ["entry_type"],
        )
        self.leaf_version = Counter(
            "ct_leaf_version_total",
            "MerkleTreeLeaf version distribution",
            ["version"],
        )
        self.leaf_type = Counter(
            "ct_leaf_type_total",
            "MerkleTreeLeaf leaf_type distribution",
            ["leaf_type"],
        )
        self.cert_version = Counter(
            "ct_certificate_version_total",
            "Certificate version distribution (v1/v2/v3)",
            ["version"],
        )

        # ---- Database metrics ----
        self.db_writes_total = Counter(
            "ct_db_writes_total",
            "Total certificate writes attempted to the database",
        )
        self.db_write_errors_total = Counter(
            "ct_db_write_errors_total",
            "Failed certificate writes to the database",
        )
        self.db_write_duration_seconds = Histogram(
            "ct_db_write_duration_seconds",
            "Time spent writing a certificate to the database",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        )
        self.db_pool_size = Gauge(
            "ct_db_pool_size",
            "Current database connection pool size",
        )
        self.db_available = Gauge(
            "ct_db_available",
            "Whether the database connection is available (1=yes, 0=no)",
        )

        # ---- Redis metrics ----
        self.redis_publishes_total = Counter(
            "ct_redis_publishes_total",
            "Total messages published to Redis",
        )
        self.redis_publish_errors_total = Counter(
            "ct_redis_publish_errors_total",
            "Failed Redis publish operations",
        )
        self.redis_publish_duration_seconds = Histogram(
            "ct_redis_publish_duration_seconds",
            "Time spent publishing a message to Redis",
            buckets=(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1),
        )
        self.redis_available = Gauge(
            "ct_redis_available",
            "Whether the Redis connection is available (1=yes, 0=no)",
        )

        # ---- WebSocket broadcast metrics ----
        self.ws_broadcasts_total = Counter(
            "ct_ws_broadcasts_total",
            "Total WebSocket broadcast attempts",
        )
        self.ws_broadcast_errors_total = Counter(
            "ct_ws_broadcast_errors_total",
            "Failed WebSocket message deliveries to individual clients",
        )
        self.ws_broadcast_duration_seconds = Histogram(
            "ct_ws_broadcast_duration_seconds",
            "Time spent broadcasting a message to all WebSocket clients",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
        )

        # ---- HTTP fetch metrics (CT log API calls) ----
        self.http_requests_total = Counter(
            "ct_http_requests_total",
            "Total HTTP requests made to CT log APIs",
            ["method", "status"],
        )
        self.http_request_duration_seconds = Histogram(
            "ct_http_request_duration_seconds",
            "Time spent on HTTP requests to CT log APIs",
            buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

        # ---- Batch processing metrics ----
        self.batch_entries_fetched = Histogram(
            "ct_batch_entries_fetched",
            "Number of entries fetched per batch from a CT log",
            buckets=(1, 10, 50, 100, 250, 500),
        )
        self.batch_processing_duration_seconds = Histogram(
            "ct_batch_processing_duration_seconds",
            "Time spent processing a single batch of CT log entries",
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
        )

    # ------------------------------------------------------------------
    # No-op fallbacks
    # ------------------------------------------------------------------

    def _register_noops(self) -> None:
        self.build_info = self._noop
        self.entries_processed = self._noop
        self.parse_failures = self._noop
        self.extraction_failures = self._noop
        self.poll_errors = self._noop
        self.skipped_logs = self._noop
        self.parse_successes = self._noop
        self.active_clients = self._noop
        self.total_logs = self._noop
        self.parse_duration = self._noop
        self.certs_by_log = self._noop
        self.extraction_failures_by_log = self._noop
        self.parse_failures_by_log = self._noop
        self.last_index = self._noop
        self.skipped_entry_type = self._noop
        self.leaf_version = self._noop
        self.leaf_type = self._noop
        self.cert_version = self._noop
        # DB
        self.db_writes_total = self._noop
        self.db_write_errors_total = self._noop
        self.db_write_duration_seconds = self._noop
        self.db_pool_size = self._noop
        self.db_available = self._noop
        # Redis
        self.redis_publishes_total = self._noop
        self.redis_publish_errors_total = self._noop
        self.redis_publish_duration_seconds = self._noop
        self.redis_available = self._noop
        # WebSocket
        self.ws_broadcasts_total = self._noop
        self.ws_broadcast_errors_total = self._noop
        self.ws_broadcast_duration_seconds = self._noop
        # HTTP
        self.http_requests_total = self._noop
        self.http_request_duration_seconds = self._noop
        # Batch
        self.batch_entries_fetched = self._noop
        self.batch_processing_duration_seconds = self._noop
