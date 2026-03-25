"""
metrics.py – Centralised Prometheus metrics for the CertStream collector.

All metric objects live here so every module imports from one place.
Import this module before starting any workers so all counters are
registered before the HTTP server exposes them.

Naming convention:  ct_<subsystem>_<measurement>_<unit>
"""

from prometheus_client import Counter, Gauge, Histogram, Info

# ─────────────────────────────────────────────────────────────────────
# Service info
# ─────────────────────────────────────────────────────────────────────

service_info = Info(
    "ct_collector",
    "Static build/version information about the collector service",
)
service_info.info({"version": "1.0.0", "component": "certstream-collector"})


# ─────────────────────────────────────────────────────────────────────
# Certificate ingestion – volume & types
# ─────────────────────────────────────────────────────────────────────

# Certs that finished parsing and were enqueued for DB write.
# Labels: log_url, ct_entry_type (x509_entry | precert_entry)
certs_parsed_total = Counter(
    "ct_certs_parsed_total",
    "Total certificates successfully parsed, by log and entry type",
    ["log_url", "ct_entry_type"],
)

# Certs written into ClickHouse ct_certs.
# Labels: log_url
certs_written_total = Counter(
    "ct_certs_written_total",
    "Total certificates written to ClickHouse",
    ["log_url"],
)

# Failed DB writes (CertWriter.flush() threw an exception).
# Labels: log_url
cert_write_errors_total = Counter(
    "ct_cert_write_errors_total",
    "Total certificate batch write failures",
    ["log_url"],
)

# Top CAs by O= field in the issuer DN.
# Labels: issuer  (e.g. "Let's Encrypt", "DigiCert Inc")
certs_by_issuer_total = Counter(
    "ct_certs_by_issuer_total",
    "Total certificates by issuer organisation (O= from issuer DN)",
    ["issuer"],
)

# Pending cert rows buffered in CertWriter waiting for the next flush.
cert_writer_pending = Gauge(
    "ct_cert_writer_pending",
    "Parsed certs buffered in CertWriter not yet flushed to ClickHouse",
)


# ─────────────────────────────────────────────────────────────────────
# HTTP fetching – throughput, latency, errors, bytes
# ─────────────────────────────────────────────────────────────────────

# Every HTTP request attempted.
# Labels: log_url, fetch_type (rfc6962 | tiled_full | tiled_partial)
fetch_requests_total = Counter(
    "ct_fetch_requests_total",
    "Total HTTP fetch attempts",
    ["log_url", "fetch_type"],
)

# Requests that returned a usable response body.
fetch_success_total = Counter(
    "ct_fetch_success_total",
    "Total successful HTTP fetches (2xx with data)",
    ["log_url", "fetch_type"],
)

# Any non-success outcome tagged with the HTTP status or reason string.
# Labels: log_url, fetch_type, status_code (e.g. "404", "429", "timeout", "error")
fetch_errors_total = Counter(
    "ct_fetch_errors_total",
    "Total fetch failures by log, type, and status code",
    ["log_url", "fetch_type", "status_code"],
)

# Raw CT entries received from the wire (before parsing).
# Labels: log_url
entries_fetched_total = Counter(
    "ct_entries_fetched_total",
    "Total CT log entries received from the wire (before parsing)",
    ["log_url"],
)

# End-to-end HTTP round-trip time.
# Labels: log_url, fetch_type
fetch_duration_seconds = Histogram(
    "ct_fetch_duration_seconds",
    "HTTP fetch round-trip latency in seconds",
    ["log_url", "fetch_type"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

# Bytes received per fetch.
# Labels: log_url, fetch_type
fetch_bytes_total = Counter(
    "ct_fetch_bytes_total",
    "Total bytes received from CT log HTTP endpoints",
    ["log_url", "fetch_type"],
)


# ─────────────────────────────────────────────────────────────────────
# Parse pipeline
# ─────────────────────────────────────────────────────────────────────

# Entries the parser could not decode.
# Labels: log_url, format (rfc6962 | tiled_sunlight | tiled_sycamore)
parse_errors_total = Counter(
    "ct_parse_errors_total",
    "Total entries that failed to parse",
    ["log_url", "format"],
)

# Wall-clock time for the synchronous parse step (runs in asyncio.to_thread).
# Labels: format
parse_duration_seconds = Histogram(
    "ct_parse_duration_seconds",
    "Wall-clock time for one batch/tile parse call (CPU-bound, in thread pool)",
    ["format"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

# Entries per batch/tile (size distribution, useful for tuning BATCH_SIZE).
# Labels: format
parse_batch_size = Histogram(
    "ct_parse_batch_size_entries",
    "Number of entries in each parsed batch or tile",
    ["format"],
    buckets=[8, 16, 32, 64, 128, 256, 512, 1024, 2048],
)


# ─────────────────────────────────────────────────────────────────────
# Queue depths – backpressure visibility
# ─────────────────────────────────────────────────────────────────────

parse_queue_depth = Gauge(
    "ct_parse_queue_depth",
    "Batches waiting in the parse queue (fetcher → parser)",
)

write_queue_depth = Gauge(
    "ct_write_queue_depth",
    "Cert batches waiting in the write queue (parser → DB writer)",
)


# ─────────────────────────────────────────────────────────────────────
# Worker / concurrency
# ─────────────────────────────────────────────────────────────────────

active_collector_tasks = Gauge(
    "ct_active_collector_tasks",
    "Number of per-log collector tasks currently running",
)

active_parser_workers = Gauge(
    "ct_active_parser_workers",
    "Number of parser worker coroutines (fixed pool size at startup)",
)


# ─────────────────────────────────────────────────────────────────────
# Per-log progress & backlog
# ─────────────────────────────────────────────────────────────────────

# Latest entry index reached for each log.
# Labels: log_url
log_progress_index = Gauge(
    "ct_log_progress_index",
    "Highest entry index collected so far for this CT log",
    ["log_url"],
)

# Most-recently observed total log size (from STH / checkpoint).
# Labels: log_url
log_length = Gauge(
    "ct_log_length",
    "Latest known CT log length (tree_size from STH or checkpoint count)",
    ["log_url"],
)

# Entries still to collect (log_length - log_progress_index).
# Labels: log_url
log_backlog = Gauge(
    "ct_log_backlog_entries",
    "Estimated entries remaining to collect for this CT log",
    ["log_url"],
)


# ─────────────────────────────────────────────────────────────────────
# Slice table bookkeeping
# ─────────────────────────────────────────────────────────────────────

# New slices inserted into ct_log_slices.
# Labels: log_id
slices_created_total = Counter(
    "ct_slices_created_total",
    "Total ct_log_slices rows inserted (new slice creation only)",
    ["log_id"],
)

# SliceWriter.flush() calls and rows written.
slice_progress_flushes_total = Counter(
    "ct_slice_progress_flushes_total",
    "Total SliceWriter bulk flush operations",
)

slice_progress_rows_total = Counter(
    "ct_slice_progress_rows_total",
    "Total ct_log_slices progress rows written by SliceWriter",
)


# ─────────────────────────────────────────────────────────────────────
# Database latency – reads
# ─────────────────────────────────────────────────────────────────────

# get_pending_slices SELECT … FINAL latency.
db_get_slices_duration_seconds = Histogram(
    "ct_db_get_slices_duration_seconds",
    "Latency of SELECT pending slices from ClickHouse (FINAL dedup)",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

# ensure_slices() total latency (cache check + optional cold load + INSERT).
db_ensure_slices_duration_seconds = Histogram(
    "ct_db_ensure_slices_duration_seconds",
    "Latency of ensure_slices() (cache check + optional cold-load + INSERT)",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)


# ─────────────────────────────────────────────────────────────────────
# Database latency – writes
# ─────────────────────────────────────────────────────────────────────

# SliceWriter.flush() INSERT latency.
db_slice_write_duration_seconds = Histogram(
    "ct_db_slice_write_duration_seconds",
    "Latency of SliceWriter bulk INSERT into ct_log_slices",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# CertWriter.flush() INSERT latency.
db_cert_write_duration_seconds = Histogram(
    "ct_db_cert_write_duration_seconds",
    "Latency of CertWriter bulk INSERT into ct_certs",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# Rows per CertWriter flush.
db_cert_write_batch_size = Histogram(
    "ct_db_cert_write_batch_size_rows",
    "Number of ct_certs rows per CertWriter flush",
    buckets=[10, 50, 100, 200, 500, 1000, 2000, 5000],
)

# Any DB operation that raised an exception.
# Labels: operation (ensure_slices | get_pending_slices | cert_flush | slice_flush | get_logs)
db_errors_total = Counter(
    "ct_db_errors_total",
    "Total database operation errors by operation name",
    ["operation"],
)


# ─────────────────────────────────────────────────────────────────────
# Connection pool
# ─────────────────────────────────────────────────────────────────────

db_pool_checked_out = Gauge(
    "ct_db_pool_checked_out",
    "SQLAlchemy QueuePool connections currently checked out",
)

db_pool_overflow = Gauge(
    "ct_db_pool_overflow",
    "SQLAlchemy QueuePool connections currently in overflow (above pool_size)",
)


# ─────────────────────────────────────────────────────────────────────
# Log-length updater
# ─────────────────────────────────────────────────────────────────────

# STH / checkpoint fetch failures.
# Labels: log_url, log_type (normal | tiled)
log_length_update_errors_total = Counter(
    "ct_log_length_update_errors_total",
    "Total failures fetching STH or checkpoint for log-length updates",
    ["log_url", "log_type"],
)

# Wall-clock time for one full update cycle across all logs.
log_length_update_duration_seconds = Histogram(
    "ct_log_length_update_duration_seconds",
    "Wall-clock time for one complete LogLengthUpdater update cycle",
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
)


# ─────────────────────────────────────────────────────────────────────
# Helper used by cert_collector.py
# ─────────────────────────────────────────────────────────────────────

def extract_issuer_o(issuer_dn: str) -> str:
    """
    Extract the O= value from an issuer DN string such as:
      'organizationName=Let's Encrypt, countryName=US'
    Truncated to 64 chars to keep Prometheus label cardinality bounded.
    Returns 'unknown' if no O= is found.
    """
    for part in issuer_dn.split(","):
        part = part.strip()
        for prefix in ("O=", "organizationName=", "2.5.4.10="):
            if part.startswith(prefix):
                val = part[len(prefix):].strip().strip("'\"")
                return val[:64]
    return "unknown"

# ─────────────────────────────────────────────────────────────────────
# WebSocket  (used by websocket.py)
# ─────────────────────────────────────────────────────────────────────




