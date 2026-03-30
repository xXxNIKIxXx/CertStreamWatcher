"""Monitoring / health-check views for Redis, ClickHouse, and collectors."""

import os
import logging
import socket
import time

from flask import Blueprint, render_template, jsonify

try:
    from app.core.metrics import (
        DB_QUERY_COUNT,
        DB_QUERY_DURATION,
        DB_QUERY_ERRORS,
        PROM_AVAILABLE as _PROM,
    )
except ImportError:
    _PROM = False

bp = Blueprint(
    "monitoring",
    __name__,
    template_folder="templates",
    url_prefix="/monitoring",
)

logger = logging.getLogger(__name__)



# Service name for DNS-based discovery (single A-record lookup)
_COLLECTOR_SERVICE = os.getenv("CT_COLLECTOR_SERVICE", "collector")
_COLLECTOR_PORT = int(os.getenv("CT_COLLECTOR_PORT", "8001"))

# How long (seconds) to remember a collector after it disappears from DNS
_TRACKER_TTL = int(os.getenv("CT_COLLECTOR_TRACKER_TTL", "300"))  # 5 min

# In-memory fallback when Redis is unavailable: {ip: last_seen_timestamp}
_mem_tracker: dict[str, float] = {}


def _track_collectors(live_ips: set[str]) -> set[str]:
    """Persist *live_ips* and return the union with recently-seen IPs.

    Uses only an in-memory dict. IPs older than ``_TRACKER_TTL``
    seconds are automatically evicted.
    """
    now = time.time()
    for ip in live_ips:
        _mem_tracker[ip] = now

    cutoff = now - _TRACKER_TTL
    stale = [ip for ip, ts in _mem_tracker.items() if ts < cutoff]
    for ip in stale:
        del _mem_tracker[ip]

    return set(_mem_tracker.keys()) | live_ips


def _discover_collectors():
    """Auto-discover collectors via DNS A-record lookup.

    Resolves the shared service name (default ``collector``) which
    returns all replica IPs in a single query — works whether there
    are 3 or 300 replicas, no looping required.

    Recently-seen IPs are tracked so that crashed replicas still
    appear (as offline) instead of silently vanishing.

    Falls back to CT_COLLECTOR_HOSTS env var if set (comma-separated).
    """
    # Allow explicit override
    explicit = os.getenv("CT_COLLECTOR_HOSTS", "").strip()
    if explicit:
        return [
            f"http://{h.strip()}:{_COLLECTOR_PORT}"
            for h in explicit.split(",")
            if h.strip()
        ]

    # DNS lookup → currently running replicas
    try:
        addrs = socket.getaddrinfo(
            _COLLECTOR_SERVICE, _COLLECTOR_PORT,
            proto=socket.IPPROTO_TCP,
        )
        live_ips = {addr[4][0] for addr in addrs}
    except socket.gaierror:
        logger.debug(
            "DNS lookup for '%s' returned no results",
            _COLLECTOR_SERVICE,
        )
        live_ips = set()

    # Merge with recently-seen IPs so crashed replicas stay visible
    all_ips = _track_collectors(live_ips)

    return [
        f"http://{ip}:{_COLLECTOR_PORT}"
        for ip in sorted(all_ips)
    ]


@bp.route("/")
def index():
    """Render the health / monitoring page."""
    return render_template(
        "monitoring.html"
    )


@bp.route("/api/status")
def api_status():
    """JSON health check for DB, Redis, and each collector."""
    result = {
        "database": _check_db(),
        "collectors": _check_collectors(),
    }
    return jsonify(result)


# ------------------------------------------------------------------
# Health-check helpers
# ------------------------------------------------------------------

def _check_db():
    if _PROM:
        DB_QUERY_COUNT.labels(endpoint="monitoring._check_db").inc()
    t0 = time.monotonic()
    try:
        from services.dashboard.app.core import clickhouse
        client = clickhouse.get_client(connect_timeout=3)
        try:
            ver = client.command("SELECT version()")
            row_count = client.command("SELECT count() FROM ct_certs")
            db_size = client.command(
                "SELECT formatReadableSize(sum(bytes)) "
                "FROM system.parts "
                "WHERE database = currentDatabase() "
                "AND table = 'ct_certs' AND active"
            )
        finally:
            try:
                client.close()
            except Exception:
                pass
        if _PROM:
            DB_QUERY_DURATION.labels(endpoint="monitoring._check_db").observe(
                time.monotonic() - t0
            )
        return {
            "status": "ok",
            "version": str(ver),
            "row_count": row_count,
            "db_size": db_size or "0 B",
        }
    except Exception as exc:
        logger.debug("DB health-check failed: %s", exc)
        if _PROM:
            DB_QUERY_ERRORS.labels(endpoint="monitoring._check_db").inc()
            DB_QUERY_DURATION.labels(endpoint="monitoring._check_db").observe(
                time.monotonic() - t0
            )
        return {"status": "error", "error": str(exc)}


#TODO: FIX VALUES PARSING BECUASE METRICS UPDATED
def _check_collectors():
    import urllib.request
    import urllib.error

    # Get the current DNS-live IPs for comparison
    try:
        addrs = socket.getaddrinfo(
            _COLLECTOR_SERVICE, _COLLECTOR_PORT,
            proto=socket.IPPROTO_TCP,
        )
        dns_live = {addr[4][0] for addr in addrs}
    except socket.gaierror:
        dns_live = set()

    collectors = []
    for url in _discover_collectors():
        # Extract IP from URL to check if it's currently in DNS
        ip = url.split("//")[1].split(":")[0]
        in_dns = ip in dns_live

        entry = {"url": url, "status": "unknown"}
        try:
            req = urllib.request.Request(
                f"{url}/metrics", method="GET"
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read().decode(errors="replace")
                # Parse a couple of key metrics from the Prometheus
                # text exposition format.
                entry["status"] = "ok"
                for line in body.splitlines():
                    if line.startswith(
                        "ct_entries_processed_total "
                    ):
                        entry["entries_processed"] = _prom_val(
                            line
                        )
                    elif line.startswith(
                        "ct_entries_parsed_success_total "
                    ):
                        entry["parsed_success"] = _prom_val(line)
                    elif line.startswith(
                        "ct_parse_failures_total "
                    ):
                        entry["parse_failures"] = _prom_val(line)
        except urllib.error.URLError as exc:
            entry["status"] = "offline" if not in_dns else "error"
            entry["error"] = str(exc.reason)
        except Exception as exc:
            entry["status"] = "offline" if not in_dns else "error"
            entry["error"] = str(exc)
        collectors.append(entry)
    return collectors


def _prom_val(line: str):
    """Extract the numeric value from a Prometheus text line."""
    try:
        return float(line.strip().split()[-1])
    except Exception:
        return None
