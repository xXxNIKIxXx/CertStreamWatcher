
"""Home / overview dashboard page."""

import logging
import time

from flask import Blueprint, render_template, jsonify

from services.dashboard.app.core import clickhouse

bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
    static_folder="static",
    url_prefix="/",
)

logger = logging.getLogger(__name__)

try:
    from services.dashboard.app.core.metrics import (
        DB_QUERY_COUNT,
        DB_QUERY_DURATION,
        DB_QUERY_ERRORS,
        PROM_AVAILABLE as _PROM,
    )
except ImportError:
    _PROM = False


@bp.route("/api/recent")
def api_recent():
    """Return the 10 most recent certificates for the dashboard."""
    certs = []
    if _PROM:
        DB_QUERY_COUNT.labels(endpoint="dashboard.api_recent").inc()
    t0 = time.monotonic()
    try:
        client = clickhouse.get_client()
        try:
            rows = client.query(
                "SELECT ts, subject, issuer, dns_names FROM ct_certs ORDER BY ts DESC LIMIT 10"
            ).result_rows
            for row in rows:
                certs.append({
                    "timestamp": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                    "subject": row[1],
                    "issuer": row[2],
                    "dns_names": row[3] if isinstance(row[3], list) else (row[3].split(",") if row[3] else []),
                })
        finally:
            try:
                client.close()
            except Exception:
                pass
        if _PROM:
            DB_QUERY_DURATION.labels(endpoint="dashboard.api_recent").observe(
                time.monotonic() - t0
            )
    except Exception as exc:
        logger.debug("Recent certs query failed: %s", exc)
        if _PROM:
            DB_QUERY_ERRORS.labels(endpoint="dashboard.api_recent").inc()
            DB_QUERY_DURATION.labels(endpoint="dashboard.api_recent").observe(
                time.monotonic() - t0
            )
    return jsonify({"certs": certs})

@bp.route("/")
def index():
    return render_template("dashboard.html")


@bp.route("/api/overview")
def api_overview():
    """Quick stats for the overview cards."""
    stats = {
        "total_certs": 0,
        "certs_24h": 0,
        "unique_issuers": 0,
        "db_ok": False,
    }
    if _PROM:
        DB_QUERY_COUNT.labels(endpoint="dashboard.api_overview").inc()
    t0 = time.monotonic()
    try:
        client = clickhouse.get_client()
        try:
            stats["total_certs"] = client.command("SELECT count() FROM ct_certs")
            stats["certs_24h"] = client.command(
                "SELECT count() FROM ct_certs WHERE ts > now() - INTERVAL 24 HOUR"
            )
            stats["unique_issuers"] = client.command(
                "SELECT uniq(issuer) FROM ct_certs"
            )
            stats["db_ok"] = True
        finally:
            try:
                client.close()
            except Exception:
                pass
        if _PROM:
            DB_QUERY_DURATION.labels(endpoint="dashboard.api_overview").observe(
                time.monotonic() - t0
            )
    except Exception as exc:
        logger.debug("Overview stats query failed: %s", exc)
        stats["error"] = str(exc)
        if _PROM:
            DB_QUERY_ERRORS.labels(endpoint="dashboard.api_overview").inc()
            DB_QUERY_DURATION.labels(endpoint="dashboard.api_overview").observe(
                time.monotonic() - t0
            )
    return jsonify(stats)

