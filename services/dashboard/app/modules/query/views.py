"""Interactive SQL query interface for the certificate database."""

import logging
import time

from flask import Blueprint, render_template, jsonify, request

from app.core import clickhouse

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
    "query",
    __name__,
    template_folder="templates",
    url_prefix="/query",
)

logger = logging.getLogger(__name__)

# Read-only queries only – reject anything that looks like a write.
_FORBIDDEN_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "TRUNCATE", "CREATE", "GRANT", "REVOKE",
    "SYSTEM", "KILL",
}

MAX_ROWS = 10000

# Pre-built example queries (ClickHouse SQL)
EXAMPLES = [
    {
        "label": "Latest 50 certificates",
        "sql": (
            "SELECT subject, issuer, dns_names, "
            "not_before, not_after, ts\n"
            "FROM ct_certs\n"
            "ORDER BY ts DESC\n"
            "LIMIT 50"
        ),
    },
    {
        "label": "Certificates per hour (last 24h)",
        "sql": (
            "SELECT toStartOfHour(ts) AS bucket,\n"
            "       count() AS cert_count\n"
            "FROM ct_certs\n"
            "WHERE ts > now() - INTERVAL 24 HOUR\n"
            "GROUP BY bucket\n"
            "ORDER BY bucket DESC"
        ),
    },
    {
        "label": "Top 20 issuers",
        "sql": (
            "SELECT issuer, count() AS cnt\n"
            "FROM ct_certs\n"
            "GROUP BY issuer\n"
            "ORDER BY cnt DESC\n"
            "LIMIT 20"
        ),
    },
    {
        "label": "Search domain (LIKE)",
        "sql": (
            "SELECT subject, dns_names, issuer, ts\n"
            "FROM ct_certs\n"
            "WHERE subject ilike '%example.com%'\n"
            "   OR arrayExists(x -> ilike(x, '%example.com%'), dns_names)\n"
            "ORDER BY ts DESC\n"
            "LIMIT 100"
        ),
    },
    {
        "label": "Table size & row count",
        "sql": (
            "SELECT\n"
            "    formatReadableSize(sum(bytes)) AS table_size,\n"
            "    sum(rows) AS total_rows\n"
            "FROM system.parts\n"
            "WHERE database = currentDatabase()\n"
            "    AND table = 'ct_certs'\n"
            "    AND active"
        ),
    },
]


@bp.route("/")
def index():
    return render_template("query.html", examples=EXAMPLES)


@bp.route("/api/execute", methods=["POST"])
def api_execute():
    """Execute a read-only SQL query and return results as JSON."""
    body = request.get_json(silent=True) or {}
    sql = (body.get("sql") or "").strip()

    if not sql:
        return jsonify({"error": "Empty query"}), 400

    # Safety: reject write operations
    first_word = sql.split()[0].upper().rstrip(";")
    if first_word in _FORBIDDEN_KEYWORDS:
        return jsonify(
            {"error": f"Write operations are not allowed ({first_word})"}
        ), 403

    if _PROM:
        DB_QUERY_COUNT.labels(endpoint="query.api_execute").inc()
    client = clickhouse.get_client(connect_timeout=5)
    try:
        t0 = time.time()
        result = client.query(sql)
        elapsed = round(time.time() - t0, 4)
        if _PROM:
            DB_QUERY_DURATION.labels(endpoint="query.api_execute").observe(elapsed)

        if result.column_names:
            columns = list(result.column_names)
            rows = result.result_rows[:MAX_ROWS]
            # Serialise non-JSON-native types
            clean_rows = []
            for row in rows:
                clean = []
                for v in row:
                    if hasattr(v, "isoformat"):
                        clean.append(v.isoformat())
                    elif isinstance(v, (dict, list)):
                        clean.append(v)
                    else:
                        clean.append(v)
                clean_rows.append(clean)
            result_data = {
                "columns": columns,
                "rows": clean_rows,
                "row_count": len(clean_rows),
                "truncated": len(clean_rows) >= MAX_ROWS,
                "elapsed_s": elapsed,
            }
        else:
            result_data = {
                "columns": [],
                "rows": [],
                "row_count": 0,
                "elapsed_s": elapsed,
                "message": "Query executed (no results).",
            }

        return jsonify(result_data)
    except Exception as exc:
        logger.debug("Query execution failed: %s", exc)
        if _PROM:
            DB_QUERY_ERRORS.labels(endpoint="query.api_execute").inc()
        return jsonify({"error": str(exc)}), 400
    finally:
        try:
            client.close()
        except Exception:
            pass
