"""Live certificate feed and recent-certs API."""

import json
import logging
import os
import threading
import time

from flask import Blueprint, render_template, jsonify, request

from app.core import clickhouse

bp = Blueprint(
    "certs",
    __name__,
    template_folder="templates",
    url_prefix="/certs",
)

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("CT_REDIS_URL") or None

# In-memory ring buffer for recent certs (fed by Redis subscriber)
_MAX_BUFFER = 1000
_cert_buffer: list = []
_buffer_lock = threading.Lock()
_subscriber_started = False

# Optional Prometheus metrics
try:
    from app.core.metrics import (
        CERT_BUFFER_SIZE,
        REDIS_SUBSCRIBER_STATUS,
        SOCKETIO_EVENTS_EMITTED,
        DB_QUERY_COUNT,
        DB_QUERY_DURATION,
        DB_QUERY_ERRORS,
        PROM_AVAILABLE as _PROM,
    )
except ImportError:
    _PROM = False


def _start_redis_subscriber():
    """Background thread: subscribe to ct:certs and fill the ring buffer."""
    global _subscriber_started
    if _subscriber_started or not REDIS_URL:
        return
    _subscriber_started = True
    logger.info("Starting Redis subscriber thread for ct:certs")
    def _run():
        try:
            import redis as redis_lib
            r = redis_lib.from_url(REDIS_URL)
            ps = r.pubsub()
            ps.subscribe("ct:certs")
            logger.info("Redis cert subscriber started")
            if _PROM:
                REDIS_SUBSCRIBER_STATUS.set(1)
            for msg in ps.listen():
                logger.debug("Received message from Redis: %s", msg)
                if msg["type"] != "message":
                    continue
                try:
                    cert = json.loads(msg["data"])
                except Exception:
                    continue
                with _buffer_lock:
                    _cert_buffer.append(cert)
                    while len(_cert_buffer) > _MAX_BUFFER:
                        _cert_buffer.pop(0)
                    if _PROM:
                        CERT_BUFFER_SIZE.set(len(_cert_buffer))
                # Also push via SocketIO if available
                try:
                    from app import socketio
                    logger.debug("Emitting cert event to SocketIO clients")
                    socketio.emit("cert_event", cert)
                    if _PROM:
                        SOCKETIO_EVENTS_EMITTED.labels(event="cert_event").inc()
                except Exception:
                    pass
        except Exception:
            logger.exception("Redis subscriber crashed")
            if _PROM:
                REDIS_SUBSCRIBER_STATUS.set(0)

    t = threading.Thread(target=_run, daemon=True)
    t.start()


@bp.record_once
def _on_register(_state):
    """Start the Redis subscriber when the blueprint is registered."""
    _start_redis_subscriber()


@bp.route("/")
def index():
    return render_template("certs.html")


@bp.route("/api/recent")
def api_recent():
    """Return the most recent certificates (from buffer or DB fallback)."""
    limit = min(int(request.args.get("limit", 50)), 1000)

    # Prefer the in-memory buffer if populated
    with _buffer_lock:
        if _cert_buffer:
            data = list(reversed(_cert_buffer[-limit:]))
            return jsonify({"source": "redis", "certs": data})

    # Fallback: query ClickHouse directly
    if _PROM:
        DB_QUERY_COUNT.labels(endpoint="certs.api_recent").inc()
    t0 = time.monotonic()
    try:
        client = clickhouse.get_client()
        try:
            result = client.query(
                "SELECT log, subject, issuer, not_before, not_after, "
                "serial_number, dns_names, fingerprint_sha256, ts "
                "FROM ct_certs ORDER BY ts DESC LIMIT {limit:UInt32}",
                parameters={"limit": limit},
            )
            cols = list(result.column_names)
            rows = [dict(zip(cols, r)) for r in result.result_rows]
        finally:
            try:
                client.close()
            except Exception:
                pass
        if _PROM:
            DB_QUERY_DURATION.labels(endpoint="certs.api_recent").observe(
                time.monotonic() - t0
            )
        # Serialise datetimes and keep arrays as-is
        for row in rows:
            for k, v in row.items():
                if hasattr(v, "isoformat"):
                    row[k] = v.isoformat()
        return jsonify({"source": "database", "certs": rows})
    except Exception as exc:
        if _PROM:
            DB_QUERY_ERRORS.labels(endpoint="certs.api_recent").inc()
            DB_QUERY_DURATION.labels(endpoint="certs.api_recent").observe(
                time.monotonic() - t0
            )
        return jsonify({"source": "error", "error": str(exc), "certs": []})
