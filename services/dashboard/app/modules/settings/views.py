from __future__ import annotations

import json
import os
import logging

from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.core import clickhouse
from app import socketio

logger = logging.getLogger(__name__)

bp = Blueprint("settings", __name__, template_folder="templates")


@bp.route("/", methods=["GET"])
def settings_page():
    raw = None
    try:
        raw = clickhouse.get_latest_setting("settings")
    except Exception:
        logger.exception("Failed to load persisted settings")

    # Default structure
    settings = {"default_action": "allow", "filters": []}
    try:
        if raw:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                settings.update(loaded)
    except Exception:
        logger.exception("Failed to parse persisted settings")

    return render_template(
        "settings.html",
        filters_json=json.dumps(settings.get("filters", []), indent=2),
        default_action=settings.get("default_action", "allow")
    )


@bp.route("/", methods=["POST"])
def settings_save():
    text = request.form.get("filters_json") or ""
    default_action = request.form.get("default_action") or "allow"
    try:
        filters = json.loads(text)
        if not isinstance(filters, list):
            raise ValueError("Filters must be a JSON list")
    except Exception as exc:
        flash(f"Invalid JSON: {exc}", "danger")
        return redirect(url_for("settings.settings_page"))

    settings = {"default_action": default_action, "filters": filters}

    # persist to ClickHouse
    try:
        clickhouse.insert_setting("settings", json.dumps(settings))
    except Exception:
        logger.exception("Failed to persist settings to ClickHouse")
        flash("Could not persist settings to database", "danger")
        return redirect(url_for("settings.settings_page"))

    # publish to Redis so collectors update
    try:
        import redis as redis_lib

        REDIS_URL = os.getenv("CT_REDIS_URL")
        if REDIS_URL:
            r = redis_lib.from_url(REDIS_URL)
            msg = json.dumps({
                "type": "settings_update",
                "settings": settings
            })
            r.publish("ct:settings", msg)
    except Exception:
        logger.exception("Failed to publish settings to Redis")

    # also emit SocketIO event to dashboard clients
    try:
        socketio.emit("settings_update", settings)
    except Exception:
        logger.exception("Failed to emit settings update via SocketIO")

    flash("Settings saved and propagated", "success")
    return redirect(url_for("settings.settings_page"))
