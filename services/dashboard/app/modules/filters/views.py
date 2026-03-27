from __future__ import annotations

import json
import os
import logging


import os
import json
import logging
from flask import jsonify

from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.core import clickhouse


logger = logging.getLogger(__name__)

bp = Blueprint("filters", __name__, template_folder="templates")


@bp.route("/", methods=["GET"])
def filters_page():
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
        "filters.html",
        filters_json=json.dumps(settings.get("filters", []), indent=2),
        default_action=settings.get("default_action", "allow")
    )


@bp.route("/", methods=["POST"])
def filters_save():
    text = request.form.get("filters_json") or ""
    default_action = request.form.get("default_action") or "allow"
    try:
        filters = json.loads(text)
        if not isinstance(filters, list):
            raise ValueError("Filters must be a JSON list")
    except Exception as exc:
        flash(f"Invalid JSON: {exc}", "danger")
        return redirect(url_for("filters.filters_page"))

    settings = {"default_action": default_action, "filters": filters}

    # persist to ClickHouse
    try:
        clickhouse.insert_setting("settings", json.dumps(settings))
    except Exception:
        logger.exception("Failed to persist settings to ClickHouse")
        flash("Could not persist settings to database", "danger")
        return redirect(url_for("filters.filters_page"))

    flash("Settings saved", "success")
    return redirect(url_for("filters.filters_page"))


# AJAX endpoint for auto-saving filters
@bp.route("/autosave", methods=["POST"])
def filters_autosave():
    data = request.get_json(force=True)
    filters = data.get("filters", [])
    default_action = data.get("default_action", "allow")
    try:
        if not isinstance(filters, list):
            raise ValueError("Filters must be a JSON list")
    except Exception as exc:
        return jsonify({"success": False, "error": f"Invalid JSON: {exc}"}), 400

    settings = {"default_action": default_action, "filters": filters}
    try:
        clickhouse.insert_setting("settings", json.dumps(settings))
    except Exception as exc:
        logger.exception("Failed to persist settings to ClickHouse (AJAX)")
        return jsonify({"success": False, "error": "Could not persist settings to database"}), 500
    return jsonify({"success": True})
