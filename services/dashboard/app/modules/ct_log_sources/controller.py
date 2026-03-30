# Bulk import from JSON
import io
import json as pyjson
from flask import send_file

# Ensure ct_logs has is_tiled column on startup
from services.dashboard.app.core import clickhouse
def ensure_is_tiled_column():
    client = clickhouse.get_client()
    try:
        columns = client.query("DESCRIBE TABLE ct_logs").result_rows
        col_names = [col[0] for col in columns]
        if "is_tiled" not in col_names:
            client.command("ALTER TABLE ct_logs ADD COLUMN is_tiled UInt8 DEFAULT 0")
    except Exception as e:
        # Log but do not crash
        import logging
        logging.getLogger(__name__).error(f"Failed to ensure is_tiled column: {e}")

ensure_is_tiled_column()


"""Controller for CT Log Sources management in dashboard."""

import logging
from flask import Blueprint, request, redirect, url_for, render_template, flash
from services.dashboard.app.core import clickhouse
from uuid import uuid4
from datetime import datetime

bp = Blueprint(
    "ct_log_sources",
    __name__,
    template_folder="templates",
    url_prefix="/ct_log_sources",
)

logger = logging.getLogger(__name__)

@bp.route("/import", methods=["GET", "POST"])
def import_json():
    if request.method == "POST":
        file = request.files.get("json_file")
        if not file or not file.filename.endswith(".json"):
            flash("Please upload a .json file", "danger")
            return render_template("ct_log_sources/import.html")
        try:
            data = pyjson.load(file)
            client = clickhouse.get_client()
            op_name_to_id = {}
            # Insert operators
            for op in data.get("operators", []):
                name = op.get("name", "")
                emails = op.get("email", [])
                # Escape single quotes for safe SQL
                safe_name = name.replace("'", "''")
                op_id = None
                result = client.query(f"SELECT id FROM ct_log_operators WHERE name = '{safe_name}'").result_rows
                if result:
                    op_id = str(result[0][0])
                else:
                    op_id = str(uuid4())
                    row = {
                        "id": op_id,
                        "name": name,
                        "email": emails,
                        "added_at": datetime.utcnow().isoformat(sep=' ')
                    }
                    sql = "INSERT INTO ct_log_operators FORMAT JSONEachRow\n" + pyjson.dumps(row, ensure_ascii=False)
                    client.command(sql)
                op_name_to_id[name] = op_id
                # Insert logs
                for log in op.get("logs", []):
                    log_row = {
                        "id": str(uuid4()),
                        "operator_id": op_id,
                        "description": log.get("description", ""),
                        "log_id": log.get("log_id", ""),
                        "key": log.get("key", ""),
                        "url": log.get("url", ""),
                        "mmd": log.get("mmd", 0),
                        "state": pyjson.dumps(log.get("state", {})),
                        "temporal_interval_start": log.get("temporal_interval", {}).get("start_inclusive", "1970-01-01T00:00:00Z"),
                        "temporal_interval_end": log.get("temporal_interval", {}).get("end_exclusive", "1970-01-01T00:00:00Z"),
                        "current_index": 0,
                        "log_length": 0,
                        "status": "active",
                        "is_tiled": 0,
                        "submission_url": "",
                        "monitoring_url": "",
                        "added_at": datetime.utcnow().isoformat(sep=' ')
                    }
                    sql = "INSERT INTO ct_logs FORMAT JSONEachRow\n" + pyjson.dumps(log_row, ensure_ascii=False)
                    client.command(sql)
                for tlog in op.get("tiled_logs", []):
                    tlog_row = {
                        "id": str(uuid4()),
                        "operator_id": op_id,
                        "description": tlog.get("description", ""),
                        "log_id": tlog.get("log_id", ""),
                        "key": tlog.get("key", ""),
                        "url": tlog.get("url", tlog.get("submission_url", "")),
                        "mmd": tlog.get("mmd", 0),
                        "state": pyjson.dumps(tlog.get("state", {})),
                        "temporal_interval_start": tlog.get("temporal_interval", {}).get("start_inclusive", "1970-01-01T00:00:00Z"),
                        "temporal_interval_end": tlog.get("temporal_interval", {}).get("end_exclusive", "1970-01-01T00:00:00Z"),
                        "current_index": 0,
                        "log_length": 0,
                        "status": "active",
                        "is_tiled": 1,
                        "submission_url": tlog.get("submission_url", ""),
                        "monitoring_url": tlog.get("monitoring_url", ""),
                        "added_at": datetime.utcnow().isoformat(sep=' ')
                    }
                    sql = "INSERT INTO ct_logs FORMAT JSONEachRow\n" + pyjson.dumps(tlog_row, ensure_ascii=False)
                    client.command(sql)
            flash("Import successful!", "success")
            return redirect(url_for("ct_log_sources.list_operators"))
        except Exception as e:
            flash(f"Import failed: {e}", "danger")
    return render_template("ct_log_sources/import.html")

# Operator CRUD
@bp.route("/operators", methods=["GET"])
def list_operators():
    client = clickhouse.get_client()
    rows = client.query("SELECT id, name, email FROM ct_log_operators ORDER BY name").result_rows
    return render_template("ct_log_sources/operators_list.html", operators=rows)

@bp.route("/operators/add", methods=["GET", "POST"])
def add_operator():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        emails = [e.strip() for e in email.split(",") if e.strip()]
        now = datetime.utcnow()
        op_id = str(uuid4())
        try:
            client = clickhouse.get_client()
            import json
            row = {
                "id": op_id,
                "name": name,
                "email": emails,
                "added_at": now.isoformat(sep=' ')
            }
            json_row = json.dumps(row, ensure_ascii=False)
            sql = "INSERT INTO ct_log_operators FORMAT JSONEachRow\n" + json_row
            client.command(sql)
            flash("Operator added", "success")
            return redirect(url_for("ct_log_sources.list_operators"))
        except Exception as e:
            flash(f"Failed to add operator: {e}", "danger")
    return render_template("ct_log_sources/operator_add.html")

@bp.route("/operators/<op_id>/edit", methods=["GET", "POST"])
def edit_operator(op_id):
    client = clickhouse.get_client()
    row = client.query(f"SELECT id, name, email FROM ct_log_operators WHERE id = '{op_id}'").first_row
    if not row:
        flash("Operator not found", "danger")
        return redirect(url_for("ct_log_sources.list_operators"))
    if request.method == "POST":
        name = request.form.get("name", row[1])
        email = request.form.get("email", ",".join(row[2]))
        emails = [e.strip() for e in email.split(",") if e.strip()]
        try:
            email_array = '[' + ','.join([f"'{e}'" for e in emails]) + ']'
            client.command(f"ALTER TABLE ct_log_operators UPDATE name = '{name}', email = {email_array} WHERE id = '{op_id}'")
            flash("Operator updated", "success")
            return redirect(url_for("ct_log_sources.list_operators"))
        except Exception as e:
            flash(f"Failed to update operator: {e}", "danger")
    return render_template("ct_log_sources/operator_edit.html", operator=row)

@bp.route("/operators/<op_id>/delete", methods=["POST"])
def delete_operator(op_id):
    try:
        client = clickhouse.get_client()
        client.command(f"ALTER TABLE ct_log_operators DELETE WHERE id = '{op_id}'")
        flash("Operator deleted", "warning")
    except Exception as e:
        flash(f"Failed to delete operator: {e}", "danger")
    return redirect(url_for("ct_log_sources.list_operators"))

# Log CRUD
@bp.route("/logs", methods=["GET"])
def list_logs():
    client = clickhouse.get_client()
    # Show log name (description) as first column, then operator, url, etc.
    # Aggregate progress from ct_log_slices: sum current_index and log_length per log
    rows = client.query(
        "SELECT l.id, l.description, o.name, l.url, l.mmd, l.state, l.temporal_interval_start, l.temporal_interval_end, "
        "COALESCE(SUM(if(s.status != 'pending', s.current_index, 0)), 0) AS total_parsed, "
        "COALESCE(SUM(s.slice_end), 0) AS total_length, "
        "l.status, l.is_tiled, l.added_at "
        "FROM ct_logs l "
        "LEFT JOIN ct_log_operators o ON l.operator_id = o.id "
        "LEFT JOIN (SELECT * FROM ct_log_slices FINAL) AS s ON toString(l.id) = s.id "
        "GROUP BY l.id, l.description, o.name, l.url, l.mmd, l.state, l.temporal_interval_start, l.temporal_interval_end, l.status, l.is_tiled, l.added_at "
        "ORDER BY l.added_at DESC"
    ).result_rows

    # Compute progress percentage for each log
    logs = []
    for row in rows:
        logs.append(row)
    return render_template("ct_log_sources/logs_list.html", logs=logs)

@bp.route("/logs/add", methods=["GET", "POST"])
def add_log():
    client = clickhouse.get_client()
    operators = client.query("SELECT id, name FROM ct_log_operators ORDER BY name").result_rows
    if request.method == "POST":
        operator_id = request.form.get("operator_id")
        description = request.form.get("description", "")
        log_id_val = request.form.get("log_id", "")
        key = request.form.get("key", "")
        url_val = request.form.get("url", "")
        mmd = int(request.form.get("mmd", 0))
        state = request.form.get("state", "")
        temporal_start = request.form.get("temporal_interval_start", "1970-01-01T00:00:00Z")
        temporal_end = request.form.get("temporal_interval_end", "1970-01-01T00:00:00Z")
        status = request.form.get("status", "active")
        is_tiled = 1 if request.form.get("is_tiled") == "on" else 0
        submission_url = request.form.get("submission_url", "")
        monitoring_url = request.form.get("monitoring_url", "")
        now = datetime.utcnow()
        log_uuid = str(uuid4())
        try:
            import json
            row = {
                "id": log_uuid,
                "operator_id": operator_id,
                "description": description,
                "log_id": log_id_val,
                "key": key,
                "url": url_val,
                "mmd": mmd,
                "state": state,
                "temporal_interval_start": temporal_start,
                "temporal_interval_end": temporal_end,
                "current_index": 0,
                "log_length": 0,
                "status": status,
                "is_tiled": is_tiled,
                "submission_url": submission_url,
                "monitoring_url": monitoring_url,
                "added_at": now.isoformat(sep=' ')
            }
            json_row = json.dumps(row, ensure_ascii=False)
            sql = "INSERT INTO ct_logs FORMAT JSONEachRow\n" + json_row
            client.command(sql)
            flash("Log added", "success")
            return redirect(url_for("ct_log_sources.list_logs"))
        except Exception as e:
            flash(f"Failed to add log: {e}", "danger")
    return render_template("ct_log_sources/log_add.html", operators=operators)

@bp.route("/logs/<log_id>/edit", methods=["GET", "POST"])
def edit_log(log_id):
    client = clickhouse.get_client()
    row = client.query(f"SELECT id, operator_id, description, log_id, key, url, mmd, state, temporal_interval_start, temporal_interval_end, current_index, log_length, status, is_tiled, submission_url, monitoring_url FROM ct_logs WHERE id = '{log_id}'").first_row
    operators = client.query("SELECT id, name FROM ct_log_operators ORDER BY name").result_rows
    if not row:
        flash("Log not found", "danger")
        return redirect(url_for("ct_log_sources.list_logs"))
    if request.method == "POST":
        operator_id = request.form.get("operator_id", row[1])
        description = request.form.get("description", row[2])
        log_id_val = request.form.get("log_id", row[3])
        key = request.form.get("key", row[4])
        url_val = request.form.get("url", row[5])
        mmd = int(request.form.get("mmd", row[6]))
        state = request.form.get("state", row[7])
        temporal_start = request.form.get("temporal_interval_start", row[8])
        temporal_end = request.form.get("temporal_interval_end", row[9])
        status = request.form.get("status", row[12])
        is_tiled = 1 if request.form.get("is_tiled") == "on" else 0
        submission_url = request.form.get("submission_url", row[14])
        monitoring_url = request.form.get("monitoring_url", row[15])
        try:
            client.command(f"ALTER TABLE ct_logs UPDATE operator_id = '{operator_id}', description = '{description}', log_id = '{log_id_val}', key = '{key}', url = '{url_val}', mmd = {mmd}, state = '{state}', temporal_interval_start = '{temporal_start}', temporal_interval_end = '{temporal_end}', status = '{status}', is_tiled = {is_tiled}, submission_url = '{submission_url}', monitoring_url = '{monitoring_url}' WHERE id = '{log_id}'")
            flash("Log updated", "success")
            return redirect(url_for("ct_log_sources.list_logs"))
        except Exception as e:
            flash(f"Failed to update log: {e}", "danger")
    return render_template("ct_log_sources/log_edit.html", log=row, operators=operators)

@bp.route("/logs/<log_id>/delete", methods=["POST"])
def delete_log(log_id):
    try:
        client = clickhouse.get_client()
        client.command(f"ALTER TABLE ct_logs DELETE WHERE id = '{log_id}'")
        flash("Log deleted", "warning")
    except Exception as e:
        flash(f"Failed to delete log: {e}", "danger")
    return redirect(url_for("ct_log_sources.list_logs"))

@bp.route("/add", methods=["GET", "POST"])
def add_log_source():
    if request.method == "POST":
        operator_id = request.form.get("operator_id")
        description = request.form.get("description", "")
        log_id_val = request.form.get("log_id", "")
        key = request.form.get("key", "")
        url_val = request.form.get("url", "")
        mmd = int(request.form.get("mmd", 0))
        state = request.form.get("state", "")
        temporal_start = request.form.get("temporal_interval_start", "1970-01-01T00:00:00Z")
        temporal_end = request.form.get("temporal_interval_end", "1970-01-01T00:00:00Z")
        status = request.form.get("status", "active")
        is_tiled = 1 if request.form.get("is_tiled") == "on" else 0
        submission_url = request.form.get("submission_url", "")
        monitoring_url = request.form.get("monitoring_url", "")
        now = datetime.utcnow()
        log_uuid = str(uuid4())
        try:
            import json
            row = {
                "id": log_uuid,
                "operator_id": operator_id,
                "description": description,
                "log_id": log_id_val,
                "key": key,
                "url": url_val,
                "mmd": mmd,
                "state": state,
                "temporal_interval_start": temporal_start,
                "temporal_interval_end": temporal_end,
                "current_index": 0,
                "log_length": 0,
                "status": status,
                "is_tiled": is_tiled,
                "submission_url": submission_url,
                "monitoring_url": monitoring_url,
                "added_at": now.isoformat(sep=' ')
            }
            json_row = json.dumps(row, ensure_ascii=False)
            sql = "INSERT INTO ct_logs FORMAT JSONEachRow\n" + json_row
            client.command(sql)
            flash("Log added", "success")
            return redirect(url_for("ct_log_sources.list_logs"))
        except Exception as e:
            flash(f"Failed to add log: {e}", "danger")
    operators = client.query("SELECT id, name FROM ct_log_operators ORDER BY name").result_rows
    return render_template("ct_log_sources/log_add.html", operators=operators)

@bp.route("/<log_id>/pause", methods=["POST"])
def pause_log_source(log_id):
    try:
        client = clickhouse.get_client()
        client.command(f"ALTER TABLE ct_log_sources UPDATE enabled = 0, status = 'paused' WHERE id = '{log_id}'")
        flash("Log source paused", "info")
    except Exception as e:
        flash(f"Failed to pause log source: {e}", "danger")
    return redirect(url_for("ct_log_sources.list_log_sources"))

@bp.route("/<log_id>/unpause", methods=["POST"])
def unpause_log_source(log_id):
    try:
        client = clickhouse.get_client()
        client.command(f"ALTER TABLE ct_log_sources UPDATE enabled = 1, status = 'active' WHERE id = '{log_id}'")
        flash("Log source unpaused", "info")
    except Exception as e:
        flash(f"Failed to unpause log source: {e}", "danger")
    return redirect(url_for("ct_log_sources.list_log_sources"))

@bp.route("/<log_id>/edit", methods=["GET", "POST"])
def edit_log_source(log_id):
    client = clickhouse.get_client()
    row = client.query(f"SELECT * FROM ct_logs WHERE id = '{log_id}'").first_row
    if not row:
        flash("Log source not found", "danger")
        return redirect(url_for("ct_log_sources.list_log_sources"))
    if request.method == "POST":
        name = request.form.get("name", row[2])
        url_ = request.form.get("url", row[1])
        try:
            client.command(f"ALTER TABLE ct_log_sources UPDATE name = '{name}', url = '{url_}' WHERE id = '{log_id}'")
            flash("Log source updated", "success")
            return redirect(url_for("ct_log_sources.list_log_sources"))
        except Exception as e:
            flash(f"Failed to update log source: {e}", "danger")
    return render_template("ct_log_sources/edit.html", log_source=row)

@bp.route("/<log_id>/delete", methods=["POST"])
def delete_log_source(log_id):
    try:
        client = clickhouse.get_client()
        client.command(f"ALTER TABLE ct_logs DELETE WHERE id = '{log_id}'")
        flash("Log deleted", "warning")
    except Exception as e:
        flash(f"Failed to delete log: {e}", "danger")
    return redirect(url_for("ct_log_sources.list_logs"))
