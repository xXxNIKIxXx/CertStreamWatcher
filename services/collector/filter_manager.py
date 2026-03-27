"""
filter_manager.py – Certificate filter with DB as source of truth.

Pipeline positions
──────────────────

Every cert that comes off the parser goes through TWO independent gates:

    1. should_write(cert)      gates ClickHouse INSERT
    2. should_broadcast(cert)  gates Redis publish

This means you can, for example:
  • Write everything to the DB but only broadcast phishing-score >= 50.
  • Write nothing that matches a known-safe issuer, but broadcast all.
  • Or use the same rules for both (the default).

Filter settings schema (stored as JSON in ct_settings key="settings")
──────────────────────────────────────────────────────────────────────
{
  "default_action": "allow" | "deny",

  "write_filters": [          ← gates DB writes  (optional, falls back to filters)
    {"field": "...", "op": "...", "value": "..."}
  ],
  "broadcast_filters": [      ← gates broadcasting  (optional, falls back to filters)
    {"field": "...", "op": "...", "value": "..."}
  ],
  "filters": [                ← used for BOTH if the above are absent
    {"field": "...", "op": "...", "value": "..."}
  ]
}

Rule fields
───────────
  field  : subject | issuer | dns_names | ct_entry_type | scripting_score
  op     : contains | equals | regex | gte | lte | gt | lt | eq
  value  : string or numeric string

Supported ops per field type:
  string fields  → contains, equals, regex
  scripting_score → gte, lte, gt, lt, eq

Sources (priority order, highest wins)
───────────────────────────────────────
  1. Database (ct_settings key="settings") — polled every DB_POLL_INTERVAL s
  2. Redis settings channel — pushed on web-app save
  3. Local file (filters.json) — fallback / bootstrap
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
from typing import Any, Dict, List, Optional

from services.shared.logger import get_logger
from .scoring import CertScoring

logger = get_logger("FilterManager")

# How often to poll the database for settings changes (seconds).
DB_POLL_INTERVAL  = int(os.getenv("CT_FILTER_DB_POLL", "15"))
# How often to check the local file for changes (seconds).
FILE_POLL_INTERVAL = int(os.getenv("CT_FILTER_POLL_INTERVAL", "5"))


class FilterManager:
    """
    Thread-safe in-memory filter that keeps itself up to date from the DB.

    All rule evaluation is done synchronously (called from async context via
    the cert pipeline) so no await is needed inside should_write /
    should_broadcast.
    """

    def __init__(
        self,
        db=None,
        file_path: Optional[str] = None,
    ) -> None:
        self._db    = db
        self._lock  = threading.Lock()

        # Active settings
        self._default_action: str           = "allow"
        self._write_rules:    List[Dict]    = []
        # Cached raw JSON so we can detect changes without re-parsing
        self._last_db_json:   Optional[str] = None

        # Scoring
        self._scorer = CertScoring(
            **self._default_scoring_config()
        )

        # Background tasks
        self._db_poll_task:   Optional[asyncio.Task] = None
        self._file_watch_task: Optional[asyncio.Task] = None

        # Local file fallback
        self.file_path  = file_path or os.getenv("CT_FILTER_FILE") or "filters.json"
        self._file_hash: Optional[str] = None

        # Bootstrap: file first, DB will overwrite on first poll
        self._load_from_file()

    # ------------------------------------------------------------------ #
    # Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Start the DB poll loop and file watcher."""
        if self._db_poll_task is None:
            self._db_poll_task = asyncio.create_task(
                self._db_poll_loop(), name="filter-db-poll"
            )
        if self._file_watch_task is None:
            self._file_watch_task = asyncio.create_task(
                self._file_watch_loop(), name="filter-file-watch"
            )
        logger.info(
            "FilterManager started — DB poll every %ds, file poll every %ds",
            DB_POLL_INTERVAL, FILE_POLL_INTERVAL,
        )

    async def stop(self) -> None:
        for task in (self._db_poll_task, self._file_watch_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._db_poll_task    = None
        self._file_watch_task = None

    # ------------------------------------------------------------------ #
    # Public filter API                                                   #
    # ------------------------------------------------------------------ #

    def passes(self, cert: Dict[str, Any]) -> bool:
        """
        Early-pipeline gate: return True if this cert should be kept at all.

        Called immediately after parsing, before scoring and before any DB
        or broadcast work.  Certs that return False are dropped completely —
        they are not scored, not written to ClickHouse, and not broadcast.

        Rules are evaluated against the raw parsed cert fields
        (subject, issuer, dns_names, ct_entry_type).  scripting_score is
        not available at this stage — use score() + should_broadcast() if
        you need score-based post-filtering after the fact.
        """
        with self._lock:
            return self._evaluate(cert, self._write_rules, self._default_action)

    def score(self, cert: Dict[str, Any]) -> int:
        """
        Compute and attach scripting_score to *cert*.
        Called after passes() so scoring only runs on kept certs.
        """
        s = self._scorer.score(cert)
        cert["scripting_score"] = s
        return s

    # Legacy compat
    def should_store(self, cert: Dict[str, Any]) -> bool:
        return self.passes(cert)

    def should_write(self, cert: Dict[str, Any]) -> bool:
        return self.passes(cert)

    def should_broadcast(self, cert: Dict[str, Any]) -> bool:
        return self.passes(cert)

    # ------------------------------------------------------------------ #
    # Settings update (called from Redis subscriber / web app)           #
    # ------------------------------------------------------------------ #

    def update_settings(self, settings: dict, persist: bool = True) -> None:
        """
        Apply new settings dict in-memory and optionally persist to DB/Redis.
        Called from:
          - Redis settings subscriber (persist=False, already in DB)
          - FilterManager._db_poll_loop (persist=False)
          - File watcher (persist=True so other nodes pick it up)
          - Web app API (persist=True)
        """
        self._apply_settings(settings)

        if persist and self._db:
            try:
                self._db.insert_setting(
                    "settings",
                    json.dumps({
                        "default_action": self._default_action,
                        "filters":        self._write_rules,
                    }),
                )
            except Exception:
                logger.exception("Failed to persist filter settings to DB")

        # Redis cert publishing removed

    def load_from_persisted(self, value: str) -> None:
        """Apply a raw JSON string from the DB (e.g. on startup)."""
        try:
            data = json.loads(value) if value else {}
            self._apply_settings(data if isinstance(data, dict) else {})
        except Exception:
            logger.exception("Failed to parse persisted settings")

    # ------------------------------------------------------------------ #
    # DB poll loop                                                        #
    # ------------------------------------------------------------------ #

    async def _db_poll_loop(self) -> None:
        """
        Poll ct_settings every DB_POLL_INTERVAL seconds.
        Only applies the new settings when the JSON has actually changed
        so we don't spam the log on every cycle.
        """
        logger.info("Filter DB poll loop started (interval=%ds)", DB_POLL_INTERVAL)
        while True:
            await asyncio.sleep(DB_POLL_INTERVAL)
            try:
                await self._poll_db_once()
            except Exception:
                logger.exception("Error in filter DB poll loop")

    async def _poll_db_once(self) -> None:
        if self._db is None:
            return
        try:
            raw = await asyncio.to_thread(
                self._db.get_latest_setting, "settings"
            )
        except Exception:
            logger.warning("Filter DB poll: get_latest_setting failed")
            return

        if not raw:
            return

        if raw == self._last_db_json:
            return   # no change

        self._last_db_json = raw
        try:
            data = json.loads(raw)
        except Exception:
            logger.error("Filter DB poll: invalid JSON in ct_settings")
            return

        if isinstance(data, dict):
            self._apply_settings(data)
            logger.info(
                "Filter settings reloaded from DB — default_action=%s rules=%d",
                self._default_action,
                len(self._write_rules),
            )
        elif isinstance(data, list):
            # Legacy: bare list of rules
            self._apply_settings({"default_action": "allow", "filters": data})
            logger.info(
                "Filter settings reloaded from DB (legacy list) — %d rules",
                len(self._broadcast_rules),
            )

    # ------------------------------------------------------------------ #
    # File watcher (fallback / bootstrap)                                #
    # ------------------------------------------------------------------ #

    async def _file_watch_loop(self) -> None:
        while True:
            await asyncio.sleep(FILE_POLL_INTERVAL)
            try:
                await self._check_file_reload()
            except Exception:
                logger.exception("Error in filter file watcher")

    async def _check_file_reload(self) -> None:
        if not os.path.exists(self.file_path):
            return
        try:
            with open(self.file_path, "rb") as fh:
                raw = fh.read()
        except Exception:
            return

        new_hash = hashlib.sha256(raw).hexdigest()
        if new_hash == self._file_hash:
            return

        self._file_hash = new_hash
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            logger.exception("Failed to parse filter file %s", self.file_path)
            return

        settings = (
            data if isinstance(data, dict)
            else {"default_action": "allow", "filters": data}
        )
        logger.info(
            "Filter file changed (%s); applying and persisting", self.file_path
        )
        # Persist to DB so other nodes pick it up via their DB poll
        self.update_settings(settings, persist=True)

    def _load_from_file(self) -> None:
        """Bootstrap: load file synchronously at construction time."""
        if not os.path.exists(self.file_path):
            return
        try:
            with open(self.file_path, "rb") as fh:
                raw = fh.read()
            self._file_hash = hashlib.sha256(raw).hexdigest()
            data = json.loads(raw.decode("utf-8"))
            settings = (
                data if isinstance(data, dict)
                else {"default_action": "allow", "filters": data}
            )
            self._apply_settings(settings)
            logger.info(
                "Bootstrapped filter from file %s — %d write rules, %d broadcast rules",
                self.file_path, len(self._write_rules), len(self._broadcast_rules),
            )
        except Exception:
            logger.exception("Failed to bootstrap filter from file %s", self.file_path)

    # ------------------------------------------------------------------ #
    # Core rule evaluation                                               #
    # ------------------------------------------------------------------ #

    def _apply_settings(self, settings: dict) -> None:
        """Parse a settings dict and update internal state under the lock."""
        default_action = settings.get("default_action", "allow")

        # Accept any of these key names for the rule list
        rules = (
            settings.get("filters")
            or settings.get("write_filters")
            or settings.get("broadcast_filters")
            or []
        )

        with self._lock:
            self._default_action = default_action
            self._write_rules    = [r for r in rules if self._valid_rule(r)]

    @staticmethod
    def _valid_rule(rule: Any) -> bool:
        return (
            isinstance(rule, dict)
            and bool(rule.get("field"))
            and rule.get("value") is not None
        )

    def _evaluate(
        self,
        cert: Dict[str, Any],
        rules: List[Dict],
        default_action: str,
    ) -> bool:
        """
        Evaluate *rules* against *cert*.
        Returns True if the cert should pass (be written or broadcast).

        Logic:
          • No rules → honour default_action.
          • Any rule that matches → flip the default_action result.
            (If default=allow and a rule matches → deny this cert.)
            (If default=deny  and a rule matches → allow this cert.)
        """
        if not rules:
            return default_action == "allow"

        for rule in rules:
            if self._rule_matches(cert, rule):
                # A match means "do the opposite of the default"
                return default_action != "allow"

        return default_action == "allow"

    @staticmethod
    def _rule_matches(cert: Dict[str, Any], rule: Dict) -> bool:
        field = rule.get("field", "")
        op    = rule.get("op", "contains")
        value = rule.get("value")

        if value is None:
            return False

        # ── Numeric field: scripting_score ──────────────────────────────
        if field == "scripting_score":
            try:
                cert_val = int(cert.get("scripting_score", 0))
                threshold = int(value)
                return {
                    "gte": cert_val >= threshold,
                    "lte": cert_val <= threshold,
                    "gt":  cert_val >  threshold,
                    "lt":  cert_val <  threshold,
                    "eq":  cert_val == threshold,
                }.get(op, False)
            except (TypeError, ValueError):
                return False

        # ── String / list fields ────────────────────────────────────────
        raw = cert.get(field, "")
        items = raw if isinstance(raw, list) else [str(raw)]

        for item in items:
            item_str = str(item)
            if op == "contains" and value.lower() in item_str.lower():
                return True
            if op == "equals" and value.lower() == item_str.lower():
                return True
            if op == "regex":
                try:
                    if re.search(value, item_str):
                        return True
                except re.error:
                    pass

        return False

    # ------------------------------------------------------------------ #
    # Scoring config                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _default_scoring_config() -> dict:
        return {
            "keywords": {
                "login": 25, "log-in": 25, "sign-in": 25, "signin": 25,
                "account": 25, "verification": 25, "verify": 25, "webscr": 25,
                "password": 25, "credential": 25, "support": 25, "activity": 25,
                "security": 25, "update": 25, "authentication": 25,
                "authenticate": 25, "authorize": 25, "wallet": 25, "alert": 25,
                "purchase": 25, "transaction": 25, "recover": 25, "unlock": 25,
                "confirm": 20, "live": 15, "office": 15, "service": 15,
                "manage": 15, "portal": 15, "invoice": 15, "secure": 10,
                "customer": 10, "client": 10, "bill": 10, "online": 10,
                "safe": 10, "form": 10,
            },
            "tlds": [
                ".ga", ".gq", ".ml", ".cf", ".tk", ".xyz", ".pw", ".cc",
                ".club", ".work", ".top", ".support", ".bank", ".info",
                ".study", ".click", ".country", ".stream", ".gdn", ".mom",
                ".xin", ".kim", ".men", ".loan", ".download", ".racing",
                ".online", ".center", ".ren", ".gb", ".win", ".review",
                ".vip", ".party", ".tech", ".science", ".business",
            ],
            "confusables": {
                "\u2460": "1", "\u2780": "1", "\U0001D7D0": "2",
            },
        }