"""
In-memory filter manager backed by a local file and persisted to
ClickHouse/Redis.

Simple deny-list rules are supported. Rules are JSON list of objects:
    {"field": "subject|issuer|dns_names", "op": "contains|equals",
     "value": "example.com"}

If any rule matches a cert, the cert is rejected (not stored/broadcast).
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Dict, Any

from .config import get_logger

logger = get_logger("CTStreamService.FilterManager")


class FilterManager:
    def __init__(self, db=None, redis=None, file_path: str | None = None):
        self._db = db
        self._redis = redis
        self.file_path = (
            file_path or os.getenv("CT_FILTER_FILE") or "filters.json"
        )
        self.rules: List[Dict[str, Any]] = []
        self.default_action: str = "allow"  # can be "allow" or "deny"
        # load from local file first, then try to load persisted value from DB
        self._load_from_file()

    def _load_from_file(self) -> None:
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        self.rules = data
                        logger.info(
                            "Loaded %d filter rules from %s",
                            len(self.rules),
                            self.file_path,
                        )
        except Exception:
            logger.exception("Failed to load filter file %s", self.file_path)

    def update_settings(self, settings: dict, persist: bool = True) -> None:
        """
        Update in-memory settings (default_action, rules) and
        optionally persist/publish.
        """
        self.default_action = settings.get("default_action", "allow")
        self.rules = settings.get("filters", []) or []
        logger.info(
            "Updated filter settings: default_action=%s, %d rules",
            self.default_action,
            len(self.rules),
        )
        if persist and self._db:
            try:
                self._db.insert_setting(
                    "settings",
                    json.dumps({
                        "default_action": self.default_action,
                        "filters": self.rules
                    })
                )
            except Exception:
                logger.exception("Failed to persist settings to DB")
        if persist and self._redis:
            try:
                msg = {
                    "type": "settings_update",
                    "settings": {
                        "default_action": self.default_action,
                        "filters": self.rules
                    }
                }
                coro = getattr(self._redis, "publish", None)
                if coro:
                    try:
                        import asyncio
                        asyncio.create_task(self._redis.publish(msg))
                    except Exception:
                        pass
            except Exception:
                logger.exception("Failed to publish settings to Redis")

    def should_store(self, cert: Dict[str, Any]) -> bool:
        """
        Return True if cert should be stored/broadcast, using rules and
        default_action.
        """
        if not self.rules:
            return self.default_action == "allow"

        for rule in self.rules:
            field = rule.get("field")
            op = rule.get("op") or "contains"
            value = rule.get("value")
            if not field or value is None:
                continue

            hay = cert.get(field, "")
            if isinstance(hay, list):
                hay_items = hay
            else:
                hay_items = [str(hay)]

            for item in hay_items:
                item_str = str(item)
                if op == "contains" and value.lower() in item_str.lower():
                    return self.default_action != "allow"
                if op == "equals" and value.lower() == item_str.lower():
                    return self.default_action != "allow"
                if op == "regex":
                    try:
                        if re.search(value, item_str):
                            return self.default_action != "allow"
                    except re.error:
                        continue

        return self.default_action == "allow"

    def load_from_persisted(self, value: str) -> None:
        try:
            data = json.loads(value) if value else {}
            if isinstance(data, dict):
                self.default_action = data.get("default_action", "allow")
                self.rules = data.get("filters", [])
                logger.info(
                    "Loaded persisted settings: default_action=%s, %d rules",
                    self.default_action,
                    len(self.rules),
                )
            elif isinstance(data, list):
                # legacy: just a list of rules
                self.rules = data
                self.default_action = "allow"
                logger.info(
                    "Loaded legacy persisted filter rules (%d)",
                    len(self.rules)
                )
        except Exception:
            logger.exception("Failed to parse persisted settings value")
