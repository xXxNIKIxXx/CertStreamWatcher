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
import asyncio
import hashlib
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
        self._watch_task: asyncio.Task | None = None
        self._file_hash: str | None = None
        self._poll_interval = int(os.getenv("CT_FILTER_POLL_INTERVAL", "5"))
        # load from local file first, then try to load persisted value from DB
        self._load_from_file()

    def _load_from_file(self) -> None:
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    # Accept either list (legacy) or dict ({default_action, filters})
                    if isinstance(data, list):
                        self.rules = data
                        self.default_action = "allow"
                        logger.info(
                            "Loaded %d filter rules from %s",
                            len(self.rules),
                            self.file_path,
                        )
                    elif isinstance(data, dict):
                        self.default_action = data.get("default_action", "allow")
                        self.rules = data.get("filters", []) or []
                        logger.info(
                            "Loaded %d filter rules from %s (default_action=%s)",
                            len(self.rules),
                            self.file_path,
                            self.default_action,
                        )
                    # compute initial hash of the raw file contents
                    try:
                        fh.seek(0)
                        raw = fh.read().encode("utf-8")
                        self._file_hash = hashlib.sha256(raw).hexdigest()
                    except Exception:
                        self._file_hash = None
        except Exception:
            logger.exception("Failed to load filter file %s", self.file_path)

    async def start(self) -> None:
        """Start background watcher task that reloads the filter file on changes.

        This should be called after DB and Redis are initialised so that
        `update_settings` can persist and publish changes.
        """
        if self._watch_task:
            return
        loop = asyncio.get_running_loop()
        self._watch_task = loop.create_task(self._watch_loop())

    async def stop(self) -> None:
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None

    async def _watch_loop(self) -> None:
        while True:
            try:
                await self._check_reload()
            except Exception:
                logger.exception("Error while watching filter file %s", self.file_path)
            await asyncio.sleep(self._poll_interval)

    async def _check_reload(self) -> None:
        # Read file and compute hash to detect changes
        if not os.path.exists(self.file_path):
            return
        try:
            with open(self.file_path, "rb") as fh:
                raw = fh.read()
        except Exception:
            logger.exception("Failed to read filter file %s", self.file_path)
            return

        new_hash = hashlib.sha256(raw).hexdigest()
        if self._file_hash == new_hash:
            return
        # Update stored hash and parse JSON
        self._file_hash = new_hash
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            logger.exception("Failed to parse JSON in filter file %s", self.file_path)
            return

        # Normalize to settings dict expected by update_settings
        if isinstance(data, dict):
            settings = {
                "default_action": data.get("default_action", "allow"),
                "filters": data.get("filters", [])
            }
        elif isinstance(data, list):
            settings = {"default_action": "allow", "filters": data}
        else:
            logger.warning("Filter file %s contained unsupported JSON type", self.file_path)
            return

        logger.info("Detected change in filter file %s; applying settings", self.file_path)
        # Persist and publish so other collectors/web clients pick up the change
        try:
            self.update_settings(settings, persist=True)
        except Exception:
            logger.exception("Failed to apply settings from filter file %s", self.file_path)

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
