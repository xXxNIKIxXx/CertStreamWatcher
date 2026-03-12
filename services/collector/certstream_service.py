"""CertStream collector service – main orchestrator.

Ties together metrics, database, Redis, WebSocket, and CT log polling
components into a single runnable async service.
"""

import asyncio
import os
import threading

from .config import LOG_LIST_URL, REDIS_DISABLED, get_logger
from .ct_logs import CTLogPoller
from .database import DatabaseManager
from .filter_manager import FilterManager
from .metrics import MetricsManager
from .redis_client import RedisPublisher
from .redis_subscriber import RedisSubscriber
from .websocket import WebSocketServer

logger = get_logger("CTStreamService")


class CertStreamService:
    """Initialises all subsystems and runs the CT log poll loop."""

    def __init__(self) -> None:
        from .config import REDIS_DISABLED
        self.metrics = MetricsManager()
        self.db = DatabaseManager(metrics=self.metrics)
        if REDIS_DISABLED:
            self.redis = None
        else:
            self.redis = RedisPublisher(metrics=self.metrics)
        self.ws = WebSocketServer(self.metrics)
        self.filter = FilterManager(db=self.db, redis=self.redis)
        if REDIS_DISABLED:
            self.settings_sub = None
        else:
            self.settings_sub = RedisSubscriber(self._on_settings_message)
        self.poller = CTLogPoller(
            self.metrics, self.db, self.redis, self.ws,
            filter_manager=self.filter,
        )
        self._settings_task: asyncio.Task | None = None

    # ------------------------------------------------------------------ #
    # Settings update handler (called from Redis subscriber)              #
    # ------------------------------------------------------------------ #

    def _on_settings_message(self, payload: dict) -> None:
        """Apply a settings update pushed via Redis."""
        if not payload:
            return
        try:
            msg_type = payload.get("type")
            if msg_type == "settings_update":
                settings = payload.get("settings") or {}
                self.filter.update_settings(settings, persist=False)
                logger.info(
                    "Settings update from Redis: default_action=%s, %d rules",
                    settings.get("default_action"),
                    len(settings.get("filters", [])),
                )
            elif msg_type == "filters_update":
                # Legacy format: bare list of filter rules
                filters = payload.get("filters") or []
                self.filter.update_settings(
                    {"default_action": "allow", "filters": filters},
                    persist=False,
                )
                logger.info(
                    "Legacy filters update from Redis (%d rules)", len(filters)
                )
        except Exception:
            logger.exception("Error handling settings message")

    # ------------------------------------------------------------------ #
    # Start / run                                                          #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Initialise every subsystem, discover logs, and start polling."""
        await self.db.init()

        # Restore the last persisted filter settings from the database
        try:
            persisted = self.db.get_latest_setting("settings")
            if persisted:
                self.filter.load_from_persisted(persisted)
                logger.info("Restored persisted settings from DB")
        except Exception:
            logger.exception("Could not load persisted settings from DB")

        if self.redis is not None:
            await self.redis.init()
        if self.settings_sub is not None:
            await self.settings_sub.init()

        try:
            await self.filter.start()
        except Exception:
            logger.exception("Failed to start filter file watcher")

        # Periodically re-apply DB settings as a Redis fallback
        self._settings_task = asyncio.create_task(self._poll_settings_loop())

        # Discover and start polling
        logs = await self.poller.discover_logs()
        logger.info("Polling %d CT logs (source: %s)", len(logs), LOG_LIST_URL)

        await self.ws.start()

        poll_tasks = [
            asyncio.create_task(self.poller.poll_log(log))
            for log in logs
        ]

        try:
            await asyncio.gather(*poll_tasks)
        finally:
            await self._shutdown()

    async def _shutdown(self) -> None:
        """Gracefully tear down all subsystems."""
        await self.db.close()
        await self.redis.close()
        try:
            await self.settings_sub.close()
        except Exception:
            pass
        if self._settings_task:
            self._settings_task.cancel()
            try:
                await self._settings_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------ #
    # DB settings poll loop (Redis fallback)                              #
    # ------------------------------------------------------------------ #

    async def _poll_settings_loop(self) -> None:
        """Re-apply DB settings on a timer so changes survive Redis restarts."""
        interval = int(os.getenv("CT_SETTINGS_POLL_INTERVAL", "15"))
        last_value: str | None = None

        while True:
            await asyncio.sleep(interval)
            try:
                val = await asyncio.to_thread(self.db.get_latest_setting, "settings")
                if val and val != last_value:
                    self.filter.load_from_persisted(val)
                    logger.info("Applied persisted settings from DB poll")
                    last_value = val
            except Exception:
                logger.exception("Error in settings poll loop")


# --------------------------------------------------------------------------- #
# Entry points                                                                 #
# --------------------------------------------------------------------------- #

async def main() -> None:
    service = CertStreamService()
    await service.start()


def start_certstream(_socketio=None):
    """Start the service in a background daemon thread (for Flask/SocketIO)."""
    def _run():
        try:
            asyncio.run(main())
        except Exception:
            logger.exception("Certstream background runner exited")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    asyncio.run(main())
