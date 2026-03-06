"""CertStream collector service – main orchestrator.

Ties together metrics, database, Redis, WebSocket, and CT log polling
components into a single runnable service.
"""

import asyncio
import threading

from .config import LOG_LIST_URL, get_logger
from .ct_logs import CTLogPoller
from .database import DatabaseManager
from .metrics import MetricsManager
from .redis_client import RedisPublisher
from .websocket import WebSocketServer
from .filter_manager import FilterManager
import os
from .redis_subscriber import RedisSubscriber

logger = get_logger("CTStreamService")


class CertStreamService:
    """Initialises all subsystems and runs the poll loop."""

    def __init__(self) -> None:
        self.metrics = MetricsManager()
        self.db = DatabaseManager(metrics=self.metrics)
        self.redis = RedisPublisher(metrics=self.metrics)
        self.ws = WebSocketServer(self.metrics)
        # Filter manager loads local rules and can persist/publish updates
        self.filter = FilterManager(db=self.db, redis=self.redis)
        # Redis subscriber listens for settings updates and applies them live
        self.settings_sub = RedisSubscriber(self._on_settings_message)
        self.poller = CTLogPoller(
            self.metrics, self.db, self.redis, self.ws,
            filter_manager=self.filter
        )
        self._settings_task: asyncio.Task | None = None

    def _on_settings_message(self, payload: dict) -> None:
        """Handle incoming settings messages from Redis (synchronous callback).

        Expected payload: {"type":"settings_update", "settings": {...}}
        """
        try:
            if not payload:
                return
            if payload.get("type") == "settings_update":
                settings = payload.get("settings") or {}
                try:
                    self.filter.update_settings(settings, persist=False)
                    logger.info(
                        "Settings update from Redis (default_action=%s, "
                        "%d rules)",
                        settings.get("default_action"),
                        len(settings.get("filters", [])),
                    )
                except Exception:
                    logger.exception("Failed to apply settings update")
            elif payload.get("type") == "filters_update":
                # legacy support
                filters = payload.get("filters") or []
                try:
                    self.filter.update_settings(
                        {"default_action": "allow", "filters": filters},
                        persist=False
                    )
                    logger.info(
                        "Legacy filters update from Redis (%d entries)",
                        len(filters),
                    )
                except Exception:
                    logger.exception("Failed to apply legacy filters update")
        except Exception:
            logger.exception("Error handling settings message")

    async def start(self) -> None:
        """Initialise subsystems, discover logs, and start polling."""
        # Best-effort init for DB and Redis
        await self.db.init()
        # Load persisted filters from DB (if any) and apply them
        try:
            persisted = self.db.get_latest_setting("settings")
            if persisted:
                self.filter.load_from_persisted(persisted)
                logger.info("Loaded persisted settings from DB")
        except Exception:
            logger.exception("Failed to load persisted settings from DB")
        await self.redis.init()
        # start settings subscriber (will no-op if Redis not configured)
        await self.settings_sub.init()

        # Start filter file watcher (if a filter file is mounted)
        try:
            await self.filter.start()
        except Exception:
            logger.exception("Failed to start filter file watcher")

        # Start background poller to fetch persisted settings periodically
        self._settings_task = asyncio.create_task(self._poll_settings_loop())

        logs = await self.poller.discover_logs()
        logger.info("Fetched %d CT logs from %s", len(logs), LOG_LIST_URL)

        # Start WebSocket server
        await self.ws.start()

        # Start per-log pollers
        tasks = [
            asyncio.create_task(self.poller.poll_log(log))
            for log in logs
        ]

        try:
            await asyncio.gather(*tasks)
        finally:
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

    async def _poll_settings_loop(self) -> None:
        """
        Periodically poll the DB for persisted settings as a Redis fallback.
        """
        last_value = None
        while True:
            try:
                # run synchronous DB query in thread
                val = await asyncio.to_thread(
                    self.db.get_latest_setting, "settings"
                )
                if val and val != last_value:
                    try:
                        self.filter.load_from_persisted(val)
                        logger.info(
                            "Applied persisted settings from DB (polled)"
                        )
                        last_value = val
                    except Exception:
                        logger.exception(
                            "Failed applying persisted settings from polled "
                            "DB value"
                        )
            except Exception:
                logger.exception("Error polling persisted settings from DB")
            await asyncio.sleep(
                int(os.getenv("CT_SETTINGS_POLL_INTERVAL", "15"))
            )


async def main() -> None:
    """Entry point for ``python -m services.collector.certstream_service``."""
    service = CertStreamService()
    await service.start()


def start_certstream(_socketio=None):
    """Entry used by Flask app to start certstream as a background task.

    Runs the async main loop in a background thread so it doesn't block
    the Flask/SocketIO process.  The optional ``_socketio`` parameter is
    accepted for compatibility with ``socketio.start_background_task``.
    """

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
