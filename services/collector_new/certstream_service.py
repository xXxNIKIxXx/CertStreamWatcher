"""CertStream collector service – main orchestrator.

Ties together metrics, database, Redis, WebSocket, and CT log polling
components into a single runnable async service.
"""

import asyncio

from .config import REDIS_DISABLED, get_logger, DB
from .database import DatabaseManager
from .log_length_updater import LogLengthUpdater

logger = get_logger("CTStreamService")


class CertStreamService:
    """Initialises all subsystems and runs the CT log poll loop."""

    def __init__(self) -> None:
        # ...existing code...
        self.db = DatabaseManager(DB)
        self.normal_logs = []
        self.tiled_logs = []
        self._settings_task: asyncio.Task | None = None
        # Ensure ct_log_progress table is created with correct engine and TTL
        try:
            from .models import create_all_clickhouse_tables
            create_all_clickhouse_tables(self.db.engine)
        except Exception as e:
            logger.error(f"Failed to create ClickHouse tables: {e}")

    # ------------------------------------------------------------------ #
    # Start / run                                                        #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        # Start Prometheus metrics server
        from prometheus_client import start_http_server
        start_http_server(8001)
        """Initialise every subsystem, discover logs, and start polling."""
        await self.db.init()

        logs = await self.db.get_log_sources()  # Test DB connection and log source query

        logger.info(f"Discovered {len(logs)} log sources from database")

        for log in logs:
            if log.is_tiled:
                self.tiled_logs.append(log)
            else:
                self.normal_logs.append(log)

        logger.info(f"Initialized with {len(self.normal_logs)} normal logs and {len(self.tiled_logs)} tiled logs")


        # High-throughput: one task per log, each collecting as fast as possible
        from .cert_collector import collect_all_logs_dynamic
        asyncio.create_task(collect_all_logs_dynamic(self.db, poll_interval=30))

        self.log_length_updater = LogLengthUpdater(self.db, interval=30)
        await self.log_length_updater.start()
        #await LogLengthUpdater(self.db, self.normal_logs, self.tiled_logs, interval=300).start()
        # Restore the last persisted filter settings from the database
        #try:
        #    persisted = self.db.get_latest_setting("settings")
        #    if persisted:
        #        self.filter.load_from_persisted(persisted)
        #        logger.info("Restored persisted settings from DB")
        #except Exception:
        #    logger.exception("Could not load persisted settings from DB")

        #if self.redis is not None:
        #    await self.redis.init()
        #if self.settings_sub is not None:
        #    await self.settings_sub.init()

        #try:
        #    await self.filter.start()
        #except Exception:
        #    logger.exception("Failed to start filter file watcher")

        # Periodically re-apply DB settings as a Redis fallback
        #self._settings_task = asyncio.create_task(self._poll_settings_loop())

        # Discover and start polling
        #logs = await self.poller.discover_logs()
        #logger.info("Polling %d CT logs", len(logs))

        #await self.ws.start()

        #poll_tasks = [
        #    asyncio.create_task(self.poller.poll_log(log))
        #    for log in logs
        #]

        # Add periodic log length update task
        #log_length_update_task = asyncio.create_task(
        #    self.poller.periodic_log_length_update(logs)
        #)

        #try:
        #    await asyncio.gather(*poll_tasks, log_length_update_task)
        #finally:
        #    await self._shutdown()

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


# --------------------------------------------------------------------------- #
# Entry points                                                                #
# --------------------------------------------------------------------------- #

async def main() -> None:
    service = CertStreamService()
    await service.start()