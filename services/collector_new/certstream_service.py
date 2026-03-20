"""CertStream collector service – main orchestrator."""

import asyncio

from .config import REDIS_DISABLED, get_logger, DB
from .database import DatabaseManager
from .log_length_updater import LogLengthUpdater
from . import metrics   # registers all metric objects before the HTTP server starts

logger = get_logger("CTStreamService")

PROMETHEUS_PORT = 8001


class CertStreamService:
    """Initialises all subsystems and runs the CT log poll loop."""

    def __init__(self) -> None:
        self.db = DatabaseManager(DB)
        self.normal_logs = []
        self.tiled_logs  = []
        self._settings_task: asyncio.Task | None = None
        try:
            from .models import create_all_clickhouse_tables
            create_all_clickhouse_tables(self.db.engine)
        except Exception as e:
            logger.error(f"Failed to create ClickHouse tables: {e}")

    async def start(self) -> None:
        """Initialise every subsystem, discover logs, and start polling."""
        # Start Prometheus scrape endpoint FIRST so metrics are available
        # even before the first collect cycle completes.
        from prometheus_client import start_http_server
        start_http_server(PROMETHEUS_PORT)
        logger.info(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")

        await self.db.init()

        logs = await self.db.get_log_sources()
        logger.info(f"Discovered {len(logs)} log sources from database")

        for log in logs:
            if log.is_tiled:
                self.tiled_logs.append(log)
            else:
                self.normal_logs.append(log)

        logger.info(
            f"Initialized with {len(self.normal_logs)} normal logs "
            f"and {len(self.tiled_logs)} tiled logs"
        )

        from .cert_collector import collect_all_logs_dynamic
        asyncio.create_task(collect_all_logs_dynamic(self.db, poll_interval=30))

        self.log_length_updater = LogLengthUpdater(self.db, interval=30)
        await self.log_length_updater.start()

    async def _shutdown(self) -> None:
        """Gracefully tear down all subsystems."""
        await self.db.close()
        if self._settings_task:
            self._settings_task.cancel()
            try:
                await self._settings_task
            except asyncio.CancelledError:
                pass


async def main() -> None:
    service = CertStreamService()
    await service.start()