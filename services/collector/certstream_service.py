import asyncio
import threading

from .config import (
    DB,
    SINGLE_NODE,
    WORKER_INDEX,
    WORKER_COUNT,
)

from services.shared.logger import get_logger

from .database import DatabaseManager
from .log_length_updater import LogLengthUpdater

logger = get_logger("CertStreamService")


async def main():
    """Entrypoint for running the collector as a module or script."""
    service = CertStreamService()
    await service.start()


class CertStreamService:
    """Initialises all subsystems and runs the collection pipeline."""

    def __init__(self) -> None:
        self.db = DatabaseManager(DB)
        self._log_length_updater: LogLengthUpdater | None = None

    # ------------------------------------------------------------------ #
    # Start                                                               #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        # Prometheus first — metrics available immediately
        from prometheus_client import start_http_server
        from .config import PROMETHEUS_PORT
        start_http_server(PROMETHEUS_PORT)
        logger.info("Prometheus metrics server on port %d", PROMETHEUS_PORT)

        # DB init (migrations, table creation)
        await self.db.init()

        if SINGLE_NODE:
            await self._run_single_node()
        else:
            await self._run_multi_node()

    # ------------------------------------------------------------------ #
    # Single-node mode                                                    #
    # ------------------------------------------------------------------ #

    async def _run_single_node(self) -> None:
        """Collect all logs locally."""
        logger.info(
            "Running in SINGLE-NODE mode"
        )
        from .cert_collector import collect_all_logs_dynamic

        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        asyncio.create_task(
            collect_all_logs_dynamic(
                self.db,
                poll_interval=30,
            ),
            name="collect-all-logs",
        )
        # Run log-length updater (blocks via its internal loop)
        await self._log_length_updater.start()

    # ------------------------------------------------------------------ #
    # Multi-node mode                                                     #
    # ------------------------------------------------------------------ #

    async def _run_multi_node(self) -> None:
        """
        Multi-node mode: Each node should pick up work from the DB. If a node finishes its assigned logs, it checks for unassigned logs and picks them up.
        No Redis is used. Coordination is done via the database.
        """
        logger.info(
            "Running in MULTI-NODE mode — WORKER_INDEX=%d WORKER_COUNT=%d",
            WORKER_INDEX, WORKER_COUNT,
        )

        # TODO: Implement DB-based coordination for log assignment.
        # For now, fallback to DynamicLogManager as a placeholder.
        from .cert_collector import DynamicLogManager
        manager = DynamicLogManager(
            db=self.db,
            poll_interval=30,
        )
        asyncio.create_task(manager.run(), name="dynamic-log-manager")

        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        await self._log_length_updater.start()

    # ------------------------------------------------------------------ #
    # Shutdown                                                            #
    # ------------------------------------------------------------------ #

    async def _run_multi_node(self) -> None:
        """
        Multi-node mode:
          1. Start WorkCoordinator  elected leader publishes log assignments.
          2. Start WorkSubscriber  receive log assignment, manage local tasks.
          3. Start LogLengthUpdater.
        """
        logger.info(
            "Running in MULTI-NODE mode  WORKER_INDEX=%d WORKER_COUNT=%d",
            WORKER_INDEX, WORKER_COUNT,
        )

        # 1. DynamicLogManager  owns parse/write queues and per-log tasks
        from .cert_collector import DynamicLogManager
        manager = DynamicLogManager(
            db=self.db,
            poll_interval=30,
        )
        asyncio.create_task(manager.run(), name="dynamic-log-manager")

        # 2. LogLengthUpdater
        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        await self._log_length_updater.start()



# start_certstream removed — not needed for simplified codebase


if __name__ == "__main__":
    asyncio.run(main())
