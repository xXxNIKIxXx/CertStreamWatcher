"""
certstream_service.py – Main orchestrator for the CertStream collector.


Single-node and multi-node modes now use DB polling and worker index for load balancing. Redis is no longer used.
  • Coordinator partitions the CT log list among WORKER_COUNT workers and
    publishes assignments to ct:work:<N> channels every COORD_INTERVAL s.
  • Each worker subscribes to its own channel and starts/stops log tasks
    as assignments change (DynamicLogManager).
  • Parsed certs are published as JSON arrays to ct:certs.
  • Every node runs a WebSocket bridge that subscribes to ct:certs and
    forwards the full stream to locally connected WS clients — so clients
    see the entire cluster output regardless of which node they hit.
  • Settings updates are pushed via ct:settings (unchanged from old service).

Environment variables
─────────────────────

    SINGLE_NODE=1           single-node mode (default: 0)
  CT_WORKER_INDEX         worker shard index (0-based, default: 0)
  CT_WORKER_COUNT         total workers in cluster (default: 1)
  CT_COORD_INTERVAL       coordinator republish interval in seconds (default: 120)
  CT_DB_DSN               ClickHouse DSN
  CT_WS_PORT              WebSocket port (default: 8765)
  CT_PROMETHEUS_PORT      Prometheus metrics port (default: 8001)
"""

import asyncio
import os
import threading

from .config import (
    DB,
    SINGLE_NODE,
    WORKER_INDEX,
    WORKER_COUNT,
)

from services.shared.logger import get_logger

from .database import DatabaseManager
from .filter_manager import FilterManager
from .log_length_updater import LogLengthUpdater
from . import metrics as _prom
from . import metrics as prom_metrics

logger = get_logger("CertStreamService")


async def main():
    """Entrypoint for running the collector as a module or script."""
    service = CertStreamService()
    await service.start()


class CertStreamService:
    """Initialises all subsystems and runs the collection pipeline."""

    def __init__(self) -> None:
        self.db       = DatabaseManager(DB)
        self.ws       = None
        self.filter   = FilterManager(db=self.db)
        self.settings_sub = None
        self._ws_bridge_task: asyncio.Task | None = None
        self._coord_task: asyncio.Task | None = None
        self._work_sub_task: asyncio.Task | None = None
        self._settings_task: asyncio.Task | None = None
        self._log_length_updater: LogLengthUpdater | None = None

        # Ensure ClickHouse tables exist at construction time
        try:
            from .models import create_all_clickhouse_tables
            create_all_clickhouse_tables(self.db.engine)
        except Exception as e:
            logger.error("Failed to create ClickHouse tables: %s", e)

    # ------------------------------------------------------------------ #
    # Settings                                                            #
    # ------------------------------------------------------------------ #

    def _on_settings_message(self, payload: dict) -> None:
        if not payload:
            return
        try:
            msg_type = payload.get("type")
            if msg_type == "settings_update":
                self.filter.update_settings(
                    payload.get("settings") or {}, persist=False
                )
                logger.info("Settings update applied from Redis")
            elif msg_type == "filters_update":
                self.filter.update_settings(
                    {"default_action": "allow",
                     "filters": payload.get("filters") or []},
                    persist=False,
                )
        except Exception:
            logger.exception("Error handling settings message")

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

        # Restore persisted filter settings from DB (DB poll loop will
        # keep them current after this; this is just the initial load)
        try:
            persisted = await self.db.get_latest_setting_async("settings")
            if persisted:
                self.filter.load_from_persisted(persisted)
                logger.info("Restored persisted filter settings from DB")
            else:
                logger.info("No persisted filter settings found; using defaults")
        except Exception:
            logger.exception("Could not load persisted settings")


        if self.settings_sub is not None:
            await self.settings_sub.init()

        # Filter file watcher
        try:
            await self.filter.start()
        except Exception:
            logger.exception("Failed to start filter file watcher")

        # Filter DB poll loop is started inside filter.start() below.
        # We keep a lightweight settings-poll task only as a Redis fallback
        # (in case Redis is down and the DB poll already handles it).
        self._settings_task = asyncio.create_task(
            self._poll_settings_loop(), name="settings-poll"
        )



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
            "Running in SINGLE-NODE mode  no Redis, no sharding."
        )
        from .cert_collector import collect_all_logs_dynamic

        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        asyncio.create_task(
            collect_all_logs_dynamic(
                self.db,
                poll_interval=30,
                filter_manager=self.filter,
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
        Multi-node mode:
          1. Start WebSocket Redis bridge — all nodes subscribe to ct:certs
             and forward to their local WS clients.
          2. Start WorkCoordinator — elected leader publishes log assignments.
          3. Start WorkSubscriber — receive log assignment, manage local tasks.
          4. Start LogLengthUpdater.
        """
        logger.info(
            "Running in MULTI-NODE mode — WORKER_INDEX=%d WORKER_COUNT=%d",
            WORKER_INDEX, WORKER_COUNT,
        )

        # 1. WebSocket bridge: subscribe to ct:certs on Redis → forward to WS


        # 2. DynamicLogManager — owns parse/write queues and per-log tasks
        from .cert_collector import DynamicLogManager
        manager = DynamicLogManager(
            db=self.db,
            redis_publisher=None,
            ws_server=self.ws,
            filter_manager=self.filter,
            poll_interval=30,
        )

        # 3. WorkSubscriber — receives assignments, calls manager.on_assignment

        # All work assignment and sharding is now handled via DB polling and worker index logic.

        # 5. Log-length updater keeps the DB slice table current
        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        asyncio.create_task(
            self._log_length_updater.start(), # type: ignore
        )

        # 6. Publish initial assignment immediately (don't wait for first interval)
        asyncio.create_task(coordinator._publish_assignments())

        # 7. Run the dynamic manager loop (blocks)
        await manager.run()

    # ------------------------------------------------------------------ #
    # Settings poll loop                                                  #
    # ------------------------------------------------------------------ #

    async def _poll_settings_loop(self) -> None:
        interval = int(os.getenv("CT_SETTINGS_POLL_INTERVAL", "15"))
        last_value: str | None = None
        while True:
            await asyncio.sleep(interval)
            try:
                val = await asyncio.to_thread(
                    self.db.get_latest_setting, "settings"
                )
                if val and val != last_value:
                    self.filter.load_from_persisted(val)
                    logger.info("Applied persisted settings from DB poll")
                    last_value = val
            except Exception:
                logger.exception("Error in settings poll loop")

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
            redis_publisher=self.redis,
            ws_server=None,
            filter_manager=self.filter,
            poll_interval=30,
        )
        asyncio.create_task(manager.run(), name="dynamic-log-manager")

        # 2. LogLengthUpdater
        self._log_length_updater = LogLengthUpdater(self.db, interval=30)
        await self._log_length_updater.start()
def start_certstream(_socketio=None):
    """Start the service in a background daemon thread (e.g. for Flask)."""
    def _run():
        try:
            asyncio.run(main())
        except Exception:
            logger.exception("CertStream background runner exited")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    asyncio.run(main())