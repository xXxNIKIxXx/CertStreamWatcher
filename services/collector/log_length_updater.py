import asyncio
import time as _time
import aiohttp
from .config import get_logger, USER_AGENT
from . import metrics

logger = get_logger("LogLengthUpdater")

_HTTP_CONCURRENCY = 20


class LogLengthUpdater:
    def __init__(self, db_manager, interval: int = 30):
        self.db       = db_manager
        self.interval = interval
        self._running = False
        logger.info(f"LogLengthUpdater initialized, update interval: {interval}s.")

    async def start(self):
        logger.info(f"Starting LogLengthUpdater with interval {self.interval}s.")
        self._running = True
        while self._running:
            normal_logs, tiled_logs = await self._fetch_logs()
            logger.info(
                f"LogLengthUpdater: updating {len(normal_logs)} normal "
                f"and {len(tiled_logs)} tiled logs."
            )
            t0 = _time.monotonic()
            await self._update_all(normal_logs, tiled_logs)
            metrics.log_length_update_duration_seconds.observe(_time.monotonic() - t0)

            # Refresh DB connection-pool gauges each cycle (cheap)
            self.db.update_pool_metrics()

            logger.info(f"LogLengthUpdater: sleeping for {self.interval}s.")
            await asyncio.sleep(self.interval)

    async def stop(self):
        logger.info("Stopping LogLengthUpdater.")
        self._running = False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_logs(self):
        def _query():
            from .models import CTLog
            with self.db.Session() as session:
                logs   = session.query(CTLog).all()
                normal = [l for l in logs if not getattr(l, "is_tiled", False)]
                tiled  = [l for l in logs if     getattr(l, "is_tiled", False)]
                return normal, tiled
        return await asyncio.to_thread(_query)

    async def _update_all(self, normal_logs, tiled_logs):
        semaphore = asyncio.Semaphore(_HTTP_CONCURRENCY)
        connector = aiohttp.TCPConnector(
            limit=_HTTP_CONCURRENCY,
            ttl_dns_cache=300,
            keepalive_timeout=30,
        )
        timeout = aiohttp.ClientTimeout(total=15, connect=5)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        ) as http:
            tasks = [
                self._fetch_normal(http, semaphore, log)
                for log in normal_logs
            ] + [
                self._fetch_tiled(http, semaphore, log)
                for log in tiled_logs
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            else:
                logger.info("No logs to update.")

    async def _fetch_normal(self, http, semaphore, log):
        sth_url = log.url.rstrip("/") + "/ct/v1/get-sth"
        async with semaphore:
            try:
                async with http.get(sth_url) as resp:
                    if resp.status == 200:
                        data      = await resp.json()
                        tree_size = data.get("tree_size")
                        if tree_size is not None:
                            logger.debug(f"[normal] {log.url}  tree_size={tree_size}")
                            metrics.log_length.labels(log_url=log.url).set(tree_size)
                            # Compute backlog if we have a progress gauge
                            try:
                                progress = metrics.log_progress_index.labels(
                                    log_url=log.url
                                )._value.get()
                                metrics.log_backlog.labels(log_url=log.url).set(
                                    max(0, tree_size - progress)
                                )
                            except Exception:
                                pass
                            await self.db.ensure_slices(log.id, tree_size)
                    else:
                        logger.warning(f"[normal] {log.url}  HTTP {resp.status}")
                        metrics.log_length_update_errors_total.labels(
                            log_url=log.url, log_type="normal"
                        ).inc()
            except Exception as exc:
                logger.error(f"[normal] Failed to fetch STH for {log.url}: {exc}")
                metrics.log_length_update_errors_total.labels(
                    log_url=log.url, log_type="normal"
                ).inc()

    async def _fetch_tiled(self, http, semaphore, log):
        checkpoint_url = log.monitoring_url.rstrip("/") + "/checkpoint"
        async with semaphore:
            try:
                async with http.get(checkpoint_url) as resp:
                    if resp.status == 200:
                        text  = await resp.text()
                        lines = text.strip().splitlines()
                        if len(lines) >= 2:
                            try:
                                log_length = int(lines[1])
                                logger.debug(
                                    f"[tiled] {log.monitoring_url}  log_length={log_length}"
                                )
                                metrics.log_length.labels(
                                    log_url=log.monitoring_url
                                ).set(log_length)
                                try:
                                    progress = metrics.log_progress_index.labels(
                                        log_url=log.monitoring_url
                                    )._value.get()
                                    metrics.log_backlog.labels(
                                        log_url=log.monitoring_url
                                    ).set(max(0, log_length - progress))
                                except Exception:
                                    pass
                                await self.db.ensure_slices(log.id, log_length)
                            except Exception as parse_err:
                                logger.error(
                                    f"[tiled] Parse error for "
                                    f"{log.monitoring_url}: {parse_err}"
                                )
                                metrics.log_length_update_errors_total.labels(
                                    log_url=log.monitoring_url, log_type="tiled"
                                ).inc()
                        else:
                            logger.warning(
                                f"[tiled] {log.monitoring_url}  too few lines in checkpoint"
                            )
                            metrics.log_length_update_errors_total.labels(
                                log_url=log.monitoring_url, log_type="tiled"
                            ).inc()
                    else:
                        logger.warning(
                            f"[tiled] {log.monitoring_url}  HTTP {resp.status}"
                        )
                        metrics.log_length_update_errors_total.labels(
                            log_url=log.monitoring_url, log_type="tiled"
                        ).inc()
            except Exception as exc:
                logger.error(
                    f"[tiled] Failed to fetch checkpoint for "
                    f"{log.monitoring_url}: {exc}"
                )
                metrics.log_length_update_errors_total.labels(
                    log_url=log.monitoring_url, log_type="tiled"
                ).inc()