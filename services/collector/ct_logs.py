"""CT log discovery and continuous polling.

Each log is polled in a dedicated async task.  Per-batch processing
follows a strict linear pipeline:

    fetch → parse → score → filter → write (DB) + broadcast (Redis + WS)

Scoring always runs so ``scripting_score`` is available in the DB.
Filtering only gates *broadcasting*; every cert (scored or not) is
written to the database so no data is silently dropped.
"""

from __future__ import annotations

import asyncio
import base64
import os
import socket
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from .certificate import CertificateParser
from .config import (
    BACKFILL_DELAY,
    BATCH_SIZE,
    LOG_LIST_URL,
    POLL_INTERVAL,
    PROMETHEUS_PORT,
    WORKER_COUNT,
    WORKER_INDEX,
    get_logger,
)
from .database import DatabaseManager
from .metrics import MetricsManager
from .redis_client import RedisPublisher
from .websocket import WebSocketServer

logger = get_logger("CTStreamService.CTLogs")


class CTLogPoller:
    """Discovers CT logs and continuously polls each one for new entries."""

    def __init__(
        self,
        metrics: MetricsManager,
        db: DatabaseManager,
        redis: RedisPublisher,
        ws: WebSocketServer,
        filter_manager=None,
    ) -> None:
        self._metrics = metrics
        self._db = db
        self._redis = redis
        self._ws = ws
        self._filter = filter_manager
        self._log_states: Dict[str, int] = {}
        self._parser = CertificateParser()

    # ------------------------------------------------------------------ #
    # Log discovery                                                        #
    # ------------------------------------------------------------------ #

    async def discover_logs(self) -> List[str]:
        """Fetch the public CT log list and return usable log URLs."""
        async with aiohttp.ClientSession() as session:
            data = await self._fetch_json(session, LOG_LIST_URL)

        logs: List[str] = []
        for operator in data.get("operators", []):
            for entry in operator.get("logs", []):
                url = entry.get("url")
                if not url:
                    continue

                parsed = urlparse(url)
                host = parsed.hostname or (
                    parsed.path.split("/")[0] if parsed.path else None
                )
                if not host:
                    continue

                # Skip logs whose hostname doesn't resolve
                try:
                    loop = asyncio.get_running_loop()
                    await asyncio.wait_for(
                        loop.getaddrinfo(host, None), timeout=2.0
                    )
                except Exception:
                    logger.warning("Unresolvable CT log host: %s", host)
                    self._metrics.skipped_logs.inc()
                    continue

                scheme = parsed.scheme or "https"
                netloc = parsed.netloc or host
                base_path = parsed.path.rstrip("/")
                log_url = (
                    f"{scheme}://{netloc}{base_path}"
                    if base_path
                    else f"{scheme}://{netloc}"
                )
                logs.append(log_url)

        self._metrics.total_logs.set(len(logs))
        logger.debug("Discovered %d CT logs total", len(logs))
        return self._partition_logs(logs)

    # ------------------------------------------------------------------ #
    # Polling loop                                                         #
    # ------------------------------------------------------------------ #

    async def poll_log(self, log_url: str) -> None:
        """Continuously poll a single CT log, processing new entries."""
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while True:
                try:
                    had_work = await self._poll_once(session, log_url)
                except Exception:
                    logger.exception("Unhandled error polling %s", log_url)
                    self._metrics.poll_errors.inc()
                    had_work = False

                await asyncio.sleep(BACKFILL_DELAY if had_work else POLL_INTERVAL)

    # ------------------------------------------------------------------ #
    # Single poll cycle                                                    #
    # ------------------------------------------------------------------ #

    async def _poll_once(
        self, session: aiohttp.ClientSession, log_url: str
    ) -> bool:
        """Fetch one batch from *log_url*, run the full pipeline, return True
        when at least one entry was processed."""

        # 1. Fetch signed tree head to find how many entries are available
        sth = await self._fetch_json(session, f"{log_url}/ct/v1/get-sth")
        if not sth or "tree_size" not in sth:
            logger.warning("Invalid STH from %s; will retry", log_url)
            return False

        tree_size: int = sth["tree_size"]
        last_index: int = self._log_states.get(log_url, 0)
        if tree_size <= last_index:
            return False

        start = last_index
        end = min(tree_size - 1, start + BATCH_SIZE - 1)
        batch_t0 = time.monotonic()

        # 2. Fetch entries
        entries_data = await self._fetch_json(
            session, f"{log_url}/ct/v1/get-entries?start={start}&end={end}"
        )
        entry_list = entries_data.get("entries", []) if entries_data else []
        self._metrics.batch_entries_fetched.observe(len(entry_list))

        # 3. Parse → Score → Filter → Write/Broadcast (per-batch pipeline)
        to_broadcast: List[dict] = []

        for idx, raw_entry in enumerate(entry_list, start=start):
            self._metrics.entries_processed.inc()

            # -- Parse --
            cert = self._parse_entry(raw_entry, log_url, idx)
            if cert is None:
                continue

            # -- Score (always; result stored in DB) --
            cert = self._score_cert(cert)

            # -- Write to DB (every cert, regardless of filter) --
            self._db.buffer_cert(cert)

            # -- Filter for broadcasting --
            if self._should_broadcast(cert):
                to_broadcast.append(cert)

        # 4. Flush DB buffer once per batch
        if self._db.available:
            try:
                await self._db.flush()
            except Exception:
                logger.exception("DB flush failed for batch from %s", log_url)

        # 5. Broadcast filtered certs (Redis pipeline + WebSocket)
        if to_broadcast:
            await self._broadcast_batch(to_broadcast)

        self._log_states[log_url] = end + 1
        self._metrics.last_index.labels(log=log_url).set(end + 1)
        self._metrics.batch_processing_duration_seconds.observe(
            time.monotonic() - batch_t0
        )
        return bool(entry_list)

    # ------------------------------------------------------------------ #
    # Pipeline steps                                                       #
    # ------------------------------------------------------------------ #

    def _parse_entry(
        self, raw_entry: dict, log_url: str, idx: int
    ) -> Optional[dict]:
        """Decode and parse a raw CT log entry into a certificate dict.

        Returns ``None`` when the entry cannot be decoded or parsed.
        """
        try:
            leaf = base64.b64decode(raw_entry["leaf_input"])
        except Exception:
            self._metrics.extraction_failures.inc()
            return None

        header = CertificateParser.parse_leaf_header(leaf)
        if header is None:
            self._metrics.extraction_failures.inc()
            return None

        leaf_version, leaf_type, entry_type = header

        # Emit leaf classification metrics
        try:
            self._metrics.leaf_version.labels(version=str(leaf_version)).inc()
            self._metrics.leaf_type.labels(leaf_type=str(leaf_type)).inc()
            self._metrics.entry_type.labels(entry_type=str(entry_type)).inc()
        except Exception:
            pass

        # Only X.509 (0) and Precertificate (1) entry types are supported
        if entry_type not in (0, 1):
            try:
                self._metrics.skipped_entry_type.labels(
                    entry_type=str(entry_type)
                ).inc()
            except Exception:
                pass
            return None

        cert: Optional[dict] = None

        # For precert entries, prefer parsing from extra_data which contains
        # the actual pre-certificate DER (RFC 6962 PrecertChainEntry)
        if entry_type == 1 and raw_entry.get("extra_data"):
            cert = self._parse_precert(raw_entry["extra_data"], log_url, idx)

        # Fall back to leaf-based extraction for x509 entries or when
        # extra_data parsing failed
        if cert is None:
            try:
                with self._metrics.parse_duration.time():
                    cert = self._parser.extract_and_parse(
                        leaf, log_url, entry_type=entry_type
                    )
            except Exception:
                logger.exception("[%s] Parse error at index %s", log_url, idx)
                cert = None

        if cert is None:
            self._metrics.parse_failures.inc()
            try:
                self._metrics.parse_failures_by_log.labels(log=log_url).inc()
            except Exception:
                pass
            logger.debug(
                "[%s] No cert produced at index=%s entry_type=%s",
                log_url, idx, entry_type,
            )
            return None

        # Attach CT leaf metadata
        cert.setdefault("ct_leaf_version", leaf_version)
        cert.setdefault("ct_leaf_type", leaf_type)
        cert.setdefault("ct_entry_type_numeric", entry_type)
        try:
            cert.setdefault("ct_timestamp", int.from_bytes(leaf[2:10], "big"))
        except Exception:
            cert.setdefault("ct_timestamp", None)
        cert.setdefault("ct_index", idx)

        self._metrics.parse_successes.inc()
        self._metrics.certs_by_log.labels(log=log_url).inc()
        try:
            self._metrics.cert_version.labels(
                version=cert.get("version", "unknown")
            ).inc()
        except Exception:
            pass

        return cert

    def _parse_precert(
        self, extra_data_b64: str, log_url: str, idx: int
    ) -> Optional[dict]:
        """Parse a precertificate from the raw extra_data field."""
        try:
            extra_der = base64.b64decode(extra_data_b64)
            # RFC 6962: PrecertChainEntry encodes certs as uint24-prefixed blobs
            candidate: Optional[bytes] = None
            if len(extra_der) >= 3:
                cert_len = int.from_bytes(extra_der[0:3], "big")
                if 3 + cert_len <= len(extra_der):
                    candidate = extra_der[3: 3 + cert_len]

            with self._metrics.parse_duration.time():
                parsed = self._parser.parse(candidate or extra_der, log_url)

            if parsed:
                parsed["ct_entry_type"] = "precert"
                parsed["format"] = "der"
            return parsed

        except Exception:
            logger.debug(
                "[%s] Precert extra_data parse failed at index=%s",
                log_url, idx, exc_info=True,
            )
            return None

    @staticmethod
    def _score_cert(cert: dict) -> dict:
        """Attach ``scripting_score`` to *cert* (already set by FilterManager,
        but run here to guarantee it exists before the DB write)."""
        cert.setdefault("scripting_score", 0)
        return cert

    def _should_broadcast(self, cert: dict) -> bool:
        """Return True when the cert should be published / broadcast."""
        if self._filter is None:
            return True
        try:
            return self._filter.should_store(cert)
        except Exception:
            logger.exception("Filter error; defaulting to broadcast=True")
            return True

    async def _broadcast_batch(self, certs: List[dict]) -> None:
        """Publish a batch of certs to Redis (if available) and WebSocket clients."""
        if self._redis.available:
            try:
                await self._redis.publish_batch(certs)
            except Exception:
                logger.exception("Redis batch publish failed")

        if self._ws.client_count > 0:
            try:
                await self._ws.broadcast_batch(certs)
            except Exception:
                logger.exception("WebSocket batch broadcast failed")

    # ------------------------------------------------------------------ #
    # HTTP helper                                                          #
    # ------------------------------------------------------------------ #

    async def _fetch_json(
        self, session: aiohttp.ClientSession, url: str
    ) -> dict:
        """GET *url* and return parsed JSON.  Retries on transient errors."""
        max_attempts = int(os.getenv("HTTP_RETRIES", "5"))
        backoff_base = float(os.getenv("HTTP_RETRY_BACKOFF", "1.0"))
        t0 = time.monotonic()

        for attempt in range(1, max_attempts + 1):
            try:
                async with session.get(url) as resp:
                    elapsed = time.monotonic() - t0
                    try:
                        self._metrics.http_requests_total.labels(
                            method="GET", status=str(resp.status)
                        ).inc()
                        self._metrics.http_request_duration_seconds.observe(elapsed)
                    except Exception:
                        pass
                    resp.raise_for_status()
                    return await resp.json()

            except (
                aiohttp.ClientConnectorError,
                aiohttp.client_exceptions.ClientConnectorDNSError,
                socket.gaierror,
                asyncio.TimeoutError,
            ) as exc:
                self._record_http_error(t0)
                logger.warning(
                    "Transient error fetching %s (attempt %d/%d): %s",
                    url, attempt, max_attempts, exc,
                )
                if attempt == max_attempts:
                    logger.error(
                        "Giving up fetching %s after %d attempts", url, max_attempts
                    )
                    return {}
                await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))

            except Exception:
                self._record_http_error(t0)
                logger.exception("Non-retryable error fetching %s", url)
                return {}

        return {}

    def _record_http_error(self, t0: float) -> None:
        elapsed = time.monotonic() - t0
        try:
            self._metrics.http_requests_total.labels(
                method="GET", status="error"
            ).inc()
            self._metrics.http_request_duration_seconds.observe(elapsed)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Worker partitioning                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _partition_logs(logs: List[str]) -> List[str]:
        """Return the slice of *logs* assigned to this worker replica."""
        widx_env = os.getenv("CT_WORKER_INDEX")
        wcount_env = os.getenv("CT_WORKER_COUNT")

        if widx_env is not None and wcount_env is not None:
            widx, wcount = int(widx_env), int(wcount_env)
        else:
            widx, wcount = CTLogPoller._auto_discover_index()

        if wcount <= 1:
            return logs

        assigned = [l for i, l in enumerate(logs) if (i % wcount) == widx]
        logger.info(
            "Worker %d/%d assigned %d of %d logs",
            widx, wcount, len(assigned), len(logs),
        )
        return assigned

    @staticmethod
    def _auto_discover_index():
        """Derive worker index from DNS peer resolution of the service name."""
        import socket as _socket

        service_name = os.getenv("CT_SERVICE_NAME", "collector")
        port = int(os.getenv("CT_PROMETHEUS_PORT", str(PROMETHEUS_PORT)))

        my_hostname = _socket.gethostname()
        try:
            my_addrs = {
                addr[4][0]
                for addr in _socket.getaddrinfo(my_hostname, None)
            }
        except _socket.gaierror:
            my_addrs = set()

        try:
            peer_addrs = _socket.getaddrinfo(
                service_name, port, proto=_socket.IPPROTO_TCP
            )
            all_ips = sorted({addr[4][0] for addr in peer_addrs})
        except _socket.gaierror:
            logger.warning(
                "DNS lookup for '%s' failed; running as sole worker", service_name
            )
            return 0, 1

        wcount = len(all_ips)
        if wcount == 0:
            return 0, 1

        for idx, ip in enumerate(all_ips):
            if ip in my_addrs:
                logger.info(
                    "Auto-discovered index %d/%d (IP %s in '%s')",
                    idx, wcount, ip, service_name,
                )
                return idx, wcount

        # Fallback: hash hostname to a deterministic position
        widx = hash(my_hostname) % wcount
        logger.warning(
            "Could not match own IP in '%s' peers; hash-based index %d/%d",
            service_name, widx, wcount,
        )
        return widx, wcount
