"""CT log discovery and polling.

This module discovers public CT logs and continuously polls each log
for new entries. Polling is batched (controlled by `BATCH_SIZE`) and
parses entries in a CPU-bound phase followed by batched I/O (DB/Redis).
Configuration and tuning knobs are provided via environment variables
to allow scaling and performance experimentation without code changes.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
import socket
from typing import Dict, List
from urllib.parse import urlparse

import aiohttp

from .certificate import CertificateParser
from .config import (
    BACKFILL_DELAY,
    BATCH_SIZE,
    LOG_LIST_URL,
    POLL_INTERVAL,
    WORKER_COUNT,
    WORKER_INDEX,
    PROMETHEUS_PORT,
    get_logger,
)
from .database import DatabaseManager
from .metrics import MetricsManager
from .redis_client import RedisPublisher
from .websocket import WebSocketServer

logger = get_logger("CTStreamService.CTLogs")


class CTLogPoller:
    """Discovers CT logs and polls each one for new certificate entries."""

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

    # ------------------------------------------------------------------
    # Log discovery
    # ------------------------------------------------------------------

    async def discover_logs(self) -> List[str]:
        """Fetch the public CT log list and return usable log URLs."""
        async with aiohttp.ClientSession() as session:
            data = await self._fetch_json(session, LOG_LIST_URL)
            logs: list[str] = []

            for operator in data.get("operators", []):
                for log_entry in operator.get("logs", []):
                    url = log_entry.get("url")
                    if not url:
                        continue

                    parsed = urlparse(url)
                    host = parsed.hostname or (
                        parsed.path.split("/")[0] if parsed.path else None
                    )
                    if not host:
                        continue

                    # Verify hostname resolves
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

                    logger.debug("Adding CT log: %s", log_url)
                    logs.append(log_url)

            self._metrics.total_logs.set(len(logs))
            logger.debug("Total CT logs discovered: %d", len(logs))

            return self._partition_logs(logs)

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    async def poll_log(self, log_url: str) -> None:
        """Continuously poll a single CT log for new entries."""
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while True:
                had_work = False
                try:
                    had_work = await self._poll_once(session, log_url)
                except Exception as exc:
                    logger.error("Error polling %s: %s", log_url, exc)
                    self._metrics.poll_errors.inc()

                # Only sleep when caught up; short delay during backfill
                if not had_work:
                    await asyncio.sleep(POLL_INTERVAL)
                else:
                    await asyncio.sleep(BACKFILL_DELAY)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _poll_once(
        self, session: aiohttp.ClientSession, log_url: str
    ) -> bool:
        """Poll one batch from a CT log.  Returns True when entries were found."""
        sth = await self._fetch_json(session, f"{log_url}/ct/v1/get-sth")
        # If STH fetch failed (transient network error), _fetch_json
        # will return an empty dict. Treat that as no work and retry
        # on the next polling cycle instead of crashing.
        if not sth or "tree_size" not in sth:
            logger.warning("Invalid or missing STH from %s; will retry", log_url)
            return False

        tree_size = sth.get("tree_size")

        last_index = self._log_states.get(log_url, 0)
        if tree_size <= last_index:
            return False

        start = last_index
        end = min(tree_size - 1, start + BATCH_SIZE - 1)

        batch_t0 = time.monotonic()

        entries_data = await self._fetch_json(
            session, f"{log_url}/ct/v1/get-entries?start={start}&end={end}"
        )
        entry_list = entries_data.get("entries", []) if entries_data else []

        self._metrics.batch_entries_fetched.observe(len(entry_list))

        # ── Phase 1: CPU-bound parsing (single pass per cert) ────────
        parsed_certs = []
        for idx, entry in enumerate(entry_list, start=start):
            self._metrics.entries_processed.inc()
            leaf = base64.b64decode(entry["leaf_input"])

            header = CertificateParser.parse_leaf_header(leaf)
            if header is None:
                self._metrics.extraction_failures.inc()
                continue

            leaf_version, leaf_type, entry_type = header
            try:
                self._metrics.leaf_version.labels(version=str(leaf_version)).inc()
            except Exception:
                pass
            try:
                self._metrics.leaf_type.labels(leaf_type=str(leaf_type)).inc()
            except Exception:
                pass
            try:
                self._metrics.entry_type.labels(entry_type=str(entry_type)).inc()
            except Exception:
                pass

            # Accept both X.509 (0) and Precertificate (1) entry types.
            if entry_type not in (0, 1):
                try:
                    self._metrics.skipped_entry_type.labels(
                        entry_type=str(entry_type)
                    ).inc()
                except Exception:
                    pass
                continue

            # Single-pass extraction + parsing (no double DER decode)
            cert = None
            # For Precertificate entries the DER may be present in the
            # entry's `extra_data` field returned by the CT get-entries API.
            # Prefer parsing that when available to correctly handle precerts.
            if entry_type == 1 and entry.get("extra_data"):
                try:
                    extra_der = base64.b64decode(entry.get("extra_data"))
                    # Per RFC6962 the PrecertChainEntry encodes ASN.1Cert
                    # items as uint24 length-prefixed blobs. Try to extract
                    # the first ASN.1Cert (the pre-certificate) and parse
                    # only that slice to avoid parsing wrapper structures.
                    candidate = None
                    if len(extra_der) >= 3:
                        try:
                            cert_len = int.from_bytes(extra_der[0:3], "big")
                            if 3 + cert_len <= len(extra_der):
                                candidate = extra_der[3 : 3 + cert_len]
                        except Exception:
                            candidate = None

                    to_try = candidate or extra_der
                    with self._metrics.parse_duration.time():
                        parsed = self._parser.parse(to_try, log_url)
                    if parsed:
                        # Attach RFC 6962 leaf metadata so downstream
                        # systems know this came from a Precertificate entry.
                        parsed["ct_entry_type"] = "precert"
                        parsed["format"] = "der"
                        parsed["ct_leaf_version"] = leaf_version
                        parsed["ct_leaf_type"] = leaf_type
                        parsed["ct_entry_type_numeric"] = entry_type
                        try:
                            parsed["ct_timestamp"] = int.from_bytes(
                                leaf[2:10], "big"
                            )
                        except Exception:
                            parsed["ct_timestamp"] = None
                        parsed["ct_index"] = idx
                        cert = parsed
                except Exception as exc:
                    # Debug: include traceback and a short excerpt of the data
                    try:
                        extra_preview = entry.get("extra_data")[:160]
                    except Exception:
                        extra_preview = None
                    logger.debug(
                        "[%s] Precert extra_data parse failed at index=%s: %s; extra_data_prefix=%s",
                        log_url,
                        idx,
                        exc,
                        extra_preview,
                        exc_info=True,
                    )

            if cert is None:
                try:
                    with self._metrics.parse_duration.time():
                        cert = self._parser.extract_and_parse(
                            leaf, log_url, entry_type=entry_type
                        )
                except Exception as exc:
                    # Keep the error-level log for visibility, but also emit a
                    # debug log with full traceback and a short leaf preview
                    try:
                        leaf_preview = base64.b64encode(leaf)[:160].decode('ascii')
                    except Exception:
                        leaf_preview = None
                    logger.exception(
                        "[%s] Parse error at index=%s: %s", log_url, idx, exc
                    )
                    logger.debug(
                        "[%s] Parse error details index=%s entry_type=%s leaf_prefix=%s",
                        log_url,
                        idx,
                        entry_type,
                        leaf_preview,
                        exc_info=True,
                    )
                    cert = None

            if cert:
                # Ensure leaf metadata exists on certs parsed via leaf
                if "ct_leaf_version" not in cert:
                    try:
                        cert["ct_leaf_version"] = leaf_version
                        cert["ct_leaf_type"] = leaf_type
                        cert["ct_entry_type_numeric"] = entry_type
                        cert["ct_timestamp"] = int.from_bytes(leaf[2:10], "big")
                        cert["ct_index"] = idx
                    except Exception:
                        cert.setdefault("ct_timestamp", None)
                parsed_certs.append(cert)
                self._metrics.parse_successes.inc()
                self._metrics.certs_by_log.labels(log=log_url).inc()
                try:
                    self._metrics.cert_version.labels(
                        version=cert.get("version", "unknown")
                    ).inc()
                except Exception:
                    pass
            else:
                # No cert parsed — record metric and emit debug context to aid
                # investigation (no sensitive keys, only short previews).
                self._metrics.parse_failures.inc()
                try:
                    self._metrics.parse_failures_by_log.labels(
                        log=log_url
                    ).inc()
                except Exception:
                    pass
                try:
                    leaf_preview = base64.b64encode(leaf)[:160].decode('ascii')
                except Exception:
                    leaf_preview = None
                logger.debug(
                    "[%s] Parsing returned no cert at index=%s entry_type=%s leaf_prefix=%s entry_keys=%s",
                    log_url,
                    idx,
                    entry_type,
                    leaf_preview,
                    list(entry.keys()) if isinstance(entry, dict) else None,
                )

        # ── Phase 2: Batched I/O ─────────────────────────────────────
        if parsed_certs:
            # Buffer all certs then flush once (one HTTP round-trip)
            # apply filtering (if present)
            to_store = []
            for cert in parsed_certs:
                try:
                    if self._filter and not self._filter.should_store(cert):
                        # dropped by filter
                        continue
                except Exception:
                    # on filter error, be conservative and keep cert
                    logger.exception("Filter error; accepting cert")
                to_store.append(cert)

            if self._db.available and to_store:
                for cert in to_store:
                    self._db.buffer_cert(cert)
                try:
                    await self._db.flush()
                except Exception:
                    logger.exception("Batch DB flush failed")

            # Redis pipeline publish
            if self._redis.available and to_store:
                try:
                    await self._redis.publish_batch(to_store)
                except Exception:
                    logger.exception("Batch Redis publish failed")

            # WebSocket broadcast
            if self._ws.client_count > 0 and to_store:
                try:
                    await self._ws.broadcast_batch(to_store)
                except Exception:
                    logger.exception("Batch WS broadcast failed")

        try:
            self._metrics.last_index.labels(log=log_url).set(end + 1)
        except Exception:
            pass

        self._metrics.batch_processing_duration_seconds.observe(
            time.monotonic() - batch_t0
        )
        self._log_states[log_url] = end + 1
        return True

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _fetch_json(self, session: aiohttp.ClientSession, url: str) -> dict:
        t0 = time.monotonic()
        # Retry on transient network/DNS/connectivity errors so the
        # whole process doesn't crash on temporary outages.
        max_attempts = int(os.getenv("HTTP_RETRIES", "5"))
        backoff_base = float(os.getenv("HTTP_RETRY_BACKOFF", "1.0"))

        for attempt in range(1, max_attempts + 1):
            try:
                async with session.get(url) as resp:
                    elapsed = time.monotonic() - t0
                    status = str(resp.status)
                    try:
                        self._metrics.http_requests_total.labels(
                            method="GET", status=status
                        ).inc()
                        self._metrics.http_request_duration_seconds.observe(elapsed)
                    except Exception:
                        pass
                    resp.raise_for_status()
                    data = await resp.json()
                    return data
            except (
                aiohttp.ClientConnectorError,
                aiohttp.client_exceptions.ClientConnectorDNSError,
                socket.gaierror,
                asyncio.TimeoutError,
            ) as exc:
                elapsed = time.monotonic() - t0
                try:
                    self._metrics.http_requests_total.labels(
                        method="GET", status="error"
                    ).inc()
                    self._metrics.http_request_duration_seconds.observe(elapsed)
                except Exception:
                    pass
                logger.warning(
                    "Transient network error fetching %s (attempt %d/%d): %s",
                    url,
                    attempt,
                    max_attempts,
                    exc,
                )
                if attempt == max_attempts:
                    logger.exception(
                        "Failed to fetch URL %s after %d attempts: %s",
                        url,
                        max_attempts,
                        exc,
                    )
                    # Return empty dict to let callers handle retrying
                    # at a higher level without raising an exception.
                    return {}
                # Exponential backoff before next attempt
                await asyncio.sleep(backoff_base * (2 ** (attempt - 1)))
                continue
            except Exception as exc:
                elapsed = time.monotonic() - t0
                try:
                    self._metrics.http_requests_total.labels(
                        method="GET", status="error"
                    ).inc()
                    self._metrics.http_request_duration_seconds.observe(elapsed)
                except Exception:
                    pass
                logger.exception("Failed to fetch URL %s: %s", url, exc)
                return {}

    @staticmethod
    def _partition_logs(logs: List[str]) -> List[str]:
        """Partition the log list for the current worker instance.

        When CT_WORKER_INDEX and CT_WORKER_COUNT are both set explicitly,
        those values are used directly.  Otherwise the index is derived
        automatically by resolving the shared service DNS name (default
        ``collector``) and finding this container's position among the
        sorted set of peer IPs.
        """
        widx_env = os.getenv("CT_WORKER_INDEX")
        wcount_env = os.getenv("CT_WORKER_COUNT")

        if widx_env is not None and wcount_env is not None:
            wcount = int(wcount_env)
            widx = int(widx_env)
        else:
            widx, wcount = CTLogPoller._auto_discover_index()

        if wcount > 1:
            filtered = [l for i, l in enumerate(logs) if (i % wcount) == widx]
            logger.info(
                "Worker %s/%s assigned %d logs (of %d)",
                widx,
                wcount,
                len(filtered),
                len(logs),
            )
            return filtered

        return logs

    @staticmethod
    def _auto_discover_index():
        """Derive worker index and count from DNS peer resolution.

        Resolves the shared service name (e.g. ``collector`` in Docker
        Compose) to obtain every replica IP, sorts them, and returns
        this container's position in that sorted list.
        """
        import socket as _socket

        service_name = os.getenv("CT_SERVICE_NAME", "collector")
        port = int(os.getenv("CT_PROMETHEUS_PORT", str(PROMETHEUS_PORT)))

        # Resolve own IP(s)
        my_hostname = _socket.gethostname()
        try:
            my_addrs = {
                addr[4][0]
                for addr in _socket.getaddrinfo(my_hostname, None)
            }
        except _socket.gaierror:
            my_addrs = set()

        # Resolve all peer IPs via the shared service DNS name
        try:
            peer_addrs = _socket.getaddrinfo(
                service_name, port, proto=_socket.IPPROTO_TCP,
            )
            all_ips = sorted({addr[4][0] for addr in peer_addrs})
        except _socket.gaierror:
            logger.warning(
                "DNS lookup for '%s' failed; running as sole worker",
                service_name,
            )
            return 0, 1

        wcount = len(all_ips)
        if wcount == 0:
            return 0, 1

        # Find our position in the sorted IP list
        for idx, ip in enumerate(all_ips):
            if ip in my_addrs:
                logger.info(
                    "Auto-discovered index %d/%d (IP %s in service '%s')",
                    idx, wcount, ip, service_name,
                )
                return idx, wcount

        # Fallback: hash hostname to pick a deterministic position
        widx = hash(my_hostname) % wcount
        logger.warning(
            "Could not match own IP in '%s' peers; hash-based index %d/%d",
            service_name, widx, wcount,
        )
        return widx, wcount
