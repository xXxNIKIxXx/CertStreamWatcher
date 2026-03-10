"""Async Redis publisher for broadcasting parsed certificates.

Set ``CT_REDIS_DISABLE=1`` to skip Redis entirely (useful when only the
built-in WebSocket stream is needed).  When Redis or its driver is
unavailable the publisher becomes a no-op and metrics reflect that.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .config import get_logger, REDIS_URL, REDIS_DISABLED

logger = get_logger("CTStreamService.Redis")

try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None


class RedisPublisher:
    """Publishes certificate events to a Redis Pub/Sub channel."""

    CHANNEL = "ct:certs"

    def __init__(self, metrics=None) -> None:
        self._conn: Optional[object] = None
        self._metrics = metrics

    @property
    def available(self) -> bool:
        return self._conn is not None

    async def init(self) -> None:
        """Connect to Redis (no-op when disabled or unavailable)."""
        if REDIS_DISABLED:
            logger.info("Redis publish disabled (CT_REDIS_DISABLE=1)")
            self._set_available(0)
            return

        if redis_from_url is None:
            logger.warning("redis.asyncio not installed; Redis publish disabled")
            self._set_available(0)
            return

        if not REDIS_URL:
            logger.info("CT_REDIS_URL not set; Redis publish disabled")
            self._set_available(0)
            return

        try:
            self._conn = redis_from_url(REDIS_URL)
            await self._conn.ping()
            logger.info("Connected to Redis at %s", REDIS_URL)
            self._set_available(1)
        except Exception:
            logger.exception("Failed to connect to Redis")
            self._conn = None
            self._set_available(0)

    async def publish(self, message: dict) -> None:
        """Publish a single JSON message to the certificates channel."""
        if not self._conn:
            return

        t0 = time.monotonic()
        try:
            await self._conn.publish(self.CHANNEL, json.dumps(message))
            self._observe_publish(t0, success=True)
        except Exception:
            logger.exception("Failed to publish message to Redis")
            self._observe_publish(t0, success=False)

    async def publish_batch(self, messages: list[dict]) -> None:
        """Publish multiple messages via a Redis pipeline."""
        if not self._conn or not messages:
            return

        t0 = time.monotonic()
        try:
            async with self._conn.pipeline(transaction=False) as pipe:
                for msg in messages:
                    pipe.publish(self.CHANNEL, json.dumps(msg))
                await pipe.execute()
            self._observe_publish(t0, success=True, count=len(messages))
        except Exception:
            logger.exception("Failed to publish batch to Redis")
            self._observe_publish(t0, success=False)

    async def close(self) -> None:
        if self._conn:
            try:
                await self._conn.close()
            except Exception:
                logger.exception("Error closing Redis connection")
            self._conn = None
            self._set_available(0)

    # ------------------------------------------------------------------
    # Metrics helpers
    # ------------------------------------------------------------------

    def _set_available(self, value: int) -> None:
        if self._metrics:
            self._metrics.redis_available.set(value)

    def _observe_publish(self, t0: float, *, success: bool, count: int = 1) -> None:
        if not self._metrics:
            return
        elapsed = time.monotonic() - t0
        if success:
            self._metrics.redis_publishes_total.inc(count)
        else:
            self._metrics.redis_publish_errors_total.inc()
        self._metrics.redis_publish_duration_seconds.observe(elapsed)
