"""Async Redis publisher for broadcasting parsed certificates.

Provides `RedisPublisher` which wraps `redis.asyncio` and exposes
`publish`/`publish_batch` helpers. When Redis or the library is not
available the publisher is a no-op and metrics reflect availability.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from .config import get_logger, REDIS_URL

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
        """Connect to Redis."""
        if redis_from_url is None:
            logger.warning("redis.asyncio not available; Redis publish disabled")
            if self._metrics:
                self._metrics.redis_available.set(0)
            return

        if not REDIS_URL:
            logger.info("CT_REDIS_URL not set; Redis publish disabled")
            if self._metrics:
                self._metrics.redis_available.set(0)
            return

        try:
            self._conn = redis_from_url(REDIS_URL)
            # Verify the connection works
            await self._conn.ping()
            logger.info("Connected to Redis at %s", REDIS_URL)
            if self._metrics:
                self._metrics.redis_available.set(1)
        except Exception:
            logger.exception("Failed to connect to Redis")
            self._conn = None
            if self._metrics:
                self._metrics.redis_available.set(0)

    async def publish(self, message: dict) -> None:
        """Publish a JSON-encoded message to the certificates channel."""
        if not self._conn:
            return

        if self._metrics:
            self._metrics.redis_publishes_total.inc()

        t0 = time.monotonic()
        try:
            await self._conn.publish(self.CHANNEL, json.dumps(message))
            if self._metrics:
                self._metrics.redis_publish_duration_seconds.observe(
                    time.monotonic() - t0
                )
        except Exception:
            logger.exception("Failed to publish message to Redis")
            if self._metrics:
                self._metrics.redis_publish_errors_total.inc()
                self._metrics.redis_publish_duration_seconds.observe(
                    time.monotonic() - t0
                )

    async def publish_batch(self, messages: list[dict]) -> None:
        """Publish multiple JSON-encoded messages using a Redis pipeline."""
        if not self._conn or not messages:
            return

        if self._metrics:
            self._metrics.redis_publishes_total.inc(len(messages))

        t0 = time.monotonic()
        try:
            async with self._conn.pipeline(transaction=False) as pipe:
                for msg in messages:
                    pipe.publish(self.CHANNEL, json.dumps(msg))
                await pipe.execute()
            if self._metrics:
                self._metrics.redis_publish_duration_seconds.observe(
                    time.monotonic() - t0
                )
        except Exception:
            logger.exception("Failed to publish batch to Redis")
            if self._metrics:
                self._metrics.redis_publish_errors_total.inc()
                self._metrics.redis_publish_duration_seconds.observe(
                    time.monotonic() - t0
                )

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._conn:
            try:
                await self._conn.close()
            except Exception:
                logger.exception("Error closing Redis connection")
            if self._metrics:
                self._metrics.redis_available.set(0)
