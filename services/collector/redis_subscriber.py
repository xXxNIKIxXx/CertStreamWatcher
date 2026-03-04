"""Async Redis subscriber for listening to settings updates (ct:settings).

Listens for JSON messages and invokes a callback with the parsed payload.
"""
from __future__ import annotations

import asyncio
import json
from typing import Callable

from .config import get_logger, REDIS_URL

logger = get_logger("CTStreamService.RedisSubscriber")

try:
    from redis.asyncio import from_url as redis_from_url
except Exception:
    redis_from_url = None


class RedisSubscriber:
    CHANNEL = "ct:settings"

    def __init__(self, on_message: Callable[[dict], None]):
        self._conn = None
        self._task = None
        self._on_message = on_message

    async def init(self) -> None:
        if redis_from_url is None or not REDIS_URL:
            logger.info("Redis subscriber disabled (redis not available or CT_REDIS_URL unset)")
            return
        try:
            self._conn = redis_from_url(REDIS_URL)
            await self._conn.ping()
            logger.info("Redis subscriber connected to %s", REDIS_URL)
            # start listening task
            self._task = asyncio.create_task(self._run())
        except Exception:
            logger.exception("Failed to start Redis subscriber")
            self._conn = None

    async def _run(self) -> None:
        try:
            pubsub = self._conn.pubsub()
            await pubsub.subscribe(self.CHANNEL)
            logger.info("Subscribed to Redis channel %s", self.CHANNEL)
            async for msg in pubsub.listen():
                if msg is None:
                    continue
                # message types: subscribe, message
                if msg.get("type") != "message":
                    continue
                data = msg.get("data")
                try:
                    if isinstance(data, (bytes, bytearray)):
                        payload = json.loads(data.decode("utf-8"))
                    elif isinstance(data, str):
                        payload = json.loads(data)
                    else:
                        continue
                    # invoke callback
                    try:
                        self._on_message(payload)
                    except Exception:
                        logger.exception("Error in on_message callback")
                except Exception:
                    logger.exception("Failed to parse Redis message")
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Redis subscriber crashed")

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._conn:
            try:
                await self._conn.close()
            except Exception:
                logger.exception("Error closing Redis subscriber connection")
