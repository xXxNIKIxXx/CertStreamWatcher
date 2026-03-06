"""Lightweight WebSocket server used to broadcast parsed certificate events.

The `WebSocketServer` is intentionally minimal: it tracks connected
clients and provides a `broadcast` helper which records simple metrics
about broadcasts. Connection lifecycle is handled by `websockets` and
clients are removed from the internal set when disconnected.
"""

from __future__ import annotations

import json
import time
from typing import Set

import websockets

from .config import get_logger, WEBSOCKET_PORT
from .metrics import MetricsManager

logger = get_logger("CTStreamService.WebSocket")


class WebSocketServer:
    """Manages WebSocket client connections and message broadcasting."""

    def __init__(self, metrics: MetricsManager) -> None:
        self._clients: Set = set()
        self._metrics = metrics

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def start(self, host: str = "0.0.0.0", port: int = WEBSOCKET_PORT):
        """Start the WebSocket server and return the server object."""
        server = await websockets.serve(self._handler, host, port)
        logger.info("WebSocket server running on ws://%s:%s", host, port)
        return server

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to all connected clients."""
        if not self._clients:
            return

        self._metrics.ws_broadcasts_total.inc()
        t0 = time.monotonic()

        logger.debug("Broadcasting message to %d clients", len(self._clients))
        dead: set = set()

        for ws in self._clients:
            try:
                await ws.send(json.dumps(message))
            except Exception as exc:
                logger.exception("Failed to send message to client: %s", exc)
                self._metrics.ws_broadcast_errors_total.inc()
                dead.add(ws)

        for ws in dead:
            self._clients.discard(ws)

        self._metrics.ws_broadcast_duration_seconds.observe(
            time.monotonic() - t0
        )
        self._update_gauge()

    async def broadcast_batch(self, messages: list[dict]) -> None:
        """Send multiple messages to all connected clients in sequence.

        This method mirrors the Redis publisher's `publish_batch` and is
        used by the poller to push batches of parsed certificates. It
        sends each message individually to every connected client.
        """
        if not self._clients or not messages:
            return

        if self._metrics:
            self._metrics.ws_broadcasts_total.inc(len(messages))
        t0 = time.monotonic()

        dead: set = set()
        for ws in list(self._clients):
            try:
                for msg in messages:
                    await ws.send(json.dumps(msg))
            except Exception as exc:
                logger.exception("Failed to send batch to client: %s", exc)
                if self._metrics:
                    self._metrics.ws_broadcast_errors_total.inc()
                dead.add(ws)

        for ws in dead:
            self._clients.discard(ws)

        if self._metrics:
            self._metrics.ws_broadcast_duration_seconds.observe(time.monotonic() - t0)
        self._update_gauge()

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    async def _handler(self, websocket) -> None:
        """Handle an individual WebSocket connection lifecycle."""
        self._clients.add(websocket)
        self._update_gauge()
        try:
            await websocket.wait_closed()
        finally:
            self._clients.discard(websocket)
            self._update_gauge()

    def _update_gauge(self) -> None:
        try:
            self._metrics.active_clients.set(len(self._clients))
        except Exception:
            pass
