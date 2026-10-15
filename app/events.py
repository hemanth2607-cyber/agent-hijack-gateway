"""Real-time Server-Sent Events (SSE) broadcaster for Operator Console.

Provides live streaming of gateway telemetry:
- Inbound scans, detected threats, risk scores
- Tool permission decisions (ALLOW, DENY, REQUIRE_APPROVAL)
- Human-in-the-loop approval lifecycle events
- Circuit breaker trips and quarantine status changes
- Outbound filter leaks and redaction actions
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, Set

logger = logging.getLogger("agent_shield.events")


class EventBroadcaster:
    """Thread-safe and async-safe pub/sub event broadcaster for SSE."""

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        """Registers a new listener queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        logger.debug("New SSE client subscribed. Total listeners: %d", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Removes a listener queue upon client disconnect."""
        self._subscribers.discard(q)
        logger.debug("SSE client unsubscribed. Remaining listeners: %d", len(self._subscribers))

    def broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Pushes an event payload to all active listener queues."""
        if not self._subscribers:
            return
        payload = {
            "event": event_type,
            "timestamp": time.time(),
            "data": data,
        }
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Subscriber queue full; drop oldest to prevent memory accumulation
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass

    async def event_generator(self, queue: asyncio.Queue) -> AsyncGenerator[str, None]:
        """Async generator yielding standard SSE formatted event frames."""
        try:
            # Send initial connection acknowledgment
            init_msg = json.dumps({"status": "connected", "time": time.time()})
            yield f"event: connected\ndata: {init_msg}\n\n"

            while True:
                try:
                    # Await next event or heartbeat timeout (15s)
                    item = await asyncio.wait_for(queue.get(), timeout=15.0)
                    evt_type = item.get("event", "message")
                    data_json = json.dumps(item.get("data", {}))
                    yield f"event: {evt_type}\ndata: {data_json}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe(queue)


event_broadcaster = EventBroadcaster()
