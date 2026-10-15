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
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, AsyncGenerator, Dict, Optional, Set

from app.config import settings

logger = logging.getLogger("agent_shield.events")


def _get_sse_signing_key() -> bytes:
    """Derives a dedicated cryptographic subkey for SSE tokens to ensure domain separation."""
    master = getattr(settings.secret_key, "get_secret_value", lambda: settings.secret_key)()
    if not isinstance(master, bytes):
        master = str(master).encode("utf-8")
    return hmac.new(master, b"AgentShield:DomainSeparation:SSE-Token:v1", hashlib.sha256).digest()


def issue_sse_token(user_name: str, role: str, ttl_seconds: float = 60.0) -> str:
    """Issues a short-lived signed HMAC token for browser EventSource connections with domain separation."""
    now = time.time()
    payload = {
        "sub": user_name,
        "role": role,
        "exp": now + ttl_seconds,
        "type": "sse",
        "domain": "agent_shield_sse_stream",
        "nonce": secrets.token_hex(16),
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signing_key = _get_sse_signing_key()
    message_to_sign = b"ahs_sse_v1:" + payload_b64.encode("utf-8")
    sig = hmac.new(signing_key, message_to_sign, hashlib.sha256).hexdigest()
    return f"sse_tok_{payload_b64}.{sig}"


def verify_sse_token(token: str) -> Optional[Dict[str, Any]]:
    """Validates HMAC signature and expiry of a domain-separated SSE ticket token."""
    if not token.startswith("sse_tok_"):
        return None
    token_body = token[len("sse_tok_"):].strip()
    parts = token_body.split(".")
    if len(parts) != 2:
        return None
    payload_b64, sig = parts
    signing_key = _get_sse_signing_key()
    message_to_sign = b"ahs_sse_v1:" + payload_b64.encode("utf-8")
    expected_sig = hmac.new(signing_key, message_to_sign, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if payload.get("type") != "sse" or payload.get("domain") != "agent_shield_sse_stream":
            return None
        if time.time() > payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None


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
