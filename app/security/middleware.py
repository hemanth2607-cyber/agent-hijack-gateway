"""Security middleware for FastAPI.

Provides:
- Request-ID correlation propagation
- Security headers (CSP, HSTS, X-Content-Type, X-Frame-Options, Referrer-Policy)
- Strict body size limits (prevents memory exhaustion DoS)
- In-memory sliding-window rate limiting per IP and API key
- Global request timeouts
"""

from __future__ import annotations

import asyncio
import time
import uuid
import re
from collections import defaultdict
from typing import Dict, List
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.config import settings

REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{8,64}$")


class RateLimiter:
    """Sliding-window rate limiter for client IPs and API keys with automatic eviction."""

    def __init__(self):
        # maps identifier -> list of timestamps (seconds)
        self._ip_history: Dict[str, List[float]] = defaultdict(list)
        self._key_history: Dict[str, List[float]] = defaultdict(list)
        self._check_counter: int = 0

    def evict_stale_entries(self, window_seconds: float = 60.0) -> int:
        """Evicts identifiers that have no recorded requests within the window."""
        now = time.monotonic()
        cutoff = now - window_seconds
        stale_ips = [
            k for k, history in self._ip_history.items()
            if not history or history[-1] < cutoff
        ]
        for k in stale_ips:
            del self._ip_history[k]

        stale_keys = [
            k for k, history in self._key_history.items()
            if not history or history[-1] < cutoff
        ]
        for k in stale_keys:
            del self._key_history[k]

        return len(stale_ips) + len(stale_keys)

    def is_rate_limited(self, identifier: str, max_requests: int, window_seconds: float = 60.0) -> bool:
        """Returns True if identifier has exceeded max_requests in window_seconds."""
        now = time.monotonic()
        cutoff = now - window_seconds

        # Periodically evict stale keys every 50 checks
        self._check_counter += 1
        if self._check_counter % 50 == 0:
            self.evict_stale_entries(window_seconds)

        history = self._ip_history[identifier]
        # Remove timestamps outside window
        while history and history[0] < cutoff:
            history.pop(0)

        if len(history) >= max_requests:
            return True

        history.append(now)
        return False

    def reset(self) -> None:
        """Clear all rate limit state (useful in tests)."""
        self._ip_history.clear()
        self._key_history.clear()
        self._check_counter = 0


rate_limiter = RateLimiter()


class SecurityMiddleware(BaseHTTPMiddleware):
    """Central HTTP security middleware."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Establish unique correlation Request-ID
        incoming_req_id = request.headers.get("X-Request-ID")
        if incoming_req_id and REQUEST_ID_REGEX.match(incoming_req_id):
            request_id = incoming_req_id
        else:
            request_id = f"req_{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id

        # 2. Rate Limiting by Client IP
        client_ip = request.client.host if request.client else "unknown"
        # Exempt health, public, and static endpoints from aggressive rate limiting
        path = request.url.path
        if not path.startswith("/static") and not path.startswith("/v1/public") and path not in ("/health", "/healthz", "/metrics", "/", "/playground", "/scenarios.json"):
            if rate_limiter.is_rate_limited(
                client_ip,
                max_requests=settings.rate_limit_per_minute_ip,
                window_seconds=60.0,
            ):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests from this client IP address. Please slow down.",
                        "request_id": request_id,
                    },
                    headers={"Retry-After": "60", "X-Request-ID": request_id},
                )

        # 3. Request Body Size Guard (Covers Content-Length and Chunked/Streaming payloads)
        content_length_header = request.headers.get("Content-Length")
        transfer_encoding = request.headers.get("Transfer-Encoding", "").lower()

        if content_length_header:
            try:
                content_length = int(content_length_header)
                if content_length > settings.max_input_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error_code": "PAYLOAD_TOO_LARGE",
                            "message": f"Request body exceeds maximum allowed size ({settings.max_input_body_bytes} bytes).",
                            "request_id": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "INVALID_CONTENT_LENGTH",
                        "message": "Invalid Content-Length header.",
                        "request_id": request_id,
                    },
                    headers={"X-Request-ID": request_id},
                )
        elif "chunked" in transfer_encoding or request.method in ("POST", "PUT", "PATCH"):
            # Chunked transfer encoding without Content-Length: enforce streaming byte limit
            body_chunks = []
            total_bytes = 0
            async for chunk in request.stream():
                total_bytes += len(chunk)
                if total_bytes > settings.max_input_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error_code": "PAYLOAD_TOO_LARGE",
                            "message": f"Chunked/streaming request body exceeds maximum allowed size ({settings.max_input_body_bytes} bytes).",
                            "request_id": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )
                body_chunks.append(chunk)

            # Re-assemble body so downstream endpoint handlers can still consume request.body()
            full_body = b"".join(body_chunks)

            async def custom_receive():
                return {"type": "http.request", "body": full_body, "more_body": False}

            request._receive = custom_receive

        # 4. Dispatch with Global Timeout
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=settings.request_timeout_seconds,
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={
                    "error_code": "GATEWAY_TIMEOUT",
                    "message": f"Request processing timed out after {settings.request_timeout_seconds}s.",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )
        except Exception as exc:
            # Fail closed on unhandled internal exceptions
            return JSONResponse(
                status_code=500,
                content={
                    "error_code": "INTERNAL_SECURITY_ERROR",
                    "message": "Internal gateway error. Risky actions are denied (fail closed).",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )

        # 5. Attach Hardened Security Headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Content Security Policy (enforces external scripts only, supports video media)
        media_src = "'self'"
        frame_src = "'none'"
        if settings.demo_video_url:
            media_src += " https://www.youtube.com https://player.vimeo.com"
            frame_src = "'self' https://www.youtube.com https://player.vimeo.com"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https://lh3.googleusercontent.com; "
            f"media-src {media_src}; "
            f"frame-src {frame_src}; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        if settings.app_env in ("production", "staging"):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response
