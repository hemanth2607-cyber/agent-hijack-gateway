"""Tests for SecurityMiddleware and rate limiting."""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.security.middleware import SecurityMiddleware, rate_limiter
from app.config import settings


async def dummy_endpoint(request):
    return JSONResponse({"status": "ok", "request_id": getattr(request.state, "request_id", None)})


app = Starlette(
    routes=[
        Route("/test", dummy_endpoint, methods=["GET", "POST"]),
        Route("/health", dummy_endpoint, methods=["GET"]),
    ]
)
app.add_middleware(SecurityMiddleware)


def test_security_headers_and_request_id():
    client = TestClient(app)
    response = client.get("/test")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_custom_request_id_propagation():
    client = TestClient(app)
    custom_id = "req_custom_trace_12345"
    response = client.get("/test", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == custom_id


def test_body_size_limit():
    client = TestClient(app)
    # Payload exceeding default size threshold (e.g. mock header)
    headers = {"Content-Length": str(settings.max_input_body_bytes + 100)}
    response = client.post("/test", headers=headers, content=b"a")
    assert response.status_code == 413
    assert response.json()["error_code"] == "PAYLOAD_TOO_LARGE"


def test_rate_limiter_throttling():
    rate_limiter.reset()
    client = TestClient(app)

    # Exhaust rate limit
    for _ in range(settings.rate_limit_per_minute_ip):
        res = client.get("/test")
        assert res.status_code == 200

    # Next request must be 429
    res = client.get("/test")
    assert res.status_code == 429
    assert res.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in res.headers

    # Health endpoint exempt
    health_res = client.get("/health")
    assert health_res.status_code == 200
    rate_limiter.reset()


def test_rate_limiter_eviction():
    rate_limiter.reset()
    # Add dummy entries with timestamps in the distant past
    rate_limiter._ip_history["198.51.100.1"] = [1.0, 2.0]
    rate_limiter._ip_history["198.51.100.2"] = [1.0]
    assert len(rate_limiter._ip_history) == 2

    # Evict entries older than window
    evicted_count = rate_limiter.evict_stale_entries(window_seconds=10.0)
    assert evicted_count == 2
    assert len(rate_limiter._ip_history) == 0
    rate_limiter.reset()


def test_chunked_streaming_body_size_limit():
    client = TestClient(app)

    # Generator simulating a chunked body without Content-Length
    def chunk_generator():
        # Yield chunks that sum to greater than max_input_body_bytes
        chunk_size = 256 * 1024
        for _ in range(5):  # 5 * 256KB = 1.25MB > 1MB limit
            yield b"X" * chunk_size

    response = client.post(
        "/test",
        headers={"Transfer-Encoding": "chunked"},
        content=chunk_generator(),
    )
    assert response.status_code == 413
    assert response.json()["error_code"] == "PAYLOAD_TOO_LARGE"
    assert "Chunked/streaming" in response.json()["message"]
