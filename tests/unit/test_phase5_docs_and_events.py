"""Tests for Phase 5 OpenAPI /docs, /redoc, /openapi.json, and SSE /events streaming."""

import json
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.events import event_broadcaster


def test_openapi_docs_endpoints():
    """Verifies that OpenAPI documentation endpoints are operational."""
    client = TestClient(app)

    # 1. Swagger UI /docs
    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200
    assert "swagger-ui" in docs_resp.text.lower() or "html" in docs_resp.text.lower()

    # 2. ReDoc UI /redoc
    redoc_resp = client.get("/redoc")
    assert redoc_resp.status_code == 200
    assert "redoc" in redoc_resp.text.lower() or "html" in redoc_resp.text.lower()

    # 3. OpenAPI Schema /openapi.json
    schema_resp = client.get("/openapi.json")
    assert schema_resp.status_code == 200
    schema_data = schema_resp.json()
    assert "openapi" in schema_data
    assert "paths" in schema_data
    # Core endpoints documented
    assert "/v1/chat" in schema_data["paths"]
    assert "/v1/scan" in schema_data["paths"]
    assert "/v1/approvals" in schema_data["paths"]
    assert "/events" in schema_data["paths"]
    assert "/healthz" in schema_data["paths"]


@pytest.mark.asyncio
async def test_sse_events_subscription_and_broadcast():
    """Verifies that SSE EventBroadcaster handles subscriber lifecycle and broadcasts events."""
    q = event_broadcaster.subscribe()
    event_broadcaster.broadcast("test_security_event", {"verdict": "BLOCK", "risk": 95.0})

    gen = event_broadcaster.event_generator(q)

    # Frame 1: Initial connection acknowledgment
    frame1 = await anext(gen)
    assert "connected" in frame1

    # Frame 2: Broadcasted security event
    frame2 = await anext(gen)
    assert "test_security_event" in frame2
    assert "BLOCK" in frame2

    event_broadcaster.unsubscribe(q)
