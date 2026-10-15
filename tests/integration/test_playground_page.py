import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_playground_route_serves_html():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/playground")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Tether Playground" in resp.text
        assert "SIMULATION MODE ACTIVE" in resp.text
        assert "playground.js" in resp.text
        assert "playground.css" in resp.text


@pytest.mark.asyncio
async def test_playground_static_assets_exist():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        js_resp = await client.get("/static/playground.js")
        assert js_resp.status_code == 200
        assert "use strict" in js_resp.text

        css_resp = await client.get("/static/playground.css")
        assert css_resp.status_code == 200
        assert "--bg-canvas" in css_resp.text
