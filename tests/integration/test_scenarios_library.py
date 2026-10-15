import json
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

SCENARIOS_PATH = Path("frontend/scenarios.json")

def test_scenarios_json_exists_and_valid():
    assert SCENARIOS_PATH.exists(), "frontend/scenarios.json must exist"
    with open(SCENARIOS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 16, f"Expected 16 scenarios, got {len(data)}"
    
    required_keys = {
        "id", "title", "category", "target_agent", "user_prompt",
        "untrusted_context", "expected_verdict", "expected_layer",
        "why", "shield_off_outcome", "shield_on_outcome"
    }
    categories = set()
    for item in data:
        missing = required_keys - set(item.keys())
        assert not missing, f"Scenario {item.get('id')} missing keys: {missing}"
        assert item["category"] in {"safe", "detector", "permission_layer", "known_limitations"}
        assert item["expected_verdict"] in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}
        categories.add(item["category"])

    assert "safe" in categories
    assert "detector" in categories
    assert "permission_layer" in categories
    assert "known_limitations" in categories


@pytest.mark.asyncio
async def test_scenarios_served_statically():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/static/scenarios.json")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 16
