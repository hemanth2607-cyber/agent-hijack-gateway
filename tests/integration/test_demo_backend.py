import json
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import ApprovalModel, Base, get_db
from app.main import app
from app.security.auth import create_api_key
from app.security.audit_chain import append_audit_entry, verify_audit_chain


@pytest_asyncio.fixture
async def demo_test_db():
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        yield session

    await test_engine.dispose()


@pytest_asyncio.fixture
async def demo_client(demo_test_db: AsyncSession):
    async def override_get_db():
        yield demo_test_db

    app.dependency_overrides[get_db] = override_get_db

    # Seed client key
    judge_key, _ = await create_api_key(demo_test_db, name="Judge Client", role="client")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.judge_key = judge_key
        ac.db = demo_test_db
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_public_audit_verify_endpoint(demo_client: AsyncClient):
    # Append a valid audit entry to the test db
    await append_audit_entry(
        db=demo_client.db,
        request_id="req_test_audit_1",
        agent_id="default_agent",
        action_type="chat_request",
        verdict="ALLOW",
        risk_score=0.0,
        reason_codes=["BENIGN_PROMPT"],
        details={"model": "mock"},
    )

    resp = await demo_client.get("/v1/public/audit/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["total_records"] == 1
    assert "head_hash" in data


@pytest.mark.asyncio
async def test_demo_reset_and_rate_limit(demo_client: AsyncClient):
    # First reset should succeed
    resp1 = await demo_client.post("/v1/demo/reset")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["status"] == "ok"
    assert data1["audit_chain_intact"] is True

    # Rapid second reset should be rate-limited (429)
    resp2 = await demo_client.post("/v1/demo/reset")
    assert resp2.status_code == 429
    assert "rate limit exceeded" in resp2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_demo_approvals_flow(demo_client: AsyncClient):
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    # Seed a demo approval
    approval = ApprovalModel(
        id="demo_test_apprv_001",
        request_id="req_test_demo",
        agent_id="default_agent",
        tool_name="send_email",
        args_redacted_json=json.dumps({"to": "partner@external.com"}),
        args_hash="hash_dummy",
        reason="Requires signoff",
        risk_score=75.0,
        taint_sources_json="[]",
        status="PENDING",
        created_at=now,
        expires_at=now + datetime.timedelta(minutes=30),
    )
    demo_client.db.add(approval)
    await demo_client.db.commit()

    # List demo approvals using judge client key
    list_resp = await demo_client.get(
        "/v1/demo/approvals",
        headers={"X-API-Key": demo_client.judge_key},
    )
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(it["id"] == "demo_test_apprv_001" for it in items)

    # Approve using demo approval endpoint
    apprv_resp = await demo_client.post(
        "/v1/demo/approvals/demo_test_apprv_001/approve",
        headers={"X-API-Key": demo_client.judge_key},
    )
    assert apprv_resp.status_code == 200
    apprv_data = apprv_resp.json()
    assert apprv_data["status"] == "APPROVED"
    assert apprv_data["capability_token"] is not None


@pytest.mark.asyncio
async def test_demo_approvals_reject_non_demo_agent(demo_client: AsyncClient):
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    # Seed an approval for a non-demo agent
    approval = ApprovalModel(
        id="non_demo_apprv_999",
        request_id="req_test_non_demo",
        agent_id="sensitive_enterprise_agent",
        tool_name="transfer_funds",
        args_redacted_json=json.dumps({"amount": 50000}),
        args_hash="hash_enterprise",
        reason="Exceeds limit",
        risk_score=90.0,
        taint_sources_json="[]",
        status="PENDING",
        created_at=now,
        expires_at=now + datetime.timedelta(minutes=30),
    )
    demo_client.db.add(approval)
    await demo_client.db.commit()

    # Attempting to approve via demo endpoint must be rejected with 403 Forbidden
    resp = await demo_client.post(
        "/v1/demo/approvals/non_demo_apprv_999/approve",
        headers={"X-API-Key": demo_client.judge_key},
    )
    assert resp.status_code == 403
    assert "designated demo agents" in resp.json()["detail"]
