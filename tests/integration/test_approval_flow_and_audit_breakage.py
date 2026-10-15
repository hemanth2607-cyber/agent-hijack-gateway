"""Integration tests for approval lifecycle, argument tampering rejection,
audit chain tampering detection, and extended Phase 5 endpoints.
"""

import json
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.db import AuditLogModel, Base, get_db
from app.main import app
from app.security.audit_chain import append_audit_entry
from app.security.auth import create_api_key
from app.shield.approvals import create_approval_request
from app.shield.capabilities import compute_args_hash
from app.shield.permissions import policy_registry
from app.shield.tools import execute_tool


@pytest_asyncio.fixture
async def flow_test_db():
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        yield session

    await test_engine.dispose()


@pytest_asyncio.fixture
async def flow_client(flow_test_db: AsyncSession):
    async def override_get_db():
        yield flow_test_db

    app.dependency_overrides[get_db] = override_get_db

    admin_key, _ = await create_api_key(flow_test_db, name="Admin Key", role="admin")
    analyst_key, _ = await create_api_key(flow_test_db, name="Analyst Key", role="analyst")
    approver_key, _ = await create_api_key(flow_test_db, name="Approver Key", role="approver")
    client_key, _ = await create_api_key(flow_test_db, name="Client Key", role="client")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.admin_key = admin_key
        ac.analyst_key = analyst_key
        ac.approver_key = approver_key
        ac.client_key = client_key
        ac.db = flow_test_db
        yield ac

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_end_to_end_send_email_approval_flow_and_execution(flow_client: AsyncClient):
    """Verifies: send_email -> pending approval -> approve -> token issued -> tool executes."""
    agent_id = "default_agent"
    request_id = "req_email_appr_01"
    email_args = {
        "to": "director@company.com",
        "subject": "Q4 Performance",
        "body": "Here is the summary.",
    }

    # 1. Simulate policy gate escalating send_email to pending approval due to tainted session
    approval = await create_approval_request(
        db=flow_client.db,
        agent_id=agent_id,
        session_id="sess_tainted_01",
        request_id=request_id,
        tool_name="send_email",
        args=email_args,
        reason="Session tainted by untrusted document input; side-effects require human approval",
        risk_score=50.0,
        taint_sources=["untrusted_contract.pdf"],
    )
    assert approval.status == "PENDING"
    approval_id = approval.id

    # 2. List pending approvals as approver
    res_list = await flow_client.get(
        "/v1/approvals",
        headers={"X-API-Key": flow_client.approver_key},
    )
    assert res_list.status_code == 200
    pending_items = res_list.json()
    assert any(item["id"] == approval_id for item in pending_items)

    # 3. Approve the request via API
    res_approve = await flow_client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers={"X-API-Key": flow_client.approver_key},
    )
    assert res_approve.status_code == 200
    approval_data = res_approve.json()
    assert approval_data["status"] == "APPROVED"
    capability_token = approval_data["capability_token"]
    assert capability_token is not None
    assert len(capability_token) > 20
    assert "." in capability_token

    # 4. Tool executes successfully using the capability token
    result = execute_tool(
        tool_name="send_email",
        args=email_args,
        capability_token=capability_token,
        agent_id=agent_id,
        request_id=request_id,
    )
    assert result["status"] == "simulated_sent"
    assert result["to"] == "director@company.com"


@pytest.mark.asyncio
async def test_end_to_end_approval_arg_tampering_rejected(flow_client: AsyncClient):
    """Verifies: approved token used with tampered arguments is strictly rejected."""
    agent_id = "default_agent"
    request_id = "req_email_tamper_02"
    approved_args = {
        "to": "finance@company.com",
        "subject": "Internal Invoice",
        "body": "Approved invoice copy.",
    }

    # 1. Create and approve the request
    approval = await create_approval_request(
        db=flow_client.db,
        agent_id=agent_id,
        session_id="sess_tainted_02",
        request_id=request_id,
        tool_name="send_email",
        args=approved_args,
        reason="Side-effect tool approval",
        risk_score=55.0,
        taint_sources=[],
    )
    res_approve = await flow_client.post(
        f"/v1/approvals/{approval.id}/approve",
        headers={"X-API-Key": flow_client.approver_key},
    )
    assert res_approve.status_code == 200
    capability_token = res_approve.json()["capability_token"]

    # 2. Adversary tampers with the recipient argument
    tampered_args = {
        "to": "attacker@evil.com",  # Tampered recipient!
        "subject": "Internal Invoice",
        "body": "Approved invoice copy.",
    }

    # 3. Execution strictly fails with PermissionError
    with pytest.raises(PermissionError) as exc_info:
        execute_tool(
            tool_name="send_email",
            args=tampered_args,
            capability_token=capability_token,
            agent_id=agent_id,
            request_id=request_id,
        )
    assert "CAPABILITY_ARGS_HASH_MISMATCH" in str(exc_info.value)


@pytest.mark.asyncio
async def test_audit_verify_detects_first_broken_link_after_direct_db_edit(flow_client: AsyncClient):
    """Directly edits an audit row in the database and proves /audit/verify reports the first broken link."""
    db = flow_client.db

    # 1. Create a chain of 4 valid audit entries
    for i in range(1, 5):
        await append_audit_entry(
            db=db,
            request_id=f"req_chain_{i:03d}",
            agent_id="default_agent",
            action_type="chat_interaction",
            verdict="ALLOW",
            risk_score=0.0,
            reason_codes=["CLEAN"],
            details={"step": i},
        )

    # 2. Verify clean chain initially
    res_initial = await flow_client.get(
        "/v1/audit/verify",
        headers={"X-API-Key": flow_client.analyst_key},
    )
    assert res_initial.status_code == 200
    assert res_initial.json()["is_valid"] is True
    assert res_initial.json()["first_broken_link_id"] is None

    # 3. Tamper directly with row 2 in SQLite database
    stmt = select(AuditLogModel).where(AuditLogModel.id == 2)
    res_row = await db.execute(stmt)
    row_2 = res_row.scalar_one()
    # Maliciously edit verdict and action_type in database
    row_2.verdict = "BLOCK"
    row_2.action_type = "tampered_unauthorized_action"
    db.add(row_2)
    await db.commit()

    # 4. Verify /audit/verify detects tampering and identifies row 2 as the first broken link
    res_tampered = await flow_client.get(
        "/v1/audit/verify",
        headers={"X-API-Key": flow_client.analyst_key},
    )
    assert res_tampered.status_code == 200
    tampered_data = res_tampered.json()
    assert tampered_data["is_valid"] is False
    assert tampered_data["first_broken_link_id"] == 2
    assert "record ID 2" in tampered_data["message"]
    assert "tampered" in tampered_data["message"]


@pytest.mark.asyncio
async def test_extended_phase5_endpoints(flow_client: AsyncClient):
    """Tests PUT /policies/{agent_id}, GET /history, GET /logs/{req_id}, GET /metrics, POST /agents/{id}/quarantine."""
    # 1. GET /metrics
    res_metrics = await flow_client.get("/metrics")
    assert res_metrics.status_code == 200
    assert "shield_requests_total" in res_metrics.text
    assert "shield_verdict_total" in res_metrics.text

    # 2. PUT /policies/researcher_agent and GET /policies/researcher_agent/history
    res_pol = await flow_client.get("/v1/policies/researcher_agent", headers={"X-API-Key": flow_client.analyst_key})
    assert res_pol.status_code == 200
    pol_data = res_pol.json()

    # Update policy version
    pol_data["version"] = 2
    res_update = await flow_client.put(
        "/policies/researcher_agent",
        headers={"X-API-Key": flow_client.analyst_key},
        json=pol_data,
    )
    assert res_update.status_code == 200
    assert res_update.json()["status"] == "updated"

    # Check history
    res_hist = await flow_client.get(
        "/policies/researcher_agent/history",
        headers={"X-API-Key": flow_client.analyst_key},
    )
    assert res_hist.status_code == 200
    hist_data = res_hist.json()
    assert hist_data["versions_count"] >= 1
    assert hist_data["history"][0]["version"] == 2

    # 3. GET /logs/{request_id}
    # Log an entry first
    await append_audit_entry(
        db=flow_client.db,
        request_id="req_lookup_unique_999",
        agent_id="test_agent",
        action_type="tool_execution",
        verdict="ALLOW",
        risk_score=10.0,
        reason_codes=["BENIGN"],
        details={"tool": "calculator"},
    )
    res_log = await flow_client.get(
        "/logs/req_lookup_unique_999",
        headers={"X-API-Key": flow_client.analyst_key},
    )
    assert res_log.status_code == 200
    assert res_log.json()["request_id"] == "req_lookup_unique_999"

    # 4. POST /agents/{agent_id}/quarantine and /release
    res_q = await flow_client.post(
        "/agents/target_agent_xyz/quarantine",
        headers={"X-API-Key": flow_client.admin_key},
        json={"reason": "Suspected exfiltration"},
    )
    assert res_q.status_code == 200
    assert res_q.json()["is_quarantined"] is True

    res_rel = await flow_client.post(
        "/agents/target_agent_xyz/release",
        headers={"X-API-Key": flow_client.admin_key},
    )
    assert res_rel.status_code == 200
    assert res_rel.json()["status"] == "released"
