"""Agent Hijack Shield (PS-023) - Main FastAPI Application.

Production-grade security gateway protecting AI agents from prompt injection,
malicious tool execution, data exfiltration, and unauthorized agency.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from typing import Any, AsyncGenerator, Dict, List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import KNOWN_DEMO_KEYS, settings
from app.events import event_broadcaster, issue_sse_token, verify_sse_token
from app.db import (
    ApiKeyModel,
    ApprovalModel,
    AuditLogModel,
    Base,
    PolicyHistoryModel,
    QuarantineModel,
    engine,
    get_db,
)
from app.models import (
    ApiKeyCreateRequest,
    ApiKeyCreatedResponse,
    ApprovalActionResponse,
    ApprovalItem,
    AuditVerifyResponse,
    ChatRequest,
    ChatResponse,
    ErrorResponse,
    Finding,
    QuarantineRequest,
    QuarantineStatusResponse,
    ScanRequest,
    ScanResponse,
)
from app.security.audit_chain import verify_audit_chain
from app.security.auth import (
    AuthenticatedUser,
    create_api_key,
    get_current_user,
    hash_api_key,
    require_role,
)
from app.security.middleware import SecurityMiddleware
from app.shield.approvals import get_approval, list_pending_approvals, resolve_approval
from app.shield.circuit_breaker import circuit_breaker
from app.shield.detector import Detector
from app.shield.permissions import (
    AgentPolicy,
    policy_registry,
    serialize_policy_to_yaml,
)
from app.shield.pipeline import security_pipeline
from app.shield.trust import TrustLevel

logger = logging.getLogger("agent_shield")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application startup and shutdown lifecycle."""
    logger.info("Initializing Agent Hijack Shield gateway...")

    # Enforce fail-closed production readiness
    try:
        settings.validate_production_readiness()
    except ValueError as e:
        import os
        import secrets
        is_cloud_or_demo = (
            settings.demo_mode
            or os.environ.get("DEMO_MODE", "").lower() in ("true", "1")
            or os.environ.get("RENDER") is not None
            or os.environ.get("RENDER_SERVICE_ID") is not None
            or os.environ.get("IS_RENDER") is not None
            or os.environ.get("PORT") is not None
        )
        if is_cloud_or_demo:
            logger.warning("[CLOUD DEPLOY RECOVERY] Production security check: %s. Generating secure fallback keys.", e)
            if settings.secret_key == INSECURE_DEV_SECRET:
                settings.secret_key = secrets.token_hex(32)
            if settings.api_keys_salt == INSECURE_DEV_SALT:
                settings.api_keys_salt = secrets.token_hex(16)
        else:
            raise

    # Create database schema if not present
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Check for hardcoded demo keys in database
    async with AsyncSession(engine) as session:
        demo_hashes = [hash_api_key(k) for k in KNOWN_DEMO_KEYS]
        res = await session.execute(select(ApiKeyModel).where(ApiKeyModel.key_hash.in_(demo_hashes)))
        found_demo_keys = res.scalars().all()
        if found_demo_keys:
            import os
            is_cloud_or_demo = (
                settings.demo_mode
                or os.environ.get("DEMO_MODE", "").lower() in ("true", "1")
                or os.environ.get("RENDER") is not None
                or os.environ.get("RENDER_SERVICE_ID") is not None
                or os.environ.get("IS_RENDER") is not None
                or os.environ.get("PORT") is not None
            )
            if settings.app_env != "development" and not is_cloud_or_demo:
                raise ValueError(
                    f"CRITICAL: Found {len(found_demo_keys)} hardcoded DEMO API key(s) in database! "
                    f"Refusing to start because APP_ENV='{settings.app_env}' (only permitted when APP_ENV='development')."
                )
            else:
                logger.warning(
                    "[SECURITY WARNING] %d DEMO API key(s) detected in database! Ensure these are revoked or deleted before deploying to production.",
                    len(found_demo_keys),
                )
                print(f"[SECURITY WARNING] {len(found_demo_keys)} DEMO API key(s) detected in database! Do not use these keys in production.")

        # In development mode, ensure at least one demo admin key exists for initial access
        result = await session.execute(select(ApiKeyModel).limit(1))
        existing_key = result.scalar_one_or_none()
        if not existing_key:
            raw_key, _ = await create_api_key(session, name="Default Admin", role="admin")
            logger.info("Created initial Admin API Key: %s", raw_key)
            print(f"\n=======================================================")
            print(f"  INITIAL DEMO ADMIN API KEY: {raw_key}")
            print(f"  Role: admin (Use header: X-API-Key: {raw_key})")
            print(f"=======================================================\n")

        # Bootstrap Judge Key for zero-setup demo
        judge_key = settings.judge_api_key
        if not judge_key:
            judge_key = (
                "sk_client_demo_9876543210abcdef"
                if settings.app_env == "development"
                else "sk_judge_demo_zero_setup_client_key_32chars"
            )

        if settings.app_env != "development":
            if len(judge_key) < 32:
                raise ValueError("JUDGE_API_KEY must be at least 32 characters long in production/staging.")
            if judge_key in KNOWN_DEMO_KEYS:
                raise ValueError(f"JUDGE_API_KEY cannot use known hardcoded demo keys in {settings.app_env}.")

        judge_hash = hash_api_key(judge_key)
        res = await session.execute(select(ApiKeyModel).where(ApiKeyModel.key_hash == judge_hash))
        existing_judge = res.scalar_one_or_none()
        if not existing_judge:
            new_judge = ApiKeyModel(
                name="Public Judge Client",
                role="client",
                key_hash=judge_hash,
                revoked=False,
            )
            session.add(new_judge)
            await session.commit()
            logger.info("Bootstrapped public Judge API key with role=client")

    yield

    logger.info("Shutting down Agent Hijack Shield gateway...")
    await engine.dispose()


app = FastAPI(
    title="Agent Hijack Shield (PS-023) API",
    version="1.0.0",
    description=(
        "Production security gateway mediating LLM agent execution, prompt injection defense, "
        "intent verification, least-privilege tool capability gating, and cryptographic audit logging."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# 1. Custom Security Middleware (Headers, Rate Limits, Body Limits, Timeout)
app.add_middleware(SecurityMiddleware)

# 2. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

detector_instance = Detector()

# Include Feature Routers
from app.routers.stats import router as stats_router
from app.routers.eval import router as eval_router
from app.routers.logs import router as logs_router
from app.routers.public import router as public_router
from app.routers.demo import router as demo_router

app.include_router(stats_router)
app.include_router(eval_router)
app.include_router(logs_router)
app.include_router(public_router)
app.include_router(demo_router)


# -----------------------------------------------------------------
# Core Shield Endpoints (/v1)
# -----------------------------------------------------------------
@app.post(
    "/v1/chat",
    response_model=ChatResponse,
    summary="Mediate Agent Chat Execution",
    tags=["Agent Gateway"],
    responses={
        200: {"description": "Agent processed or gated response"},
        400: {"model": ErrorResponse, "description": "Invalid request schema"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        500: {"model": ErrorResponse, "description": "Fail-closed gateway error"},
    },
)
async def chat_endpoint(
    req: ChatRequest,
    request: Request,
    shield: Optional[bool] = Query(
        None, description="Toggle shield on/off for live side-by-side comparison"
    ),
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> ChatResponse:
    """Processes an agent chat prompt through the full inbound -> tool gate -> outbound pipeline."""
    # Allow query parameter ?shield=false to override body setting for easy demo comparison
    if shield is not None:
        req.shield_enabled = shield

    req_id = request.headers.get("X-Request-ID")
    resp = await security_pipeline.process_chat(
        db=db,
        request=req,
        request_id=req_id,
        caller_role=user.role,
    )
    event_broadcaster.broadcast(
        "chat_event",
        {
            "request_id": resp.request_id,
            "verdict": resp.verdict,
            "risk_score": resp.risk_score,
            "shield_enabled": resp.shield_enabled,
            "latency_ms": resp.latency_ms,
            "findings_count": len(resp.findings),
            "tool_calls_count": len(resp.tool_calls),
            "pending_approvals": resp.pending_approvals,
        },
    )
    return resp


@app.post(
    "/v1/scan",
    response_model=ScanResponse,
    summary="Fast Input Risk Scan",
    tags=["Detection"],
    responses={
        200: {"description": "Detailed risk assessment and matched rules"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    },
)
async def scan_endpoint(
    req: ScanRequest,
    user: AuthenticatedUser = Depends(require_role("client")),
) -> ScanResponse:
    """Performs fast synchronous text scan across rules, heuristics, and normalization layers."""
    trust = TrustLevel(req.trust_level)
    scan_res = detector_instance.scan_text(
        raw_text=req.text,
        trust_level=trust,
        source_id=req.source_id,
    )
    event_broadcaster.broadcast(
        "scan_event",
        {
            "verdict": scan_res.verdict,
            "risk_score": scan_res.risk_score,
            "findings_count": len(scan_res.findings),
            "reason_codes": scan_res.reason_codes,
            "scan_time_ms": scan_res.scan_time_ms,
        },
    )
    return scan_res


# -----------------------------------------------------------------
# Human-In-The-Loop Approvals
# -----------------------------------------------------------------
@app.get(
    "/v1/approvals",
    response_model=List[ApprovalItem],
    summary="List Pending Approvals",
    tags=["Human-in-the-Loop"],
)
async def list_approvals_endpoint(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    user: AuthenticatedUser = Depends(require_role("approver")),
    db: AsyncSession = Depends(get_db),
) -> List[ApprovalItem]:
    """Retrieves all pending operations awaiting human security sign-off."""
    records = await list_pending_approvals(db, agent_id=agent_id)
    items = []
    for r in records:
        try:
            args_redacted = json.loads(r.args_redacted_json)
        except Exception:
            args_redacted = {"raw": r.args_redacted_json}
        try:
            taint_sources = json.loads(r.taint_sources_json)
        except Exception:
            taint_sources = []

        items.append(
            ApprovalItem(
                id=r.id,
                agent_id=r.agent_id,
                session_id=r.session_id,
                request_id=r.request_id,
                tool_name=r.tool_name,
                args_redacted=args_redacted,
                args_hash=r.args_hash,
                reason=r.reason,
                risk_score=r.risk_score,
                taint_sources=taint_sources,
                status=r.status,  # type: ignore[arg-type]
                created_at=r.created_at,
                expires_at=r.expires_at,
            )
        )
    return items


@app.post(
    "/v1/approvals/{approval_id}/approve",
    response_model=ApprovalActionResponse,
    summary="Approve High-Risk Tool Call",
    tags=["Human-in-the-Loop"],
)
async def approve_tool_call(
    approval_id: str,
    user: AuthenticatedUser = Depends(require_role("approver")),
    db: AsyncSession = Depends(get_db),
) -> ApprovalActionResponse:
    """Authorizes a pending tool execution, issuing an HMAC single-use capability token."""
    try:
        approval, cap_token = await resolve_approval(
            db=db,
            approval_id=approval_id,
            action="APPROVED",
            approver_role=user.role,
            approver_id=user.name,
        )
        return ApprovalActionResponse(
            approval_id=approval.id,
            status="APPROVED",
            capability_token=cap_token,
            message="Operation approved. Capability token issued.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (PermissionError, ValueError, TimeoutError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post(
    "/v1/approvals/{approval_id}/reject",
    response_model=ApprovalActionResponse,
    summary="Reject High-Risk Tool Call",
    tags=["Human-in-the-Loop"],
)
async def reject_tool_call(
    approval_id: str,
    user: AuthenticatedUser = Depends(require_role("approver")),
    db: AsyncSession = Depends(get_db),
) -> ApprovalActionResponse:
    """Rejects a pending tool execution."""
    try:
        approval, _ = await resolve_approval(
            db=db,
            approval_id=approval_id,
            action="REJECTED",
            approver_role=user.role,
            approver_id=user.name,
        )
        return ApprovalActionResponse(
            approval_id=approval.id,
            status="REJECTED",
            capability_token=None,
            message="Operation rejected.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (PermissionError, ValueError, TimeoutError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# -----------------------------------------------------------------
# Audit Log & Cryptographic Verification
# -----------------------------------------------------------------
@app.get(
    "/v1/audit",
    summary="Query Audit Logs",
    tags=["Audit & Compliance"],
)
async def query_audit_logs(
    agent_id: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieves immutable hash-chained audit log records."""
    stmt = select(AuditLogModel).order_by(desc(AuditLogModel.id))
    if agent_id:
        stmt = stmt.where(AuditLogModel.agent_id == agent_id)
    if verdict:
        stmt = stmt.where(AuditLogModel.verdict == verdict.upper())

    stmt = stmt.limit(limit).offset(offset)
    res = await db.execute(stmt)
    records = res.scalars().all()

    entries = []
    for r in records:
        try:
            reasons = json.loads(r.reason_codes)
        except Exception:
            reasons = []
        try:
            details = json.loads(r.details_json)
        except Exception:
            details = {}

        entries.append({
            "id": r.id,
            "request_id": r.request_id,
            "timestamp": r.timestamp,
            "agent_id": r.agent_id,
            "session_id": r.session_id,
            "action_type": r.action_type,
            "verdict": r.verdict,
            "risk_score": r.risk_score,
            "reason_codes": reasons,
            "details": details,
            "prev_hash": r.prev_hash,
            "current_hash": r.current_hash,
        })

    return {"records": entries, "count": len(entries), "limit": limit, "offset": offset}


@app.get(
    "/v1/audit/verify",
    response_model=AuditVerifyResponse,
    summary="Cryptographic Audit Chain Integrity Verification",
    tags=["Audit & Compliance"],
)
async def verify_audit_endpoint(
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> AuditVerifyResponse:
    """Verifies SHA-256 chain linkage across all audit records and identifies any broken links."""
    return await verify_audit_chain(db)


# -----------------------------------------------------------------
# Circuit Breaker & Quarantine Controls
# -----------------------------------------------------------------
@app.post(
    "/v1/quarantine/{target}",
    response_model=QuarantineStatusResponse,
    summary="Emergency Quarantine Agent or Session",
    tags=["Circuit Breaker"],
)
async def quarantine_endpoint(
    target: str,
    body: QuarantineRequest,
    target_type: str = Query("session", enum=["agent", "session"]),
    user: AuthenticatedUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> QuarantineStatusResponse:
    """Manually places an agent or session into emergency quarantine."""
    rec = await circuit_breaker.quarantine_target(
        db=db,
        target_id=target,
        target_type=target_type,
        reason=body.reason,
        quarantined_by=user.name,
    )
    return QuarantineStatusResponse(
        target_id=rec.target_id,
        target_type=rec.target_type,
        is_quarantined=rec.is_quarantined,
        quarantined_at=rec.quarantined_at,
        reason=rec.reason,
        quarantined_by=rec.quarantined_by,
    )


@app.post(
    "/v1/quarantine/{target}/release",
    summary="Release Agent or Session from Quarantine",
    tags=["Circuit Breaker"],
)
async def release_quarantine_endpoint(
    target: str,
    user: AuthenticatedUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Releases an agent or session from quarantine. Admin only."""
    success = await circuit_breaker.release_quarantine(
        db=db,
        target_id=target,
        released_by=user.name,
        user_role=user.role,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Target not found in active quarantine")
    return {"target": target, "status": "released", "released_by": user.name}


@app.post(
    "/v1/agents/{agent_id}/quarantine",
    response_model=QuarantineStatusResponse,
    summary="Quarantine Specific Agent",
    tags=["Circuit Breaker"],
)
@app.post("/agents/{agent_id}/quarantine", include_in_schema=False)
async def agent_quarantine_endpoint(
    agent_id: str,
    body: QuarantineRequest = QuarantineRequest(reason="Admin quarantined agent"),
    user: AuthenticatedUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> QuarantineStatusResponse:
    """Places a specific agent into circuit breaker quarantine."""
    rec = await circuit_breaker.quarantine_target(
        db=db,
        target_id=agent_id,
        target_type="agent",
        reason=body.reason,
        quarantined_by=user.name,
    )
    return QuarantineStatusResponse(
        target_id=rec.target_id,
        target_type=rec.target_type,
        is_quarantined=rec.is_quarantined,
        quarantined_at=rec.quarantined_at,
        reason=rec.reason,
        quarantined_by=rec.quarantined_by,
    )


@app.post(
    "/v1/agents/{agent_id}/release",
    summary="Release Agent from Quarantine",
    tags=["Circuit Breaker"],
)
@app.post("/agents/{agent_id}/release", include_in_schema=False)
async def agent_release_endpoint(
    agent_id: str,
    user: AuthenticatedUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Releases a quarantined agent. Admin only."""
    success = await circuit_breaker.release_quarantine(
        db=db,
        target_id=agent_id,
        released_by=user.name,
        user_role=user.role,
    )
    if not success:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found in active quarantine")
    return {"agent_id": agent_id, "status": "released", "released_by": user.name}


# -----------------------------------------------------------------
# Agent Policies Management
# -----------------------------------------------------------------
@app.get(
    "/v1/policies/{agent_id}",
    summary="View Agent Policy",
    tags=["Policy Engine"],
)
@app.get("/policies/{agent_id}", include_in_schema=False)
async def get_policy_endpoint(
    agent_id: str,
    user: AuthenticatedUser = Depends(require_role("analyst")),
) -> Dict[str, Any]:
    """Returns the active security policy for an agent."""
    policy = policy_registry.get_policy(agent_id)
    return policy.model_dump()


@app.put(
    "/v1/policies/{agent_id}",
    summary="Update Agent Policy",
    tags=["Policy Engine"],
)
@app.put("/policies/{agent_id}", include_in_schema=False)
async def update_policy_endpoint(
    agent_id: str,
    policy: AgentPolicy,
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Updates an agent's security policy. Privilege widening requires admin role."""
    policy.agent_id = agent_id
    success, msg, diff = policy_registry.register_policy(policy, user_role=user.role)
    if not success:
        raise HTTPException(status_code=403, detail=msg)

    # Record policy version change in database
    history = PolicyHistoryModel(
        agent_id=agent_id,
        version=policy.version,
        policy_yaml=serialize_policy_to_yaml(policy),
        updated_by=user.name,
    )
    db.add(history)
    await db.commit()

    return {"status": "updated", "message": msg, "version": policy.version, "diff": diff}


@app.get(
    "/v1/policies/{agent_id}/history",
    summary="Get Agent Policy History",
    tags=["Policy Engine"],
)
@app.get("/policies/{agent_id}/history", include_in_schema=False)
async def get_policy_history_endpoint(
    agent_id: str,
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Returns the versioned history of policy updates for an agent."""
    stmt = (
        select(PolicyHistoryModel)
        .where(PolicyHistoryModel.agent_id == agent_id)
        .order_by(desc(PolicyHistoryModel.version))
    )
    res = await db.execute(stmt)
    records = res.scalars().all()
    history = [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "version": r.version,
            "policy_yaml": r.policy_yaml,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_by": r.updated_by,
        }
        for r in records
    ]
    return {"agent_id": agent_id, "versions_count": len(history), "history": history}


@app.get(
    "/logs/{request_id}",
    summary="Get Log by Request ID (Root Alias)",
    tags=["Audit & Logs"],
    include_in_schema=False,
)
async def get_log_by_request_id_root(
    request_id: str,
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Root alias for /v1/logs/{request_id}."""
    from app.routers.logs import get_log_by_request_id
    return await get_log_by_request_id(request_id=request_id, user=user, db=db)


@app.get(
    "/metrics",
    summary="Prometheus & Operational Telemetry Metrics",
    tags=["Monitoring & Events"],
)
async def get_metrics_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> PlainTextResponse:
    """Exposes gateway operational metrics in Prometheus plaintext format.

    Authentication & Security Boundary:
    - In development (APP_ENV=development): Unauthenticated access is permitted for local monitoring/testing.
    - In production/staging (APP_ENV!=development): Requires authentication with 'analyst' or 'admin' role
      via X-API-Key or Authorization Bearer header.
    """
    if settings.app_env != "development":
        key = x_api_key if isinstance(x_api_key, str) else None
        if not key and isinstance(authorization, str):
            if authorization.startswith("Bearer "):
                key = authorization[7:].strip()
            elif authorization.startswith("ApiKey "):
                key = authorization[7:].strip()
            else:
                key = authorization.strip()
        user = await get_current_user(x_api_key=key, db=db)
        if not user.has_role("analyst"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Metrics endpoint requires 'analyst' or 'admin' role in production",
            )

    from sqlalchemy import func
    total_res = await db.execute(select(func.count(AuditLogModel.id)))
    total_reqs = total_res.scalar() or 0

    verdict_stmt = select(AuditLogModel.verdict, func.count(AuditLogModel.id)).group_by(AuditLogModel.verdict)
    verdict_res = await db.execute(verdict_stmt)
    counts = {v: c for v, c in verdict_res.all()}
    q_res = await db.execute(select(func.count(QuarantineModel.target_id)).where(QuarantineModel.is_quarantined == True))
    q_count = q_res.scalar() or 0

    lines = [
        "# HELP shield_requests_total Total number of chat requests processed by the security gateway",
        "# TYPE shield_requests_total counter",
        f"shield_requests_total {total_reqs}",
        "# HELP shield_verdict_total Total decisions by verdict type",
        "# TYPE shield_verdict_total counter",
        f'shield_verdict_total{{verdict="BLOCK"}} {counts.get("BLOCK", 0)}',
        f'shield_verdict_total{{verdict="FLAG"}} {counts.get("FLAG", 0)}',
        f'shield_verdict_total{{verdict="ALLOW"}} {counts.get("ALLOW", 0)}',
        "# HELP shield_circuit_breaker_quarantined Number of currently quarantined targets",
        "# TYPE shield_circuit_breaker_quarantined gauge",
        f"shield_circuit_breaker_quarantined {q_count}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")



# -----------------------------------------------------------------
# Authentication & API Key Management
# -----------------------------------------------------------------
@app.post(
    "/v1/auth/keys",
    response_model=ApiKeyCreatedResponse,
    summary="Generate New API Key",
    tags=["Authentication"],
)
async def create_key_endpoint(
    req: ApiKeyCreateRequest,
    user: AuthenticatedUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyCreatedResponse:
    """Generates a new API key with assigned RBAC role. Raw key is displayed once."""
    raw_key, record = await create_api_key(db, name=req.name, role=req.role)
    return ApiKeyCreatedResponse(
        name=record.name,
        role=record.role,
        api_key=raw_key,
        message="Store this API key securely; it cannot be displayed again.",
    )


# -----------------------------------------------------------------
# Real-Time Monitoring & Telemetry (SSE)
# -----------------------------------------------------------------
@app.post(
    "/v1/events/token",
    summary="Generate Short-Lived SSE Browser Ticket",
    tags=["Monitoring & Events"],
)
@app.post("/events/token", include_in_schema=False)
async def generate_sse_token_endpoint(
    user: AuthenticatedUser = Depends(require_role("analyst")),
) -> Dict[str, Any]:
    """Generates a short-lived (60s) HMAC ticket allowing browser EventSource connections to /events.

    Browser EventSource Usage:
    ```javascript
    // 1. Fetch short-lived ticket using API Key
    const res = await fetch('/v1/events/token', {
      method: 'POST',
      headers: { 'X-API-Key': 'your_analyst_key' }
    });
    const { sse_token } = await res.json();

    // 2. Open standard EventSource connection with ticket query param
    const es = new EventSource('/events?token=' + encodeURIComponent(sse_token));
    es.addEventListener('scan', (e) => console.log('Scan event:', JSON.parse(e.data)));
    ```
    """
    token = issue_sse_token(user_name=user.name, role=user.role, ttl_seconds=60.0)
    return {
        "sse_token": token,
        "token_type": "Bearer",
        "expires_in_seconds": 60,
        "stream_url": f"/events?token={token}",
    }


@app.get(
    "/events",
    summary="Real-Time Server-Sent Events (SSE) Stream",
    tags=["Monitoring & Events"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "Continuous stream of security audit, scan, and tool decision events",
        }
    },
)
@app.get(
    "/api/v1/events",
    summary="Real-Time Server-Sent Events (SSE) Stream (v1)",
    tags=["Monitoring & Events"],
    include_in_schema=False,
)
async def sse_events_endpoint(
    request: Request,
    token: Optional[str] = Query(None, description="Short-lived HMAC ticket for browser EventSource"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
):
    """Subscribes to live gateway security events (scans, tool calls, approvals, circuit breaker).

    Connection Methods:
    1. Browser EventSource (Recommended for Web UI):
       Request a ticket from POST /v1/events/token, then connect to /events?token=<ticket>.
    2. Direct Streaming Fetch (Recommended for Services & Node.js):
       Connect with X-API-Key or Authorization Bearer header:
       `const resp = await fetch('/events', { headers: { 'X-API-Key': key } });`
    """
    # Verify authentication
    is_authenticated = False
    if token and isinstance(token, str):
        payload = verify_sse_token(token)
        if payload:
            is_authenticated = True
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired SSE ticket",
            )
    else:
        key = x_api_key if isinstance(x_api_key, str) else None
        if not key and isinstance(authorization, str):
            if authorization.startswith("Bearer "):
                key = authorization[7:].strip()
            elif authorization.startswith("ApiKey "):
                key = authorization[7:].strip()
            else:
                key = authorization.strip()
        if key:
            user = await get_current_user(x_api_key=key, db=db)
            if user:
                is_authenticated = True

    if not is_authenticated:
        if settings.app_env != "development":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required for SSE stream. Provide ?token=<ticket> or X-API-Key header.",
            )

    queue = event_broadcaster.subscribe()
    return StreamingResponse(
        event_broadcaster.event_generator(queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# -----------------------------------------------------------------
# Health Endpoint
# -----------------------------------------------------------------
@app.get("/healthz", tags=["System"])
async def health_check() -> Dict[str, str]:
    """System liveness probe."""
    return {"status": "healthy", "service": "Agent Hijack Shield", "version": "1.0.0"}


# -----------------------------------------------------------------
# Minimal Secure Frontend (Dashboard)
# -----------------------------------------------------------------
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_landing():
        landing_file = os.path.join(frontend_dir, "landing.html")
        if os.path.exists(landing_file):
            return FileResponse(landing_file)
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse({"message": "Frontend not found"})

    @app.get("/playground", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def serve_playground():
        playground_file = os.path.join(frontend_dir, "playground.html")
        if os.path.exists(playground_file):
            return FileResponse(playground_file)
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse({"message": "Playground not found"})

    @app.get("/scenarios.json", include_in_schema=False)
    async def serve_scenarios():
        scenarios_file = os.path.join(frontend_dir, "scenarios.json")
        if os.path.exists(scenarios_file):
            return FileResponse(scenarios_file, media_type="application/json")
        return JSONResponse([])
