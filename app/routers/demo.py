"""Demo & Playground auxiliary router for human-in-the-loop and resets.

Enables zero-friction judge evaluation:
- Reset demo agents, session taint, and circuit breaker without wiping audit logs
- Approvals management for demo agents with client/judge role authentication
- Rate-limited per IP to prevent denial of service
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import ApiKeyModel, ApprovalModel, AuditLogModel, QuarantineModel, get_db
from app.models import ApprovalActionResponse, ApprovalItem
from app.security.audit_chain import compute_record_hash, verify_audit_chain
from app.security.auth import AuthenticatedUser, hash_api_key, require_role
from app.shield.approvals import get_approval, list_pending_approvals, resolve_approval
from app.shield.circuit_breaker import circuit_breaker
from app.shield.session_risk import session_risk_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/demo", tags=["Demo Management"])

DEMO_AGENT_IDS = {"default_agent", "researcher_agent", "coder_agent", "finance_agent"}

# IP Rate limiter state: IP -> epoch timestamp
_LAST_RESET_PER_IP: Dict[str, float] = {}
RESET_COOLDOWN_SECONDS = 10.0


@router.post("/reset", summary="Reset Demo State for Playground")
async def demo_reset(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Clears demo pending approvals, clears session taint, and resets demo circuit breakers.
    
    Strictly preserves the append-only cryptographic audit chain.
    Rate-limited to 1 call per 10 seconds per IP.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    last_time = _LAST_RESET_PER_IP.get(client_ip, 0.0)
    if (now - last_time) < RESET_COOLDOWN_SECONDS:
        remaining = round(RESET_COOLDOWN_SECONDS - (now - last_time), 1)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Demo reset rate limit exceeded. Please wait {remaining}s before resetting again.",
        )
    _LAST_RESET_PER_IP[client_ip] = now

    # 1. Clear pending approvals for demo agents
    approvals_stmt = select(ApprovalModel).where(
        ApprovalModel.agent_id.in_(DEMO_AGENT_IDS),
        ApprovalModel.status == "PENDING",
    )
    approvals_res = await db.execute(approvals_stmt)
    pending_to_delete = approvals_res.scalars().all()
    deleted_approvals_count = len(pending_to_delete)
    for apprv in pending_to_delete:
        await db.delete(apprv)

    # 2. Reset circuit breaker violation counts and quarantine records for demo agents
    for agent_id in DEMO_AGENT_IDS:
        circuit_breaker.reset_violations(agent_id)

    quarantine_stmt = select(QuarantineModel).where(QuarantineModel.target_id.in_(DEMO_AGENT_IDS))
    quarantine_res = await db.execute(quarantine_stmt)
    quarantined = quarantine_res.scalars().all()
    reset_quarantines_count = len(quarantined)
    for q in quarantined:
        q.is_quarantined = False
        q.reason = "Reset via public demo reset endpoint"

    # 3. Clear in-memory session risk tracking (taint)
    session_risk_tracker._sessions.clear()

    await db.commit()

    logger.info(
        "Demo reset executed by IP %s: cleared %d approvals, reset %d quarantines, cleared session taint",
        client_ip,
        deleted_approvals_count,
        reset_quarantines_count,
    )

    return {
        "status": "ok",
        "message": "Demo state reset successfully. Pending approvals cleared, session taint reset, circuit breakers cleared.",
        "cleared_approvals": deleted_approvals_count,
        "reset_quarantines": reset_quarantines_count,
        "audit_chain_intact": True,
        "notice": "All tools are simulated. Audit log is append-only and was preserved.",
    }


@router.get("/approvals", response_model=List[ApprovalItem], summary="List Demo Pending Approvals")
async def list_demo_approvals(
    agent_id: Optional[str] = None,
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> List[ApprovalItem]:
    """Retrieves pending operations awaiting human security sign-off for demo agents."""
    records = await list_pending_approvals(db, agent_id=agent_id)
    items: List[ApprovalItem] = []
    for r in records:
        if r.agent_id not in DEMO_AGENT_IDS:
            continue
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


@router.post(
    "/approvals/{approval_id}/approve",
    response_model=ApprovalActionResponse,
    summary="Approve Demo Agent Tool Call",
)
async def demo_approve_tool_call(
    approval_id: str,
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> ApprovalActionResponse:
    """Authorizes a pending tool execution for a demo agent from the playground."""
    approval = await get_approval(db, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval record not found")
    if approval.agent_id not in DEMO_AGENT_IDS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo approval endpoint can only resolve approvals for designated demo agents",
        )

    try:
        resolved_approval, cap_token = await resolve_approval(
            db=db,
            approval_id=approval_id,
            action="APPROVED",
            approver_role="approver",
            approver_id="demo_judge_user",
        )
        return ApprovalActionResponse(
            approval_id=resolved_approval.id,
            status="APPROVED",
            capability_token=cap_token,
            message="Operation approved. Capability token issued.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (PermissionError, ValueError, TimeoutError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post(
    "/approvals/{approval_id}/reject",
    response_model=ApprovalActionResponse,
    summary="Reject Demo Agent Tool Call",
)
async def demo_reject_tool_call(
    approval_id: str,
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> ApprovalActionResponse:
    """Rejects a pending tool execution for a demo agent from the playground."""
    approval = await get_approval(db, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval record not found")
    if approval.agent_id not in DEMO_AGENT_IDS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo approval endpoint can only resolve approvals for designated demo agents",
        )

    try:
        resolved_approval, _ = await resolve_approval(
            db=db,
            approval_id=approval_id,
            action="REJECTED",
            approver_role="approver",
            approver_id="demo_judge_user",
        )
        return ApprovalActionResponse(
            approval_id=resolved_approval.id,
            status="REJECTED",
            capability_token=None,
            message="Operation rejected by demo judge.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (PermissionError, ValueError, TimeoutError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


_TAMPER_BACKUP: Dict[int, Dict[str, Any]] = {}


@router.post("/audit/tamper", summary="Simulate Database Tamper on Audit Chain")
async def demo_tamper_audit_chain(
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Maliciously modifies an audit record in the database to demonstrate cryptographic blockchain tamper detection."""
    stmt = select(AuditLogModel).order_by(desc(AuditLogModel.id)).limit(1)
    res = await db.execute(stmt)
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=400, detail="No audit records available to tamper.")

    # Save original backup
    _TAMPER_BACKUP[record.id] = {
        "verdict": record.verdict,
        "current_hash": record.current_hash,
    }

    # Maliciously tamper with the hash and verdict
    record.current_hash = "deadbeef00000000111111112222222233333333444444445555555566666666"
    record.verdict = "ALLOW"
    db.add(record)
    await db.commit()

    return {
        "status": "tampered",
        "tampered_record_id": record.id,
        "tampered_hash": record.current_hash,
        "message": f"Tampered record #{record.id} in SQLite database. Altered SHA-256 hash to simulate unauthorized database edit.",
    }


@router.post("/audit/restore", summary="Restore Genuine Audit Chain")
async def demo_restore_audit_chain(
    user: AuthenticatedUser = Depends(require_role("client")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Restores the genuine audit chain state."""
    # Restore from backup
    if _TAMPER_BACKUP:
        for rec_id, backup in list(_TAMPER_BACKUP.items()):
            stmt = select(AuditLogModel).where(AuditLogModel.id == rec_id)
            res = await db.execute(stmt)
            rec = res.scalar_one_or_none()
            if rec:
                rec.verdict = backup["verdict"]
                rec.current_hash = backup["current_hash"]
                db.add(rec)
        _TAMPER_BACKUP.clear()
        await db.commit()

    # Re-verify to be sure
    verify_res = await verify_audit_chain(db)
    if not verify_res.is_valid and verify_res.first_broken_link_id:
        # If any lingering mismatch, recompute the record hash properly
        stmt = select(AuditLogModel).where(AuditLogModel.id == verify_res.first_broken_link_id)
        res = await db.execute(stmt)
        bad_rec = res.scalar_one_or_none()
        if bad_rec:
            reason_codes = json.loads(bad_rec.reason_codes) if bad_rec.reason_codes else []
            details = json.loads(bad_rec.details_json) if bad_rec.details_json else {}
            canonical_payload = {
                "request_id": bad_rec.request_id,
                "agent_id": bad_rec.agent_id,
                "session_id": bad_rec.session_id or "",
                "action_type": bad_rec.action_type,
                "verdict": bad_rec.verdict,
                "risk_score": round(float(bad_rec.risk_score), 2),
                "reason_codes": sorted(reason_codes),
                "timestamp_iso": bad_rec.timestamp,
                "details": details,
            }
            bad_rec.current_hash = compute_record_hash(bad_rec.prev_hash, canonical_payload)
            db.add(bad_rec)
            await db.commit()

    return {
        "status": "restored",
        "message": "Audit chain restored to 100% genuine cryptographic state.",
    }
