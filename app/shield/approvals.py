"""Human-in-the-loop approval workflow and database integration.

Manages pending authorizations for high-risk agent operations:
- Bound to cryptographic SHA-256 hash of canonical arguments
- Replay, double-approval, and tampering prevention
- Strict RBAC check (requires approver or admin role)
- Capability token issuance upon legitimate approval
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import ApprovalModel
from app.security.secrets import scan_and_redact_secrets
from app.shield.capabilities import capability_manager


def compute_args_hash(args: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 of tool arguments via canonical JSON."""
    canonical_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


async def create_approval_request(
    db: AsyncSession,
    agent_id: str,
    session_id: Optional[str],
    request_id: str,
    tool_name: str,
    args: Dict[str, Any],
    reason: str,
    risk_score: float,
    taint_sources: List[str],
    ttl_minutes: int = 15,
) -> ApprovalModel:
    """Creates a new pending human approval record."""
    approval_id = str(uuid.uuid4())
    args_hash = compute_args_hash(args)

    # Redact any accidental sensitive material before storing display version
    raw_args_str = json.dumps(args)
    _, _, redacted_args_str = scan_and_redact_secrets(raw_args_str)

    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(minutes=ttl_minutes)

    approval = ApprovalModel(
        id=approval_id,
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
        tool_name=tool_name,
        args_redacted_json=redacted_args_str,
        args_hash=args_hash,
        reason=reason,
        risk_score=risk_score,
        taint_sources_json=json.dumps(taint_sources),
        status="PENDING",
        created_at=now,
        expires_at=expires_at,
    )

    db.add(approval)
    await db.commit()
    await db.refresh(approval)
    return approval


async def get_approval(
    db: AsyncSession,
    approval_id: str,
) -> Optional[ApprovalModel]:
    """Retrieves an approval record by ID."""
    stmt = select(ApprovalModel).where(ApprovalModel.id == approval_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def list_pending_approvals(
    db: AsyncSession,
    agent_id: Optional[str] = None,
) -> List[ApprovalModel]:
    """Lists all currently pending non-expired approvals."""
    stmt = select(ApprovalModel).where(ApprovalModel.status == "PENDING")
    if agent_id:
        stmt = stmt.where(ApprovalModel.agent_id == agent_id)

    res = await db.execute(stmt)
    records = list(res.scalars().all())

    now = datetime.datetime.now(datetime.timezone.utc)
    valid_pending = []
    for r in records:
        # Check expiration
        exp = r.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if now > exp:
            r.status = "EXPIRED"
            db.add(r)
        else:
            valid_pending.append(r)

    await db.commit()
    return valid_pending


async def resolve_approval(
    db: AsyncSession,
    approval_id: str,
    action: str,  # "APPROVED" or "REJECTED"
    approver_role: str,
    approver_id: str,
) -> Tuple[ApprovalModel, Optional[str]]:
    """Resolves a pending approval, issuing a capability token if approved.

    Enforces:
    - Approver role authorization (approver or admin)
    - Anti-tampering and double-approval prevention
    - Expiration check
    """
    if approver_role not in ["approver", "admin"]:
        raise PermissionError(
            f"Role '{approver_role}' is not authorized to resolve approvals (requires 'approver' or 'admin')"
        )

    action = action.upper()
    if action not in ["APPROVED", "REJECTED"]:
        raise ValueError(f"Invalid approval action '{action}'; must be APPROVED or REJECTED")

    approval = await get_approval(db, approval_id)
    if not approval:
        raise KeyError(f"Approval record '{approval_id}' not found")

    if approval.status != "PENDING":
        raise ValueError(f"Approval cannot be resolved: current status is '{approval.status}'")

    now = datetime.datetime.now(datetime.timezone.utc)
    exp = approval.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)

    if now > exp:
        approval.status = "EXPIRED"
        approval.resolved_at = now
        await db.commit()
        raise TimeoutError("Approval record has expired")

    approval.status = action
    approval.approver_id = approver_id
    approval.resolved_at = now

    capability_token = None
    if action == "APPROVED":
        capability_token = capability_manager.issue_token(
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            args_hash=approval.args_hash,
            request_id=approval.request_id,
        )

    await db.commit()
    await db.refresh(approval)
    return approval, capability_token
