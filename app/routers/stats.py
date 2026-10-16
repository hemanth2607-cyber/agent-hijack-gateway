"""Stats and Telemetry Router for Agent Hijack Shield."""

from __future__ import annotations

import json
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import ApprovalModel, AuditLogModel, QuarantineModel, get_db
from app.security.auth import AuthenticatedUser, require_role
from app.shield.detector import DETECTION_RULES
from app.shield.permissions import policy_registry

router = APIRouter(prefix="/v1/stats", tags=["Stats & Analytics"])


@router.get("", summary="Get Gateway Security Analytics & Operational Stats")
async def get_security_stats(
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Returns aggregated security metrics, verdict distribution, and operational health."""
    # 1. Total Requests Count
    total_res = await db.execute(select(func.count(AuditLogModel.id)))
    total_requests = total_res.scalar() or 0

    # 2. Verdict Distribution
    verdict_stmt = select(AuditLogModel.verdict, func.count(AuditLogModel.id)).group_by(AuditLogModel.verdict)
    verdict_res = await db.execute(verdict_stmt)
    verdict_counts = {v: count for v, count in verdict_res.all()}

    # 3. Pending Approvals Count
    approval_stmt = select(func.count(ApprovalModel.id)).where(ApprovalModel.status == "PENDING")
    approval_res = await db.execute(approval_stmt)
    pending_approvals = approval_res.scalar() or 0

    # 4. Active Quarantines Count
    quarantine_stmt = select(func.count(QuarantineModel.target_id)).where(QuarantineModel.is_quarantined == True)
    quarantine_res = await db.execute(quarantine_stmt)
    active_quarantines = quarantine_res.scalar() or 0

    # 5. Average Risk Score
    avg_risk_stmt = select(func.avg(AuditLogModel.risk_score))
    avg_risk_res = await db.execute(avg_risk_stmt)
    avg_risk = round(float(avg_risk_res.scalar() or 0.0), 2)

    # 6. Block Rate Calculation
    blocked_count = verdict_counts.get("BLOCK", 0)
    block_rate = round((blocked_count / total_requests * 100), 2) if total_requests > 0 else 0.0

    # 7. Layer breakdown and headline aggregates
    det_stmt = select(func.count(AuditLogModel.id)).where(
        AuditLogModel.action_type == "INBOUND_SCAN",
        AuditLogModel.verdict.in_(["BLOCK", "FLAG"]),
    )
    det_res = await db.execute(det_stmt)
    detector_blocks = det_res.scalar() or 0

    perm_stmt = select(func.count(AuditLogModel.id)).where(
        AuditLogModel.action_type == "TOOL_AUTHORIZATION",
        AuditLogModel.verdict.in_(["BLOCK", "DENIED"]),
    )
    perm_res = await db.execute(perm_stmt)
    permission_blocks = perm_res.scalar() or 0

    total_held_res = await db.execute(select(func.count(ApprovalModel.id)))
    total_held = total_held_res.scalar() or 0

    human_stmt = select(func.count(AuditLogModel.id)).where(
        AuditLogModel.action_type.in_(["APPROVAL_RESOLVE", "TOOL_AUTHORIZATION"]),
        AuditLogModel.verdict.in_(["FLAG", "NEEDS_APPROVAL", "APPROVAL_REQUIRED"]),
    )
    human_res = await db.execute(human_stmt)
    human_count = max(human_res.scalar() or 0, total_held)

    risky_stopped = blocked_count + permission_blocks

    import datetime
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")

    return {
        "status": "OPERATIONAL",
        "requests_screened": total_requests,
        "attacks_blocked": blocked_count,
        "actions_held": total_held or pending_approvals,
        "risky_actions_stopped": risky_stopped,
        "total_requests": total_requests,
        "verdict_distribution": {
            "BLOCK": verdict_counts.get("BLOCK", 0),
            "FLAG": verdict_counts.get("FLAG", 0),
            "ALLOW": verdict_counts.get("ALLOW", 0),
        },
        "layer_counts": {
            "text_detector": detector_blocks,
            "permission_rules": permission_blocks,
            "human_approval": human_count,
        },
        "block_rate_percent": block_rate,
        "avg_risk_score": avg_risk,
        "pending_approvals_count": pending_approvals,
        "active_quarantines_count": active_quarantines,
        "active_policies_count": len(policy_registry._policies),
        "active_detection_rules": len(DETECTION_RULES),
        "last_updated": now_str,
    }
