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
    block_rate = round((blocked_count / total_requests) * 100.0, 2) if total_requests > 0 else 0.0

    return {
        "status": "OPERATIONAL",
        "total_requests": total_requests,
        "verdict_distribution": {
            "BLOCK": verdict_counts.get("BLOCK", 0),
            "FLAG": verdict_counts.get("FLAG", 0),
            "ALLOW": verdict_counts.get("ALLOW", 0),
        },
        "block_rate_percent": block_rate,
        "avg_risk_score": avg_risk,
        "pending_approvals_count": pending_approvals,
        "active_quarantines_count": active_quarantines,
        "active_policies_count": len(policy_registry._policies),
        "active_detection_rules": len(DETECTION_RULES),
    }
