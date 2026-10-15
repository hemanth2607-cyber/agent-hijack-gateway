"""Audit Logs API Router for Agent Hijack Shield."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AuditLogModel, get_db
from app.security.auth import AuthenticatedUser, require_role

router = APIRouter(prefix="/v1/logs", tags=["Audit & Logs"])


@router.get("", summary="Query Gateway Audit Logs")
async def get_logs_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: ALLOW, FLAG, BLOCK"),
    user: AuthenticatedUser = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieves paginated audit trail records with cryptographic hash links."""
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
