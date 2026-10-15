"""Tamper-evident, cryptographically forward-secure hash-chained audit log.

Guarantees integrity and non-repudiation:
- Every record stores prev_hash and current_hash = SHA256(prev_hash + canonical_json)
- Any modification, insertion, or deletion breaks the cryptographic link
- verify_audit_chain() verifies the entire chain and pinpoint broken links
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import AuditLogModel
from app.models import AuditVerifyResponse


def compute_record_hash(prev_hash: str, payload_data: Dict[str, Any]) -> str:
    """Computes SHA-256 hash across previous hash and canonical sorted JSON."""
    canonical_json = json.dumps(payload_data, sort_keys=True, separators=(",", ":"))
    content_to_hash = f"{prev_hash}|{canonical_json}"
    return hashlib.sha256(content_to_hash.encode("utf-8")).hexdigest()


import asyncio

_audit_chain_lock = asyncio.Lock()


async def get_latest_hash(db: AsyncSession) -> str:
    """Retrieves the latest audit entry hash or defaults to genesis hash."""
    result = await db.execute(
        select(AuditLogModel.current_hash).order_by(desc(AuditLogModel.id)).limit(1)
    )
    latest = result.scalar_one_or_none()
    return latest if latest is not None else settings.audit_chain_genesis_hash


async def append_audit_entry(
    db: AsyncSession,
    request_id: str,
    agent_id: str,
    action_type: str,
    verdict: str,
    risk_score: float,
    reason_codes: List[str],
    details: Dict[str, Any],
    session_id: Optional[str] = None,
    timestamp: Optional[datetime.datetime] = None,
) -> AuditLogModel:
    """Appends an immutable, hash-linked audit record to the database with strict concurrency lock."""
    if timestamp is None:
        timestamp_dt = datetime.datetime.now(datetime.timezone.utc)
        timestamp_str = timestamp_dt.isoformat()
    elif isinstance(timestamp, datetime.datetime):
        timestamp_str = timestamp.isoformat()
    else:
        timestamp_str = str(timestamp)

    async with _audit_chain_lock:
        # 1. Fetch the latest record hash
        prev_hash = await get_latest_hash(db)

        # 2. Prepare canonical data dictionary for hashing
        canonical_payload = {
            "request_id": request_id,
            "agent_id": agent_id,
            "session_id": session_id or "",
            "action_type": action_type,
            "verdict": verdict,
            "risk_score": round(float(risk_score), 2),
            "reason_codes": sorted(reason_codes),
            "timestamp_iso": timestamp_str,
            "details": details,
        }

        # 3. Compute cryptographic current_hash
        current_hash = compute_record_hash(prev_hash, canonical_payload)

        # 4. Create and persist model
        entry = AuditLogModel(
            request_id=request_id,
            timestamp=timestamp_str,
            agent_id=agent_id,
            session_id=session_id,
            action_type=action_type,
            verdict=verdict,
            risk_score=risk_score,
            reason_codes=json.dumps(reason_codes),
            details_json=json.dumps(details),
            prev_hash=prev_hash,
            current_hash=current_hash,
        )

        db.add(entry)
        await db.commit()
        await db.refresh(entry)
        return entry


async def verify_audit_chain(db: AsyncSession) -> AuditVerifyResponse:
    """Verifies cryptographic integrity of the entire audit chain from genesis."""
    result = await db.execute(
        select(AuditLogModel).order_by(AuditLogModel.id.asc())
    )
    records = result.scalars().all()

    if not records:
        return AuditVerifyResponse(
            is_valid=True,
            total_records=0,
            message="Audit log is empty; genesis state valid.",
        )

    expected_prev_hash = settings.audit_chain_genesis_hash

    for record in records:
        # Check that record's prev_hash matches what is expected
        if record.prev_hash != expected_prev_hash:
            return AuditVerifyResponse(
                is_valid=False,
                total_records=len(records),
                first_broken_link_id=record.id,
                expected_hash=expected_prev_hash,
                actual_hash=record.prev_hash,
                message=f"Audit chain broken at record ID {record.id}: prev_hash mismatch.",
            )

        # Reconstruct canonical payload for this record
        try:
            reason_codes = json.loads(record.reason_codes)
            details = json.loads(record.details_json)
        except Exception:
            return AuditVerifyResponse(
                is_valid=False,
                total_records=len(records),
                first_broken_link_id=record.id,
                message=f"Audit chain corrupted at record ID {record.id}: JSON deserialization failure.",
            )

        canonical_payload = {
            "request_id": record.request_id,
            "agent_id": record.agent_id,
            "session_id": record.session_id or "",
            "action_type": record.action_type,
            "verdict": record.verdict,
            "risk_score": round(float(record.risk_score), 2),
            "reason_codes": sorted(reason_codes),
            "timestamp_iso": (
                record.timestamp
                if isinstance(record.timestamp, str)
                else record.timestamp.isoformat()
            ),
            "details": details,
        }

        recomputed_hash = compute_record_hash(expected_prev_hash, canonical_payload)

        if recomputed_hash != record.current_hash:
            return AuditVerifyResponse(
                is_valid=False,
                total_records=len(records),
                first_broken_link_id=record.id,
                expected_hash=recomputed_hash,
                actual_hash=record.current_hash,
                message=f"Audit record ID {record.id} content was tampered with (hash mismatch).",
            )

        expected_prev_hash = record.current_hash

    return AuditVerifyResponse(
        is_valid=True,
        total_records=len(records),
        message="Cryptographic audit chain fully verified. 0 broken links detected.",
    )
