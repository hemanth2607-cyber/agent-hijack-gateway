"""Circuit breaker and automated quarantine management.

Provides automated and administrative containment:
- Triggers automatic quarantine on canary exfiltration or repeated security blocks (N threshold)
- Refuses execution and all tool invocations for quarantined agents or sessions
- Admin-only release authorization
- Full database audit tracking via QuarantineModel
"""

from __future__ import annotations

import datetime
from typing import Dict, NamedTuple, Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import QuarantineModel


class CircuitBreakerStatus(NamedTuple):
    """Quarantine status inspection result."""

    is_quarantined: bool
    reason: Optional[str] = None
    quarantined_by: Optional[str] = None
    quarantined_at: Optional[datetime.datetime] = None


class CircuitBreaker:
    """Monitors violation thresholds and controls quarantine state."""

    def __init__(self, session_block_threshold: int = 3, agent_block_threshold: int = 5):
        self.session_block_threshold = session_block_threshold
        self.agent_block_threshold = agent_block_threshold
        # In-memory violation counters: target_id -> count
        self._block_counts: Dict[str, int] = {}

    def record_violation(self, target_id: str) -> int:
        """Increments and returns the consecutive violation count for an agent or session."""
        self._block_counts[target_id] = self._block_counts.get(target_id, 0) + 1
        return self._block_counts[target_id]

    def reset_violations(self, target_id: str) -> None:
        """Clears violation counters upon clean session completion."""
        self._block_counts.pop(target_id, None)

    async def is_quarantined(
        self,
        db: AsyncSession,
        target_id: str,
    ) -> CircuitBreakerStatus:
        """Checks if a target (agent_id or session_id) is currently quarantined."""
        stmt = select(QuarantineModel).where(
            QuarantineModel.target_id == target_id,
            QuarantineModel.is_quarantined == True,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()

        if not record:
            return CircuitBreakerStatus(is_quarantined=False)

        # Check if temporary quarantine has expired
        if record.quarantined_until is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
            quarantine_end = record.quarantined_until
            if quarantine_end.tzinfo is None:
                quarantine_end = quarantine_end.replace(tzinfo=datetime.timezone.utc)
            if now > quarantine_end:
                record.is_quarantined = False
                await db.commit()
                return CircuitBreakerStatus(is_quarantined=False)

        return CircuitBreakerStatus(
            is_quarantined=True,
            reason=record.reason,
            quarantined_by=record.quarantined_by,
            quarantined_at=record.quarantined_at,
        )

    async def quarantine_target(
        self,
        db: AsyncSession,
        target_id: str,
        target_type: str,  # "agent" or "session"
        reason: str,
        quarantined_by: str = "circuit_breaker",
        duration_minutes: Optional[int] = None,
    ) -> QuarantineModel:
        """Places an agent or session under quarantine."""
        now = datetime.datetime.now(datetime.timezone.utc)
        quarantine_until = None
        if duration_minutes:
            quarantine_until = now + datetime.timedelta(minutes=duration_minutes)

        stmt = select(QuarantineModel).where(QuarantineModel.target_id == target_id)
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()

        if record:
            record.is_quarantined = True
            record.reason = reason
            record.quarantined_by = quarantined_by
            record.quarantined_at = now
            record.quarantined_until = quarantine_until
        else:
            record = QuarantineModel(
                target_id=target_id,
                target_type=target_type,
                is_quarantined=True,
                quarantined_at=now,
                quarantined_until=quarantine_until,
                reason=reason,
                quarantined_by=quarantined_by,
            )
            db.add(record)

        await db.commit()
        await db.refresh(record)
        return record

    async def release_quarantine(
        self,
        db: AsyncSession,
        target_id: str,
        released_by: str,
        user_role: str,
    ) -> bool:
        """Lifts quarantine status. Requires admin role."""
        if user_role != "admin":
            raise PermissionError("Only administrators can release agents or sessions from quarantine")

        stmt = select(QuarantineModel).where(QuarantineModel.target_id == target_id)
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()

        if not record or not record.is_quarantined:
            return False

        record.is_quarantined = False
        record.reason = f"Released by admin '{released_by}'"
        self.reset_violations(target_id)

        await db.commit()
        return True


# Global circuit breaker instance
circuit_breaker = CircuitBreaker()
