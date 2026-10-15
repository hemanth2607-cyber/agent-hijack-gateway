"""Multi-turn session risk tracking, crescendo attack detection, and taint escalation.

Tracks conversational history per session to detect:
- Crescendo attacks (gradual probing and slow role drift across multiple turns)
- Repeated refusals followed by reworded injection attempts
- Memory poisoning (untrusted external payloads attempting to write instructions into long-term memory)
- Automatic taint escalation when cumulative session risk crosses thresholds
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

# Patterns indicative of memory poisoning attacks
MEMORY_POISONING_PATTERNS = [
    re.compile(r"(?i)\bremember\s+(?:this\s+)?(?:for\s+all\s+future|in\s+future\s+conversations|forever)\b"),
    re.compile(r"(?i)\bsave\s+this\s+as\s+a\s+permanent\s+rule\b"),
    re.compile(r"(?i)\bstore\s+in\s+your\s+memory\s+that\s+you\s+must\b"),
    re.compile(r"(?i)\bupdate\s+your\s+core\s+beliefs\s+to\b"),
    re.compile(r"(?i)\bfrom\s+now\s+on\s+in\s+every\s+chat\b"),
]

# Taint thresholds
SESSION_TAINT_THRESHOLD = 65.0
SESSION_MAX_TURNS_HISTORY = 20
DECAY_FACTOR_PER_TURN = 0.85  # Exponential moving risk decay


class TurnRecord(BaseModel):
    timestamp: float
    turn_risk: float
    verdict: str
    reasons: List[str]


class SessionState(BaseModel):
    session_id: str
    turns: List[TurnRecord] = Field(default_factory=list)
    rolling_risk: float = 0.0
    is_tainted: bool = False
    refusal_count: int = 0
    crescendo_detected: bool = False
    memory_poisoning_detected: bool = False
    last_updated: float = Field(default_factory=time.monotonic)


class SessionRiskTracker:
    """In-memory rolling session risk state manager with automatic escalation."""

    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

    def get_session(self, session_id: str) -> SessionState:
        """Retrieves or creates state for a session ID."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def record_turn(
        self,
        session_id: str,
        turn_risk: float,
        verdict: str,
        reason_codes: List[str],
        text_payload: str,
        taint_source: Optional[str] = None,
    ) -> SessionState:
        """Updates rolling session risk after an inbound or outbound turn."""
        session = self.get_session(session_id)
        now = time.monotonic()
        if taint_source:
            session.is_tainted = True

        # 1. Check for Memory Poisoning Patterns in text
        is_mem_poison = any(p.search(text_payload) for p in MEMORY_POISONING_PATTERNS)
        if is_mem_poison:
            session.memory_poisoning_detected = True
            turn_risk = max(turn_risk, 85.0)
            reason_codes.append("DETECTED_MEMORY_POISONING_ATTEMPT")

        # 2. Check for Refusal Escalation (Crescendo indicator)
        if verdict == "BLOCK":
            session.refusal_count += 1
        elif verdict == "ALLOW" and session.refusal_count > 0:
            # User previously blocked, now probing with slightly altered syntax
            turn_risk += min(25.0, session.refusal_count * 10.0)
            reason_codes.append("REPEATED_PROBING_AFTER_REFUSAL")

        # 3. Calculate Rolling Risk with Exponential Moving Weight
        if not session.turns:
            session.rolling_risk = turn_risk
        else:
            session.rolling_risk = (session.rolling_risk * DECAY_FACTOR_PER_TURN) + (turn_risk * (1 - DECAY_FACTOR_PER_TURN))

        # 4. Detect Crescendo (Monotonically rising risk across last 3 turns)
        if len(session.turns) >= 2:
            last_risks = [t.turn_risk for t in session.turns[-2:]] + [turn_risk]
            if last_risks[0] < last_risks[1] < last_risks[2] and (last_risks[2] - last_risks[0]) >= 20.0:
                session.crescendo_detected = True
                session.rolling_risk = min(100.0, session.rolling_risk + 20.0)
                reason_codes.append("DETECTED_CRESCENDO_ATTACK_DRIFT")

        # 5. Taint Escalation
        if session.rolling_risk >= SESSION_TAINT_THRESHOLD or session.memory_poisoning_detected:
            session.is_tainted = True
            reason_codes.append("SESSION_TAINT_ESCALATED")

        # Record turn
        turn = TurnRecord(
            timestamp=now,
            turn_risk=round(turn_risk, 1),
            verdict=verdict,
            reasons=reason_codes,
        )
        session.turns.append(turn)
        if len(session.turns) > SESSION_MAX_TURNS_HISTORY:
            session.turns.pop(0)

        session.last_updated = now
        session.rolling_risk = round(session.rolling_risk, 1)
        return session

    def is_tainted(self, session_id: Optional[str]) -> bool:
        """Returns True if the session has exceeded taint thresholds."""
        if not session_id or session_id not in self._sessions:
            return False
        return self._sessions[session_id].is_tainted

    def reset_session(self, session_id: str) -> None:
        """Resets session risk state."""
        if session_id in self._sessions:
            del self._sessions[session_id]


session_tracker = SessionRiskTracker()
session_risk_tracker = session_tracker
