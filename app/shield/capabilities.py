"""HMAC-SHA256 Capability Tokens for Single-Use Tool Authorization.

Enforces least-privilege capability-based access control:
- Tokens are cryptographically bound to (agent_id, tool_name, args_hash, request_id, exp, nonce)
- Short time-to-live (TTL 60 seconds)
- Strictly single-use with in-memory / cache replay rejection
- Constant-time signature verification preventing timing attacks
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, NamedTuple, Optional, Set, Tuple

from app.config import settings
from app.models import CapabilityTokenClaims


def compute_args_hash(args: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 of tool arguments via canonical JSON."""
    canonical_json = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class CapabilityVerificationResult(NamedTuple):
    """Result of capability token verification and consumption."""

    is_valid: bool
    reason_code: str
    message: str
    claims: Optional[CapabilityTokenClaims] = None


class CapabilityManager:
    """Issues, verifies, and single-use consumes HMAC tool capability tokens."""

    def __init__(self, ttl_seconds: float = 60.0):
        self.ttl_seconds = ttl_seconds
        # In-memory store of consumed nonces to prevent replay attacks
        self._consumed_nonces: Set[str] = set()
        self._nonce_timestamps: Dict[str, float] = {}

    def _get_signing_key(self) -> bytes:
        raw = getattr(settings.secret_key, "get_secret_value", lambda: settings.secret_key)()
        if isinstance(raw, bytes):
            return raw
        return str(raw).encode("utf-8")

    def _cleanup_expired_nonces(self, now: float) -> None:
        """Evicts nonces older than 2x TTL to keep memory bounded."""
        expired_cutoff = now - (self.ttl_seconds * 2.0)
        expired_keys = [
            nonce for nonce, ts in self._nonce_timestamps.items() if ts < expired_cutoff
        ]
        for nonce in expired_keys:
            self._consumed_nonces.discard(nonce)
            self._nonce_timestamps.pop(nonce, None)

    def issue_token(
        self,
        agent_id: str,
        tool_name: str,
        args_hash: str,
        request_id: str,
    ) -> str:
        """Generates a signed, single-use capability token."""
        now = time.time()
        self._cleanup_expired_nonces(now)

        claims = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args_hash": args_hash,
            "request_id": request_id,
            "exp": now + self.ttl_seconds,
            "nonce": secrets.token_hex(16),
        }

        claims_json = json.dumps(claims, sort_keys=True, separators=(",", ":"))
        claims_b64 = base64.urlsafe_b64encode(claims_json.encode("utf-8")).decode("ascii").rstrip("=")

        sig = hmac.new(
            self._get_signing_key(),
            claims_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return f"{claims_b64}.{sig}"

    def verify_and_consume_token(
        self,
        token: str,
        expected_agent_id: str,
        expected_tool_name: str,
        expected_args_hash: str,
        expected_request_id: Optional[str] = None,
    ) -> CapabilityVerificationResult:
        """Verifies HMAC signature, validates binding constraints, and consumes token single-use."""
        now = time.time()
        self._cleanup_expired_nonces(now)

        parts = token.strip().split(".")
        if len(parts) != 2:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="INVALID_TOKEN_FORMAT",
                message="Capability token does not match expected format",
            )

        claims_b64, signature = parts[0], parts[1]

        # 1. Constant-time HMAC signature verification
        expected_sig = hmac.new(
            self._get_signing_key(),
            claims_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="INVALID_TOKEN_SIGNATURE",
                message="Cryptographic signature verification failed",
            )

        # 2. Decode claims
        try:
            padded_b64 = claims_b64 + "=" * (-len(claims_b64) % 4)
            claims_bytes = base64.urlsafe_b64decode(padded_b64)
            claims_dict = json.loads(claims_bytes.decode("utf-8"))
            claims = CapabilityTokenClaims.model_validate(claims_dict)
        except Exception as exc:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="MALFORMED_TOKEN_CLAIMS",
                message=f"Failed to parse claims: {exc}",
            )

        # 3. Expiration Check
        if now > claims.exp:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_TOKEN_EXPIRED",
                message="Capability token has expired",
                claims=claims,
            )

        # 4. Replay Check
        if claims.nonce in self._consumed_nonces:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_REPLAY_DETECTED",
                message="Capability token has already been consumed (replay attack rejected)",
                claims=claims,
            )

        # 5. Strict Claims Binding Verification
        if claims.agent_id != expected_agent_id:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_AGENT_MISMATCH",
                message=f"Token bound to agent '{claims.agent_id}', not '{expected_agent_id}'",
                claims=claims,
            )

        if claims.tool_name != expected_tool_name:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_TOOL_MISMATCH",
                message=f"Token bound to tool '{claims.tool_name}', not '{expected_tool_name}'",
                claims=claims,
            )

        if claims.args_hash != expected_args_hash:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_ARGS_HASH_MISMATCH",
                message="Arguments hash does not match capability token binding",
                claims=claims,
            )

        if expected_request_id and claims.request_id != expected_request_id:
            return CapabilityVerificationResult(
                is_valid=False,
                reason_code="CAPABILITY_REQUEST_MISMATCH",
                message="Request correlation ID does not match capability token binding",
                claims=claims,
            )

        # 6. Single-Use Consumption
        self._consumed_nonces.add(claims.nonce)
        self._nonce_timestamps[claims.nonce] = now

        return CapabilityVerificationResult(
            is_valid=True,
            reason_code="CAPABILITY_VERIFIED_AND_CONSUMED",
            message="Capability token successfully verified and consumed",
            claims=claims,
        )


# Global capability manager instance
capability_manager = CapabilityManager()
