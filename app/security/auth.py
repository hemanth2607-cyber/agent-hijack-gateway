"""API-key authentication with salted hashes, constant-time verification, and RBAC.

Enforces least-privilege role boundaries:
- admin: update policies, quarantine and release agents, manage API keys
- analyst: view audit logs, stats, and verification reports
- approver: approve or reject human-in-the-loop tool execution requests
- client: submit chat and scan requests
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from typing import Callable, List, Optional
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import ApiKeyModel, get_db

logger = logging.getLogger("shield.security.auth")

ROLE_HIERARCHY = {
    "admin": {"admin", "analyst", "approver", "client"},
    "approver": {"approver", "client"},
    "analyst": {"analyst", "client"},
    "client": {"client"},
}


def hash_api_key(raw_key: str) -> str:
    """Hashes a raw API key using HMAC-SHA256 with the configured secret salt."""
    salt_bytes = settings.api_keys_salt.encode("utf-8")
    key_bytes = raw_key.encode("utf-8")
    return hmac.new(salt_bytes, key_bytes, hashlib.sha256).hexdigest()


def generate_new_api_key(prefix: str = "ahs") -> str:
    """Generates a high-entropy cryptographically secure raw API key."""
    random_part = secrets.token_urlsafe(32)
    return f"{prefix}_{random_part}"


class AuthenticatedUser:
    """Represents the authenticated caller and their RBAC permissions."""

    def __init__(self, key_id: int, name: str, role: str):
        self.key_id = key_id
        self.name = name
        self.role = role

    def has_role(self, required_role: str) -> bool:
        """Checks if user's role satisfies the required RBAC role."""
        allowed_roles = ROLE_HIERARCHY.get(self.role, set())
        return required_role in allowed_roles


async def create_api_key(
    db: AsyncSession, name: str, role: str
) -> tuple[str, ApiKeyModel]:
    """Generates and persists a new API key as a salted hash.

    Returns:
        tuple[raw_plaintext_key, ApiKeyModel]
    """
    if role not in ROLE_HIERARCHY:
        raise ValueError(f"Invalid RBAC role: {role}")

    raw_key = generate_new_api_key()
    hashed = hash_api_key(raw_key)

    api_key_record = ApiKeyModel(
        key_hash=hashed,
        name=name,
        role=role,
        revoked=False,
    )
    db.add(api_key_record)
    await db.commit()
    await db.refresh(api_key_record)

    return raw_key, api_key_record


async def get_current_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> AuthenticatedUser:
    """FastAPI dependency to authenticate requests via the X-API-Key header."""
    # Check for dev auth bypass (loudly warned at startup)
    if settings.allow_dev_auth_bypass and settings.app_env == "development":
        if not x_api_key:
            return AuthenticatedUser(key_id=0, name="dev_bypass_admin", role="admin")

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication header: X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Compute key hash using HMAC-SHA256
    incoming_hash = hash_api_key(x_api_key)

    # Lookup in database
    result = await db.execute(
        select(ApiKeyModel).where(ApiKeyModel.key_hash == incoming_hash)
    )
    key_record = result.scalar_one_or_none()

    if not key_record or key_record.revoked:
        # Constant-time comparison to prevent timing side channels
        hmac.compare_digest(incoming_hash, "0" * 64)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Constant-time check on stored hash
    if not hmac.compare_digest(incoming_hash, key_record.key_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return AuthenticatedUser(
        key_id=key_record.id,
        name=key_record.name,
        role=key_record.role,
    )


def require_role(required_role: str) -> Callable:
    """Enforces specific RBAC role access on endpoint dependencies."""

    async def role_checker(
        user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        if not user.has_role(required_role):
            logger.warning(
                "Access denied for user '%s' (role: %s) to resource requiring '%s'",
                user.name,
                user.role,
                required_role,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires '{required_role}' privilege. Current role: '{user.role}'",
            )
        return user

    return role_checker
