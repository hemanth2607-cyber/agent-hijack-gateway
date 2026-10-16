"""SQLAlchemy 2.x database models, async engine, and session management.

Schema designed for SQLite with easy migration path to PostgreSQL.
"""

from __future__ import annotations

import datetime
from typing import AsyncGenerator
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


class ApiKeyModel(Base):
    """Hashed API keys with role-based access control (RBAC)."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)  # admin, analyst, approver, client
    created_at = Column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    revoked = Column(Boolean, default=False, nullable=False)


class AuditLogModel(Base):
    """Tamper-evident, forward-secure hash-chained audit log records."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(String(35), nullable=False)
    agent_id = Column(String(100), nullable=False, index=True)
    session_id = Column(String(100), nullable=True, index=True)
    action_type = Column(String(50), nullable=False)
    verdict = Column(String(30), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    reason_codes = Column(Text, nullable=False)  # JSON serialized list of strings
    details_json = Column(Text, nullable=False)  # JSON serialized details (redacted)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False, unique=True, index=True)

    __table_args__ = (
        Index("idx_audit_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_audit_verdict_timestamp", "verdict", "timestamp"),
    )


class ApprovalModel(Base):
    """Human-in-the-loop pending approval records bound to strict argument hashes."""

    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True)  # UUID
    agent_id = Column(String(100), nullable=False, index=True)
    session_id = Column(String(100), nullable=True)
    request_id = Column(String(64), nullable=False)
    tool_name = Column(String(100), nullable=False)
    args_redacted_json = Column(Text, nullable=False)
    args_hash = Column(String(64), nullable=False)  # SHA-256 of canonical args
    reason = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    taint_sources_json = Column(Text, nullable=False)  # JSON list of source IDs
    status = Column(
        String(20), default="PENDING", nullable=False, index=True
    )  # PENDING, APPROVED, REJECTED, EXPIRED, CONSUMED
    approver_id = Column(String(100), nullable=True)
    created_at = Column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    expires_at = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


class QuarantineModel(Base):
    """Per-agent and per-session quarantine circuit-breaker status."""

    __tablename__ = "quarantines"

    target_id = Column(String(100), primary_key=True)  # agent_id or session_id
    target_type = Column(String(20), nullable=False)  # "agent" or "session"
    is_quarantined = Column(Boolean, default=True, nullable=False)
    quarantined_at = Column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    quarantined_until = Column(DateTime, nullable=True)
    reason = Column(Text, nullable=False)
    quarantined_by = Column(String(100), nullable=False)  # "circuit_breaker" or admin username


class PolicyHistoryModel(Base):
    """Versioned audit trail of policy modifications."""

    __tablename__ = "policy_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(100), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    policy_yaml = Column(Text, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False
    )
    updated_by = Column(String(100), nullable=False)


import os
import re
import logging

logger = logging.getLogger("agent_shield.db")


def _get_safe_database_url() -> str:
    """Ensures parent directory for SQLite exists and is writable, falling back safely."""
    url = settings.database_url
    if "sqlite" in url:
        match = re.search(r"sqlite(?:\+[a-z]+)?:///(.*)", url)
        if match:
            raw_path = match.group(1)
            dir_path = os.path.dirname(raw_path)
            if dir_path:
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    test_file = os.path.join(dir_path, ".db_write_test")
                    with open(test_file, "w") as f:
                        f.write("ok")
                    os.remove(test_file)
                except Exception as e:
                    logger.warning(
                        "[DATABASE CONFIG] Directory '%s' not writable (%s). Falling back to './shield.db'.",
                        dir_path,
                        e,
                    )
                    return "sqlite+aiosqlite:///./shield.db"
    return url


# Engine & Session Factory setup
engine = create_async_engine(
    _get_safe_database_url(),
    echo=False,
    future=True,
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection helper yielding an active database session."""
    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database schema tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
