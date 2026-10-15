"""CLI utility to create or display a client-role Judge API key for Tether.

Usage:
    python -m app.create_judge_key
"""

import asyncio
import os
import secrets
import sys
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings
from app.db import ApiKeyModel, Base, engine
from app.security.auth import hash_api_key


async def create_judge_key() -> str:
    # Ensure database tables exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    raw_token = f"sk_judge_{secrets.token_hex(24)}"
    key_hash = hash_api_key(raw_token)

    async with AsyncSession(engine) as session:
        # Check if an existing Judge Client key exists
        res = await session.execute(
            select(ApiKeyModel).where(ApiKeyModel.name == "Public Judge Client")
        )
        existing = res.scalar_one_or_none()
        if existing:
            existing.key_hash = key_hash
            existing.revoked = False
        else:
            new_key = ApiKeyModel(
                name="Public Judge Client",
                role="client",
                key_hash=key_hash,
                revoked=False,
            )
            session.add(new_key)
        await session.commit()

    print("\n" + "=" * 60)
    print("  TETHER / AGENT HIJACK SHIELD - JUDGE KEY GENERATED")
    print("=" * 60)
    print(f"  Judge API Key : {raw_token}")
    print(f"  Role          : client (read-only + chat + demo approver)")
    print(f"  Length        : {len(raw_token)} chars")
    print("=" * 60)
    print("Set this in your environment as:")
    print(f"  export JUDGE_API_KEY={raw_token}\n")
    return raw_token


if __name__ == "__main__":
    asyncio.run(create_judge_key())
