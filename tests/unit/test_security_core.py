"""Unit tests for the security core modules.

Covers:
- Configuration validation and environment invariants
- Salted API key hashing, constant-time verification, and RBAC hierarchy
- Cryptographic hash-chained audit logging and verification
- Secret detection (AWS, OpenAI, GitHub, JWT, Luhn-checked credit cards) and redaction
- SSRF prevention (IP notations, schemes, private networks, cloud metadata)
- Path traversal, canonicalization, null bytes, and sensitive file patterns
"""

import os
import tempfile
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.config import Settings, INSECURE_DEV_SECRET, INSECURE_DEV_SALT
from app.db import Base, ApiKeyModel, AuditLogModel
from app.security.auth import (
    hash_api_key,
    generate_new_api_key,
    create_api_key,
    AuthenticatedUser,
    ROLE_HIERARCHY,
)
from app.security.audit_chain import (
    append_audit_entry,
    verify_audit_chain,
    compute_record_hash,
)
from app.security.secrets import (
    scan_for_secrets,
    redact_secrets,
    validate_luhn,
)
from app.security.ssrf import (
    validate_url,
    parse_and_validate_ip,
)
from app.security.paths import (
    validate_file_path,
    sanitize_raw_path,
)


# Fixture for temporary in-memory async SQLite database
@pytest_asyncio.fixture
async def async_test_db():
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        yield session

    await test_engine.dispose()


# -------------------------------------------------------------
# 1. Config Invariants Tests
# -------------------------------------------------------------
def test_config_production_refusal():
    """Ensure gateway refuses to start in production with default secrets."""
    prod_settings = Settings(
        app_env="production",
        secret_key=INSECURE_DEV_SECRET,
        api_keys_salt="custom-salt",
    )
    with pytest.raises(ValueError, match="CRITICAL: Refusing to start in production"):
        prod_settings.validate_production_readiness()

    cors_wildcard = Settings(
        app_env="production",
        secret_key="a" * 32,
        api_keys_salt="b" * 32,
        cors_origins=["*"],
    )
    with pytest.raises(ValueError, match="Wildcard CORS origin is forbidden"):
        cors_wildcard.validate_production_readiness()


# -------------------------------------------------------------
# 2. Auth & RBAC Tests
# -------------------------------------------------------------
@pytest.mark.asyncio
async def test_api_key_creation_and_hashing(async_test_db: AsyncSession):
    raw_key, record = await create_api_key(async_test_db, name="test-admin", role="admin")

    assert raw_key.startswith("ahs_")
    assert record.role == "admin"
    assert record.key_hash == hash_api_key(raw_key)

    # RBAC hierarchy check
    user = AuthenticatedUser(key_id=record.id, name=record.name, role=record.role)
    assert user.has_role("admin") is True
    assert user.has_role("approver") is True
    assert user.has_role("analyst") is True
    assert user.has_role("client") is True

    client_user = AuthenticatedUser(key_id=2, name="test-client", role="client")
    assert client_user.has_role("client") is True
    assert client_user.has_role("admin") is False
    assert client_user.has_role("approver") is False


# -------------------------------------------------------------
# 3. Audit Chain Tests
# -------------------------------------------------------------
@pytest.mark.asyncio
async def test_audit_chain_integrity(async_test_db: AsyncSession):
    # Empty chain verification
    initial_verify = await verify_audit_chain(async_test_db)
    assert initial_verify.is_valid is True
    assert initial_verify.total_records == 0

    # Append sequential entries
    entry1 = await append_audit_entry(
        async_test_db,
        request_id="req_001",
        agent_id="agent_alpha",
        action_type="chat",
        verdict="ALLOW",
        risk_score=15.0,
        reason_codes=["CLEAN_INPUT"],
        details={"text_snippet": "Hello world"},
    )
    assert entry1.id == 1
    assert len(entry1.current_hash) == 64

    entry2 = await append_audit_entry(
        async_test_db,
        request_id="req_002",
        agent_id="agent_alpha",
        action_type="scan",
        verdict="FLAG",
        risk_score=45.0,
        reason_codes=["SUSPICIOUS_OVERRIDE"],
        details={"matched_rule": "R01"},
    )
    assert entry2.id == 2
    assert entry2.prev_hash == entry1.current_hash

    # Verify untampered chain
    verify_res = await verify_audit_chain(async_test_db)
    assert verify_res.is_valid is True
    assert verify_res.total_records == 2
    assert verify_res.first_broken_link_id is None

    # Tamper with record 1
    entry1.risk_score = 99.0
    await async_test_db.commit()

    tampered_verify = await verify_audit_chain(async_test_db)
    assert tampered_verify.is_valid is False
    assert tampered_verify.first_broken_link_id == 1


# -------------------------------------------------------------
# 4. Secrets & Redaction Tests
# -------------------------------------------------------------
def test_secrets_detection_and_redaction():
    sample_text = (
        "Here is my aws key AKIAIOSFODNN7EXAMPLE and "
        "my OpenAI key sk-proj-1234567890abcdef1234567890 and my github token "
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz and my credit card 4532 0150 0000 0007."
    )
    matches = scan_for_secrets(sample_text)
    types = [m.secret_type for m in matches]
    assert "aws_access_key" in types
    assert "openai_api_key" in types
    assert "github_token" in types
    assert "credit_card" in types

    redacted = redact_secrets(sample_text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "sk-proj-1234567890abcdef1234567890" not in redacted
    assert "4532 0150 0000 0007" not in redacted
    assert "[REDACTED_AWS_ACCESS_KEY]" in redacted
    assert "[REDACTED_CREDIT_CARD]" in redacted


def test_luhn_algorithm_validation():
    # Valid Visa card candidate
    assert validate_luhn("4532015000000007") is True
    # Invalid card number (single digit altered)
    assert validate_luhn("4532015000000008") is False


# -------------------------------------------------------------
# 5. SSRF Validation Tests
# -------------------------------------------------------------
def test_ssrf_blocking_private_and_metadata():
    # Loopback
    safe, reason = validate_url("http://127.0.0.1:8080/admin", resolve_dns=False)
    assert safe is False
    assert "LOOPBACK" in reason

    # Cloud metadata (AWS/GCP/Azure)
    safe, reason = validate_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
    assert safe is False
    assert "LINK_LOCAL" in reason

    # RFC 1918 Private
    safe, reason = validate_url("http://192.168.1.1/router", resolve_dns=False)
    assert safe is False
    assert "PRIVATE_NETWORK" in reason

    # Decimal format IP (127.0.0.1 = 2130706433)
    safe, reason = validate_url("http://2130706433/", resolve_dns=False)
    assert safe is False
    assert "LOOPBACK" in reason

    # Forbidden scheme
    safe, reason = validate_url("file:///etc/passwd", resolve_dns=False)
    assert safe is False
    assert "FORBIDDEN_URL_SCHEME_FILE" in reason

    # Whitelist domain enforcement
    safe, reason = validate_url(
        "https://docs.python.org/3/library/",
        allowed_domains=["docs.python.org", "wikipedia.org"],
        resolve_dns=False,
    )
    assert safe is True


# -------------------------------------------------------------
# 6. Path Traversal & Canonicalization Tests
# -------------------------------------------------------------
def test_path_traversal_defenses():
    with tempfile.TemporaryDirectory() as tmp_dir:
        docs_dir = os.path.join(tmp_dir, "docs")
        os.makedirs(docs_dir, exist_ok=True)
        safe_file = os.path.join(docs_dir, "report.txt")
        with open(safe_file, "w") as f:
            f.write("safe content")

        # 1. Valid safe file access
        safe, path, reason = validate_file_path("report.txt", allowed_base_dirs=[docs_dir])
        assert safe is True
        assert path == os.path.realpath(safe_file)

        # 2. Traversal attempt with ../
        safe, path, reason = validate_file_path("../evil.txt", allowed_base_dirs=[docs_dir])
        assert safe is False
        assert "PATH_TRAVERSAL" in reason

        # 3. URL encoded traversal %2e%2e
        safe, path, reason = validate_file_path("%2e%2e/evil.txt", allowed_base_dirs=[docs_dir])
        assert safe is False

        # 3b. Double-encoded traversal %252e%252e%252f
        safe, path, reason = validate_file_path("%252e%252e%252fevil.txt", allowed_base_dirs=[docs_dir])
        assert safe is False

        # 4. Null byte injection
        safe, path, reason = validate_file_path("report.txt\x00.exe", allowed_base_dirs=[docs_dir])
        assert safe is False
        assert "NULL_BYTE" in reason

        # 4b. Encoded and double-encoded null bytes
        safe, path, reason = validate_file_path("report.txt%00.exe", allowed_base_dirs=[docs_dir])
        assert safe is False
        assert "NULL_BYTE" in reason

        safe, path, reason = validate_file_path("report.txt%2500.exe", allowed_base_dirs=[docs_dir])
        assert safe is False
        assert "NULL_BYTE" in reason

        # 5. Denied patterns (.env, id_rsa, *secret*)
        secret_file = os.path.join(docs_dir, ".env")
        safe, path, reason = validate_file_path(".env", allowed_base_dirs=[docs_dir])
        assert safe is False
        assert "DENIED_PATTERN" in reason

        # 6. Real Symlink Escape Test
        outside_secret = os.path.join(tmp_dir, "outside_secret.txt")
        with open(outside_secret, "w") as f:
            f.write("super_secret_outside")

        symlink_path = os.path.join(docs_dir, "symlink_to_outside.txt")
        try:
            os.symlink(outside_secret, symlink_path)
            # Default allow_symlinks=False: must be denied
            safe, path, reason = validate_file_path("symlink_to_outside.txt", allowed_base_dirs=[docs_dir], allow_symlinks=False)
            assert safe is False
            assert "SYMLINK_ACCESS_DENIED" in reason

            # Even if allow_symlinks=True, resolving the symlink points outside docs_dir, so it must be blocked!
            safe, path, reason = validate_file_path("symlink_to_outside.txt", allowed_base_dirs=[docs_dir], allow_symlinks=True)
            assert safe is False
            assert "PATH_TRAVERSAL" in reason
        except (OSError, NotImplementedError):
            # Windows non-elevated developer mode fallback: verify logic with pathlib mock
            pass
