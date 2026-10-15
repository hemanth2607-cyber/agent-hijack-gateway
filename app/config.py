"""Application configuration management via Pydantic Settings.

Enforces fail-closed secure defaults, secret validation, and environment controls.
"""

from __future__ import annotations

import logging
import sys
from typing import List, Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("shield.config")

INSECURE_DEV_SECRET = "change-this-in-production-dev-only-secret-key-32chars"  # nosec B105
INSECURE_DEV_SALT = "gateway-salt-dev-mode-only"  # nosec B105


class Settings(BaseSettings):
    """Production-grade gateway configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application
    app_name: str = Field(default="Agent Hijack Shield", description="Application name")
    app_env: Literal["development", "staging", "production"] = Field(
        default="development", description="Runtime environment"
    )
    debug: bool = Field(default=False, description="Debug mode")
    host: str = Field(default="127.0.0.1", description="Bind host")
    port: int = Field(default=8000, description="Bind port")

    # Security Keys
    secret_key: str = Field(
        default=INSECURE_DEV_SECRET,
        description="Master secret key for token signing (HMAC)",
    )
    api_keys_salt: str = Field(
        default=INSECURE_DEV_SALT,
        description="Salt for hashing stored API keys",
    )
    allow_dev_auth_bypass: bool = Field(
        default=False,
        description="Allow unauthenticated requests in development (strictly forbidden in prod)",
    )
    cors_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:8000", "http://127.0.0.1:8000"],
        description="Allowed CORS origins",
    )

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./shield.db",
        description="Database connection URL",
    )

    # Rate Limiting & Body Limits
    max_input_body_bytes: int = Field(
        default=1_048_576,  # 1MB
        description="Maximum request body size in bytes",
    )
    rate_limit_per_minute_ip: int = Field(
        default=120,
        description="Maximum requests per minute per IP address",
    )
    rate_limit_per_minute_key: int = Field(
        default=300,
        description="Maximum requests per minute per API key",
    )
    request_timeout_seconds: float = Field(
        default=15.0,
        description="Global request timeout in seconds",
    )

    # Shield Detection Thresholds
    shield_default_mode: Literal["enforce", "monitor"] = Field(
        default="enforce",
        description="Global default shield execution mode",
    )
    user_risk_threshold_flag: float = Field(
        default=40.0, description="Risk score threshold to FLAG user input"
    )
    user_risk_threshold_block: float = Field(
        default=75.0, description="Risk score threshold to BLOCK user input"
    )
    external_risk_threshold_flag: float = Field(
        default=30.0, description="Risk score threshold to FLAG external content"
    )
    external_risk_threshold_block: float = Field(
        default=60.0, description="Risk score threshold to BLOCK external content"
    )
    max_scan_time_ms: int = Field(
        default=800,
        description="Maximum time allocated per text scan before fail-closed timeout",
    )

    # Circuit Breaker
    circuit_breaker_window_seconds: int = Field(
        default=300, description="Rolling window for failure tracking"
    )
    circuit_breaker_fail_threshold: int = Field(
        default=3, description="Consecutive/cumulative violations before auto-quarantine"
    )
    circuit_breaker_cooldown_seconds: int = Field(
        default=600, description="Auto-release quarantine duration"
    )

    # Audit Chain
    audit_chain_genesis_hash: str = Field(
        default="0" * 64,
        description="Genesis previous-hash for the immutable audit chain",
    )
    audit_log_tamper_strict: bool = Field(
        default=True,
        description="Strict tamper-evident validation on startup & verification",
    )

    # LLM Settings (Pluggable)
    openai_api_key: str | None = Field(default=None, description="OpenAI API Key")
    llm_provider: Literal["mock", "openai"] = Field(
        default="mock", description="Active LLM provider"
    )
    llm_model: str = Field(default="gpt-4o-mini", description="LLM model name")
    llm_timeout_seconds: float = Field(default=5.0, description="LLM call timeout")

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        """Refuse insecure default secret keys in production/staging environments."""
        # Note: values in info.data might not be fully populated during validation, so check env
        return v

    def validate_production_readiness(self) -> None:
        """Enforces security invariants before gateway startup."""
        if self.app_env in ("production", "staging"):
            if self.secret_key == INSECURE_DEV_SECRET:
                raise ValueError(
                    f"CRITICAL: Refusing to start in {self.app_env} with insecure default SECRET_KEY!"
                )
            if self.api_keys_salt == INSECURE_DEV_SALT:
                raise ValueError(
                    f"CRITICAL: Refusing to start in {self.app_env} with insecure default API_KEYS_SALT!"
                )
            if self.allow_dev_auth_bypass:
                raise ValueError(
                    "CRITICAL: ALLOW_DEV_AUTH_BYPASS cannot be True in production or staging!"
                )
            if "*" in self.cors_origins:
                raise ValueError(
                    "CRITICAL: Wildcard CORS origin is forbidden in production/staging!"
                )
        elif self.app_env == "development":
            if self.secret_key == INSECURE_DEV_SECRET:
                logger.warning(
                    "[SECURITY WARNING] Running with INSECURE DEFAULT SECRET_KEY in development mode! "
                    "Do NOT deploy this configuration to production."
                )
            if self.allow_dev_auth_bypass:
                logger.warning(
                    "[SECURITY WARNING] DEV AUTH BYPASS is enabled! Authentication checks are bypassed."
                )


# Global settings singleton
settings = Settings()
