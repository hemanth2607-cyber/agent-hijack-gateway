"""Pydantic v2 schemas for API requests, responses, and internal gateway domain objects.

Enforces strict field boundaries, max lengths, safe serialization, and standard error formats.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


# Standard Error Model
class ErrorResponse(BaseModel):
    """Standardized API error response format across all endpoints."""

    model_config = ConfigDict(extra="forbid")

    error_code: str = Field(description="Machine-readable error identifier")
    message: str = Field(description="Human-readable description of error")
    request_id: str = Field(description="Unique correlation ID for tracing")


# Authentication & RBAC Models
class ApiKeyCreateRequest(BaseModel):
    """Request to generate a new API key."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=2, max_length=100, description="Key identifier/name")
    role: Literal["admin", "analyst", "approver", "client"] = Field(
        ..., description="RBAC role assigned to the key"
    )


class ApiKeyCreatedResponse(BaseModel):
    """Returned once upon key creation. Raw key is never stored or shown again."""

    name: str
    role: str
    api_key: str = Field(description="Raw plaintext API key (display once)")
    message: str = Field(default="Store this API key securely; it cannot be retrieved again.")


class ApiKeyInfo(BaseModel):
    """Metadata view of an existing API key without revealing the secret."""

    id: int
    name: str
    role: str
    created_at: datetime.datetime
    revoked: bool


# Provenance & Document Schemas
class DocumentInput(BaseModel):
    """External document input representing untrusted data (PDF, web page, email, RAG chunk)."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., max_length=256, description="Source URL, filename, or source ID")
    content: str = Field(..., max_length=1_000_000, description="Raw content of the document")
    type: Literal["web", "pdf", "email", "rag", "file", "memory", "tool_output"] = Field(
        default="file", description="Source content medium"
    )
    trust_level: Optional[Literal["USER", "EXTERNAL", "SYSTEM"]] = Field(
        default=None, description="Optional caller-supplied trust level (gateway forces untrusted media to EXTERNAL)"
    )


# Finding & Detection Models
class Finding(BaseModel):
    """Detailed record of a matched detection rule or heuristic violation."""

    rule_id: str = Field(..., description="Unique rule or heuristic identifier")
    category: str = Field(..., description="Threat category (e.g., direct_override, exfiltration)")
    owasp_ref: str = Field(..., description="Associated OWASP LLM Top 10 vulnerability reference")
    snippet: str = Field(..., description="Truncated and redacted snippet that triggered the rule")
    weight: float = Field(..., ge=0.0, le=100.0, description="Risk weight contribution")
    location: Optional[str] = Field(default=None, description="Location in text or argument")


class ScanRequest(BaseModel):
    """Standalone input scan request."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=500_000, description="Text to analyze")
    trust_level: Literal["USER", "EXTERNAL", "SYSTEM"] = Field(
        default="EXTERNAL", description="Trust level assigned to this payload"
    )
    source_id: Optional[str] = Field(default=None, max_length=256, description="Source provenance ID")


class ScanResponse(BaseModel):
    """Detailed risk assessment and findings report from the detector."""

    risk_score: float = Field(..., ge=0.0, le=100.0, description="Composite risk score 0-100")
    verdict: Literal["ALLOW", "FLAG", "BLOCK"] = Field(
        ..., description="Final gating verdict"
    )
    findings: List[Finding] = Field(default_factory=list, description="Specific matched signals")
    reason_codes: List[str] = Field(default_factory=list, description="Machine-readable decision codes")
    explanation: str = Field(..., description="Human-readable explanation of risk verdict")
    normalization_signals: List[str] = Field(
        default_factory=list, description="Obfuscation tactics detected during normalization"
    )
    normalized_length: int = Field(..., description="Length of text after canonicalization")
    scan_time_ms: float = Field(..., description="Time taken to scan in milliseconds")


# Tool Execution & Capability Schemas
class ToolCallDecision(BaseModel):
    """Policy decision regarding a proposed agent tool invocation."""

    tool_name: str
    args: Dict[str, Any]
    verdict: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    reason_codes: List[str]
    capability_token: Optional[str] = None  # Populated only if ALLOW
    approval_id: Optional[str] = None  # Populated only if REQUIRE_APPROVAL


class CapabilityTokenClaims(BaseModel):
    """Claims encoded within an HMAC-signed single-use tool capability token."""

    agent_id: str
    tool_name: str
    args_hash: str
    request_id: str
    exp: float
    nonce: str


# Chat Endpoints
class ChatRequest(BaseModel):
    """Core chat request to mediate agent execution."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(default="demo_agent", min_length=1, max_length=100)
    session_id: Optional[str] = Field(default=None, max_length=100)
    message: str = Field(..., min_length=1, max_length=100_000)
    documents: List[DocumentInput] = Field(default_factory=list)
    shield_enabled: bool = Field(default=True, description="Toggle shield on/off for comparative demos")


class ChatResponse(BaseModel):
    """Response returned after running through the secure gateway pipeline."""

    response: str = Field(..., description="Agent response or safe refusal message")
    verdict: Literal["ALLOW", "FLAG", "BLOCK"]
    risk_score: float
    findings: List[Finding] = Field(default_factory=list)
    tool_calls: List[ToolCallDecision] = Field(default_factory=list)
    pending_approvals: List[str] = Field(default_factory=list)
    request_id: str
    shield_enabled: bool
    latency_ms: float


# Human-In-The-Loop Approvals
class ApprovalItem(BaseModel):
    """Pending or resolved approval record."""

    id: str
    agent_id: str
    session_id: Optional[str]
    request_id: str
    tool_name: str
    args_redacted: Dict[str, Any]
    args_hash: str
    reason: str
    risk_score: float
    taint_sources: List[str]
    status: Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"]
    created_at: datetime.datetime
    expires_at: datetime.datetime


class ApprovalActionResponse(BaseModel):
    """Result of an approval or rejection operation."""

    approval_id: str
    status: Literal["APPROVED", "REJECTED"]
    capability_token: Optional[str] = None
    message: str


# Audit Verification
class AuditVerifyResponse(BaseModel):
    """Cryptographic audit chain verification result."""

    is_valid: bool
    total_records: int
    first_broken_link_id: Optional[int] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    message: str


# Quarantine Models
class QuarantineRequest(BaseModel):
    """Emergency quarantine or release action."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=3, max_length=500)


class QuarantineStatusResponse(BaseModel):
    """Quarantine status of an agent or session."""

    target_id: str
    target_type: str
    is_quarantined: bool
    quarantined_at: Optional[datetime.datetime] = None
    reason: Optional[str] = None
    quarantined_by: Optional[str] = None
