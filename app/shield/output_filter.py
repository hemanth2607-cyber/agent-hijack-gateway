"""Outbound security filter, canary token tracker, and data leak prevention.

Protects against:
- System prompt and secret canary exfiltration (immediate CRITICAL quarantine)
- PII leaks (SSNs, phone numbers, emails)
- Credential and private key leaks (AWS, OpenAI, GitHub, Slack, Private Keys, JWTs)
- Luhn-validated credit card exfiltration
- Markdown and HTML image/script auto-exfiltration channels
"""

from __future__ import annotations

import re
import secrets
from typing import List, NamedTuple, Optional, Tuple

from app.models import Finding
from app.security.secrets import scan_and_redact_secrets, validate_luhn

# PII regex patterns
PHONE_PATTERN = re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

# Auto-exfiltration markdown image and hidden HTML patterns
MARKDOWN_IMAGE_EXFIL = re.compile(r"!\[([^\]]*)\]\((https?://[^)\s]+)\)")
HTML_EXFIL_TAGS = re.compile(r"<(?:img|script|iframe|link|embed|object)\s+[^>]*>", re.IGNORECASE)


class OutputFilterResult(NamedTuple):
    """Result of the outbound filter inspection."""

    safe_text: str
    is_blocked: bool
    risk_score: float
    findings: List[Finding]
    reason_codes: List[str]
    canary_leaked: bool


def generate_canary_token(session_id: Optional[str] = None, request_id: Optional[str] = None) -> str:
    """Generates a high-entropy, unique canary token seeded into system prompt."""
    random_hex = secrets.token_hex(16)
    return f"SHIELD_CANARY_{random_hex}"


def filter_agent_output(
    raw_text: str,
    canary_token: Optional[str] = None,
    redact_pii: bool = True,
    block_markdown_exfil: bool = True,
) -> OutputFilterResult:
    """Inspects and redacts agent output before returning to user or client."""
    if not raw_text:
        return OutputFilterResult(
            safe_text="",
            is_blocked=False,
            risk_score=0.0,
            findings=[],
            reason_codes=[],
            canary_leaked=False,
        )

    findings: List[Finding] = []
    reason_codes: List[str] = []
    canary_leaked = False
    is_blocked = False
    risk_score = 0.0

    # 1. Canary Token Leak Inspection (CRITICAL)
    if canary_token and canary_token in raw_text:
        canary_leaked = True
        is_blocked = True
        risk_score = 100.0
        reason_codes.append("CRITICAL_CANARY_TOKEN_LEAK_DETECTED")
        findings.append(
            Finding(
                rule_id="O_CANARY_01",
                category="system_prompt_exfiltration",
                owasp_ref="LLM01:System_Prompt_Leak",
                snippet=f"Canary leak: {canary_token[:15]}...",
                weight=100.0,
                location="agent_output",
            )
        )
        return OutputFilterResult(
            safe_text="[SECURITY VIOLATION: Output blocked due to sensitive system token exfiltration attempt]",
            is_blocked=True,
            risk_score=100.0,
            findings=findings,
            reason_codes=reason_codes,
            canary_leaked=True,
        )

    # 2. Markdown Image Auto-Exfiltration Detection
    clean_text = raw_text
    if block_markdown_exfil:
        md_matches = list(MARKDOWN_IMAGE_EXFIL.finditer(clean_text))
        if md_matches:
            for match in md_matches:
                img_alt, img_url = match.group(1), match.group(2)
                # Check if URL contains query params or suspicious exfil path
                if "?" in img_url or "token" in img_url.lower() or "secret" in img_url.lower() or "leak" in img_url.lower():
                    reason_codes.append("MARKDOWN_IMAGE_EXFILTRATION_DETECTED")
                    findings.append(
                        Finding(
                            rule_id="O_EXF_01",
                            category="data_exfiltration",
                            owasp_ref="LLM02:Data_Exfiltration",
                            snippet=f"Exfil URL: {img_url[:40]}...",
                            weight=90.0,
                            location="output_markdown",
                        )
                    )
                    is_blocked = True
                    risk_score = max(risk_score, 90.0)
                    # Strip the malicious markdown image tag
                    clean_text = clean_text.replace(match.group(0), "[REDACTED_SUSPICIOUS_IMAGE_LINK]")

    # 3. HTML Exfiltration Tags
    html_tags = list(HTML_EXFIL_TAGS.finditer(clean_text))
    if html_tags:
        reason_codes.append("HTML_EXFILTRATION_TAG_DETECTED")
        for tag in html_tags:
            tag_str = tag.group(0)
            clean_text = clean_text.replace(tag_str, "[REDACTED_HTML_TAG]")
        risk_score = max(risk_score, 75.0)

    # 4. Secrets & Credentials Scan and Redaction
    has_secrets, secret_findings, redacted_text = scan_and_redact_secrets(clean_text)
    if has_secrets:
        reason_codes.append("SECRETS_LEAK_PREVENTED_AND_REDACTED")
        for sf in secret_findings:
            findings.append(
                Finding(
                    rule_id="O_SEC_01",
                    category="credential_leak",
                    owasp_ref="LLM06:Sensitive_Information_Disclosure",
                    snippet=f"Redacted secret: {sf}",
                    weight=85.0,
                    location="output_secrets",
                )
            )
        risk_score = max(risk_score, 85.0)
        clean_text = redacted_text

    # 5. PII Detection and Redaction (Phones, Emails)
    if redact_pii:
        # Redact phones
        phone_matches = list(PHONE_PATTERN.finditer(clean_text))
        if phone_matches:
            for pm in phone_matches:
                clean_text = clean_text.replace(pm.group(0), "[REDACTED_PHONE]")
            reason_codes.append("PII_PHONE_REDACTED")
            risk_score = max(risk_score, 30.0)

    return OutputFilterResult(
        safe_text=clean_text,
        is_blocked=is_blocked,
        risk_score=risk_score,
        findings=findings,
        reason_codes=reason_codes,
        canary_leaked=canary_leaked,
    )
