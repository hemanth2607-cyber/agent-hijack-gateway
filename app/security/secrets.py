"""Secret and PII detection patterns and redaction helpers.

Detects and redacts credentials, private keys, tokens, and PII using
linear-safe regex patterns and checksum validators (e.g. Luhn algorithm).
"""

from __future__ import annotations

import re
from typing import List, NamedTuple


class SecretMatch(NamedTuple):
    secret_type: str
    snippet: str
    start: int
    end: int


# Linear-safe regex patterns for high-risk credentials
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "openai_api_key": re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
    "github_token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "slack_token": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,})\b"),
    "ssn": re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "credit_card_candidate": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
}


def validate_luhn(card_number_str: str) -> bool:
    """Validates credit card numbers using the standard Luhn algorithm (mod 10)."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Luhn check
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def scan_for_secrets(text: str) -> List[SecretMatch]:
    """Scans text for credentials, tokens, private keys, and validated credit cards."""
    matches: List[SecretMatch] = []
    if not text:
        return matches

    for secret_type, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            matched_str = m.group(0)
            if secret_type == "credit_card_candidate":  # nosec B105
                if validate_luhn(matched_str):
                    matches.append(
                        SecretMatch(
                            secret_type="credit_card",  # nosec B106
                            snippet=f"{matched_str[:4]}...{matched_str[-4:]}",
                            start=m.start(),
                            end=m.end(),
                        )
                    )
            else:
                redacted_snippet = (
                    f"{matched_str[:4]}...{matched_str[-3:]}"
                    if len(matched_str) > 8
                    else "[REDACTED]"
                )
                matches.append(
                    SecretMatch(
                        secret_type=secret_type,
                        snippet=redacted_snippet,
                        start=m.start(),
                        end=m.end(),
                    )
                )

    return matches


def redact_secrets(text: str) -> str:
    """Redacts all detected sensitive credentials from text."""
    if not text:
        return ""

    result = text
    # 1. Redact validated credit cards
    def replace_cc(m: re.Match) -> str:
        s = m.group(0)
        return "[REDACTED_CREDIT_CARD]" if validate_luhn(s) else s

    result = SECRET_PATTERNS["credit_card_candidate"].sub(replace_cc, result)

    # 2. Redact other credential patterns
    for name, pattern in SECRET_PATTERNS.items():
        if name == "credit_card_candidate":
            continue
        placeholder = f"[REDACTED_{name.upper()}]"
        result = pattern.sub(placeholder, result)

    return result


def scan_and_redact_secrets(text: str) -> Tuple[bool, List[str], str]:
    """Scans and redacts credentials in one step. Returns (has_secrets, finding_types, redacted_text)."""
    matches = scan_for_secrets(text)
    redacted = redact_secrets(text)
    has_secrets = len(matches) > 0
    findings = [m.secret_type for m in matches]
    return has_secrets, findings, redacted
