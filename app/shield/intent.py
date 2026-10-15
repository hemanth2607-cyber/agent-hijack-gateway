"""Rule-based intent alignment engine.

Verifies that proposed agent tool calls and their target arguments align with
the user's original explicit instructions, preventing indirect prompt injection
from inducing unprompted side effects or data exfiltration.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, NamedTuple, Optional, Set


class IntentAlignmentResult(NamedTuple):
    """Result of intent alignment check between user prompt and proposed tool call."""

    is_aligned: bool
    risk_contribution: float
    reasons: List[str]
    explanation: str


# Intent categorizers
READ_ONLY_TRIGGERS: Set[str] = {
    "summarize", "summary", "read", "explain", "explanation", "translate",
    "translation", "search", "find", "analyze", "analysis", "what is",
    "how to", "tell me about", "describe", "show me", "check", "inspect",
}

MATH_TRIGGERS: Set[str] = {
    "calculate", "computation", "compute", "math", "add", "subtract",
    "multiply", "divide", "sum", "average", "convert",
}

COMMUNICATION_TRIGGERS: Set[str] = {
    "email", "send email", "message", "notify", "contact", "mail",
    "forward", "reach out", "send to", "alert",
}

FINANCIAL_TRIGGERS: Set[str] = {
    "pay", "transfer", "wire", "send money", "buy", "purchase",
    "payment", "invoice", "refund", "remit",
}

SYSTEM_EXEC_TRIGGERS: Set[str] = {
    "run", "execute", "shell", "bash", "command", "deploy", "delete",
    "drop table", "remove file",
}


def extract_user_intent_types(user_message: str) -> Set[str]:
    """Identifies expected action types from user message using keyword analysis."""
    msg_lower = user_message.lower()
    intents: Set[str] = set()

    if any(trigger in msg_lower for trigger in READ_ONLY_TRIGGERS):
        intents.add("READ_ONLY")

    if any(trigger in msg_lower for trigger in MATH_TRIGGERS):
        intents.add("MATH")

    if any(trigger in msg_lower for trigger in COMMUNICATION_TRIGGERS):
        intents.add("COMMUNICATION")

    if any(trigger in msg_lower for trigger in FINANCIAL_TRIGGERS):
        intents.add("FINANCIAL")

    if any(trigger in msg_lower for trigger in SYSTEM_EXEC_TRIGGERS):
        intents.add("SYSTEM_EXEC")

    # If no triggers match, default to benign read/general
    if not intents:
        intents.add("GENERAL_QUERY")

    return intents


def check_intent_alignment(
    user_message: str,
    tool_name: str,
    args: Dict[str, Any],
) -> IntentAlignmentResult:
    """Evaluates whether the proposed tool call aligns with user intent.

    Flags:
    - Side-effect tools (send_email, transfer_funds, bash, delete) when user asked read-only query
    - Unmentioned email recipients or payment destinations not present in user query
    - Exfiltration endpoints not requested by user
    """
    intents = extract_user_intent_types(user_message)
    msg_lower = user_message.lower()
    reasons: List[str] = []
    risk_boost = 0.0

    # 1. Disallow persistent side-effect actions when request is strictly Read-Only or Math
    is_strictly_read = "READ_ONLY" in intents or "MATH" in intents
    has_explicit_action = bool(intents.intersection({"COMMUNICATION", "FINANCIAL", "SYSTEM_EXEC"}))

    if is_strictly_read and not has_explicit_action:
        # User only asked to read/summarize/calculate
        if tool_name in ["send_email", "mail_client"]:
            reasons.append("INTENT_MISMATCH_EMAIL_ON_READ_REQUEST")
            risk_boost += 60.0

        elif tool_name in ["transfer_funds", "make_payment", "execute_trade"]:
            reasons.append("INTENT_MISMATCH_FINANCIAL_ACTION_ON_READ_REQUEST")
            risk_boost += 85.0

        elif tool_name in ["delete_file", "drop_tables", "wipe_disk"]:
            reasons.append("INTENT_MISMATCH_DESTRUCTIVE_TOOL_ON_READ_REQUEST")
            risk_boost += 90.0

        elif tool_name in ["execute_bash", "shell_exec", "run_cmd"]:
            reasons.append("INTENT_MISMATCH_SYSTEM_EXEC_ON_READ_REQUEST")
            risk_boost += 80.0

    # 2. Destination Entity Verification: Email recipient
    if tool_name == "send_email":
        recipient = str(args.get("to") or args.get("recipient") or "").strip().lower()
        if recipient:
            # Check if recipient or recipient's name/domain was mentioned in user prompt
            user_tokens = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", user_message.lower())
            if recipient not in user_tokens:
                # Also check local part
                local_part = recipient.split("@")[0]
                if local_part not in msg_lower and recipient not in msg_lower:
                    reasons.append("INTENT_UNMENTIONED_EMAIL_RECIPIENT")
                    risk_boost += 50.0

    # 3. Destination Entity Verification: Transfer funds
    if tool_name in ["transfer_funds", "make_payment"]:
        destination = str(args.get("destination") or args.get("to_account") or args.get("recipient") or "").strip()
        if destination and destination.lower() not in msg_lower:
            reasons.append("INTENT_UNMENTIONED_TRANSFER_DESTINATION")
            risk_boost += 70.0

    # 4. Outbound HTTP Request Target Check
    if tool_name in ["http_request", "web_fetch"]:
        url = str(args.get("url") or args.get("uri") or "").lower()
        if url:
            # Extract host
            host_match = re.search(r"https?://([^/:\s]+)", url)
            if host_match:
                host = host_match.group(1).lower()
                # If host is an arbitrary exfil service not in user prompt
                if host not in msg_lower and any(exfil in host for exfil in ["webhook.site", "pipedream", "requestbin", "ngrok"]):
                    reasons.append("INTENT_UNPROMPTED_EXFILTRATION_ENDPOINT")
                    risk_boost += 85.0

    is_aligned = len(reasons) == 0
    risk_boost = min(100.0, risk_boost)

    if not is_aligned:
        explanation = f"Tool call '{tool_name}' exhibits intent misalignment with user query: {', '.join(reasons)}"
    else:
        explanation = f"Tool call '{tool_name}' matches detected user intent: {list(intents)}"

    return IntentAlignmentResult(
        is_aligned=is_aligned,
        risk_contribution=risk_boost,
        reasons=reasons,
        explanation=explanation,
    )
