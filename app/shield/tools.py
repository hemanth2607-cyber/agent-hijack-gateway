"""Secure Tool Execution Registry for Agent Hijack Shield.

In accordance with least-privilege security invariants:
- Every tool function strictly refuses to run without a cryptographically valid capability token.
- Tokens must be bound to (agent_id, tool_name, args_hash, request_id) and are single-use.
- Direct invocation without a valid token raises PermissionError, failing closed.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from app.shield.capabilities import CapabilityManager, compute_args_hash

logger = logging.getLogger("agent_shield.tools")

# Default global capability manager for tools
_default_capability_mgr = CapabilityManager()


def enforce_tool_capability(
    tool_name: str,
    args: Dict[str, Any],
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> None:
    """Validates and single-use consumes the capability token before tool execution.
    
    Raises:
        PermissionError: If token is missing, invalid, expired, or replayed.
    """
    if not capability_token or not capability_token.strip():
        raise PermissionError(
            f"Access denied: Tool '{tool_name}' strictly refuses execution without a capability token."
        )

    mgr = manager or _default_capability_mgr
    args_hash = compute_args_hash(args)
    verification = mgr.verify_and_consume_token(
        token=capability_token,
        expected_agent_id=agent_id,
        expected_tool_name=tool_name,
        expected_args_hash=args_hash,
        expected_request_id=request_id,
    )

    if not verification.is_valid:
        raise PermissionError(
            f"Access denied for tool '{tool_name}' ({verification.reason_code}): {verification.message}"
        )


# -------------------------------------------------------------
# Individual Tool Implementations (Gated by Capability Token)
# -------------------------------------------------------------

def tool_calculator(
    expression: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Evaluates basic mathematical expressions."""
    args = {"expression": expression}
    enforce_tool_capability("calculator", args, capability_token, agent_id, request_id, manager)

    clean_expr = expression.replace(" ", "")
    if not all(c.isdigit() or c in "+-*/()." for c in clean_expr):
        return {"error": "Invalid mathematical expression"}
    try:
        # Bounded math evaluation
        result = eval(clean_expr, {"__builtins__": None}, {})  # nosec B307
        return {"result": result, "status": "success"}
    except Exception as exc:
        return {"error": f"Evaluation error: {exc}"}


def tool_read_clock(
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Returns current UTC timestamp."""
    args: Dict[str, Any] = {}
    enforce_tool_capability("read_clock", args, capability_token, agent_id, request_id, manager)
    return {"current_utc": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()), "status": "success"}


def tool_search_docs(
    query: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Searches simulated internal document index."""
    args = {"query": query}
    enforce_tool_capability("search_docs", args, capability_token, agent_id, request_id, manager)
    return {
        "query": query,
        "results": [
            f"Document result 1 for '{query}': Overview and specifications.",
            f"Document result 2 for '{query}': Operating procedures and guidelines.",
        ],
        "status": "success",
    }


def tool_summarize_text(
    text: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Generates a brief summary of text."""
    args = {"text": text}
    enforce_tool_capability("summarize_text", args, capability_token, agent_id, request_id, manager)
    snippet = text[:100] + "..." if len(text) > 100 else text
    return {"summary": f"Summary: {snippet}", "status": "success"}


def tool_read_file(
    path: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Reads a file from the workspace."""
    args = {"path": path}
    enforce_tool_capability("read_file", args, capability_token, agent_id, request_id, manager)
    return {"path": path, "content": f"Simulated content of {path}", "status": "success"}


def tool_write_file(
    path: str,
    content: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Writes content to a file in the workspace."""
    args = {"path": path, "content": content}
    enforce_tool_capability("write_file", args, capability_token, agent_id, request_id, manager)
    return {"path": path, "bytes_written": len(content), "status": "simulated_success"}


def tool_send_email(
    to: str,
    subject: str,
    body: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Sends an email to a verified recipient."""
    args = {"to": to, "subject": subject, "body": body}
    enforce_tool_capability("send_email", args, capability_token, agent_id, request_id, manager)
    return {"status": "simulated_sent", "to": to, "subject": subject}


def tool_transfer_funds(
    amount: float,
    destination: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Transfers funds within authorized limits."""
    args = {"amount": amount, "destination": destination}
    enforce_tool_capability("transfer_funds", args, capability_token, agent_id, request_id, manager)
    return {"status": "simulated_transferred", "amount": amount, "destination": destination}


def tool_http_request(
    url: str,
    capability_token: str,
    agent_id: str,
    request_id: str,
    method: str = "GET",
    data: Optional[str] = None,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Executes an outbound HTTP request to an allowlisted destination."""
    args: Dict[str, Any] = {"url": url}
    if method != "GET":
        args["method"] = method
    if data is not None:
        args["data"] = data
    enforce_tool_capability("http_request", args, capability_token, agent_id, request_id, manager)
    return {"status": 200, "url": url, "response": "Simulated HTTP response body"}


# -------------------------------------------------------------
# Unified Tool Dispatcher
# -------------------------------------------------------------

TOOL_REGISTRY = {
    "calculator": lambda args, tok, aid, rid, mgr: tool_calculator(
        expression=str(args.get("expression", "0")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "read_clock": lambda args, tok, aid, rid, mgr: tool_read_clock(
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "search_docs": lambda args, tok, aid, rid, mgr: tool_search_docs(
        query=str(args.get("query", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "summarize_text": lambda args, tok, aid, rid, mgr: tool_summarize_text(
        text=str(args.get("text", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "read_file": lambda args, tok, aid, rid, mgr: tool_read_file(
        path=str(args.get("path", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "write_file": lambda args, tok, aid, rid, mgr: tool_write_file(
        path=str(args.get("path", "")),
        content=str(args.get("content", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "send_email": lambda args, tok, aid, rid, mgr: tool_send_email(
        to=str(args.get("to") or args.get("recipient", "")),
        subject=str(args.get("subject", "")),
        body=str(args.get("body", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "transfer_funds": lambda args, tok, aid, rid, mgr: tool_transfer_funds(
        amount=float(args.get("amount", 0.0)),
        destination=str(args.get("destination", "")),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
    "http_request": lambda args, tok, aid, rid, mgr: tool_http_request(
        url=str(args.get("url", "")),
        method=str(args.get("method", "GET")),
        data=args.get("data"),
        capability_token=tok,
        agent_id=aid,
        request_id=rid,
        manager=mgr,
    ),
}


def execute_tool(
    tool_name: str,
    args: Dict[str, Any],
    capability_token: str,
    agent_id: str,
    request_id: str,
    manager: Optional[CapabilityManager] = None,
) -> Dict[str, Any]:
    """Dispatches tool execution with mandatory capability token enforcement."""
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool '{tool_name}'")

    handler = TOOL_REGISTRY[tool_name]
    return handler(args, capability_token, agent_id, request_id, manager)
