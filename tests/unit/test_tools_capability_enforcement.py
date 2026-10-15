"""Unit tests for tool capability token enforcement in app/shield/tools.py.

Verifies the security invariant that every tool function strictly refuses
direct execution without a valid, single-use, cryptographically signed capability token.
"""

from __future__ import annotations

import pytest

from app.shield.capabilities import CapabilityManager, compute_args_hash
from app.shield.tools import (
    execute_tool,
    tool_calculator,
    tool_http_request,
    tool_read_clock,
    tool_read_file,
    tool_search_docs,
    tool_send_email,
    tool_summarize_text,
    tool_transfer_funds,
    tool_write_file,
)


def test_tool_calculator_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_calc"
    req_id = "req_calc_01"
    expr = "42 * 2"
    args = {"expression": expr}
    args_hash = compute_args_hash(args)

    # 1. Direct call without token -> MUST fail closed
    with pytest.raises(PermissionError, match="strictly refuses execution without a capability token"):
        tool_calculator(expression=expr, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # 2. Direct call with forged token -> MUST fail closed
    with pytest.raises(PermissionError, match="Access denied"):
        tool_calculator(expression=expr, capability_token="fake.token.signature", agent_id=agent_id, request_id=req_id, manager=mgr)

    # 3. Call with valid capability token -> MUST succeed
    valid_token = mgr.issue_token(agent_id, "calculator", args_hash, req_id)
    res = tool_calculator(expression=expr, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "success"
    assert res["result"] == 84

    # 4. Replay attempt with already consumed token -> MUST fail closed
    with pytest.raises(PermissionError, match="CAPABILITY_REPLAY_DETECTED"):
        tool_calculator(expression=expr, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)


def test_tool_read_clock_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_clock"
    req_id = "req_clock_01"
    args = {}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_read_clock(capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "read_clock", args_hash, req_id)
    res = tool_read_clock(capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "success"
    assert "current_utc" in res


def test_tool_search_docs_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_search"
    req_id = "req_search_01"
    query = "security policy"
    args = {"query": query}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_search_docs(query=query, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "search_docs", args_hash, req_id)
    res = tool_search_docs(query=query, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "success"
    assert len(res["results"]) > 0


def test_tool_summarize_text_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_summary"
    req_id = "req_summary_01"
    text = "Short text to summarize"
    args = {"text": text}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_summarize_text(text=text, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "summarize_text", args_hash, req_id)
    res = tool_summarize_text(text=text, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "success"
    assert "Summary" in res["summary"]


def test_tool_read_file_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_fs"
    req_id = "req_read_01"
    path = "/workspace/data.txt"
    args = {"path": path}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_read_file(path=path, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "read_file", args_hash, req_id)
    res = tool_read_file(path=path, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "success"
    assert res["path"] == path


def test_tool_write_file_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_fs"
    req_id = "req_write_01"
    path = "/workspace/out.txt"
    content = "Hello world"
    args = {"path": path, "content": content}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_write_file(path=path, content=content, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "write_file", args_hash, req_id)
    res = tool_write_file(path=path, content=content, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "simulated_success"
    assert res["bytes_written"] == len(content)


def test_tool_send_email_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_mail"
    req_id = "req_mail_01"
    to = "user@company.com"
    subject = "Report"
    body = "Monthly metrics"
    args = {"to": to, "subject": subject, "body": body}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_send_email(to=to, subject=subject, body=body, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "send_email", args_hash, req_id)
    res = tool_send_email(to=to, subject=subject, body=body, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "simulated_sent"
    assert res["to"] == to


def test_tool_transfer_funds_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_finance"
    req_id = "req_tx_01"
    amount = 150.0
    destination = "ACCT-987"
    args = {"amount": amount, "destination": destination}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_transfer_funds(amount=amount, destination=destination, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "transfer_funds", args_hash, req_id)
    res = tool_transfer_funds(amount=amount, destination=destination, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == "simulated_transferred"
    assert res["amount"] == amount


def test_tool_http_request_capability_enforcement():
    mgr = CapabilityManager()
    agent_id = "agent_net"
    req_id = "req_http_01"
    url = "https://api.weather.gov/v1/forecast"
    args = {"url": url}
    args_hash = compute_args_hash(args)

    # Without token
    with pytest.raises(PermissionError):
        tool_http_request(url=url, capability_token="", agent_id=agent_id, request_id=req_id, manager=mgr)

    # With valid token
    valid_token = mgr.issue_token(agent_id, "http_request", args_hash, req_id)
    res = tool_http_request(url=url, capability_token=valid_token, agent_id=agent_id, request_id=req_id, manager=mgr)
    assert res["status"] == 200
    assert res["url"] == url


def test_execute_tool_dispatcher_tampered_args_rejection():
    mgr = CapabilityManager()
    agent_id = "agent_dispatch"
    req_id = "req_dispatch_01"
    orig_args = {"expression": "10 + 10"}
    orig_hash = compute_args_hash(orig_args)

    valid_token = mgr.issue_token(agent_id, "calculator", orig_hash, req_id)

    # Attacker tampers with arguments
    tampered_args = {"expression": "999 * 999"}
    with pytest.raises(PermissionError, match="CAPABILITY_ARGS_HASH_MISMATCH"):
        execute_tool(
            tool_name="calculator",
            args=tampered_args,
            capability_token=valid_token,
            agent_id=agent_id,
            request_id=req_id,
            manager=mgr,
        )
