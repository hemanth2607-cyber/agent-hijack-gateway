"""Agent policy engine, YAML schema loader, and granular tool authorization.

Enforces least-privilege tool execution:
- Allowed/denied tool allowlists with explicit deny overriding allow
- Strict argument schema and budget validation
- Network domain and SSRF policy enforcement
- File system path restrictions and traversal denial
- Email recipient domain restrictions
- Session taint escalation (tainted sessions require human approval for all mutations)
- Secret detection inside arguments
- Versioned policy history with privilege widening protection (admin-only)
"""

from __future__ import annotations

import difflib
import fnmatch
import json
import logging
import os
import re
from typing import Any, Dict, List, Literal, NamedTuple, Optional, Set
import yaml
from pydantic import BaseModel, ConfigDict, Field

from app.security.paths import is_safe_path
from app.security.secrets import scan_and_redact_secrets
from app.security.ssrf import validate_url

logger = logging.getLogger("agent_shield.permissions")


class ArgumentRule(BaseModel):
    """Validation constraints for a single tool argument."""

    model_config = ConfigDict(extra="ignore")

    type: Optional[str] = None  # string, integer, float, boolean, list, dict
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[str]] = None


class NetworkPolicy(BaseModel):
    """Network egress constraints."""

    model_config = ConfigDict(extra="ignore")

    allowed_domains: List[str] = Field(default_factory=list)
    denied_domains: List[str] = Field(default_factory=list)


class FilePolicy(BaseModel):
    """File system access constraints."""

    model_config = ConfigDict(extra="ignore")

    allowed_directories: List[str] = Field(default_factory=list)
    denied_patterns: List[str] = Field(
        default_factory=lambda: ["*.env*", "*id_rsa*", "*secret*", "/etc/*", "C:\\Windows\\*"]
    )


class AgentPolicy(BaseModel):
    """Declarative security policy defining permissions for an autonomous agent."""

    model_config = ConfigDict(extra="ignore")

    agent_id: str
    version: int = 1
    description: str = ""
    allowed_tools: List[str] = Field(default_factory=list)
    denied_tools: List[str] = Field(default_factory=list)
    require_approval_tools: List[str] = Field(default_factory=list)
    argument_schemas: Dict[str, Dict[str, ArgumentRule]] = Field(default_factory=dict)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    filesystem: FilePolicy = Field(default_factory=FilePolicy)
    allowed_email_domains: List[str] = Field(default_factory=list)
    max_transaction_amount: float = 500.0
    taint_escalation: bool = True  # If tainted, side-effect tools require approval


class ToolPolicyContext(BaseModel):
    """Contextual metadata evaluated during tool gating."""

    model_config = ConfigDict(extra="ignore")

    request_id: str
    session_id: Optional[str] = None
    is_tainted: bool = False
    trust_level: str = "USER"
    caller_role: str = "client"


class ToolGateResult(NamedTuple):
    """Decision produced by the tool policy engine."""

    verdict: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    reason_codes: List[str]
    reason: str


# Tools that perform persistent side effects or external interactions
SIDE_EFFECT_TOOLS: Set[str] = {
    "send_email",
    "transfer_funds",
    "execute_bash",
    "write_file",
    "delete_file",
    "http_request",
    "update_database",
    "deploy_service",
}


def load_policy_from_yaml(yaml_content: str) -> AgentPolicy:
    """Parses and validates an AgentPolicy from raw YAML string."""
    try:
        raw_data = yaml.safe_load(yaml_content)
        if not isinstance(raw_data, dict):
            raise ValueError("Policy YAML root must be a mapping dictionary")
        return AgentPolicy.model_validate(raw_data)
    except Exception as exc:
        raise ValueError(f"Invalid Agent Policy YAML: {str(exc)}") from exc


def serialize_policy_to_yaml(policy: AgentPolicy) -> str:
    """Serializes an AgentPolicy to canonical YAML format."""
    return yaml.dump(policy.model_dump(), sort_keys=False)


def compute_policy_diff(old_yaml: str, new_yaml: str) -> str:
    """Calculates unified textual diff between two policy revisions."""
    diff_lines = list(
        difflib.unified_diff(
            old_yaml.splitlines(keepends=True),
            new_yaml.splitlines(keepends=True),
            fromfile="policy_prev.yaml",
            tofile="policy_new.yaml",
        )
    )
    return "".join(diff_lines)


def detect_privilege_widening(old_policy: AgentPolicy, new_policy: AgentPolicy) -> Tuple[bool, List[str]]:
    """Checks if a new policy expands permissions compared to the old policy.

    Privilege widening includes:
    - Adding new allowed tools
    - Removing denied tools
    - Removing tools from require_approval_tools
    - Adding new allowed network domains or removing denied domains
    - Removing denied file patterns
    - Increasing max_transaction_amount
    """
    widened_reasons: List[str] = []

    # 1. Allowed tools widened
    new_allowed = set(new_policy.allowed_tools) - set(old_policy.allowed_tools)
    if new_allowed:
        widened_reasons.append(f"Expanded allowed tools: {sorted(list(new_allowed))}")

    # 2. Denied tools relaxed
    removed_denied = set(old_policy.denied_tools) - set(new_policy.denied_tools)
    if removed_denied:
        widened_reasons.append(f"Removed denied tools: {sorted(list(removed_denied))}")

    # 3. Approval requirement removed
    removed_approvals = set(old_policy.require_approval_tools) - set(new_policy.require_approval_tools)
    if removed_approvals:
        widened_reasons.append(f"Relaxed approval requirement on: {sorted(list(removed_approvals))}")

    # 4. Budget expansion
    if new_policy.max_transaction_amount > old_policy.max_transaction_amount:
        widened_reasons.append(
            f"Increased max transaction budget from {old_policy.max_transaction_amount} to {new_policy.max_transaction_amount}"
        )

    # 5. Network domains expanded
    new_domains = set(new_policy.network.allowed_domains) - set(old_policy.network.allowed_domains)
    if new_domains:
        widened_reasons.append(f"Added allowed network domains: {sorted(list(new_domains))}")

    is_widened = len(widened_reasons) > 0
    return is_widened, widened_reasons


class PolicyRegistry:
    """In-memory cache and manager for agent security policies."""

    def __init__(self, policy_dir: str = "policies"):
        self.policy_dir = policy_dir
        self._policies: Dict[str, AgentPolicy] = {}
        self.load_all_policies()

    def load_all_policies(self) -> None:
        """Loads all .yaml policies from the policy directory."""
        if not os.path.exists(self.policy_dir):
            os.makedirs(self.policy_dir, exist_ok=True)
            return

        for fname in os.listdir(self.policy_dir):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                fpath = os.path.join(self.policy_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        policy = load_policy_from_yaml(f.read())
                        self._policies[policy.agent_id] = policy
                except Exception as exc:
                    logger.error("Failed to load policy file %s: %s", fname, exc)

    def get_policy(self, agent_id: str) -> AgentPolicy:
        """Retrieves policy for agent or returns default restrictive policy."""
        if agent_id in self._policies:
            return self._policies[agent_id]

        # Default restrictive policy (fail-closed)
        return AgentPolicy(
            agent_id=agent_id,
            version=1,
            description="Default zero-trust restrictive policy",
            allowed_tools=["calculator", "read_clock", "search_docs"],
            denied_tools=["execute_bash", "delete_file", "transfer_funds"],
            require_approval_tools=["send_email", "write_file", "http_request"],
            max_transaction_amount=0.0,
        )

    def register_policy(
        self,
        new_policy: AgentPolicy,
        user_role: str,
    ) -> Tuple[bool, str, str]:
        """Registers or updates a policy with privilege widening protection."""
        agent_id = new_policy.agent_id
        old_policy = self._policies.get(agent_id)

        if old_policy is not None:
            is_widened, reasons = detect_privilege_widening(old_policy, new_policy)
            if is_widened and user_role != "admin":
                return (
                    False,
                    f"Privilege widening rejected: only admins can expand agent permissions. Reasons: {'; '.join(reasons)}",
                    "",
                )
            new_policy.version = old_policy.version + 1
            diff = compute_policy_diff(
                serialize_policy_to_yaml(old_policy),
                serialize_policy_to_yaml(new_policy),
            )
        else:
            diff = compute_policy_diff("", serialize_policy_to_yaml(new_policy))

        self._policies[agent_id] = new_policy

        # Persist to disk
        fpath = os.path.join(self.policy_dir, f"{agent_id}.yaml")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(serialize_policy_to_yaml(new_policy))

        return True, "Policy saved successfully", diff


# Global in-memory registry instance
policy_registry = PolicyRegistry()


def check_tool_call(
    policy: AgentPolicy,
    tool_name: str,
    args: Dict[str, Any],
    context: ToolPolicyContext,
) -> ToolGateResult:
    """Evaluates proposed tool call and arguments against agent policy and context.

    Returns:
    - ALLOW: Tool permitted without human intervention
    - REQUIRE_APPROVAL: Requires approver role sign-off
    - DENY: Hard block
    """
    reasons: List[str] = []

    # 1. Explicit Deny Check (Deny always takes precedence over allow)
    if tool_name in policy.denied_tools:
        return ToolGateResult(
            verdict="DENY",
            reason_codes=["TOOL_EXPLICITLY_DENIED"],
            reason=f"Tool '{tool_name}' is explicitly denied in agent policy",
        )

    # 2. Allowlist Check
    if tool_name not in policy.allowed_tools and tool_name not in policy.require_approval_tools:
        return ToolGateResult(
            verdict="DENY",
            reason_codes=["TOOL_NOT_IN_ALLOWLIST"],
            reason=f"Tool '{tool_name}' is not authorized in agent policy",
        )

    # 3. Sensitive Data / Secret Scanner in Arguments
    args_str = json.dumps(args)
    has_secret, secret_findings, _ = scan_and_redact_secrets(args_str)
    if has_secret:
        return ToolGateResult(
            verdict="DENY",
            reason_codes=["SENSITIVE_DATA_IN_ARGUMENTS"],
            reason=f"Argument payload contains plaintext secrets/credentials: {secret_findings}",
        )

    # 4. Taint Escalation Check
    # If the session has been tainted (e.g. by memory poisoning or untrusted document injection),
    # all side-effect tools must require approval or be denied
    if context.is_tainted and policy.taint_escalation and tool_name in SIDE_EFFECT_TOOLS:
        if tool_name in ["transfer_funds", "execute_bash", "delete_file"]:
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["TAINTED_SESSION_CRITICAL_TOOL_BLOCKED"],
                reason=f"Critical tool '{tool_name}' blocked because session is tainted by untrusted inputs",
            )
        reasons.append("TAINTED_SESSION_ESCALATED_TO_APPROVAL")

    # 5. Network Policy & SSRF Check
    if tool_name in ["http_request", "web_fetch", "fetch_url"]:
        url = args.get("url") or args.get("uri")
        if not url:
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["MISSING_REQUIRED_URL_ARGUMENT"],
                reason="HTTP request missing required 'url' parameter",
            )
        # SSRF filter
        is_safe, ssrf_reason = validate_url(str(url), resolve_dns=False)
        if not is_safe:
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["SSRF_TARGET_BLOCKED"],
                reason=f"URL rejected by SSRF guard: {ssrf_reason}",
            )
        # Domain allowlist/denylist
        url_lower = str(url).lower()
        if policy.network.denied_domains:
            for d_pattern in policy.network.denied_domains:
                if fnmatch.fnmatch(url_lower, f"*{d_pattern.lower()}*"):
                    return ToolGateResult(
                        verdict="DENY",
                        reason_codes=["NETWORK_DOMAIN_DENIED"],
                        reason=f"Destination domain matches denied pattern '{d_pattern}'",
                    )
        if policy.network.allowed_domains:
            domain_allowed = any(
                fnmatch.fnmatch(url_lower, f"*{a_domain.lower()}*")
                for a_domain in policy.network.allowed_domains
            )
            if not domain_allowed:
                return ToolGateResult(
                    verdict="DENY",
                    reason_codes=["NETWORK_DOMAIN_NOT_ALLOWED"],
                    reason="Destination domain not in policy network allowlist",
                )

    # 6. File Access & Path Traversal Check
    if tool_name in ["read_file", "write_file", "delete_file"]:
        filepath = args.get("path") or args.get("filepath") or args.get("filename")
        if not filepath:
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["MISSING_FILEPATH_ARGUMENT"],
                reason="File tool missing required 'path' parameter",
            )
        filepath_str = str(filepath)
        is_safe_file, path_reason = is_safe_path(filepath_str)
        if not is_safe_file:
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["PATH_TRAVERSAL_OR_DENIED_FILE"],
                reason=f"File path violates filesystem security: {path_reason}",
            )

    # 7. Email Domain Policy
    if tool_name == "send_email":
        recipient = str(args.get("to") or args.get("recipient") or "")
        if policy.allowed_email_domains:
            email_valid = any(
                recipient.lower().endswith(dom.lower()) for dom in policy.allowed_email_domains
            )
            if not email_valid:
                return ToolGateResult(
                    verdict="DENY",
                    reason_codes=["EMAIL_DOMAIN_NOT_AUTHORIZED"],
                    reason=f"Recipient '{recipient}' domain not in authorized email list",
                )

    # 8. Budget Constraints
    if tool_name in ["transfer_funds", "make_payment", "execute_trade"]:
        try:
            amount = float(args.get("amount", 0.0))
            if amount > policy.max_transaction_amount:
                return ToolGateResult(
                    verdict="REQUIRE_APPROVAL",
                    reason_codes=["TRANSACTION_EXCEEDS_POLICY_BUDGET"],
                    reason=f"Amount ${amount:.2f} exceeds agent limit ${policy.max_transaction_amount:.2f}",
                )
        except (ValueError, TypeError):
            return ToolGateResult(
                verdict="DENY",
                reason_codes=["INVALID_NUMERIC_AMOUNT"],
                reason="Transaction amount must be a valid positive number",
            )

    # 9. Argument Schema Validation
    if tool_name in policy.argument_schemas:
        schema = policy.argument_schemas[tool_name]
        for param_name, rule in schema.items():
            if param_name in args:
                val = args[param_name]
                if rule.max_length is not None and len(str(val)) > rule.max_length:
                    return ToolGateResult(
                        verdict="DENY",
                        reason_codes=["ARGUMENT_EXCEEDS_MAX_LENGTH"],
                        reason=f"Argument '{param_name}' exceeds maximum allowed length of {rule.max_length}",
                    )
                if rule.pattern is not None:
                    if not re.search(rule.pattern, str(val)):
                        return ToolGateResult(
                            verdict="DENY",
                            reason_codes=["ARGUMENT_PATTERN_MISMATCH"],
                            reason=f"Argument '{param_name}' does not match required regex pattern",
                        )

    # 10. Check if tool requires human approval
    if tool_name in policy.require_approval_tools or "TAINTED_SESSION_ESCALATED_TO_APPROVAL" in reasons:
        reasons.append("HIGH_RISK_ACTION_REQUIRES_APPROVAL")
        return ToolGateResult(
            verdict="REQUIRE_APPROVAL",
            reason_codes=reasons,
            reason=f"Tool '{tool_name}' requires human approval per security policy",
        )

    # 11. Allow
    return ToolGateResult(
        verdict="ALLOW",
        reason_codes=["TOOL_POLICY_AUTHORIZED"],
        reason="Tool call satisfies all policy constraints",
    )
