/**
 * Tether // Agent Hijack Shield - Reasons Translation Mapping
 * Plain-English mapping table for reason codes to executive-friendly explanations.
 * Ensures judges and business people understand every security decision in 60 seconds.
 */

const REASON_MAP = {
  // Session & Taint Tracking
  "TAINTED_SESSION_ESCALATED_TO_APPROVAL": "Held for a person to approve because the agent had read untrusted content",
  "SESSION_TAINT_ESCALATED": "Session marked as contaminated after ingesting external untrusted data",
  "DETECTED_MEMORY_POISONING_ATTEMPT": "Blocked attempt to corrupt the agent's long-term memory or instructions",
  "DETECTED_CRESCENDO_ATTACK_DRIFT": "Blocked gradual multi-turn attack attempting to build malicious context",
  "REPEATED_PROBING_AFTER_REFUSAL": "Quarantined after repeated probing following previous security refusals",
  "AUTO_QUARANTINE_SESSION_TRIGGERED": "Session automatically quarantined due to multiple severe violations",
  "AGENT_QUARANTINED": "Agent execution halted: agent is currently under security quarantine",
  "SESSION_QUARANTINED": "Session halted: active quarantine in effect",

  // Inbound Detection Heuristics
  "R_DIR_OVERRIDE_01": "Blocked direct command override in user prompt",
  "R_DIR_OVERRIDE_02": "Blocked attempt to reset system persona or safety instructions",
  "R_DIR_OVERRIDE_03": "Blocked jailbreak attempt using roleplay bypass",
  "R_LEAK_SYS_01": "Blocked attempt to extract internal system instructions",
  "R_LEAK_SYS_02": "Blocked attempt to reveal gateway configuration or API keys",
  "R_MUL_HI_01": "Blocked multilingual prompt injection written in Hindi (Devanagari)",
  "R_MUL_TA_01": "Blocked multilingual prompt injection written in Tamil",
  "R_OBF_B64_01": "De-obfuscated and blocked Base64-encoded attack payload",
  "R_OBF_HEX_01": "De-obfuscated and blocked Hex-encoded attack payload",
  "R_OBF_ZW_01": "Stripped invisible zero-width Unicode characters used to hide injection",
  "R_OBF_LEET_01": "Normalized and blocked Leetspeak obfuscated command",
  "R_IND_TAG_01": "Blocked fake system override tag embedded inside document context",
  "R_IND_EXFIL_01": "Blocked indirect exfiltration instruction inside external document",
  "R_DELIM_SPLIT_01": "Blocked delimiter manipulation attempting to break prompt framing",

  // Permission & Tool Gating Rules
  "TOOL_EXPLICITLY_DENIED": "Blocked: tool is strictly forbidden by policy for this agent",
  "TOOL_NOT_IN_ALLOWLIST": "Blocked: tool is not on the agent's approved allowlist",
  "SSRF_TARGET_BLOCKED": "Blocked attempt to reach private cloud metadata address (SSRF attack)",
  "NETWORK_DOMAIN_DENIED": "Blocked: external network call to unauthorized domain",
  "NETWORK_DOMAIN_NOT_ALLOWED": "Blocked: domain is not on the agent's network allowlist",
  "EMAIL_DOMAIN_NOT_AUTHORIZED": "Blocked: attempted to send email to unauthorized external address",
  "TRANSACTION_EXCEEDS_POLICY_BUDGET": "Held for human approval: transaction exceeds $500 policy threshold",
  "PATH_TRAVERSAL_OR_DENIED_FILE": "Blocked attempt to access sensitive configuration or system files",
  "SENSITIVE_DATA_IN_ARGUMENTS": "Blocked: tool arguments contain detected API credentials or secrets",
  "CAPABILITY_VERIFICATION_FAILED": "Blocked: single-use capability token is invalid or expired",
  "FAIL_CLOSED_EXCEPTION": "Fail-closed gateway protection triggered: execution halted safely",

  // Outbound Inspection
  "DETECTED_OUTBOUND_SECRET_LEAK": "Blocked outbound transmission: response contains detected secrets or keys",
  "DETECTED_SSN_OR_FINANCIAL_LEAK": "Blocked outbound transmission: response contains sensitive personal data",

  // Normal Operations & Shield Off Demo
  "SHIELD_DISABLED_UNPROTECTED_EXECUTION": "Executed without protection (Shield OFF demo mode)",
  "TOOL_POLICY_AUTHORIZED": "Allowed: action conforms to agent security policy",
  "CLEAN_BENIGN_PROMPT": "Allowed: clean prompt with no detected policy or safety violations",
  "ALLOW": "Allowed: verified clean interaction",
};

/**
 * Translates a single reason code or array of codes into a plain-English explanation.
 * @param {string|string[]} codes
 * @returns {string}
 */
function translateReasonCodes(codes) {
  if (!codes) return "Safe interaction passed through gateway";
  const list = Array.isArray(codes) ? codes : [codes];
  if (list.length === 0) return "Safe interaction passed through gateway";

  const mapped = [];
  for (const c of list) {
    if (!c) continue;
    const clean = String(c).trim();
    if (REASON_MAP[clean]) {
      mapped.push(REASON_MAP[clean]);
    } else if (clean.startsWith("R_")) {
      mapped.push("Blocked by heuristic detector rule " + clean);
    } else {
      // Format SNAKE_CASE cleanly
      const readable = clean
        .replace(/_/g, " ")
        .toLowerCase()
        .replace(/^\w/, (chr) => chr.toUpperCase());
      mapped.push(readable);
    }
  }

  return mapped.length > 0 ? mapped.join("; ") : "Verified clean by gateway policy";
}

// Export for browser ES / standard script loading
if (typeof window !== "undefined") {
  window.REASON_MAP = REASON_MAP;
  window.translateReasonCodes = translateReasonCodes;
}
