# Tether // Agent Hijack Shield - Developer Integration Guide

Tether is a defense-in-depth security gateway that protects autonomous AI agents from indirect prompt injection, tool hijacking, and data exfiltration.

It operates as a **zero-code-rewrite reverse proxy** between your agent runtime and the underlying LLM provider, enforcing strict least privilege, taint tracking, and single-use cryptographic capability tokens.

---

## 1. Quickstart: Connecting Your Agent in 30 Seconds

### Python (OpenAI SDK Drop-In)
Tether implements the standard OpenAI-compatible `/v1/chat` interface. You only need to set `base_url` and provide your client API key:

```python
from openai import OpenAI

# Point your standard client to Tether Gateway
client = OpenAI(
    base_url="https://agent-hijack-gateway.onrender.com/v1",  # Or http://localhost:8000/v1
    api_key="sk_client_demo_judge_access",                  # Client-role API key
)

# Call agent as normal - Tether screens all inputs and tool requests
response = client.chat.completions.create(
    model="coder_agent",
    messages=[
        {"role": "user", "content": "Analyze GitHub PR #42 and summarize dependencies."},
    ],
)

print(response.choices[0].message.content)
```

---

### LangChain / LangGraph Integration

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

# Initialize Tether-mediated LLM
llm = ChatOpenAI(
    base_url="https://agent-hijack-gateway.onrender.com/v1",
    api_key="sk_client_demo_judge_access",
    model="coder_agent",
    temperature=0.0,
)

# Autonomous tool execution is governed by Tether's declarative policy
# Untrusted document inputs cannot trigger unauthorized bash or email dispatch
```

---

### TypeScript / Node.js

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://agent-hijack-gateway.onrender.com/v1",
  apiKey: "sk_client_demo_judge_access",
});

async function main() {
  const completion = await client.chat.completions.create({
    model: "coder_agent",
    messages: [{ role: "user", content: "Review recent commits" }],
  });
  console.log(completion.choices[0].message.content);
}

main();
```

---

### Raw HTTP / cURL

```bash
curl -X POST https://agent-hijack-gateway.onrender.com/v1/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk_client_demo_judge_access" \
  -d '{
    "agent_id": "coder_agent",
    "message": "Read system configuration and verify certificates.",
    "shield_enabled": true
  }'
```

---

## 2. Defining Declarative Security Policies (`policies/<agent_id>.yaml`)

Tether enforces security boundaries through declarative YAML configuration. Each agent has an isolated policy that restricts capabilities regardless of what prompt instructions the LLM generates:

```yaml
# policies/coder_agent.yaml
agent_id: coder_agent
version: 1
description: Software engineering assistant with restricted filesystem and zero bash execution

# Safe read-only tools allowed to execute autonomously
allowed_tools:
  - git_diff
  - run_linter
  - read_code
  - read_file

# State-modifying or network tools requiring human authorization
require_approval_tools:
  - write_file
  - git_push
  - http_request

# Forbidden capabilities that can NEVER be called
denied_tools:
  - execute_bash
  - delete_file
  - drop_tables
  - send_email

# Filesystem sandboxing
filesystem:
  allowed_directories:
    - "/workspace/public"
    - "/workspace/src"
  denied_patterns:
    - "*.env*"
    - "*id_rsa*"
    - "*secret*"

# If untrusted input enters the context window, escalate all tools to approval
taint_escalation: true
```

---

## 3. How Tether Protects Agents in Production

```
                                      [ UNTRUSTED INPUT ]
                                     (Document / Webhook / Email)
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. INBOUND DETECTOR & DE-OBFUSCATION                                   │
│    - Strips Leetspeak, Unicode Zero-Width, Base64, Hex                 │
│    - Normalizes & scans for override delimiters (R_OVR_01)             │
│    - Marks context: <<<EXTERNAL_UNTRUSTED_CONTENT_uuid>>>              │
│    - Permanently tags session: is_tainted = true                       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. LEAST-PRIVILEGE POLICY ENGINE                                       │
│    - Evaluates requested tool against policies/<agent>.yaml            │
│    - If tainted: escalates sensitive tools to REQUIRE_APPROVAL         │
│    - Halts unauthorized execution before side-effects occur            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. HUMAN-IN-THE-LOOP & CAPABILITY MINTING                              │
│    - Queues checkpoint: POST /v1/approvals                             │
│    - Reviewer inspects exact tool name and parameter hash              │
│    - Upon authorization, mints HMAC-SHA256 capability token            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. IMMUTABLE CRYPTOGRAPHIC AUDIT LOG                                   │
│    - Every scan, verdict, approval, and tool call linked via SHA-256   │
│    - Validated anytime via GET /v1/public/audit/verify                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Single-Use Capability Tokens

To prevent replay attacks and race conditions, Tether does not allow agents to run privileged tools directly. When an approval is granted:

1. Tether calculates:
   $$\text{HMAC-SHA256}(K_{\text{secret}}, \text{approval\_id} \parallel \text{agent\_id} \parallel \text{tool\_name} \parallel H(\text{parameters}))$$
2. A single-use `capability_token` is returned to the agent execution harness.
3. The harness presents the token to the execution sandbox; once consumed, the token is invalidated.

---

## 5. Tamper-Evident Audit Verification

Developers and security auditors can verify that logs have never been modified:

```python
import httpx

res = httpx.get("https://agent-hijack-gateway.onrender.com/v1/public/audit/verify")
audit = res.json()

print(f"Verified {audit['total_blocks']} blocks.")
print(f"Chain status: {'VALID' if audit['valid'] else 'TAMPERED'}")
```

If any entry in the database is modified, inserted, or deleted, the forward-secure hash chain breaks immediately.
