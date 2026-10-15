# Security Policy: Agent Hijack Shield

## 1. Supported Versions

Only the latest active release on the `master` branch is supported for critical security patches and vulnerability triage.

| Version / Branch | Supported | Notes |
| :--- | :--- | :--- |
| `master` (v1.x) | :white_check_mark: | Active production-ready branch |
| `< 1.0.0` | :x: | Prototype milestones; upgrade immediately |

---

## 2. Reporting a Vulnerability

We treat all potential bypasses, privilege escalation issues, and cryptographic weaknesses with critical priority. If you discover a security vulnerability in Agent Hijack Shield:

1. **Do NOT open a public GitHub issue.**
2. Send an encrypted email with your findings to **`security@agentshield.internal`** (or contact the internal repository maintainers).
3. Include the following details in your report:
   - Specific component or file affected (e.g., `policy_gate.py`, `normalize.py`).
   - Detailed attack vector or payload (e.g., bypass string, homoglyph chain, SSRF destination).
   - Expected vs. actual behavior.
   - Minimal reproduction script or curl command.
4. **Response SLA**:
   - Initial triage acknowledgement: within **24 hours**.
   - Reproducibility verification and severity classification: within **48 hours**.
   - Remediation patch release: within **7 calendar days** for high/critical severity.

---

## 3. Production Deployment Security Invariants

When deploying Agent Hijack Shield in production environments, the following invariants are **strictly enforced**:

### 3.1. Strict Fail-Closed Environment Configuration
- Set `APP_ENV=production`.
- The gateway lifespan startup hook will **refuse to boot** if any demo API keys (`sk_admin_demo_...`, `sk_client_demo_...`) exist in the database.
- Database initialization via `python -m app.seed_demo` is hardcoded to fail if `APP_ENV != development`.
- If a database connectivity error or cryptographic failure occurs during request evaluation, the gateway fails closed (`500 Internal Server Error`) and blocks the transaction.

### 3.2. Cryptographic Secret Management
- **Master Encryption Key**: Store `AGENT_SHIELD_SECRET_KEY` in a secure key vault (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager). Never commit `.env` files containing secrets.
- **Key Rotation**:
  - Rotating the master key invalidates existing capability tokens (5-minute lifetime) and SSE tokens (60-second lifetime).
  - Existing audit log chains require key archival: past records are keyed using HMAC; retain past verification keys in an HSM/vault to verify historical audit blocks.
- **Domain Separation**:
  - Capability tokens use subkey derivation: `HMAC(master_key, "AgentShield:CapabilityToken:v1")`.
  - SSE tokens use separate subkey derivation: `HMAC(master_key, "AgentShield:DomainSeparation:SSE-Token:v1")`.
  - Capability tokens are strictly excluded from `/v1/chat` client responses (`exclude=True`).

### 3.3. Network & Infrastructure Isolation
- Restrict inbound traffic to the gateway reverse proxy via TLS termination (HTTPS only).
- Protect internal health and telemetry endpoints:
  - In production, `/metrics` requires bearer authentication via `METRICS_SCRAPE_TOKEN`.
- Prevent Server-Side Request Forgery (SSRF):
  - Tools dispatching network calls (`http_request`) resolve DNS and block requests targeting RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and cloud metadata IP addresses (`169.254.169.254`).

---

## 4. Known Security Limitations & Threat Realism

In alignment with security transparency, the following empirical limitations and edge cases are documented:

1. **Heuristic & Pattern Detection Limitations**:
   - While inbound pattern matching achieves **95.65% recall** on held-out attacks, adaptive adversarial attacks (novel paraphrasing, zero-shot role inversion) achieve only **9.09% recall** against pattern heuristics alone.
   - **Architectural Mitigation**: The gateway never relies on pattern matching as a sole defense. Inbound detection is backed by **zero-trust external content isolation**, **session taint propagation**, and **mandatory tool capability enforcement**.
2. **Known Defense-in-Depth Escape (`abuse_20`)**:
   - In `eval/defense_in_depth_eval.py`, scenario `abuse_20_non_pattern_secret_allowed_domain_untainted` represents an edge case:
     - An agent attempts to send an unstructured, non-pattern custom passphrase to an **authorized internal recipient** (`finance@company.com`) during an **untainted session**.
     - Because the payload does not match known credential patterns (AWS, OpenAI, PEM, JWT) and destination is within `allowed_email_domains`, the policy gate permits the call.
   - **Recommendation**: For environments handling arbitrary secret passphrases, configure `require_approval_tools: [send_email]` unconditionally across all recipient domains.
3. **Adversarial Benign False Positive Rate**:
   - Security discussions and documentation containing quoted attack phrases in external content produce an elevated false-positive rate (50% on adversarial benign external quotes) due to zero-trust external document amplification.
   - This tradeoff is intentional: the gateway errs on the side of caution when processing untrusted third-party documents.
