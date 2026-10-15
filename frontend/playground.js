/**
 * Tether Playground // Agent Hijack Shield Interactive Console
 * Analog-Digital Instrument Console JS
 * Strict CSP: textContent only (no innerHTML for dynamic text), external JS only.
 */

(function () {
  "use strict";

  // State Management
  const state = {
    clientKey: "",
    agents: [],
    scenarios: [],
    activeAgentId: "default_agent",
    shieldEnabled: true,
    activeCategory: "all",
    activeScenarioId: "scenario_05",
    currentTourStep: 0,
    sseEventSource: null,
  };

  // DOM Elements
  const el = {
    activeAgentLabel: document.getElementById("activeAgentLabel"),
    activeAgentChip: document.getElementById("activeAgentChip"),
    headerShieldChip: document.getElementById("headerShieldChip"),
    headerShieldVal: document.getElementById("headerShieldVal"),
    agentPills: document.getElementById("agentPills"),
    policySummaryText: document.getElementById("policySummaryText"),
    shieldToggle: document.getElementById("shieldToggle"),
    shieldToggleHint: document.getElementById("shieldToggleHint"),
    categoryFilters: document.getElementById("categoryFilters"),
    scenarioSelect: document.getElementById("scenarioSelect"),
    scenBadge: document.getElementById("scenBadge"),
    scenExpected: document.getElementById("scenExpected"),
    scenTitle: document.getElementById("scenTitle"),
    scenWhy: document.getElementById("scenWhy"),
    userPromptInput: document.getElementById("userPromptInput"),
    untrustedDocInput: document.getElementById("untrustedDocInput"),
    btnRun: document.getElementById("btnRun"),
    btnRunLabel: document.getElementById("btnRunLabel"),
    btnSideBySide: document.getElementById("btnSideBySide"),
    btnDemoReset: document.getElementById("btnDemoReset"),
    btnVerifyAudit: document.getElementById("btnVerifyAudit"),
    btnTour: document.getElementById("btnTour"),
    deckModeIndicator: document.getElementById("deckModeIndicator"),

    // Left Panel (Shield ON)
    shieldOnVerdict: document.getElementById("shieldOnVerdict"),
    shieldOnRisk: document.getElementById("shieldOnRisk"),
    shieldOnLayer: document.getElementById("shieldOnLayer"),
    shieldOnLatency: document.getElementById("shieldOnLatency"),
    shieldOnResponseTitle: document.getElementById("shieldOnResponseTitle"),
    shieldOnResponseText: document.getElementById("shieldOnResponseText"),
    shieldOnFindings: document.getElementById("shieldOnFindings"),
    shieldOnTools: document.getElementById("shieldOnTools"),

    // Right Panel (Shield OFF)
    panelShieldOff: document.getElementById("panelShieldOff"),
    shieldOffVerdict: document.getElementById("shieldOffVerdict"),
    shieldOffStatus: document.getElementById("shieldOffStatus"),
    shieldOffLatency: document.getElementById("shieldOffLatency"),
    shieldOffResponseText: document.getElementById("shieldOffResponseText"),
    shieldOffTools: document.getElementById("shieldOffTools"),
    shieldOffOutcomeText: document.getElementById("shieldOffOutcomeText"),

    // Approvals
    pendingApprovalsCount: document.getElementById("pendingApprovalsCount"),
    approvalsList: document.getElementById("approvalsList"),

    // Audit
    telemetryAuditStatus: document.getElementById("telemetryAuditStatus"),
    telemetryAuditSub: document.getElementById("telemetryAuditSub"),
    auditBadge: document.getElementById("auditBadge"),
    auditMsg: document.getElementById("auditMsg"),
    auditMeta: document.getElementById("auditMeta"),

    // SSE
    telemetrySseStatus: document.getElementById("telemetrySseStatus"),
    telemetrySseSub: document.getElementById("telemetrySseSub"),
    sseBadge: document.getElementById("sseBadge"),
    sseFeedLog: document.getElementById("sseFeedLog"),

    // Tour
    tourOverlay: document.getElementById("tourOverlay"),
    tourStepTag: document.getElementById("tourStepTag"),
    tourStepTitle: document.getElementById("tourStepTitle"),
    tourStepDesc: document.getElementById("tourStepDesc"),
    tourPrevBtn: document.getElementById("tourPrevBtn"),
    tourNextBtn: document.getElementById("tourNextBtn"),
    tourCloseBtn: document.getElementById("tourCloseBtn"),

    // Toast
    toastContainer: document.getElementById("toastContainer"),
  };

  // Toast Helper
  function showToast(msg) {
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = msg;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 4000);
  }

  // Safe DOM Helper: set text content
  function setText(element, text) {
    if (element) {
      element.textContent = text != null ? String(text) : "";
    }
  }

  // Clear Children
  function clearChildren(parent) {
    while (parent && parent.firstChild) {
      parent.removeChild(parent.firstChild);
    }
  }

  // Append SSE feed line
  function appendSseLine(prefix, text) {
    const entry = document.createElement("div");
    entry.className = "feed-entry";
    const timeStr = new Date().toLocaleTimeString();
    entry.textContent = `[${timeStr}] ${prefix} ${text}`;
    el.sseFeedLog.appendChild(entry);
    el.sseFeedLog.scrollTop = el.sseFeedLog.scrollHeight;
  }

  // Initialize
  async function init() {
    setupEventListeners();
    await loadConfig();
    await loadAgents();
    await loadScenarios();
    await checkAuditChain();
    await loadPendingApprovals();
    initSseStream();

    // Check tour query param
    const params = new URLSearchParams(window.location.search);
    if (params.get("tour") === "1") {
      startTour();
    }
  }

  // 1. Load Public Config
  async function loadConfig() {
    try {
      const res = await fetch("/v1/public/config");
      if (res.ok) {
        const data = await res.json();
        state.clientKey = data.client_key || "";
      }
    } catch (e) {
      console.warn("Could not load /v1/public/config:", e);
    }
  }

  // 2. Load Agents
  async function loadAgents() {
    try {
      const res = await fetch("/v1/public/agents");
      if (res.ok) {
        state.agents = await res.json();
        updateAgentUI();
      }
    } catch (e) {
      console.warn("Could not load /v1/public/agents:", e);
    }
  }

  function updateAgentUI() {
    const current = state.agents.find((a) => a.agent_id === state.activeAgentId);
    if (current) {
      setText(el.activeAgentLabel, current.name || current.agent_id);
      setText(el.policySummaryText, current.allowed_tools_summary || current.description);
    }

    // Update pill buttons active state
    const pills = el.agentPills.querySelectorAll(".pill-btn");
    pills.forEach((p) => {
      if (p.getAttribute("data-agent") === state.activeAgentId) {
        p.classList.add("active");
      } else {
        p.classList.remove("active");
      }
    });
  }

  // 3. Load Scenarios
  async function loadScenarios() {
    try {
      const res = await fetch("/static/scenarios.json");
      if (res.ok) {
        state.scenarios = await res.json();
        renderScenarioDropdown();
        // Select initial scenario
        selectScenario(state.activeScenarioId || (state.scenarios[0] && state.scenarios[0].id));
      }
    } catch (e) {
      console.warn("Could not load /static/scenarios.json:", e);
    }
  }

  function renderScenarioDropdown() {
    clearChildren(el.scenarioSelect);

    const filtered = state.scenarios.filter((s) => {
      if (state.activeCategory === "all") return true;
      return s.category === state.activeCategory;
    });

    filtered.forEach((scen) => {
      const opt = document.createElement("option");
      opt.value = scen.id;
      opt.textContent = `${scen.title} (${scen.expected_verdict})`;
      if (scen.id === state.activeScenarioId) {
        opt.selected = true;
      }
      el.scenarioSelect.appendChild(opt);
    });
  }

  function selectScenario(id) {
    const scen = state.scenarios.find((s) => s.id === id);
    if (!scen) return;
    state.activeScenarioId = id;

    // Switch active agent if target_agent is specified
    if (scen.target_agent) {
      state.activeAgentId = scen.target_agent;
      updateAgentUI();
    }

    // Populate inputs
    el.userPromptInput.value = scen.user_prompt || "";
    el.untrustedDocInput.value = scen.untrusted_context || "";

    // Update scenario context card
    setText(el.scenBadge, scen.category.toUpperCase().replace("_", " "));
    setText(el.scenExpected, `EXPECTED: ${scen.expected_verdict}`);
    setText(el.scenTitle, scen.title);
    setText(el.scenWhy, scen.why);
    setText(el.shieldOffOutcomeText, scen.shield_off_outcome);

    // Update dropdown value
    el.scenarioSelect.value = id;
  }

  // 4. Shield Toggle
  function setShieldState(enabled) {
    state.shieldEnabled = enabled;
    if (enabled) {
      el.shieldToggle.classList.add("switch-on");
      el.shieldToggle.classList.remove("switch-off");
      el.shieldToggle.setAttribute("aria-pressed", "true");
      el.headerShieldChip.classList.add("chip-shield-on");
      el.headerShieldChip.classList.remove("chip-shield-off");
      setText(el.headerShieldVal, "SHIELD ACTIVE");
      setText(el.btnRunLabel, "Run With Shield ON");
      setText(
        el.shieldToggleHint,
        "Tether multi-layer gate active: inbound scan, taint escalation, permission checks, audit logging."
      );
    } else {
      el.shieldToggle.classList.add("switch-off");
      el.shieldToggle.classList.remove("switch-on");
      el.shieldToggle.setAttribute("aria-pressed", "false");
      el.headerShieldChip.classList.add("chip-shield-off");
      el.headerShieldChip.classList.remove("chip-shield-on");
      setText(el.headerShieldVal, "SHIELD DISABLED");
      setText(el.btnRunLabel, "Run With Shield OFF");
      setText(
        el.shieldToggleHint,
        "Gateway bypassed: agent naively executes prompts and documents without security validation."
      );
    }
  }

  // 5. Execute Request
  async function executeChat(shieldEnabled) {
    const userPrompt = el.userPromptInput.value.trim();
    const untrustedDoc = el.untrustedDocInput.value.trim();

    const documents = [];
    if (untrustedDoc) {
      documents.push({
        source: "external://untrusted_context_document.txt",
        content: untrustedDoc,
        type: "rag",
      });
    }

    const payload = {
      agent_id: state.activeAgentId,
      message: userPrompt,
      documents: documents,
      shield_enabled: shieldEnabled,
    };

    const headers = { "Content-Type": "application/json" };
    if (state.clientKey) {
      headers["X-API-Key"] = state.clientKey;
    }

    const t0 = performance.now();
    try {
      const resp = await fetch("/v1/chat", {
        method: "POST",
        headers: headers,
        body: JSON.stringify(payload),
      });

      const t1 = performance.now();
      const latencyMs = Math.round(t1 - t0);

      if (!resp.ok) {
        let errDetail = `Status ${resp.status}`;
        try {
          const errData = await resp.json();
          errDetail = errData.detail || errData.message || errDetail;
        } catch (_) {}
        return {
          error: true,
          status: resp.status,
          message: `Request failed: ${errDetail}`,
          latencyMs: latencyMs,
        };
      }

      const data = await resp.json();
      data.client_latency_ms = latencyMs;
      return data;
    } catch (networkErr) {
      const t1 = performance.now();
      return {
        error: true,
        status: 0,
        message: `Request failed: ${networkErr.message || "Network unreachable"}`,
        latencyMs: Math.round(t1 - t0),
      };
    }
  }

  // Render Shield ON Panel
  function renderShieldOnResult(result) {
    if (result.error) {
      // Error state: show "Request failed: <reason>" with no score or verdict badge
      setText(el.shieldOnVerdict, "ERROR");
      el.shieldOnVerdict.className = "verdict-badge badge-block";
      setText(el.shieldOnRisk, "—");
      setText(el.shieldOnLayer, "—");
      setText(el.shieldOnLatency, `${result.latencyMs}ms`);
      setText(el.shieldOnResponseTitle, "Gateway Error");
      setText(el.shieldOnResponseText, result.message);
      clearChildren(el.shieldOnFindings);
      clearChildren(el.shieldOnTools);
      return;
    }

    // Left panel title renaming per User Feedback:
    // "Agent response" when verdict is ALLOW, "Safe refusal" only for BLOCK
    if (result.verdict === "ALLOW") {
      setText(el.shieldOnResponseTitle, "Agent response");
      setText(el.shieldOnVerdict, "ALLOW");
      el.shieldOnVerdict.className = "verdict-badge badge-allow";
    } else if (result.verdict === "BLOCK") {
      setText(el.shieldOnResponseTitle, "Safe refusal");
      setText(el.shieldOnVerdict, "BLOCK");
      el.shieldOnVerdict.className = "verdict-badge badge-block";
    } else if (result.verdict === "REQUIRE_APPROVAL") {
      setText(el.shieldOnResponseTitle, "Action Pending Approval");
      setText(el.shieldOnVerdict, "REQUIRE_APPROVAL");
      el.shieldOnVerdict.className = "verdict-badge badge-approval";
    } else {
      setText(el.shieldOnResponseTitle, "Agent response");
      setText(el.shieldOnVerdict, result.verdict);
      el.shieldOnVerdict.className = "verdict-badge badge-neutral";
    }

    setText(el.shieldOnRisk, result.risk_score != null ? `${result.risk_score.toFixed(1)}/100` : "0.0/100");

    // Intercepting layer determination
    let layer = "None";
    if (result.findings && result.findings.length > 0) {
      layer = "Detector";
    } else if (result.tool_calls && result.tool_calls.some((t) => t.verdict === "DENY")) {
      layer = "Permission Layer";
    } else if (result.verdict === "REQUIRE_APPROVAL") {
      layer = "Human-in-the-Loop";
    }
    setText(el.shieldOnLayer, layer);
    setText(el.shieldOnLatency, `${result.latency_ms || result.client_latency_ms}ms`);
    setText(el.shieldOnResponseText, result.response);

    // Findings
    clearChildren(el.shieldOnFindings);
    if (result.findings && result.findings.length > 0) {
      result.findings.forEach((f) => {
        const chip = document.createElement("span");
        chip.className = "finding-chip";
        chip.textContent = `${f.rule_id || "FINDING"} (${f.confidence ? (f.confidence * 100).toFixed(0) : "100"}%): ${f.description || ""}`;
        el.shieldOnFindings.appendChild(chip);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "empty-state";
      empty.textContent = "No detector anomalies found.";
      el.shieldOnFindings.appendChild(empty);
    }

    // Tool decisions
    clearChildren(el.shieldOnTools);
    if (result.tool_calls && result.tool_calls.length > 0) {
      result.tool_calls.forEach((t) => {
        const item = document.createElement("div");
        item.className = "tool-chip";

        const nameSpan = document.createElement("span");
        nameSpan.textContent = `${t.tool_name}(${JSON.stringify(t.args || {})})`;

        const verdictSpan = document.createElement("span");
        verdictSpan.className = `verdict-badge ${t.verdict === "ALLOW" ? "badge-allow" : t.verdict === "REQUIRE_APPROVAL" ? "badge-approval" : "badge-block"}`;
        verdictSpan.textContent = t.verdict;

        item.appendChild(nameSpan);
        item.appendChild(verdictSpan);
        el.shieldOnTools.appendChild(item);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "empty-state";
      empty.textContent = "No tool invocations proposed.";
      el.shieldOnTools.appendChild(empty);
    }

    // Refresh pending approvals if any were generated
    if (result.pending_approvals && result.pending_approvals.length > 0) {
      loadPendingApprovals();
    }
  }

  // Render Shield OFF Panel (Dynamic status text per User Feedback)
  function renderShieldOffResult(result) {
    if (result.error) {
      setText(el.shieldOffVerdict, "ERROR");
      el.shieldOffVerdict.className = "verdict-badge badge-block";
      setText(el.shieldOffStatus, "Error");
      setText(el.shieldOffLatency, `${result.latencyMs}ms`);
      setText(el.shieldOffResponseText, result.message);
      clearChildren(el.shieldOffTools);
      el.shieldOffResponseText.classList.remove("bypass-alert");
      return;
    }

    const toolCalls = result.tool_calls || [];
    const hasTools = toolCalls.length > 0;

    // Check if risky tool actions or potential exfiltrations were attempted
    const isRisky = toolCalls.some((t) => {
      const name = (t.tool_name || "").toLowerCase();
      const argsStr = JSON.stringify(t.args || {}).toLowerCase();
      return (
        name.includes("email") ||
        name.includes("bash") ||
        name.includes("http") ||
        name.includes("file") ||
        name.includes("transfer") ||
        argsStr.includes("attacker") ||
        argsStr.includes("evil.com") ||
        argsStr.includes(".env")
      );
    });

    // 1. Right panel status text derived from real response
    if (!hasTools) {
      setText(el.shieldOffStatus, "Executed: no tool actions");
      setText(el.shieldOffVerdict, "SAFE EXECUTION");
      el.shieldOffVerdict.className = "verdict-badge badge-neutral";
      el.shieldOffResponseText.classList.remove("bypass-alert");
    } else {
      const toolDescriptions = toolCalls.map((t) => {
        if (t.tool_name === "send_email" && t.args && t.args.to) {
          return `Attempted send_email to ${t.args.to}`;
        }
        if (t.tool_name === "http_request" && t.args && t.args.url) {
          return `Attempted http_request to ${t.args.url}`;
        }
        if (t.tool_name === "read_file" && t.args && t.args.path) {
          return `Attempted read_file on ${t.args.path}`;
        }
        if (t.tool_name === "execute_bash") {
          return `Attempted execute_bash`;
        }
        if (t.tool_name === "transfer_funds") {
          return `Attempted transfer_funds of $${t.args?.amount || 0}`;
        }
        return `Attempted ${t.tool_name}`;
      });

      setText(el.shieldOffStatus, toolDescriptions.join(", "));

      if (isRisky) {
        setText(el.shieldOffVerdict, "UNPROTECTED BYPASS");
        el.shieldOffVerdict.className = "verdict-badge badge-bypass";
        el.shieldOffResponseText.classList.add("bypass-alert");
      } else {
        setText(el.shieldOffVerdict, "EXECUTED");
        el.shieldOffVerdict.className = "verdict-badge badge-neutral";
        el.shieldOffResponseText.classList.remove("bypass-alert");
      }
    }

    setText(el.shieldOffLatency, `${result.latency_ms || result.client_latency_ms}ms`);
    setText(el.shieldOffResponseText, result.response);

    // Tool actions list
    clearChildren(el.shieldOffTools);
    if (hasTools) {
      toolCalls.forEach((t) => {
        const item = document.createElement("div");
        item.className = "tool-chip";

        const nameSpan = document.createElement("span");
        nameSpan.textContent = `${t.tool_name}(${JSON.stringify(t.args || {})})`;

        const verdictSpan = document.createElement("span");
        verdictSpan.className = `verdict-badge ${isRisky ? "badge-block" : "badge-neutral"}`;
        verdictSpan.textContent = "DISPATCHED";

        item.appendChild(nameSpan);
        item.appendChild(verdictSpan);
        el.shieldOffTools.appendChild(item);
      });
    } else {
      const empty = document.createElement("span");
      empty.className = "empty-state";
      empty.textContent = "No unshielded tools recorded.";
      el.shieldOffTools.appendChild(empty);
    }
  }

  // Run Current Shield State
  async function handleRunCurrent() {
    el.btnRun.disabled = true;
    setText(el.btnRunLabel, "Evaluating...");
    setText(el.deckModeIndicator, state.shieldEnabled ? "SHIELD ACTIVE" : "SHIELD BYPASS");

    const result = await executeChat(state.shieldEnabled);

    if (state.shieldEnabled) {
      renderShieldOnResult(result);
    } else {
      renderShieldOffResult(result);
    }

    el.btnRun.disabled = false;
    setText(el.btnRunLabel, state.shieldEnabled ? "Run With Shield ON" : "Run With Shield OFF");
  }

  // Run Side-by-Side (Shield OFF vs ON)
  async function handleRunSideBySide() {
    el.btnSideBySide.disabled = true;
    setText(el.deckModeIndicator, "SIDE-BY-SIDE COMPARISON");

    // Indicate loading
    setText(el.shieldOnVerdict, "RUNNING");
    setText(el.shieldOffVerdict, "RUNNING");

    // Fire in parallel
    const [resOff, resOn] = await Promise.all([executeChat(false), executeChat(true)]);

    renderShieldOnResult(resOn);
    renderShieldOffResult(resOff);

    el.btnSideBySide.disabled = false;
    showToast("Side-by-side execution finished. Compare results above.");
  }

  // 6. Approvals Management
  async function loadPendingApprovals() {
    try {
      const headers = {};
      if (state.clientKey) headers["X-API-Key"] = state.clientKey;

      const res = await fetch("/v1/demo/approvals", { headers: headers });
      if (res.ok) {
        const items = await res.json();
        renderApprovals(items);
      }
    } catch (e) {
      console.warn("Could not load /v1/demo/approvals:", e);
    }
  }

  function renderApprovals(items) {
    setText(el.pendingApprovalsCount, `${items.length} PENDING`);
    clearChildren(el.approvalsList);

    if (!items || items.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-state-card";
      empty.textContent =
        "No pending approvals. Run Scenario 5 (Indirect Injection) or Scenario 14 (High-Value Transfer) to generate an approval checkpoint.";
      el.approvalsList.appendChild(empty);
      return;
    }

    items.forEach((item) => {
      const card = document.createElement("div");
      card.className = "approval-item-card";

      const topRow = document.createElement("div");
      topRow.className = "approval-card-top";

      const toolName = document.createElement("span");
      toolName.className = "approval-tool-name";
      toolName.textContent = `AGENT: ${item.agent_id} // TOOL: ${item.tool_name}`;

      const riskBadge = document.createElement("span");
      riskBadge.className = "badge-count";
      riskBadge.textContent = `RISK: ${item.risk_score ? item.risk_score.toFixed(0) : "N/A"}`;

      topRow.appendChild(toolName);
      topRow.appendChild(riskBadge);

      const reason = document.createElement("div");
      reason.className = "approval-reason";
      reason.textContent = `Reason: ${item.reason || "High-risk tool operation requires approval"}`;

      const argsBox = document.createElement("div");
      argsBox.className = "response-box text-sm";
      argsBox.textContent = `Arguments: ${JSON.stringify(item.args_redacted || {})}`;

      const actionsRow = document.createElement("div");
      actionsRow.className = "approval-actions";

      const btnApprove = document.createElement("button");
      btnApprove.className = "btn btn-sm btn-approve";
      btnApprove.textContent = "✔ Authorize Tool Call";
      btnApprove.onclick = async () => {
        btnApprove.disabled = true;
        await resolveApproval(item.id, true);
      };

      const btnReject = document.createElement("button");
      btnReject.className = "btn btn-sm btn-reject";
      btnReject.textContent = "✕ Refuse / Block";
      btnReject.onclick = async () => {
        btnReject.disabled = true;
        await resolveApproval(item.id, false);
      };

      actionsRow.appendChild(btnApprove);
      actionsRow.appendChild(btnReject);

      card.appendChild(topRow);
      card.appendChild(reason);
      card.appendChild(argsBox);
      card.appendChild(actionsRow);

      el.approvalsList.appendChild(card);
    });
  }

  async function resolveApproval(approvalId, isApprove) {
    const endpoint = `/v1/demo/approvals/${approvalId}/${isApprove ? "approve" : "reject"}`;
    try {
      const headers = { "Content-Type": "application/json" };
      if (state.clientKey) headers["X-API-Key"] = state.clientKey;

      const res = await fetch(endpoint, { method: "POST", headers: headers });
      if (res.ok) {
        const data = await res.json();
        const actionLabel = isApprove ? "Approved" : "Rejected";
        showToast(
          `Approval ${actionLabel}! ${data.capability_token ? "Capability Token Issued." : ""}`
        );
        await loadPendingApprovals();
        await checkAuditChain();
      } else {
        const err = await res.json();
        showToast(`Approval failed: ${err.detail || "Server error"}`);
      }
    } catch (e) {
      showToast(`Error: ${e.message}`);
    }
  }

  // 7. Cryptographic Audit Chain Verification
  async function checkAuditChain() {
    try {
      const res = await fetch("/v1/public/audit/verify");
      if (res.ok) {
        const data = await res.json();
        if (data.is_valid) {
          setText(el.telemetryAuditStatus, "VERIFIED");
          el.telemetryAuditStatus.className = "cell-val color-green";
          setText(el.telemetryAuditSub, `${data.total_records} Chain Records`);

          setText(el.auditBadge, "VALID (TAMPER-EVIDENT)");
          el.auditBadge.className = "status-badge status-valid";
          setText(
            el.auditMsg,
            `Cryptographic forward hash chain intact across all ${data.total_records} audit entries.`
          );
          setText(
            el.auditMeta,
            `Head Hash: ${data.head_hash ? data.head_hash.substring(0, 32) : "genesis"}... | Total Records: ${data.total_records}`
          );
        } else {
          setText(el.telemetryAuditStatus, "CORRUPTED");
          el.telemetryAuditStatus.className = "cell-val color-red";

          setText(el.auditBadge, "TAMPER DETECTED");
          el.auditBadge.className = "status-badge status-invalid";
          setText(el.auditMsg, data.message || "Audit record verification mismatch.");
        }
      }
    } catch (e) {
      setText(el.auditMsg, "Could not reach audit verify endpoint.");
    }
  }

  // 8. Demo Reset
  async function handleDemoReset() {
    el.btnDemoReset.disabled = true;
    setText(el.btnDemoReset, "Resetting...");

    try {
      const res = await fetch("/v1/demo/reset", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        showToast("Demo state reset: pending approvals cleared, session taint cleared.");
        await loadPendingApprovals();
        await checkAuditChain();
      } else if (res.status === 429) {
        const data = await res.json();
        showToast(`Rate limit: ${data.detail || "Please wait 10s"}`);
      } else {
        showToast("Reset failed.");
      }
    } catch (e) {
      showToast(`Reset error: ${e.message}`);
    } finally {
      el.btnDemoReset.disabled = false;
      setText(el.btnDemoReset, "↺ Reset Demo");
    }
  }

  // 9. SSE Stream
  async function initSseStream() {
    try {
      const headers = { "Content-Type": "application/json" };
      if (state.clientKey) headers["X-API-Key"] = state.clientKey;

      const tokenRes = await fetch("/v1/events/token", { method: "POST", headers: headers });
      if (!tokenRes.ok) {
        setText(el.telemetrySseStatus, "TOKEN ERR");
        setText(el.sseBadge, "OFFLINE");
        return;
      }

      const tokenData = await tokenRes.json();
      const sseToken = tokenData.sse_token;
      if (!sseToken) return;

      const evtSource = new EventSource(`/v1/events?token=${encodeURIComponent(sseToken)}`);
      state.sseEventSource = evtSource;

      evtSource.onopen = () => {
        setText(el.telemetrySseStatus, "LIVE (SSE)");
        el.telemetrySseStatus.className = "cell-val color-green";
        setText(el.sseBadge, "STREAMING");
        appendSseLine("[SYSTEM]", "SSE stream established. Listening for gateway audit events.");
      };

      evtSource.addEventListener("chat_event", (e) => {
        try {
          const payload = JSON.parse(e.data);
          const verdictStr = payload.verdict || "DECISION";
          const score = payload.risk_score != null ? payload.risk_score.toFixed(1) : "0.0";
          appendSseLine(
            `[VERDICT: ${verdictStr}]`,
            `Request ID: ${payload.request_id || "N/A"} | Risk Score: ${score} | Shield: ${payload.shield_enabled ? "ON" : "OFF"}`
          );
        } catch (_) {}
      });

      evtSource.addEventListener("audit_event", (e) => {
        try {
          const payload = JSON.parse(e.data);
          appendSseLine(
            "[AUDIT LOGGED]",
            `Action: ${payload.action_type || "chat"} | Agent: ${payload.agent_id} | Hash: ${(payload.current_hash || "").substring(0, 16)}...`
          );
          checkAuditChain();
        } catch (_) {}
      });

      evtSource.onerror = () => {
        setText(el.telemetrySseStatus, "RECONNECTING");
        setText(el.sseBadge, "RETRYING");
      };
    } catch (e) {
      console.warn("SSE init error:", e);
    }
  }

  // 10. Interactive 60-Second Guided Tour
  const TOUR_STEPS = [
    {
      targetId: "stepAgent",
      stepTag: "STEP 1 OF 5",
      title: "Step 1: Select Target AI Agent",
      desc: "Each agent runs with a unique least-privilege policy. MailBot is permitted to email internal company domains (@company.com), but restricted from dangerous system tools.",
      action: () => {
        state.activeAgentId = "default_agent";
        updateAgentUI();
      },
    },
    {
      targetId: "stepScenario",
      stepTag: "STEP 2 OF 5",
      title: "Step 2: Load Poisoned Document Scenario",
      desc: "We will load Scenario 5 (Indirect Prompt Injection). A malicious external document instructs MailBot to exfiltrate confidential data to attacker@evil.com.",
      action: () => {
        selectScenario("scenario_05");
      },
    },
    {
      targetId: "stepExecute",
      stepTag: "STEP 3 OF 5",
      title: "Step 3: Run Side-by-Side Comparison",
      desc: "Click 'Run Side-by-Side'. On the right, the unprotected agent naively obeys the injected instruction. On the left, Tether detects the untrusted document taint, halts execution, and generates a Human Approval checkpoint.",
      action: () => {
        handleRunSideBySide();
      },
    },
    {
      targetId: "stepApproval",
      stepTag: "STEP 4 OF 5",
      title: "Step 4: Human-in-the-Loop Approval",
      desc: "Observe the pending approval generated below. Notice how Tether's taint escalation prevents unprompted tool actions from firing until an authorized operator inspects the payload.",
      action: () => {
        el.stepApproval.scrollIntoView({ behavior: "smooth" });
      },
    },
    {
      targetId: "stepAudit",
      stepTag: "STEP 5 OF 5",
      title: "Step 5: Cryptographic Chain Verification",
      desc: "Every gateway event is cryptographically linked with HMAC-SHA256 forward hashes. Click 'Verify Hash Chain' to mathematically verify that the audit log has zero broken links or tampered entries.",
      action: () => {
        checkAuditChain();
      },
    },
  ];

  function startTour() {
    state.currentTourStep = 0;
    renderTourStep();
    el.tourOverlay.classList.remove("hidden");
  }

  function renderTourStep() {
    const s = TOUR_STEPS[state.currentTourStep];
    if (!s) return;

    setText(el.tourStepTag, s.stepTag);
    setText(el.tourStepTitle, s.title);
    setText(el.tourStepDesc, s.desc);

    el.tourPrevBtn.disabled = state.currentTourStep === 0;
    setText(el.tourNextBtn, state.currentTourStep === TOUR_STEPS.length - 1 ? "Finish Tour ✓" : "Next Step →");

    // Remove previous highlights
    document.querySelectorAll(".tour-highlight").forEach((node) => node.classList.remove("tour-highlight"));

    // Highlight target element if present
    if (s.targetId) {
      const target = document.getElementById(s.targetId);
      if (target) {
        target.classList.add("tour-highlight");
        target.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }

    // Execute step action
    if (typeof s.action === "function") {
      s.action();
    }
  }

  function nextTourStep() {
    if (state.currentTourStep < TOUR_STEPS.length - 1) {
      state.currentTourStep++;
      renderTourStep();
    } else {
      closeTour();
      showToast("Tour completed! Feel free to explore all 16 scenarios.");
    }
  }

  function prevTourStep() {
    if (state.currentTourStep > 0) {
      state.currentTourStep--;
      renderTourStep();
    }
  }

  function closeTour() {
    el.tourOverlay.classList.add("hidden");
    document.querySelectorAll(".tour-highlight").forEach((node) => node.classList.remove("tour-highlight"));
  }

  // Event Listeners
  function setupEventListeners() {
    // Agent Pills
    el.agentPills.addEventListener("click", (e) => {
      const btn = e.target.closest(".pill-btn");
      if (btn) {
        const agentId = btn.getAttribute("data-agent");
        if (agentId) {
          state.activeAgentId = agentId;
          updateAgentUI();
        }
      }
    });

    // Shield Toggle
    el.shieldToggle.addEventListener("click", () => {
      setShieldState(!state.shieldEnabled);
    });

    // Category Filters
    el.categoryFilters.addEventListener("click", (e) => {
      const btn = e.target.closest(".cat-btn");
      if (btn) {
        el.categoryFilters.querySelectorAll(".cat-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.activeCategory = btn.getAttribute("data-cat") || "all";
        renderScenarioDropdown();
        // Select first visible scenario
        const firstVisible = state.scenarios.find(
          (s) => state.activeCategory === "all" || s.category === state.activeCategory
        );
        if (firstVisible) {
          selectScenario(firstVisible.id);
        }
      }
    });

    // Scenario Select Dropdown
    el.scenarioSelect.addEventListener("change", (e) => {
      selectScenario(e.target.value);
    });

    // Action Buttons
    el.btnRun.addEventListener("click", handleRunCurrent);
    el.btnSideBySide.addEventListener("click", handleRunSideBySide);
    el.btnDemoReset.addEventListener("click", handleDemoReset);
    el.btnVerifyAudit.addEventListener("click", checkAuditChain);
    el.btnTour.addEventListener("click", startTour);

    // Tour Modal Controls
    el.tourCloseBtn.addEventListener("click", closeTour);
    el.tourNextBtn.addEventListener("click", nextTourStep);
    el.tourPrevBtn.addEventListener("click", prevTourStep);
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
