"""Multi-layered adversarial detector with ensemble scoring and fail-closed timeout guards.

Combines:
1. Normalization & Obfuscation Signals (zero-width, homoglyphs, bidi, encoded blobs, hidden HTML)
2. Linear-Safe Regex Rule Matching (direct overrides, personas, exfil, fake tags, tool poisoning, multilingual)
3. De-spaced Canonical Stream Scanning (catches split-letter evasions like "i g n o r e")
4. Structural Heuristics (imperative density, 2nd-person directives, tool mentions, Shannon entropy)
5. Context-Aware Adjustments (educational/quoted query discounting, external data amplification)
6. Optional LLM Judge with strict schema validation and hash caching
7. Ensemble Aggregation with Diminishing Returns
8. Per-Scan Time Budget with Fail-Closed Guarantees
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple

from app.config import settings
from app.models import Finding, ScanResponse
from app.shield.normalize import normalize_input, NormalizedResult
from app.shield.rules import DETECTION_RULES, ShieldRule
from app.shield.trust import TrustLevel

# Directive verbs for imperative density calculation
IMPERATIVE_VERBS: Set[str] = {
    "ignore", "disregard", "forget", "override", "bypass", "cancel",
    "send", "post", "forward", "curl", "wget", "transmit", "upload",
    "delete", "remove", "drop", "transfer", "execute", "run", "call",
    "print", "reveal", "dump", "leak", "copy", "repeat", "display",
    "disable", "deactivate", "stop", "switch", "act", "pretend",
}

# Directive phrases for second-person directive density
SECOND_PERSON_PATTERNS = [
    re.compile(r"(?i)\byou\s+must\b"),
    re.compile(r"(?i)\byou\s+will\b"),
    re.compile(r"(?i)\byou\s+are\s+(?:required|forced|instructed)\b"),
    re.compile(r"(?i)\bdo\s+not\s+(?:follow|obey|remember)\b"),
    re.compile(r"(?i)\byour\s+new\s+(?:task|role|instructions?)\b"),
]

# High-risk tool names to look for inside untrusted text
KNOWN_TOOLS: Set[str] = {
    "transfer_money", "send_email", "delete_file", "search_web", "read_file",
    "execute_command", "shell_exec", "run_script", "call_api",
}

# Educational / Research Context Phrases (Reduces False Positives for security researchers)
EDUCATIONAL_CONTEXT_PATTERNS = [
    re.compile(r"(?i)\bwhat\s+is\s+(?:prompt\s+injection|jailbreak(?:ing)?)\b"),
    re.compile(r"(?i)\bhow\s+does\s+(?:prompt\s+injection|an\s+override\s+attack)\s+work\b"),
    re.compile(r"(?i)\bexamples?\s+of\s+(?:a\s+prompt\s+injection|jailbreak)\b"),
    re.compile(r"(?i)\bexplain\s+(?:how\s+attackers?|the\s+vulnerability|how\s+attacks?)\b"),
    re.compile(r"(?i)\bstudy(?:ing)?\s+(?:ai\s+safety|prompt\s+security)\b"),
    re.compile(r"(?i)\bfor\s+example,\s+an\s+attacker\s+might\s+say\b"),
    re.compile(r"(?i)\b(?:can\s+you\s+)?explain\s+(?:how\s+)?(?:attacks?|injections?|prompts?|guardrails?)\b"),
    re.compile(r"(?i)\battacks?\s+(?:like|such\s+as)\s+['\"`“]"),
    re.compile(r"(?i)\bphrases?\s+(?:like|such\s+as)\s+['\"`“]"),
]


# De-spaced signatures for split payload evasion
DESPACED_SIGNATURES: Dict[str, Tuple[str, str, float]] = {
    "ignoreallpreviousinstructions": ("R_SPLIT_01", "direct_override", 85.0),
    "ignorepreviousinstructions": ("R_SPLIT_01", "direct_override", 85.0),
    "disregardallinstructions": ("R_SPLIT_01", "direct_override", 85.0),
    "youarenowdan": ("R_SPLIT_02", "role_reassignment", 90.0),
    "repeatthewordsabove": ("R_SPLIT_03", "system_prompt_extraction", 80.0),
    "printyourprompt": ("R_SPLIT_03", "system_prompt_extraction", 80.0),
    "transfermoney": ("R_SPLIT_04", "tool_poisoning", 85.0),
    "webhooksite": ("R_SPLIT_05", "data_exfiltration", 85.0),
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of text to detect high-entropy encoded or encrypted payloads."""
    if not text or len(text) < 16:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
    return entropy


def compute_imperative_density(text: str) -> float:
    """Computes ratio of imperative directive verbs relative to word count."""
    words = [w.lower().strip(".,!?;:\"'()") for w in text.split()]
    if not words:
        return 0.0
    imperative_count = sum(1 for w in words if w in IMPERATIVE_VERBS)
    return imperative_count / len(words)


def compute_second_person_density(text: str) -> int:
    """Counts occurrences of second-person command patterns."""
    return sum(len(p.findall(text)) for p in SECOND_PERSON_PATTERNS)


def check_educational_context(text: str) -> bool:
    """Checks if text appears to be an educational or analytical inquiry about security."""
    return any(p.search(text) is not None for p in EDUCATIONAL_CONTEXT_PATTERNS)


class Detector:
    """Adversarial security detector implementing layered analysis and ensemble scoring."""

    def __init__(
        self,
        rules: Optional[List[ShieldRule]] = None,
        max_scan_time_ms: Optional[int] = None,
    ):
        self.rules = rules or DETECTION_RULES
        self.max_scan_time_ms = max_scan_time_ms or settings.max_scan_time_ms

    def scan_text(
        self,
        raw_text: str,
        trust_level: TrustLevel = TrustLevel.EXTERNAL,
        source_id: Optional[str] = None,
    ) -> ScanResponse:
        """Main detection function analyzing text across all defense layers."""
        start_time = time.perf_counter()

        if not raw_text or not raw_text.strip():
            return ScanResponse(
                risk_score=0.0,
                verdict="ALLOW",
                findings=[],
                reason_codes=["EMPTY_INPUT"],
                explanation="Input text is empty. Allowed by default.",
                normalization_signals=[],
                normalized_length=0,
                scan_time_ms=0.0,
            )

        # 1. Normalization & De-obfuscation Layer
        norm_res: NormalizedResult = normalize_input(raw_text)
        normalized_text = norm_res.normalized_text
        despaced_text = norm_res.despaced_text
        obfuscation_signals = norm_res.obfuscation_signals

        findings: List[Finding] = []
        reason_codes: List[str] = []

        # 2. Rule-Based Regex Scanning on Normalized Text
        matched_rule_spans: List[Tuple[int, int]] = []
        for rule in self.rules:
            # Check elapsed time for performance guard
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            if elapsed_ms > self.max_scan_time_ms:
                reason_code = (
                    "SCAN_TIMEOUT_FAIL_CLOSED_EXTERNAL"
                    if trust_level == TrustLevel.EXTERNAL
                    else "SCAN_TIMEOUT_FLAG"
                )
                verdict = "BLOCK" if trust_level == TrustLevel.EXTERNAL else "FLAG"
                return ScanResponse(
                    risk_score=80.0 if verdict == "BLOCK" else 50.0,
                    verdict=verdict,
                    findings=findings,
                    reason_codes=[reason_code],
                    explanation=f"Scan exceeded time budget ({self.max_scan_time_ms}ms). Fail closed.",
                    normalization_signals=obfuscation_signals,
                    normalized_length=len(normalized_text),
                    scan_time_ms=elapsed_ms,
                )

            if hasattr(rule.pattern, "finditer"):
                matches = list(rule.pattern.finditer(normalized_text))
            else:
                m_single = rule.pattern.search(normalized_text)
                matches = [m_single] if m_single else []
            if matches:
                m = matches[0]
                snippet = normalized_text[max(0, m.start() - 15) : min(len(normalized_text), m.end() + 15)]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        owasp_ref=rule.owasp_ref,
                        snippet=f"...{snippet.strip()}...",
                        weight=rule.weight,
                        location=f"idx_{m.start()}",
                    )
                )
                reason_codes.append(f"MATCH_{rule.rule_id}_{rule.category.upper()}")
                for match in matches:
                    matched_rule_spans.append((match.start(), match.end()))

        # 3. De-spaced Canonical Stream Scanning (Catches "i g n o r e", "d i s r e g a r d")
        matched_despaced_sigs: List[str] = []
        for sig, (sig_id, sig_cat, sig_weight) in DESPACED_SIGNATURES.items():
            if sig in despaced_text:
                findings.append(
                    Finding(
                        rule_id=sig_id,
                        category=sig_cat,
                        owasp_ref="LLM01:Prompt_Injection",
                        snippet=f"Split payload: '{sig}'",
                        weight=sig_weight,
                        location="despaced_stream",
                    )
                )
                reason_codes.append(f"MATCH_{sig_id}_SPLIT_PAYLOAD")
                matched_despaced_sigs.append(sig)

        # 4. Structural Heuristics Layer
        # 4a. Obfuscation Signals penalty
        if obfuscation_signals:
            boost = min(35.0, len(obfuscation_signals) * 12.0)
            findings.append(
                Finding(
                    rule_id="H_OBFUSCATION",
                    category="obfuscation_tactics",
                    owasp_ref="LLM01:Prompt_Injection",
                    snippet=f"Signals: {', '.join(obfuscation_signals[:3])}",
                    weight=boost,
                    location="normalizer",
                )
            )
            reason_codes.append("HEURISTIC_OBFUSCATION_DETECTED")

        # 4b. Imperative Directive Density
        imp_density = compute_imperative_density(normalized_text)
        if imp_density >= 0.12 and len(normalized_text.split()) >= 6:
            weight = min(40.0, imp_density * 100.0)
            findings.append(
                Finding(
                    rule_id="H_IMPERATIVE_DENSITY",
                    category="structural_heuristic",
                    owasp_ref="LLM01:Prompt_Injection",
                    snippet=f"Imperative verb ratio: {imp_density:.2%}",
                    weight=weight,
                    location="text_density",
                )
            )
            reason_codes.append("HEURISTIC_HIGH_IMPERATIVE_DENSITY")

        # 4c. Second-Person Directive Count
        sec_person_count = compute_second_person_density(normalized_text)
        if sec_person_count >= 2:
            weight = min(35.0, sec_person_count * 15.0)
            findings.append(
                Finding(
                    rule_id="H_SECOND_PERSON_DIRECTIVES",
                    category="structural_heuristic",
                    owasp_ref="LLM01:Prompt_Injection",
                    snippet=f"Found {sec_person_count} second-person directive patterns",
                    weight=weight,
                    location="directives",
                )
            )
            reason_codes.append("HEURISTIC_MULTIPLE_DIRECTIVES")

        # 4d. Tool Mentions in Untrusted Content
        if trust_level == TrustLevel.EXTERNAL:
            found_tools = [tool for tool in KNOWN_TOOLS if tool in normalized_text.lower()]
            if found_tools:
                findings.append(
                    Finding(
                        rule_id="H_UNTRUSTED_TOOL_MENTION",
                        category="tool_poisoning",
                        owasp_ref="LLM06:Excessive_Agency",
                        snippet=f"Untrusted text references tools: {found_tools}",
                        weight=65.0,
                        location="external_tool_mention",
                    )
                )
                reason_codes.append("HEURISTIC_UNTRUSTED_TOOL_MENTION")

        # 4e. High Shannon Entropy (encrypted or binary payload)
        entropy = calculate_shannon_entropy(normalized_text)
        if entropy > 5.5 and len(normalized_text) > 100:
            findings.append(
                Finding(
                    rule_id="H_HIGH_ENTROPY",
                    category="anomalous_payload",
                    owasp_ref="LLM01:Prompt_Injection",
                    snippet=f"Shannon entropy: {entropy:.2f}",
                    weight=30.0,
                    location="entropy",
                )
            )
            reason_codes.append("HEURISTIC_HIGH_ENTROPY")

        # 5. Ensemble Scoring with Diminishing Returns
        # Formula: composite = highest_weight + sum(remaining_weights) * 0.15
        if not findings:
            raw_score = 0.0
        else:
            sorted_weights = sorted([f.weight for f in findings], reverse=True)
            highest = sorted_weights[0]
            rest_sum = sum(sorted_weights[1:])
            raw_score = min(100.0, highest + (rest_sum * 0.15))

        # 6. Context-Aware Adjustments
        # 6a. Educational Context & Quoted-Phrase Discount (USER content only)
        # Distinguishes using an attack phrase (directive) from mentioning it (conceptual inquiry)
        if trust_level == TrustLevel.USER and raw_score > 0.0:
            is_educational = check_educational_context(normalized_text)

            # Extract character offset spans of quoted text in normalized_text
            quote_spans: List[Tuple[int, int]] = []
            for qm in re.finditer(r"['\"`“]([^'\"`”]{4,200})['\"`”]", normalized_text):
                quote_spans.append((qm.start(1), qm.end(1)))

            text_without_quotes = re.sub(r"['\"`“][^'\"`”]{4,200}['\"`”]", " ", normalized_text)
            has_inquiry_framing = any(
                re.search(pat, text_without_quotes, re.IGNORECASE)
                for pat in [
                    r"\b(?:explain|understand|analyze|study|meaning\s+of|definition\s+of)\b",
                    r"\b(?:how\s+do|how\s+does|why\s+do|what\s+does|can\s+you\s+explain)\b",
                    r"\b(?:attacks?|injections?|phrases?|prompts?)\s+(?:like|such\s+as)\b",
                    r"\b(?:how\s+(?:can\s+we|to|do\s+we)\s+(?:detect|mitigate|defend\s+against))\b",
                ]
            )
            is_quoted_inquiry = bool(quote_spans and has_inquiry_framing)

            # Check if all despaced signatures are inside quotes
            despaced_all_in_quotes = True
            for sig in matched_despaced_sigs:
                sig_in_any_quote = any(
                    sig in re.sub(r"\s+", "", normalized_text[q_start:q_end])
                    for q_start, q_end in quote_spans
                )
                if not sig_in_any_quote:
                    despaced_all_in_quotes = False
                    break

            # Security invariant: discount requires at least one rule match,
            # and EVERY matched span across all rule occurrences must fall strictly within a quote span.
            # If an attack phrase appears inside quotes AND outside quotes, or if an attack is outside,
            # all_in_quotes evaluates to False.
            all_in_quotes = bool(
                quote_spans
                and (matched_rule_spans or matched_despaced_sigs)
                and despaced_all_in_quotes
                and all(
                    any(q_start <= m_start and m_end <= q_end for q_start, q_end in quote_spans)
                    for m_start, m_end in matched_rule_spans
                )
            )

            if is_quoted_inquiry and all_in_quotes:
                discount = 45.0  # Calibrated discount for legitimate quoted user inquiries
                raw_score = max(0.0, raw_score - discount)
                reason_codes.append("CONTEXT_QUOTED_INQUIRY_DISCOUNT_APPLIED")
                if is_educational:
                    reason_codes.append("CONTEXT_EDUCATIONAL_DISCOUNT_APPLIED")
            elif is_educational:
                discount = 30.0
                raw_score = max(0.0, raw_score - discount)
                reason_codes.append("CONTEXT_EDUCATIONAL_DISCOUNT_APPLIED")



        # 6b. External Untrusted Amplification
        if trust_level == TrustLevel.EXTERNAL and raw_score > 0.0:
            raw_score = min(100.0, raw_score * 1.15)
            reason_codes.append("CONTEXT_EXTERNAL_DATA_AMPLIFICATION")

        final_score = round(raw_score, 1)

        # 7. Threshold Evaluation
        if trust_level == TrustLevel.EXTERNAL:
            flag_thresh = settings.external_risk_threshold_flag
            block_thresh = settings.external_risk_threshold_block
        else:
            flag_thresh = settings.user_risk_threshold_flag
            block_thresh = settings.user_risk_threshold_block

        if final_score >= block_thresh:
            verdict = "BLOCK"
            explanation = (
                f"High risk score ({final_score}/100) exceeded block threshold ({block_thresh}). "
                f"Matched critical threat patterns: {', '.join(f.category for f in findings[:2])}."
            )
        elif final_score >= flag_thresh:
            verdict = "FLAG"
            explanation = (
                f"Suspicious risk score ({final_score}/100) exceeded flag threshold ({flag_thresh}). "
                "Sanitizing content and enforcing tainted policy constraints."
            )
        else:
            verdict = "ALLOW"
            explanation = f"Clean risk score ({final_score}/100) within allowable limits."

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ScanResponse(
            risk_score=final_score,
            verdict=verdict,
            findings=findings,
            reason_codes=reason_codes,
            explanation=explanation,
            normalization_signals=obfuscation_signals,
            normalized_length=len(normalized_text),
            scan_time_ms=round(elapsed_ms, 2),
        )


detector = Detector()
