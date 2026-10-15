"""Detection rule definitions with OWASP LLM Top 10 mappings and weights.

Rules are strictly linear-safe regexes that detect:
- Direct instruction overrides and disregard directives
- Role reassignment and jailbreak personas (DAN, Developer Mode, AIM)
- System prompt extraction and leakage attempts
- Data exfiltration (HTTP POST, webhooks, URLs, emails)
- Markdown image and link auto-exfiltration
- Synthetic role tags and chat template tokens (SYSTEM:, <|im_start|>, [INST])
- Tool poisoning and tool-call syntax simulation
- Concealment phrases ("do not tell the user", "silently")
- Urgency and fake administrative authority pressure
- Multilingual instruction overrides (Hindi, Tamil, Spanish, French, German, Chinese, Arabic, Russian)
"""

from __future__ import annotations

import re
from typing import List, NamedTuple


class ShieldRule(NamedTuple):
    rule_id: str
    category: str
    owasp_ref: str
    weight: float
    description: str
    pattern: re.Pattern


DETECTION_RULES: List[ShieldRule] = [
    # -------------------------------------------------------------
    # 1. Direct Instruction Override (LLM01)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_OVR_01",
        category="direct_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Explicit directive to ignore, disregard, or override prior instructions",
        pattern=re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass|cancel|drop)\s+(?:all\s+)?(?:prior|previous|above|existing|system)?\s*(?:instructions?|directives?|prompts?|rules?|commands?|guidelines?|safety\s+constraints?)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_OVR_02",
        category="direct_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=80.0,
        description="Declaration of new operating instructions or priority override",
        pattern=re.compile(
            r"(?i)\b(?:new\s+instructions?\s+follow|your\s+new\s+task\s+is\s+now|from\s+now\s+on\s+you\s+must|stop\s+following\s+your\s+rules)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_OVR_03",
        category="direct_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=75.0,
        description="Instruction to disregard guardrails or safety guidelines",
        pattern=re.compile(
            r"(?i)\b(?:disable|bypass|deactivate|turn\s+off)\s+(?:all\s+)?(?:safety|guardrails?|content\s+filters?|moderation|policies?)\b"
        ),
    ),

    # -------------------------------------------------------------
    # 2. Role Reassignment & Jailbreak Personas (LLM01)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_JLB_01",
        category="role_reassignment",
        owasp_ref="LLM01:Prompt_Injection",
        weight=90.0,
        description="Known jailbreak personas (DAN, AIM, Developer Mode, ChaosGPT)",
        pattern=re.compile(
            r"(?i)\b(?:you\s+are\s+now\s+DAN|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak\s+mode|act\s+as\s+an\s+unfiltered\s+AI|stay\s+in\s+character\s+as\s+DAN)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_JLB_02",
        category="role_reassignment",
        owasp_ref="LLM01:Prompt_Injection",
        weight=70.0,
        description="Hypothetical or fiction-based bypass framing",
        pattern=re.compile(
            r"(?i)\b(?:for\s+hypothetical\s+purposes\s+only|in\s+a\s+fictional\s+world\s+without\s+rules|pretend\s+you\s+have\s+no\s+ethics|imagine\s+you\s+are\s+free\s+of\s+restrictions)\b"
        ),
    ),

    # -------------------------------------------------------------
    # 3. System Prompt Extraction (LLM07)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_EXT_01",
        category="system_prompt_extraction",
        owasp_ref="LLM07:System_Prompt_Leakage",
        weight=85.0,
        description="Direct instruction to reveal or print internal system instructions",
        pattern=re.compile(
            r"(?i)\b(?:print|repeat|output|reveal|dump|leak|show|copy)\s+(?:all\s+)?(?:the\s+words\s+above|(?:your\s+)?(?:full\s+)?system\s+(?:prompt|instructions?|message)|(?:all\s+)?(?:your\s+)?initial\s+(?:prompt|instructions?|directives?)|everything\s+above)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_EXT_02",
        category="system_prompt_extraction",
        owasp_ref="LLM07:System_Prompt_Leakage",
        weight=75.0,
        description="Inquiry into hidden initial instructions or canary tokens",
        pattern=re.compile(
            r"(?i)\b(?:what\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:initial|first|system)\s+(?:instructions?|rules?|prompts?)|display\s+your\s+configuration\s+text)\b"
        ),
    ),

    # -------------------------------------------------------------
    # 4. Data Exfiltration via Network & URLs (LLM02)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_EXF_01",
        category="data_exfiltration",
        owasp_ref="LLM02:Sensitive_Info_Disclosure",
        weight=90.0,
        description="Instruction to send, post, or transmit data to external endpoints",
        pattern=re.compile(
            r"(?i)\b(?:send|post|transmit|forward|curl|wget)\s+(?:all\s+)?(?:this|the\s+data|secrets?|keys?|passwords?|results?|file)\s+(?:to|via)\s+(?:https?://|webhook|http|email)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_EXF_02",
        category="data_exfiltration",
        owasp_ref="LLM02:Sensitive_Info_Disclosure",
        weight=85.0,
        description="Reference to known exfiltration webhook services",
        pattern=re.compile(
            r"(?i)\b(?:webhook\.site|requestbin\.net|pipedream\.net|ngrok\.io|burpcollaborator\.net|hookbin\.com)\b"
        ),
    ),
    ShieldRule(
        rule_id="R_EXF_03",
        category="markdown_exfil",
        owasp_ref="LLM02:Sensitive_Info_Disclosure",
        weight=95.0,
        description="Markdown image or link constructed with URL parameters for auto-exfiltration",
        pattern=re.compile(
            r"""!\[.*?\]\(\s*https?://[^\s)]+[?&](?:data|secret|token|key|leak|body|content|payload)=[^\s)]+\)""",
            flags=re.IGNORECASE,
        ),
    ),

    # -------------------------------------------------------------
    # 5. Synthetic Role Tags & Template Tokens (LLM01)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_TAG_01",
        category="fake_role_tags",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Chat template delimiter tags (ChatML, LLaMA, Anthropic)",
        pattern=re.compile(
            r"(?i)(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)"
        ),
    ),
    ShieldRule(
        rule_id="R_TAG_02",
        category="fake_role_tags",
        owasp_ref="LLM01:Prompt_Injection",
        weight=80.0,
        description="Synthetic conversation role headers",
        pattern=re.compile(
            r"(?m)^\s*(?:SYSTEM|ASSISTANT|HUMAN|AI|ADMIN)\s*:\s*[A-Z]"
        ),
    ),

    # -------------------------------------------------------------
    # 6. Tool-Call Syntax Injection & Poisoning (LLM06)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_TLS_01",
        category="tool_poisoning",
        owasp_ref="LLM06:Excessive_Agency",
        weight=90.0,
        description="Synthetic XML or JSON tool call injection syntax",
        pattern=re.compile(
            r"(?i)(?:<tool_call>|<function_call>|```json\s*\{\s*\"name\"\s*:\s*\"[a-zA-Z_]+\"|\"function\":\s*\{\"name\":)"
        ),
    ),
    ShieldRule(
        rule_id="R_TLS_02",
        category="tool_poisoning",
        owasp_ref="LLM06:Excessive_Agency",
        weight=85.0,
        description="Injected tool invocation signature",
        pattern=re.compile(
            r"(?i)\b(?:call_tool|execute_tool|invoke_function)\s*\(\s*['\"][a-zA-Z_]+['\"]"
        ),
    ),

    # -------------------------------------------------------------
    # 7. Concealment & Covert Execution (LLM01)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_CNC_01",
        category="concealment",
        owasp_ref="LLM01:Prompt_Injection",
        weight=80.0,
        description="Instructions to hide actions or conceal output from the user",
        pattern=re.compile(
            r"(?i)\b(?:do\s+not\s+(?:tell|inform|alert|warn|show)\s+(?:the\s+)?user|keep\s+this\s+(?:secret|hidden|confidential)|silently\s+execute|run\s+without\s+outputting)\b"
        ),
    ),

    # -------------------------------------------------------------
    # 8. Urgency & Authority Pressure (LLM01)
    # -------------------------------------------------------------
    ShieldRule(
        rule_id="R_URG_01",
        category="urgency_authority",
        owasp_ref="LLM01:Prompt_Injection",
        weight=65.0,
        description="Artificial urgency or fake administrative authorization claims",
        pattern=re.compile(
            r"(?i)\b(?:emergency\s+override\s+code|authorized\s+by\s+(?:root|admin|ceo)|maintenance\s+override\s+authorized|critical\s+immediate\s+action\s+required)\b"
        ),
    ),

    # -------------------------------------------------------------
    # 9. Multilingual Overrides (LLM01)
    # -------------------------------------------------------------
    # Hindi
    ShieldRule(
        rule_id="R_MUL_HI_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Hindi prompt injection override",
        pattern=re.compile(
            r"(?:पिछला\s+निर्देश\s+भूल\s+जाओ|सभी\s+पिछले\s+निर्देशों\s+को\s+अनदेखा\s+करें|नया\s+कार्य\s+शुरू\s+करें)"
        ),
    ),
    # Tamil
    ShieldRule(
        rule_id="R_MUL_TA_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Tamil prompt injection override",
        pattern=re.compile(
            r"(?:முந்தைய\s+வழிமுறைகளை\s+புறக்கணிக்கவும்|அனைத்து\s+முந்தைய\s+விதிகளையும்\s+(?:மறந்துவிடுங்கள்|மறந்துவிட்டு)|முந்தைய\s+கட்டளைகளை\s+புறக்கணிக்கவும்|முந்தைய\s+அறிவுறுத்தல்களை\s+புறக்கணிக்கவும்)"
        ),
    ),
    # Japanese
    ShieldRule(
        rule_id="R_MUL_JA_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Japanese prompt injection override",
        pattern=re.compile(
            r"(?:前の指示を(?:すべて|全て)?無視|これまでの指示を(?:すべて|全て)?無視|前のルールを忘れて|すべての指示を無視|全ての指示を無視|過去の命令を無視)"
        ),
    ),
    # Spanish
    ShieldRule(
        rule_id="R_MUL_ES_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Spanish prompt injection override",
        pattern=re.compile(
            r"(?i)\b(?:ignora\s+(?:todas\s+las\s+)?instrucciones\s+(?:anteriores|previas)|olvida\s+las\s+instrucciones\s+anteriores)\b"
        ),
    ),
    # French
    ShieldRule(
        rule_id="R_MUL_FR_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="French prompt injection override",
        pattern=re.compile(
            r"(?i)\b(?:ignorez\s+(?:toutes\s+les\s+)?instructions\s+précédentes|oubliez\s+les\s+règles\s+précédentes)\b"
        ),
    ),
    # German
    ShieldRule(
        rule_id="R_MUL_DE_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="German prompt injection override",
        pattern=re.compile(
            r"(?i)\b(?:ignoriere\s+(?:alle\s+)?vorherigen\s+(?:anweisungen|befehle)|vergiss\s+alle\s+vorherigen\s+regeln)\b"
        ),
    ),
    # Chinese (Simplified)
    ShieldRule(
        rule_id="R_MUL_ZH_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Chinese prompt injection override",
        pattern=re.compile(
            r"(?:忽略之前的所有指令|无视前面的指示|忘记所有以前的指示|从现在开始，你是一个)"
        ),
    ),
    # Arabic
    ShieldRule(
        rule_id="R_MUL_AR_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Arabic prompt injection override",
        pattern=re.compile(
            r"(?:تجاهل\s+(?:كافة|جميع)\s+التعليمات\s+السابقة|انسى\s+كافة\s+الاوامر\s+السابقة)"
        ),
    ),
    # Russian
    ShieldRule(
        rule_id="R_MUL_RU_01",
        category="multilingual_override",
        owasp_ref="LLM01:Prompt_Injection",
        weight=85.0,
        description="Russian prompt injection override",
        pattern=re.compile(
            r"(?i)\b(?:игнорируй\s+(?:все\s+)?предыдущие\s+(?:инструкции|команды)|забудь\s+все\s+предыдущие\s+правила)\b"
        ),
    ),
]
