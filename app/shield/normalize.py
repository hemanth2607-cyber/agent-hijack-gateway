"""Unicode normalization, de-obfuscation, and hidden payload extraction.

Neutralizes evasion tactics including:
- Zero-width & bidi control characters
- Unicode tag characters (U+E0000 range)
- Cyrillic & Greek homoglyph lookalikes
- HTML entities & URL-encoding
- Hidden HTML (comments, display:none, visibility:hidden, tiny fonts, alt/title attributes)
- Markdown image alt and link title concealment
- Encoded payloads (base64, hex, rot13, unicode escapes) with bounded depth/size
- Leetspeak substitution
- Split/spaced payloads (de-spaced canonical stream)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from typing import Dict, List, NamedTuple, Set, Tuple

# Cyrillic and Greek homoglyphs mapped to ASCII equivalents
HOMOGLYPH_MAP = {
    # Cyrillic lowercase
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "п": "n",
    "г": "r", "т": "t", "в": "b",
    # Cyrillic uppercase
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X",
    # Greek lowercase
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
}

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # zero-width no-break space / BOM
    "\u2060",  # word joiner
    "\u00ad",  # soft hyphen
}

# BiDi directional control overrides
BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}

# Leetspeak basic mapping
LEET_MAP = {
    "@": "a", "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "$": "s", "7": "t", "8": "b", "!": "i",
}

# Bounded decode limits to prevent decompression / regex bomb abuse
MAX_DECODE_BYTES = 50_000
MAX_DECODE_DEPTH = 3


class NormalizedResult(NamedTuple):
    normalized_text: str
    despaced_text: str
    obfuscation_signals: List[str]
    extracted_hidden_text: List[str]


def strip_zero_width_and_bidi(text: str) -> Tuple[str, List[str]]:
    """Strips zero-width and bidi characters, recording detected signals."""
    signals = []
    cleaned_chars = []
    has_zw = False
    has_bidi = False
    has_tags = False

    for char in text:
        cp = ord(char)
        if char in ZERO_WIDTH_CHARS:
            has_zw = True
            continue
        if char in BIDI_CHARS:
            has_bidi = True
            continue
        # Unicode Tag range (U+E0000 - U+E007F) used for hidden text steganography
        if 0xE0000 <= cp <= 0xE007F:
            has_tags = True
            continue
        cleaned_chars.append(char)

    if has_zw:
        signals.append("ZERO_WIDTH_CHARS_DETECTED")
    if has_bidi:
        signals.append("BIDI_CONTROL_CHARS_DETECTED")
    if has_tags:
        signals.append("UNICODE_TAGS_DETECTED")

    return "".join(cleaned_chars), signals


def fold_homoglyphs(text: str) -> Tuple[str, List[str]]:
    """Folds Cyrillic/Greek homoglyphs to Latin equivalents when mixed into Latin words.

    Preserves authentic pure Cyrillic text (e.g. Russian) while catching
    adversarial homoglyph substitution attacks (e.g. 'ignоrе').
    """
    signals = []
    homoglyph_count = 0

    words = re.split(r"(\s+)", text)
    result_words = []

    for word in words:
        if not word.strip():
            result_words.append(word)
            continue

        has_latin = any("a" <= c.lower() <= "z" for c in word)
        has_homoglyph = any(c in HOMOGLYPH_MAP for c in word)

        # If token mixes Latin with homoglyphs, or has homoglyphs that form known attack tokens
        if has_latin and has_homoglyph:
            folded = []
            for char in word:
                if char in HOMOGLYPH_MAP:
                    folded.append(HOMOGLYPH_MAP[char])
                    homoglyph_count += 1
                else:
                    folded.append(char)
            result_words.append("".join(folded))
        else:
            result_words.append(word)

    if homoglyph_count > 0:
        signals.append(f"HOMOGLYPH_SUBSTITUTIONS_{homoglyph_count}")

    return "".join(result_words), signals


def extract_html_and_markdown_hidden_content(text: str) -> Tuple[str, List[str], List[str]]:
    """Extracts concealed text from HTML tags, comments, attributes, and Markdown."""
    signals = []
    hidden_snippets = []

    # 1. HTML Comments: <!-- comment -->
    comment_pattern = re.compile(r"<!--(.*?)-->", flags=re.DOTALL)
    for match in comment_pattern.finditer(text):
        comment_body = match.group(1).strip()
        if comment_body:
            hidden_snippets.append(comment_body)
            if "HTML_COMMENTS" not in signals:
                signals.append("HTML_COMMENTS")

    # 2. Hidden HTML Elements: style="display:none", style="visibility:hidden", font-size:0
    hidden_elem_pattern = re.compile(
        r"""<[^>]+style=['"][^'"]*?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^'"]*?['"][^>]*>(.*?)</[^>]+>""",
        flags=re.IGNORECASE | re.DOTALL,
    )
    for match in hidden_elem_pattern.finditer(text):
        hidden_text = match.group(1).strip()
        if hidden_text:
            hidden_snippets.append(hidden_text)
            if "HIDDEN_HTML_ELEMENT" not in signals:
                signals.append("HIDDEN_HTML_ELEMENT")

    # 3. HTML alt and title attributes: <img alt="instructions"> or <a title="...">
    attr_pattern = re.compile(r"""(?:alt|title)=['"]([^'"]{4,})['"]""", flags=re.IGNORECASE)
    for match in attr_pattern.finditer(text):
        val = match.group(1).strip()
        if val:
            hidden_snippets.append(val)
            if "HTML_ATTRIBUTE_PAYLOAD" not in signals:
                signals.append("HTML_ATTRIBUTE_PAYLOAD")

    # 4. Markdown image alt and link title: ![alt text](url) or [link](url "title")
    md_img_pattern = re.compile(r"""!\[(.*?)\]\([^)]+\)""")
    for match in md_img_pattern.finditer(text):
        alt = match.group(1).strip()
        if alt:
            hidden_snippets.append(alt)
            if "MARKDOWN_IMAGE_ALT" not in signals:
                signals.append("MARKDOWN_IMAGE_ALT")

    md_link_title_pattern = re.compile(r"""\[.*?\]\(.*?\s+["'](.*?)["']\)""")
    for match in md_link_title_pattern.finditer(text):
        title = match.group(1).strip()
        if title:
            hidden_snippets.append(title)
            if "MARKDOWN_LINK_TITLE" not in signals:
                signals.append("MARKDOWN_LINK_TITLE")

    # Append any extracted hidden text to the main text stream so detectors can inspect it
    augmented_text = text
    if hidden_snippets:
        augmented_text += "\n\n[EXTRACTED_HIDDEN_CONTENT]\n" + "\n".join(hidden_snippets)

    return augmented_text, signals, hidden_snippets


def decode_encoded_blobs(text: str, max_depth: int = MAX_DECODE_DEPTH) -> Tuple[str, List[str]]:
    """Identifies and decodes Base64, Hex, and ROT13 payloads under strict bounds.
    Supports bounded recursive decoding up to max_depth levels.
    """
    signals: List[str] = []
    all_decoded_parts: List[str] = []
    total_bytes_decoded = 0

    current_texts = [text]
    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4,}\s*){2,}={0,2}|[A-Za-z0-9+/]{12,}={0,2}")
    hex_pattern = re.compile(r"\b([0-9a-fA-F]{16,})\b")
    rot13_triggers = ["vtaber", "flfgrz", "cebzcg", "wnvyoernx", "nffvfgnag"]

    for depth in range(1, max_depth + 1):
        next_texts: List[str] = []
        for curr in current_texts:
            # 1. Base64 Candidate Blobs
            for match in b64_pattern.finditer(curr):
                candidate = match.group(0).strip()
                if len(candidate) > MAX_DECODE_BYTES or len(candidate) < 12:
                    continue
                try:
                    raw_bytes = base64.b64decode(candidate, validate=False)
                    if total_bytes_decoded + len(raw_bytes) > MAX_DECODE_BYTES:
                        if "DECODE_SIZE_LIMIT_EXCEEDED" not in signals:
                            signals.append("DECODE_SIZE_LIMIT_EXCEEDED")
                        break
                    printable_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in raw_bytes) / len(raw_bytes)
                    if printable_ratio > 0.85 and len(raw_bytes) >= 8:
                        decoded_str = raw_bytes.decode("utf-8", errors="ignore").strip()
                        if decoded_str and any(c.isalpha() for c in decoded_str):
                            if decoded_str not in all_decoded_parts:
                                all_decoded_parts.append(decoded_str)
                                next_texts.append(decoded_str)
                                total_bytes_decoded += len(raw_bytes)
                                if "BASE64_PAYLOAD_DECODED" not in signals:
                                    signals.append("BASE64_PAYLOAD_DECODED")
                                if depth > 1 and "NESTED_ENCODING_DECODED" not in signals:
                                    signals.append("NESTED_ENCODING_DECODED")
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    pass

            # 2. Hex Candidate Blobs
            for match in hex_pattern.finditer(curr):
                candidate = match.group(1)
                if len(candidate) % 2 != 0 or len(candidate) > MAX_DECODE_BYTES:
                    continue
                try:
                    raw_bytes = bytes.fromhex(candidate)
                    if total_bytes_decoded + len(raw_bytes) > MAX_DECODE_BYTES:
                        if "DECODE_SIZE_LIMIT_EXCEEDED" not in signals:
                            signals.append("DECODE_SIZE_LIMIT_EXCEEDED")
                        break
                    printable_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in raw_bytes) / len(raw_bytes)
                    if printable_ratio > 0.85 and len(raw_bytes) >= 8:
                        decoded_str = raw_bytes.decode("utf-8", errors="ignore").strip()
                        if decoded_str and any(c.isalpha() for c in decoded_str):
                            if decoded_str not in all_decoded_parts:
                                all_decoded_parts.append(decoded_str)
                                next_texts.append(decoded_str)
                                total_bytes_decoded += len(raw_bytes)
                                if "HEX_PAYLOAD_DECODED" not in signals:
                                    signals.append("HEX_PAYLOAD_DECODED")
                                if depth > 1 and "NESTED_ENCODING_DECODED" not in signals:
                                    signals.append("NESTED_ENCODING_DECODED")
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    pass

            # 3. ROT13 (only at depth 1 to avoid cycling)
            if depth == 1:
                curr_lower = curr.lower()
                if any(trigger in curr_lower for trigger in rot13_triggers):
                    rot13_decoded = codecs.decode(curr, "rot_13")
                    if rot13_decoded not in all_decoded_parts:
                        all_decoded_parts.append(rot13_decoded)
                        next_texts.append(rot13_decoded)
                        if "ROT13_PAYLOAD_DECODED" not in signals:
                            signals.append("ROT13_PAYLOAD_DECODED")

        if not next_texts or total_bytes_decoded >= MAX_DECODE_BYTES:
            break
        current_texts = next_texts

    result_text = text
    if all_decoded_parts:
        result_text += "\n\n[DECODED_EMBEDDED_PAYLOADS]\n" + "\n".join(all_decoded_parts)

    return result_text, signals


def decode_leetspeak(text: str) -> Tuple[str, List[str]]:
    """Substitutes leetspeak characters within mixed alphanumeric words.

    Preserves markdown syntax (![img]), valid email addresses, and pure numbers.
    """
    signals = []
    leet_count = 0

    # Protect valid email addresses from @ replacement
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    placeholders: Dict[str, str] = {}
    temp_text = text

    for i, m in enumerate(email_pattern.finditer(text)):
        holder = f"__EMAIL_TOKEN_SAFE_{i}__"
        orig = m.group(0)
        placeholders[holder] = orig
        temp_text = temp_text.replace(orig, holder)

    # Word replacement function
    def replace_token(match: re.Match) -> str:
        nonlocal leet_count
        word = match.group(0)
        if word.isdigit() or word.startswith("__EMAIL_TOKEN_SAFE_"):
            return word

        # Only decode if word contains at least one letter and one leet symbol
        has_letters = any(c.isalpha() for c in word)
        has_leet = any(c in LEET_MAP for c in word)
        if not (has_letters and has_leet):
            return word

        decoded = []
        for c in word:
            if c in LEET_MAP:
                decoded.append(LEET_MAP[c])
                leet_count += 1
            else:
                decoded.append(c)
        return "".join(decoded)

    # Match alphanumeric + leet tokens (avoiding isolated punctuation like ![)
    token_pattern = re.compile(r"[a-zA-Z0-9@!$345701]{2,}")
    processed = token_pattern.sub(replace_token, temp_text)

    # Restore email addresses
    for holder, orig in placeholders.items():
        processed = processed.replace(holder, orig)

    if leet_count >= 2:
        signals.append(f"LEETSPEAK_DETECTED_{leet_count}")

    return processed, signals


def normalize_input(raw_text: str) -> NormalizedResult:
    """Master input normalization pipeline.

    Executes:
    1. Unicode NFKC canonical decomposition & composition
    2. Stripping zero-width, bidi, and Unicode tag characters
    3. Cyrillic/Greek homoglyph folding
    4. HTML entity and URL unescaping
    5. Hidden HTML and Markdown text extraction
    6. Base64, Hex, and ROT13 payload decoding
    7. Leetspeak mapping
    8. Whitespace collapsing and de-spaced canonical payload synthesis
    """
    if not raw_text:
        return NormalizedResult("", "", [], [])

    signals: List[str] = []

    # 1. NFKC Canonical Normalization
    nfkc_text = unicodedata.normalize("NFKC", raw_text)

    # 2. Strip Zero-Width and BiDi
    clean_text, zw_signals = strip_zero_width_and_bidi(nfkc_text)
    signals.extend(zw_signals)

    # 3. Fold Homoglyphs
    homo_text, homo_signals = fold_homoglyphs(clean_text)
    signals.extend(homo_signals)

    # 4. Unescape HTML and URL entities
    unescaped = html.unescape(urllib.parse.unquote(homo_text))

    # 5. Extract Hidden HTML and Markdown Content
    with_hidden, hidden_signals, hidden_snippets = extract_html_and_markdown_hidden_content(unescaped)
    signals.extend(hidden_signals)

    # 6. Decode Base64/Hex/ROT13 payloads on the uncorrupted text
    with_decoded, decode_signals = decode_encoded_blobs(with_hidden)
    signals.extend(decode_signals)

    # 7. Decode Leetspeak on the main text only
    with_leet, leet_signals = decode_leetspeak(with_hidden)
    signals.extend(leet_signals)

    # Append any decoded payload segments from step 6
    if "[DECODED_EMBEDDED_PAYLOADS]" in with_decoded:
        decoded_part = with_decoded.split("[DECODED_EMBEDDED_PAYLOADS]")[1]
        final_text = with_leet + "\n\n[DECODED_EMBEDDED_PAYLOADS]" + decoded_part
    else:
        final_text = with_leet

    # 8. Collapse Whitespace
    collapsed_text = re.sub(r"[ \t]+", " ", final_text)
    collapsed_text = re.sub(r"\n\s*\n+", "\n\n", collapsed_text).strip()

    # 9. Synthesize De-spaced and De-punctuated Stream (for split-word attacks)
    despaced_text = re.sub(r"[^a-zA-Z0-9]", "", collapsed_text).lower()

    return NormalizedResult(
        normalized_text=collapsed_text,
        despaced_text=despaced_text,
        obfuscation_signals=signals,
        extracted_hidden_text=hidden_snippets,
    )
