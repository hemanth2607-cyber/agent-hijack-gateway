import os
import re
import pytest

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))

def test_no_innerhtml_in_frontend_js():
    """Verify that frontend JavaScript files do not use innerHTML to avoid XSS and follow CSP."""
    js_files = ["dashboard.js", "reasons.js"]
    for js_file in js_files:
        path = os.path.join(FRONTEND_DIR, js_file)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            # Ensure .innerHTML is not present
            matches = re.findall(r"\.innerHTML\b", content)
            assert len(matches) == 0, f"Found innerHTML usage in {js_file}: {matches}"

def test_no_inline_scripts_in_dashboard_html():
    """Verify that dashboard.html does not contain inline scripts, complying with CSP."""
    html_path = os.path.join(FRONTEND_DIR, "dashboard.html")
    assert os.path.exists(html_path), "dashboard.html must exist"
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
        # Find script tags with inline code (not purely src attributes)
        script_matches = re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", content, re.DOTALL | re.IGNORECASE)
        non_empty = [m.strip() for m in script_matches if m.strip()]
        assert len(non_empty) == 0, f"Found inline scripts in dashboard.html: {non_empty}"

def test_no_admin_key_or_capability_tokens_in_frontend():
    """Verify frontend code does not leak admin keys or capability tokens."""
    for root, _, files in os.walk(FRONTEND_DIR):
        for file in files:
            if file.endswith((".js", ".html")):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "sk_admin_" not in content, f"Leaked sk_admin_ in {file}"
                    assert "sk_analyst_" not in content, f"Leaked sk_analyst_ in {file}"
                    assert "capability_token" not in content or "Never display capability tokens" in content or "no capability tokens" in content, f"Potential capability_token leakage in {file}"
