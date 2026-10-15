"""Automated Demo Video Recorder for Tether // Agent Hijack Shield.

Uses Playwright to walk through the 60-second tour on the live gateway console:
1. Opens / (Landing page) and clicks ENTER PLAYGROUND
2. Selects Scenario 5 (Indirect Injection via Poisoned Document)
3. Clicks 'Run Side-by-Side (Shield OFF vs ON)'
4. Observes unshielded data exfiltration vs Tether taint escalation
5. Inspects the pending Human Approval and clicks 'Authorize Tool Call'
6. Clicks 'Verify Hash Chain' to confirm tamper-evident cryptographic log integrity
7. Expands the 'Known Limitations' panel (ad_05, abuse_20)

Outputs:
- Video: frontend/assets/demo.mp4
- Poster: frontend/assets/poster.jpg

Prerequisites:
    pip install playwright
    playwright install chromium
"""

import asyncio
import os
import shutil
import sys
import time

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


async def record_walkthrough(base_url: str = "http://localhost:8000"):
    if not PLAYWRIGHT_AVAILABLE:
        print("\n" + "=" * 60)
        print("  PLAYWRIGHT NOT INSTALLED")
        print("=" * 60)
        print("  To record the demo video, install playwright:")
        print("    pip install playwright")
        print("    playwright install chromium")
        print("=" * 60)
        print("  Note: Tether's landing page includes a built-in 6-scene")
        print("  animated Canvas explainer that plays automatically when")
        print("  no external video file is present.")
        print("=" * 60 + "\n")
        return False

    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "assets"))
    temp_dir = os.path.join(assets_dir, "temp_video")
    os.makedirs(temp_dir, exist_ok=True)

    print(f"[*] Starting Chromium to record walkthrough at {base_url}...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=temp_dir,
            record_video_size={"width": 1440, "height": 900},
        )
        page = await context.new_page()

        # Helper to inject animated subtitles for audio-free viewing
        async def show_caption(title: str, text: str, duration_sec: float = 3.0):
            print(f"  [Scene] {title}: {text}")
            await page.evaluate(
                """([title, text]) => {
                    let cap = document.getElementById('demoCaptionOverlay');
                    if (!cap) {
                        cap = document.createElement('div');
                        cap.id = 'demoCaptionOverlay';
                        cap.style.position = 'fixed';
                        cap.style.bottom = '30px';
                        cap.style.left = '50%';
                        cap.style.transform = 'translateX(-50%)';
                        cap.style.backgroundColor = 'rgba(23, 21, 15, 0.95)';
                        cap.style.color = '#FFFFFF';
                        cap.style.border = '2px solid #FF5A1F';
                        cap.style.boxShadow = '4px 4px 0 #17150F';
                        cap.style.padding = '12px 24px';
                        cap.style.borderRadius = '4px';
                        cap.style.fontFamily = 'monospace';
                        cap.style.zIndex = '99999';
                        cap.style.maxWidth = '800px';
                        cap.style.textAlign = 'center';
                        document.body.appendChild(cap);
                    }
                    cap.innerHTML = `<div style="color:#FF5A1F;font-weight:bold;font-size:12px;margin-bottom:4px;">${title}</div><div style="font-size:14px;">${text}</div>`;
                    cap.style.display = 'block';
                }""",
                [title, text],
            )
            await asyncio.sleep(duration_sec)

        # Scene 1: Landing Page
        print("[1/7] Navigating to landing page...")
        await page.goto(f"{base_url}/", wait_until="networkidle")
        await show_caption("SCENE 1: OVERVIEW", "Tether: Production-grade security gateway for autonomous AI agents.", 3.0)
        await page.screenshot(path=os.path.join(assets_dir, "poster.jpg"))
        await page.click("#btnEnterPlayground")
        await asyncio.sleep(1.5)

        # Scene 2: Scenario 5 (Indirect Injection)
        print("[2/7] Selecting Scenario 5 (Indirect Injection)...")
        await page.wait_for_selector("#scenarioSelect")
        await page.select_option("#scenarioSelect", "scenario_05")
        await show_caption("SCENE 2: POISONED DOCUMENT", "Loading Scenario 5: Untrusted external document with embedded exfiltration payload.", 3.5)
        await asyncio.sleep(1.0)

        # Scene 3: Run Side-by-Side
        print("[3/7] Running Side-by-Side evaluation...")
        await show_caption("SCENE 3: COMPARISON RUN", "Evaluating Side-by-Side: Raw unprotected agent vs Tether security gateway.", 2.5)
        await page.click("#btnSideBySide")
        await asyncio.sleep(3.0)

        # Scene 4: Observe Results
        print("[4/7] Highlighting results...")
        await show_caption("SCENE 4: TAINT ESCALATION", "Shield OFF attempted exfiltration to attacker@evil.com. Shield ON halted execution and generated a pending approval checkpoint.", 4.0)
        await asyncio.sleep(2.0)

        # Scene 5: Approve Tool Call
        print("[5/7] Approving pending human checkpoint...")
        await show_caption("SCENE 5: HUMAN-IN-THE-LOOP", "Authorizing tool call via client judge key. A cryptographically bound single-use capability token is issued.", 3.5)
        approve_btn = await page.query_selector(".btn-approve")
        if approve_btn:
            await approve_btn.click()
            await asyncio.sleep(2.0)

        # Scene 6: Cryptographic Audit Verification
        print("[6/7] Verifying cryptographic audit chain...")
        await show_caption("SCENE 6: AUDIT VERIFICATION", "Verifying HMAC-SHA256 forward links across immutable audit log entries.", 3.0)
        await page.click("#btnVerifyAudit")
        await asyncio.sleep(2.5)

        # Scene 7: Known Limitations & Honest Disclosure
        print("[7/7] Viewing Known Limitations panel...")
        await show_caption("SCENE 7: HONEST DISCLOSURE", "Empirical limitations: Grandmother roleplay evasion (ad_05) and untainted internal passphrase leakage (abuse_20).", 3.5)
        limitations_summary = await page.query_selector(".limitations-summary")
        if limitations_summary:
            await limitations_summary.click()
            await asyncio.sleep(2.0)

        await context.close()
        await browser.close()

    # Move recorded video to target location
    video_files = [f for f in os.listdir(temp_dir) if f.endswith(".webm") or f.endswith(".mp4")]
    if video_files:
        src = os.path.join(temp_dir, video_files[0])
        dest = os.path.join(assets_dir, "demo.mp4")
        shutil.move(src, dest)
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"[✓] Demo video saved to {dest}")
        print(f"[✓] Demo poster saved to {os.path.join(assets_dir, 'poster.jpg')}")
        return True
    return False


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    asyncio.run(record_walkthrough(url))
