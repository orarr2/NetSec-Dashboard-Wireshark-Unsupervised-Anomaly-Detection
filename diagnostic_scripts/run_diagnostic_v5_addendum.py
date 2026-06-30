"""Surgical addendum to complete what v3/v4 missed:
   - Walk all 9 Security tab items.
   - Capture Live Recording page (FIX1 overwrite banner).
   - Captures while S1 is loaded.
"""
import os, sys, json, time, threading, traceback, socket, hashlib, re
from pathlib import Path

HERE = Path(__file__).parent.resolve()
ROOT = HERE.parent
PCAPS = ROOT / "attack_tests" / "pcaps"
OUT = Path("/home/user/diagnostic_output_v5")
OUT.mkdir(parents=True, exist_ok=True)
SHOT_DIR = OUT / "screenshots"
SHOT_DIR.mkdir(parents=True, exist_ok=True)

import subprocess as _sp
_orig_check_call = _sp.check_call
def _noop_check_call(*a, **kw):
    if a and isinstance(a[0], list) and 'pip' in ' '.join(a[0]): return 0
    return _orig_check_call(*a, **kw)
_sp.check_call = _noop_check_call

import dash
_orig_run = dash.Dash.run
def _stub_run(self, *a, **kw): pass
dash.Dash.run = _stub_run

print("Loading dashboard...")
sys.path.insert(0, str(HERE))
import importlib.util
spec = importlib.util.spec_from_file_location('dashboard_module', str(HERE / 'dashboard_module.py'))
mod = importlib.util.module_from_spec(spec)
sys.modules['dashboard_module'] = mod
spec.loader.exec_module(mod)
dash.Dash.run = _orig_run

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]
PORT = free_port()
URL = f"http://127.0.0.1:{PORT}"

print(f"Launching on {URL}")
def _serve():
    try:
        mod.app.run(host="127.0.0.1", port=PORT, debug=False,
                    use_reloader=False, dev_tools_silence_routes_logging=True)
    except Exception: traceback.print_exc()
threading.Thread(target=_serve, daemon=True).start()
import urllib.request
for _ in range(60):
    try: urllib.request.urlopen(URL, timeout=0.5); break
    except Exception: time.sleep(0.25)

from playwright.sync_api import sync_playwright

REPORT = {"screenshots": [], "security_walk": {}, "phases": [], "server_500s": 0}

def shot(page, name, desc=""):
    path = SHOT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    sz = path.stat().st_size
    REPORT["screenshots"].append({"name": name, "desc": desc, "bytes": sz})
    print(f"  [shot] {name}  ({sz/1024:.1f} KB)")

with sync_playwright() as pw:
    browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 1100})
    page = ctx.new_page()

    server_500s = [0]
    def _on_response(resp):
        if resp.status == 500 and "/_dash" in resp.url: server_500s[0] += 1
    page.on("response", _on_response)

    print("\n[1] Welcome -> Continue -> Load S1")
    page.goto(URL, wait_until="networkidle", timeout=30000)
    time.sleep(2.5)
    cb = page.locator('input[type="checkbox"]').first
    if cb.count() and not cb.is_checked(): cb.check(); time.sleep(0.4)
    page.get_by_role("button", name="Continue").first.click()
    time.sleep(1.5)

    page.locator('#pcap-path-input').fill(str(PCAPS / "tcp_syn_scan.pcap"))
    time.sleep(0.4)
    page.get_by_role("button", name=re.compile(r"^\s*Load\s*$")).first.click()
    time.sleep(2.5)
    page.locator("#staged-analyze-btn").first.click()
    for _ in range(60):
        if page.locator("#sidebar").count() and page.locator("text=Top Talkers").count(): break
        time.sleep(0.5)
    time.sleep(2.0)

    print("\n[2] Click Security top-tab")
    # Target by exact text inside a clickable element
    sec_tab = page.locator('div').filter(has_text=re.compile(r'^\s*🛡️\s*Security\s*$'))
    if sec_tab.count():
        sec_tab.first.click()
        print("  clicked Security top-tab via icon+label")
    else:
        # Fallback: click on the literal text Security on the page
        page.locator("text=/^Security$/").first.click()
        print("  clicked Security text fallback")
    time.sleep(2.0)
    shot(page, "01_security_tab_opened", "Security tab opened - should show 9 security items")

    print("\n[3] Walk Security items")
    items = ["TCP SYN Analysis", "Model Agreement Matrix", "Contamination Sweep",
             "Beaconing (C2)", "DNS Tunneling", "DGA Domains",
             "ARP / Rogue DHCP", "TLS Fingerprint", "Kill-Chain Risk"]
    for label in items:
        try:
            loc = page.get_by_text(label, exact=False).first
            if not loc.count():
                REPORT["security_walk"][label] = "not_found"; continue
            loc.scroll_into_view_if_needed(timeout=2000)
            loc.click(timeout=4000); time.sleep(1.0)
            slug = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            shot(page, f"sec_{slug}", f"Security: {label}")
            REPORT["security_walk"][label] = "ok"
        except Exception as e:
            REPORT["security_walk"][label] = f"err: {str(e)[:80]}"

    print("\n[4] Back to Analyze and visit Live Recording (FIX1 banner)")
    an_tab = page.locator('div').filter(has_text=re.compile(r'^\s*📊\s*Analyze\s*$'))
    if an_tab.count(): an_tab.first.click()
    time.sleep(1.0)
    page.get_by_text("Live Recording", exact=False).first.click()
    time.sleep(2.0)
    shot(page, "02_live_recording_with_banner", "Live Recording page - FIX1 overwrite banner should show 'Heads-up'")

    # Crop the banner area
    print("\n[5] Zoom on FIX1 banner")
    # Take a small viewport screenshot of just the top portion
    page.set_viewport_size({"width": 1440, "height": 600})
    time.sleep(0.5)
    shot(page, "03_live_banner_zoom", "Live Recording - top of page showing FIX1 banner")
    page.set_viewport_size({"width": 1440, "height": 1100})

    print("\n[6] Click-refresh stress test (20 rapid clicks)")
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.get_by_text("Top Talkers", exact=False).first.click()
    time.sleep(1.0)
    server_500s_before = server_500s[0]
    seq = []
    for i in range(20):
        labels = ["Top Talkers", "Devices", "Protocols", "Traffic Timeline",
                  "Burst vs Scan", "DNS Services", "Analysis Insights"]
        label = labels[i % len(labels)]
        try:
            page.get_by_text(label, exact=False).first.click(timeout=2000)
            time.sleep(0.35)
            seq.append((label, "ok"))
        except Exception as e:
            seq.append((label, f"err: {str(e)[:50]}"))
    server_500s_during = server_500s[0] - server_500s_before
    REPORT["stress_test"] = {
        "clicks": len(seq), "server_500_errors_during": server_500s_during,
        "verdict": "PASS - no server errors" if server_500s_during == 0
                   else f"FAIL - {server_500s_during} server 500s during 20 clicks",
        "sequence": seq,
    }
    print(f"  verdict: {REPORT['stress_test']['verdict']}")
    shot(page, "04_after_stress_test", f"After 20-click stress test ({server_500s_during} server errors)")

    ctx.close(); browser.close()

REPORT["server_500s"] = server_500s[0]
sw_ok = sum(1 for v in REPORT["security_walk"].values() if v == "ok")
sw_total = len(REPORT["security_walk"])
print()
print("=" * 60)
print(f"Security walk:  {sw_ok}/{sw_total} OK")
print(f"Total screenshots: {len(REPORT['screenshots'])}")
print(f"Total server 500 errors observed: {server_500s[0]}")
print(f"Stress test verdict: {REPORT['stress_test']['verdict']}")

with open(OUT / "REPORT.json", "w", encoding="utf-8") as f:
    json.dump(REPORT, f, indent=2, default=str)
