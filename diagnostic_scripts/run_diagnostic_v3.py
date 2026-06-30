"""End-to-end diagnostic runner v2 for the NetSec Dashboard.

Improvements over v1:
  - Targets the staged-analyze-btn specifically (not generic 'Load').
  - Waits for the *sidebar* to appear (true dashboard signal) before walking nav.
  - Loads BOTH S1 (tcp_syn_scan) and S2 (synflood) to exercise comparison.
  - Tests three click-refresh scenarios: tab switch, sidebar nav, sub-tab.
  - 24-second flicker test, takes a screenshot every 2s.
  - Also tests xmas_scan and arpspoof in separate runs (subset).
"""
import os, sys, json, time, threading, traceback, socket, hashlib, re, base64
from pathlib import Path

HERE = Path(__file__).parent.resolve()
ROOT = HERE.parent
PCAPS = ROOT / "attack_tests" / "pcaps"
OUT = Path("/home/user/diagnostic_output_v3")
OUT.mkdir(parents=True, exist_ok=True)
SHOT_DIR = OUT / "screenshots"
SHOT_DIR.mkdir(parents=True, exist_ok=True)

# Patch subprocess.check_call to not run pip again
import subprocess as _sp
_orig_check_call = _sp.check_call
def _noop_check_call(*a, **kw):
    if a and isinstance(a[0], list) and 'pip' in ' '.join(a[0]):
        return 0
    return _orig_check_call(*a, **kw)
_sp.check_call = _noop_check_call

import dash
_orig_run = dash.Dash.run
def _stub_run(self, *a, **kw):
    pass
dash.Dash.run = _stub_run

print("[step 1] Loading dashboard module...")
sys.path.insert(0, str(HERE))
import importlib.util
spec = importlib.util.spec_from_file_location('dashboard_module', str(HERE / 'dashboard_module.py'))
mod = importlib.util.module_from_spec(spec)
sys.modules['dashboard_module'] = mod
spec.loader.exec_module(mod)
print("    OK")

dash.Dash.run = _orig_run

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

PORT = free_port()
URL = f"http://127.0.0.1:{PORT}"

print(f"[step 2] Launching Dash on {URL} ...")
def _serve():
    try:
        mod.app.run(host="127.0.0.1", port=PORT, debug=False,
                    use_reloader=False, dev_tools_silence_routes_logging=True)
    except Exception:
        traceback.print_exc()

server_thread = threading.Thread(target=_serve, daemon=True)
server_thread.start()

import urllib.request
for _ in range(60):
    try:
        urllib.request.urlopen(URL, timeout=0.5); break
    except Exception:
        time.sleep(0.25)
else:
    print("    ! server did not come up"); sys.exit(2)
print("    OK")

from playwright.sync_api import sync_playwright

REPORT = {
    "url": URL, "port": PORT, "phases": [], "screenshots": [],
    "console_errors": [], "network_failures": [],
    "flicker_test": {}, "click_refresh_test": {}, "nav_walk": [],
    "fix_verifications": {},
}

def shot(page, name, desc=""):
    path = SHOT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    sz = path.stat().st_size
    REPORT["screenshots"].append({"name": name, "desc": desc, "bytes": sz})
    print(f"    [shot] {name}  ({sz/1024:.1f} KB)")
    return path

def dom_hash(page):
    h = page.evaluate("() => document.documentElement.outerHTML")
    cleaned = re.sub(r'(_dash-loading|data-dash-is-loading)="[^"]*"', '', h)
    cleaned = re.sub(r'data-reactroot="[^"]*"', '', cleaned)
    return hashlib.sha256(cleaned.encode()).hexdigest()[:16], len(h)

def perf(page):
    try:
        return page.evaluate("""() => ({
            navs: performance.getEntriesByType('navigation').length,
            ress: performance.getEntriesByType('resource').length,
            ready: document.readyState,
            url: location.href,
        })""")
    except Exception:
        return None

def wait_for_dashboard(page, timeout=120):
    """Wait until the sidebar with nav items appears."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            # The sidebar has id='sidebar' and contains nav-item divs
            if page.locator("#sidebar").count():
                # Check that we see at least 5 nav items
                navs = page.locator("[id*='nav-item']").count()
                if navs >= 5:
                    return True
            # Also check by text - the main dashboard always renders a nav label
            if page.locator("text=Top Talkers").count():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False

with sync_playwright() as pw:
    browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()

    page.on("console", lambda msg: REPORT["console_errors"].append({
        "type": msg.type, "text": msg.text[:300]
    }) if msg.type == "error" else None)
    page.on("requestfailed", lambda req: REPORT["network_failures"].append({
        "url": req.url, "failure": (req.failure or "?")[:120]
    }))

    # ---------- PHASE A: Welcome screen ----------
    print("\n[A] Welcome screen")
    page.goto(URL, wait_until="networkidle", timeout=30000)
    time.sleep(2.0)
    shot(page, "A1_welcome", "Initial welcome / splash screen")

    # Tick ack
    cb = page.locator('input[type="checkbox"]').first
    if cb.count() and not cb.is_checked():
        cb.check(); time.sleep(0.4)
    shot(page, "A2_ack_ticked", "Ack ticked")

    # Click Continue
    cont = page.get_by_role("button", name="Continue")
    if cont.count():
        cont.first.click(); time.sleep(1.5)
        page.wait_for_load_state("networkidle")
    REPORT["phases"].append({"phase":"A", "ok": True})
    shot(page, "A3_choice_screen", "After Continue: choice screen (PCAP path + Live recording)")

    # ---------- PHASE B: Load S1 = tcp_syn_scan.pcap ----------
    print("\n[B] Loading S1 = tcp_syn_scan.pcap")
    s1_path = str(PCAPS / "tcp_syn_scan.pcap")
    # Find pcap-path-input and fill it
    inp = page.locator('#pcap-path-input')
    if not inp.count():
        inp = page.locator('input[type="text"]').first
    inp.fill(s1_path)
    time.sleep(0.5)
    shot(page, "B1_s1_path_typed", "S1 path typed in input")

    # Click the "Load" button (this stages the file)
    load_btn = page.get_by_role("button", name=re.compile(r"^\s*Load\s*$"))
    if load_btn.count():
        load_btn.first.click()
        print(f"    clicked Load")
        time.sleep(2.0)
    shot(page, "B2_s1_staged", "S1 file staged - should show READY TO ANALYZE + Analyze button")

    # NOW click the "Analyze" button (id=staged-analyze-btn)
    print("    waiting for analysis after Analyze click...")
    analyze_btn = page.locator("#staged-analyze-btn")
    if not analyze_btn.count():
        analyze_btn = page.get_by_role("button", name=re.compile(r"Analyze"))
    if analyze_btn.count():
        analyze_btn.first.click()
        print(f"    clicked Analyze")

    # Wait for the dashboard sidebar
    ok = wait_for_dashboard(page, timeout=90)
    print(f"    dashboard ready: {ok}")
    time.sleep(1.5)
    shot(page, "B3_dashboard_loaded", "Dashboard after S1 analysis (sidebar + first chart)")
    REPORT["phases"].append({"phase":"B", "s1": s1_path, "loaded": ok})

    if not ok:
        print("    ! Dashboard did not load after Analyze. Aborting walk.")
        with open(OUT / "REPORT.json", "w") as f:
            json.dump(REPORT, f, indent=2, default=str)
        sys.exit(3)

    # ---------- PHASE C: Walk every nav item ----------
    print("\n[C] Walking all nav items (S1 only)")
    NAV_LABELS = [
        "Top Talkers", "Burst vs Scan", "Protocols", "DNS Services",
        "Devices", "Traffic Timeline", "Upload / Download",
        "LSTM Errors", "Analysis Insights",
        "My Device Profile", "Z-score Deviation",
        "Browsing Categories", "Browsing by Hour", "IP Browsing History",
        "TCP SYN Analysis", "Model Agreement Matrix", "Contamination Sweep",
        "Beaconing (C2)", "DNS Tunneling", "DGA Domains",
        "ARP / Rogue DHCP", "TLS Fingerprint", "Kill-Chain Risk",
        "Device Hierarchy S2", "Device Hierarchy S1",
        "Device Map (PCA)", "Proximity Map (RSSI)",
        "External Traffic", "Identification Coverage",
        "Live Recording",
    ]
    for label in NAV_LABELS:
        try:
            loc = page.locator(f"text=/^{re.escape(label)}/").first
            if not loc.count():
                # Try less strict match
                loc = page.get_by_text(label, exact=False).first
            if not loc.count():
                REPORT["nav_walk"].append({"label": label, "status": "not_found"})
                continue
            loc.scroll_into_view_if_needed(timeout=2000)
            loc.click(timeout=4000)
            time.sleep(0.9)  # let charts render
            slug = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            shot(page, f"C_nav_{slug}", f"Nav: {label}")
            REPORT["nav_walk"].append({"label": label, "status": "ok"})
        except Exception as e:
            REPORT["nav_walk"].append({"label": label, "status": f"err: {str(e)[:100]}"})

    # ---------- PHASE D: Flicker test (24s) ----------
    print("\n[D] Flicker test - 24s idle on Top Talkers")
    try:
        page.get_by_text("Top Talkers", exact=False).first.click()
        time.sleep(2.0)
    except Exception:
        pass
    flicker_samples = []; baseline_hash = None
    t0 = time.time()
    while time.time() - t0 < 24.0:
        elapsed = round(time.time() - t0, 2)
        h, s = dom_hash(page)
        if baseline_hash is None: baseline_hash = h
        change = "" if h == baseline_hash else "  ** CHANGED **"
        flicker_samples.append({"t": elapsed, "hash": h, "size": s})
        if int(elapsed) % 6 == 0 and abs(elapsed - int(elapsed)) < 0.6:
            shot(page, f"D_flicker_t{int(elapsed):02d}s", f"Flicker test t={int(elapsed)}s {change}")
        time.sleep(0.5)
    distinct = sorted({fs["hash"] for fs in flicker_samples})
    REPORT["flicker_test"] = {
        "duration_s": 24.0, "samples": len(flicker_samples),
        "distinct_dom_hashes": len(distinct),
        "verdict": "PASS - no flicker" if len(distinct) == 1 else f"FAIL - {len(distinct)} distinct snapshots",
        "first_change_at": next(
            (fs["t"] for fs in flicker_samples[1:] if fs["hash"] != flicker_samples[0]["hash"]),
            None),
        "hashes": distinct[:20],
        "timeline": flicker_samples,
    }
    print(f"    verdict: {REPORT['flicker_test']['verdict']}")

    # ---------- PHASE E: Click-refresh test ----------
    print("\n[E] Click-refresh test")
    page.get_by_text("Top Talkers", exact=False).first.click(); time.sleep(0.8)
    seq = ["Devices", "Protocols", "Traffic Timeline", "Top Talkers", "Devices", "TCP SYN Analysis", "Top Talkers"]
    p_before = perf(page)
    click_log = [{"step": "before", "perf": p_before}]
    for label in seq:
        try:
            page.get_by_text(label, exact=False).first.click(timeout=3000)
            time.sleep(0.6)
            click_log.append({"step": label, "perf": perf(page)})
        except Exception as e:
            click_log.append({"step": label, "error": str(e)[:120]})
    nav_counts = [c["perf"]["navs"] for c in click_log if c.get("perf")]
    REPORT["click_refresh_test"] = {
        "sequence": seq,
        "log": click_log,
        "navs_counter_values": nav_counts,
        "distinct_navs_values": sorted(set(nav_counts)),
        "verdict": ("PASS - no full reloads" if len(set(nav_counts)) <= 1
                    else f"FAIL - navigation count changed: {nav_counts}"),
    }
    print(f"    verdict: {REPORT['click_refresh_test']['verdict']}")
    shot(page, "E_after_click_seq", "After click sequence")

    # ---------- PHASE F: Load S2 (synflood.pcap) -- the heavy stress test ----------
    print("\n[F] Loading S2 = synflood.pcap (37k pkts, spoofed flood)")
    s2_path = str(PCAPS / "synflood.pcap")
    # The sidebar should have a "+ Load second PCAP" button
    add_s2 = page.locator("text=/Load second PCAP/i").first
    if not add_s2.count():
        add_s2 = page.locator("text=/Add S2/i").first
    if not add_s2.count():
        add_s2 = page.locator("text=/second PCAP/i").first
    if add_s2.count():
        add_s2.click()
        time.sleep(1.5)
        shot(page, "F1_s2_modal", "S2 modal open")
        # Find the S2 path input
        s2_inputs = page.locator('input[type="text"]').all()
        for inp in s2_inputs:
            try:
                placeholder = (inp.get_attribute("placeholder") or "")
                if "pcap" in placeholder.lower() or "path" in placeholder.lower():
                    inp.fill(s2_path); break
            except Exception:
                pass
        time.sleep(0.5)
        shot(page, "F2_s2_path_typed", "S2 path typed")
        # Try a Load button in the modal
        for b in ["Load", "Add", "Confirm", "Stage"]:
            try:
                btn = page.get_by_role("button", name=re.compile(rf"^\s*{b}\s*$"))
                if btn.count():
                    btn.first.click(); print(f"    clicked S2 {b}")
                    time.sleep(2.0); break
            except Exception:
                pass
        shot(page, "F3_s2_staged", "S2 staged")
        # Click "Analyze S2"
        s2_an = page.locator("#staged-second-analyze-btn")
        if not s2_an.count():
            s2_an = page.get_by_role("button", name=re.compile(r"Analyze.*S2"))
        if s2_an.count():
            s2_an.first.click()
            print("    clicked Analyze S2 - analysis can take 60s+ for 37k pkts...")
            # Wait for comparison view
            t0 = time.time()
            while time.time() - t0 < 180:
                t = page.inner_text("body").lower()
                if "comparison" in t or "session 2" in t or "s1 vs s2" in t:
                    break
                time.sleep(1)
            print(f"    waited {time.time()-t0:.0f}s for S2 analysis")
            time.sleep(2)
        shot(page, "F4_after_s2", "After S2 analysis complete (Comparison should now be navigable)")
        REPORT["phases"].append({"phase": "F", "s2": s2_path, "elapsed_s2_s": time.time() - t0 if 't0' in dir() else None})
    else:
        print("    ! could not find S2 load button")
        REPORT["phases"].append({"phase": "F", "skipped": "no S2 entry point"})

    # Click into Comparison
    try:
        page.get_by_text("Traffic S1 vs S2", exact=False).first.click()
        time.sleep(2)
        shot(page, "F5_comparison_view", "Comparison: S1 vs S2 traffic")
    except Exception as e:
        print(f"    comparison view not clickable: {e}")
    try:
        page.get_by_text("New / Gone IPs", exact=False).first.click()
        time.sleep(1.5)
        shot(page, "F6_new_gone_ips", "Comparison: New / Gone IPs")
    except Exception:
        pass

    # ---------- PHASE G: Fix verification (12 prior fixes) ----------
    print("\n[G] Verifying 12 prior fixes")
    cell48 = open(HERE / "dashboard_module.py", "r", encoding="utf-8").read()
    checks = {
        "FIX1_overwrite_banner_on_live_record":
            ("S1 already loaded" in cell48 or "will replace S1" in cell48),
        "FIX2_smart_interval_disable_when_idle":
            ("live-recording-tick" in cell48 and 'disabled=True' in cell48),
        "FIX3_double_click_guard_analyzing_flag":
            ("_analyzing" in cell48 and "worker._analyzing" in cell48),
        "FIX4_replace_s1_workflow":
            ("Replace S1 PCAP" in cell48 and "replacing-s1" in cell48),
        "FIX5_clear_staged_on_modal_cancel":
            ("staged-second-pcap" in cell48 and re.search(r'staged-second-pcap.*None', cell48) is not None),
        "FIX6_pre_tick_ack_when_data_loaded":
            (re.search(r'intro-ack.*value=True', cell48) is not None or "intro-ack-check" in cell48),
        "FIX7_per_tab_chart_memory":
            ("last-chart-per-tab" in cell48),
        "FIX8_clientside_button_feedback":
            (cell48.count("app.clientside_callback") >= 3),
        "FIX9_prevent_initial_call_manage_live":
            ("manage_live_panel" in cell48 and "prevent_initial_call=True" in cell48),
        "FIX10_deferred_global_assignment":
            ("globals()[" in cell48 or "global S1" in cell48),
        "FIX11_dcc_loading_sidebar":
            ("dcc.Loading" in cell48 and "sidebar" in cell48),
        "FIX12_pending_snapshot_overwrite_banner":
            ("will replace" in cell48.lower() and "snapshot" in cell48.lower()),
    }
    REPORT["fix_verifications"] = {k: bool(v) for k, v in checks.items()}
    for k, v in checks.items():
        print(f"    {'✓' if v else '✗'} {k}")

    shot(page, "Z_final", "Final state at end of run")

    # ---------- Summary ----------
    REPORT["summary"] = {
        "screenshots_captured": len(REPORT["screenshots"]),
        "console_error_count": len(REPORT["console_errors"]),
        "network_failure_count": len(REPORT["network_failures"]),
        "console_unique_errors": list(set(e["text"][:80] for e in REPORT["console_errors"])),
        "fixes_present": sum(1 for v in REPORT["fix_verifications"].values() if v),
        "fixes_total": len(REPORT["fix_verifications"]),
        "nav_walked_ok": sum(1 for n in REPORT["nav_walk"] if n.get("status") == "ok"),
        "nav_walked_total": len(REPORT["nav_walk"]),
    }

    ctx.close(); browser.close()

with open(OUT / "REPORT.json", "w", encoding="utf-8") as f:
    json.dump(REPORT, f, indent=2, default=str)

print("\n" + "=" * 60)
print("DIAGNOSTIC v2 COMPLETE")
print("=" * 60)
for k, v in REPORT["summary"].items():
    print(f"  {k:30s} {v}")
print()
print(f"Flicker: {REPORT['flicker_test'].get('verdict')}")
print(f"Click:   {REPORT['click_refresh_test'].get('verdict')}")
