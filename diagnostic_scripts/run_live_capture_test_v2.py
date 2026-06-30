"""Live capture diagnostic - drives the dashboard's Live Recording feature
through Playwright while a background traffic generator hammers github.com /
pypi.org so the captured PCAP actually has packets.

Workflow:
  1. Welcome -> Continue -> open Live Recording.
  2. Pick interface = 'any' (number 2 in tshark -D).
  3. Click S1's Record button.
  4. Start background HTTP traffic loops.
  5. Take a screenshot every 25 seconds for 130s total (so we observe live counters
     ticking up).
  6. Click S1's Stop & Save.
  7. Click Analyze on the pending-snapshot card.
  8. Wait for analysis to finish; capture the resulting dashboard.
"""
import os, sys, json, time, threading, traceback, socket, hashlib, re, subprocess
from pathlib import Path

HERE = Path(__file__).parent.resolve()
ROOT = HERE.parent
OUT = Path("/home/user/diagnostic_output_live_v2")
OUT.mkdir(parents=True, exist_ok=True)
SHOT_DIR = OUT / "screenshots"
SHOT_DIR.mkdir(parents=True, exist_ok=True)

# Patch subprocess.check_call and dash.run for clean import
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

print("Loading dashboard module...")
sys.path.insert(0, str(HERE))
import importlib.util
spec = importlib.util.spec_from_file_location('dashboard_module', str(HERE / 'dashboard_module.py'))
mod = importlib.util.module_from_spec(spec)
sys.modules['dashboard_module'] = mod
spec.loader.exec_module(mod)
dash.Dash.run = _orig_run

# Background traffic generator
TRAFFIC_RUN = {"go": True}
def traffic_gen():
    """Sustained HTTPS load on allowed domains so the live capture has packets."""
    urls = ["https://github.com/", "https://pypi.org/", "https://archive.ubuntu.com/",
            "https://api.github.com/zen", "https://raw.githubusercontent.com/octocat/Hello-World/master/README"]
    pkt_estimate = 0
    while TRAFFIC_RUN["go"]:
        # Fire 4 parallel curls
        procs = []
        for _ in range(4):
            url = urls[pkt_estimate % len(urls)]
            p = subprocess.Popen(["curl", "-s", "-o", "/dev/null",
                                  "--max-time", "8", url])
            procs.append(p)
            pkt_estimate += 1
        for p in procs:
            try: p.wait(timeout=10)
            except Exception: p.kill()
        time.sleep(0.2)

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]
PORT = free_port()
URL = f"http://127.0.0.1:{PORT}"

print(f"Launching dashboard on {URL}")
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

REPORT = {"url": URL, "screenshots": [], "phases": [],
          "tshark_chunks_observed": [], "traffic_gen_estimate": 0,
          "server_500s": 0, "console_errors": []}

def shot(page, name, desc=""):
    p = SHOT_DIR / f"{name}.png"
    page.screenshot(path=str(p), full_page=True)
    sz = p.stat().st_size
    REPORT["screenshots"].append({"name": name, "desc": desc, "bytes": sz})
    print(f"  [shot] {name}  ({sz/1024:.1f} KB)  {desc}")

with sync_playwright() as pw:
    browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 1100})
    page = ctx.new_page()

    s500 = [0]
    page.on("response", lambda r: s500.__setitem__(0, s500[0]+1)
            if r.status == 500 and "/_dash" in r.url else None)
    page.on("console", lambda m: REPORT["console_errors"].append({"type": m.type, "text": m.text[:200]})
            if m.type == "error" else None)

    # ---------- A. Welcome -> Continue ----------
    print("\n[A] Welcome -> Continue")
    page.goto(URL, wait_until="networkidle", timeout=30000)
    time.sleep(2.5)
    cb = page.locator('input[type="checkbox"]').first
    if cb.count() and not cb.is_checked(): cb.check(); time.sleep(0.4)
    page.get_by_role("button", name="Continue").first.click()
    time.sleep(1.5)
    shot(page, "01_choice_screen", "Choice screen: Load PCAP or Record live")

    # ---------- B. Click "Record live" entry ----------
    print("\n[B] Click 'Record live' entry")
    # The button on the choice view is id=record-live-btn
    rec_btn = page.locator("#record-live-btn")
    if not rec_btn.count():
        rec_btn = page.get_by_role("button", name=re.compile(r"Record", re.I))
    rec_btn.first.click()
    print("  clicked record-live-btn")
    # Wait for dashboard sidebar + Live Recording panel
    for _ in range(60):
        if page.locator("#sidebar").count() and page.locator("text=Live Recording").count():
            break
        time.sleep(0.4)
    time.sleep(2.0)
    shot(page, "02_live_recording_page_loaded", "Live Recording page (S1 + S2 panels, both idle)")

    # ---------- C. Set interface = 'any' on S1 ----------
    print("\n[C] Set S1 interface to 'any'")
    # The dropdown has id={'session':'S1','type':'live-iface'} - alphabetized in HTML
    # Open it by clicking the dcc.Dropdown
    iface_dd = page.locator('[id*=\'"type":"live-iface"\'][id*=\'"session":"S1"\']')
    if not iface_dd.count():
        # Try with session first then type (alphabetized)
        iface_dd = page.locator('[id*=\'"session":"S1"\'][id*=\'"type":"live-iface"\']')
    print(f"  iface dropdown found: {iface_dd.count()}")
    iface_dd.first.click()
    time.sleep(0.5)
    # Click the "2: any" option in the dropdown
    page.get_by_text("2: any", exact=False).first.click()
    time.sleep(0.5)
    shot(page, "03_iface_set_to_any", "S1 interface set to 'any' (Linux all-interfaces)")

    # ---------- D. Click S1's Record button ----------
    print("\n[D] Click S1 Record button")
    # Multiple "⏺ Record" buttons exist (S1 + S2). S1 is first.
    rec_s1 = page.locator('[id*=\'"action":"record"\'][id*=\'"session":"S1"\']')
    print(f"  S1 record button found: {rec_s1.count()}")
    rec_s1.first.click()
    print("  clicked Record on S1")
    time.sleep(2.0)
    shot(page, "04_recording_started", "Recording started - State should now read 'Recording'")

    # ---------- E. Start traffic generator + wait + intermediate screenshots ----------
    print("\n[E] Starting background traffic generator + sampling 130s of recording")
    tgen = threading.Thread(target=traffic_gen, daemon=True)
    tgen.start()
    print("  traffic generator started")
    record_start = time.time()
    sample_times = [10, 30, 60, 90, 125]
    for st in sample_times:
        while time.time() - record_start < st:
            time.sleep(0.5)
        elapsed = int(time.time() - record_start)
        try:
            shot(page, f"05_recording_t{elapsed:03d}s", f"Recording in progress @ t={elapsed}s")
        except Exception as e:
            print(f"  shot at t={st}s failed: {e}")
        # Inspect on-disk chunks
        try:
            chunks = list(Path("/root/netsec_sessions").glob("*S1*"))
            sizes = [(c.name, c.stat().st_size) for c in chunks]
            REPORT["tshark_chunks_observed"].append({
                "t": elapsed, "chunks": sizes
            })
            print(f"  t={elapsed}s: {len(chunks)} chunk file(s) on disk, "
                  f"total {sum(s for _,s in sizes):,} bytes")
        except Exception as e:
            print(f"  chunk check: {e}")

    # ---------- F. Stop & Save ----------
    print("\n[F] Click S1 Stop & Save")
    stop_s1 = page.locator('[id*=\'"action":"stop"\'][id*=\'"session":"S1"\']')
    print(f"  Stop button found: {stop_s1.count()}")
    stop_s1.first.click()
    print("  clicked Stop & Save - mergecap should merge chunks now")
    # Wait for the pending-snapshot card to appear
    for _ in range(30):
        try:
            t = page.inner_text("body")
            if "Analyze" in t and "recording" in t.lower():
                break
        except Exception: pass
        time.sleep(0.5)
    time.sleep(2.0)
    shot(page, "06_after_stop_save", "After Stop & Save - pending-snapshot card with Analyze button")

    # ---------- G. Click Analyze on the pending-snapshot ----------
    print("\n[G] Click Analyze on pending snapshot")
    # Look for the Analyze button within the snapshot card
    # The pending-snapshot has an Analyze button. ID pattern unknown - try locating by text within container
    try:
        analyze_pending = page.get_by_role("button", name=re.compile(r"^.*Analyze.*$"))
        # Filter to ones with session S1
        n = analyze_pending.count()
        print(f"  found {n} Analyze-like buttons")
        # Pick the one in the S1 panel - typically the last one visible
        # Actually, the pending snapshot Analyze should appear in the S1 panel
        for i in range(n):
            try:
                btn = analyze_pending.nth(i)
                if btn.is_visible():
                    txt = btn.inner_text()
                    if "Analyze" in txt and len(txt) < 30:  # not the staged-analyze-btn on choice
                        print(f"  trying button {i}: '{txt}'")
                        btn.click()
                        break
            except Exception: pass
    except Exception as e:
        print(f"  could not find pending Analyze: {e}")

    print("  waiting for analysis (up to 60s)...")
    # Wait for the analysed dashboard view
    for sec in range(60):
        time.sleep(1)
        try:
            t = page.inner_text("body").lower()
            if "top talkers" in t and ("github" in t or "pkts" in t):
                break
        except Exception: pass
    time.sleep(2.0)
    shot(page, "07_after_analysis", "After analysis - dashboard should show the captured traffic")

    # ---------- H. Stop traffic generator and inspect ----------
    TRAFFIC_RUN["go"] = False
    print("\n[H] Stopping traffic generator")
    tgen.join(timeout=3)

    # Visit Top Talkers, Protocols, Devices to see real captured traffic
    print("\n[I] Visit a few views of the captured traffic")
    for label in ["Top Talkers", "Protocols", "Devices", "Traffic Timeline", "Burst vs Scan"]:
        try:
            page.get_by_text(label, exact=False).first.click(timeout=3000)
            time.sleep(1.2)
            slug = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            shot(page, f"08_view_{slug}", f"Captured traffic view: {label}")
        except Exception as e:
            print(f"  {label}: {e}")

    # ---------- J. Check resulting PCAP on disk ----------
    print("\n[J] Inspect resulting PCAP on disk")
    try:
        chunks = list(Path("/root/netsec_sessions").glob("*S1*"))
        for c in sorted(chunks):
            print(f"  {c.name}  ({c.stat().st_size:,} bytes)")
        # tshark -r the final merged file if found
        merged = sorted([c for c in chunks if "merged" in c.name.lower() or "saved" in c.name.lower()])
        if not merged: merged = chunks
        if merged:
            best = sorted(merged, key=lambda p: p.stat().st_size, reverse=True)[0]
            ts = subprocess.check_output(["tshark", "-r", str(best), "-q", "-z", "io,stat,0"],
                                          stderr=subprocess.STDOUT, timeout=10).decode()
            print("=== tshark -r io,stat ===")
            print(ts)
            REPORT["final_pcap"] = {"path": str(best), "bytes": best.stat().st_size, "io_stat": ts}
    except Exception as e:
        print(f"  pcap inspection: {e}")

    REPORT["server_500s"] = s500[0]
    ctx.close(); browser.close()

with open(OUT / "REPORT.json", "w", encoding="utf-8") as f:
    json.dump(REPORT, f, indent=2, default=str)

print("\n" + "=" * 60)
print("LIVE CAPTURE DIAGNOSTIC COMPLETE")
print("=" * 60)
print(f"  Screenshots:            {len(REPORT['screenshots'])}")
print(f"  Tshark chunks observed: {len(REPORT['tshark_chunks_observed'])}")
print(f"  Server 500 errors:      {REPORT['server_500s']}")
print(f"  Console errors:         {len(REPORT['console_errors'])}")
if "final_pcap" in REPORT:
    print(f"  Final PCAP:             {REPORT['final_pcap']['bytes']:,} bytes")
