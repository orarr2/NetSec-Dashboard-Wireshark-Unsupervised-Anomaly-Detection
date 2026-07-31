"""Analysis worker - the queue consumer (spec section 5.2).

Claims queued sessions from the history DB, runs the EXISTING pipeline
unchanged (judge_cli.analyze_and_judge on the raw PCAP - decision
IDX-01/section 3), persists everything to the DB, reconciles telemetry
(spec 12.2), renders the JSON/MD/HTML/PDF reports, and notifies.

The pipeline and markdown renderer are injectable so the loop is fully
testable without tshark, torch or an LLM:

    run_once(conn, analyze_fn=stub, md_fn=stub)

Run for real:  python -m server.worker      (repo root, deps installed)
Environment:
    NETSEC_DATA_ROOT      storage root (default /srv/netsec)
    NETSEC_DB             history DB path override
    NETSEC_POLL_S         queue poll interval (default 10)
    NETSEC_INFRA_DSTS     declared infra destinations for reconciliation
    NETSEC_NOTIFY_EMAIL   optional: mail each report (send_report env)
    N8N_WEBHOOK_URL       optional: POST a JSON summary per session
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import baseline, db, enrich, reconcile, report_html, report_map
from . import report_pdf, results, storage

SHODAN_MAX_PEERS = int(os.environ.get("NETSEC_SHODAN_MAX_PEERS", "5"))


def _shodan_enabled():
    # Take only the first token, so an inline "0  # comment" in .env (which
    # some parsers keep as part of the value) still counts as off. Requires
    # an explicit "1" / "true" / "on" / "yes" to enable - fail-closed, since
    # this turns on a paid / rate-limited external lookup.
    raw = os.environ.get("NETSEC_ENABLE_SHODAN", "").strip().split()
    return bool(raw) and raw[0].lower() in ("1", "true", "on", "yes")


def enrich_threat_intel(conn, out, assembled, S, shodan_fn=None):
    """Attach external-peer threat intel to judged candidates and re-rank
    by the now-active W_TI weight (stage YA). Off unless NETSEC_ENABLE_
    SHODAN is set - then, for each judged internal IP, its public peers
    (from S['ip_pairs']) are looked up on Shodan and the worst reputation
    becomes the candidate's ti_signals.score. Returns the count enriched."""
    if not _shodan_enabled():
        return 0
    from llm_judge import judge_core, threat_intel
    shodan_fn = shodan_fn or (lambda ip: enrich.shodan_ip(conn, ip))
    cands = {c["candidate_id"]: c
             for c in (assembled.get("candidates") or [])}
    pairs = S.get("ip_pairs") or {}
    iso_min, iso_max = judge_core._iso_bounds(list(cands.values())) \
        if cands else (None, None)
    n = 0
    for r in out.get("results") or []:
        cand = cands.get(r.get("candidate_id"))
        if not cand:
            continue
        internal = r["candidate_id"]
        peers = [dst for (src, dst), _ in pairs.items()
                 if src == internal and enrich.is_public_ip(dst)]
        best, best_info = 0.0, None
        for peer in peers[:SHODAN_MAX_PEERS]:
            info = threat_intel.classify(shodan_fn(peer))
            if info["score"] > best:
                best, best_info = info["score"], dict(info, peer=peer)
        if best_info:
            cand["ti_signals"] = {"score": best, "detail": best_info}
            r["ti_signals"] = cand["ti_signals"]
            r["priority"] = judge_core.priority_score(
                cand, r["verdict"], iso_min, iso_max)
            n += 1
    if n:
        out["results"].sort(key=lambda x: -x.get("priority", 0))
    return n


def _collect_bssids(S):
    """Best-effort gather of (bssid, rssi, distance_m) the capture saw.
    Defensive about the S-dict shape - a missing structure just yields
    fewer points, never an error."""
    points = []
    top = S.get("wifi_bssid") if isinstance(S, dict) else None
    if top:
        points.append({"bssid": str(top).lower(), "ssid": S.get("wifi_ssid"),
                       "rssi": None, "distance_m": None})
    wlan = S.get("wlan_features") if isinstance(S, dict) else None
    if isinstance(wlan, dict):
        for mac, feat in wlan.items():
            samples = (feat or {}).get("rssi_samples") or []
            if not samples:
                continue
            mean = sum(samples) / len(samples)
            points.append({"bssid": str(mac).lower(),
                           "ssid": (feat or {}).get("ssid"),
                           "rssi": round(mean, 1), "distance_m": None})
    return points


def build_map_report(conn, S, out_path, wigle_fn=None):
    """Locate the session's BSSIDs via Wigle and render the geo map.
    Returns out_path when at least one AP was located, else None."""
    wigle_fn = wigle_fn or (lambda b: enrich.wigle_bssid(conn, b))
    located = []
    for p in _collect_bssids(S):
        info = wigle_fn(p["bssid"])
        if info and info.get("lat") is not None:
            located.append(dict(p, ssid=p.get("ssid") or info.get("ssid"),
                                lat=info["lat"], lon=info["lon"]))
    if not located:
        return None
    return report_map.render(located, out_path)


def _default_analyze(pcap_path, label):
    """analyze_fn contract: (out, assembled, client, context, S, findings)."""
    from llm_judge import judge_cli
    return judge_cli.analyze_and_judge(pcap_path, label=label or "S1",
                                       return_session=True)


def _default_md(pcap_path, out, assembled, client, context):
    from llm_judge import judge_cli
    return judge_cli._render_markdown(pcap_path, out, assembled, client,
                                      context=context)


def _tshark_version():
    try:
        tsh = shutil.which("tshark")
        if not tsh:
            return None
        first = subprocess.check_output([tsh, "--version"], text=True,
                                        stderr=subprocess.DEVNULL,
                                        timeout=10).splitlines()[0]
        return first.strip()[:100]
    except Exception:
        return None


def _notify(session, out, report_paths):
    """Best-effort email + webhook. A broken mailbox must never lose an
    analysis that already cost minutes of compute (send_report's rule)."""
    email = os.environ.get("NETSEC_NOTIFY_EMAIL", "").strip()
    if email:
        try:
            from llm_judge import send_report
            with open(report_paths["md"], encoding="utf-8") as f:
                md = f.read()
            ok, msg = send_report.send_report(
                email, md,
                subject=f"NetSec verdicts - session {session['id']} "
                        f"({session.get('label')})")
            print(f"[worker] email: {msg}", flush=True)
        except Exception as e:
            print(f"[worker] email failed (continuing): {e}", flush=True)
    hook = os.environ.get("N8N_WEBHOOK_URL", "").strip()
    if hook:
        try:
            summary = {
                "session_id": session["id"], "label": session.get("label"),
                "kind": session.get("kind"), "sha256": session.get("sha256"),
                "results": len(out.get("results") or []),
                "worst": (out.get("results") or [{}])[0].get(
                    "verdict", {}).get("verdict"),
            }
            req = urllib.request.Request(
                hook, data=json.dumps(summary).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=15).read()
        except Exception as e:
            print(f"[worker] webhook failed (continuing): {e}", flush=True)


def process_job(conn, job, analyze_fn=None, md_fn=None, data_root=None):
    """One claimed session end to end. Raises nothing: failures land in
    sessions.error and the loop moves on."""
    analyze_fn = analyze_fn or _default_analyze
    md_fn = md_fn or _default_md
    root = storage.data_root(data_root)
    sid = job["id"]
    pcap_path = job["storage_path"]
    try:
        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(f"pcap missing on disk: {pcap_path}")

        out, assembled, client, context, S, findings = analyze_fn(
            pcap_path, job.get("label"))
        if not isinstance(S, dict):
            S = {}

        # OSINT threat-intel re-rank (stage YA) BEFORE persistence, so the
        # stored priority reflects an external peer's reputation. Off
        # without NETSEC_ENABLE_SHODAN - then a no-op, results unchanged.
        try:
            n_ti = enrich_threat_intel(conn, out, assembled, S)
            if n_ti:
                print(f"[worker] session {sid}: threat-intel enriched "
                      f"{n_ti} candidate(s)", flush=True)
        except Exception as e:
            print(f"[worker] threat-intel enrichment skipped: {e}",
                  flush=True)

        results.write_all(conn, sid, S, findings, assembled, out)
        recon = reconcile.reconcile(conn, sid, S)
        # score this session against each device's own history; a device
        # with no baseline yet is simply skipped (spec section 3/D3)
        try:
            n_dev = baseline.write_baseline_findings(conn, sid)
            if n_dev:
                print(f"[worker] session {sid}: {n_dev} baseline "
                      f"deviation(s)", flush=True)
        except Exception as e:
            print(f"[worker] baseline scoring skipped: {e}", flush=True)

        rep_dir = os.path.join(root, "reports", str(sid))
        os.makedirs(rep_dir, exist_ok=True)
        paths = {"json": os.path.join(rep_dir, "verdicts.json"),
                 "md": os.path.join(rep_dir, "verdicts.md"),
                 "html": os.path.join(rep_dir, "report.html"),
                 "pdf": os.path.join(rep_dir, "report.pdf")}

        with open(paths["json"], "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2, default=str)
        md = md_fn(pcap_path, out, assembled, client, context)
        with open(paths["md"], "w", encoding="utf-8") as f:
            f.write(md)
        session = db.get_session(conn, sid)
        html = report_html.render(session, md,
                                  extra={"reconciliation": recon})
        with open(paths["html"], "w", encoding="utf-8") as f:
            f.write(html)
        pdf = report_pdf.render(html, paths["pdf"])

        for kind in ("json", "md", "html"):
            db.add_report(conn, sid, kind, paths[kind])
        if pdf:
            db.add_report(conn, sid, "pdf", pdf)
        # geo map of located access points (stage YA) - only when Wigle
        # locates at least one BSSID; otherwise skipped like the PDF
        try:
            map_path = build_map_report(
                conn, S, os.path.join(rep_dir, "map.html"))
            if map_path:
                db.add_report(conn, sid, "map", map_path)
        except Exception as e:
            print(f"[worker] map report skipped: {e}", flush=True)

        stats = out.get("stats") or {}
        n_pkts = S.get("n_pkts") if isinstance(S, dict) else None
        ips = S.get("ips_src") if isinstance(S, dict) else None
        duration = None
        try:
            duration = (S["t1"] - S["t0"]).total_seconds()
        except Exception:
            pass
        db.mark_done(conn, sid, n_pkts=n_pkts,
                     n_ips=len(ips) if ips is not None else None,
                     duration_s=duration,
                     prompt_version=stats.get("prompt_version"),
                     tshark_version=_tshark_version(),
                     pipeline_version=os.environ.get(
                         "NETSEC_PIPELINE_VERSION"))
        _notify(session, out, paths)
        print(f"[worker] session {sid} done "
              f"({len(out.get('results') or [])} verdicts)", flush=True)
        return True
    except Exception as e:
        db.mark_error(conn, sid, e)
        print(f"[worker] session {sid} FAILED: {e}", flush=True)
        return False


def run_once(conn=None, analyze_fn=None, md_fn=None, data_root=None):
    """Claim and process at most one job. Returns the session id, or
    None when the queue is empty."""
    own = conn is None
    conn = conn or db.connect()
    try:
        job = db.claim_next_job(conn)
        if job is None:
            return None
        process_job(conn, job, analyze_fn=analyze_fn, md_fn=md_fn,
                    data_root=data_root)
        return job["id"]
    finally:
        if own:
            conn.close()


def main():
    poll_s = float(os.environ.get("NETSEC_POLL_S", "10"))
    print(f"[worker] polling every {poll_s:.0f}s "
          f"(db={db.default_db_path()})", flush=True)
    conn = db.connect()
    try:
        while True:
            if run_once(conn) is None:
                time.sleep(poll_s)
    except KeyboardInterrupt:
        print("[worker] stopped", flush=True)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
