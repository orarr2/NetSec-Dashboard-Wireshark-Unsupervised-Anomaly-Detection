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
    NETSEC_NOTIFY_EMAIL   fallback recipient when the upload had no
                          X-Notify-Email header (solo-operator setup)
    N8N_WEBHOOK_URL       fallback delivery when SMTP fails, or the sole
                          channel when no recipient is configured
"""
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from . import baseline, db, enrich, notify, reconcile, report_html
from . import report_map, report_pdf, results, storage

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


def _default_analyze(pcap_path, label, baseline_conn=None,
                     current_session_id=None, panel_override=None):
    """analyze_fn contract: (out, assembled, client, context, S, findings).
    baseline_conn (L5) is an optional DB connection so the judge sees
    each candidate's prior-session history. current_session_id excludes
    the running session from the history lookup.
    panel_override (N1) is a per-upload LLM_JUDGE_PANEL spec picked by
    the dashboard's Send-to-VM dropdown - overrides the .env default
    for just this session."""
    from llm_judge import judge_cli
    return judge_cli.analyze_and_judge(pcap_path, label=label or "S1",
                                       return_session=True,
                                       baseline_conn=baseline_conn,
                                       current_session_id=current_session_id,
                                       panel_spec_override=panel_override)


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
    """Delegate to server.notify.deliver, which walks the SMTP -> n8n
    fallback chain and returns one log entry per attempted mechanism.
    Never raises: a broken mailbox must not lose an analysis that
    already cost minutes of compute."""
    try:
        log = notify.deliver(session, out, report_paths)
    except Exception as e:
        print(f"[worker] notify pipeline crashed (continuing): {e}",
              flush=True)
        return
    for mode, ok, msg in log:
        tag = "" if ok else "FAILED "
        print(f"[worker] notify {tag}[{mode}]: {msg}", flush=True)


# The libpcap file header is 24 bytes. Anything shorter cannot be a
# valid capture, and letting tshark run on 0 bytes returned the cryptic
# "Invalid value NaN" from the pandas parse layer instead of a message
# a human could act on. Caught early here so the failure row explains
# itself.
_MIN_PCAP_HEADER_BYTES = 24


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
        size = os.path.getsize(pcap_path)
        if size < _MIN_PCAP_HEADER_BYTES:
            raise ValueError(
                f"PCAP is {size} byte(s) - too small to be a valid capture "
                f"(need at least {_MIN_PCAP_HEADER_BYTES} for the libpcap "
                f"file header). Nothing to analyze.")

        # L5+N1: pass DB conn + session_id (baseline_history) and the
        # per-upload panel spec (N1 dropdown). analyze_fn contract
        # accepts baseline_conn / current_session_id / panel_override.
        # Injected stubs in tests may ignore them (TypeError fallback).
        panel_override = job.get("judge_panel_override")
        try:
            out, assembled, client, context, S, findings = analyze_fn(
                pcap_path, job.get("label"),
                baseline_conn=conn, current_session_id=sid,
                panel_override=panel_override)
        except TypeError:
            # older analyze_fn signature (positional only) - fall back
            out, assembled, client, context, S, findings = analyze_fn(
                pcap_path, job.get("label"))
        if not isinstance(S, dict):
            S = {}
        # Provenance for the report renderer - the analyze_fn only sees
        # the sha-named storage path (0bbe30ec_new4.pcapng). The user-
        # facing metadata (original filename, which sensor uploaded)
        # lives in the DB row we already have.
        S["_source_pcap_name"] = job.get("orig_name")
        try:
            sensor_row = conn.execute(
                "SELECT name FROM sensors WHERE id=?",
                (job.get("sensor_id"),)).fetchone()
            if sensor_row:
                S["_source_sensor"] = sensor_row["name"]
        except Exception:
            pass

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
                 "summary": os.path.join(rep_dir, "summary.md"),
                 "html": os.path.join(rep_dir, "report.html"),
                 "pdf": os.path.join(rep_dir, "report.pdf")}

        with open(paths["json"], "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2, default=str)
        md = md_fn(pcap_path, out, assembled, client, context)
        with open(paths["md"], "w", encoding="utf-8") as f:
            f.write(md)
        # Executive summary = the notification email's whole body. The
        # full report travels only as the PDF attachment - nobody reads
        # a 7-page wall of text inside an email client.
        try:
            from llm_judge import judge_cli
            summary_md = judge_cli.render_exec_summary(pcap_path, out,
                                                       context)
            with open(paths["summary"], "w", encoding="utf-8") as f:
                f.write(summary_md)
        except Exception as e:
            print(f"[worker] summary render skipped: {e}", flush=True)
            paths.pop("summary", None)
        session = db.get_session(conn, sid)
        # Verdict banner: worst verdict on top of the HTML/PDF report.
        # results are priority-sorted, but "worst" must be severity-
        # ranked - a high-priority suspicious must not mask a malicious.
        _sev_rank = {"malicious": 0, "suspicious": 1, "benign": 2}
        _verdicts = [((r.get("verdict") or {}).get("verdict"))
                     for r in (out.get("results") or [])]
        _verdicts = [v for v in _verdicts if v in _sev_rank]
        worst = min(_verdicts, key=_sev_rank.get) if _verdicts else "benign"
        counts = {v: _verdicts.count(v) for v in _sev_rank}
        banner = {"severity": worst,
                  "text": (f"{worst.upper()} - {counts['malicious']} "
                           f"malicious / {counts['suspicious']} suspicious "
                           f"/ {counts['benign']} benign - session {sid} "
                           f"({session.get('label') or 'capture'})")}
        html = report_html.render(session, md,
                                  extra={"reconciliation": recon},
                                  banner=banner)
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


def process_compare_job(conn, job, data_root=None, judge_fn=None,
                        render_fn=None):
    """One claimed compare_job end to end. Reads the two per-session
    verdicts.json files (already sitting on disk from the per-session
    runs), asks the LLM panel ONE pair-level question via judge_fn, and
    mails a single combined report. Raises nothing: failures land in
    compare_jobs.error.

    judge_fn signature: (s1_out, s2_out, clients, s1_label, s2_label,
    prompt_version) -> {"verdict":..., "panel_report":...,
    "pair_blob":..., "prompt_version":...}
    Injected so tests can skip the LLM call.

    render_fn signature: (job, s1_session, s2_session, pair_result)
    -> (summary_md, full_md) - defaults to the compare_report renderer
    which stays out of the hot path for tests that only want the DB shape.
    """
    from llm_judge import judge_config, judge_core, llm_clients  # noqa
    from . import compare_report

    judge_fn = judge_fn or judge_core.judge_session_pair
    render_fn = render_fn or compare_report.render
    make_clients = llm_clients.make_panel_clients
    root = storage.data_root(data_root)
    jid = job["id"]
    s1_id, s2_id = job["s1_session_id"], job["s2_session_id"]

    try:
        s1_session = db.get_session(conn, s1_id)
        s2_session = db.get_session(conn, s2_id)
        if not s1_session or not s2_session:
            raise ValueError(
                f"compare_job {jid}: session missing "
                f"(s1={s1_session is not None}, "
                f"s2={s2_session is not None})")
        for tag, sess in (("s1", s1_session), ("s2", s2_session)):
            if sess.get("status") != "done":
                raise ValueError(
                    f"compare_job {jid}: {tag} session {sess['id']} "
                    f"status={sess.get('status')} (must be 'done')")

        def _load_out(session_id):
            rep = db.get_report(conn, session_id, "json")
            if not rep or not os.path.isfile(rep["path"]):
                raise FileNotFoundError(
                    f"session {session_id}: verdicts.json missing")
            with open(rep["path"], "r", encoding="utf-8") as fh:
                return json.load(fh)

        s1_out = _load_out(s1_id)
        s2_out = _load_out(s2_id)

        # Panel resolution: honor the per-upload override the button
        # posted; empty spec -> the .env default. Same shape as
        # judge_cli._resolve_panel_spec, but that lives inside a CLI
        # module we don't want to import from the worker just for this.
        panel_spec = (job.get("judge_panel_override") or "").strip()
        if not panel_spec:
            try:
                from llm_judge import panel_presets
                preset = panel_presets.preset_by_id(
                    panel_presets.DEFAULT_PRESET_ID) or {}
                panel_spec = preset.get("spec") or ""
            except Exception:
                panel_spec = ""
        # If the ingest_api resolved a preset id already (e.g. "fresh_cloud_3")
        # we still need to expand it to the raw spec.
        try:
            from llm_judge import panel_presets
            preset_hit = panel_presets.preset_by_id(panel_spec)
            if preset_hit and preset_hit.get("spec"):
                panel_spec = preset_hit["spec"]
        except Exception:
            pass
        panel_spec = panel_spec or os.environ.get("LLM_JUDGE_PANEL", "")
        if not panel_spec:
            raise RuntimeError(
                "compare_job needs an LLM panel spec - set "
                "LLM_JUDGE_PANEL in .env or pass a preset via "
                "X-Judge-Panel")
        entries = judge_core.parse_panel_spec(panel_spec)
        clients, init_failures = make_clients(
            entries, verdict_schema=judge_core.PAIR_VERDICT_SCHEMA)
        if not clients:
            raise RuntimeError(
                f"compare_job {jid}: no panel clients could be built "
                f"({init_failures})")

        pair = judge_fn(s1_out, s2_out, clients,
                        s1_label=(s1_session.get("label") or "S1"),
                        s2_label=(s2_session.get("label") or "S2"),
                        prompt_version=None)

        # Write outputs under reports/compare/<jid>/
        rep_dir = os.path.join(root, "reports", "compare", str(jid))
        os.makedirs(rep_dir, exist_ok=True)
        paths = {"json": os.path.join(rep_dir, "verdict.json"),
                 "summary": os.path.join(rep_dir, "summary.md"),
                 "md": os.path.join(rep_dir, "report.md"),
                 "html": os.path.join(rep_dir, "report.html"),
                 "pdf": os.path.join(rep_dir, "report.pdf")}
        # verdict.json is the machine-readable single source of truth
        with open(paths["json"], "w", encoding="utf-8") as fh:
            json.dump({"job_id": jid, "s1_session_id": s1_id,
                       "s2_session_id": s2_id, **pair}, fh,
                      ensure_ascii=False, indent=2, default=str)
        # summary_md is the mail body; full_md is the PDF/HTML source
        summary_md, full_md = render_fn(job, s1_session, s2_session, pair)
        with open(paths["summary"], "w", encoding="utf-8") as fh:
            fh.write(summary_md)
        with open(paths["md"], "w", encoding="utf-8") as fh:
            fh.write(full_md)
        # HTML wraps the full_md through the same charset-safe wrapper
        # the per-session report uses; the posture drives the banner tint
        from llm_judge import send_report
        posture = ((pair.get("verdict") or {}).get("posture_delta")
                   or "mixed")
        banner = {"severity": posture,
                  "text": (f"Posture: {posture.upper()} - "
                           f"{s1_session.get('label') or s1_id} vs "
                           f"{s2_session.get('label') or s2_id}")}
        html = send_report.markdown_to_html(full_md, banner=banner)
        with open(paths["html"], "w", encoding="utf-8") as fh:
            fh.write(html)
        try:
            pdf_path = report_pdf.render(html, paths["pdf"])
        except Exception as e:
            print(f"[worker] compare {jid}: PDF render skipped ({e})",
                  flush=True)
            pdf_path = None

        db.mark_compare_done(
            conn, jid,
            verdict_json=json.dumps(pair.get("verdict") or {},
                                    ensure_ascii=False),
            stats_json=json.dumps({
                "s1_totals": pair.get("pair_blob", {}).get("totals",
                                                            {}).get("s1"),
                "s2_totals": pair.get("pair_blob", {}).get("totals",
                                                            {}).get("s2"),
                "flip_count_total":
                    pair.get("pair_blob", {}).get("flip_count_total", 0),
                "models_answered": pair.get("models_answered", []),
                "models_total": pair.get("models_total"),
            }, ensure_ascii=False),
            prompt_version=pair.get("prompt_version"))

        # Notify. Reuse notify.deliver with a synthetic session-like
        # dict so the same SMTP -> n8n fallback covers compare jobs
        # without a second delivery module.
        synthetic = {
            "id": f"compare-{jid}",
            "label": f"compare S{s1_id}↔S{s2_id}",
            "notify_email": job.get("notify_email"),
            "kind": job.get("kind", "prod"),
        }
        deliver_paths = {"summary": paths["summary"],
                         "md": paths["md"],
                         "html": paths["html"]}
        if pdf_path:
            deliver_paths["pdf"] = pdf_path
        # Wrap in a fake `out` that the mailer's summary path can read
        wrapped = {"stats": {"prompt_version": pair.get("prompt_version"),
                             "models": pair.get("models_answered")},
                   "results": [],
                   "analyst_commentary": None,
                   "_compare_summary_md": summary_md}
        _notify(synthetic, wrapped, deliver_paths)
        print(f"[worker] compare_job {jid} done "
              f"(S{s1_id} vs S{s2_id}, "
              f"posture={pair['verdict'].get('posture_delta')}, "
              f"answered={len(pair.get('models_answered', []))}/"
              f"{pair.get('models_total')})", flush=True)
        return True
    except Exception as e:
        db.mark_compare_error(conn, jid, e)
        print(f"[worker] compare_job {jid} FAILED: {e}", flush=True)
        return False


def run_once(conn=None, analyze_fn=None, md_fn=None, data_root=None):
    """Claim and process at most one job. Returns the session id
    (or the compare_job id, prefixed) when work was picked up, or
    None when both queues are empty. Compare jobs are drained
    BEFORE session jobs when both queues have work: a comparison
    depends on already-done sessions, so finishing the pair as soon
    as it is queueable keeps the mail latency close to the moment
    the user clicked.
    """
    own = conn is None
    conn = conn or db.connect()
    try:
        cjob = db.claim_next_compare_job(conn)
        if cjob is not None:
            process_compare_job(conn, cjob, data_root=data_root)
            return f"compare:{cjob['id']}"
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
