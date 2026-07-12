"""AI Second Opinion panel for the NetSec Dashboard.

Bridges the main dashboard (app/) with the standalone LLM-as-Judge
add-on (llm_judge/). The dashboard imports this module conditionally, so
a missing llm_judge/ folder (or missing provider config) does not break
the dashboard - the panel just shows setup instructions instead.

State model:
- AI_JUDGE_CACHE holds the last-run verdicts per session ("s1" / "s2").
- Switching to a different chart and back keeps the verdicts.
- Loading a new PCAP into a session should clear its cache
  (dashboard call: reset_cache_for_session("s1")).

The panel is composed of pure functions that return Dash components; it
takes the palette (INK, INK_DIM, ...) as parameters so it stays
independent of the dashboard's exact styling variables.
"""
from datetime import datetime, timezone

# Module-level: last-run verdicts dict per session, keyed by "s1"/"s2".
AI_JUDGE_CACHE = {"s1": None, "s2": None}


def reset_cache_for_session(session_key):
    """Called by the dashboard when a session is (re)loaded."""
    if session_key in AI_JUDGE_CACHE:
        AI_JUDGE_CACHE[session_key] = None


def _try_import():
    """Import the judge lazily; report success + reason on failure."""
    import os
    import sys
    try:
        _HERE = os.path.dirname(os.path.abspath(__file__))
        _ROOT = os.path.dirname(_HERE)
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from llm_judge import judge_config, judge_core        # noqa: E402
        from llm_judge.llm_clients import make_client         # noqa: E402
        from llm_judge.judge_cli import build_context         # noqa: E402
        return {
            "ok": True,
            "judge_config": judge_config,
            "judge_core": judge_core,
            "make_client": make_client,
            "build_context": build_context,
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def is_available():
    return _try_import()["ok"]


def provider_status():
    """Return (ok, provider, model, message) about the current provider."""
    import os
    j = _try_import()
    if not j["ok"]:
        return False, "n/a", "n/a", j["error"]
    cfg = j["judge_config"]
    provider = cfg.LLM_JUDGE_PROVIDER
    if provider == "claude":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return (False, provider, cfg.CLAUDE_MODEL,
                    "No API key in the environment - set ANTHROPIC_API_KEY "
                    "before starting the dashboard, or switch provider.")
        return True, provider, cfg.CLAUDE_MODEL, "Ready"
    if provider == "ollama":
        return (True, provider, cfg.OLLAMA_MODEL,
                f"Ready ({cfg.OLLAMA_HOST}) - needs the Ollama daemon "
                f"running and `{cfg.OLLAMA_MODEL}` pulled.")
    if provider == "openai_compat":
        if not cfg.OPENAI_COMPAT_MODEL:
            return (False, provider, "n/a",
                    "OPENAI_COMPAT_MODEL is not set.")
        return (True, provider, cfg.OPENAI_COMPAT_MODEL,
                f"Ready ({cfg.OPENAI_COMPAT_BASE_URL})")
    return False, provider, "n/a", f"Unknown provider: {provider!r}"


# --------------------------------------------------------------------------
# Run the judge on a session (pure Python, no Dash)
# --------------------------------------------------------------------------
def run_judge(S, findings):
    """Judge every flagged candidate in one session. Blocks until done;
    on Ollama this may take a couple of minutes on the first call.
    Returns a dict that both round-trips through dcc.Store and feeds
    render_verdicts_card."""
    j = _try_import()
    if not j["ok"]:
        raise RuntimeError(f"Judge not available: {j['error']}")
    assembled = j["judge_core"].assemble_candidates(S, findings)
    client = j["make_client"](
        verdict_schema=j["judge_core"].VERDICT_SCHEMA)
    out = j["judge_core"].judge_candidates(
        assembled["candidates"], client=client, verbose=False)
    context = j["build_context"](S, findings, assembled)
    cfg = j["judge_config"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provider": cfg.LLM_JUDGE_PROVIDER,
        "model": client.model_id,
        "prompt_version": cfg.PROMPT_VERSION,
        "guardrail": bool(cfg.RULE_GUARDRAIL),
        "stats": out["stats"],
        "results": out["results"],
        "dropped": out["dropped"],
        "capped": assembled["capped"],
        "context": context,
    }


# --------------------------------------------------------------------------
# Dash rendering
# --------------------------------------------------------------------------
def _palette(**over):
    p = {
        "INK": "#e8e4f5", "INK_DIM": "#9b94b8", "INK_MUTE": "#5a536f",
        "VIOLET": "#8b5cf6", "VIOLET_BRIGHT": "#a78bfa", "CYAN": "#22d3ee",
        "GLASS_BG": "rgba(255,255,255,0.04)",
        "GLASS_BORDER": "rgba(255,255,255,0.08)",
        "GLASS_BORDER_STRONG": "rgba(255,255,255,0.14)",
    }
    p.update(over)
    return p


def _title_row(session_key, model_label, palette):
    from dash import html
    p = palette
    return html.Div([
        html.Div([
            html.Span("\U0001F9E0",
                      style={"fontSize": "1.5rem", "marginRight": "12px"}),
            html.Span(f"AI Second Opinion — {session_key.upper()}",
                      style={"fontFamily": "'Newsreader', Georgia, serif",
                             "fontSize": "1.6rem", "color": p["INK"],
                             "letterSpacing": "-0.01em"}),
        ], style={"display": "flex", "alignItems": "center"}),
        html.Span(model_label,
                  style={"marginLeft": "auto",
                         "fontFamily": "'JetBrains Mono', monospace",
                         "fontSize": "0.75rem", "color": p["INK_DIM"],
                         "textTransform": "uppercase",
                         "letterSpacing": "0.14em"}),
    ], style={"display": "flex", "alignItems": "center",
              "marginBottom": "18px"})


def _card(children, palette, extra_style=None):
    from dash import html
    p = palette
    style = {
        "padding": "22px 24px", "borderRadius": "16px",
        "background": p["GLASS_BG"],
        "border": f"1px solid {p['GLASS_BORDER_STRONG']}",
        "marginBottom": "14px",
    }
    style.update(extra_style or {})
    return html.Div(children, style=style)


def _run_button(session_key, palette, label="Run AI Second Opinion"):
    from dash import html
    p = palette
    return html.Div(label,
        id={"type": "ai-run-btn", "session": session_key}, n_clicks=0,
        style={"cursor": "pointer", "userSelect": "none",
               "display": "inline-block",
               "padding": "12px 26px", "borderRadius": "12px",
               "background": f"linear-gradient(135deg, {p['VIOLET']}, "
                             f"{p['CYAN']})",
               "color": "white", "fontWeight": "600",
               "fontFamily": "'Inter Tight', sans-serif",
               "fontSize": "0.95rem",
               "boxShadow": f"0 6px 24px rgba(139,92,246,0.35)"})


def render_run_state(session_key, provider_ok, provider, model, msg,
                     n_candidates_hint, palette):
    """Initial state of the panel: describes what will happen + Run button."""
    from dash import html
    p = palette
    dot_color = p["CYAN"] if provider_ok else "#f59e0b"
    action = _run_button(session_key, p) if provider_ok else html.Div(
        "Provider not ready — fix the setup above and reload the "
        "dashboard.",
        style={"color": p["INK_DIM"], "fontStyle": "italic",
               "padding": "10px 0"})
    return html.Div([
        html.P(
            "Ask a language model to cross-reference all detectors "
            "(IsolationForest, DBSCAN, deterministic rules) into a single "
            "verdict per flagged entity, with a reasoning trace and a "
            "recommended action. The advisor never blocks traffic — "
            "it re-ranks and explains.",
            style={"color": p["INK_DIM"], "lineHeight": "1.6",
                   "marginBottom": "18px"}),
        html.Div([
            html.Div(style={"width": "10px", "height": "10px",
                            "borderRadius": "50%", "marginRight": "10px",
                            "background": dot_color,
                            "marginTop": "6px"}),
            html.Div([
                html.Span("Provider: ",
                          style={"color": p["INK_DIM"],
                                 "fontSize": "0.85rem"}),
                html.Span(f"{provider} · {model}",
                          style={"color": p["INK"], "fontWeight": "600",
                                 "fontSize": "0.9rem",
                                 "fontFamily": "'JetBrains Mono', monospace"}),
                html.Div(msg, style={"color": p["INK_DIM"],
                                     "fontSize": "0.8rem",
                                     "marginTop": "4px"}),
            ]),
        ], style={"display": "flex", "alignItems": "flex-start",
                  "marginBottom": "18px"}),
        html.Div([
            html.Span(f"{n_candidates_hint} candidate(s) will be judged.",
                      style={"color": p["INK"], "fontSize": "0.95rem",
                             "marginRight": "18px"}),
            action,
        ], style={"display": "flex", "alignItems": "center"}),
    ])


def _verdict_pill(verdict, palette):
    p = palette
    bg = {"malicious": "#7f1d1d", "suspicious": "#92400e",
          "benign": "#14532d"}.get(verdict, "#374151")
    from dash import html
    return html.Span(verdict.upper(),
        style={"background": bg, "color": "white",
               "padding": "3px 10px", "borderRadius": "999px",
               "fontFamily": "'JetBrains Mono', monospace",
               "fontSize": "0.72rem", "letterSpacing": "0.08em",
               "fontWeight": "700"})


def render_verdicts_card(verdicts_data, session_key, palette):
    """Render the ranked verdict table + metadata + top verdict."""
    from dash import html
    p = palette
    if not verdicts_data:
        return html.Div("No verdicts yet.", style={"color": p["INK_DIM"]})
    stats = verdicts_data["stats"]
    ctx = verdicts_data.get("context") or {}
    results = verdicts_data["results"]
    top = results[0] if results else None

    # ---- metadata strip ----
    meta = html.Div([
        html.Span(f"model {verdicts_data['model']}", style={
            "background": "rgba(139,92,246,0.15)", "color": p["INK"],
            "padding": "4px 10px", "borderRadius": "999px",
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "0.75rem", "marginRight": "8px"}),
        html.Span(f"prompt {verdicts_data['prompt_version']}", style={
            "background": "rgba(34,211,238,0.15)", "color": p["INK"],
            "padding": "4px 10px", "borderRadius": "999px",
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "0.75rem", "marginRight": "8px"}),
        html.Span(("guardrail on" if verdicts_data["guardrail"]
                   else "guardrail off"), style={
            "background": "rgba(251,191,36,0.12)", "color": p["INK"],
            "padding": "4px 10px", "borderRadius": "999px",
            "fontFamily": "'JetBrains Mono', monospace",
            "fontSize": "0.75rem", "marginRight": "8px"}),
        html.Span(f"judged {stats['judged']} · dropped "
                  f"{stats['dropped']} · capped "
                  f"{len(verdicts_data['capped'])}",
                  style={"color": p["INK_DIM"], "fontSize": "0.8rem"}),
    ], style={"marginBottom": "18px"})

    # ---- pipeline stats ----
    pstats = None
    if ctx:
        ml = ctx["ml"]
        rules = ctx["rules"]
        rule_bits = []
        if rules["scan_alerts"]:
            rule_bits.append(f"{rules['scan_alerts']} scan alert(s)")
        if rules["flood_alerts"]:
            rule_bits.append(f"{rules['flood_alerts']} flood alert(s)")
        if rules["amp_alerts"]:
            rule_bits.append(f"{rules['amp_alerts']} DNS-amp alert(s)")
        if rules["arp_spoofing_ips"]:
            rule_bits.append(
                f"{rules['arp_spoofing_ips']} ARP-multi-MAC IP(s)")
        rule_line = " · ".join(rule_bits) if rule_bits \
            else "no deterministic rule fired"
        pstats = _card([
            html.Div("PIPELINE STATS", style={
                "color": p["INK_DIM"], "fontSize": "0.72rem",
                "letterSpacing": "0.14em", "marginBottom": "10px",
                "fontFamily": "'JetBrains Mono', monospace"}),
            html.Div([
                html.Span(f"{ctx['n_packets']:,} packets · "
                          f"{ctx['duration_s']}s · "
                          f"{ctx['total_ips']} src IPs · "
                          f"{ctx['total_macs']} MACs",
                          style={"color": p["INK"],
                                 "fontSize": "0.92rem",
                                 "marginBottom": "6px", "display": "block"}),
                html.Span(f"ML: {ml['isolation_forest_anomalies']} "
                          f"IsolationForest anomal"
                          f"{'y' if ml['isolation_forest_anomalies']==1 else 'ies'}"
                          f" · {ml['dbscan_noise']} DBSCAN noise "
                          f"({ml['dbscan_clusters']} cluster"
                          f"{'' if ml['dbscan_clusters']==1 else 's'}"
                          f")",
                          style={"color": p["INK_DIM"],
                                 "fontSize": "0.85rem",
                                 "display": "block",
                                 "marginBottom": "4px"}),
                html.Span(f"Rules: {rule_line}",
                          style={"color": p["INK_DIM"],
                                 "fontSize": "0.85rem",
                                 "display": "block"}),
            ]),
        ], p)

    # ---- top verdict card ----
    top_card = None
    if top:
        v = top["verdict"]
        top_card = _card([
            html.Div("TOP VERDICT", style={
                "color": p["INK_DIM"], "fontSize": "0.72rem",
                "letterSpacing": "0.14em", "marginBottom": "10px",
                "fontFamily": "'JetBrains Mono', monospace"}),
            html.Div([
                html.Span(top["candidate_id"], style={
                    "color": p["INK"], "fontSize": "1.15rem",
                    "fontFamily": "'JetBrains Mono', monospace",
                    "marginRight": "14px", "fontWeight": "600"}),
                _verdict_pill(v["verdict"], p),
                html.Span(f" · {v['category']}", style={
                    "color": p["INK_DIM"], "fontSize": "0.9rem",
                    "marginLeft": "10px"}),
                html.Span(f" · confidence {v['confidence']:.2f}", style={
                    "color": p["INK_DIM"], "fontSize": "0.9rem"}),
            ], style={"marginBottom": "10px",
                      "display": "flex", "alignItems": "center",
                      "flexWrap": "wrap"}),
            html.Div(v["reasoning"], style={
                "color": p["INK_DIM"], "fontStyle": "italic",
                "borderLeft": f"3px solid {p['VIOLET_BRIGHT']}",
                "paddingLeft": "14px", "lineHeight": "1.6",
                "fontSize": "0.92rem"}),
        ], p)

    # ---- full table ----
    header = html.Tr([
        html.Th(h, style={"color": p["INK_DIM"], "fontWeight": "500",
                          "fontSize": "0.72rem",
                          "letterSpacing": "0.14em", "textAlign": "left",
                          "padding": "10px 8px", "borderBottom":
                          f"1px solid {p['GLASS_BORDER_STRONG']}"})
        for h in ("#", "CANDIDATE", "VERDICT", "CATEGORY", "CONF",
                  "PRIORITY", "⛑", "ACTION", "REASONING")
    ])
    rows = []
    for i, r in enumerate(results, 1):
        v = r["verdict"]
        rows.append(html.Tr([
            html.Td(str(i), style={"color": p["INK_DIM"],
                                   "padding": "10px 8px",
                                   "fontFamily":
                                       "'JetBrains Mono', monospace"}),
            html.Td(r["candidate_id"],
                    style={"color": p["INK"], "padding": "10px 8px",
                           "fontFamily": "'JetBrains Mono', monospace"}),
            html.Td(_verdict_pill(v["verdict"], p),
                    style={"padding": "10px 8px"}),
            html.Td(v["category"], style={"color": p["INK_DIM"],
                                          "padding": "10px 8px"}),
            html.Td(f"{v['confidence']:.2f}",
                    style={"color": p["INK"], "padding": "10px 8px",
                           "textAlign": "right"}),
            html.Td(f"{r['priority']:.3f}",
                    style={"color": p["INK"], "padding": "10px 8px",
                           "textAlign": "right"}),
            html.Td("⚑" if r.get("guardrail") else "",
                    style={"color": p["VIOLET_BRIGHT"],
                           "padding": "10px 8px",
                           "textAlign": "center", "fontSize": "1.1rem"}),
            html.Td(v["recommended_action"],
                    style={"color": p["INK_DIM"], "padding": "10px 8px"}),
            html.Td(v["reasoning"],
                    style={"color": p["INK_DIM"], "padding": "10px 8px",
                           "fontSize": "0.85rem", "lineHeight": "1.5"}),
        ], style={"borderBottom": f"1px solid {p['GLASS_BORDER']}"}))
    table_card = _card([
        html.Div("TRIAGED QUEUE (ranked by ensemble priority)", style={
            "color": p["INK_DIM"], "fontSize": "0.72rem",
            "letterSpacing": "0.14em", "marginBottom": "12px",
            "fontFamily": "'JetBrains Mono', monospace"}),
        html.Div(html.Table([header] + rows,
                            style={"width": "100%",
                                   "borderCollapse": "collapse"}),
                 style={"overflowX": "auto"}),
    ], p) if results else _card([
        html.Div("No candidates were flagged in this session — "
                 "nothing to judge.", style={"color": p["INK_DIM"]}),
    ], p)

    # ---- footer / rerun ----
    footer = html.Div([
        html.Span(f"Generated {verdicts_data['generated_at']}",
                  style={"color": p["INK_MUTE"], "fontSize": "0.78rem"}),
        html.Div(_run_button(session_key, p, "Re-run"),
                 style={"marginLeft": "auto"}),
    ], style={"display": "flex", "alignItems": "center",
              "marginTop": "18px"})

    return html.Div([meta, pstats, top_card, table_card, footer])


def render_ai_advisor_panel(session_key, S, findings, palette=None):
    """Top-level entry called from _get_chart_content for the ai_advisor_*
    chart ids. `findings` may be None; the callback will recompute."""
    from dash import dcc, html
    p = palette or _palette()

    ok_import = is_available()
    ok, provider, model, msg = provider_status()

    # No session for the requested scope
    if S is None:
        return _card([
            _title_row(session_key,
                       f"{provider} · {model}" if ok_import
                       else "add-on not installed", p),
            html.Div(f"Load {session_key.upper()} first, then come back "
                     "for the second opinion.",
                     style={"color": p["INK_DIM"]}),
        ], p)

    # Judge add-on missing
    if not ok_import:
        return _card([
            _title_row(session_key, "add-on not installed", p),
            html.P(
                "This panel bridges the dashboard to the standalone "
                "LLM-as-Judge add-on. It looks like the "
                "`llm_judge/` folder is missing or not importable.",
                style={"color": p["INK_DIM"], "lineHeight": "1.6"}),
            html.Pre(msg, style={"color": p["INK_MUTE"],
                                  "fontFamily":
                                      "'JetBrains Mono', monospace",
                                  "fontSize": "0.8rem",
                                  "background": "rgba(0,0,0,0.25)",
                                  "padding": "10px 14px",
                                  "borderRadius": "8px",
                                  "overflow": "auto"}),
            html.P("See `llm_judge/README.md` for setup, or ignore this "
                   "panel — the rest of the dashboard is unaffected.",
                   style={"color": p["INK_DIM"], "marginTop": "12px"}),
        ], p)

    # Cached from a previous run
    cached = AI_JUDGE_CACHE.get(session_key)
    initial = (render_verdicts_card(cached, session_key, p) if cached
               else render_run_state(session_key, ok, provider, model, msg,
                                     _candidate_count_hint(S, findings), p))

    return _card([
        _title_row(session_key, f"{provider} · {model}", p),
        dcc.Loading(
            html.Div(initial,
                     id={"type": "ai-advisor-content",
                         "session": session_key}),
            type="dot", color=p["VIOLET_BRIGHT"],
            parent_style={"minHeight": "160px"},
        ),
    ], p)


def _candidate_count_hint(S, findings):
    """Best-effort estimate of how many candidates the judge will see."""
    j = _try_import()
    if not j["ok"] or S is None:
        return "?"
    try:
        f = findings or {}
        assembled = j["judge_core"].assemble_candidates(S, f)
        return len(assembled["candidates"])
    except Exception:
        return "?"
