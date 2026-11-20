"""The agents' HTTP service: submit a candidate, poll its report, the 24-hour overview and health."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from agent import __version__, policy
from agent.adapter import case_metadata, normalize_case
from agent.db import OPEN_ACTIONS, Database, get_db, new_id
from agent.graph import build_graph, stream_graph
from agent.profile import build_profile
from agent.sanitize import sanitize_case
from agent.trace import build_agent_value_summary, emit_trace, format_trace_lines

LOGGER = logging.getLogger("netsec_agent")
WINDOW_HOURS = 24


class CaseSubmit(BaseModel):
    """One NETSEC candidate: its `candidates` row plus the rows of the same session that belong to it."""

    model_config = ConfigDict(extra="allow")

    # The id is the case's identity and is stored as it is, so it may not carry control characters.
    candidate_id: str = Field(min_length=1, max_length=128, pattern=r"^[^\x00-\x1f\x7f]+$")
    kind: str = Field(default="ip", pattern=r"^[a-z_]{1,32}$")
    session: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    adv_signals: list[dict[str, Any]] = Field(default_factory=list)
    fusion: list[dict[str, Any]] = Field(default_factory=list)
    ip_features: dict[str, Any] | None = None
    analyst_note: str = Field(default="", max_length=4000)


def _iso(ts: float | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))


def _metadata(row: dict) -> dict:
    return {
        "candidate_id": row["candidate_id"],
        "kind": row["kind"],
        "session_id": row["session_id"],
        "pcap_name": row["pcap_name"],
        "pcap_sha256": row["pcap_sha256"],
        "technique": row["technique"],
        "score": row["score"],
        "asset_role": row["asset_role"],
        "engines": json.loads(row["engines_json"] or "{}"),
    }


def _trace_summary(trace: list) -> tuple[list[dict], int, int, list[str], list[dict]]:
    """Timeline, token totals, cited sources and the model calls of one case."""
    timeline: list[dict] = []
    cited: list[str] = []
    llm_calls: list[dict] = []
    tokens_in = tokens_out = 0
    for entry in trace:
        if not isinstance(entry, dict):
            continue
        content = entry.get("content") if isinstance(entry.get("content"), dict) else {}
        llm = content.get("llm") if isinstance(content.get("llm"), dict) else None
        timeline.append({
            "iter": entry.get("iter"),
            "speaker": entry.get("speaker"),
            "kind": entry.get("kind"),
            "llm_used": content.get("llm_used"),
            "source": content.get("source"),
        })
        for src in content.get("cited_sources") or []:
            if src not in cited:
                cited.append(src)
        if llm and llm.get("calls"):
            tokens_in += int(llm.get("tokens_in") or 0)
            tokens_out += int(llm.get("tokens_out") or 0)
            llm_calls.append({
                "speaker": entry.get("speaker"),
                "model": llm.get("model"),
                "tokens_in": int(llm.get("tokens_in") or 0),
                "tokens_out": int(llm.get("tokens_out") or 0),
                "latency_s": llm.get("latency_s"),
            })
    return timeline, tokens_in, tokens_out, cited, llm_calls


def _route_to_human(db: Database, case_id: str, kind: str, reason: str, trace: list[dict], content: dict) -> None:
    """A run that cannot finish on its own becomes a human_review verdict with a pending approval row."""
    priority = policy.priority("human_review")
    trace = [*trace, {
        "iter": len(trace), "speaker": "pipeline", "kind": kind, "ts": time.time(),
        "policy": policy.POLICY_VERSION, "content": content,
    }]
    # The approval row comes first: if it cannot be written, the case must not read as decided.
    if not any(a["status"] == "pending" for a in db.approvals_for_case(case_id)):
        db.create_approval(case_id, "human_review", priority)
    db.update_case(
        case_id, status="open", action="human_review", priority=priority, rationale=reason, assessment="",
        trace_json=json.dumps(trace, default=str), cited_sources_json="[]", agent_value_json="",
        fallback_reason=kind, policy_version=policy.POLICY_VERSION, decided_at=time.time(),
    )


def recover_interrupted_runs(db: Database | None = None) -> int:
    """Startup only. A row still queued or processing belonged to a task that died with the old process."""
    db = db or get_db()
    reason = "service restarted while the run was in progress; routed to a human"
    rows = db.interrupted_cases()
    for row in rows:
        _route_to_human(db, row["id"], "graph_interrupted", reason, json.loads(row["trace_json"] or "[]"), {})
    if rows:
        LOGGER.warning("recovered_interrupted_runs: %d row(s) routed to human_review", len(rows))
    return len(rows)


def _agent_ready() -> bool:
    try:
        build_graph()
        return True
    except Exception:
        return False


def create_app() -> FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            recover_interrupted_runs()
        except Exception as exc:
            LOGGER.warning("recover_interrupted_runs_failed: %s", exc)
        yield

    app = FastAPI(title="NETSEC triage agents", version=__version__, lifespan=lifespan)
    # At most this many graphs run at once; the rest wait in their task thread with the row in 'queued'.
    concurrency = max(1, int(os.environ.get("NETSEC_AGENT_ASYNC_CONCURRENCY", "2") or 2))
    app.state.async_slots = threading.BoundedSemaphore(concurrency)

    def _run_case(case_id: str, payload: dict) -> None:
        """Background task: wait for a slot, stream the graph, keep the row's trace current, store the verdict."""
        db = get_db()
        trace: list[dict] = []
        final: dict[str, Any] = {}
        started = time.time()
        with app.state.async_slots:
            try:
                db.update_case(case_id, status="processing")
                for final in stream_graph(case_id, payload, db_path=db.path):
                    if len(final.get("trace") or []) != len(trace):
                        trace = list(final["trace"])
                        with contextlib.suppress(Exception):
                            db.update_case(case_id, trace_json=json.dumps(trace, default=str))
                if not final.get("action"):
                    raise RuntimeError("the graph ended without a verdict")
            except Exception as exc:
                LOGGER.exception("graph_failed case_id=%s", case_id)
                _route_to_human(
                    db, case_id, "graph_failed", f"pipeline error: {type(exc).__name__}; routed to a human",
                    trace, {"error": type(exc).__name__},
                )
                return
        action = str(final["action"])
        case_status = "open" if action in OPEN_ACTIONS else "closed"
        cited = list(final.get("cited_sources") or [])
        db.update_case(
            case_id, status=case_status, action=action, priority=int(final.get("priority") or 0),
            rationale=str(final.get("rationale") or ""), assessment=str(final.get("assessment") or ""),
            trace_json=json.dumps(trace, default=str), cited_sources_json=json.dumps(cited),
            agent_value_json=json.dumps(build_agent_value_summary(trace) or {}, default=str),
            fallback_reason=final.get("fallback_reason"), policy_version=policy.POLICY_VERSION,
            decided_at=time.time(),
        )
        # The same block the report returns goes to stdout, so journald shows every run.
        with contextlib.suppress(Exception):
            lines = format_trace_lines(
                case_id, trace, metadata=_metadata(db.get_case(case_id)),
                verdict={"action": action, "priority": final.get("priority")}, status=case_status,
            )
            emit_trace(
                case_id, lines, tokens_in=int(final.get("tokens_in") or 0),
                tokens_out=int(final.get("tokens_out") or 0), guard_fired=bool(final.get("guard_fired")),
                elapsed_s=time.time() - started,
            )

    @app.post("/cases/submit-async", status_code=status.HTTP_202_ACCEPTED)
    def cases_submit_async(body: CaseSubmit, background: BackgroundTasks, response: Response) -> dict:
        """Returns 202 and a case id at once; the graph runs in the background. Poll GET /report/{case_id}."""
        payload = body.model_dump()
        case = normalize_case(payload)
        db = get_db()
        existing = db.find_case(case["session_id"], case["candidate_id"])
        case_id = new_id("ns")
        if existing is None:
            try:
                db.create_case(case_id, sanitize_case(case)["clean_case"], case_metadata(case, build_profile(case)))
            except sqlite3.IntegrityError:
                existing = db.find_case(case["session_id"], case["candidate_id"])
                if existing is None:
                    raise
        if existing is not None:
            # One case per candidate of a session: a second submit returns the first one.
            response.status_code = status.HTTP_200_OK
            return {"case_id": existing["id"], "status": existing["status"],
                    "poll": f"/report/{existing['id']}", "duplicate": True}
        background.add_task(_run_case, case_id, payload)
        return {"case_id": case_id, "status": "queued", "poll": f"/report/{case_id}"}

    @app.get("/report/{case_id}")
    def report_case(case_id: str) -> dict:
        """One case: metadata, verdict, cited sources, timeline, token usage, the trace and its terminal lines."""
        row = get_db().get_case(case_id)
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case_not_found")
        trace = json.loads(row["trace_json"] or "[]")
        timeline, tokens_in, tokens_out, cited, llm_calls = _trace_summary(trace)
        metadata = _metadata(row)
        return {
            "case_id": row["id"],
            "submitted_at": _iso(row["submitted_at"]),
            "metadata": metadata,
            "verdict": {
                "action": row["action"],
                "rationale": row["rationale"],
                "priority": row["priority"],
                "status": row["status"],
                "assessment": row["assessment"],
            },
            "grounded_sources": cited,
            "decision_timeline": timeline,
            "llm_calls": llm_calls,
            "token_usage": {"in": tokens_in, "out": tokens_out},
            "trace_lines": format_trace_lines(
                row["id"], trace, metadata=metadata,
                verdict={"action": row["action"], "priority": row["priority"]}, status=row["status"],
            ),
            "trace": trace,
        }

    @app.get("/report")
    def report_overview() -> dict:
        """The last 24 hours: counts by action and by technique, and the approvals waiting on a human."""
        db = get_db()
        now = time.time()
        rows = db.list_cases(since=now - WINDOW_HOURS * 3600)
        by_action: dict[str, int] = {}
        by_technique: dict[str, int] = {}
        for row in rows:
            action = row["action"] or "undecided"
            technique = row["technique"] or "none"
            by_action[action] = by_action.get(action, 0) + 1
            by_technique[technique] = by_technique.get(technique, 0) + 1
        sla_hours = float(policy.get("queues", "approval_sla_hours", default=24))
        pending = db.list_pending_approvals(limit=20)
        return {
            "generated_at": _iso(now),
            "window_hours": WINDOW_HOURS,
            "total_cases": len(rows),
            "by_action": by_action,
            "by_technique": by_technique,
            "approval_sla_hours": sla_hours,
            "overdue_approvals": sum(1 for a in pending if now - float(a["created_at"]) > sla_hours * 3600),
            "pending_approvals": [
                {
                    "approval_id": a["id"],
                    "case_id": a["case_id"],
                    "action": a["action"],
                    "priority": a["priority"],
                    "created_at": _iso(a["created_at"]),
                    "age_hours": round((now - float(a["created_at"])) / 3600, 1),
                    "overdue": now - float(a["created_at"]) > sla_hours * 3600,
                }
                for a in pending
            ],
        }

    @app.get("/health")
    def health() -> dict:
        db_ok = get_db().ready()
        agent_ok = _agent_ready()
        return {
            "status": "ok" if db_ok and agent_ok else "degraded",
            "version": __version__,
            "db_ready": db_ok,
            "agent_ready": agent_ok,
            # The research backend is a static table until the corpus of phase P3 exists.
            "rag_ready": False,
        }

    return app


app = create_app()
