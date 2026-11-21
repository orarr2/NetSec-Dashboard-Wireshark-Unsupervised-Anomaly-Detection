"""The operator banner: host, service, policy, research backend, database and poller, as data and as terminal lines."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from pathlib import Path
from typing import Any

from agent import __version__, policy
from agent.chat import use_live
from agent.db import Database
from agent.corpus.store import corpus_path, open_corpus
from agent.research import BACKEND as _STATIC_BACKEND
from agent.state import caps
from agent.trace import _clock

STARTED_AT = time.time()
BAR = "=" * 56
_REPO_ROOT = Path(__file__).resolve().parent.parent


def display_now() -> str:
    return _clock(time.time())


def _meminfo() -> dict[str, int]:
    """/proc/meminfo in kB; empty where the file does not exist."""
    try:
        text = Path("/proc/meminfo").read_text(encoding="ascii")
    except OSError:
        return {}
    out = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            out[key.strip()] = int(parts[0])
    return out


def _commit() -> str:
    """The deployed commit: the environment, or the COMMIT file the install step writes next to the package."""
    value = os.environ.get("NETSEC_AGENT_COMMIT")
    if not value:
        try:
            value = (_REPO_ROOT / "COMMIT").read_text(encoding="ascii").strip()
        except OSError:
            value = ""
    return value[:12] or "unknown"


def _host(data_dir: Path) -> dict[str, Any]:
    mem = _meminfo()
    total, available = mem.get("MemTotal"), mem.get("MemAvailable")
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):
        load = None
    try:
        disk = shutil.disk_usage(data_dir if data_dir.exists() else Path("/"))
        disk_info = {"disk_pct": round(100 * disk.used / disk.total), "disk_used_gb": round(disk.used / 1e9),
                     "disk_total_gb": round(disk.total / 1e9)}
    except OSError:
        disk_info = {"disk_pct": None, "disk_used_gb": None, "disk_total_gb": None}
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "arch": platform.machine(),
        "cpus": os.cpu_count(),
        "load": load,
        "mem_total_gb": round(total / 1e6, 1) if total else None,
        "mem_used_pct": round(100 * (total - available) / total) if total and available is not None else None,
        **disk_info,
    }


def _database(db: Database) -> dict[str, Any]:
    now = time.time()
    try:
        rows = db.list_cases(since=now - 24 * 3600)
        pending = db.list_pending_approvals(limit=500)
    except Exception as exc:
        return {"error": type(exc).__name__}
    by_action: dict[str, int] = {}
    for row in rows:
        key = row["action"] or "undecided"
        by_action[key] = by_action.get(key, 0) + 1
    sla_hours = float(policy.get("queues", "approval_sla_hours", default=24))
    return {
        "total_24h": len(rows),
        "by_action": by_action,
        "pending_approvals": len(pending),
        "overdue_approvals": sum(1 for a in pending if now - float(a["created_at"]) > sla_hours * 3600),
        "approval_sla_hours": sla_hours,
    }


def _research_info() -> dict[str, Any]:
    """The research backend actually in use, with how many chunks the corpus holds."""
    store = open_corpus()
    if store is None:
        return {"backend": _STATIC_BACKEND, "corpus_path": corpus_path()}
    try:
        return {
            "backend": "corpus", "corpus_path": store.path, "chunks": store.count(),
            "built_at": store.get_meta("built_at"),
            "embed_model": store.get_meta("embed_model"),
            "sources": store.get_meta("sources"),
        }
    finally:
        store.close()


def collect_status(db: Database, poller: dict[str, Any] | None, async_concurrency: int) -> dict[str, Any]:
    database = _database(db)
    poller = poller or {"enabled": False}
    live = use_live()
    missing = []
    if not live:
        missing.append("live models (phase P2)")
    research_info = _research_info()
    if research_info["backend"] == "static_table":
        missing.append("research corpus (phase P3)")
    if not poller.get("enabled"):
        missing.append("poller is off (NETSEC_AGENT_SOURCE_DB is not set)")
    elif poller.get("last_error"):
        missing.append(f"netsec.db could not be read ({poller['last_error']})")
    if "error" in database:
        missing.append(f"agent database unavailable ({database['error']})")
    return {
        "host": _host(Path(db.path).parent),
        "service": {
            "version": __version__,
            "uptime_s": int(time.time() - STARTED_AT),
            "commit": _commit(),
            "python": platform.python_version(),
            "use_live": live,
            "wall_clock_cap_s": caps()["wall_clock_cap_s"],
            "async_concurrency": async_concurrency,
            "policy_version": policy.POLICY_VERSION,
            "actions": list(policy.get("actions", default=[])),
        },
        "research": research_info,
        "database": database,
        "poller": poller,
        "missing": missing,
    }


def _or_na(value: Any, suffix: str = "") -> str:
    return "n/a" if value is None else f"{value}{suffix}"


def status_lines(d: dict[str, Any]) -> list[str]:
    h, s, db, p = d["host"], d["service"], d["database"], d["poller"]
    degraded = "error" in db or bool(p.get("last_error"))
    up = s["uptime_s"]
    uptime = f"{up // 3600}h {(up % 3600) // 60:02d}m" if up >= 3600 else f"{up // 60}m {up % 60:02d}s"
    load = " ".join(f"{x:.2f}" for x in h["load"]) if h["load"] else "n/a"
    disk = (f"{h['disk_pct']}% ({h['disk_used_gb']}/{h['disk_total_gb']} GB)"
            if h["disk_pct"] is not None else "n/a")
    if "error" in db:
        database = f"unavailable ({db['error']})"
    else:
        actions = ", ".join(f"{k} {v}" for k, v in sorted(db["by_action"].items())) or "none"
        database = (f"{db['total_24h']} cases in 24h: {actions}   approvals pending {db['pending_approvals']} "
                    f"(overdue {db['overdue_approvals']}, sla {db['approval_sla_hours']:g}h)")
    if not p.get("enabled"):
        poller = "off"
    else:
        last = _clock(p["last_poll_at"])[11:] if p.get("last_poll_at") else "never"
        poller = (f"every {p['interval_s']:g}s  finished sessions seen {p['sessions_seen']}  "
                  f"cases submitted {p['submitted_total']}  last poll {last}")
        if p.get("last_error"):
            poller += f"  error: {p['last_error']}"
    r = d["research"]
    if r["backend"] == "static_table":
        research = "static_table (a stand-in until the corpus is wired)"
    else:
        chunks = r.get("chunks")
        built = (r.get("built_at") or "")[:10]
        model = r.get("embed_model") or "?"
        research = f"corpus  {chunks} chunks  built {built}  embedder {model}"
    return [
        BAR,
        f"  NETSEC agents - {'degraded' if degraded else 'operational'}   {h['hostname']}   {display_now()}",
        BAR,
        f"  host      {h['os']}  {h['arch']}  {_or_na(h['cpus'])} cpu  {_or_na(h['mem_total_gb'], ' GB')} ram",
        f"  load      {load}   mem {_or_na(h['mem_used_pct'], '%')}   disk {disk}",
        f"  service   netsec-agent v{s['version']}  up {uptime}  commit {s['commit']}  python {s['python']}",
        f"  agents    model layer {'on' if s['use_live'] else 'off (rule tree only)'}  "
        f"wall clock {s['wall_clock_cap_s']:g}s  parallel runs {s['async_concurrency']}",
        f"  policy    {s['policy_version']}  actions {', '.join(s['actions'])}",
        f"  research  {research}",
        f"  database  {database}",
        f"  poller    {poller}",
        f"  missing   {'; '.join(d['missing']) or 'nothing'}",
        BAR,
    ]
