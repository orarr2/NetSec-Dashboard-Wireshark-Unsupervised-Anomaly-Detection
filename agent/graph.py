"""The LangGraph topology: sanitize -> intake -> supervisor -> (perception | research | decision | approval gate)."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator, Mapping

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph

from agent import nodes
from agent.adapter import normalize_case
from agent.db import db_path as default_db_path
from agent.state import CaseState, new_budget

DEFAULT_CHECKPOINT_PATH = "/var/lib/netsec-agent/checkpoints.sqlite"
_ROUTES = {
    "profile_builder": "profile_builder",
    "rag_retriever": "rag_retriever",
    "decision": "decision",
    "approval_gate": "approval_gate",
    "end": END,
}
_GRAPHS: dict[str, Any] = {}
_CONNECTIONS: dict[str, sqlite3.Connection] = {}
_LOCK = threading.Lock()


def checkpoint_path() -> str:
    return os.environ.get("NETSEC_AGENT_CHECKPOINT_PATH", DEFAULT_CHECKPOINT_PATH)


def _route(state: Mapping[str, Any]) -> str:
    hop = state.get("next_hop")
    return hop if hop in _ROUTES else "end"


def build_graph(path: str | None = None):
    """Compiled graph, one per checkpoint file. An empty path or 'none' runs without checkpoints."""
    key = checkpoint_path() if path is None else path
    with _LOCK:
        if key in _GRAPHS:
            return _GRAPHS[key]
        g = StateGraph(CaseState)
        g.add_node("sanitize", nodes.sanitize_node)
        g.add_node("signal_extractor", nodes.signal_extractor_node)
        g.add_node("supervisor", nodes.supervisor_node)
        g.add_node("profile_builder", nodes.profile_builder_node)
        g.add_node("rag_retriever", nodes.rag_retriever_node)
        g.add_node("decision", nodes.decision_node)
        g.add_node("approval_gate", nodes.approval_gate_node)
        g.set_entry_point("sanitize")
        g.add_edge("sanitize", "signal_extractor")
        g.add_edge("signal_extractor", "supervisor")
        g.add_conditional_edges("supervisor", _route, _ROUTES)
        g.add_edge("profile_builder", "supervisor")
        g.add_edge("rag_retriever", "supervisor")
        g.add_edge("decision", "supervisor")
        g.add_edge("approval_gate", END)
        saver = None
        if key and key.lower() != "none":
            Path(key).parent.mkdir(parents=True, exist_ok=True)
            _CONNECTIONS[key] = sqlite3.connect(key, check_same_thread=False)
            saver = SqliteSaver(_CONNECTIONS[key])
        _GRAPHS[key] = g.compile(checkpointer=saver)
        return _GRAPHS[key]


def reset_graph_cache() -> None:
    with _LOCK:
        for conn in _CONNECTIONS.values():
            with contextlib.suppress(Exception):
                conn.close()
        _CONNECTIONS.clear()
        _GRAPHS.clear()


def stream_graph(
    case_id: str,
    payload: Mapping[str, Any],
    *,
    db_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Iterator[dict]:
    """Run one case through the graph, yielding the whole state after every step."""
    initial: CaseState = {
        "case_id": case_id,
        "case": normalize_case(payload, env),
        "runtime": {"db_path": db_path or default_db_path()},
        "budget": new_budget(),
        "trace": [],
        "tokens_in": 0,
        "tokens_out": 0,
    }
    config = {"configurable": {"thread_id": case_id}, "recursion_limit": 60}
    for snapshot in build_graph().stream(initial, config=config, stream_mode="values"):
        yield dict(snapshot)


def run_graph(
    case_id: str,
    payload: Mapping[str, Any],
    *,
    db_path: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict:
    """Run one case through the graph and return its final state."""
    final: dict = {}
    for final in stream_graph(case_id, payload, db_path=db_path, env=env):
        pass
    return final
