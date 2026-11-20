"""Every test runs offline against its own database and checkpoint file."""

from __future__ import annotations

import pytest

from agent.tests.builders import load_vm_candidates

_ENV_TO_CLEAR = (
    "NETSEC_MY_DEVICE_IP", "NETSEC_INFRA_DSTS", "NETSEC_AGENT_DISPLAY_TZ", "NETSEC_AGENT_ASYNC_CONCURRENCY",
    "NETSEC_AGENT_POLICY_PATH", "AGENT_MAX_ITERATIONS", "AGENT_MAX_TOOL_HOPS", "AGENT_COST_CAP_USD",
    "WALL_CLOCK_CAP_SECONDS", "AGENT_LLM_TIMEOUT_SECONDS", "AGENT_SUPERVISOR_ROUTING", "AGENT_LLM_PROVIDER",
)


@pytest.fixture(autouse=True)
def isolated_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSEC_AGENT_DB_PATH", str(tmp_path / "netsec-agent.db"))
    monkeypatch.setenv("NETSEC_AGENT_CHECKPOINT_PATH", str(tmp_path / "checkpoints.sqlite"))
    monkeypatch.setenv("NETSEC_AGENT_USE_LIVE", "0")
    for name in _ENV_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)
    from agent.db import reset_db_registry
    from agent.graph import reset_graph_cache

    reset_db_registry()
    reset_graph_cache()
    yield
    reset_graph_cache()
    reset_db_registry()


@pytest.fixture(scope="session")
def vm_candidates() -> dict[str, dict]:
    return load_vm_candidates()
