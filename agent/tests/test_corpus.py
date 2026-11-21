"""The RAG corpus: the SQLite store, the search, the build pipeline, and the fall-through to the static table."""

from __future__ import annotations

import json
import math
import sqlite3

import httpx
import pytest

from agent import research
from agent.corpus import build as build_module
from agent.corpus import eval as eval_module
from agent.corpus.store import CorpusStore, _as_blob, _cosine, _from_blob, embed_batch, open_corpus


# ---- the vector store -------------------------------------------------------

def _norm(vector: list[float]) -> list[float]:
    """Unit-length vector, so cosine over a batch is a direct similarity."""
    length = math.sqrt(sum(x * x for x in vector)) or 1.0
    return [x / length for x in vector]


def _toy_vectors(dim: int = 8) -> dict[str, list[float]]:
    return {
        "scan": _norm([1, 0, 0, 0, 0, 0, 0, 0]),
        "flood": _norm([0, 1, 0, 0, 0, 0, 0, 0]),
        "arp": _norm([0, 0, 1, 0, 0, 0, 0, 0]),
        "dns": _norm([0, 0, 0, 1, 0, 0, 0, 0]),
        "unrelated": _norm([0, 0, 0, 0, 1, 0, 0, 0]),
    }


@pytest.fixture
def toy_store(tmp_path):
    path = tmp_path / "corpus.sqlite"
    store = CorpusStore(str(path))
    vectors = _toy_vectors()
    chunks = [
        {"id": "attack:T1046", "source": "mitre-attack", "technique": "T1046", "title": "Scan", "tactic": "Discovery",
         "text": "An attacker runs a scan to find services."},
        {"id": "rfc9293:0", "source": "rfc:9293", "technique": "T1046", "title": "TCP", "tactic": "Discovery",
         "text": "TCP uses a three-way handshake; a SYN with no reply is a closed port."},
        {"id": "attack:T1498.001", "source": "mitre-attack", "technique": "T1498.001", "title": "Flood", "tactic": "Impact",
         "text": "A flood sends high-volume traffic at a target."},
        {"id": "attack:T1557.002", "source": "mitre-attack", "technique": "T1557.002", "title": "ARP spoof",
         "tactic": "Credential Access", "text": "An attacker forges ARP replies to receive the victim's traffic."},
        {"id": "rfc1035:0", "source": "rfc:1035", "technique": "T1071.004", "title": "DNS", "tactic": "C2",
         "text": "DNS carries name queries and answers in UDP datagrams; each query is a label tree."},
    ]
    store.add_chunks(chunks[:1], [vectors["scan"]])
    store.add_chunks(chunks[1:2], [vectors["scan"]])
    store.add_chunks(chunks[2:3], [vectors["flood"]])
    store.add_chunks(chunks[3:4], [vectors["arp"]])
    store.add_chunks(chunks[4:5], [vectors["dns"]])
    store.set_meta("embed_model", "test:toy")
    store.set_meta("built_at", "2026-11-21T00:00:00Z")
    return path, store


def test_a_fresh_store_has_the_schema_and_no_chunks(tmp_path):
    store = CorpusStore(str(tmp_path / "corpus.sqlite"))
    assert store.count() == 0 and store.by_source() == {}
    assert store.techniques_present() == set()
    assert store.get_meta("missing") is None
    assert store.get_meta("missing", "fallback") == "fallback"


def test_add_chunks_persists_the_text_and_embedding(tmp_path):
    store = CorpusStore(str(tmp_path / "corpus.sqlite"))
    stored = store.add_chunks(
        [{"id": "x:1", "source": "mitre-attack", "technique": "T1046", "title": "Scan", "tactic": "Discovery",
          "text": "example"}],
        [[0.1, 0.2, 0.3]],
    )
    assert stored == 1 and store.count() == 1
    with store.connect() as conn:
        row = conn.execute("SELECT * FROM chunks").fetchone()
    assert (row["id"], row["source"], row["technique"], row["text"]) == ("x:1", "mitre-attack", "T1046", "example")
    assert _from_blob(row["embedding"]) == pytest.approx([0.1, 0.2, 0.3], abs=1e-5)


def test_meta_round_trips_any_json_value(tmp_path):
    store = CorpusStore(str(tmp_path / "corpus.sqlite"))
    store.set_meta("sources", {"mitre-attack": 10, "rfc:826": 4})
    store.set_meta("built_at", "2026-11-21T00:00:00Z")
    assert store.get_meta("sources") == {"mitre-attack": 10, "rfc:826": 4}
    assert store.get_meta("built_at") == "2026-11-21T00:00:00Z"


def test_blob_round_trips_a_vector_as_float32():
    vec = [0.0, 1.0, -1.0, 2.5, 0.001]
    assert _from_blob(_as_blob(vec)) == pytest.approx(vec, abs=1e-5)


def test_cosine_between_well_known_vectors():
    assert _cosine([1, 0, 0], [1, 0, 0]) == pytest.approx(1.0)
    assert _cosine([1, 0, 0], [0, 1, 0]) == pytest.approx(0.0)
    assert _cosine([1, 0, 0], [-1, 0, 0]) == pytest.approx(-1.0)
    assert _cosine([0, 0, 0], [1, 0, 0]) == 0.0


def test_search_ranks_the_closest_chunks_first(toy_store):
    _, store = toy_store
    vectors = _toy_vectors()
    hits = store.search(vectors["scan"], k=2)
    assert [h["id"] for h in hits] == ["attack:T1046", "rfc9293:0"]
    # Both have cosine 1.0 (toy vectors are identical for the "scan" family).
    assert all(h["distance"] == pytest.approx(0.0) for h in hits)


def test_search_prefers_chunks_tagged_with_the_asked_technique(toy_store):
    _, store = toy_store
    vectors = _toy_vectors()
    # The query vector is the ARP vector, but the technique filter is T1046.
    hits = store.search(vectors["arp"], k=1, technique="T1046")
    assert [h["id"] for h in hits] == ["attack:T1046"]
    assert hits[0]["support"] == "direct"


def test_search_falls_back_to_the_parent_technique(toy_store):
    _, store = toy_store
    vectors = _toy_vectors()
    # The chunk is tagged with the parent technique; the asked sub-id has no own chunk.
    with store.connect() as conn:
        conn.execute("UPDATE chunks SET technique = 'T1498' WHERE id = 'attack:T1498.001'")
    hits = store.search(vectors["flood"], k=1, technique="T1498.001")
    assert [h["id"] for h in hits] == ["attack:T1498.001"]
    assert hits[0]["support"] == "parent"


def test_search_falls_back_to_the_full_corpus_when_no_chunk_is_tagged(toy_store):
    _, store = toy_store
    vectors = _toy_vectors()
    hits = store.search(vectors["dns"], k=1, technique="T9999")
    assert [h["id"] for h in hits] == ["rfc1035:0"]
    assert hits[0]["support"] == "semantic"


def test_a_vector_of_a_different_length_is_skipped(toy_store):
    _, store = toy_store
    hits = store.search([1.0, 0.0, 0.0], k=3)  # the store uses 8-dim vectors
    assert hits == []


def test_open_corpus_returns_none_when_no_path_is_set(monkeypatch, tmp_path):
    monkeypatch.delenv("NETSEC_AGENT_CORPUS_PATH", raising=False)
    assert open_corpus() is None
    assert open_corpus(str(tmp_path / "missing.sqlite")) is None


def test_open_corpus_returns_none_for_an_empty_corpus(tmp_path):
    path = tmp_path / "empty.sqlite"
    CorpusStore(str(path)).connect()  # create the file with the schema but no chunks
    assert open_corpus(str(path)) is None


def test_open_corpus_opens_a_real_file(toy_store):
    path, _ = toy_store
    store = open_corpus(str(path))
    assert store is not None
    assert store.count() == 5
    store.close()


def test_open_corpus_cannot_write_through_the_readonly_handle(toy_store):
    path, _ = toy_store
    store = open_corpus(str(path))
    assert store is not None
    with pytest.raises(sqlite3.OperationalError):
        store.connect().execute("DELETE FROM chunks")
    store.close()


# ---- embedding --------------------------------------------------------------

class _FakeEmbed:
    def __init__(self):
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        text = kwargs["json"]["prompt"]
        # The embedding is derived from the text so a test can predict the top match.
        return _Response({"embedding": [hash(text[:40]) % 97 / 100.0 for _ in range(8)]})


class _Response:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.request = httpx.Request("POST", "http://127.0.0.1:11434/api/embeddings")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=self.request,
                                        response=httpx.Response(self.status_code, request=self.request))

    def json(self):
        return self._payload


def test_embed_batch_calls_ollama_once_per_text(monkeypatch):
    fake = _FakeEmbed()
    monkeypatch.setattr(httpx, "post", fake)
    out = embed_batch(["hello", "world"], model="toy:tiny")
    assert len(out) == 2 and len(out[0]) == 8
    assert all(url.endswith("/api/embeddings") for url, _ in fake.calls)
    assert fake.calls[0][1]["json"]["model"] == "toy:tiny"


def test_embed_batch_uses_the_default_model(monkeypatch):
    fake = _FakeEmbed()
    monkeypatch.setattr(httpx, "post", fake)
    embed_batch(["hello"])
    assert fake.calls[0][1]["json"]["model"] == "nomic-embed-text:latest"


# ---- build pipeline ---------------------------------------------------------

def test_chunk_paragraphs_keeps_chunks_inside_the_size_range():
    text = "\n\n".join(["Paragraph about ARP " * 20 for _ in range(10)])
    chunks = build_module._chunk_paragraphs(text, max_chars=400, min_chars=100)
    assert chunks
    assert all(100 <= len(c) <= 500 for c in chunks)  # a little overflow is fine; min >= min_chars


def test_attack_chunks_yields_one_row_per_engine_technique():
    """The MITRE parser picks `attack-pattern` objects whose external id is one of our techniques."""
    bundle = {
        "objects": [
            {
                "type": "attack-pattern", "name": "Network Service Discovery",
                "description": "A host probes addresses and ports to find open services.",
                "x_mitre_detection": "Watch for many SYN packets to many destinations with no reply.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
            },
            {
                "type": "attack-pattern", "name": "Something Else",
                "description": "Not in the engine technique list.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            },
            {"type": "attack-pattern", "name": "No ID", "description": "No external id.", "external_references": []},
        ]
    }
    chunks = list(build_module.attack_chunks(json.dumps(bundle)))
    assert [c["id"] for c in chunks] == ["attack:T1046"]
    assert chunks[0]["title"].startswith("T1046 - Network Service Discovery")
    assert "attack:T9999" not in {c["id"] for c in chunks}


def test_rfc_chunks_only_keeps_sections_that_mention_the_protocol_words():
    text = "Preamble unrelated\n\nARP replies bind IP to MAC.\n\nUnrelated section about politeness.\n\n"
    chunks = list(build_module.rfc_chunks("826", "T1557.002", "Collection", "ARP", text))
    assert len(chunks) == 1
    assert "ARP" in chunks[0]["text"]
    assert chunks[0]["id"].startswith("rfc826:")


def test_build_corpus_end_to_end(monkeypatch, tmp_path):
    """One pass of build_corpus with every fetch redirected to a cached in-memory string."""
    attack_bundle = json.dumps({"objects": [
        {"type": "attack-pattern", "name": "Scan",
         "description": "A SYN scan sends a SYN and records whether SYN-ACK comes back.",
         "x_mitre_detection": "Many SYN packets to many destinations with no reply.",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}]},
    ]})
    rfc_826 = "ARP replies bind IP to MAC on the link.\n\nFraming details and padding.\n"
    pages = {
        build_module.ATTACK_URL: attack_bundle,
        "https://www.rfc-editor.org/rfc/rfc826.txt": rfc_826,
    }

    def _fake_get(url, **kwargs):
        if url not in pages:
            raise httpx.HTTPError(f"unexpected url: {url}")
        return _Response({}).__class__(payload={}, status_code=200).__init__  # unused

    class FakeGet:
        def __init__(self, text):
            self.text = text
            self.status_code = 200
            self.request = httpx.Request("GET", "http://x")

        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        if url not in pages:
            raise httpx.HTTPError(f"unexpected url {url}")
        return FakeGet(pages[url])

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", _FakeEmbed())
    # Shrink the RFC list so the test does not pull all the configured RFCs.
    monkeypatch.setattr(build_module, "RFCS",
                        (("826", "T1557.002", "Credential Access", "ARP address resolution protocol"),))
    monkeypatch.setattr(build_module, "ENGINE_TECHNIQUES", ("T1046",))
    monkeypatch.setattr(build_module, "EMBED_BATCH", 4)

    out = build_module.build_corpus(str(tmp_path / "corpus.sqlite"), cache_dir=str(tmp_path / "cache"), verbose=False)
    assert out["total"] >= 2

    store = open_corpus(str(tmp_path / "corpus.sqlite"))
    assert store is not None
    assert "attack:T1046" in {r["id"] for r in store.search([0.0] * 8, k=5)}
    assert store.get_meta("sources")["mitre-attack"] == 1
    store.close()


# ---- research wiring --------------------------------------------------------

@pytest.fixture
def _corpus_env(toy_store, monkeypatch):
    path, _ = toy_store
    monkeypatch.setenv("NETSEC_AGENT_CORPUS_PATH", str(path))

    vectors = _toy_vectors()

    def fake_embed(texts, **kwargs):
        # Return the vector that matches the technique in the query.
        out = []
        for text in texts:
            if "T1046" in text:
                out.append(vectors["scan"])
            elif "T1498.001" in text:
                out.append(vectors["flood"])
            elif "T1557.002" in text:
                out.append(vectors["arp"])
            elif "T1071.004" in text:
                out.append(vectors["dns"])
            else:
                out.append(vectors["unrelated"])
        return out

    monkeypatch.setattr(research, "embed_batch", fake_embed)
    return path


def test_research_uses_the_corpus_when_one_is_configured(_corpus_env):
    result = research.query_security_standards("T1046", "unknown")
    assert result["backend"] == "corpus"
    assert result["coverage"] == "direct_match"
    assert "attack:T1046" in result["tool_result_ids"]
    # The toy corpus does not answer the policy questions, so the sufficiency is insufficient.
    assert result["decision_coverage"]["sufficiency"] == "insufficient_coverage"


def test_research_falls_back_to_the_static_table_on_a_corpus_error(_corpus_env, monkeypatch):
    def raise_(*args, **kwargs):
        raise httpx.ConnectError("no ollama")

    monkeypatch.setattr(research, "embed_batch", raise_)
    result = research.query_security_standards("T1046", "unknown")
    assert result["backend"] == "static_table"
    assert result["coverage"] == "direct_match" and result["tool_result_ids"] == ["attack:T1046"]


def test_research_without_a_corpus_uses_the_static_table(monkeypatch):
    monkeypatch.delenv("NETSEC_AGENT_CORPUS_PATH", raising=False)
    result = research.query_security_standards("T1046", "unknown")
    assert result["backend"] == "static_table"


def test_research_sufficiency_is_sufficient_when_the_passages_answer_every_question(toy_store, monkeypatch):
    path, store = toy_store
    monkeypatch.setenv("NETSEC_AGENT_CORPUS_PATH", str(path))

    # Add one chunk that names every answer keyword, so the keyword-based coverage reads sufficient.
    with store.connect() as conn:
        conn.execute(
            "INSERT INTO chunks (id, source, technique, title, tactic, text, embedding) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("attack:T1046:full", "mitre-attack", "T1046", "Scan", "Discovery",
             "Mitigation: block unexpected scans at the firewall. Severity is high on infra. "
             "False positives: a benign vulnerability scanner can look the same.",
             _as_blob([0.9] * 8)))

    vectors = _toy_vectors()
    monkeypatch.setattr(research, "embed_batch", lambda texts, **kw: [vectors["scan"]])
    result = research.query_security_standards("T1046", "Network Infrastructure")
    assert result["decision_coverage"]["sufficiency"] == "sufficient_coverage"
    assert set(result["decision_coverage"]["answered"]) == {"containment", "severity", "false_positive"}


# ---- evaluation grid --------------------------------------------------------

def test_rag_relevance_eval_reports_direct_matches(_corpus_env):
    out = eval_module.rag_relevance_eval(path=str(_corpus_env),
                                          techniques=("T1046", "T1498.001", "T1557.002", "T1071.004", "T1571"),
                                          asset_roles=("unknown",))
    assert out["backend"] == "corpus"
    assert out["total"] == 5
    assert out["counts"]["direct_match"] == 4  # T1571 is not in the corpus; the rest are
    assert out["direct_match_pct"] == 80.0
    unmatched = [r for r in out["rows"] if r["coverage"] != "direct_match"]
    assert [r["technique"] for r in unmatched] == ["T1571"]


def test_rag_relevance_eval_without_a_corpus(monkeypatch):
    monkeypatch.delenv("NETSEC_AGENT_CORPUS_PATH", raising=False)
    out = eval_module.rag_relevance_eval()
    assert out["backend"] == "static_table"
    assert out["direct_match_pct"] == 0


def test_rag_truth_test_passes_when_the_top_source_matches(_corpus_env, monkeypatch):
    cases = (
        {"query": "ARP spoofing", "technique": "T1557.002", "expect_source": "mitre-attack"},
        {"query": "DNS tunneling", "technique": "T1071.004", "expect_source": "rfc:1035"},
    )
    out = eval_module.rag_truth_test(path=str(_corpus_env), lesson_cases=cases)
    assert out["pass"] is True
    assert out["passed"] == 2 and out["total"] == 2


def test_rag_truth_test_fails_when_a_top_source_is_wrong(_corpus_env, monkeypatch):
    cases = ({"query": "something", "technique": "T1046", "expect_source": "rfc:5555"},)
    out = eval_module.rag_truth_test(path=str(_corpus_env), lesson_cases=cases)
    assert out["pass"] is False
    assert out["cases"][0]["got_source"] in ("mitre-attack", "rfc:9293")
