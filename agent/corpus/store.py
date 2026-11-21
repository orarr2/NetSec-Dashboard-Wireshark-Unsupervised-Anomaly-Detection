"""The SQLite-backed vector store: chunks with a technique tag, their embeddings and a cosine search over them."""

from __future__ import annotations

import array
import json
import math
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

import httpx

from agent.chat import ollama_url

EMBED_MODEL_ENV = "NETSEC_AGENT_EMBED_MODEL"
DEFAULT_EMBED_MODEL = "nomic-embed-text:latest"
EMBED_BATCH = 16

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    technique TEXT,
    title TEXT,
    tactic TEXT,
    text TEXT NOT NULL,
    embedding BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chunks_technique ON chunks (technique);
CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks (source);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"""


def embed_model() -> str:
    return os.environ.get(EMBED_MODEL_ENV) or DEFAULT_EMBED_MODEL


def _as_blob(vector: Sequence[float]) -> bytes:
    """Store a float vector as a packed float32 blob; readers reverse it the same way."""
    buf = array.array("f", vector)
    return buf.tobytes()


def _from_blob(blob: bytes) -> list[float]:
    buf = array.array("f")
    buf.frombytes(blob)
    return list(buf)


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity, 1.0 is identical. Inputs must be the same length and non-zero."""
    na = math.sqrt(_dot(a, a))
    nb = math.sqrt(_dot(b, b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return _dot(a, b) / (na * nb)


def embed_batch(texts: Sequence[str], *, model: str | None = None, timeout: float = 60.0) -> list[list[float]]:
    """Embed a batch of texts with Ollama. One call per text; the local server is on the loopback, so this is cheap."""
    model = model or embed_model()
    out = []
    url = f"{ollama_url()}/api/embeddings"
    for text in texts:
        response = httpx.post(url, json={"model": model, "prompt": text}, timeout=timeout)
        response.raise_for_status()
        out.append(response.json()["embedding"])
    return out


class CorpusStore:
    """A corpus is one SQLite file. The agents open it read-only, the build step writes it from scratch."""

    def __init__(self, path: str, *, readonly: bool = False):
        self.path = str(Path(path))
        self.readonly = readonly
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            if self.readonly:
                self._conn = sqlite3.connect(f"file:{Path(self.path).resolve().as_uri()[7:]}?mode=ro", uri=True,
                                             timeout=10)
                self._conn.execute("PRAGMA query_only = ON")
            else:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
                self._conn = sqlite3.connect(self.path, timeout=30)
                self._conn.executescript(_SCHEMA)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def add_chunks(self, chunks: Iterable[dict], embeddings: Sequence[Sequence[float]]) -> int:
        """One row per chunk, with its embedding as a float32 blob. Returns the number of rows stored."""
        rows = []
        for chunk, vector in zip(chunks, embeddings):
            rows.append((chunk["id"], chunk["source"], chunk.get("technique"), chunk.get("title"),
                         chunk.get("tactic"), chunk["text"], _as_blob(vector)))
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO chunks (id, source, technique, title, tactic, text, embedding) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        return len(rows)

    def set_meta(self, key: str, value: Any) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO meta (key, value_json) VALUES (?, ?)",
                         (key, json.dumps(value, ensure_ascii=False)))

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self.connect() as conn:
            row = conn.execute("SELECT value_json FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value_json"]) if row else default

    def count(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])

    def by_source(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute("SELECT source, COUNT(*) AS n FROM chunks GROUP BY source").fetchall()
        return {r["source"]: int(r["n"]) for r in rows}

    def search(self, query_vector: Sequence[float], *, k: int = 3, technique: str | None = None) -> list[dict]:
        """Top-k chunks by cosine similarity. When a technique is named, prefer chunks tagged with it or its parent."""
        # One level up: "T1046.001" -> "T1046"; "T1046" -> None. MITRE IDs are two levels deep.
        parent = technique.rsplit(".", 1)[0] if technique and "." in technique else None
        with self.connect() as conn:
            if technique:
                # Pull chunks tagged with the exact technique first, then its parent; fall back to the full corpus.
                rows = conn.execute(
                    "SELECT id, source, technique, title, tactic, text, embedding FROM chunks "
                    "WHERE technique = ? OR technique = ?",
                    (technique, parent)).fetchall()
                if not rows:
                    rows = conn.execute(
                        "SELECT id, source, technique, title, tactic, text, embedding FROM chunks").fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, source, technique, title, tactic, text, embedding FROM chunks").fetchall()
        scored = []
        for row in rows:
            vector = _from_blob(row["embedding"])
            if len(vector) != len(query_vector):
                continue
            scored.append((_cosine(query_vector, vector), row))
        scored.sort(key=lambda t: -t[0])
        out = []
        for score, row in scored[:k]:
            matches_parent = parent and row["technique"] and row["technique"] == parent
            matches_exact = technique and row["technique"] == technique
            support = "direct" if matches_exact else ("parent" if matches_parent else "semantic")
            out.append({
                "id": row["id"], "source": row["source"], "technique": row["technique"],
                "title": row["title"], "tactic": row["tactic"], "text": row["text"],
                "distance": round(1.0 - score, 4),  # 0 is identical
                "support": support,
            })
        return out

    def techniques_present(self) -> set[str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT DISTINCT technique FROM chunks WHERE technique IS NOT NULL").fetchall()
        return {r["technique"] for r in rows}


def corpus_path() -> str | None:
    """The corpus file path from the environment; None means the research step uses its stand-in table."""
    value = (os.environ.get("NETSEC_AGENT_CORPUS_PATH") or "").strip()
    return value or None


def open_corpus(path: str | None = None) -> CorpusStore | None:
    """Open the corpus for reading. Returns None when no path is configured or the file does not exist."""
    target = path or corpus_path()
    if not target:
        return None
    if not Path(target).is_file():
        return None
    store = CorpusStore(target, readonly=True)
    # Verify the file opens and has rows; an empty or incomplete corpus falls through to the stand-in backend.
    try:
        if store.count() == 0:
            store.close()
            return None
    except Exception:
        store.close()
        return None
    return store
