#!/usr/bin/env python3
"""NetSec RAG - a local retrieval-augmented question engine for the VM.

STANDALONE and NOT WIRED INTO ANYTHING. This file is prepared for the VM
but nothing in app/, server/ or llm_judge/ imports it. Integrate later
if wanted; for now it runs entirely on its own.

What it is
----------
Ask questions in plain language and get an answer grounded in your own
material - two kinds:

  1. Arbitrary documents you point it at (.txt, .md, .json).
  2. The NetSec reports themselves. `ingest-netsec /srv/netsec/reports`
     turns every session's verdicts.json + summary into searchable
     chunks, so you can finally ask the archive questions it could
     never answer before:
       "which devices were ever judged malicious?"
       "what did the panel say about 172.10.146.42 across sessions?"
       "which attack categories recur most on my network?"

Design - same philosophy as companion.py
----------------------------------------
Local-first and dependency-light. The only hard third-party dep is
numpy (already a project dependency); everything else is stdlib +
urllib. No chromadb / faiss / langchain / sentence-transformers, so
there is nothing to fail to build on the ARM VM.

  - Embeddings: Ollama's embedding endpoint with `nomic-embed-text`
    (a 137M model - one `ollama pull nomic-embed-text` on the VM).
    The heavy chat models are NOT used for embedding.
  - Vector store: SQLite with the vectors as float32 BLOBs; cosine
    similarity is a normalized dot-product in numpy. Brute force over
    a few thousand chunks is sub-millisecond. (For 100k+ chunks you
    would swap in FAISS - noted, not needed at this scale.)
  - Generation is HYBRID, exactly like the judge panel:
        --generator local   -> Ollama chat model on the VM (private,
                               ~a minute per answer on CPU)
        --generator groq    -> Groq cloud (2-5 s, needs GROQ_API_KEY;
                               the retrieved chunks leave the machine)
    Retrieval is ALWAYS local; only the final phrasing optionally goes
    to the cloud. A 2-3B local model is weak on parametric knowledge
    but fine at "answer from the text in front of you", which is
    exactly what RAG hands it.

Setup on the VM
---------------
    ollama pull nomic-embed-text          # once; the embed model
    # a chat model already exists (qwen2.5:3b etc.) for --generator local
    pip install numpy                     # already present in the project

Usage
-----
    # index your own docs
    python tools/netsec_rag.py index ~/notes ~/study/*.md

    # index the NetSec report archive
    python tools/netsec_rag.py ingest-netsec /srv/netsec/reports

    # ask (local generation, fully private)
    python tools/netsec_rag.py ask "which IPs flipped to malicious?"

    # ask with cloud phrasing (faster; retrieved text leaves the box)
    GROQ_API_KEY=... python tools/netsec_rag.py ask \
        --generator groq "summarise the port-scan findings"

    python tools/netsec_rag.py stats            # what is indexed
    python tools/netsec_rag.py serve            # tiny local chat page

Config (env or flags)
---------------------
    NETSEC_RAG_DB          store path        (default ~/netsec-rag/store.db)
    NETSEC_OLLAMA_URL      Ollama base       (default http://127.0.0.1:11434)
    NETSEC_RAG_EMBED_MODEL embed model       (default nomic-embed-text)
    NETSEC_RAG_GEN_MODEL   local chat model  (default qwen2.5:3b)
    GROQ_API_KEY           for --generator groq
    NETSEC_RAG_GROQ_MODEL  groq model        (default llama-3.3-70b-versatile)

If you run this OFF the VM, point NETSEC_OLLAMA_URL through the same SSH
tunnel companion.py opens (127.0.0.1:11434 -> the ollama container).
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
import urllib.error

import numpy as np

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
DEFAULT_DB = os.path.expanduser(
    os.environ.get("NETSEC_RAG_DB", "~/netsec-rag/store.db"))
OLLAMA_URL = os.environ.get("NETSEC_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.environ.get("NETSEC_RAG_EMBED_MODEL", "nomic-embed-text")
GEN_MODEL = os.environ.get("NETSEC_RAG_GEN_MODEL", "qwen2.5:3b")
GROQ_MODEL = os.environ.get("NETSEC_RAG_GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

# Chunking: ~1000 chars with 150 overlap keeps a chunk inside one
# nomic-embed context window with room to spare, and the overlap stops a
# fact from being split across a boundary where neither half retrieves.
CHUNK_CHARS = int(os.environ.get("NETSEC_RAG_CHUNK_CHARS", "1000"))
CHUNK_OVERLAP = int(os.environ.get("NETSEC_RAG_CHUNK_OVERLAP", "150"))
TEXT_EXTS = {".txt", ".md", ".markdown", ".log", ".json", ".csv"}


# --------------------------------------------------------------------------
# HTTP helpers (urllib only, like companion.py)
# --------------------------------------------------------------------------
def _post_json(url, payload, headers=None, timeout=300):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"HTTP {e.code} from {url}: {detail}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot reach {url}: {e.reason}") from None


# --------------------------------------------------------------------------
# Embeddings (Ollama)
# --------------------------------------------------------------------------
def embed_texts(texts, model=EMBED_MODEL, base=OLLAMA_URL):
    """Return an (N, dim) float32 matrix of embeddings for `texts`.

    Tries the newer batch endpoint /api/embed first (one request for the
    whole list); falls back to per-text /api/embeddings for older Ollama
    builds. Both ship in current Ollama - the fallback just means more
    round-trips, never a failure."""
    if not texts:
        return np.zeros((0, 0), dtype=np.float32)
    # batch endpoint
    try:
        out = _post_json(f"{base}/api/embed",
                         {"model": model, "input": list(texts)})
        vecs = out.get("embeddings")
        if vecs:
            return np.asarray(vecs, dtype=np.float32)
    except RuntimeError:
        pass
    # per-text fallback
    rows = []
    for t in texts:
        out = _post_json(f"{base}/api/embeddings",
                         {"model": model, "prompt": t})
        rows.append(out["embedding"])
    return np.asarray(rows, dtype=np.float32)


def _normalize(mat):
    """Row-normalize so a dot product IS cosine similarity."""
    if mat.size == 0:
        return mat
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


# --------------------------------------------------------------------------
# Chunking + document loaders
# --------------------------------------------------------------------------
def chunk_text(text, size=CHUNK_CHARS, overlap=CHUNK_OVERLAP):
    """Split into ~size-char chunks with overlap, breaking on paragraph
    then sentence boundaries so a chunk rarely ends mid-sentence."""
    text = re.sub(r"[ \t]+", " ", (text or "").strip())
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            window = text[start:end]
            # prefer a paragraph break, then a sentence end, in the last
            # third of the window; else hard-cut at a space.
            cut = -1
            for pat in ("\n\n", ". ", ".\n", "? ", "! ", "\n", " "):
                idx = window.rfind(pat)
                if idx > size * 0.6:
                    cut = idx + len(pat)
                    break
            if cut > 0:
                end = start + cut
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return [c for c in chunks if c]


def iter_document_chunks(path):
    """Yield (source, ordinal, text, meta) for one file. .json files are
    flattened to pretty text so their structure is searchable too."""
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except Exception as e:
        print(f"  ! skip {path}: {e}", file=sys.stderr)
        return
    if ext == ".json":
        try:
            raw = json.dumps(json.loads(raw), indent=1, ensure_ascii=False)
        except Exception:
            pass  # not valid json - index as-is
    for i, ch in enumerate(chunk_text(raw)):
        yield (path, i, ch, {"kind": "file", "ext": ext})


# --------------------------------------------------------------------------
# NetSec-specific ingester - the interesting angle
# --------------------------------------------------------------------------
def iter_netsec_chunks(reports_root):
    """Walk a NetSec reports/ tree and yield searchable chunks with rich
    metadata (session, ip, verdict, category, date). One chunk per judged
    candidate plus one for each session's executive summary, so a query
    can retrieve a single IP's verdict across every session it appears in.

    Structure expected (what server/worker.py writes):
        reports/<sid>/verdicts.json
        reports/<sid>/summary.md
        reports/compare/<jid>/summary.md
    """
    if not os.path.isdir(reports_root):
        print(f"  ! not a directory: {reports_root}", file=sys.stderr)
        return

    def _walk_session(sid, vpath):
        try:
            out = json.load(open(vpath, encoding="utf-8"))
        except Exception as e:
            print(f"  ! skip {vpath}: {e}", file=sys.stderr)
            return
        ctx = out.get("context") or {}
        when = (ctx.get("time_range") or [None])[0]
        src = ctx.get("original_filename") or f"session {sid}"
        for r in out.get("results") or []:
            v = r.get("verdict") or {}
            ev = r.get("evidence") or {}
            dev = (ev.get("device") or {})
            name = " ".join(str(x) for x in
                            (dev.get("vendor"), dev.get("hostname")) if x)
            trig = ", ".join(ev.get("trigger_reasons") or [])
            text = (
                f"Session {sid} ({src}"
                + (f", recorded {when}" if when else "") + "). "
                f"IP {r.get('candidate_id')} was judged "
                f"{v.get('verdict')} - category {v.get('category')}, "
                f"confidence {v.get('confidence')}. "
                + (f"Device: {name}. " if name else "")
                + (f"Triggered by: {trig}. " if trig else "")
                + f"Reasoning: {v.get('reasoning') or ''}")
            yield (f"netsec:session:{sid}:{r.get('candidate_id')}", 0, text,
                   {"kind": "netsec_verdict", "session_id": sid,
                    "ip": r.get("candidate_id"), "verdict": v.get("verdict"),
                    "category": v.get("category"), "date": when})
        # executive summary as one chunk (the session-level narrative)
        spath = os.path.join(os.path.dirname(vpath), "summary.md")
        if os.path.isfile(spath):
            summ = open(spath, encoding="utf-8", errors="replace").read()
            for i, ch in enumerate(chunk_text(summ)):
                yield (f"netsec:summary:{sid}", i, ch,
                       {"kind": "netsec_summary", "session_id": sid,
                        "date": when})

    for entry in sorted(os.listdir(reports_root)):
        sub = os.path.join(reports_root, entry)
        vpath = os.path.join(sub, "verdicts.json")
        if os.path.isfile(vpath):
            yield from _walk_session(entry, vpath)
        # comparison reports live under reports/compare/<jid>/summary.md
        if entry == "compare" and os.path.isdir(sub):
            for jid in sorted(os.listdir(sub)):
                spath = os.path.join(sub, jid, "summary.md")
                if os.path.isfile(spath):
                    txt = open(spath, encoding="utf-8",
                               errors="replace").read()
                    for i, ch in enumerate(chunk_text(txt)):
                        yield (f"netsec:compare:{jid}", i, ch,
                               {"kind": "netsec_compare", "compare_job": jid})


# --------------------------------------------------------------------------
# Vector store (SQLite + numpy)
# --------------------------------------------------------------------------
class VectorStore:
    def __init__(self, path=DEFAULT_DB):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL,
                ord INTEGER NOT NULL,
                text TEXT NOT NULL,
                meta_json TEXT,
                dim INTEGER NOT NULL,
                vec BLOB NOT NULL,
                content_hash TEXT UNIQUE
            )""")
        self.db.commit()
        self._cache = None  # (ids, normalized matrix)

    def add(self, source, ord_, text, meta, vec):
        """Insert one chunk. content_hash dedups identical text so
        re-indexing the same file is idempotent."""
        h = hashlib.sha256((source + "|" + text).encode("utf-8")).hexdigest()
        vec = np.asarray(vec, dtype=np.float32)
        try:
            self.db.execute(
                "INSERT INTO chunks (source, ord, text, meta_json, dim, vec, "
                "content_hash) VALUES (?,?,?,?,?,?,?)",
                (source, ord_, text, json.dumps(meta), int(vec.shape[0]),
                 vec.tobytes(), h))
            self._cache = None
            return True
        except sqlite3.IntegrityError:
            return False  # already indexed

    def commit(self):
        self.db.commit()

    def _matrix(self):
        if self._cache is not None:
            return self._cache
        ids, rows = [], []
        for cid, dim, blob in self.db.execute(
                "SELECT id, dim, vec FROM chunks"):
            ids.append(cid)
            rows.append(np.frombuffer(blob, dtype=np.float32, count=dim))
        mat = _normalize(np.vstack(rows)) if rows else np.zeros((0, 0), np.float32)
        self._cache = (ids, mat)
        return self._cache

    def search(self, qvec, k=6, where=None):
        """Cosine top-k. `where` optionally filters on a metadata field,
        e.g. {"verdict": "malicious"} or {"ip": "8.8.8.8"}."""
        ids, mat = self._matrix()
        if not ids:
            return []
        q = _normalize(np.asarray(qvec, dtype=np.float32).reshape(1, -1))[0]
        if q.shape[0] != mat.shape[1]:
            raise RuntimeError(
                f"query dim {q.shape[0]} != index dim {mat.shape[1]} - the "
                f"embed model changed; rebuild the store")
        scores = mat @ q
        order = np.argsort(-scores)
        hits = []
        for idx in order:
            cid = ids[int(idx)]
            row = self.db.execute(
                "SELECT source, ord, text, meta_json FROM chunks WHERE id=?",
                (cid,)).fetchone()
            meta = json.loads(row[3] or "{}")
            if where and any(meta.get(kk) != vv for kk, vv in where.items()):
                continue
            hits.append({"score": float(scores[idx]), "source": row[0],
                         "ord": row[1], "text": row[2], "meta": meta})
            if len(hits) >= k:
                break
        return hits

    def stats(self):
        n = self.db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        by_kind = {}
        for (mj,) in self.db.execute("SELECT meta_json FROM chunks"):
            kind = (json.loads(mj or "{}").get("kind") or "?")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        srcs = self.db.execute(
            "SELECT COUNT(DISTINCT source) FROM chunks").fetchone()[0]
        return {"chunks": n, "sources": srcs, "by_kind": by_kind}


# --------------------------------------------------------------------------
# Generation backends (hybrid: local Ollama or cloud Groq)
# --------------------------------------------------------------------------
_SYSTEM = (
    "You are a precise assistant answering ONLY from the provided context "
    "passages. Extract the CONCRETE facts (IPs, verdicts, categories, "
    "dates, device names) directly from the passages - never answer with "
    "citation numbers alone (e.g. NOT '[1], [2] were malicious', but "
    "'192.168.1.10 (session 4) and 172.10.146.42 (session 21) were "
    "malicious'). Cite the passage numbers as [1], [2] AFTER the fact. "
    "If the answer is not in the context, say exactly: 'That is not in "
    "the indexed material.' Never invent facts.")


def _build_prompt(question, hits):
    ctx = "\n\n".join(f"[{i+1}] (source: {h['source']})\n{h['text']}"
                      for i, h in enumerate(hits))
    return (f"Context passages:\n{ctx}\n\n"
            f"Question: {question}\n\n"
            f"Answer using only the passages above, with [n] citations.")


def generate_local(question, hits, model=GEN_MODEL, base=OLLAMA_URL):
    out = _post_json(f"{base}/api/chat", {
        "model": model, "stream": False,
        "messages": [{"role": "system", "content": _SYSTEM},
                     {"role": "user", "content": _build_prompt(question, hits)}],
        "options": {"temperature": 0.1}})
    return (out.get("message") or {}).get("content", "").strip()


def stream_local(question, hits, model=GEN_MODEL, base=OLLAMA_URL):
    """Yield incremental token dicts from Ollama's /api/chat stream.

    Each yielded dict is what Ollama emitted: usually {"message":
    {"content": "..."}}. Consumers concatenate the .content chunks to
    build the growing answer. The RAG web UI uses this for
    llama.ui-style token-by-token rendering."""
    payload = {
        "model": model, "stream": True, "keep_alive": "30m",
        "messages": [{"role": "system", "content": _SYSTEM},
                     {"role": "user",
                      "content": _build_prompt(question, hits)}],
        "options": {"temperature": 0.1},
    }
    req = urllib.request.Request(
        f"{base}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    # 900s: even the ARM CPU finishes any reasonable answer within.
    with urllib.request.urlopen(req, timeout=900) as r:
        for raw in r:
            if not raw:
                continue
            try:
                yield json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                continue


def generate_groq(question, hits, model=GROQ_MODEL):
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        raise RuntimeError("GROQ_API_KEY not set - needed for --generator groq")
    out = _post_json(GROQ_URL, {
        "model": model, "temperature": 0.1,
        "messages": [{"role": "system", "content": _SYSTEM},
                     {"role": "user", "content": _build_prompt(question, hits)}]},
        headers={"Authorization": f"Bearer {key}"})
    return out["choices"][0]["message"]["content"].strip()


# --------------------------------------------------------------------------
# Engine - ties it together
# --------------------------------------------------------------------------
class RagEngine:
    def __init__(self, db_path=DEFAULT_DB, embed_model=EMBED_MODEL):
        self.store = VectorStore(db_path)
        self.embed_model = embed_model

    def _index_stream(self, stream, batch=32):
        """Embed + store a stream of (source, ord, text, meta) tuples."""
        added = skipped = 0
        buf = []

        def flush():
            nonlocal added, skipped
            if not buf:
                return
            vecs = embed_texts([t for (_, _, t, _) in buf], self.embed_model)
            for (src, ordn, txt, meta), vec in zip(buf, vecs):
                if self.store.add(src, ordn, txt, meta, vec):
                    added += 1
                else:
                    skipped += 1
            buf.clear()

        for tup in stream:
            buf.append(tup)
            if len(buf) >= batch:
                flush()
        flush()
        self.store.commit()
        return added, skipped

    def index_paths(self, paths):
        def stream():
            for p in paths:
                for g in glob.glob(os.path.expanduser(p)):
                    if os.path.isdir(g):
                        for root, _, files in os.walk(g):
                            for fn in files:
                                if os.path.splitext(fn)[1].lower() in TEXT_EXTS:
                                    yield from iter_document_chunks(
                                        os.path.join(root, fn))
                    elif os.path.splitext(g)[1].lower() in TEXT_EXTS:
                        yield from iter_document_chunks(g)
        return self._index_stream(stream())

    def ingest_netsec(self, reports_root):
        return self._index_stream(iter_netsec_chunks(reports_root))

    def retrieve(self, question, k=6, where=None):
        qvec = embed_texts([question], self.embed_model)[0]
        return self.store.search(qvec, k=k, where=where)

    def answer(self, question, k=6, generator="local", where=None):
        hits = self.retrieve(question, k=k, where=where)
        if not hits:
            return {"answer": "That is not in the indexed material.",
                    "sources": []}
        gen = generate_groq if generator == "groq" else generate_local
        text = gen(question, hits)
        return {"answer": text, "sources": hits}

    def stream_answer(self, question, k=6, where=None):
        """Yield (kind, payload) tuples for a UI to render live:

            ("sources", [hit_dict, ...])          # first, exactly once
            ("token", "text chunk")               # zero or more
            ("done", {"tokens_out": N, ...})      # last, exactly once
            ("error", "explanation")              # instead of done, on fail

        Only the LOCAL generator is streamable (Ollama supports token
        streaming). The Groq path is fire-and-forget - callers that want
        streaming force generator=local."""
        try:
            hits = self.retrieve(question, k=k, where=where)
        except Exception as e:
            yield ("error", f"retrieval failed: {e}")
            return
        if not hits:
            yield ("sources", [])
            yield ("token", "That is not in the indexed material.")
            yield ("done", {"tokens_out": 0})
            return
        yield ("sources", hits)
        n = 0
        try:
            for chunk in stream_local(question, hits, base=OLLAMA_URL):
                text = ((chunk.get("message") or {}).get("content") or "")
                if text:
                    n += 1
                    yield ("token", text)
                if chunk.get("done"):
                    yield ("done", {"tokens_out":
                                    chunk.get("eval_count") or n,
                                    "total_ms":
                                    (chunk.get("total_duration") or 0)
                                    // 1_000_000})
                    return
            yield ("done", {"tokens_out": n})
        except Exception as e:
            yield ("error", f"generation failed: {e}")


# --------------------------------------------------------------------------
# Minimal local chat page (stdlib http.server, no Dash) - optional serve
# --------------------------------------------------------------------------
_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetSec RAG</title><style>
body{font-family:-apple-system,Segoe UI,sans-serif;max-width:760px;margin:0 auto;
padding:16px;background:#0d1117;color:#e6edf3}
#log{margin:12px 0}.q{color:#79c0ff;margin-top:14px}.a{white-space:pre-wrap;margin:6px 0}
.src{font-size:12px;color:#8b949e;border-left:2px solid #30363d;padding-left:8px;margin:4px 0}
input,button{font-size:16px;padding:10px;border-radius:8px;border:1px solid #30363d;
background:#161b22;color:#e6edf3}input{width:74%}button{width:22%}
</style></head><body><h3>NetSec RAG</h3>
<div id="log"></div>
<div><input id="q" placeholder="ask your indexed material..."
onkeydown="if(event.key==='Enter')go()"><button onclick="go()">Ask</button></div>
<script>
async function go(){const q=document.getElementById('q').value.trim();if(!q)return;
document.getElementById('q').value='';const log=document.getElementById('log');
log.innerHTML+='<div class="q">'+q+'</div><div class="a" id="pending">...</div>';
// Relative URL - works both at http://host:5200/ (direct) and at
// https://host/rag/ (behind the Caddy path prefix).
const r=await fetch('ask',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({q})});const d=await r.json();
document.getElementById('pending').removeAttribute('id');
log.lastChild.textContent=d.answer;
for(const s of d.sources){const e=document.createElement('div');e.className='src';
e.textContent='['+ (d.sources.indexOf(s)+1) +'] '+s.source+' ('+s.score.toFixed(2)+')';
log.appendChild(e);}window.scrollTo(0,document.body.scrollHeight);}
</script></body></html>"""


def serve(engine, host="127.0.0.1", port=5200, generator="local"):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_PAGE.encode("utf-8"))

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            q = json.loads(self.rfile.read(n) or b"{}").get("q", "")
            try:
                res = engine.answer(q, generator=generator)
            except Exception as e:
                res = {"answer": f"error: {e}", "sources": []}
            body = json.dumps({"answer": res["answer"],
                               "sources": [{"source": h["source"],
                                            "score": h["score"]}
                                           for h in res["sources"]]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

    print(f"serving on http://{host}:{port}  (generator={generator})")
    HTTPServer((host, port), H).serve_forever()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--embed-model", default=EMBED_MODEL)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_idx = sub.add_parser("index", help="index files/dirs (.txt .md .json ...)")
    p_idx.add_argument("paths", nargs="+")

    p_net = sub.add_parser("ingest-netsec", help="index a NetSec reports/ tree")
    p_net.add_argument("reports_root")

    p_ask = sub.add_parser("ask", help="ask a question")
    p_ask.add_argument("question")
    p_ask.add_argument("-k", type=int, default=6, help="passages to retrieve")
    p_ask.add_argument("--generator", choices=["local", "groq"], default="local")
    p_ask.add_argument("--where", help='JSON metadata filter, e.g. \'{"verdict":"malicious"}\'')

    sub.add_parser("stats", help="what is indexed")

    p_srv = sub.add_parser("serve", help="tiny local chat page")
    p_srv.add_argument("--host", default="127.0.0.1")
    p_srv.add_argument("--port", type=int, default=5200)
    p_srv.add_argument("--generator", choices=["local", "groq"], default="local")

    args = ap.parse_args(argv)
    eng = RagEngine(db_path=os.path.expanduser(args.db),
                    embed_model=args.embed_model)

    if args.cmd == "index":
        t0 = time.time()
        added, skipped = eng.index_paths(args.paths)
        print(f"indexed {added} new chunk(s), {skipped} already present "
              f"({time.time()-t0:.1f}s)")
    elif args.cmd == "ingest-netsec":
        t0 = time.time()
        added, skipped = eng.ingest_netsec(args.reports_root)
        print(f"ingested {added} NetSec chunk(s), {skipped} already present "
              f"({time.time()-t0:.1f}s)")
    elif args.cmd == "ask":
        where = json.loads(args.where) if args.where else None
        res = eng.answer(args.question, k=args.k,
                         generator=args.generator, where=where)
        print("\n" + res["answer"] + "\n")
        if res["sources"]:
            print("sources:")
            for i, h in enumerate(res["sources"], 1):
                print(f"  [{i}] {h['source']}  (cos {h['score']:.2f})")
    elif args.cmd == "stats":
        s = eng.store.stats()
        print(json.dumps(s, indent=2))
    elif args.cmd == "serve":
        serve(eng, host=args.host, port=args.port, generator=args.generator)


if __name__ == "__main__":
    main()
