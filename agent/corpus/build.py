"""Build the RAG corpus from MITRE ATT&CK and the protocol RFCs; run as a script, not from the service.

    python -m agent.corpus.build --out /var/lib/netsec-agent/corpus.sqlite

The downloads land in a cache directory so a rebuild is idempotent; delete them to force a fresh pull.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Iterable

import httpx

from agent.corpus.store import EMBED_BATCH, CorpusStore, embed_batch, embed_model

# MITRE ATT&CK enterprise bundle (STIX 2.1). One stable URL at the CTI mirror.
ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
# The techniques the NETSEC engines point at; one-chunk-per-technique at a minimum.
ENGINE_TECHNIQUES = (
    "T1046", "T1498", "T1498.001", "T1498.002", "T1557", "T1557.002",
    "T1071", "T1071.001", "T1071.004", "T1090", "T1090.004", "T1568.002", "T1571",
)
# RFCs for the protocols the engines inspect. Keyed by (technique, tactic) so a chunk ties to its MITRE entry.
RFCS = (
    # DNS - used by T1071.004 (DNS C2) and T1568.002 (DGA)
    ("1035", "T1071.004", "Command and Control", "DNS protocol structure"),
    # TLS 1.3
    ("8446", "T1071.001", "Command and Control", "TLS 1.3 server name indication and handshake"),
    # HTTP semantics
    ("9110", "T1071.001", "Command and Control", "HTTP request semantics and headers"),
    # ARP
    ("826", "T1557.002", "Credential Access, Collection", "ARP address resolution protocol"),
    # TCP (used in SYN scan recognition)
    ("9293", "T1046", "Discovery", "TCP connection setup and state"),
)
# Size cuts for chunks. Keep each one small enough to sit in a 512-token prompt and still carry the facts.
CHUNK_MAX_CHARS = 1400
CHUNK_MIN_CHARS = 220


def _fetch(url: str, cache: Path, *, timeout: float = 90.0) -> str:
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.is_file() and cache.stat().st_size > 0:
        return cache.read_text(encoding="utf-8")
    response = httpx.get(url, timeout=timeout, follow_redirects=True,
                        headers={"User-Agent": "netsec-agent-corpus-builder/0.1"})
    response.raise_for_status()
    cache.write_text(response.text, encoding="utf-8")
    return response.text


def _chunk_paragraphs(text: str, *, max_chars: int = CHUNK_MAX_CHARS, min_chars: int = CHUNK_MIN_CHARS) -> list[str]:
    """Split on blank lines and merge adjacent paragraphs until each chunk is between min and max characters."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    out: list[str] = []
    buf = ""
    for p in paragraphs:
        combined = (buf + "\n\n" + p) if buf else p
        if len(combined) > max_chars and len(buf) >= min_chars:
            out.append(buf)
            buf = p
        else:
            buf = combined
    if buf.strip():
        out.append(buf)
    # Join any tails that are too short into the previous chunk so the embedder has enough context.
    merged: list[str] = []
    for chunk in out:
        if merged and len(chunk) < min_chars:
            merged[-1] = merged[-1] + "\n\n" + chunk
        else:
            merged.append(chunk)
    return merged


def attack_chunks(text: str) -> Iterable[dict]:
    """One chunk per engine technique, built from the ATT&CK STIX bundle's `attack-pattern` objects."""
    bundle = json.loads(text)
    by_id: dict[str, dict] = {}
    for obj in bundle.get("objects") or []:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                by_id[ref["external_id"]] = obj
                break
    for technique in ENGINE_TECHNIQUES:
        obj = by_id.get(technique)
        if obj is None:
            continue
        name = obj.get("name") or technique
        tactics = ", ".join(phase.get("phase_name", "") for phase in obj.get("kill_chain_phases") or [])
        description = (obj.get("x_mitre_detection") or "") + "\n\n" + (obj.get("description") or "")
        description = re.sub(r"\n{3,}", "\n\n", description).strip()
        if not description:
            continue
        yield {
            "id": f"attack:{technique}",
            "source": "mitre-attack",
            "technique": technique,
            "title": f"{technique} - {name}",
            "tactic": tactics,
            "text": f"{name} ({technique})\n\n{description}"[:4000],
        }


def rfc_chunks(number: str, technique: str, tactic: str, title: str, text: str) -> Iterable[dict]:
    """Split one RFC into paragraph-sized chunks, tagged with the technique it answers for."""
    # The RFC headers and footers add noise; cut page breaks and the usual boilerplate.
    text = re.sub(r"\f.*?\n", "\n", text)
    text = re.sub(r"\[Page \d+\]", "", text)
    text = re.sub(r"RFC \d+ +.*? +\w+ \d{4}", "", text)
    chunks = _chunk_paragraphs(text)
    # Keep only the chunks that mention the protocol content the engines care about.
    keywords = {
        "T1071.004": ("DNS", "domain", "query"),
        "T1071.001": ("TLS", "SNI", "server_name", "HTTP", "Host"),
        "T1557.002": ("ARP", "hardware", "address"),
        "T1046": ("TCP", "SYN", "port"),
    }
    needles = tuple(k.lower() for k in keywords.get(technique, ()))
    for i, chunk in enumerate(chunks):
        if needles and not any(needle in chunk.lower() for needle in needles):
            continue
        yield {
            "id": f"rfc{number}:{i}",
            "source": f"rfc:{number}",
            "technique": technique,
            "title": f"RFC {number} - {title}",
            "tactic": tactic,
            "text": chunk[:CHUNK_MAX_CHARS],
        }


def build_corpus(output: str, *, cache_dir: str | None = None, verbose: bool = True) -> dict:
    """Pull MITRE + the RFCs, embed every chunk, and write them into one SQLite file. Returns the counts."""
    cache = Path(cache_dir or Path(output).parent / "corpus-cache")
    started = time.time()

    if verbose:
        print(f"[corpus] downloading and parsing MITRE ATT&CK", flush=True)
    attack_text = _fetch(ATTACK_URL, cache / "enterprise-attack.json")
    chunks = list(attack_chunks(attack_text))

    for number, technique, tactic, title in RFCS:
        if verbose:
            print(f"[corpus] downloading and chunking RFC {number}", flush=True)
        try:
            text = _fetch(f"https://www.rfc-editor.org/rfc/rfc{number}.txt", cache / f"rfc{number}.txt")
        except httpx.HTTPError as exc:
            if verbose:
                print(f"[corpus] RFC {number} could not be fetched ({type(exc).__name__}); skipped", flush=True)
            continue
        chunks.extend(rfc_chunks(number, technique, tactic, title, text))

    if verbose:
        print(f"[corpus] embedding {len(chunks)} chunks with {embed_model()}", flush=True)
    tmp_path = str(Path(output).with_suffix(".sqlite.tmp"))
    Path(tmp_path).unlink(missing_ok=True)
    store = CorpusStore(tmp_path)
    try:
        for i in range(0, len(chunks), EMBED_BATCH):
            batch = chunks[i:i + EMBED_BATCH]
            vectors = embed_batch([c["text"] for c in batch])
            store.add_chunks(batch, vectors)
            if verbose:
                print(f"[corpus] stored {i + len(batch)} / {len(chunks)}", flush=True)
        store.set_meta("built_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        store.set_meta("embed_model", embed_model())
        store.set_meta("sources", {"mitre-attack": sum(1 for c in chunks if c["source"] == "mitre-attack"),
                                   **{f"rfc:{n}": sum(1 for c in chunks if c["source"] == f"rfc:{n}")
                                      for n, _, _, _ in RFCS}})
    finally:
        store.close()
    Path(tmp_path).replace(output)

    elapsed = time.time() - started
    total = len(chunks)
    if verbose:
        print(f"[corpus] done: {total} chunks in {output} ({elapsed:.1f}s)", flush=True)
    return {"total": total, "elapsed_s": elapsed, "output": output}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the RAG corpus of the NETSEC agents.")
    parser.add_argument("--out", required=True, help="path to the output SQLite file")
    parser.add_argument("--cache", default=None, help="where the raw downloads are cached")
    parser.add_argument("--quiet", action="store_true", help="suppress progress messages")
    args = parser.parse_args()
    build_corpus(args.out, cache_dir=args.cache, verbose=not args.quiet)


if __name__ == "__main__":
    main()
