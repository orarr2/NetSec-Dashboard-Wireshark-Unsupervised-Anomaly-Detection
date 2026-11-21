"""The RAG corpus: MITRE ATT&CK and the protocol RFCs the engines quote, stored once and retrieved on demand."""

from agent.corpus.store import CorpusStore, embed_batch

__all__ = ["CorpusStore", "embed_batch"]
