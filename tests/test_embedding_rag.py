"""Tests for embedding RAG convenience helpers."""

from src.llm import embedding_rag


class FakeEmbeddingRAG:
    pass


class FakeHybridRAG:
    pass


def test_get_rag_caches_instances_per_hybrid_mode(monkeypatch):
    """Requesting hybrid and non-hybrid RAG should not share a singleton."""
    monkeypatch.setattr(embedding_rag, "_default_rags", {})
    monkeypatch.setattr(embedding_rag, "EmbeddingRAG", FakeEmbeddingRAG)
    monkeypatch.setattr(embedding_rag, "HybridRAG", FakeHybridRAG)

    hybrid_rag = embedding_rag.get_rag(hybrid=True)
    embedding_only_rag = embedding_rag.get_rag(hybrid=False)

    assert isinstance(hybrid_rag, FakeHybridRAG)
    assert isinstance(embedding_only_rag, FakeEmbeddingRAG)
    assert hybrid_rag is not embedding_only_rag
    assert embedding_rag.get_rag(hybrid=True) is hybrid_rag
    assert embedding_rag.get_rag(hybrid=False) is embedding_only_rag
