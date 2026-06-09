"""Tests for embedding RAG convenience helpers."""

from src.llm import embedding_rag
from src.llm.embedding_rag import EmbeddingRAG, VulnerabilityDocument


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


class FakeEmbedding:
    def tolist(self):
        return [0.1, 0.2, 0.3]


class FakeEmbedder:
    def encode(self, texts):
        assert len(texts) == 1
        return [FakeEmbedding()]


class FakeCollection:
    def __init__(self):
        self.added = None

    def add(self, **kwargs):
        self.added = kwargs


def test_add_custom_vulnerability_updates_index_and_clears_cache(tmp_path):
    """Custom documents should be searchable via the local ID index immediately."""
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    collection = FakeCollection()
    vulnerability = VulnerabilityDocument(
        id="CUSTOM-001",
        title="Custom Finding",
        description="Custom vulnerability description",
        vulnerable_code="function withdraw() external {}",
        fixed_code="function withdraw() external nonReentrant {}",
        category="reentrancy",
        severity="high",
    )

    rag._initialized = True
    rag._embedder = FakeEmbedder()
    rag._collection = collection
    rag._doc_index = {}
    rag._query_cache = {"stale": (0.0, [])}
    rag._cache_hits = 3
    rag._cache_misses = 2

    rag.add_custom_vulnerability(vulnerability)

    assert rag._doc_index["CUSTOM-001"] is vulnerability
    assert rag._query_cache == {}
    assert rag._cache_hits == 0
    assert rag._cache_misses == 0
    assert collection.added["ids"] == ["CUSTOM-001"]
