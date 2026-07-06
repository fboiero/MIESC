"""Tests for embedding RAG convenience helpers."""

from src.llm import embedding_rag
from src.llm.embedding_rag import (
    EmbeddingRAG,
    VulnerabilityDocument,
    _coerce_batch_queries,
    _coerce_batch_query_text,
    _coerce_collection_name,
    _coerce_result_count,
)


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


class FakeClient:
    def __init__(self):
        self.deleted = []
        self.created = []
        self.collection = FakeCollection()

    def delete_collection(self, name):
        self.deleted.append(name)

    def create_collection(self, **kwargs):
        self.created.append(kwargs)
        return self.collection


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


def test_reindex_resets_local_index_and_cache(tmp_path, monkeypatch):
    """Reindexing the base KB should discard stale custom index/cache state."""
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    client = FakeClient()
    indexed = []

    rag._initialized = True
    rag._client = client
    rag._collection = FakeCollection()
    rag._doc_index = {"CUSTOM-001": object()}
    rag._query_cache = {"stale": (0.0, [])}
    rag._cache_hits = 4
    rag._cache_misses = 5
    monkeypatch.setattr(rag, "_index_knowledge_base", lambda: indexed.append(True))

    rag.reindex()

    assert client.deleted == [EmbeddingRAG.COLLECTION_NAME]
    assert client.created[0]["name"] == EmbeddingRAG.COLLECTION_NAME
    assert indexed == [True]
    assert "CUSTOM-001" not in rag._doc_index
    assert rag._doc_index
    assert rag._query_cache == {}
    assert rag._cache_hits == 0
    assert rag._cache_misses == 0


def test_text_coercion_helpers_strip_and_reject_control_chars():
    assert embedding_rag._coerce_document_text("  document text  ") == "document text"
    assert embedding_rag._coerce_document_text("document\ntext") == ""
    assert embedding_rag._coerce_query_text(b" query ") == "query"
    assert embedding_rag._coerce_query_text("query\x7fvalue") == ""


def test_batch_query_helpers_strip_and_reject_control_chars():
    assert _coerce_batch_queries(("alpha", "beta")) == ["alpha", "beta"]
    assert _coerce_batch_queries("not-a-sequence") == []
    assert _coerce_batch_query_text("  alpha  ") == (True, "alpha")
    assert _coerce_batch_query_text("alpha\nbeta") == (False, "")
    assert _coerce_batch_query_text(b" beta ") == (True, "beta")
    assert _coerce_batch_query_text(b"beta\x7f") == (False, "")


def test_result_count_and_collection_name_helpers_reject_control_chars():
    assert _coerce_result_count(" 7 ", 3) == 7
    assert _coerce_result_count("7\x7f", 3) == 3
    assert _coerce_collection_name("  vuln_cache  ") == "vuln_cache"
    assert _coerce_collection_name("bad\nname") == "miesc_vulnerabilities"
