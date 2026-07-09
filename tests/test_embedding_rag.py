"""Tests for embedding RAG convenience helpers."""

import pytest

from src.llm import embedding_rag
from src.llm.embedding_rag import (
    EmbeddingRAG,
    HybridRAG,
    RetrievalResult,
    VulnerabilityDocument,
    _coerce_batch_queries,
    _coerce_batch_query_text,
    _coerce_cache_query_text,
    _coerce_collection_name,
    _coerce_embedding_vector,
    _coerce_persist_directory,
    _coerce_result_count,
    _coerce_text_list,
    _is_safe_text,
    _result_rows,
    batch_get_context_for_findings,
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
        self.query_payload = {"ids": [[]]}
        self.query_calls = []
        self.count_value = 1

    def add(self, **kwargs):
        self.added = kwargs

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return self.query_payload

    def count(self):
        return self.count_value


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


def initialized_rag(tmp_path, payload=None):
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    collection = FakeCollection()
    if payload is not None:
        collection.query_payload = payload
    rag._initialized = True
    rag._collection = collection
    rag._doc_index = {
        "SWC-107": VulnerabilityDocument(
            id="SWC-107",
            title="Reentrancy",
            description="Reentrancy vulnerability",
            category="reentrancy",
            severity="high",
            source_tier="standard",
            tags=["reentrancy"],
        )
    }
    return rag, collection


def test_search_uses_empty_query_for_non_text_input_without_crashing(tmp_path):
    payload = {"ids": [["SWC-107"]], "distances": [[0.25]], "metadatas": [[{}]]}
    rag, collection = initialized_rag(tmp_path, payload)

    results = rag.search({"query": "reentrancy"}, n_results=1)

    assert len(results) == 1
    assert collection.query_calls[0]["query_texts"] == [""]


def test_search_skips_result_rows_with_non_mapping_metadata(tmp_path):
    payload = {
        "ids": [["SWC-107", "SWC-107"]],
        "distances": [[0.1, 0.2]],
        "metadatas": [[[], "bad"]],
    }
    rag, _collection = initialized_rag(tmp_path, payload)

    assert rag.search("reentrancy", n_results=2) == []


def test_search_skips_unknown_and_blank_result_ids(tmp_path):
    payload = {
        "ids": [["", {"bad": "id"}, "UNKNOWN"]],
        "distances": [[0.1, 0.2, 0.3]],
        "metadatas": [[{}, {}, {}]],
    }
    rag, _collection = initialized_rag(tmp_path, payload)

    assert rag.search("reentrancy", n_results=3) == []


def test_search_dedupes_duplicate_result_ids_and_keeps_best_score(tmp_path):
    payload = {
        "ids": [["SWC-107", "SWC-107"]],
        "distances": [[0.7, 0.1]],
        "metadatas": [[{}, {}]],
    }
    rag, _collection = initialized_rag(tmp_path, payload)

    results = rag.search("reentrancy", n_results=2)

    assert [result.document.id for result in results] == ["SWC-107"]
    assert results[0].similarity_score > 0.8


def test_batch_search_preserves_empty_slots_for_invalid_queries(tmp_path):
    payload = {"ids": [["SWC-107"]], "distances": [[0.2]], "metadatas": [[{}]]}
    rag, collection = initialized_rag(tmp_path, payload)

    results = rag.batch_search(["reentrancy", {"bad": "query"}, "bad\nquery"], n_results=1)

    assert len(results) == 3
    assert results[0]
    assert results[1] == []
    assert results[2] == []
    assert collection.query_calls[0]["query_texts"] == ["reentrancy"]


def test_get_cached_result_evicts_tuple_with_malformed_results(tmp_path):
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    rag._query_cache = {"key": (0.0, ["bad"])}

    assert rag._get_cached_result("key") is None
    assert "key" not in rag._query_cache


def test_cache_result_resets_malformed_cache_container(tmp_path):
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    rag._query_cache = ["bad"]
    doc = VulnerabilityDocument(id="DOC-6")
    result = RetrievalResult(document=doc, similarity_score=0.5, relevance_reason="ok")

    rag._cache_result("key", [result])

    assert isinstance(rag._query_cache, dict)


def test_cache_result_does_not_increment_miss_for_disabled_cache(tmp_path):
    rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
    doc = VulnerabilityDocument(id="DOC-7")
    result = RetrievalResult(document=doc, similarity_score=0.5, relevance_reason="ok")

    rag._cache_result("key", [result])

    assert rag._cache_misses == 0
    assert rag._query_cache == {}


def test_add_custom_vulnerability_rejects_empty_embedding_rows(tmp_path):
    class EmptyEmbedder:
        def encode(self, _texts):
            return []

    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    rag._initialized = True
    rag._embedder = EmptyEmbedder()
    rag._collection = FakeCollection()

    with pytest.raises(ValueError, match="finite numeric vector"):
        rag.add_custom_vulnerability(VulnerabilityDocument(id="CUSTOM-EMPTY"))


def test_search_by_finding_ignores_hostile_get_accessors(tmp_path):
    rag, _collection = initialized_rag(tmp_path)
    captured = {}

    def fake_multi_step(query, filter_category=None):
        captured["query"] = query
        captured["filter_category"] = filter_category
        return []

    rag.multi_step_search = fake_multi_step
    finding = ExplodingGetDict(
        type="reentrancy",
        title="Withdraw issue",
        description="External call before state update",
        swc_id="SWC-107",
    )

    assert rag.search_by_finding(finding, code_context=["bad"]) == []
    assert "Vulnerability type: reentrancy" in captured["query"]
    assert "Code:" not in captured["query"]
    assert captured["filter_category"] == "reentrancy"


def test_search_by_finding_tolerates_malformed_finding(tmp_path):
    rag, _collection = initialized_rag(tmp_path)
    captured = {}
    rag.multi_step_search = lambda query, filter_category=None: (
        captured.setdefault("args", (query, filter_category)) or []
    )

    rag.search_by_finding(["not", "mapping"], code_context="code")

    assert captured["args"] == ("Code: code", None)


def test_get_context_for_llm_coerces_malformed_max_length(tmp_path):
    rag, _collection = initialized_rag(tmp_path)
    doc = VulnerabilityDocument(
        id="DOC-8",
        title="Reentrancy",
        description="x" * 500,
        category="reentrancy",
    )
    rag.search_by_finding = lambda *_args, **_kwargs: [
        RetrievalResult(document=doc, similarity_score=0.9, relevance_reason="ok")
    ]

    context = rag.get_context_for_llm({"type": "reentrancy"}, max_context_length="bad")

    assert context.startswith("## Similar Known Vulnerabilities")
    assert len(context) <= embedding_rag.MAX_CONTEXT_LENGTH


def test_hybrid_search_coerces_query_and_embedding_weight(tmp_path, monkeypatch):
    class FakeBM25:
        def get_scores(self, tokens):
            assert tokens == []
            return [1.0]

    rag = HybridRAG(persist_directory=str(tmp_path), embedding_weight=99)
    rag._initialized = True
    rag._bm25 = FakeBM25()
    doc = VulnerabilityDocument(id="SWC-107")
    monkeypatch.setattr(
        EmbeddingRAG,
        "search",
        lambda *_args, **_kwargs: [RetrievalResult(doc, 0.5, "ok")],
    )

    assert rag.embedding_weight == 1.0
    results = HybridRAG.search(rag, {"bad": "query"}, n_results=1)
    assert len(results) == 1
    assert 0.0 <= results[0].similarity_score <= 1.0


def test_batch_get_context_for_findings_skips_non_mapping_findings(monkeypatch):
    class FakeRAG:
        def batch_search(self, queries):
            assert queries == ["Vulnerability type: reentrancy\nsafe description\nCode: code"]
            return [
                [
                    RetrievalResult(
                        VulnerabilityDocument(
                            id="DOC-9",
                            title="Reentrancy",
                            description="desc",
                            category="reentrancy",
                        ),
                        0.8,
                        "ok",
                    )
                ]
            ]

    monkeypatch.setattr(embedding_rag, "get_rag", lambda hybrid=True: FakeRAG())
    findings = [
        ExplodingGetDict(
            type="reentrancy",
            title="Finding title",
            description="safe description",
        ),
        None,
        ["bad"],
        "bad",
    ]

    contexts = batch_get_context_for_findings(findings, code="code")

    assert list(contexts) == ["Finding title"]
    assert "Similar Known Vulnerabilities" in contexts["Finding title"]


def test_get_rag_normalizes_hybrid_cache_key(monkeypatch):
    monkeypatch.setattr(embedding_rag, "_default_rags", {})
    monkeypatch.setattr(embedding_rag, "EmbeddingRAG", FakeEmbeddingRAG)
    monkeypatch.setattr(embedding_rag, "HybridRAG", FakeHybridRAG)

    assert isinstance(embedding_rag.get_rag(hybrid="yes"), FakeEmbeddingRAG)
    assert isinstance(embedding_rag.get_rag(hybrid=True), FakeHybridRAG)
    assert set(embedding_rag._default_rags) == {False, True}


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
    assert _coerce_text_list(["  alpha  ", b" beta ", "gamma\ndelta"]) == ["alpha", "beta"]
    assert len(_coerce_text_list([f"tag-{i}" for i in range(125)])) == 100
    assert _coerce_cache_query_text({"query": "alpha"}) == ""
    assert embedding_rag._coerce_document_text("  document text  ") == "document text"
    assert embedding_rag._coerce_document_text("document\ntext") == ""
    assert embedding_rag._coerce_document_text("x" * 20_001) == ""
    assert embedding_rag._coerce_query_text(b" query ") == "query"
    assert embedding_rag._coerce_query_text("query\x7fvalue") == ""
    assert embedding_rag._coerce_query_text("query\u2028value") == ""
    assert embedding_rag._coerce_query_text("query\u200bvalue") == ""


def test_text_list_handles_hostile_collection_iteration():
    class HostileList(list):
        def __iter__(self):
            raise RuntimeError("boom")

    assert _coerce_text_list(HostileList(["alpha"])) == []


def test_safe_metadata_filter_rejects_malformed_filter_shapes(monkeypatch):
    monkeypatch.setattr(embedding_rag, "build_metadata_filter", lambda *_args: {"$and": []})
    assert embedding_rag._safe_metadata_filter("reentrancy", "high") is None

    monkeypatch.setattr(
        embedding_rag,
        "build_metadata_filter",
        lambda *_args: {"$and": [{"category": "reentrancy"}, {"severity": "high"}]},
    )
    assert embedding_rag._safe_metadata_filter("reentrancy", "high") == {
        "$and": [{"category": "reentrancy"}, {"severity": "high"}]
    }

    monkeypatch.setattr(
        embedding_rag,
        "build_metadata_filter",
        lambda *_args: {"category": "reentrancy\u2028bad"},
    )
    assert embedding_rag._safe_metadata_filter("reentrancy", None) is None


def test_batch_query_helpers_strip_and_reject_control_chars():
    assert _coerce_batch_queries(("alpha", "beta")) == ["alpha", "beta"]
    assert len(_coerce_batch_queries([str(i) for i in range(125)])) == 100
    assert _coerce_batch_queries("not-a-sequence") == []
    assert _coerce_batch_query_text("  alpha  ") == (True, "alpha")
    assert _coerce_batch_query_text("alpha\nbeta") == (False, "")
    assert _coerce_batch_query_text(b" beta ") == (True, "beta")
    assert _coerce_batch_query_text(b"beta\x7f") == (False, "")


def test_batch_query_helpers_handle_hostile_tuple_subclass():
    class HostileTuple(tuple):
        def __iter__(self):
            raise RuntimeError("boom")

    assert _coerce_batch_queries(HostileTuple(("alpha",))) == []


def test_result_count_and_collection_name_helpers_reject_control_chars():
    assert _coerce_result_count(" 7 ", 3) == 7
    assert _coerce_result_count("7\x7f", 3) == 3
    assert _coerce_result_count(10_000, 3) == embedding_rag.MAX_QUERY_RESULTS
    assert _coerce_collection_name("  vuln_cache  ") == "vuln_cache"
    assert _coerce_collection_name("bad\nname") == "miesc_vulnerabilities"
    assert _coerce_collection_name("bad\u2028name") == "miesc_vulnerabilities"
    assert _result_rows({"ids": [["a"], ["b"]]}, "ids") == [["a"], ["b"]]
    assert _result_rows({"ids": "not-a-row-list"}, "ids") == []
    collection = type("Collection", (), {"metadata": {"version": "  v1.2.3  "}})()
    assert embedding_rag._collection_metadata_text(collection, "version") == "v1.2.3"
    collection.metadata["version"] = "v1\n2.3"
    assert embedding_rag._collection_metadata_text(collection, "version") is None
    assert _result_rows(ExplodingGetDict(ids=[["a"]]), "ids") == [["a"]]
    assert embedding_rag._similarity_from_distance("0.25") == 0.75
    assert embedding_rag._similarity_from_distance(True) == 0.0
    assert embedding_rag._similarity_from_query_result(None, "0.8") == 0.8
    assert embedding_rag._similarity_from_query_result(None, True) == 0.0


def test_result_row_helpers_cap_and_handle_hostile_shapes():
    rows = [[str(i) for i in range(embedding_rag.MAX_RESULT_ROW_ITEMS + 20)]]
    assert len(embedding_rag._result_row(rows, 0)) == embedding_rag.MAX_RESULT_ROW_ITEMS
    assert embedding_rag._result_rows(
        {"ids": [[str(i)] for i in range(embedding_rag.MAX_RESULT_ROWS + 20)]}, "ids"
    )[-1] == [str(embedding_rag.MAX_RESULT_ROWS - 1)]

    class HostileLen(list):
        def __len__(self):
            raise RuntimeError("boom")

    assert embedding_rag._result_row(HostileLen([["a"]]), 0) == []
    assert embedding_rag._result_value(HostileLen(["a"]), 0) is None
    assert not embedding_rag._has_aligned_optional_result_value(HostileLen([["a"]]), 0, 0)


def test_persist_directory_and_embedding_vector_helpers_reject_control_chars():
    assert _coerce_persist_directory("  ~/miesc-cache  ").parts[-1] == "miesc-cache"
    assert _coerce_persist_directory("bad\npath") == _coerce_persist_directory(None)
    assert _coerce_persist_directory("bad\u2028path") == _coerce_persist_directory(None)
    assert _coerce_embedding_vector([1, " 2 ", 3.5]) == [1.0, 2.0, 3.5]
    assert _coerce_embedding_vector(["1\n", 2]) is None
    assert _coerce_embedding_vector(["1\u2028", 2]) is None
    assert _coerce_embedding_vector([0.0] * (embedding_rag.MAX_EMBEDDING_VECTOR_ITEMS + 1)) is None
    assert _coerce_embedding_vector([embedding_rag.MAX_EMBEDDING_ABS_VALUE + 1]) is None
    assert (
        len(embedding_rag._coerce_embedding_rows([[0]] * 600)) == embedding_rag.MAX_EMBEDDING_ROWS
    )


def test_persist_directory_handles_hostile_pathlike():
    class HostilePath:
        def __fspath__(self):
            raise RuntimeError("boom")

    assert _coerce_persist_directory(HostilePath()) == _coerce_persist_directory(None)


def test_embedding_rows_handles_hostile_tolist():
    class HostileRows:
        def tolist(self):
            raise RuntimeError("boom")

    assert embedding_rag._coerce_embedding_rows(HostileRows()) == []


def test_embedding_rag_boundaries_use_safe_text_and_collection_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(EmbeddingRAG, "COLLECTION_NAME", "bad\nname", raising=False)
    rag = EmbeddingRAG(persist_directory=str(tmp_path), embedding_model="  test-model  ")

    assert _is_safe_text("alpha")
    assert not _is_safe_text("alpha\nbeta")
    assert rag._collection_name() == "miesc_vulnerabilities"
    metadata = rag._collection_metadata()
    assert metadata["embedding_model"] == "test-model"
    assert metadata["knowledge_base_count"] > 0


class ExplodingGetDict(dict):
    def get(self, *_args, **_kwargs):  # pragma: no cover - must not be called
        raise AssertionError("get should not be called")


def test_vulnerability_document_metadata_coerces_non_string_scalar_fields():
    doc = VulnerabilityDocument(id="DOC-1")
    doc.swc_id = ["SWC-107"]
    doc.cwe_id = {"id": "CWE-841"}
    doc.title = "bad\ntitle"
    doc.severity = {"level": "high"}
    doc.category = ["reentrancy"]
    doc.source_tier = {"tier": "incident"}
    doc.source_type = ["pattern"]
    doc.real_exploit = ["hack"]
    doc.fixed_code = {"code": "fix"}

    metadata = doc.to_metadata()

    assert metadata["swc_id"] == ""
    assert metadata["cwe_id"] == ""
    assert metadata["title"] == ""
    assert metadata["severity"] == "medium"
    assert metadata["category"] == "general"
    assert metadata["source_tier"] == "curated"
    assert metadata["source_type"] == "pattern"
    assert metadata["has_exploit"] is False
    assert metadata["has_fix"] is False


def test_vulnerability_to_text_skips_nested_tag_and_reference_shapes():
    doc = VulnerabilityDocument(
        id="DOC-2",
        title="Safe Title",
        description="Description",
        tags=[" reentrancy ", {"bad": "tag"}, ["nested"], "oracle"],
        references=[" docs ", {"bad": "ref"}, ["nested"], "audit"],
    )

    text = doc.to_text()

    assert "Tags: reentrancy, oracle" in text
    assert "References: docs, audit" in text
    assert "{'bad':" not in text
    assert "['nested']" not in text


def test_source_weight_falls_back_for_non_string_or_unknown_tier():
    doc = VulnerabilityDocument(id="DOC-3", source_tier={"bad": "tier"})
    assert doc.source_weight() == embedding_rag.SOURCE_TIER_WEIGHTS["curated"]

    doc.source_tier = "unknown-tier"
    assert doc.source_weight() == embedding_rag.SOURCE_TIER_WEIGHTS["curated"]


def test_retrieval_context_sanitizes_malformed_document_fields():
    doc = VulnerabilityDocument(id="DOC-4")
    doc.title = ["bad"]
    doc.category = {"bad": "category"}
    doc.severity = "high\ncritical"
    doc.source_tier = ["tier"]
    doc.source_type = {"type": "pattern"}
    doc.description = {"description": "bad"}
    doc.real_exploit = ["exploit"]

    result = RetrievalResult(document=doc, similarity_score=float("inf"), relevance_reason="ok")

    context = result.to_context()

    assert "**Untitled** (Score: 0.00)" in context
    assert "- Category: general" in context
    assert "- Severity: medium" in context
    assert "- Real Exploit: N/A" in context
    assert "['bad']" not in context


def test_retrieval_context_sanitizes_steps_and_relevance_reason():
    doc = VulnerabilityDocument(id="DOC-CTX", title="Safe", description="Description")
    result = RetrievalResult(
        document=doc,
        similarity_score=0.8,
        relevance_reason="bad\u2028reason",
        retrieval_steps=[" step ", {"bad": "step"}, "ok"],
    )

    context = result.to_context()

    assert "- Relevance: semantic similarity" in context
    assert "- Retrieval Steps: step; ok" in context


def test_rank_result_tolerates_malformed_doc_cues(tmp_path):
    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    doc = VulnerabilityDocument(id="DOC-5", title="Reentrancy")
    doc.category = {"bad": "category"}
    doc.swc_id = ["SWC-107"]
    doc.cwe_id = {"id": "CWE-841"}
    doc.tags = [" reentrancy ", {"bad": "tag"}]
    doc.source_tier = {"bad": "tier"}
    result = RetrievalResult(
        document=doc,
        similarity_score=0.5,
        relevance_reason="semantic",
        retrieval_steps=[" step ", {"bad": "step"}],
    )

    ranked = rag._rank_result(result, original_query="reentrancy", step={"bad": "step"})

    assert 0.0 <= ranked.similarity_score <= 1.0
    assert "source_tier=curated" in ranked.retrieval_steps
    assert "{'bad':" not in ";".join(ranked.retrieval_steps)


def test_safe_mapping_get_handles_hostile_mapping_accessors():
    class HostileMapping(dict):
        def __contains__(self, key):
            raise RuntimeError("contains")

        def __getitem__(self, key):
            raise RuntimeError("getitem")

    assert embedding_rag._safe_mapping_get(HostileMapping(type="reentrancy"), "type") is None


def test_document_id_helpers_reject_unicode_controls_and_normalize_index(monkeypatch, tmp_path):
    safe_doc = VulnerabilityDocument(id=" DOC-OK ", title="Safe")
    bad_doc = VulnerabilityDocument(id="bad\u2028id", title="Bad")
    monkeypatch.setattr(embedding_rag, "VULNERABILITY_KNOWLEDGE_BASE", [safe_doc, bad_doc])
    rag = EmbeddingRAG(persist_directory=str(tmp_path))

    rag._build_doc_index()

    assert rag._doc_index == {"DOC-OK": safe_doc}
    assert embedding_rag._is_valid_result_id("bad\u2028id") is False


def test_search_caps_returned_rows_and_skips_unsafe_ids(tmp_path):
    doc = VulnerabilityDocument(id="SWC-107")
    safe_ids = ["SWC-107"] * 150
    payload = {
        "ids": [["bad\u2028id", *safe_ids]],
        "distances": [[0.1] * 151],
        "metadatas": [[{}] * 151],
    }
    rag, collection = initialized_rag(tmp_path, payload)
    rag._doc_index = {"SWC-107": doc}

    results = rag.search("reentrancy", n_results=10_000)

    assert [result.document.id for result in results] == ["SWC-107"]
    assert collection.query_calls[0]["n_results"] == embedding_rag.MAX_QUERY_RESULTS


def test_batch_search_caps_returned_rows_and_skips_unsafe_ids(tmp_path):
    doc = VulnerabilityDocument(id="SWC-107")
    payload = {
        "ids": [["bad\u2028id", *["SWC-107"] * 150]],
        "distances": [[0.1] * 151],
        "metadatas": [[{}] * 151],
    }
    rag, collection = initialized_rag(tmp_path, payload)
    rag._doc_index = {"SWC-107": doc}

    results = rag.batch_search(["reentrancy"], n_results=10_000)

    assert [result.document.id for result in results[0]] == ["SWC-107"]
    assert collection.query_calls[0]["n_results"] == embedding_rag.MAX_QUERY_RESULTS


def test_embedding_rag_cache_helpers_handle_hostile_cache_access(tmp_path):
    class HostileCache(dict):
        def __getitem__(self, key):
            raise RuntimeError("boom")

        def __setitem__(self, key, value):
            raise RuntimeError("boom")

    rag = EmbeddingRAG(persist_directory=str(tmp_path))
    rag._query_cache = HostileCache({"key": (0.0, [])})
    doc = VulnerabilityDocument(id="DOC-CACHE")
    result = RetrievalResult(document=doc, similarity_score=0.5, relevance_reason="ok")

    assert rag._get_cached_result("key") is None
    rag._cache_result("key", [result])


def test_get_context_for_llm_skips_raising_context_results(tmp_path):
    class RaisingResult:
        def to_context(self):
            raise RuntimeError("boom")

    rag, _collection = initialized_rag(tmp_path)
    doc = VulnerabilityDocument(id="DOC-CTX", title="Safe", description="Description")
    rag.search_by_finding = lambda *_args, **_kwargs: [
        RaisingResult(),
        RetrievalResult(document=doc, similarity_score=0.9, relevance_reason="ok"),
    ]

    context = rag.get_context_for_llm({"type": "reentrancy"})

    assert "Safe" in context
