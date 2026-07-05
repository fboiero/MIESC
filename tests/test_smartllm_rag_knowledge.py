"""
Tests for src.adapters.smartllm_rag_knowledge — the knowledge base
that feeds RAG context to SmartLLM. v5.1.7 coverage push.

Focus: the public knowledge-construction API + contract-type
classifier. Not testing internal _get_*_knowledge() helpers
individually; their output is exercised via get_relevant_knowledge.
"""

from __future__ import annotations

import math
import time

import pytest

import src.llm.embedding_rag as embedding_rag_module
from src.adapters.smartllm_rag_knowledge import (
    _get_account_abstraction_knowledge,
    _get_cross_chain_knowledge,
    _get_intent_knowledge,
    _get_l2_knowledge,
    _get_mev_advanced_knowledge,
    _get_proxy_knowledge,
    _get_restaking_knowledge,
    _get_token_knowledge,
    detect_contract_type,
    get_advanced_knowledge,
    get_all_vulnerability_patterns,
    get_defi_knowledge,
    get_exploit_context,
    get_formal_invariants,
    get_governance_knowledge,
    get_pattern_count,
    get_relevant_knowledge,
    get_vulnerability_context,
)
from src.llm.embedding_rag import EmbeddingRAG, RetrievalResult, VulnerabilityDocument


class _ExplodingCollection:
    def add(self, **_kwargs):
        raise AssertionError("Malformed custom vulnerability should not reach collection.add")


class _ExplodingEmbedder:
    def encode(self, _texts):
        raise AssertionError("Malformed custom vulnerability should not be embedded")


class _UninitializedEmbeddingRAG(EmbeddingRAG):
    def _ensure_initialized(self):
        raise AssertionError("Malformed custom vulnerability should not initialize RAG")


class _MalformedSearchCollection:
    def __init__(self, payload):
        self.payload = payload
        self.query_texts = None
        self.n_results = None
        self.where = "unset"

    def query(self, **kwargs):
        self.query_texts = kwargs["query_texts"]
        self.n_results = kwargs["n_results"]
        self.where = kwargs["where"]
        return self.payload


class _RecordingMultiStepRAG(EmbeddingRAG):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.search_calls = []

    def _ensure_initialized(self):
        self._initialized = True

    def _expand_query(self, query):
        return [query]

    def search(self, query, filter_category=None, filter_severity=None, n_results=None):
        self.search_calls.append((query, filter_category, filter_severity, n_results))
        return []


class _FakeCollectionForInit:
    def __init__(self, metadata, count):
        self.metadata = metadata
        self._count = count

    def count(self):
        return self._count


class _FakeClientForInit:
    def __init__(self, existing_collection):
        self.existing_collection = existing_collection
        self.created_collection = _FakeCollectionForInit(
            {"knowledge_base_version": "created"},
            0,
        )
        self.deleted_names = []
        self.created_metadata = None

    def get_or_create_collection(self, **_kwargs):
        return self.existing_collection

    def delete_collection(self, name):
        self.deleted_names.append(name)

    def create_collection(self, **kwargs):
        self.created_metadata = kwargs["metadata"]
        return self.created_collection


class _FakeChromaForInit:
    def __init__(self, client):
        self.client = client

    def PersistentClient(self, **_kwargs):  # noqa: N802 - mirrors ChromaDB API
        return self.client


class _RecordingInitializeRAG(EmbeddingRAG):
    def __init__(self, *args, existing_collection, **kwargs):
        super().__init__(*args, **kwargs)
        self.fake_client = _FakeClientForInit(existing_collection)
        self.indexed_count = 0

    def _build_doc_index(self):
        self._doc_index = {"existing": object()}

    def _index_knowledge_base(self):
        self.indexed_count += 1


# ---------------------------------------------------------------------------
# detect_contract_type
# ---------------------------------------------------------------------------


class TestDetectContractType:
    @pytest.mark.parametrize(
        "code,expected",
        [
            # DeFi
            (
                "contract Vault { function deposit() external {} function withdraw() external {} }",
                "defi",
            ),
            (
                "contract Pool { function swap() external {} function getreserves() external {} }",
                "defi",
            ),
            (
                "contract Lender { function borrow() external {} function liquidate() external {} }",
                "defi",
            ),
            # Governance
            (
                "contract DAO { function propose() external {} function vote() external {} }",
                "governance",
            ),
            (
                "contract Timelock { function queue() external {} function execute() external {} }",
                "governance",
            ),
            # NFT
            ("contract MyNFT is ERC721 { function mint() external {} }", "nft"),
            ("contract Card is ERC1155 { function safeTransferFrom() external {} }", "nft"),
            # Token
            ("contract Token is ERC20 { function transfer() external {} }", "token"),
            # General fallback
            ("contract Empty { function f() external {} }", "general"),
        ],
    )
    def test_classification(self, code, expected):
        assert detect_contract_type(code) == expected

    def test_empty_code_is_general(self):
        assert detect_contract_type("") == "general"

    def test_case_insensitive_keyword_match(self):
        # uppercase keyword should still match
        assert detect_contract_type("contract X { function PROPOSE() external {} }") == "governance"

    def test_defi_takes_precedence_over_governance(self):
        """If a contract has BOTH defi and governance markers, defi wins (first
        check in the order)."""
        code = "contract X { function swap() external {} function vote() external {} }"
        assert detect_contract_type(code) == "defi"


# ---------------------------------------------------------------------------
# get_relevant_knowledge — top-level dispatcher
# ---------------------------------------------------------------------------


class TestGetRelevantKnowledge:
    def test_returns_string(self):
        result = get_relevant_knowledge("contract C {}")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_defi_contract_includes_defi_section(self):
        defi_code = (
            "contract Pool { function swap() external {} function getreserves() external {} }"
        )
        result = get_relevant_knowledge(defi_code)
        # Should reference DeFi-specific concepts
        assert any(
            kw in result.lower()
            for kw in (
                "defi",
                "swap",
                "oracle",
                "flash",
                "liquidity",
                "pool",
            )
        )

    def test_governance_contract_includes_governance_section(self):
        gov_code = "contract DAO { function propose() external {} function vote() external {} }"
        result = get_relevant_knowledge(gov_code)
        assert any(
            kw in result.lower()
            for kw in (
                "governance",
                "vote",
                "proposal",
                "quorum",
                "timelock",
            )
        )

    def test_returns_general_knowledge_for_simple_contract(self):
        result = get_relevant_knowledge("contract X { uint256 x; }")
        assert isinstance(result, str)
        assert len(result) > 100  # at least basic content


# ---------------------------------------------------------------------------
# get_defi_knowledge / get_governance_knowledge
# ---------------------------------------------------------------------------


class TestSpecializedKnowledge:
    def test_defi_knowledge_contains_patterns(self):
        out = get_defi_knowledge()
        assert isinstance(out, str)
        # Should mention common DeFi vuln categories
        assert any(
            kw in out.lower()
            for kw in (
                "flash",
                "oracle",
                "reentran",
                "manipul",
                "price",
            )
        )

    def test_governance_knowledge_contains_patterns(self):
        out = get_governance_knowledge()
        assert isinstance(out, str)
        assert any(
            kw in out.lower()
            for kw in (
                "vote",
                "proposal",
                "timelock",
                "quorum",
                "delegat",
            )
        )

    def test_advanced_knowledge_returns_content(self):
        out = get_advanced_knowledge()
        assert isinstance(out, str)
        assert len(out) > 100


# ---------------------------------------------------------------------------
# get_vulnerability_context / get_all_vulnerability_patterns
# ---------------------------------------------------------------------------


class TestVulnerabilityContext:
    def test_get_all_returns_dict(self):
        patterns = get_all_vulnerability_patterns()
        assert isinstance(patterns, dict)
        assert len(patterns) > 0

    def test_known_vuln_returns_context(self):
        for vuln in ("reentrancy", "flash_loan", "oracle_manipulation"):
            ctx = get_vulnerability_context(vuln)
            # Either a populated dict or an empty dict (graceful miss)
            assert isinstance(ctx, dict)

    def test_unknown_vuln_returns_dict(self):
        ctx = get_vulnerability_context("totally-fictional-vuln-xyz")
        assert isinstance(ctx, dict)


# ---------------------------------------------------------------------------
# get_exploit_context
# ---------------------------------------------------------------------------


class TestExploitContext:
    def test_returns_list_for_known_vuln(self):
        for vuln in ("reentrancy", "flash_loan"):
            exploits = get_exploit_context(vuln)
            assert isinstance(exploits, list)

    def test_returns_list_for_unknown_vuln(self):
        exploits = get_exploit_context("unknown")
        assert isinstance(exploits, list)


# ---------------------------------------------------------------------------
# get_formal_invariants
# ---------------------------------------------------------------------------


class TestFormalInvariants:
    def test_returns_string(self):
        result = get_formal_invariants()
        assert isinstance(result, str)
        assert len(result) > 50


# ---------------------------------------------------------------------------
# get_pattern_count
# ---------------------------------------------------------------------------


class TestPatternCount:
    def test_returns_dict_with_counts(self):
        counts = get_pattern_count()
        assert isinstance(counts, dict)
        # Should have at least the major categories
        assert len(counts) > 0
        for value in counts.values():
            assert isinstance(value, int)
            assert value >= 0


class TestSpecializedKnowledgeBodies:
    """Each specialized knowledge helper returns a non-empty section."""

    @pytest.mark.parametrize(
        "fn",
        [
            _get_proxy_knowledge,
            _get_cross_chain_knowledge,
            _get_token_knowledge,
            _get_account_abstraction_knowledge,
            _get_restaking_knowledge,
            _get_intent_knowledge,
            _get_l2_knowledge,
            _get_mev_advanced_knowledge,
        ],
    )
    def test_helper_returns_nonempty(self, fn):
        out = fn()
        assert isinstance(out, str)
        assert len(out.strip()) > 0


class TestRelevantKnowledgeDispatch:
    """get_relevant_knowledge appends the right section per contract type."""

    BASELINE = len(get_relevant_knowledge("contract C { uint x; }"))

    @pytest.mark.parametrize(
        "keyword",
        [
            "uups",            # proxy
            "wormhole",        # cross-chain bridge
            "rebase",          # token
            "paymaster",       # account abstraction
            "eigenlayer",      # restaking
            "cowswap",         # intent
            "arbitrum",        # l2
            "flashbot",        # mev
        ],
    )
    def test_keyword_adds_knowledge(self, keyword):
        code = f"contract C {{ /* {keyword} */ uint x; }}"
        out = get_relevant_knowledge(code)
        assert len(out) > self.BASELINE  # a specialized section was appended


class TestEmbeddingRAGCustomVulnerabilityShapes:
    @pytest.mark.parametrize("bad_model", ["", "   ", None, ["bad-model"]])
    def test_malformed_embedding_model_config_uses_default_before_initialization(
        self,
        tmp_path,
        bad_model,
    ):
        rag = EmbeddingRAG(
            persist_directory=str(tmp_path),
            embedding_model=bad_model,  # type: ignore[arg-type]
        )

        assert rag.embedding_model_name == EmbeddingRAG.DEFAULT_MODEL
        assert rag._collection_metadata()["embedding_model"] == EmbeddingRAG.DEFAULT_MODEL
        assert rag._initialized is False

    def test_embedding_model_config_strips_bytes_before_initialization(self, tmp_path):
        rag = EmbeddingRAG(
            persist_directory=str(tmp_path),
            embedding_model=b"  all-mpnet-base-v2  ",  # type: ignore[arg-type]
        )

        assert rag.embedding_model_name == "all-mpnet-base-v2"
        assert rag._collection_metadata()["embedding_model"] == "all-mpnet-base-v2"
        assert rag._initialized is False

    @pytest.mark.parametrize(
        "metadata",
        [
            None,
            [],
            {"knowledge_base_version": ["bad-version"]},
            {"knowledge_base_version": "   "},
        ],
    )
    def test_malformed_collection_metadata_version_reindexes(
        self,
        tmp_path,
        monkeypatch,
        metadata,
    ):
        existing_collection = _FakeCollectionForInit(
            metadata,
            len(embedding_rag_module.VULNERABILITY_KNOWLEDGE_BASE),
        )
        rag = _RecordingInitializeRAG(
            persist_directory=str(tmp_path),
            existing_collection=existing_collection,
        )
        fake_chroma = _FakeChromaForInit(rag.fake_client)

        monkeypatch.setattr(
            embedding_rag_module,
            "_get_sentence_transformer",
            lambda: lambda _model_name: object(),
        )
        monkeypatch.setattr(
            embedding_rag_module,
            "_get_chromadb",
            lambda: fake_chroma,
        )

        rag._ensure_initialized()

        assert rag.fake_client.deleted_names == [EmbeddingRAG.COLLECTION_NAME]
        assert (
            rag.fake_client.created_metadata["knowledge_base_version"]
            == embedding_rag_module.KNOWLEDGE_BASE_VERSION
        )
        assert rag._collection is rag.fake_client.created_collection
        assert rag.indexed_count == 1
        assert rag._initialized is True

    def test_rejects_non_document_before_index_or_cache_mutation(self, tmp_path):
        rag = _UninitializedEmbeddingRAG(persist_directory=str(tmp_path))
        rag._embedder = _ExplodingEmbedder()
        rag._collection = _ExplodingCollection()
        rag._doc_index = {"existing": object()}
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_hits = 2
        rag._cache_misses = 3

        with pytest.raises(TypeError, match="VulnerabilityDocument"):
            rag.add_custom_vulnerability({"id": "CUSTOM-001"})  # type: ignore[arg-type]

        assert list(rag._doc_index) == ["existing"]
        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_hits == 2
        assert rag._cache_misses == 3

    def test_malformed_tags_and_references_render_as_text_and_metadata(self):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-001",
            title="Custom Finding",
            description="Custom vulnerability description",
            tags=["custom", 123, None],
            references="https://example.invalid/advisory",
        )

        text = vulnerability.to_text()
        metadata = vulnerability.to_metadata()

        assert "Tags: custom, 123" in text
        assert "References: https://example.invalid/advisory" in text
        assert metadata["tags"] == "custom,123"
        assert metadata["references"] == "https://example.invalid/advisory"

    def test_scalar_tags_and_malformed_references_do_not_break_context_or_ranking(
        self,
        tmp_path,
    ):
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-002",
            title="Scalar Tags",
            description="Custom vulnerability description",
            category="custom",
            tags=42,  # type: ignore[arg-type]
            references=["https://one.invalid", 7, None, "https://four.invalid"],
        )
        result = RetrievalResult(
            document=vulnerability,
            similarity_score=0.5,
            relevance_reason="test",
        )

        context = result.to_context()
        ranked = rag._rank_result(result, original_query="custom 42", step="test")

        assert "- References: https://one.invalid, 7, https://four.invalid" in context
        assert ranked.similarity_score > result.similarity_score

    @pytest.mark.parametrize("bad_id", ["", "   ", ["CUSTOM-001"]])
    def test_rejects_malformed_document_id_before_index_or_cache_mutation(
        self,
        tmp_path,
        bad_id,
    ):
        rag = _UninitializedEmbeddingRAG(persist_directory=str(tmp_path))
        rag._embedder = _ExplodingEmbedder()
        rag._collection = _ExplodingCollection()
        rag._doc_index = {"existing": object()}
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_hits = 2
        rag._cache_misses = 3
        vulnerability = VulnerabilityDocument(
            id=bad_id,  # type: ignore[arg-type]
            title="Custom Finding",
            description="Custom vulnerability description",
        )

        with pytest.raises(ValueError, match="non-empty string"):
            rag.add_custom_vulnerability(vulnerability)

        assert list(rag._doc_index) == ["existing"]
        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_hits == 2
        assert rag._cache_misses == 3


class TestEmbeddingRAGSearchBoundaryShapes:
    def test_search_coerces_query_and_bounds_malformed_similarity_metadata(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-003",
            title="Malformed Similarity Boundary",
            description="Custom vulnerability description",
            category="custom",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-003", ["bad-id"], "missing-doc"]],
                "distances": [["not-a-number", -0.25, 3.0]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-003": vulnerability}

        results = rag.search(["custom"], n_results=3)  # type: ignore[arg-type]

        assert collection.query_texts == ["['custom']"]
        assert [result.document.id for result in results] == ["CUSTOM-003"]
        assert 0.0 <= results[0].similarity_score < 0.3
        assert results[0].relevance_reason == "Matches category: custom"

    def test_search_bounds_non_finite_and_negative_distances(self, tmp_path):
        documents = {
            doc_id: VulnerabilityDocument(
                id=doc_id,
                title=doc_id,
                description="Custom vulnerability description",
            )
            for doc_id in (
                "CUSTOM-NAN",
                "CUSTOM-POS-INF",
                "CUSTOM-NEG-INF",
                "CUSTOM-NEGATIVE-DISTANCE",
            )
        }
        collection = _MalformedSearchCollection(
            {
                "ids": [list(documents)],
                "distances": [[float("nan"), float("inf"), float("-inf"), -0.25]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = documents

        results = rag.search("distance boundary", n_results=4)
        scores_by_id = {result.document.id: result.similarity_score for result in results}

        assert set(scores_by_id) == set(documents)
        assert all(math.isfinite(score) for score in scores_by_id.values())
        assert all(0.0 <= score <= 1.0 for score in scores_by_id.values())
        assert scores_by_id["CUSTOM-NEG-INF"] < 0.3
        assert scores_by_id["CUSTOM-NEGATIVE-DISTANCE"] > 0.9

    @pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf"), -0.5])
    def test_rank_result_bounds_non_finite_and_negative_scores(self, tmp_path, score):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-SCORE",
            title="Malformed Score Boundary",
            description="Custom vulnerability description",
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        result = RetrievalResult(
            document=vulnerability,
            similarity_score=score,
            relevance_reason="test",
        )

        ranked = rag._rank_result(result, original_query="score boundary")

        assert math.isfinite(ranked.similarity_score)
        assert 0.0 <= ranked.similarity_score <= 1.0
        assert ranked.similarity_score < 0.3

    def test_search_skips_ids_without_aligned_document_and_metadata_rows(self, tmp_path):
        valid = VulnerabilityDocument(
            id="CUSTOM-ALIGNED",
            title="Aligned Result",
            description="Custom vulnerability description",
        )
        missing_document = VulnerabilityDocument(
            id="CUSTOM-MISSING-DOCUMENT",
            title="Missing Document Row",
            description="Custom vulnerability description",
        )
        missing_metadata = VulnerabilityDocument(
            id="CUSTOM-MISSING-METADATA",
            title="Missing Metadata Row",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [
                    [
                        "CUSTOM-ALIGNED",
                        "CUSTOM-MISSING-DOCUMENT",
                        "CUSTOM-MISSING-METADATA",
                    ]
                ],
                "documents": [["aligned text", "metadata-only text"]],
                "metadatas": [[{"id": "CUSTOM-ALIGNED"}]],
                "distances": [[0.2, 0.1, 0.0]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {
            "CUSTOM-ALIGNED": valid,
            "CUSTOM-MISSING-DOCUMENT": missing_document,
            "CUSTOM-MISSING-METADATA": missing_metadata,
        }

        results = rag.search("aligned", n_results=3)

        assert [result.document.id for result in results] == ["CUSTOM-ALIGNED"]

    def test_search_bounds_malformed_result_count_and_filter_values(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-COUNT",
            title="Malformed Count Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-COUNT"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), top_k=2)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-COUNT": vulnerability}

        results = rag.search(
            "count boundary",
            filter_category=["bad"],  # type: ignore[arg-type]
            filter_severity={"bad": "filter"},  # type: ignore[arg-type]
            n_results={"bad": "count"},  # type: ignore[arg-type]
        )

        assert collection.n_results == 2
        assert collection.where is None
        assert [result.document.id for result in results] == ["CUSTOM-COUNT"]

    def test_multi_step_search_normalizes_count_and_filters_before_expansion(self, tmp_path):
        rag = _RecordingMultiStepRAG(persist_directory=str(tmp_path), top_k="bad")  # type: ignore[arg-type]

        results = rag.multi_step_search(
            b"count boundary",
            filter_category=["bad"],  # type: ignore[arg-type]
            filter_severity=b" high ",
            n_results=False,  # type: ignore[arg-type]
        )

        assert results == []
        assert rag.search_calls == [("count boundary", None, "high", 10)]

    @pytest.mark.parametrize(
        "queries",
        [
            "single query",
            b"single query",
            {"query": "mapping"},
            {"query"},
            42,
            None,
        ],
    )
    def test_batch_search_rejects_malformed_query_containers_before_initialization(
        self,
        tmp_path,
        queries,
    ):
        rag = _UninitializedEmbeddingRAG(persist_directory=str(tmp_path))
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_hits = 2
        rag._cache_misses = 3

        results = rag.batch_search(queries)  # type: ignore[arg-type]

        assert results == []
        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_hits == 2
        assert rag._cache_misses == 3

    def test_batch_search_skips_malformed_result_rows_and_query_values(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-004",
            title="Batch Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-004"], "bad-row"],
                "distances": [[0.2], [0.1]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-004": vulnerability}

        results = rag.batch_search([b"batch", {"q": "bad"}], n_results=2)  # type: ignore[list-item]

        assert collection.query_texts == ["batch", "{'q': 'bad'}"]
        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-004"],
            [],
        ]

    def test_batch_search_skips_present_malformed_document_metadata_rows(self, tmp_path):
        first = VulnerabilityDocument(
            id="CUSTOM-BATCH-ALIGNED",
            title="Batch Aligned",
            description="Custom vulnerability description",
        )
        second = VulnerabilityDocument(
            id="CUSTOM-BATCH-SKIPPED",
            title="Batch Skipped",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-BATCH-ALIGNED"], ["CUSTOM-BATCH-SKIPPED"]],
                "documents": [["aligned text"], "bad-row"],
                "metadatas": [[{"id": "CUSTOM-BATCH-ALIGNED"}], []],
                "distances": [[0.2], [0.1]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {
            "CUSTOM-BATCH-ALIGNED": first,
            "CUSTOM-BATCH-SKIPPED": second,
        }

        results = rag.batch_search(["first", "second"], n_results=1)

        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-ALIGNED"],
            [],
        ]

    def test_batch_search_discards_malformed_cached_result_and_queries_collection(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-005",
            title="Malformed Cache Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-005"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-005": vulnerability}
        cache_key = rag._get_cache_key("batch", None, None, 1)
        rag._query_cache = {cache_key: (9999999999.0, ["not-a-retrieval-result"])}

        results = rag.batch_search(["batch"], n_results=1)

        assert collection.query_texts == ["batch"]
        assert [[result.document.id for result in row] for row in results] == [["CUSTOM-005"]]
        assert rag._cache_hits == 0
        assert rag._cache_misses == 1

    @pytest.mark.parametrize(
        "cache_key,results",
        [
            ("custom", "not-a-list"),
            ("custom", ["not-a-retrieval-result"]),
            (["bad-key"], []),
        ],
    )
    def test_cache_result_rejects_malformed_storage_payloads(
        self,
        tmp_path,
        cache_key,
        results,
    ):
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_misses = 3

        rag._cache_result(cache_key, results)  # type: ignore[arg-type]

        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_misses == 3

    def test_cache_key_normalizes_malformed_direct_inputs(self, tmp_path):
        rag = EmbeddingRAG(persist_directory=str(tmp_path), top_k=2)

        cache_key = rag._get_cache_key(
            {"query": "oracle"},  # type: ignore[arg-type]
            ["bad-category"],  # type: ignore[arg-type]
            b" high ",
            {"bad": "count"},  # type: ignore[arg-type]
            strategy=None,  # type: ignore[arg-type]
        )
        expected = rag._get_cache_key(
            "{'query': 'oracle'}",
            None,
            "high",
            2,
            strategy="semantic",
        )

        assert cache_key == expected

    def test_cached_result_ignores_malformed_cache_key_without_mutating_cache(self, tmp_path):
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_hits = 2

        cached = rag._get_cached_result(["bad-key"])  # type: ignore[arg-type]

        assert cached is None
        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_hits == 2

    def test_cached_result_uses_default_ttl_when_class_ttl_is_malformed(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-TTL",
            title="TTL Boundary",
            description="Custom vulnerability description",
        )
        result = RetrievalResult(
            document=vulnerability,
            similarity_score=0.5,
            relevance_reason="test",
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        cache_key = rag._get_cache_key("ttl boundary", None, None, 1)
        cached_at = time.time()
        rag._query_cache = {cache_key: (cached_at, [result])}
        rag.CACHE_TTL_SECONDS = {"bad": "ttl"}  # type: ignore[assignment]

        cached = rag._get_cached_result(cache_key)

        assert cached == [result]
        assert rag._query_cache == {cache_key: (cached_at, [result])}
        assert rag._cache_hits == 1
