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
from src.llm.embedding_rag import EmbeddingRAG, HybridRAG, RetrievalResult, VulnerabilityDocument


class _ExplodingCollection:
    def add(self, **_kwargs):
        raise AssertionError("Malformed custom vulnerability should not reach collection.add")


class _ExplodingEmbedder:
    def encode(self, _texts):
        raise AssertionError("Malformed custom vulnerability should not be embedded")


class _ListEmbedding:
    def __init__(self, values):
        self.values = values

    def tolist(self):
        return self.values


class _RecordingEmbedder:
    def __init__(self):
        self.documents = None

    def encode(self, documents, **_kwargs):
        self.documents = documents
        return _ListEmbedding([[0.1, 0.2] for _ in documents])


class _StaticEmbeddingEmbedder:
    def __init__(self, values):
        self.values = values
        self.documents = None

    def encode(self, documents, **_kwargs):
        self.documents = documents
        return _ListEmbedding(self.values)


class _RecordingIndexCollection:
    def __init__(self):
        self.add_payload = None

    def add(self, **kwargs):
        self.add_payload = kwargs


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
        self.get_or_create_name = None
        self.deleted_names = []
        self.created_name = None
        self.created_metadata = None

    def get_or_create_collection(self, **kwargs):
        self.get_or_create_name = kwargs["name"]
        return self.existing_collection

    def delete_collection(self, name):
        self.deleted_names.append(name)

    def create_collection(self, **kwargs):
        self.created_name = kwargs["name"]
        self.created_metadata = kwargs["metadata"]
        return self.created_collection


class _FakeChromaForInit:
    def __init__(self, client):
        self.client = client
        self.persistent_path = None

    def PersistentClient(self, **kwargs):  # noqa: N802 - mirrors ChromaDB API
        self.persistent_path = kwargs["path"]
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


class _ExplodingStringValue:
    def __str__(self):
        raise AssertionError("Malformed cache query should not be stringified")


class _ExplodingFloatValue:
    def __float__(self):
        raise RuntimeError("Malformed distance should not abort result conversion")


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
    @pytest.mark.parametrize(
        "bad_directory",
        [
            "",
            "   ",
            "bad\x00path",
            ["not-a-path"],
        ],
    )
    def test_malformed_persist_directory_uses_default_path(
        self,
        tmp_path,
        monkeypatch,
        bad_directory,
    ):
        fallback = tmp_path / "fallback" / "chromadb"
        monkeypatch.setattr(
            embedding_rag_module,
            "_default_persist_directory",
            lambda: fallback,
        )

        rag = EmbeddingRAG(persist_directory=bad_directory)  # type: ignore[arg-type]

        assert rag.persist_dir == fallback
        assert rag.persist_dir.is_dir()
        assert rag._initialized is False

    def test_file_persist_directory_falls_back_before_chroma_initialization(
        self,
        tmp_path,
        monkeypatch,
    ):
        fallback = tmp_path / "fallback" / "chromadb"
        malformed_file = tmp_path / "not-a-directory"
        malformed_file.write_text("not a directory", encoding="utf-8")
        monkeypatch.setattr(
            embedding_rag_module,
            "_default_persist_directory",
            lambda: fallback,
        )
        existing_collection = _FakeCollectionForInit(
            {"knowledge_base_version": embedding_rag_module.KNOWLEDGE_BASE_VERSION},
            len(embedding_rag_module.VULNERABILITY_KNOWLEDGE_BASE),
        )
        rag = _RecordingInitializeRAG(
            persist_directory=str(malformed_file),
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

        assert rag.persist_dir == fallback
        assert fake_chroma.persistent_path == str(fallback)
        assert "\x00" not in fake_chroma.persistent_path
        assert rag._initialized is True

    def test_bytes_persist_directory_is_decoded_and_stripped(self, tmp_path):
        persist_dir = tmp_path / "byte-path"

        rag = EmbeddingRAG(
            persist_directory=f"  {persist_dir}  ".encode(),  # type: ignore[arg-type]
        )

        assert rag.persist_dir == persist_dir
        assert rag.persist_dir.is_dir()

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
        assert rag.fake_client.created_name == EmbeddingRAG.COLLECTION_NAME
        assert (
            rag.fake_client.created_metadata["knowledge_base_version"]
            == embedding_rag_module.KNOWLEDGE_BASE_VERSION
        )
        assert rag._collection is rag.fake_client.created_collection
        assert rag.indexed_count == 1
        assert rag._initialized is True

    @pytest.mark.parametrize(
        "bad_name",
        [
            "",
            "  ",
            "bad/name",
            "bad\nname",
            "ab",
            "a" * 64,
            ["bad-name"],
        ],
    )
    def test_malformed_collection_name_uses_default_namespace(
        self,
        tmp_path,
        monkeypatch,
        bad_name,
    ):
        existing_collection = _FakeCollectionForInit(
            {"knowledge_base_version": embedding_rag_module.KNOWLEDGE_BASE_VERSION},
            len(embedding_rag_module.VULNERABILITY_KNOWLEDGE_BASE),
        )
        rag = _RecordingInitializeRAG(
            persist_directory=str(tmp_path),
            existing_collection=existing_collection,
        )
        fake_chroma = _FakeChromaForInit(rag.fake_client)

        monkeypatch.setattr(EmbeddingRAG, "COLLECTION_NAME", bad_name)
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

        assert rag.fake_client.get_or_create_name == embedding_rag_module.DEFAULT_COLLECTION_NAME
        assert rag.fake_client.deleted_names == []
        assert rag.fake_client.created_name is None
        assert rag.indexed_count == 0
        assert rag._initialized is True

    def test_collection_name_strips_valid_bytes_namespace(self, tmp_path, monkeypatch):
        existing_collection = _FakeCollectionForInit(
            {"knowledge_base_version": embedding_rag_module.KNOWLEDGE_BASE_VERSION},
            len(embedding_rag_module.VULNERABILITY_KNOWLEDGE_BASE),
        )
        rag = _RecordingInitializeRAG(
            persist_directory=str(tmp_path),
            existing_collection=existing_collection,
        )
        fake_chroma = _FakeChromaForInit(rag.fake_client)

        monkeypatch.setattr(EmbeddingRAG, "COLLECTION_NAME", b"  custom_namespace  ")
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

        assert rag.fake_client.get_or_create_name == "custom_namespace"
        assert rag._initialized is True

    def test_reindex_uses_default_namespace_for_malformed_collection_name(
        self,
        tmp_path,
        monkeypatch,
    ):
        existing_collection = _FakeCollectionForInit(
            {"knowledge_base_version": embedding_rag_module.KNOWLEDGE_BASE_VERSION},
            len(embedding_rag_module.VULNERABILITY_KNOWLEDGE_BASE),
        )
        rag = _RecordingInitializeRAG(
            persist_directory=str(tmp_path),
            existing_collection=existing_collection,
        )
        rag._initialized = True
        rag._client = rag.fake_client
        rag._collection = existing_collection

        monkeypatch.setattr(EmbeddingRAG, "COLLECTION_NAME", "../bad")

        rag.reindex()

        assert rag.fake_client.deleted_names == [embedding_rag_module.DEFAULT_COLLECTION_NAME]
        assert rag.fake_client.created_name == embedding_rag_module.DEFAULT_COLLECTION_NAME
        assert rag.indexed_count == 1

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

    def test_nested_metadata_list_tags_are_skipped_in_text_and_metadata(self):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-TAG-LIST-BOUNDARY",
            title="Custom Finding",
            description="Custom vulnerability description",
            tags=["custom", ["nested", "tag"], {"bad": "tag"}, b"bytes-tag"],
            references=["https://example.invalid/advisory", ["nested-ref"]],
        )

        text = vulnerability.to_text()
        metadata = vulnerability.to_metadata()

        assert "Tags: custom, bytes-tag" in text
        assert "nested" not in text
        assert "{'bad': 'tag'}" not in text
        assert metadata["tags"] == "custom,bytes-tag"
        assert metadata["references"] == "https://example.invalid/advisory"

    def test_malformed_document_text_fields_do_not_abort_rendering(self):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-TEXT-BOUNDARY",
            title=_ExplodingStringValue(),  # type: ignore[arg-type]
            description=_ExplodingStringValue(),  # type: ignore[arg-type]
            vulnerable_code=_ExplodingStringValue(),  # type: ignore[arg-type]
            fixed_code=b"fixed bytes",
            attack_scenario=_ExplodingStringValue(),  # type: ignore[arg-type]
            tags=["custom", _ExplodingStringValue()],
            references=[_ExplodingStringValue(), b"https://example.invalid/ref"],
        )

        text = vulnerability.to_text()

        assert "Title: " in text
        assert "Description: " in text
        assert "Vulnerable Code Pattern" not in text
        assert "Fixed Code Pattern:\nfixed bytes" in text
        assert "Attack Scenario:" not in text
        assert "Tags: custom" in text
        assert "References: https://example.invalid/ref" in text

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

    def test_malformed_knowledge_base_document_is_skipped_in_index_payloads(
        self,
        tmp_path,
        monkeypatch,
    ):
        valid = VulnerabilityDocument(
            id="CUSTOM-VALID",
            title="Valid Custom Finding",
            description="Custom vulnerability description",
        )
        invalid_id = VulnerabilityDocument(
            id=["bad-id"],  # type: ignore[arg-type]
            title="Invalid Custom Finding",
            description="Custom vulnerability description",
        )
        collection = _RecordingIndexCollection()
        embedder = _RecordingEmbedder()
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._collection = collection
        rag._embedder = embedder

        monkeypatch.setattr(
            embedding_rag_module,
            "VULNERABILITY_KNOWLEDGE_BASE",
            [valid, {"not": "a-document"}, invalid_id],
        )

        rag._build_doc_index()
        rag._index_knowledge_base()

        assert rag._doc_index == {"CUSTOM-VALID": valid}
        assert embedder.documents == [valid.to_text()]
        assert collection.add_payload["ids"] == ["CUSTOM-VALID"]
        assert collection.add_payload["metadatas"] == [valid.to_metadata()]

    def test_malformed_embedding_vectors_are_skipped_in_index_payloads(
        self,
        tmp_path,
        monkeypatch,
    ):
        valid = VulnerabilityDocument(
            id="CUSTOM-VECTOR-VALID",
            title="Valid Vector",
            description="Custom vulnerability description",
        )
        bad_nan = VulnerabilityDocument(
            id="CUSTOM-VECTOR-NAN",
            title="NaN Vector",
            description="Custom vulnerability description",
        )
        bad_text = VulnerabilityDocument(
            id="CUSTOM-VECTOR-TEXT",
            title="Text Vector",
            description="Custom vulnerability description",
        )
        collection = _RecordingIndexCollection()
        embedder = _StaticEmbeddingEmbedder(
            [
                [0.1, "0.2"],
                [0.3, float("nan")],
                [0.4, "not-a-number"],
            ]
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._collection = collection
        rag._embedder = embedder

        monkeypatch.setattr(
            embedding_rag_module,
            "VULNERABILITY_KNOWLEDGE_BASE",
            [valid, bad_nan, bad_text],
        )

        rag._index_knowledge_base()

        assert embedder.documents == [valid.to_text(), bad_nan.to_text(), bad_text.to_text()]
        assert collection.add_payload["ids"] == ["CUSTOM-VECTOR-VALID"]
        assert collection.add_payload["embeddings"] == [[0.1, 0.2]]
        assert collection.add_payload["documents"] == [valid.to_text()]

    def test_custom_vulnerability_rejects_malformed_embedding_vector_before_mutation(
        self,
        tmp_path,
    ):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-BAD-VECTOR",
            title="Malformed Embedding Vector",
            description="Custom vulnerability description",
        )
        collection = _RecordingIndexCollection()
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._embedder = _StaticEmbeddingEmbedder([[0.1, float("inf")]])
        rag._doc_index = {"existing": vulnerability}
        rag._query_cache = {"stale": (0.0, [])}
        rag._cache_hits = 2
        rag._cache_misses = 3

        with pytest.raises(ValueError, match="finite numeric vector"):
            rag.add_custom_vulnerability(vulnerability)

        assert collection.add_payload is None
        assert rag._doc_index == {"existing": vulnerability}
        assert rag._query_cache == {"stale": (0.0, [])}
        assert rag._cache_hits == 2
        assert rag._cache_misses == 3


class TestEmbeddingRAGSearchBoundaryShapes:
    def test_search_empties_malformed_query_and_bounds_malformed_similarity_metadata(self, tmp_path):
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

        # Hardened contract: a malformed (non-str) query is emptied, not stringified,
        # so no attacker-controlled structure reaches the vector search.
        assert collection.query_texts == [""]
        assert [result.document.id for result in results] == ["CUSTOM-003"]
        assert 0.0 <= results[0].similarity_score < 0.3
        # Emptied query cannot category-match, so ranking falls back to semantic similarity.
        assert results[0].relevance_reason == "Semantic similarity match"

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

    def test_search_bounds_malformed_distance_score_objects(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-BAD-DISTANCE",
            title="Malformed Distance Object Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-BAD-DISTANCE"]],
                "distances": [[_ExplodingFloatValue()]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-BAD-DISTANCE": vulnerability}

        results = rag.search("distance score boundary", n_results=1)

        assert [result.document.id for result in results] == ["CUSTOM-BAD-DISTANCE"]
        assert math.isfinite(results[0].similarity_score)
        assert 0.0 <= results[0].similarity_score < 0.3

    def test_search_bounds_optional_similarity_rows_when_distance_missing(self, tmp_path):
        documents = {
            doc_id: VulnerabilityDocument(
                id=doc_id,
                title=doc_id,
                description="Custom vulnerability description",
            )
            for doc_id in (
                "CUSTOM-SIMILARITY-VALID",
                "CUSTOM-SIMILARITY-HIGH",
                "CUSTOM-SIMILARITY-BAD",
            )
        }
        collection = _MalformedSearchCollection(
            {
                "ids": [list(documents)],
                "similarities": [[0.75, 3.0, _ExplodingFloatValue()]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = documents

        results = rag.search("similarity row boundary", n_results=3)
        scores_by_id = {result.document.id: result.similarity_score for result in results}

        assert set(scores_by_id) == set(documents)
        assert scores_by_id["CUSTOM-SIMILARITY-VALID"] > 0.7
        assert scores_by_id["CUSTOM-SIMILARITY-HIGH"] > scores_by_id[
            "CUSTOM-SIMILARITY-VALID"
        ]
        assert scores_by_id["CUSTOM-SIMILARITY-BAD"] < 0.3
        assert all(math.isfinite(score) for score in scores_by_id.values())

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

    def test_search_skips_present_malformed_metadata_values(self, tmp_path):
        valid = VulnerabilityDocument(
            id="CUSTOM-METADATA-ALIGNED",
            title="Aligned Metadata",
            description="Custom vulnerability description",
        )
        malformed = VulnerabilityDocument(
            id="CUSTOM-METADATA-MALFORMED",
            title="Malformed Metadata",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-METADATA-ALIGNED", "CUSTOM-METADATA-MALFORMED"]],
                "documents": [["aligned text", "malformed metadata text"]],
                "metadatas": [[{"id": "CUSTOM-METADATA-ALIGNED"}, ["bad-metadata"]]],
                "distances": [[0.2, 0.1]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {
            "CUSTOM-METADATA-ALIGNED": valid,
            "CUSTOM-METADATA-MALFORMED": malformed,
        }

        results = rag.search("metadata boundary", n_results=2)

        assert [result.document.id for result in results] == ["CUSTOM-METADATA-ALIGNED"]

    def test_search_skips_blank_result_ids(self, tmp_path):
        valid = VulnerabilityDocument(
            id="CUSTOM-ID-VALID",
            title="Valid Result ID",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["", "   ", "CUSTOM-ID-VALID"]],
                "documents": [["empty id text", "blank id text", "valid id text"]],
                "metadatas": [[{"id": ""}, {"id": "   "}, {"id": "CUSTOM-ID-VALID"}]],
                "distances": [[0.0, 0.0, 0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-ID-VALID": valid}

        results = rag.search("result id boundary", n_results=3)

        assert [result.document.id for result in results] == ["CUSTOM-ID-VALID"]

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

    def test_search_ignores_control_char_result_counts(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-COUNT-TEXT",
            title="Malformed Count Text Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-COUNT-TEXT"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), top_k=2)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-COUNT-TEXT": vulnerability}

        results = rag.search("count boundary", n_results="2\n")

        assert collection.n_results == 2
        assert [result.document.id for result in results] == ["CUSTOM-COUNT-TEXT"]

    def test_coerce_embedding_model_name_rejects_control_chars(self):
        assert embedding_rag_module._coerce_embedding_model_name("  custom-model  ") == "custom-model"
        assert (
            embedding_rag_module._coerce_embedding_model_name("custom\nmodel")
            == EmbeddingRAG.DEFAULT_MODEL
        )

    def test_coerce_cache_ttl_seconds_rejects_control_chars(self):
        assert embedding_rag_module._coerce_cache_ttl_seconds("3600") == 3600
        assert (
            embedding_rag_module._coerce_cache_ttl_seconds("3600\n")
            == EmbeddingRAG.DEFAULT_CACHE_TTL_SECONDS
        )

    def test_coerce_filter_text_rejects_control_chars(self):
        assert embedding_rag_module._coerce_filter_text("  filter text  ") == "filter text"
        assert embedding_rag_module._coerce_filter_text("filter\ntext") is None

    def test_search_drops_malformed_metadata_filter_builder_output(
        self,
        tmp_path,
        monkeypatch,
    ):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-FILTER",
            title="Malformed Filter Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-FILTER"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-FILTER": vulnerability}
        monkeypatch.setattr(
            embedding_rag_module,
            "build_metadata_filter",
            lambda _category, _severity: ["bad-filter"],
        )

        results = rag.search(
            "filter boundary",
            filter_category="custom",
            filter_severity="medium",
            n_results=1,
        )

        assert collection.where is None
        assert [result.document.id for result in results] == ["CUSTOM-FILTER"]

    def test_batch_search_drops_raising_metadata_filter_builder(self, tmp_path, monkeypatch):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-BATCH-FILTER",
            title="Malformed Batch Filter Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-BATCH-FILTER"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-BATCH-FILTER": vulnerability}

        def raise_filter_error(_category, _severity):
            raise TypeError("malformed filter")

        monkeypatch.setattr(embedding_rag_module, "build_metadata_filter", raise_filter_error)

        results = rag.batch_search(
            ["filter boundary"],
            filter_category="custom",
            filter_severity="medium",
            n_results=1,
        )

        assert collection.where is None
        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-FILTER"]
        ]

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

        # Hardened contract: bytes decode to text, but a dict query value is dropped.
        assert collection.query_texts == ["batch"]
        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-004"],
            [],
        ]

    def test_batch_search_skips_unstringifiable_query_entries(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-BATCH-QUERY",
            title="Batch Query Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-BATCH-QUERY"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-BATCH-QUERY": vulnerability}

        results = rag.batch_search(
            ["batch", _ExplodingStringValue()],
            n_results=1,
        )

        assert collection.query_texts == ["batch"]
        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-QUERY"],
            [],
        ]

    def test_batch_search_bounds_malformed_distance_score_objects(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-BATCH-BAD-DISTANCE",
            title="Batch Malformed Distance Boundary",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-BATCH-BAD-DISTANCE"]],
                "distances": [[_ExplodingFloatValue()]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-BATCH-BAD-DISTANCE": vulnerability}

        results = rag.batch_search(["distance score boundary"], n_results=1)

        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-BAD-DISTANCE"]
        ]
        assert math.isfinite(results[0][0].similarity_score)
        assert 0.0 <= results[0][0].similarity_score < 0.3

    def test_batch_search_bounds_optional_similarity_rows_when_distance_missing(
        self,
        tmp_path,
    ):
        documents = {
            doc_id: VulnerabilityDocument(
                id=doc_id,
                title=doc_id,
                description="Custom vulnerability description",
            )
            for doc_id in (
                "CUSTOM-BATCH-SIMILARITY-VALID",
                "CUSTOM-BATCH-SIMILARITY-BAD",
            )
        }
        collection = _MalformedSearchCollection(
            {
                "ids": [list(documents)],
                "similarities": [[0.8, _ExplodingFloatValue()]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = documents

        results = rag.batch_search(["batch similarity row boundary"], n_results=2)
        scores_by_id = {
            result.document.id: result.similarity_score for result in results[0]
        }

        assert set(scores_by_id) == set(documents)
        assert scores_by_id["CUSTOM-BATCH-SIMILARITY-VALID"] > 0.75
        assert scores_by_id["CUSTOM-BATCH-SIMILARITY-BAD"] < 0.3
        assert all(math.isfinite(score) for score in scores_by_id.values())

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

    def test_batch_search_skips_present_malformed_metadata_values(self, tmp_path):
        valid = VulnerabilityDocument(
            id="CUSTOM-BATCH-METADATA-ALIGNED",
            title="Batch Aligned Metadata",
            description="Custom vulnerability description",
        )
        malformed = VulnerabilityDocument(
            id="CUSTOM-BATCH-METADATA-MALFORMED",
            title="Batch Malformed Metadata",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [
                    [
                        "CUSTOM-BATCH-METADATA-ALIGNED",
                        "CUSTOM-BATCH-METADATA-MALFORMED",
                    ]
                ],
                "documents": [["aligned text", "malformed metadata text"]],
                "metadatas": [[{"id": "CUSTOM-BATCH-METADATA-ALIGNED"}, "bad-metadata"]],
                "distances": [[0.2, 0.1]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {
            "CUSTOM-BATCH-METADATA-ALIGNED": valid,
            "CUSTOM-BATCH-METADATA-MALFORMED": malformed,
        }

        results = rag.batch_search(["metadata boundary"], n_results=2)

        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-METADATA-ALIGNED"]
        ]

    def test_batch_search_skips_blank_result_ids(self, tmp_path):
        valid = VulnerabilityDocument(
            id="CUSTOM-BATCH-ID-VALID",
            title="Valid Batch Result ID",
            description="Custom vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["", "   ", "CUSTOM-BATCH-ID-VALID"]],
                "documents": [["empty id text", "blank id text", "valid id text"]],
                "metadatas": [[{"id": ""}, {"id": "   "}, {"id": "CUSTOM-BATCH-ID-VALID"}]],
                "distances": [[0.0, 0.0, 0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path), enable_cache=False)
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-BATCH-ID-VALID": valid}

        results = rag.batch_search(["result id boundary"], n_results=3)

        assert [[result.document.id for result in row] for row in results] == [
            ["CUSTOM-BATCH-ID-VALID"]
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

    def test_cache_key_bounds_malformed_direct_query_inputs(self, tmp_path):
        rag = EmbeddingRAG(persist_directory=str(tmp_path), top_k=2)

        cache_key = rag._get_cache_key(
            _ExplodingStringValue(),  # type: ignore[arg-type]
            ["bad-category"],  # type: ignore[arg-type]
            b" high ",
            {"bad": "count"},  # type: ignore[arg-type]
            strategy=None,  # type: ignore[arg-type]
        )
        expected = rag._get_cache_key(
            "",
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

    def test_cached_result_evicts_invalid_cached_row_type(self, tmp_path):
        vulnerability = VulnerabilityDocument(
            id="CUSTOM-CACHE-ROW",
            title="Cache Row Boundary",
            description="Custom vulnerability description",
        )
        result = RetrievalResult(
            document=vulnerability,
            similarity_score=0.5,
            relevance_reason="test",
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        cache_key = rag._get_cache_key("row boundary", None, None, 1)
        rag._query_cache = {cache_key: [time.time(), [result]]}  # type: ignore[dict-item]
        rag._cache_hits = 2

        cached = rag._get_cached_result(cache_key)

        assert cached is None
        assert rag._query_cache == {}
        assert rag._cache_hits == 2

    def test_search_evicts_stale_cached_result_and_queries_collection(self, tmp_path):
        stale = VulnerabilityDocument(
            id="CUSTOM-STALE-CACHED",
            title="Stale Cached",
            description="Cached vulnerability description",
        )
        fresh = VulnerabilityDocument(
            id="CUSTOM-FRESH-RESULT",
            title="Fresh Result",
            description="Fresh vulnerability description",
        )
        collection = _MalformedSearchCollection(
            {
                "ids": [["CUSTOM-FRESH-RESULT"]],
                "distances": [[0.2]],
            }
        )
        rag = EmbeddingRAG(persist_directory=str(tmp_path))
        rag._initialized = True
        rag._collection = collection
        rag._doc_index = {"CUSTOM-FRESH-RESULT": fresh}
        cache_key = rag._get_cache_key("stale boundary", None, None, 1)
        rag._query_cache = {
            cache_key: (
                time.time() - EmbeddingRAG.DEFAULT_CACHE_TTL_SECONDS - 1,
                [
                    RetrievalResult(
                        document=stale,
                        similarity_score=1.0,
                        relevance_reason="stale",
                    )
                ],
            )
        }

        results = rag.search("stale boundary", n_results=1)

        assert collection.query_texts == ["stale boundary"]
        assert [result.document.id for result in results] == ["CUSTOM-FRESH-RESULT"]
        assert rag._cache_hits == 0
        assert rag._cache_misses == 1

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


class TestHybridRAGSearchBoundaryShapes:
    @pytest.mark.parametrize(
        "requested,expected",
        [
            ({"bad": "count"}, 6),
            (2, 4),
        ],
    )
    def test_search_coerces_result_limit_before_fetching_embeddings(
        self,
        tmp_path,
        monkeypatch,
        requested,
        expected,
    ):
        calls = []

        def record_search(self, query, filter_category=None, filter_severity=None, n_results=None):
            calls.append((query, filter_category, filter_severity, n_results))
            return []

        monkeypatch.setattr(EmbeddingRAG, "search", record_search)

        rag = HybridRAG(persist_directory=str(tmp_path), top_k=3)
        rag._initialized = True
        rag._bm25 = None

        results = rag.search("hybrid boundary", n_results=requested)  # type: ignore[arg-type]

        assert results == []
        assert calls == [("hybrid boundary", None, None, expected)]
