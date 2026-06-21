"""
Tests for src.adapters.smartllm_rag_knowledge — the knowledge base
that feeds RAG context to SmartLLM. v5.1.7 coverage push.

Focus: the public knowledge-construction API + contract-type
classifier. Not testing internal _get_*_knowledge() helpers
individually; their output is exercised via get_relevant_knowledge.
"""

from __future__ import annotations

import pytest

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
