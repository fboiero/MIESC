"""
Tests for src/adapters/invariant_synthesizer.py

Covers:
- Enums: InvariantFormat, InvariantCategory
- SynthesizedInvariant dataclass and to_dict()
- InvariantSynthesizer instantiation
- Pattern-based detection (_detect_pattern_invariants)
- Contract type detection (_detect_contract_type)
- Merge and deduplication logic
- Format output generation (solidity, certora, echidna, halmos, foundry)
- Cache key generation and helpers
- synthesize() end-to-end with mocked Ollama
- Convenience function synthesize_invariants()
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from miesc.adapters.invariant_synthesizer import (
    InvariantCategory,
    InvariantFormat,
    InvariantSynthesizer,
    SynthesizedInvariant,
    synthesize_invariants,
)

# ---------------------------------------------------------------------------
# Sample contracts for testing
# ---------------------------------------------------------------------------

ERC20_CONTRACT = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20, Ownable {
    uint256 public totalSupply;

    mapping(address => uint256) public balances;

    constructor() ERC20("MyToken", "MTK") {}

    function transfer(address to, uint256 amount) public override returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        balances[to] += amount;
    }
}
"""

VAULT_CONTRACT = """
pragma solidity ^0.8.0;

contract Vault {
    uint256 public totalSupply;
    uint256 public totalAssets;

    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external {
        totalAssets += amount;
    }

    function withdraw(uint256 shareAmount) external {
        totalAssets -= shareAmount;
    }
}
"""

REENTRANCY_CONTRACT = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""

CEI_VIOLATION_CONTRACT = """
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] -= bal;  // state change AFTER call
    }
}
"""

GENERIC_CONTRACT = """
pragma solidity ^0.8.0;

contract Generic {
    uint256 public value;
    function setValue(uint256 v) external { value = v; }
}
"""


@pytest.fixture
def synthesizer():
    """Create InvariantSynthesizer with mocked dependencies."""
    with patch(
        "miesc.adapters.invariant_synthesizer.get_model", return_value="deepseek-coder:6.7b"
    ):
        with patch(
            "miesc.adapters.invariant_synthesizer.get_ollama_host",
            return_value="http://localhost:11434",
        ):
            with patch(
                "miesc.adapters.invariant_synthesizer.get_retry_config",
                return_value={"attempts": 2, "delay": 1},
            ):
                synth = InvariantSynthesizer()
                return synth


@pytest.fixture
def erc20_file():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(ERC20_CONTRACT)
        f.flush()
        fname = f.name
    yield fname
    os.unlink(fname)


@pytest.fixture
def vault_file():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(VAULT_CONTRACT)
        f.flush()
        fname = f.name
    yield fname
    os.unlink(fname)


@pytest.fixture
def generic_file():
    with tempfile.NamedTemporaryFile(suffix=".sol", mode="w", delete=False) as f:
        f.write(GENERIC_CONTRACT)
        f.flush()
        fname = f.name
    yield fname
    os.unlink(fname)


# ===========================================================================
# Enums
# ===========================================================================


class TestInvariantFormat:
    def test_all_formats(self):
        assert InvariantFormat.SOLIDITY.value == "solidity"
        assert InvariantFormat.CERTORA.value == "certora"
        assert InvariantFormat.ECHIDNA.value == "echidna"
        assert InvariantFormat.HALMOS.value == "halmos"
        assert InvariantFormat.FOUNDRY.value == "foundry"
        assert InvariantFormat.NATURAL.value == "natural"
        assert len(InvariantFormat) == 6

    def test_format_from_value(self):
        assert InvariantFormat("solidity") == InvariantFormat.SOLIDITY
        assert InvariantFormat("certora") == InvariantFormat.CERTORA


class TestInvariantCategory:
    def test_all_categories(self):
        assert InvariantCategory.ACCOUNTING.value == "accounting"
        assert InvariantCategory.SOLVENCY.value == "solvency"
        assert InvariantCategory.ACCESS_CONTROL.value == "access_control"
        assert InvariantCategory.STATE_TRANSITION.value == "state_transition"
        assert InvariantCategory.REENTRANCY.value == "reentrancy"
        assert InvariantCategory.OVERFLOW.value == "overflow"
        assert InvariantCategory.TEMPORAL.value == "temporal"
        assert InvariantCategory.CUSTOM.value == "custom"
        assert len(InvariantCategory) == 8

    def test_category_from_value(self):
        assert InvariantCategory("accounting") == InvariantCategory.ACCOUNTING


# ===========================================================================
# SynthesizedInvariant dataclass
# ===========================================================================


class TestSynthesizedInvariant:
    def test_defaults(self):
        inv = SynthesizedInvariant(
            name="balance_non_negative",
            description="User balances cannot be negative",
            category=InvariantCategory.ACCOUNTING,
            importance="HIGH",
            natural_language="For all users, balance >= 0",
        )
        assert inv.solidity_assertion is None
        assert inv.certora_spec is None
        assert inv.echidna_property is None
        assert inv.halmos_test is None
        assert inv.foundry_test is None
        assert inv.confidence == 0.0
        assert inv.source == "llm"
        assert inv.related_vulnerabilities == []
        assert inv.metadata == {}

    def test_full_construction(self):
        inv = SynthesizedInvariant(
            name="total_supply_consistency",
            description="sum(balances) == totalSupply",
            category=InvariantCategory.ACCOUNTING,
            importance="CRITICAL",
            natural_language="Total supply equals sum of all balances",
            solidity_assertion="assert(totalSupply == sumBalances());",
            certora_spec="invariant totalSupply() == sumBalances()",
            echidna_property="function echidna_supply() returns (bool) { return true; }",
            confidence=0.95,
            source="pattern",
            related_vulnerabilities=["SWC-101"],
            metadata={"related_functions": ["transfer", "mint"]},
        )
        assert inv.confidence == 0.95
        assert inv.source == "pattern"
        assert "SWC-101" in inv.related_vulnerabilities

    def test_to_dict(self):
        inv = SynthesizedInvariant(
            name="test_inv",
            description="desc",
            category=InvariantCategory.REENTRANCY,
            importance="HIGH",
            natural_language="Natural language description",
            confidence=0.8,
            source="pattern",
        )
        d = inv.to_dict()
        assert d["name"] == "test_inv"
        assert d["category"] == "reentrancy"
        assert d["importance"] == "HIGH"
        assert d["confidence"] == 0.8
        assert d["source"] == "pattern"
        assert d["solidity_assertion"] is None
        assert d["related_vulnerabilities"] == []

    def test_to_dict_with_all_fields(self):
        inv = SynthesizedInvariant(
            name="full_inv",
            description="full description",
            category=InvariantCategory.ACCESS_CONTROL,
            importance="CRITICAL",
            natural_language="Only owner can call admin functions",
            solidity_assertion="require(msg.sender == owner);",
            certora_spec="rule onlyOwner { }",
            echidna_property="function echidna_owner() returns (bool) { return true; }",
            halmos_test="function check_owner() public { }",
            foundry_test="function invariant_owner() public { }",
            confidence=0.99,
            source="pattern",
            related_vulnerabilities=["SWC-105"],
            metadata={"key": "value"},
        )
        d = inv.to_dict()
        assert d["solidity_assertion"] is not None
        assert d["certora_spec"] is not None
        assert d["metadata"]["key"] == "value"


# ===========================================================================
# InvariantSynthesizer initialization
# ===========================================================================


class TestInvariantSynthesizerInit:
    def test_init_creates_instance(self, synthesizer):
        assert synthesizer is not None
        assert synthesizer._model == "deepseek-coder:6.7b"
        assert synthesizer._ollama_host == "http://localhost:11434"
        assert synthesizer._max_retries == 2
        assert synthesizer._retry_delay == 1

    def test_init_creates_cache_dir(self, synthesizer):
        assert synthesizer._cache_dir.exists()

    def test_init_loads_formal_invariants(self, synthesizer):
        assert isinstance(synthesizer._formal_invariants, dict)

    def test_init_loads_vulnerability_patterns(self, synthesizer):
        assert synthesizer._vulnerability_patterns is not None


# ===========================================================================
# Contract type detection
# ===========================================================================


class TestDetectContractType:
    def test_detect_erc20(self, synthesizer):
        code = "contract Token { function transfer() {} function balanceOf() {} function totalSupply() {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "erc20"

    def test_detect_vault_generic(self, synthesizer):
        code = "contract Vault { function deposit() {} function withdraw() {} uint256 vault; }"
        result = synthesizer._detect_contract_type(code)
        assert result == "vault"

    def test_detect_erc4626(self, synthesizer):
        code = "contract MyVault is ERC4626 { function totalAssets() {} function totalSupply() {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "erc4626"

    def test_detect_erc721(self, synthesizer):
        code = "contract NFT is ERC721 { function ownerOf(uint256) {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "erc721"

    def test_detect_governance(self, synthesizer):
        code = "contract Governance { function vote() {} function proposal() {} function governance() {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "governance"

    def test_detect_staking(self, synthesizer):
        code = "contract Staking { function stake(uint256 amount) {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "staking"

    def test_detect_dex(self, synthesizer):
        code = "contract AMM { function swap(uint256 amountIn) {} function liquidity() {} }"
        result = synthesizer._detect_contract_type(code)
        assert result == "dex"

    def test_detect_generic(self, synthesizer):
        code = "contract Simple { uint256 public value; }"
        result = synthesizer._detect_contract_type(code)
        assert result == "generic"


# ===========================================================================
# Pattern-based invariant detection
# ===========================================================================


class TestDetectPatternInvariants:
    def test_erc20_finds_supply_invariants(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(ERC20_CONTRACT)
        names = [inv.name for inv in invariants]
        # Should find transfer-preserves-supply
        assert any("transfer" in n or "supply" in n for n in names)

    def test_erc20_finds_balance_invariant(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(ERC20_CONTRACT)
        names = [inv.name for inv in invariants]
        assert any("balance" in n for n in names)

    def test_vault_finds_solvency_invariant(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(VAULT_CONTRACT)
        # vault type detection will trigger vault-specific invariants
        assert len(invariants) > 0

    def test_reentrancy_guard_detected(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(REENTRANCY_CONTRACT)
        reentrancy_invs = [
            inv for inv in invariants if inv.category == InvariantCategory.REENTRANCY
        ]
        assert len(reentrancy_invs) > 0

    def test_owner_pattern_detected(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(REENTRANCY_CONTRACT)
        access_invs = [
            inv for inv in invariants if inv.category == InvariantCategory.ACCESS_CONTROL
        ]
        assert len(access_invs) > 0

    def test_cei_violation_detected(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(CEI_VIOLATION_CONTRACT)
        # .call{} followed by state change should trigger reentrancy warning
        names = [inv.name for inv in invariants]
        assert any("state" in n or "external" in n or "reentrancy" in n for n in names)

    def test_generic_contract_returns_list(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(GENERIC_CONTRACT)
        assert isinstance(invariants, list)

    def test_empty_code_returns_list(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants("")
        assert isinstance(invariants, list)

    def test_invariants_have_required_fields(self, synthesizer):
        invariants = synthesizer._detect_pattern_invariants(ERC20_CONTRACT)
        for inv in invariants:
            assert inv.name
            assert inv.category in InvariantCategory
            assert inv.importance in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert inv.natural_language


# ===========================================================================
# Merge and deduplication
# ===========================================================================


class TestMergeInvariants:
    def _make_inv(self, name, importance="HIGH", natural_language="A unique description"):
        return SynthesizedInvariant(
            name=name,
            description=name,
            category=InvariantCategory.ACCOUNTING,
            importance=importance,
            natural_language=natural_language,
            source="pattern",
            confidence=0.9,
        )

    def test_merge_no_duplicates(self, synthesizer):
        p = [self._make_inv("inv_a", natural_language="Balance consistency check alpha")]
        l = [self._make_inv("inv_b", natural_language="Supply conservation proof beta")]
        merged = synthesizer._merge_invariants(p, l)
        assert len(merged) == 2

    def test_merge_deduplicates_by_name(self, synthesizer):
        p = [self._make_inv("inv_a")]
        l = [self._make_inv("inv_a")]  # same name
        merged = synthesizer._merge_invariants(p, l)
        assert len(merged) == 1

    def test_merge_pattern_takes_priority(self, synthesizer):
        p = [self._make_inv("inv_x", natural_language="Pattern based invariant")]
        l = [self._make_inv("inv_x", natural_language="LLM based invariant")]
        merged = synthesizer._merge_invariants(p, l)
        assert merged[0].source == "pattern"  # pattern version kept

    def test_merge_sorts_by_importance(self, synthesizer):
        p = [
            self._make_inv("low_inv", importance="LOW", natural_language="Low importance thing"),
            self._make_inv(
                "critical_inv", importance="CRITICAL", natural_language="Critical safety property"
            ),
        ]
        merged = synthesizer._merge_invariants(p, [])
        assert merged[0].importance == "CRITICAL"
        assert merged[-1].importance == "LOW"

    def test_merge_empty_inputs(self, synthesizer):
        merged = synthesizer._merge_invariants([], [])
        assert merged == []

    def test_merge_only_pattern(self, synthesizer):
        p = [self._make_inv("p1"), self._make_inv("p2")]
        merged = synthesizer._merge_invariants(p, [])
        assert len(merged) == 2

    def test_merge_only_llm(self, synthesizer):
        l = [
            self._make_inv("l1", natural_language="Balance conservation across transfers"),
            self._make_inv(
                "l2", natural_language="Reentrancy guard prevents callback exploitation"
            ),
        ]
        merged = synthesizer._merge_invariants([], l)
        assert len(merged) == 2


# ===========================================================================
# Semantic similarity check
# ===========================================================================


class TestSemanticSimilarity:
    def _inv(self, natural_language):
        return SynthesizedInvariant(
            name="x",
            description="d",
            category=InvariantCategory.ACCOUNTING,
            importance="HIGH",
            natural_language=natural_language,
        )

    def test_identical_texts_are_similar(self, synthesizer):
        a = self._inv("balance must always be positive value")
        b = self._inv("balance must always be positive value")
        assert synthesizer._is_semantically_similar(a, b) is True

    def test_completely_different_texts(self, synthesizer):
        a = self._inv("reentrancy lock prevents callback exploitation")
        b = self._inv("governance proposal requires quorum threshold met")
        result = synthesizer._is_semantically_similar(a, b)
        assert result is False

    def test_empty_natural_language(self, synthesizer):
        a = self._inv("")
        b = self._inv("some text")
        assert synthesizer._is_semantically_similar(a, b) is False


# ===========================================================================
# Format output generation
# ===========================================================================


class TestFormatInvariants:
    @pytest.fixture
    def accounting_inv(self):
        return SynthesizedInvariant(
            name="balance_conservation",
            description="sum(balances) == totalSupply",
            category=InvariantCategory.ACCOUNTING,
            importance="CRITICAL",
            natural_language="Total supply equals sum of all balances",
        )

    @pytest.fixture
    def reentrancy_inv(self):
        return SynthesizedInvariant(
            name="no_reentrancy",
            description="Lock prevents reentrancy",
            category=InvariantCategory.REENTRANCY,
            importance="CRITICAL",
            natural_language="Reentrancy lock is set during execution",
        )

    @pytest.fixture
    def access_control_inv(self):
        return SynthesizedInvariant(
            name="owner_only",
            description="Only owner can call admin",
            category=InvariantCategory.ACCESS_CONTROL,
            importance="HIGH",
            natural_language="Admin functions are restricted to owner",
        )

    def test_to_solidity_accounting(self, synthesizer, accounting_inv):
        result = synthesizer._to_solidity(accounting_inv)
        assert "function check_balance_conservation" in result
        assert "balance_conservation" in result

    def test_to_solidity_reentrancy(self, synthesizer, reentrancy_inv):
        result = synthesizer._to_solidity(reentrancy_inv)
        assert "modifier" in result.lower() or "reentrancy" in result.lower()

    def test_to_solidity_other(self, synthesizer, access_control_inv):
        result = synthesizer._to_solidity(access_control_inv)
        assert "owner_only" in result

    def test_to_certora_accounting(self, synthesizer, accounting_inv):
        result = synthesizer._to_certora(accounting_inv)
        assert "invariant balance_conservation" in result

    def test_to_certora_access_control(self, synthesizer, access_control_inv):
        result = synthesizer._to_certora(access_control_inv)
        assert "rule owner_only" in result

    def test_to_certora_other(self, synthesizer, reentrancy_inv):
        result = synthesizer._to_certora(reentrancy_inv)
        assert "invariant no_reentrancy" in result

    def test_to_echidna(self, synthesizer, accounting_inv):
        result = synthesizer._to_echidna(accounting_inv)
        assert "echidna_balance_conservation" in result
        assert "returns (bool)" in result

    def test_to_halmos(self, synthesizer, accounting_inv):
        result = synthesizer._to_halmos(accounting_inv)
        assert "check_balance_conservation" in result
        assert "@custom:halmos" in result

    def test_to_foundry(self, synthesizer, accounting_inv):
        result = synthesizer._to_foundry(accounting_inv)
        assert "invariant_balance_conservation" in result

    def test_generated_formats_use_safe_identifiers(self, synthesizer):
        inv = SynthesizedInvariant(
            name="123 unsafe-name!",
            description="Unsafe names should not leak into callable identifiers",
            category=InvariantCategory.ACCOUNTING,
            importance="HIGH",
            natural_language="Generated invariant names are valid in target formats",
        )

        assert "function echidna_inv_123_unsafe_name" in synthesizer._to_echidna(inv)
        assert "function invariant_inv_123_unsafe_name" in synthesizer._to_foundry(inv)
        assert "invariant inv_123_unsafe_name" in synthesizer._to_certora(inv)

    def test_generated_formats_mark_candidate_bindings(self, synthesizer, accounting_inv):
        output = "\n".join(
            [
                synthesizer._to_solidity(accounting_inv),
                synthesizer._to_certora(accounting_inv),
                synthesizer._to_echidna(accounting_inv),
                synthesizer._to_halmos(accounting_inv),
                synthesizer._to_foundry(accounting_inv),
            ]
        )

        assert "TODO" not in output
        assert "Candidate property" in output
        assert "Bind protocol-specific state variables" in output

    def test_format_invariants_solidity_only(self, synthesizer, accounting_inv):
        result = synthesizer._format_invariants([accounting_inv], [InvariantFormat.SOLIDITY])
        assert result[0].solidity_assertion is not None
        assert result[0].certora_spec is None
        assert result[0].echidna_property is None

    def test_format_invariants_multiple_formats(self, synthesizer, accounting_inv):
        formats = [InvariantFormat.SOLIDITY, InvariantFormat.CERTORA, InvariantFormat.ECHIDNA]
        result = synthesizer._format_invariants([accounting_inv], formats)
        assert result[0].solidity_assertion is not None
        assert result[0].certora_spec is not None
        assert result[0].echidna_property is not None

    def test_format_invariants_all_formats(self, synthesizer, accounting_inv):
        formats = [
            InvariantFormat.SOLIDITY,
            InvariantFormat.CERTORA,
            InvariantFormat.ECHIDNA,
            InvariantFormat.HALMOS,
            InvariantFormat.FOUNDRY,
        ]
        result = synthesizer._format_invariants([accounting_inv], formats)
        assert result[0].solidity_assertion is not None
        assert result[0].certora_spec is not None
        assert result[0].echidna_property is not None
        assert result[0].halmos_test is not None
        assert result[0].foundry_test is not None


# ===========================================================================
# Parse LLM invariants
# ===========================================================================


class TestParseLlmInvariants:
    def test_parse_valid_json_block(self, synthesizer):
        response = """
Here are the invariants:
```json
{
  "invariants": [
    {
      "name": "supply_conservation",
      "category": "accounting",
      "importance": "CRITICAL",
      "natural_language": "Total supply equals sum of all balances",
      "formal_spec": "sum(balances) == totalSupply"
    }
  ]
}
```
"""
        result = synthesizer._parse_llm_invariants(response)
        assert len(result) == 1
        assert result[0].name == "supply_conservation"
        assert result[0].category == InvariantCategory.ACCOUNTING

    def test_parse_raw_json(self, synthesizer):
        response = json.dumps(
            {
                "invariants": [
                    {
                        "name": "inv_one",
                        "category": "reentrancy",
                        "importance": "HIGH",
                        "natural_language": "Reentrancy locked",
                        "formal_spec": "lock == true during execution",
                    }
                ]
            }
        )
        result = synthesizer._parse_llm_invariants(response)
        assert len(result) == 1
        assert result[0].category == InvariantCategory.REENTRANCY

    def test_parse_unknown_category_defaults_to_custom(self, synthesizer):
        response = json.dumps(
            {
                "invariants": [
                    {
                        "name": "weird_inv",
                        "category": "totally_unknown",
                        "importance": "MEDIUM",
                        "natural_language": "Something weird",
                    }
                ]
            }
        )
        result = synthesizer._parse_llm_invariants(response)
        assert result[0].category == InvariantCategory.CUSTOM

    def test_parse_invalid_json_returns_empty(self, synthesizer):
        result = synthesizer._parse_llm_invariants("not valid json at all")
        assert result == []

    def test_parse_empty_string_returns_empty(self, synthesizer):
        result = synthesizer._parse_llm_invariants("")
        assert result == []

    def test_parse_non_dict_items_skipped(self, synthesizer):
        response = json.dumps(
            {
                "invariants": [
                    "not_a_dict",
                    None,
                    {
                        "name": "valid_inv",
                        "category": "accounting",
                        "importance": "LOW",
                        "natural_language": "Valid",
                    },
                ]
            }
        )
        result = synthesizer._parse_llm_invariants(response)
        # Only the dict item should be parsed
        assert len(result) == 1


# ===========================================================================
# Cache helpers
# ===========================================================================


class TestCacheHelpers:
    def test_cache_key_deterministic(self, synthesizer):
        code = "contract Test {}"
        formats = [InvariantFormat.SOLIDITY]
        cats = [InvariantCategory.ACCOUNTING]
        key1 = synthesizer._get_cache_key(code, formats, cats)
        key2 = synthesizer._get_cache_key(code, formats, cats)
        assert key1 == key2

    def test_cache_key_differs_for_different_code(self, synthesizer):
        formats = [InvariantFormat.SOLIDITY]
        cats = [InvariantCategory.ACCOUNTING]
        key1 = synthesizer._get_cache_key("contract A {}", formats, cats)
        key2 = synthesizer._get_cache_key("contract B {}", formats, cats)
        assert key1 != key2

    def test_get_cached_result_miss(self, synthesizer):
        result = synthesizer._get_cached_result("nonexistent_key_xyz_12345")
        assert result is None

    def test_cache_roundtrip(self, synthesizer):
        key = "test_cache_key_roundtrip_abc"
        data = {"status": "success", "invariants": [], "test": True}
        synthesizer._cache_result(key, data)
        cached = synthesizer._get_cached_result(key)
        assert cached is not None
        assert cached["test"] is True
        assert cached["status"] == "success"
        # Cleanup
        cache_file = synthesizer._cache_dir / f"{key}.json"
        if cache_file.exists():
            cache_file.unlink()

    def test_count_by_category(self, synthesizer):
        invs = [
            SynthesizedInvariant("a", "d", InvariantCategory.ACCOUNTING, "HIGH", "nl"),
            SynthesizedInvariant("b", "d", InvariantCategory.ACCOUNTING, "HIGH", "nl"),
            SynthesizedInvariant("c", "d", InvariantCategory.REENTRANCY, "HIGH", "nl"),
        ]
        counts = synthesizer._count_by_category(invs)
        assert counts["accounting"] == 2
        assert counts["reentrancy"] == 1

    def test_count_by_importance(self, synthesizer):
        invs = [
            SynthesizedInvariant("a", "d", InvariantCategory.ACCOUNTING, "CRITICAL", "nl"),
            SynthesizedInvariant("b", "d", InvariantCategory.ACCOUNTING, "HIGH", "nl"),
            SynthesizedInvariant("c", "d", InvariantCategory.REENTRANCY, "CRITICAL", "nl"),
        ]
        counts = synthesizer._count_by_importance(invs)
        assert counts["CRITICAL"] == 2
        assert counts["HIGH"] == 1

    def test_error_result_structure(self, synthesizer):
        import time

        start = time.time()
        result = synthesizer._error_result("something went wrong", start)
        assert result["status"] == "error"
        assert result["error"] == "something went wrong"
        assert result["invariants"] == []
        assert "execution_time" in result


# ===========================================================================
# Ollama availability and call
# ===========================================================================


class TestOllamaInteraction:
    def test_ollama_not_available_when_subprocess_fails(self, synthesizer):
        with patch("subprocess.run", side_effect=FileNotFoundError("ollama not found")):
            result = synthesizer._is_ollama_available()
        assert result is False

    def test_ollama_not_available_when_returncode_nonzero(self, synthesizer):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            result = synthesizer._is_ollama_available()
        assert result is False

    def test_ollama_available_when_deepseek_present(self, synthesizer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "deepseek-coder:6.7b   5GB   some date"
        with patch("subprocess.run", return_value=mock_result):
            result = synthesizer._is_ollama_available()
        assert result is True

    def test_call_ollama_success(self, synthesizer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"invariants": []}'
        with patch("subprocess.run", return_value=mock_result):
            result = synthesizer._call_ollama("test prompt")
        assert result == '{"invariants": []}'

    def test_call_ollama_timeout_returns_none(self, synthesizer):
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ollama", 180)):
            result = synthesizer._call_ollama("test prompt")
        assert result is None

    def test_call_ollama_empty_stdout_returns_none(self, synthesizer):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            result = synthesizer._call_ollama("test prompt")
        assert result is None


# ===========================================================================
# synthesize() end-to-end (Ollama mocked as unavailable → pattern-only)
# ===========================================================================


class TestSynthesizeEndToEnd:
    def test_synthesize_erc20_pattern_only(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(erc20_file, use_cache=False)
        assert result["status"] == "success"
        assert len(result["invariants"]) > 0
        assert result["from_cache"] is False
        assert "summary" in result
        assert result["summary"]["total"] > 0

    def test_synthesize_returns_summary_structure(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(erc20_file, use_cache=False)
        summary = result["summary"]
        assert "total" in summary
        assert "by_category" in summary
        assert "by_importance" in summary
        assert "formats_generated" in summary

    def test_synthesize_nonexistent_file_returns_error(self, synthesizer):
        result = synthesizer.synthesize("/nonexistent/path/contract.sol", use_cache=False)
        assert result["status"] == "error"
        assert result["invariants"] == []

    def test_synthesize_with_specific_formats(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(
                erc20_file,
                formats=[InvariantFormat.SOLIDITY, InvariantFormat.CERTORA],
                use_cache=False,
            )
        assert result["status"] == "success"
        assert "solidity" in result["summary"]["formats_generated"]
        assert "certora" in result["summary"]["formats_generated"]
        # Verify invariants have solidity and certora fields populated
        for inv in result["invariants"]:
            assert inv["solidity_assertion"] is not None
            assert inv["certora_spec"] is not None

    def test_synthesize_with_category_filter(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(
                erc20_file,
                categories=[InvariantCategory.ACCOUNTING, InvariantCategory.REENTRANCY],
                use_cache=False,
            )
        assert result["status"] == "success"

    def test_synthesize_caches_result(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result1 = synthesizer.synthesize(erc20_file, use_cache=True)
            result2 = synthesizer.synthesize(erc20_file, use_cache=True)
        assert result1["status"] == "success"
        # Second call should hit cache
        assert result2["from_cache"] is True

    def test_synthesize_skips_cache_when_disabled(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(erc20_file, use_cache=False)
        assert result["from_cache"] is False

    def test_synthesize_with_llm_response(self, synthesizer, erc20_file):
        llm_response = json.dumps(
            {
                "invariants": [
                    {
                        "name": "llm_generated_inv",
                        "category": "accounting",
                        "importance": "HIGH",
                        "natural_language": "LLM generated invariant",
                        "formal_spec": "balances[user] >= 0",
                    }
                ]
            }
        )
        with patch.object(synthesizer, "_is_ollama_available", return_value=True):
            with patch.object(synthesizer, "_call_ollama", return_value=llm_response):
                result = synthesizer.synthesize(erc20_file, use_cache=False)
        assert result["status"] == "success"
        names = [inv["name"] for inv in result["invariants"]]
        assert "llm_generated_inv" in names

    def test_synthesize_metadata_includes_model(self, synthesizer, erc20_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(erc20_file, use_cache=False)
        assert result["metadata"]["model"] == "deepseek-coder:6.7b"

    def test_synthesize_generic_contract(self, synthesizer, generic_file):
        with patch.object(synthesizer, "_is_ollama_available", return_value=False):
            result = synthesizer.synthesize(generic_file, use_cache=False)
        assert result["status"] == "success"
        # Generic contract may have 0 pattern invariants, but no error
        assert isinstance(result["invariants"], list)


# ===========================================================================
# Convenience function
# ===========================================================================


class TestSynthesizeInvariantsConvenience:
    def test_synthesize_invariants_with_path(self, erc20_file):
        with patch(
            "miesc.adapters.invariant_synthesizer.get_model", return_value="deepseek-coder:6.7b"
        ):
            with patch(
                "miesc.adapters.invariant_synthesizer.get_ollama_host",
                return_value="http://localhost:11434",
            ):
                with patch(
                    "miesc.adapters.invariant_synthesizer.get_retry_config",
                    return_value={"attempts": 2, "delay": 1},
                ):
                    with patch(
                        "miesc.adapters.invariant_synthesizer.InvariantSynthesizer._is_ollama_available",
                        return_value=False,
                    ):
                        result = synthesize_invariants(erc20_file)
        assert result["status"] == "success"

    def test_synthesize_invariants_with_formats(self, erc20_file):
        with patch(
            "miesc.adapters.invariant_synthesizer.get_model", return_value="deepseek-coder:6.7b"
        ):
            with patch(
                "miesc.adapters.invariant_synthesizer.get_ollama_host",
                return_value="http://localhost:11434",
            ):
                with patch(
                    "miesc.adapters.invariant_synthesizer.get_retry_config",
                    return_value={"attempts": 2, "delay": 1},
                ):
                    with patch(
                        "miesc.adapters.invariant_synthesizer.InvariantSynthesizer._is_ollama_available",
                        return_value=False,
                    ):
                        result = synthesize_invariants(erc20_file, formats=["solidity", "echidna"])
        assert result["status"] == "success"
        assert "solidity" in result["summary"]["formats_generated"]

    def test_synthesize_invariants_unknown_format_skipped(self, erc20_file):
        with patch(
            "miesc.adapters.invariant_synthesizer.get_model", return_value="deepseek-coder:6.7b"
        ):
            with patch(
                "miesc.adapters.invariant_synthesizer.get_ollama_host",
                return_value="http://localhost:11434",
            ):
                with patch(
                    "miesc.adapters.invariant_synthesizer.get_retry_config",
                    return_value={"attempts": 2, "delay": 1},
                ):
                    with patch(
                        "miesc.adapters.invariant_synthesizer.InvariantSynthesizer._is_ollama_available",
                        return_value=False,
                    ):
                        # "fakeformat" should be skipped gracefully
                        result = synthesize_invariants(
                            erc20_file, formats=["solidity", "fakeformat"]
                        )
        assert result["status"] == "success"

    def test_synthesize_invariants_nonexistent_returns_error(self):
        with patch(
            "miesc.adapters.invariant_synthesizer.get_model", return_value="deepseek-coder:6.7b"
        ):
            with patch(
                "miesc.adapters.invariant_synthesizer.get_ollama_host",
                return_value="http://localhost:11434",
            ):
                with patch(
                    "miesc.adapters.invariant_synthesizer.get_retry_config",
                    return_value={"attempts": 2, "delay": 1},
                ):
                    result = synthesize_invariants("/nonexistent/file.sol")
        assert result["status"] == "error"
