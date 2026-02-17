"""
Tests for Chain Abstraction module.

Tests the multi-chain smart contract abstraction layer.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.chain_abstraction import (
    AbstractChainAnalyzer,
    AbstractContract,
    AbstractEvent,
    AbstractFunction,
    AbstractModifier,
    AbstractVariable,
    ChainRegistry,
    ChainType,
    ContractLanguage,
    Location,
    Mutability,
    Parameter,
    SecurityProperty,
    TypeInfo,
    Visibility,
    VulnerabilityMapping,
    VULNERABILITY_MAPPINGS,
    get_analyzer_for_chain,
    get_analyzer_for_file,
    get_chain_registry,
    get_vulnerability_mapping,
    normalize_vulnerability_type,
    register_chain_analyzer,
)


class TestChainType:
    """Test ChainType enum."""

    def test_evm_chains(self):
        """Test EVM chain values."""
        assert ChainType.ETHEREUM.value == "ethereum"
        assert ChainType.POLYGON.value == "polygon"
        assert ChainType.ARBITRUM.value == "arbitrum"
        assert ChainType.OPTIMISM.value == "optimism"
        assert ChainType.BSC.value == "bsc"
        assert ChainType.AVALANCHE.value == "avalanche"

    def test_non_evm_chains(self):
        """Test non-EVM chain values."""
        assert ChainType.SOLANA.value == "solana"
        assert ChainType.NEAR.value == "near"
        assert ChainType.SUI.value == "sui"
        assert ChainType.APTOS.value == "aptos"
        assert ChainType.STELLAR.value == "stellar"
        assert ChainType.ALGORAND.value == "algorand"
        assert ChainType.CARDANO.value == "cardano"

    def test_evm_chains_method(self):
        """Test getting EVM chains list."""
        evm = ChainType.evm_chains()
        assert len(evm) == 6
        assert ChainType.ETHEREUM in evm
        assert ChainType.SOLANA not in evm

    def test_move_chains_method(self):
        """Test getting Move chains list."""
        move = ChainType.move_chains()
        assert len(move) == 2
        assert ChainType.SUI in move
        assert ChainType.APTOS in move


class TestContractLanguage:
    """Test ContractLanguage enum."""

    def test_all_languages(self):
        """Test all language values."""
        assert ContractLanguage.SOLIDITY.value == "solidity"
        assert ContractLanguage.VYPER.value == "vyper"
        assert ContractLanguage.RUST.value == "rust"
        assert ContractLanguage.MOVE.value == "move"
        assert ContractLanguage.CAIRO.value == "cairo"
        assert ContractLanguage.TEAL.value == "teal"
        assert ContractLanguage.PYTEAL.value == "pyteal"
        assert ContractLanguage.PLUTUS.value == "plutus"
        assert ContractLanguage.AIKEN.value == "aiken"


class TestVisibility:
    """Test Visibility enum."""

    def test_all_visibilities(self):
        """Test all visibility values."""
        assert Visibility.PUBLIC.value == "public"
        assert Visibility.EXTERNAL.value == "external"
        assert Visibility.INTERNAL.value == "internal"
        assert Visibility.PRIVATE.value == "private"


class TestMutability:
    """Test Mutability enum."""

    def test_all_mutabilities(self):
        """Test all mutability values."""
        assert Mutability.PURE.value == "pure"
        assert Mutability.VIEW.value == "view"
        assert Mutability.PAYABLE.value == "payable"
        assert Mutability.NONPAYABLE.value == "nonpayable"
        assert Mutability.MUTABLE.value == "mutable"


class TestSecurityProperty:
    """Test SecurityProperty enum."""

    def test_all_properties(self):
        """Test all security properties."""
        assert SecurityProperty.ACCESS_CONTROL.value == "access_control"
        assert SecurityProperty.REENTRANCY.value == "reentrancy"
        assert SecurityProperty.ARITHMETIC.value == "arithmetic"
        assert SecurityProperty.INPUT_VALIDATION.value == "input_validation"
        assert SecurityProperty.EXTERNAL_CALLS.value == "external_calls"
        assert SecurityProperty.MEV.value == "mev"


class TestTypeInfo:
    """Test TypeInfo dataclass."""

    def test_create_simple(self):
        """Test creating simple type."""
        t = TypeInfo(name="uint256")
        assert t.name == "uint256"
        assert t.is_primitive is True
        assert t.is_array is False
        assert t.is_mapping is False

    def test_create_array(self):
        """Test creating array type."""
        t = TypeInfo(name="uint256", is_array=True)
        assert t.is_array is True
        assert str(t) == "uint256[]"

    def test_create_mapping(self):
        """Test creating mapping type."""
        key = TypeInfo(name="address")
        value = TypeInfo(name="uint256")
        t = TypeInfo(name="mapping", is_mapping=True, key_type=key, value_type=value)
        assert t.is_mapping is True
        assert "mapping" in str(t)
        assert "address" in str(t)
        assert "uint256" in str(t)

    def test_str_simple(self):
        """Test string representation."""
        t = TypeInfo(name="bool")
        assert str(t) == "bool"


class TestParameter:
    """Test Parameter dataclass."""

    def test_create_parameter(self):
        """Test creating parameter."""
        t = TypeInfo(name="uint256")
        p = Parameter(name="amount", type_info=t)
        assert p.name == "amount"
        assert p.type_info.name == "uint256"
        assert p.is_indexed is False

    def test_create_indexed_parameter(self):
        """Test creating indexed parameter."""
        t = TypeInfo(name="address")
        p = Parameter(name="sender", type_info=t, is_indexed=True)
        assert p.is_indexed is True


class TestLocation:
    """Test Location dataclass."""

    def test_create_location(self):
        """Test creating location."""
        loc = Location(file="Token.sol", line=42, column=10)
        assert loc.file == "Token.sol"
        assert loc.line == 42
        assert loc.column == 10

    def test_to_dict(self):
        """Test dictionary conversion."""
        loc = Location(file="Token.sol", line=42, column=10, end_line=45)
        d = loc.to_dict()
        assert d["file"] == "Token.sol"
        assert d["line"] == 42
        assert d["end_line"] == 45


class TestAbstractVariable:
    """Test AbstractVariable dataclass."""

    def test_create_variable(self):
        """Test creating variable."""
        t = TypeInfo(name="uint256")
        v = AbstractVariable(name="totalSupply", type_info=t)
        assert v.name == "totalSupply"
        assert v.visibility == Visibility.INTERNAL
        assert v.is_constant is False

    def test_create_constant(self):
        """Test creating constant."""
        t = TypeInfo(name="uint8")
        v = AbstractVariable(
            name="DECIMALS",
            type_info=t,
            is_constant=True,
            initial_value="18",
        )
        assert v.is_constant is True
        assert v.initial_value == "18"

    def test_to_dict(self):
        """Test dictionary conversion."""
        t = TypeInfo(name="address")
        v = AbstractVariable(name="owner", type_info=t, visibility=Visibility.PUBLIC)
        d = v.to_dict()
        assert d["name"] == "owner"
        assert d["visibility"] == "public"


class TestAbstractModifier:
    """Test AbstractModifier dataclass."""

    def test_create_modifier(self):
        """Test creating modifier."""
        m = AbstractModifier(name="onlyOwner")
        assert m.name == "onlyOwner"
        assert m.parameters == []

    def test_to_dict(self):
        """Test dictionary conversion."""
        t = TypeInfo(name="address")
        p = Parameter(name="account", type_info=t)
        m = AbstractModifier(name="onlyRole", parameters=[p])
        d = m.to_dict()
        assert d["name"] == "onlyRole"
        assert len(d["parameters"]) == 1


class TestAbstractFunction:
    """Test AbstractFunction dataclass."""

    def test_create_function(self):
        """Test creating function."""
        f = AbstractFunction(name="transfer")
        assert f.name == "transfer"
        assert f.visibility == Visibility.PUBLIC
        assert f.mutability == Mutability.NONPAYABLE

    def test_signature(self):
        """Test function signature."""
        t1 = TypeInfo(name="address")
        t2 = TypeInfo(name="uint256")
        p1 = Parameter(name="to", type_info=t1)
        p2 = Parameter(name="amount", type_info=t2)
        f = AbstractFunction(name="transfer", parameters=[p1, p2])
        assert f.signature == "transfer(address, uint256)"

    def test_is_constructor(self):
        """Test constructor detection."""
        f = AbstractFunction(name="constructor")
        assert f.is_constructor is True

        f2 = AbstractFunction(name="initialize")
        assert f2.is_constructor is True

        f3 = AbstractFunction(name="transfer")
        assert f3.is_constructor is False

    def test_is_fallback(self):
        """Test fallback detection."""
        f = AbstractFunction(name="fallback")
        assert f.is_fallback is True

        f2 = AbstractFunction(name="receive")
        assert f2.is_fallback is True

    def test_to_dict(self):
        """Test dictionary conversion."""
        f = AbstractFunction(
            name="withdraw",
            visibility=Visibility.EXTERNAL,
            mutability=Mutability.PAYABLE,
            calls_external=True,
        )
        d = f.to_dict()
        assert d["name"] == "withdraw"
        assert d["visibility"] == "external"
        assert d["calls_external"] is True


class TestAbstractEvent:
    """Test AbstractEvent dataclass."""

    def test_create_event(self):
        """Test creating event."""
        e = AbstractEvent(name="Transfer")
        assert e.name == "Transfer"
        assert e.parameters == []

    def test_to_dict(self):
        """Test dictionary conversion."""
        t = TypeInfo(name="address")
        p = Parameter(name="from", type_info=t, is_indexed=True)
        e = AbstractEvent(name="Transfer", parameters=[p])
        d = e.to_dict()
        assert d["name"] == "Transfer"
        assert d["parameters"][0]["indexed"] is True


class TestAbstractContract:
    """Test AbstractContract dataclass."""

    def test_create_contract(self):
        """Test creating contract."""
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/to/Token.sol",
        )
        assert c.name == "Token"
        assert c.chain_type == ChainType.ETHEREUM
        assert c.language == ContractLanguage.SOLIDITY

    def test_content_hash(self):
        """Test content hash computation."""
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            source_code="contract Token {}",
        )
        h1 = c.content_hash
        assert len(h1) == 16

        c2 = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            source_code="contract Token {}",
        )
        assert c.content_hash == c2.content_hash

    def test_get_function(self):
        """Test getting function by name."""
        f1 = AbstractFunction(name="transfer")
        f2 = AbstractFunction(name="approve")
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            functions=[f1, f2],
        )
        assert c.get_function("transfer") == f1
        assert c.get_function("nonexistent") is None

    def test_get_public_functions(self):
        """Test getting public functions."""
        f1 = AbstractFunction(name="transfer", visibility=Visibility.PUBLIC)
        f2 = AbstractFunction(name="_internal", visibility=Visibility.INTERNAL)
        f3 = AbstractFunction(name="withdraw", visibility=Visibility.EXTERNAL)
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            functions=[f1, f2, f3],
        )
        public = c.get_public_functions()
        assert len(public) == 2

    def test_get_state_variables(self):
        """Test getting state variables."""
        t = TypeInfo(name="uint256")
        v1 = AbstractVariable(name="totalSupply", type_info=t)
        v2 = AbstractVariable(name="DECIMALS", type_info=t, is_constant=True)
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            variables=[v1, v2],
        )
        state = c.get_state_variables()
        assert len(state) == 1
        assert state[0].name == "totalSupply"

    def test_has_modifier(self):
        """Test checking for modifier."""
        m = AbstractModifier(name="onlyOwner")
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            modifiers=[m],
        )
        assert c.has_modifier("onlyOwner") is True
        assert c.has_modifier("onlyAdmin") is False

    def test_to_dict(self):
        """Test dictionary conversion."""
        c = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="/path/Token.sol",
            compiler_version="0.8.19",
        )
        d = c.to_dict()
        assert d["name"] == "Token"
        assert d["chain_type"] == "ethereum"
        assert d["language"] == "solidity"


class TestVulnerabilityMapping:
    """Test VulnerabilityMapping dataclass."""

    def test_vulnerability_mappings_exist(self):
        """Test vulnerability mappings are defined."""
        assert "access_control" in VULNERABILITY_MAPPINGS
        assert "reentrancy" in VULNERABILITY_MAPPINGS
        assert "arithmetic" in VULNERABILITY_MAPPINGS
        assert "input_validation" in VULNERABILITY_MAPPINGS
        assert "signature" in VULNERABILITY_MAPPINGS

    def test_mapping_structure(self):
        """Test mapping structure."""
        m = VULNERABILITY_MAPPINGS["reentrancy"]
        assert m.canonical_name == "reentrancy"
        assert m.severity_default == "Critical"
        assert m.security_property == SecurityProperty.REENTRANCY
        assert len(m.solidity_names) > 0
        assert len(m.swc_ids) > 0

    def test_get_vulnerability_mapping_direct(self):
        """Test getting mapping by canonical name."""
        m = get_vulnerability_mapping("reentrancy")
        assert m is not None
        assert m.canonical_name == "reentrancy"

    def test_get_vulnerability_mapping_chain_specific(self):
        """Test getting mapping by chain-specific name."""
        m = get_vulnerability_mapping("missing-signer-check")
        assert m is not None
        assert m.canonical_name == "access_control"

    def test_get_vulnerability_mapping_not_found(self):
        """Test getting nonexistent mapping."""
        m = get_vulnerability_mapping("unknown-vuln-type")
        assert m is None

    def test_normalize_vulnerability_type(self):
        """Test normalizing vulnerability type."""
        normalized = normalize_vulnerability_type("reentrancy-eth", ChainType.ETHEREUM)
        assert normalized == "reentrancy"

    def test_normalize_vulnerability_type_unknown(self):
        """Test normalizing unknown type."""
        normalized = normalize_vulnerability_type("unknown", ChainType.ETHEREUM)
        assert normalized == "unknown"


class TestChainRegistry:
    """Test ChainRegistry class."""

    @pytest.fixture
    def reset_registry(self):
        """Reset registry singleton."""
        ChainRegistry._instance = None
        ChainRegistry._analyzers = {}
        yield
        ChainRegistry._instance = None
        ChainRegistry._analyzers = {}

    def test_singleton(self, reset_registry):
        """Test singleton pattern."""
        r1 = ChainRegistry()
        r2 = ChainRegistry()
        assert r1 is r2

    def test_list_chains_empty(self, reset_registry):
        """Test listing chains when empty."""
        r = ChainRegistry()
        chains = r.list_chains()
        assert chains == []

    def test_get_status(self, reset_registry):
        """Test getting status."""
        r = ChainRegistry()
        status = r.get_status()
        assert "registered_chains" in status
        assert "analyzers" in status


class TestChainRegistryFunctions:
    """Test chain registry helper functions."""

    @pytest.fixture
    def reset_registry(self):
        """Reset registry."""
        ChainRegistry._instance = None
        ChainRegistry._analyzers = {}
        yield
        ChainRegistry._instance = None
        ChainRegistry._analyzers = {}

    def test_get_chain_registry(self, reset_registry):
        """Test getting registry."""
        r = get_chain_registry()
        assert isinstance(r, ChainRegistry)

    def test_get_analyzer_for_chain_empty(self, reset_registry):
        """Test getting analyzer when none registered."""
        analyzer = get_analyzer_for_chain(ChainType.ETHEREUM)
        assert analyzer is None

    def test_get_analyzer_for_file_empty(self, reset_registry):
        """Test getting analyzer for file when none registered."""
        analyzer = get_analyzer_for_file("test.sol")
        assert analyzer is None
