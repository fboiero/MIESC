"""Tests for miesc.adapters.crosschain_adapter — Cross-chain bridge security analyzer."""

import pytest

from miesc.adapters.crosschain_adapter import (
    CROSSCHAIN_VULNERABILITY_PATTERNS,
    BridgeType,
    CrossChainAdapter,
)
from src.core.tool_protocol import ToolStatus

# ---------------------------------------------------------------------------
# Sample Solidity code fixtures
# ---------------------------------------------------------------------------

BRIDGE_CONTRACT_SOL = """
pragma solidity ^0.8.0;
contract Bridge {
    mapping(bytes32 => bool) public processedMessages;

    function relay(bytes32 msgHash, bytes calldata proof) external {
        require(!processedMessages[msgHash], "Already processed");
        processedMessages[msgHash] = true;
    }

    function lock(uint amount) external payable {
        require(msg.value == amount);
    }
}
"""

BRIDGE_WITH_MINT_SOL = """
pragma solidity ^0.8.0;
contract TokenBridge {
    function deposit(uint amount) external {
        _lock(amount);
    }

    function withdraw(bytes32 msgHash) external {
        require(processedMessages[msgHash] == false);
        processedMessages[msgHash] = true;
        _mint(msg.sender, amount);
    }

    function relay(bytes32 msgHash, bytes calldata data) external {
        execute(msgHash, data);
    }
}
"""

BURN_MINT_BRIDGE_SOL = """
pragma solidity ^0.8.0;
// bridge that burns on source and mints on destination
contract BurnMintBridge {
    function burn(uint amount) external {
        _burn(msg.sender, amount);
    }
    function mint(address to, uint amount) external {
        _mint(to, amount);
    }
    function relay(bytes32 h) external {}
    function deposit(uint v) external {}
}
"""

LIQUIDITY_POOL_BRIDGE_SOL = """
pragma solidity ^0.8.0;
contract LiquidityBridge {
    mapping(address => uint) public pool;
    function deposit(uint amount) external {
        pool[msg.sender] += amount;
    }
    function relay(bytes32 h) external {}
    function bridge(uint amount) external {}
}
"""

ROLLUP_BRIDGE_SOL = """
pragma solidity ^0.8.0;
// l2 rollup bridge
contract RollupBridge {
    function deposit(uint amount) external {}
    function relay(bytes32 h) external {}
    function processL2Block(bytes calldata data) external {}
}
"""

MESSAGE_PASSING_BRIDGE_SOL = """
pragma solidity ^0.8.0;
contract MessageBridge {
    function relay(bytes32 msgId, bytes calldata message) external {}
    function deposit(uint amount) external {}
    function dispatch(bytes calldata msg_data) external {}
}
"""

CHAIN_REFERENCE_SOL = """
pragma solidity ^0.8.0;
// supports ethereum, polygon, and avalanche
contract MultiChainBridge {
    function bridgeTo(string memory chain, uint amount) external {
        // Destination: ethereum, polygon, avalanche
    }
    function relay(bytes32 h) external {}
}
"""

NON_BRIDGE_SOL = """
pragma solidity ^0.8.0;
contract SimpleToken {
    mapping(address => uint) public balances;
    function transfer(address to, uint amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter():
    return CrossChainAdapter()


@pytest.fixture
def bridge_sol_file(tmp_path):
    """Write the sample bridge contract to a temp .sol file."""
    f = tmp_path / "Bridge.sol"
    f.write_text(BRIDGE_CONTRACT_SOL)
    return str(f)


@pytest.fixture
def non_bridge_sol_file(tmp_path):
    f = tmp_path / "Token.sol"
    f.write_text(NON_BRIDGE_SOL)
    return str(f)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestCrossChainAdapterMetadata:
    def test_get_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "crosschain_analyzer"

    def test_get_metadata_version(self, adapter):
        meta = adapter.get_metadata()
        assert meta.version == "1.0.0"

    def test_get_metadata_has_capabilities(self, adapter):
        meta = adapter.get_metadata()
        assert len(meta.capabilities) >= 3

    def test_get_metadata_no_api_key_required(self, adapter):
        meta = adapter.get_metadata()
        assert meta.requires_api_key is False

    def test_get_metadata_cost_is_zero(self, adapter):
        meta = adapter.get_metadata()
        assert meta.cost == 0.0


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


class TestCrossChainAdapterAvailability:
    def test_is_available_returns_tool_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_is_available_is_available(self, adapter):
        # Pattern-based analyzer is always available
        assert adapter.is_available() == ToolStatus.AVAILABLE


# ---------------------------------------------------------------------------
# can_analyze
# ---------------------------------------------------------------------------


class TestCrossChainAdapterCanAnalyze:
    def test_can_analyze_sol_file(self, adapter):
        assert adapter.can_analyze("Contract.sol") is True

    def test_can_analyze_sol_file_with_path(self, adapter):
        assert adapter.can_analyze("/some/path/MyBridge.sol") is True

    def test_cannot_analyze_ts_file(self, adapter):
        assert adapter.can_analyze("contract.ts") is False

    def test_cannot_analyze_js_file(self, adapter):
        assert adapter.can_analyze("hardhat.js") is False

    def test_cannot_analyze_json_file(self, adapter):
        assert adapter.can_analyze("abi.json") is False

    def test_cannot_analyze_no_extension(self, adapter):
        assert adapter.can_analyze("contractfile") is False

    def test_cannot_analyze_circom_file(self, adapter):
        assert adapter.can_analyze("circuit.circom") is False


# ---------------------------------------------------------------------------
# _normalize_vuln_type (via CROSSCHAIN_VULNERABILITY_PATTERNS keys)
# ---------------------------------------------------------------------------


class TestCrosschainVulnerabilityPatterns:
    """Verify the vulnerability pattern dictionary contains expected keys."""

    def test_insufficient_verification_present(self):
        assert "insufficient_verification" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_replay_attack_present(self):
        assert "replay_attack" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_state_inconsistency_present(self):
        assert "state_inconsistency" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_oracle_manipulation_present(self):
        assert "oracle_manipulation" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_bridge_fund_drainage_present(self):
        assert "bridge_fund_drainage" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_token_mismatch_present(self):
        assert "token_mismatch" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_cross_chain_mev_present(self):
        assert "cross_chain_mev" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_relayer_trust_present(self):
        assert "relayer_trust" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_finality_assumption_present(self):
        assert "finality_assumption" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_emergency_withdrawal_present(self):
        assert "emergency_withdrawal" in CROSSCHAIN_VULNERABILITY_PATTERNS

    def test_each_pattern_has_severity(self):
        for key, val in CROSSCHAIN_VULNERABILITY_PATTERNS.items():
            assert "severity" in val, f"{key} missing severity"

    def test_each_pattern_has_description(self):
        for key, val in CROSSCHAIN_VULNERABILITY_PATTERNS.items():
            assert "description" in val, f"{key} missing description"


# ---------------------------------------------------------------------------
# _detect_bridge_type
# ---------------------------------------------------------------------------


class TestDetectBridgeType:
    def test_detects_lock_mint(self, adapter):
        bridge_type = adapter._detect_bridge_type(BURN_MINT_BRIDGE_SOL.replace("burn", "lock"))
        assert bridge_type == BridgeType.LOCK_MINT

    def test_detects_burn_mint(self, adapter):
        bridge_type = adapter._detect_bridge_type(BURN_MINT_BRIDGE_SOL)
        assert bridge_type == BridgeType.BURN_MINT

    def test_detects_liquidity_pool(self, adapter):
        bridge_type = adapter._detect_bridge_type(LIQUIDITY_POOL_BRIDGE_SOL)
        assert bridge_type == BridgeType.LIQUIDITY_POOL

    def test_detects_rollup(self, adapter):
        bridge_type = adapter._detect_bridge_type(ROLLUP_BRIDGE_SOL)
        assert bridge_type == BridgeType.ROLLUP

    def test_detects_message_passing_via_relay(self, adapter):
        bridge_type = adapter._detect_bridge_type(MESSAGE_PASSING_BRIDGE_SOL)
        assert bridge_type == BridgeType.MESSAGE_PASSING

    def test_unknown_for_plain_code(self, adapter):
        bridge_type = adapter._detect_bridge_type("contract Foo {}")
        assert bridge_type == BridgeType.UNKNOWN

    def test_bridge_type_enum_values_are_lowercase(self):
        for member in BridgeType:
            assert member.value == member.value.lower()


# ---------------------------------------------------------------------------
# _find_chain_references
# ---------------------------------------------------------------------------


class TestFindChainReferences:
    def test_finds_ethereum(self, adapter):
        refs = adapter._find_chain_references("// supports ethereum mainnet")
        assert "ethereum" in refs

    def test_finds_polygon(self, adapter):
        refs = adapter._find_chain_references("bridge to polygon network")
        assert "polygon" in refs

    def test_finds_avalanche(self, adapter):
        refs = adapter._find_chain_references("avalanche chain")
        assert "avalanche" in refs

    def test_finds_multiple_chains(self, adapter):
        refs = adapter._find_chain_references(CHAIN_REFERENCE_SOL)
        assert "ethereum" in refs
        assert "polygon" in refs
        assert "avalanche" in refs

    def test_returns_empty_for_no_chain(self, adapter):
        refs = adapter._find_chain_references("contract Foo {}")
        assert refs == []

    def test_case_insensitive(self, adapter):
        refs = adapter._find_chain_references("ETHEREUM mainnet bridge")
        assert "ethereum" in refs


# ---------------------------------------------------------------------------
# analyze() — happy path
# ---------------------------------------------------------------------------


class TestCrossChainAdapterAnalyze:
    def test_analyze_bridge_contract_returns_success(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert result["status"] == "success"
        assert result["tool"] == "crosschain_analyzer"

    def test_analyze_bridge_contract_has_findings_key(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert "findings" in result

    def test_analyze_bridge_contract_detects_bridge(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert result["metadata"]["is_bridge_contract"] is True

    def test_analyze_bridge_contract_has_bridge_type(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert result["metadata"]["bridge_type"] in [bt.value for bt in BridgeType]

    def test_analyze_bridge_contract_has_chain_references(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert "chain_references" in result["metadata"]

    def test_analyze_bridge_contract_has_execution_time(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        assert result["execution_time"] >= 0

    def test_analyze_bridge_contract_findings_have_required_fields(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        for finding in result["findings"]:
            assert "id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert "category" in finding

    def test_analyze_bridge_produces_some_findings(self, adapter, bridge_sol_file):
        """Bridge without verification/pause/emergency should trigger findings."""
        result = adapter.analyze(bridge_sol_file)
        assert len(result["findings"]) > 0

    def test_analyze_non_bridge_contract(self, adapter, non_bridge_sol_file):
        result = adapter.analyze(non_bridge_sol_file)
        assert result["status"] == "success"
        assert result["metadata"]["is_bridge_contract"] is False

    def test_analyze_bridge_type_lock_mint_detection(self, adapter, tmp_path):
        f = tmp_path / "LockMintBridge.sol"
        f.write_text(BRIDGE_WITH_MINT_SOL)
        result = adapter.analyze(str(f))
        assert result["status"] == "success"

    def test_analyze_findings_are_deduplicated(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        titles = [(f["category"], f["title"]) for f in result["findings"]]
        assert len(titles) == len(set(titles))

    def test_analyze_findings_sorted_by_severity(self, adapter, bridge_sol_file):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        result = adapter.analyze(bridge_sol_file)
        findings = result["findings"]
        if len(findings) >= 2:
            severities = [severity_order.get(f["severity"], 4) for f in findings]
            assert severities == sorted(severities)

    def test_analyze_chain_reference_contract(self, adapter, tmp_path):
        f = tmp_path / "MultiChain.sol"
        f.write_text(CHAIN_REFERENCE_SOL)
        result = adapter.analyze(str(f))
        assert result["status"] == "success"
        assert "ethereum" in result["metadata"]["chain_references"]


# ---------------------------------------------------------------------------
# analyze() — edge cases
# ---------------------------------------------------------------------------


class TestCrossChainAdapterEdgeCases:
    def test_analyze_nonexistent_file_returns_error(self, adapter):
        result = adapter.analyze("/nonexistent/path/Contract.sol")
        assert result["status"] == "error"
        assert result["tool"] == "crosschain_analyzer"
        assert "findings" in result
        assert result["findings"] == []

    def test_analyze_nonexistent_file_has_error_message(self, adapter):
        result = adapter.analyze("/nonexistent/path/Contract.sol")
        assert "error" in result

    def test_normalize_findings_from_analyze_result(self, adapter, bridge_sol_file):
        result = adapter.analyze(bridge_sol_file)
        normalized = adapter.normalize_findings(result)
        assert isinstance(normalized, list)

    def test_normalize_findings_empty_dict(self, adapter):
        assert adapter.normalize_findings({}) == []

    def test_normalize_findings_non_dict(self, adapter):
        assert adapter.normalize_findings("not a dict") == []

    def test_get_default_config(self, adapter):
        config = adapter.get_default_config()
        assert "timeout" in config
        assert config["timeout"] > 0
