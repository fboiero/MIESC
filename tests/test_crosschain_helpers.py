"""Tests for CrossChainAdapter bridge-security analyzers (pure, no network)."""

from __future__ import annotations

from src.adapters.crosschain_adapter import BridgeType, CrossChainAdapter

BRIDGE = """contract Bridge {
    mapping(bytes32 => bool) processed;
    address oracle;
    function deposit(uint amount) external { }
    function withdraw(bytes32 msgHash, bytes sig) external {
        require(ecrecover(msgHash, 0, bytes32(0), bytes32(0)) == oracle);
        msg.sender.call.value(amount)("");
    }
    function relayMessage(bytes data) external { emit MessageRelayed(data); }
    function setOracle(address o) external { oracle = o; }
}"""


def _adapter():
    return CrossChainAdapter()


class TestBridgeDetection:
    def test_detects_bridge(self):
        assert _adapter()._detect_bridge_contract(BRIDGE) is True

    def test_non_bridge(self):
        assert _adapter()._detect_bridge_contract("contract C { uint x; }") is False

    def test_bridge_type(self):
        assert _adapter()._detect_bridge_type(BRIDGE) == BridgeType.MESSAGE_PASSING


class TestSecurityAnalyzers:
    def test_replay_protection(self):
        out = _adapter()._analyze_replay_protection(BRIDGE, "B.sol")
        assert any(f.get("category") == "replay_attack" for f in out)

    def test_state_consistency(self):
        out = _adapter()._analyze_state_consistency(BRIDGE, "B.sol")
        assert any(f.get("category") == "finality_assumption" for f in out)

    def test_oracle_security(self):
        out = _adapter()._analyze_oracle_security(BRIDGE, "B.sol")
        cats = {f.get("category") for f in out}
        assert "oracle_manipulation" in cats or "relayer_trust" in cats

    def test_emergency_mechanisms(self):
        out = _adapter()._analyze_emergency_mechanisms(BRIDGE, "B.sol")
        assert any(f.get("category") == "emergency_withdrawal" for f in out)


class TestUtilities:
    def test_error_result(self):
        res = _adapter()._error_result(0.0, "boom")
        assert res["status"] == "error"
        assert res["error"] == "boom"

    def test_read_file_missing(self):
        assert _adapter()._read_file("/no/such/bridge_xyz.sol") is None

    def test_read_file_ok(self, tmp_path):
        f = tmp_path / "B.sol"
        f.write_text("contract B {}", encoding="utf-8")
        assert _adapter()._read_file(str(f)) == "contract B {}"

    def test_deduplicate_findings(self):
        a = _adapter()
        findings = [
            {"category": "replay_attack", "location": {"line": 5}},
            {"category": "replay_attack", "location": {"line": 5}},
        ]
        assert len(a._deduplicate_findings(findings)) <= 1
