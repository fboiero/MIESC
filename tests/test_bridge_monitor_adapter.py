"""
Tests for BridgeMonitorAdapter (src/adapters/bridge_monitor_adapter.py).

Pure-logic module (no subprocess, no external CLI / z3): heuristic detection of
cross-chain *bridge* security gaps in Solidity source (relay verification, nonce
tracking, mint protection, pause, relayer trust, deposit/withdraw invariant,
finality). Every helper takes strings and returns dicts -> no mocking needed.

Note: this analyzes EVM Solidity bridge contracts; it is not a non-EVM-chain feature.
"""

from miesc.adapters.bridge_monitor_adapter import BridgeMonitorAdapter
from miesc.core.tool_protocol import ToolStatus


def _a():
    return BridgeMonitorAdapter()


def _lines(src):
    return src.split("\n")


# A single contract that trips every individual check (relayer, processMessage with
# no verify, mint with no guard, no pause, no nonce, deposit+withdraw no invariant,
# sourceChain with no finality).
VULN_BRIDGE = """\
pragma solidity ^0.8.0;
contract TokenBridge {
    address public relayer;
    uint public sourceChain;
    mapping(address => uint) _balances;
    function deposit(uint amount) external {}
    function withdraw(uint amount) external {}
    function processMessage(bytes calldata data) external {
        mint(msg.sender, 1);
    }
    function mint(address to, uint amt) external {
        _balances[to] += amt;
    }
}
"""


# --------------------------------------------------------------------------- #
# metadata / availability
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _a()
    md = a.get_metadata()
    assert md.name == "bridge_monitor"
    assert a.is_available() == ToolStatus.AVAILABLE


# --------------------------------------------------------------------------- #
# _is_bridge_contract
# --------------------------------------------------------------------------- #
def test_is_bridge_true_with_two_or_more_indicators():
    a = _a()
    assert a._is_bridge_contract("contract Bridge { address relayer; }") is True


def test_is_bridge_false_with_fewer_than_two():
    a = _a()
    assert a._is_bridge_contract("contract Token { function transfer() public {} }") is False


# --------------------------------------------------------------------------- #
# _check_relay_verification
# --------------------------------------------------------------------------- #
def test_relay_verification_flags_unverified_handler():
    a = _a()
    src = "function processMessage(bytes data) external { doStuff(); }"
    out = a._check_relay_verification(src, _lines(src), "C.sol")
    assert any(f["type"] == "unverified_relay_message" for f in out)


def test_relay_verification_handles_nested_braces_in_body():
    a = _a()
    # nested block forces the brace-depth matcher to increment past the inner '{'
    src = "function processMessage(bytes d) external { if (d.length > 0) { run(d); } }"
    out = a._check_relay_verification(src, _lines(src), "C.sol")
    assert any(f["type"] == "unverified_relay_message" for f in out)


def test_relay_verification_clean_when_signature_checked():
    a = _a()
    src = "function processMessage(bytes data) external { require(ecrecover(h,v,r,s) == signer); }"
    out = a._check_relay_verification(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_nonce_tracking
# --------------------------------------------------------------------------- #
def test_nonce_tracking_flags_relay_without_nonce():
    a = _a()
    src = "function relayMessage(bytes d) external { execute(d); }"
    out = a._check_nonce_tracking(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_nonce_tracking" for f in out)


def test_nonce_tracking_clean_with_used_hashes():
    a = _a()
    src = (
        "mapping(bytes32=>bool) usedHashes;\n"
        "function relayMessage(bytes d) external { require(!usedHashes[keccak256(d)]); }"
    )
    out = a._check_nonce_tracking(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_mint_protection
# --------------------------------------------------------------------------- #
def test_mint_protection_flags_unguarded_mint():
    a = _a()
    src = "function mint(address to, uint amt) external {\n  _bal[to] += amt;\n}"
    out = a._check_mint_protection(src, _lines(src), "C.sol")
    assert any(f["type"] == "unprotected_mint" for f in out)


def test_mint_protection_clean_with_onlyBridge():
    a = _a()
    src = "function mint(address to, uint amt) external onlyBridge {\n  _bal[to] += amt;\n}"
    out = a._check_mint_protection(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_pause_mechanism
# --------------------------------------------------------------------------- #
def test_pause_flags_missing_pause():
    a = _a()
    src = "contract Bridge {\n  function f() external {}\n}"
    out = a._check_pause_mechanism(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_pause_mechanism" for f in out)


def test_pause_clean_with_pausable():
    a = _a()
    src = "contract Bridge is Pausable {\n  function f() external whenNotPaused {}\n}"
    out = a._check_pause_mechanism(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_relayer_trust
# --------------------------------------------------------------------------- #
def test_relayer_trust_flags_single_relayer():
    a = _a()
    src = "address public relayer;\nfunction setRelayer(address r) external {}"
    out = a._check_relayer_trust(src, _lines(src), "C.sol")
    assert any(f["type"] == "single_relayer_trust" for f in out)


def test_relayer_trust_clean_with_multisig():
    a = _a()
    src = (
        "address public relayer;\nuint threshold;\nfunction verify(bytes[] signatures) external {}"
    )
    out = a._check_relayer_trust(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_deposit_withdrawal
# --------------------------------------------------------------------------- #
def test_deposit_withdrawal_flags_missing_invariant():
    a = _a()
    src = "function deposit() external {}\nfunction withdraw() external {}"
    out = a._check_deposit_withdrawal(src, _lines(src), "C.sol")
    assert any(f["type"] == "deposit_withdrawal_imbalance" for f in out)


def test_deposit_withdrawal_clean_with_balance_tracking():
    a = _a()
    src = "uint totalDeposited;\n" "function deposit() external {}\nfunction withdraw() external {}"
    out = a._check_deposit_withdrawal(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_finality
# --------------------------------------------------------------------------- #
def test_finality_flags_cross_chain_without_finality():
    a = _a()
    src = "uint sourceChain;\nfunction relay() external { use(sourceChain); }"
    out = a._check_finality(src, _lines(src), "C.sol")
    assert any(f["type"] == "insufficient_finality_check" for f in out)


def test_finality_clean_with_confirmations():
    a = _a()
    src = "uint sourceChain;\nuint minConfirmations;\nfunction relay() external {}"
    out = a._check_finality(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# analyze — end to end (real temp files)
# --------------------------------------------------------------------------- #
def test_analyze_non_bridge_returns_empty():
    a = _a()
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".sol")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("contract Token { function transfer() public {} }")
        out = a.analyze(path)
        assert out["status"] == "success"
        assert out["metadata"]["is_bridge"] is False
        assert out["findings"] == []
    finally:
        os.unlink(path)


def test_analyze_bridge_produces_deduped_findings(tmp_path):
    a = _a()
    sol = tmp_path / "bridge.sol"
    sol.write_text(VULN_BRIDGE)
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_bridge"] is True
    assert out["findings"]  # multiple bridge gaps detected
    types = {f["type"] for f in out["findings"]}
    # at least the mint + pause + relayer gaps should surface
    assert {"unprotected_mint", "missing_pause_mechanism", "single_relayer_trust"} & types
    # dedup: no duplicate (type,line) pairs
    keys = [(f["type"], f["location"]["line"]) for f in out["findings"]]
    assert len(keys) == len(set(keys))


def test_analyze_missing_file_returns_error():
    a = _a()
    out = a.analyze("/nonexistent/bridge.sol")
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_skips_non_dict_and_maps_known_type():
    a = _a()
    raw = [
        {"type": "unprotected_mint", "line": 5, "file": "C.sol", "code": "mint(...)"},
        "not-a-dict",
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 1
    assert out[0]["tool"] == "bridge_monitor"
    assert out[0]["location"]["line"] == 5


def test_normalize_findings_empty():
    assert _a().normalize_findings([]) == []
    assert _a().normalize_findings(None) == []
