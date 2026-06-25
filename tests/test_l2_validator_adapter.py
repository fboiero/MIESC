"""
Tests for L2ValidatorAdapter (src/adapters/l2_validator_adapter.py).

Pure-logic module (no subprocess, no external CLI / z3): static analysis of L2 /
rollup security gaps in Solidity (cross-domain messaging auth, withdrawal delay &
proof, sequencer forced inclusion / centralization, optimistic dispute mechanism,
L1-data-cost gas estimation). Every helper takes strings and returns dicts.
"""

from src.adapters.l2_validator_adapter import L2ValidatorAdapter
from src.core.tool_protocol import ToolStatus


def _a():
    return L2ValidatorAdapter()


def _lines(src):
    return src.split("\n")


# --------------------------------------------------------------------------- #
# metadata / availability / detection gate
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _a()
    assert a.get_metadata().name == "l2_validator"
    assert a.is_available() == ToolStatus.AVAILABLE


def test_is_l2_contract():
    a = _a()
    assert a._is_l2_contract("CrossDomainMessenger m; uint stateRoot;") is True
    assert a._is_l2_contract("contract Token { function transfer() {} }") is False


# --------------------------------------------------------------------------- #
# _check_cross_domain_messaging
# --------------------------------------------------------------------------- #
def test_cross_domain_flags_handler_without_sender_check():
    a = _a()
    src = "ICrossDomainMessenger m;\nfunction finalizeDeposit() external { credit(); }"
    out = a._check_cross_domain_messaging(src, _lines(src), "C.sol")
    assert any(f["type"] == "unsafe_cross_domain_message" for f in out)


def test_cross_domain_clean_with_sender_check():
    a = _a()
    src = ("ICrossDomainMessenger m;\n"
           "function receiveMsg() external { require(m.xDomainMessageSender() == l1); }")
    out = a._check_cross_domain_messaging(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_withdrawal_safety
# --------------------------------------------------------------------------- #
def test_withdrawal_flags_missing_delay():
    a = _a()
    src = "function withdraw() external { pay(); }"
    out = a._check_withdrawal_safety(src, _lines(src), "C.sol")
    assert any(f["type"] == "withdrawal_delay_bypass" for f in out)


def test_withdrawal_flags_finalize_without_proof():
    a = _a()
    # has delay (challengePeriod) but no state proof -> isolates the verification gap
    src = "uint challengePeriod;\nfunction finalizeWithdrawal() external { release(); }"
    out = a._check_withdrawal_safety(src, _lines(src), "C.sol")
    assert any(f["type"] == "l2_to_l1_verification_gap" for f in out)


def test_withdrawal_clean_with_delay_and_proof():
    a = _a()
    src = "uint withdrawalDelay;\nbytes32 stateRoot;\nfunction withdrawFunds() external {}"
    out = a._check_withdrawal_safety(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_sequencer_dependency
# --------------------------------------------------------------------------- #
def test_sequencer_flags_missing_forced_inclusion():
    a = _a()
    src = "address sequencer;\nfunction submit() external onlySequencer {}"
    out = a._check_sequencer_dependency(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_forced_inclusion" for f in out)


def test_sequencer_flags_centralization():
    a = _a()
    src = "address public sequencer;\nfunction forceInclude() external {}"
    out = a._check_sequencer_dependency(src, _lines(src), "C.sol")
    assert any(f["type"] == "centralized_sequencer_risk" for f in out)


def test_sequencer_clean_with_forced_inclusion_and_decentralization():
    a = _a()
    src = "Sequencer logic;\nfunction forceInclude() external {}\naddress[] sequencerSet;"
    out = a._check_sequencer_dependency(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_dispute_mechanism
# --------------------------------------------------------------------------- #
def test_dispute_flags_optimistic_without_fraud_proof():
    a = _a()
    src = "// optimistic rollup\nbytes32 stateCommitment;"
    out = a._check_dispute_mechanism(src, _lines(src), "C.sol")
    assert any(f["type"] == "missing_dispute_mechanism" for f in out)


def test_dispute_clean_with_dispute_game():
    a = _a()
    src = "// optimistic rollup\ncontract DisputeGame { function bisect() {} }"
    out = a._check_dispute_mechanism(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# _check_l2_gas
# --------------------------------------------------------------------------- #
def test_l2_gas_flags_estimation_without_l1_cost():
    a = _a()
    src = "uint gasLimit;\nfunction quote() external { estimateGas(); }"
    out = a._check_l2_gas(src, _lines(src), "C.sol")
    assert any(f["type"] == "unsafe_l2_gas_estimation" for f in out)


def test_l2_gas_clean_with_l1_fee():
    a = _a()
    src = "function quote() external { estimateGas(); getL1Fee(); }"
    out = a._check_l2_gas(src, _lines(src), "C.sol")
    assert out == []


# --------------------------------------------------------------------------- #
# analyze — end to end
# --------------------------------------------------------------------------- #
def test_analyze_non_l2_returns_empty(tmp_path):
    a = _a()
    sol = tmp_path / "plain.sol"
    sol.write_text("contract Token { function transfer() public {} }")
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_l2"] is False
    assert out["findings"] == []


def test_analyze_l2_produces_deduped_findings(tmp_path):
    a = _a()
    sol = tmp_path / "rollup.sol"
    sol.write_text(
        "pragma solidity ^0.8.0;\n"
        "// optimistic L2 rollup with sequencer\n"
        "contract L2Bridge {\n"
        "  address public sequencer;\n"
        "  ICrossDomainMessenger messenger;\n"
        "  function finalizeWithdrawal() external { release(); }\n"
        "}\n"
    )
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_l2"] is True
    assert out["findings"]
    keys = [(f["type"], f["location"]["line"]) for f in out["findings"]]
    assert len(keys) == len(set(keys))  # deduped


def test_analyze_missing_file_returns_error():
    a = _a()
    out = a.analyze("/nonexistent/rollup.sol")
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_known_and_unknown_type_and_skip_non_dict():
    a = _a()
    raw = [
        {"type": "centralized_sequencer_risk", "line": 4, "file": "C.sol", "code": "x"},
        {"type": "totally_unknown_type", "line": 8, "file": "C.sol", "code": "y"},
        ["not", "a", "dict"],
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 2
    assert all(f["tool"] == "l2_validator" for f in out)
    assert all(f["id"].startswith("L2V-") for f in out)
    # unknown type falls back to the default Medium config
    unknown = next(f for f in out if f["type"] == "totally_unknown_type")
    assert unknown["severity"] == "Medium"


def test_normalize_findings_empty():
    assert _a().normalize_findings([]) == []
    assert _a().normalize_findings(None) == []
