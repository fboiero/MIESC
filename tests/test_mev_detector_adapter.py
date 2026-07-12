"""
Tests for MEVDetectorAdapter (src/adapters/mev_detector_adapter.py).

Pure-python MEV vulnerability detector (regex only, no external deps): front-run /
sandwich / timestamp / flash-loan patterns, MEV risk scoring & banding, DeFi
gating, severity filtering and normalization.
"""

from miesc.adapters.mev_detector_adapter import MEVDetectorAdapter
from src.core.tool_protocol import ToolStatus

# Triggers sandwich_swap + flashloan_reentrancy + timestamp_dependence.
MEV = (
    "pragma solidity ^0.8.0;\n"
    "contract Pool {\n"
    "    uint price;\n"
    "    uint deadline;\n"
    "    function swapTokens(uint amt) public {\n"
    "        require(block.timestamp >= deadline);\n"
    "        price = amt;\n"
    "    }\n"
    "    function flashLoan(uint amt) public { borrow(amt); }\n"
    "}\n"
)


def _a():
    return MEVDetectorAdapter()


# --------------------------------------------------------------------------- #
# metadata / helpers
# --------------------------------------------------------------------------- #
def test_metadata_availability_can_analyze_config():
    a = _a()
    assert a.get_metadata().name == "mev_detector"
    assert a.is_available() == ToolStatus.AVAILABLE
    assert a.can_analyze("C.sol") is True
    assert a.can_analyze("C.txt") is False
    assert a.get_default_config()["include_defi_only"] is False


def test_is_defi_contract():
    a = _a()
    assert a._is_defi_contract("contract P { function swap() public {} }") is True
    assert a._is_defi_contract("contract Token { function transfer() public {} }") is False


def test_risk_scoring_and_levels():
    a = _a()
    assert a._calculate_mev_risk([]) == 0.0
    crit = [{"severity": "Critical"}, {"severity": "Critical"}]
    assert a._calculate_mev_risk(crit) == 100.0
    assert a._risk_level(80) == "Critical"
    assert a._risk_level(60) == "High"
    assert a._risk_level(30) == "Medium"
    assert a._risk_level(5) == "Low"
    assert a._risk_level(0) == "None"


def test_severity_helpers_and_attack_vectors():
    a = _a()
    assert a._severity_level("Critical") == 4
    assert a._severity_level("???") == 0
    bd = a._severity_breakdown([{"severity": "High"}, {"severity": "Medium"}])
    assert bd["High"] == 1 and bd["Medium"] == 1
    vectors = a._extract_attack_vectors([{"mev_impact": "Sandwich attack"}, {"mev_impact": ""}])
    assert vectors == ["Sandwich attack"]


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def test_analyze_detects_mev(tmp_path):
    a = _a()
    sol = tmp_path / "Pool.sol"
    sol.write_text(MEV)
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["total_issues"] > 0
    assert out["metadata"]["mev_risk_score"] > 0
    assert out["metadata"]["attack_vectors"]
    vectors = {f["attack_vector"] for f in out["findings"]}
    assert {"timestamp_dependence", "flashloan_reentrancy"} & vectors


def test_analyze_min_severity_filter(tmp_path):
    a = _a()
    sol = tmp_path / "Pool.sol"
    sol.write_text(MEV)
    out = a.analyze(str(sol), min_severity="High")
    assert all(a._severity_level(f["severity"]) >= a._severity_level("High")
               for f in out["findings"])


def test_analyze_defi_only_skips_non_defi(tmp_path):
    a = _a()
    sol = tmp_path / "Plain.sol"
    sol.write_text("contract Token { function transfer() public {} }")
    out = a.analyze(str(sol), include_defi_only=True)
    assert out["status"] == "skipped"
    assert "Not a DeFi" in out["reason"]


def test_analyze_handles_error(tmp_path):
    a = _a()
    out = a.analyze(str(tmp_path))  # directory -> open raises -> error branch
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_passthrough_and_empty():
    a = _a()
    assert a.normalize_findings({"findings": [{"id": "x"}]}) == [{"id": "x"}]
    assert a.normalize_findings("not-a-dict") == []
    assert a.normalize_findings({}) == []
