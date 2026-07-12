"""
Tests for ThreatModelAdapter (src/adapters/threat_model_adapter.py).

Pure-python STRIDE/DREAD threat modeller (regex only, no external deps): STRIDE
pattern detection, DREAD-score -> severity mapping, threat metrics (breakdown,
avg DREAD, highest-risk category, audit-readiness), filtering and normalization.
"""

from miesc.adapters.threat_model_adapter import ThreatModelAdapter
from src.core.tool_protocol import ToolStatus

# Trips several STRIDE patterns: tx.origin (Spoofing), public state var (Tampering),
# setter w/o validation (Tampering), unbounded loop + external call (DoS).
THREAT = (
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    uint public total;\n"
    "    address owner;\n"
    "    address[] users;\n"
    "    function login() external { require(tx.origin == owner); }\n"
    "    function setRate(uint r) external { total = r; }\n"
    "    function payout() external {\n"
    "        for (uint i = 0; i < users.length; i++) { users[i].call(''); }\n"
    "    }\n"
    "}\n"
)


def _a():
    return ThreatModelAdapter()


# --------------------------------------------------------------------------- #
# metadata / helpers
# --------------------------------------------------------------------------- #
def test_metadata_availability_can_analyze_config():
    a = _a()
    assert a.get_metadata().name == "threat_model"
    assert a.is_available() == ToolStatus.AVAILABLE
    assert a.can_analyze("C.sol") is True
    assert a.can_analyze("C.txt") is False
    assert isinstance(a.get_default_config(), dict)


def test_dread_to_severity_all_bands():
    a = _a()
    assert a._dread_to_severity(9.0) == "Critical"
    assert a._dread_to_severity(7.5) == "High"
    assert a._dread_to_severity(6.0) == "Medium"
    assert a._dread_to_severity(4.0) == "Low"
    assert a._dread_to_severity(2.0) == "Info"


def test_calculate_threat_metrics_empty_and_populated():
    a = _a()
    empty = a._calculate_threat_metrics([])
    assert empty["audit_readiness"] == 100.0
    assert empty["highest_risk"] == "None"

    threats = [
        {"stride_category": "Spoofing", "dread_score": 8.0, "severity": "Critical"},
        {"stride_category": "Spoofing", "dread_score": 6.0, "severity": "Medium"},
        {"stride_category": "Tampering", "dread_score": 7.0, "severity": "High"},
    ]
    m = a._calculate_threat_metrics(threats)
    assert m["stride_breakdown"]["Spoofing"] == 2
    assert m["highest_risk"] == "Spoofing"
    assert m["audit_readiness"] == 100 - (10 + 2 + 5)  # Critical+Medium+High penalties
    assert m["avg_dread"] == round((8.0 + 6.0 + 7.0) / 3, 2)


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def test_analyze_detects_threats(tmp_path):
    a = _a()
    sol = tmp_path / "Vault.sol"
    sol.write_text(THREAT)
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["total_threats"] > 0
    assert out["metadata"]["stride_breakdown"]
    cats = {f["stride_category"] for f in out["findings"]}
    assert {"Spoofing", "Tampering"} & cats


def test_analyze_min_dread_filter(tmp_path):
    a = _a()
    sol = tmp_path / "Vault.sol"
    sol.write_text(THREAT)
    out = a.analyze(str(sol), min_dread_score=9.5)  # very high -> filters most/all out
    assert out["status"] == "success"
    assert all(f["dread_score"] >= 9.5 for f in out["findings"])


def test_analyze_handles_error(tmp_path):
    a = _a()
    out = a.analyze(str(tmp_path))  # directory -> open raises -> error branch
    assert out["status"] == "error"
    assert out["error"]
    assert out["findings"] == []


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_passthrough_and_empty():
    a = _a()
    assert a.normalize_findings({"findings": [{"id": "x"}]}) == [{"id": "x"}]
    assert a.normalize_findings("not-a-dict") == []
    assert a.normalize_findings({}) == []
