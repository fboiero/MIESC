"""
Tests for GasAnalyzerAdapter (src/adapters/gas_analyzer_adapter.py).

Pure-python gas anti-pattern detector (regex only, no external deps): public-vs-
external, missing immutable, zero-init, postfix increment, array .length in loop,
etc., plus severity filtering / breakdown and normalization.
"""

from miesc.adapters.gas_analyzer_adapter import GasAnalyzerAdapter
from src.core.tool_protocol import ToolStatus

GAS = (
    "pragma solidity ^0.8.0;\n"
    "contract C {\n"
    "    uint256 owner;\n"
    "    function getValue() public returns (uint) {\n"
    "        for (uint i = 0; i < arr.length; i++) {\n"
    "            sum += arr[i];\n"
    "        }\n"
    "        uint x = 0;\n"
    "        return x;\n"
    "    }\n"
    "}\n"
)


def _a():
    return GasAnalyzerAdapter()


# --------------------------------------------------------------------------- #
# metadata / availability / helpers
# --------------------------------------------------------------------------- #
def test_metadata_availability_can_analyze_config():
    a = _a()
    assert a.get_metadata().name == "gas_analyzer"
    assert a.is_available() == ToolStatus.AVAILABLE
    assert a.can_analyze("C.sol") is True
    assert a.can_analyze("C.txt") is False
    assert a.get_default_config()["min_severity"] == "Low"


def test_severity_level_and_breakdown():
    a = _a()
    assert a._severity_level("High") == 3
    assert a._severity_level("Critical") == 4
    assert a._severity_level("nonsense") == 0
    bd = a._severity_breakdown([{"severity": "Medium"}, {"severity": "Medium"}, {"severity": "Low"}])
    assert bd["Medium"] == 2 and bd["Low"] == 1


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
def test_analyze_detects_gas_patterns(tmp_path):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text(GAS)
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["total_issues"] > 0
    assert out["metadata"]["total_gas_savings"] > 0
    patterns = {f["pattern"] for f in out["findings"]}
    # a representative subset should fire
    assert {"public_not_external", "array_length_loop", "zero_init"} & patterns


def test_analyze_min_severity_filter(tmp_path):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text(GAS)
    out = a.analyze(str(sol), min_severity="Medium")
    assert out["status"] == "success"
    # nothing below Medium survives
    assert all(a._severity_level(f["severity"]) >= a._severity_level("Medium")
               for f in out["findings"])


def test_analyze_handles_error(tmp_path):
    a = _a()
    # a directory path -> open() raises -> error branch
    out = a.analyze(str(tmp_path))
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
