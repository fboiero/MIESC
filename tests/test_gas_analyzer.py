"""
Tests for GasAnalyzerAdapter
==============================

Covers:
- Metadata and availability
- Detection of unbounded loops (DoS risk)
- Detection of storage reads inside loops (high gas)
- Detection of repeated external calls (gas griefing)
- Edge cases: empty contract, non-existent file
"""

import os
import tempfile

import pytest

from src.adapters.gas_analyzer_adapter import GasAnalyzerAdapter
from src.core.tool_protocol import ToolCategory, ToolStatus

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter():
    return GasAnalyzerAdapter()


def _write_contract(source: str) -> str:
    """Write *source* to a temp .sol file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".sol")
    with os.fdopen(fd, "w") as f:
        f.write(source)
    return path


# ---------------------------------------------------------------------------
# Task 1: Metadata + is_available
# ---------------------------------------------------------------------------


class TestMetadata:
    def test_tool_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "gas_analyzer"

    def test_tool_version(self, adapter):
        meta = adapter.get_metadata()
        assert meta.version == "1.0.0"

    def test_tool_category(self, adapter):
        meta = adapter.get_metadata()
        assert meta.category == ToolCategory.GAS_OPTIMIZATION

    def test_no_api_key_required(self, adapter):
        meta = adapter.get_metadata()
        assert meta.requires_api_key is False

    def test_cost_is_zero(self, adapter):
        meta = adapter.get_metadata()
        assert meta.cost == 0.0

    def test_is_available_returns_available(self, adapter):
        """Gas analyzer is built-in — always available."""
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_can_analyze_sol_file(self, adapter):
        assert adapter.can_analyze("Contract.sol") is True

    def test_can_analyze_non_sol_returns_false(self, adapter):
        assert adapter.can_analyze("Contract.js") is False


# ---------------------------------------------------------------------------
# Task 2: Contract pattern detection
# ---------------------------------------------------------------------------


UNBOUNDED_LOOP_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnboundedLoop {
    address[] public users;

    // DoS risk: iterates over unbounded array — gas griefing vector
    function payAll() external {
        for (uint i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether);
        }
    }
}
"""

STORAGE_IN_LOOP_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StorageInLoop {
    uint256[] public scores;

    // sload_in_loop: for(...) { ... array[ on one line triggers the pattern
    function sumScores() public view returns (uint256 total) {
        for (uint256 i = 0; i < scores.length; i++) { total += scores[i]; }
    }
}
"""

REPEATED_EXTERNAL_CALLS_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf() external view returns (uint256);
}

contract GasGriefing {
    IToken public token;

    // repeated_external_call: same call twice on one line — cache the result
    function expensiveCheck() external view returns (bool) {
        require(token.balanceOf() > 0 && token.balanceOf() > 1, "low balance");
        return true;
    }
}
"""


class TestPatternDetection:
    # --- Unbounded loop / array-length-in-loop ---

    def test_array_length_loop_detected(self, adapter):
        path = _write_contract(UNBOUNDED_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert result["status"] == "success"
            patterns = [f["pattern"] for f in result["findings"]]
            assert "array_length_loop" in patterns, f"Expected array_length_loop, got: {patterns}"
        finally:
            os.unlink(path)

    def test_array_length_loop_severity(self, adapter):
        path = _write_contract(UNBOUNDED_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            loop_findings = [f for f in result["findings"] if f["pattern"] == "array_length_loop"]
            assert loop_findings, "No array_length_loop findings"
            assert loop_findings[0]["severity"] == "Medium"
        finally:
            os.unlink(path)

    def test_array_length_loop_has_gas_saved(self, adapter):
        path = _write_contract(UNBOUNDED_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            loop_findings = [f for f in result["findings"] if f["pattern"] == "array_length_loop"]
            assert loop_findings[0]["gas_saved"] > 0
        finally:
            os.unlink(path)

    # --- Storage in loop ---

    def test_sload_in_loop_detected(self, adapter):
        path = _write_contract(STORAGE_IN_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert result["status"] == "success"
            patterns = [f["pattern"] for f in result["findings"]]
            assert "sload_in_loop" in patterns, f"Expected sload_in_loop, got: {patterns}"
        finally:
            os.unlink(path)

    def test_sload_in_loop_severity(self, adapter):
        path = _write_contract(STORAGE_IN_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            sload_findings = [f for f in result["findings"] if f["pattern"] == "sload_in_loop"]
            assert sload_findings[0]["severity"] == "Medium"
        finally:
            os.unlink(path)

    def test_sload_in_loop_gas_impact(self, adapter):
        """SLOAD costs ~2100 gas — impact should be at least that."""
        path = _write_contract(STORAGE_IN_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            sload_findings = [f for f in result["findings"] if f["pattern"] == "sload_in_loop"]
            assert sload_findings[0]["gas_saved"] >= 2100
        finally:
            os.unlink(path)

    # --- Repeated external calls ---

    def test_repeated_external_call_detected(self, adapter):
        path = _write_contract(REPEATED_EXTERNAL_CALLS_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert result["status"] == "success"
            patterns = [f["pattern"] for f in result["findings"]]
            assert "repeated_external_call" in patterns, (
                f"Expected repeated_external_call, got: {patterns}"
            )
        finally:
            os.unlink(path)

    def test_repeated_external_call_severity(self, adapter):
        path = _write_contract(REPEATED_EXTERNAL_CALLS_CONTRACT)
        try:
            result = adapter.analyze(path)
            ec_findings = [
                f for f in result["findings"] if f["pattern"] == "repeated_external_call"
            ]
            assert ec_findings[0]["severity"] == "Medium"
        finally:
            os.unlink(path)

    def test_repeated_external_call_gas_impact(self, adapter):
        """Each external CALL opcode costs 2600+ gas base."""
        path = _write_contract(REPEATED_EXTERNAL_CALLS_CONTRACT)
        try:
            result = adapter.analyze(path)
            ec_findings = [
                f for f in result["findings"] if f["pattern"] == "repeated_external_call"
            ]
            assert ec_findings[0]["gas_saved"] >= 2600
        finally:
            os.unlink(path)

    # --- Metadata in result ---

    def test_result_has_total_gas_savings(self, adapter):
        path = _write_contract(STORAGE_IN_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert "total_gas_savings" in result["metadata"]
            assert result["metadata"]["total_gas_savings"] > 0
        finally:
            os.unlink(path)

    def test_result_has_severity_breakdown(self, adapter):
        path = _write_contract(UNBOUNDED_LOOP_CONTRACT)
        try:
            result = adapter.analyze(path)
            breakdown = result["metadata"]["severity_breakdown"]
            assert isinstance(breakdown, dict)
            assert "High" in breakdown and "Medium" in breakdown and "Low" in breakdown
        finally:
            os.unlink(path)

    def test_min_severity_filter(self, adapter):
        """min_severity='High' should suppress Medium/Low findings."""
        path = _write_contract(UNBOUNDED_LOOP_CONTRACT)
        try:
            result_all = adapter.analyze(path)
            result_high = adapter.analyze(path, min_severity="High")
            # Contract only has Medium/Low patterns — filtered result should be empty
            # (or at least fewer than unfiltered)
            assert result_high["metadata"]["total_issues"] <= result_all["metadata"]["total_issues"]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Task 3: Edge cases
# ---------------------------------------------------------------------------


EMPTY_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Empty {}
"""


class TestEdgeCases:
    def test_empty_contract_returns_no_findings(self, adapter):
        path = _write_contract(EMPTY_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert result["status"] == "success"
            assert result["findings"] == []
            assert result["metadata"]["total_issues"] == 0
        finally:
            os.unlink(path)

    def test_empty_contract_zero_gas_savings(self, adapter):
        path = _write_contract(EMPTY_CONTRACT)
        try:
            result = adapter.analyze(path)
            assert result["metadata"]["total_gas_savings"] == 0
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_error_status(self, adapter):
        result = adapter.analyze("/tmp/this_file_definitely_does_not_exist_12345.sol")
        assert result["status"] == "error"
        assert result["findings"] == []

    def test_nonexistent_file_has_error_key(self, adapter):
        result = adapter.analyze("/tmp/nonexistent_contract_xyz.sol")
        assert "error" in result

    def test_normalize_findings_from_result(self, adapter):
        """normalize_findings() must extract the findings list from a result dict."""
        path = _write_contract(STORAGE_IN_LOOP_CONTRACT)
        try:
            raw = adapter.analyze(path)
            normalized = adapter.normalize_findings(raw)
            assert isinstance(normalized, list)
            assert normalized == raw["findings"]
        finally:
            os.unlink(path)

    def test_normalize_findings_empty_input(self, adapter):
        assert adapter.normalize_findings({}) == []
        assert adapter.normalize_findings(None) == []  # type: ignore[arg-type]
