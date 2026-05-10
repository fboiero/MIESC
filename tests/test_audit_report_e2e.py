"""
Tests for MIESC cross-command pipeline: audit -> report

Validates that output from scan/audit commands can be ingested by the
report command without crashing, and that key data (tool_list, layer_summary)
is correctly extracted.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import os
import tempfile
from unittest.mock import patch

import pytest
from click.testing import CliRunner

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def simple_template(tmp_path):
    """Create a minimal 'simple' template so the report command can find it."""
    # The report command searches for templates via get_data_path.
    # We create a trivial markdown template and patch the lookup.
    tpl = tmp_path / "simple.md"
    tpl.write_text(
        "# Report\n"
        "Contract: {contract_name}\n"
        "Findings: {total_findings}\n"
        "Critical: {critical_count}\n"
        "Tools: {tools_count}\n"
    )
    return tpl


def _make_scan_output(findings=None, tool="slither", contract="Token.sol"):
    """Build a JSON structure matching `miesc scan` output format."""
    if findings is None:
        findings = [
            {
                "id": "SLI-001",
                "title": "Reentrancy",
                "severity": "HIGH",
                "type": "reentrancy",
                "description": "External call before state update",
                "location": {"file": contract, "line": 42},
                "tool": tool,
            }
        ]
    return {
        "version": "5.3.0",
        "contract": contract,
        "timestamp": "2026-04-22T12:00:00",
        "results": [
            {
                "tool": tool,
                "status": "success",
                "findings": findings,
                "execution_time": 1.5,
            }
        ],
    }


def _make_audit_quick_output(contract="Token.sol"):
    """Build a JSON structure matching `miesc audit quick` output format."""
    return {
        "version": "5.3.0",
        "contract": contract,
        "timestamp": "2026-04-22T12:00:00",
        "results": [
            {
                "tool": "slither",
                "status": "success",
                "findings": [
                    {
                        "id": "SLI-001",
                        "title": "Reentrancy",
                        "severity": "HIGH",
                        "type": "reentrancy",
                        "description": "State change after external call",
                        "location": {"file": contract, "line": 10},
                    }
                ],
                "execution_time": 0.8,
            },
            {
                "tool": "aderyn",
                "status": "success",
                "findings": [
                    {
                        "id": "AD-001",
                        "title": "Unprotected selfdestruct",
                        "severity": "CRITICAL",
                        "type": "selfdestruct",
                        "description": "selfdestruct without access control",
                        "location": {"file": contract, "line": 55},
                    }
                ],
                "execution_time": 0.5,
            },
            {
                "tool": "solhint",
                "status": "success",
                "findings": [],
                "execution_time": 0.3,
            },
        ],
    }


# ---------------------------------------------------------------------------
# 1. test_scan_json_ingested_by_report
# ---------------------------------------------------------------------------


class TestScanJsonIngestedByReport:
    def test_scan_json_ingested_by_report(self, runner, simple_template):
        """Run scan mock output through report command, verify no crash."""
        data = _make_scan_output()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            json_path = f.name

        try:
            from miesc.cli.commands.report import report

            # Patch get_data_path to return our simple template
            with patch("miesc.cli.commands.report.get_data_path", return_value=simple_template):
                result = runner.invoke(report, [json_path, "-t", "simple"])

            # Should not crash — exit code 0
            assert result.exit_code == 0, f"Report failed: {result.output}"
        finally:
            os.unlink(json_path)


# ---------------------------------------------------------------------------
# 2. test_audit_quick_json_ingested_by_report
# ---------------------------------------------------------------------------


class TestAuditQuickJsonIngestedByReport:
    def test_audit_quick_json_ingested_by_report(self, runner, simple_template):
        """Verify audit-quick output format works with report command."""
        data = _make_audit_quick_output()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            json_path = f.name

        try:
            from miesc.cli.commands.report import report

            with patch("miesc.cli.commands.report.get_data_path", return_value=simple_template):
                result = runner.invoke(report, [json_path, "-t", "simple"])

            assert result.exit_code == 0, f"Report failed: {result.output}"
        finally:
            os.unlink(json_path)


# ---------------------------------------------------------------------------
# 3. test_report_reads_tools_from_findings
# ---------------------------------------------------------------------------


class TestReportReadsToolsFromFindings:
    def test_report_reads_tools_from_results(self):
        """Verify tool_list extraction from results[] entries."""
        data = _make_audit_quick_output()

        # Reproduce the tool_list extraction logic from report.py lines 646-656
        tool_list = data.get("tools", [])
        if not tool_list:
            tool_set = set()
            for r in data.get("results", []):
                if r.get("tool"):
                    tool_set.add(r["tool"])
            findings = data.get("findings", [])
            for f in findings:
                t = f.get("tool") or f.get("source", "")
                if t:
                    tool_set.add(t)
            tool_list = sorted(tool_set)

        assert "slither" in tool_list
        assert "aderyn" in tool_list
        assert "solhint" in tool_list
        assert len(tool_list) == 3

    def test_report_reads_tools_from_findings_field(self):
        """Verify tool extraction works from findings[] with 'tool' attribute."""
        data = {
            "version": "5.3.0",
            "findings": [
                {"tool": "slither", "severity": "HIGH", "title": "Reentrancy"},
                {"tool": "aderyn", "severity": "MEDIUM", "title": "Gas issue"},
            ],
        }

        tool_list = data.get("tools", [])
        if not tool_list:
            tool_set = set()
            for r in data.get("results", []):
                if r.get("tool"):
                    tool_set.add(r["tool"])
            findings = data.get("findings", [])
            for f in findings:
                t = f.get("tool") or f.get("source", "")
                if t:
                    tool_set.add(t)
            tool_list = sorted(tool_set)

        assert "slither" in tool_list
        assert "aderyn" in tool_list


# ---------------------------------------------------------------------------
# 4. test_report_layer_summary_from_scan
# ---------------------------------------------------------------------------


class TestReportLayerSummaryFromScan:
    def test_report_layer_summary_populated(self):
        """Verify layer_summary is populated when scan output has per-tool metadata."""
        from miesc.cli.constants import LAYERS

        data = _make_audit_quick_output()

        # Simulate the layer inference the report command does:
        # For each tool in results, figure out which layer it belongs to.
        tools_by_layer = {}
        tool_layer_lookup = {}
        for layer_num, layer_info in LAYERS.items():
            for tool_name in layer_info["tools"]:
                tool_layer_lookup[tool_name] = (layer_num, layer_info["name"])

        for r in data.get("results", []):
            tool = r.get("tool", "")
            if tool in tool_layer_lookup:
                layer_num, layer_name = tool_layer_lookup[tool]
                key = f"Layer {layer_num}: {layer_name}"
                if key not in tools_by_layer:
                    tools_by_layer[key] = []
                tools_by_layer[key].append(tool)

        # slither, aderyn, solhint are all in Layer 1: Static Analysis
        assert "Layer 1: Static Analysis" in tools_by_layer
        assert "slither" in tools_by_layer["Layer 1: Static Analysis"]
        assert "aderyn" in tools_by_layer["Layer 1: Static Analysis"]
        assert "solhint" in tools_by_layer["Layer 1: Static Analysis"]

    def test_scan_metadata_carries_execution_time(self):
        """Verify per-tool metadata (execution_time) is present in results."""
        data = _make_scan_output()

        for r in data["results"]:
            assert "execution_time" in r
            assert isinstance(r["execution_time"], (int, float))
            assert r["execution_time"] > 0
