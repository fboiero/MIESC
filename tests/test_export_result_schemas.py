"""``miesc export`` must read every result-file shape MIESC writes.

``miesc scan`` / ``audit`` write ``{"results": [{"tool", "findings"}]}``; the ML
orchestrator behind ``audit full --ml`` writes ``raw_findings`` (a dict, capped to 20)
and ``ml_enhanced`` (the complete, severity-adjusted list) with no ``results`` key at
all. ``miesc report`` already reads both; ``export`` only read ``results`` and exported
zero findings from the second shape (observed on a real run with 64 findings).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from miesc.cli.commands.export import export
from miesc.cli.utils import finding_list, results_from_result_file


def _finding(tool: str, title: str, severity: str = "HIGH", line: int = 10) -> dict:
    return {
        "tool": tool,
        "type": title.lower().replace(" ", "_"),
        "title": title,
        "message": f"{title} detected",
        "description": f"{title} detected",
        "severity": severity,
        "confidence": 0.9,
        "location": {"file": "Vault.sol", "line": line},
    }


ML_FINDINGS = [
    _finding("slither", "Reentrancy", "HIGH", 42),
    _finding("aderyn", "Unchecked Call", "MEDIUM", 77),
    _finding("slither", "Timestamp Dependence", "LOW", 90),
]

# Shape written by miesc/core/ml_orchestrator.py::MLAnalysisResult.to_dict()
ML_ORCHESTRATOR_DATA = {
    "contract_path": "contracts/Vault.sol",
    "tools_run": ["slither", "aderyn"],
    "tool_status": {"slither": "success", "aderyn": "success"},
    "raw_findings": {"total": 3, "findings": ML_FINDINGS[:2]},
    "ml_enhanced": {
        "filtered_count": 3,
        "findings": ML_FINDINGS,
        "false_positives_removed": 0,
        "severity_adjustments": 0,
        "top_findings": ML_FINDINGS[:1],
    },
    "clusters": {"count": 0, "clusters": []},
    "timestamp": "2026-10-23T12:00:00",
}

# Shape written by miesc scan / audit (unchanged behaviour)
SCAN_DATA = {
    "contract": "contracts/Vault.sol",
    "results": [
        {"tool": "slither", "status": "success", "findings": ML_FINDINGS[:2]},
        {"tool": "aderyn", "status": "success", "findings": ML_FINDINGS[2:]},
    ],
}


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _write(tmp_path: Path, data: dict) -> Path:
    f = tmp_path / "audit.json"
    f.write_text(json.dumps(data))
    return f


class TestResultsFromResultFile:
    def test_scan_shape_is_passed_through(self):
        results = results_from_result_file(SCAN_DATA, "fallback.sol")
        assert results == SCAN_DATA["results"]

    def test_flat_findings_shape_wraps_the_document(self):
        data = {"contract": "A.sol", "findings": ML_FINDINGS}
        assert results_from_result_file(data, "x") == [data]

    def test_ml_orchestrator_shape_prefers_ml_enhanced_and_groups_by_tool(self):
        results = results_from_result_file(ML_ORCHESTRATOR_DATA, "fallback.sol")
        assert [r["tool"] for r in results] == ["slither", "aderyn"]
        assert sum(len(r["findings"]) for r in results) == 3
        assert all(r["contract"] == "contracts/Vault.sol" for r in results)
        # ml_enhanced is the complete list; raw_findings is capped at 20 entries
        assert results[0]["findings"][1]["title"] == "Timestamp Dependence"

    def test_ml_orchestrator_shape_falls_back_to_top_then_raw(self):
        data = dict(ML_ORCHESTRATOR_DATA)
        data["ml_enhanced"] = {"findings": [], "top_findings": ML_FINDINGS[:1]}
        assert sum(len(r["findings"]) for r in results_from_result_file(data, "x")) == 1
        data["ml_enhanced"] = {"findings": [], "top_findings": []}
        assert sum(len(r["findings"]) for r in results_from_result_file(data, "x")) == 2

    def test_legacy_list_shaped_raw_findings(self):
        data = {"contract_path": "A.sol", "raw_findings": ML_FINDINGS}
        assert sum(len(r["findings"]) for r in results_from_result_file(data, "x")) == 3

    def test_unknown_shape_degrades_to_the_document_itself(self):
        data = {"something": 1}
        assert results_from_result_file(data, "x") == [data]

    def test_finding_list_drops_non_dicts(self):
        assert finding_list({"findings": [{"a": 1}, "junk", None]}) == [{"a": 1}]
        assert finding_list([{"a": 1}, 3]) == [{"a": 1}]
        assert finding_list("nope") == []
        assert finding_list(None) == []


class TestExportReadsTheMlOrchestratorShape:
    def test_sarif_has_one_result_per_finding(self, runner, tmp_path):
        inp = _write(tmp_path, ML_ORCHESTRATOR_DATA)
        out = tmp_path / "r.sarif.json"
        result = runner.invoke(export, [str(inp), "-f", "sarif", "-o", str(out)])
        assert result.exit_code == 0, result.output
        sarif = json.loads(out.read_text())
        assert len(sarif["runs"][0]["results"]) == 3

    def test_csv_has_one_row_per_finding_with_its_tool(self, runner, tmp_path):
        inp = _write(tmp_path, ML_ORCHESTRATOR_DATA)
        out = tmp_path / "r.csv"
        result = runner.invoke(export, [str(inp), "-f", "csv", "-o", str(out)])
        assert result.exit_code == 0, result.output
        rows = [r for r in out.read_text().splitlines() if r.strip()]
        assert len(rows) == 1 + 3
        # grouped by tool: slither's two findings, then aderyn's
        assert [r.split(",")[0] for r in rows[1:]] == ["slither", "slither", "aderyn"]

    def test_jsonl_has_one_line_per_finding(self, runner, tmp_path):
        inp = _write(tmp_path, ML_ORCHESTRATOR_DATA)
        out = tmp_path / "r.jsonl"
        result = runner.invoke(export, [str(inp), "-f", "jsonl", "-o", str(out)])
        assert result.exit_code == 0, result.output
        lines = [json.loads(line) for line in out.read_text().splitlines() if line]
        assert len(lines) == 3
        assert {line["tool"] for line in lines} == {"slither", "aderyn"}
        assert all(line["contract"] == "contracts/Vault.sol" for line in lines)

    def test_markdown_and_html_count_the_findings(self, runner, tmp_path):
        inp = _write(tmp_path, ML_ORCHESTRATOR_DATA)
        for fmt, needle in (("markdown", "Reentrancy"), ("html", "Timestamp Dependence")):
            out = tmp_path / f"r.{fmt}"
            result = runner.invoke(export, [str(inp), "-f", fmt, "-o", str(out)])
            assert result.exit_code == 0, result.output
            assert needle in out.read_text()

    def test_github_annotates_every_finding(self, runner, tmp_path):
        inp = _write(tmp_path, ML_ORCHESTRATOR_DATA)
        result = runner.invoke(export, [str(inp), "-f", "github"])
        assert result.exit_code == 0, result.output
        assert result.output.count("::") >= 3

    def test_scan_shape_still_exports_the_same(self, runner, tmp_path):
        inp = _write(tmp_path, SCAN_DATA)
        out = tmp_path / "r.sarif.json"
        result = runner.invoke(export, [str(inp), "-f", "sarif", "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert len(json.loads(out.read_text())["runs"][0]["results"]) == 3
