"""
Tests for the `miesc baseline` CLI commands and the shared CI gate.

Covers:
- baseline generate: writes .miesc-baseline.json from a results JSON
- baseline diff: reports new / known / fixed counts
- --fail-on-new exit code: 0 when no new findings, 1 when new findings exist
- missing / invalid baseline exits 2
- apply_baseline_gate (used by scan & audit) exit-code contract

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from miesc.cli.commands.baseline import (
    apply_baseline_gate,
    baseline,
    load_findings_from_results,
)
from miesc.core.baseline import generate_baseline


# =============================================================================
# Helpers
# =============================================================================


def _finding(rule="reentrancy", file="contracts/Bank.sol", line=15, message="Reentrancy in withdraw()"):
    return {
        "type": rule,
        "severity": "high",
        "message": message,
        "location": {"file": file, "line": line},
        "tool": "slither",
    }


def _write_results(path: Path, findings) -> Path:
    """Write a scan-style results JSON (top-level findings + results)."""
    path.write_text(
        json.dumps(
            {
                "contract": "contracts/",
                "findings": findings,
                "results": [{"tool": "slither", "status": "success", "findings": findings}],
            }
        ),
        encoding="utf-8",
    )
    return path


# =============================================================================
# load_findings_from_results
# =============================================================================


class TestLoadFindings:
    def test_top_level_findings(self, tmp_path):
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])
        findings = load_findings_from_results(str(results))
        assert len(findings) == 2

    def test_flatten_from_results_when_no_top_level(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text(
            json.dumps(
                {"results": [{"tool": "slither", "findings": [_finding(), _finding(rule="b")]}]}
            ),
            encoding="utf-8",
        )
        findings = load_findings_from_results(str(path))
        assert len(findings) == 2


# =============================================================================
# baseline generate
# =============================================================================


class TestGenerateCommand:
    def test_generate_writes_baseline(self, tmp_path):
        runner = CliRunner()
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])
        out = tmp_path / ".miesc-baseline.json"

        result = runner.invoke(
            baseline, ["generate", str(results), "-o", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["count"] == 2

    def test_generate_is_deterministic_on_disk(self, tmp_path):
        runner = CliRunner()
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])
        out1 = tmp_path / "b1.json"
        out2 = tmp_path / "b2.json"

        runner.invoke(baseline, ["generate", str(results), "-o", str(out1)])
        runner.invoke(baseline, ["generate", str(results), "-o", str(out2)])
        assert out1.read_bytes() == out2.read_bytes()

    def test_generate_quiet_prints_path(self, tmp_path):
        runner = CliRunner()
        results = _write_results(tmp_path / "r.json", [_finding()])
        out = tmp_path / "b.json"
        result = runner.invoke(baseline, ["generate", str(results), "-o", str(out), "-q"])
        assert result.exit_code == 0
        assert str(out) in result.output


# =============================================================================
# baseline diff
# =============================================================================


class TestDiffCommand:
    def _make_baseline(self, tmp_path, findings) -> Path:
        path = tmp_path / ".miesc-baseline.json"
        generate_baseline(findings).save(path)
        return path

    def test_diff_reports_counts(self, tmp_path):
        runner = CliRunner()
        base = self._make_baseline(tmp_path, [_finding(rule="a")])
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])

        result = runner.invoke(baseline, ["diff", str(results), "--baseline", str(base)])
        assert result.exit_code == 0, result.output
        assert "New:   1" in result.output
        assert "Known: 1" in result.output

    def test_diff_line_shift_stays_known(self, tmp_path):
        runner = CliRunner()
        base = self._make_baseline(tmp_path, [_finding(line=15)])
        results = _write_results(tmp_path / "r.json", [_finding(line=200)])

        result = runner.invoke(baseline, ["diff", str(results), "--baseline", str(base)])
        assert "New:   0" in result.output
        assert "Known: 1" in result.output

    def test_fail_on_new_exits_1_when_new(self, tmp_path):
        runner = CliRunner()
        base = self._make_baseline(tmp_path, [_finding(rule="a")])
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])

        result = runner.invoke(
            baseline, ["diff", str(results), "--baseline", str(base), "--fail-on-new"]
        )
        assert result.exit_code == 1
        assert "failed" in result.output.lower()

    def test_fail_on_new_exits_0_when_no_new(self, tmp_path):
        runner = CliRunner()
        base = self._make_baseline(tmp_path, [_finding(rule="a"), _finding(rule="b")])
        # current is a subset (one fixed) -> no NEW findings
        results = _write_results(tmp_path / "r.json", [_finding(rule="a")])

        result = runner.invoke(
            baseline, ["diff", str(results), "--baseline", str(base), "--fail-on-new"]
        )
        assert result.exit_code == 0, result.output

    def test_missing_baseline_exits_2(self, tmp_path):
        runner = CliRunner()
        results = _write_results(tmp_path / "r.json", [_finding()])
        result = runner.invoke(
            baseline, ["diff", str(results), "--baseline", str(tmp_path / "nope.json")]
        )
        assert result.exit_code == 2


# =============================================================================
# apply_baseline_gate (shared by scan & audit)
# =============================================================================


class TestApplyBaselineGate:
    def test_gate_exits_1_on_new_with_fail_flag(self, tmp_path):
        base = tmp_path / "b.json"
        generate_baseline([_finding(rule="a")]).save(base)
        with pytest.raises(SystemExit) as exc:
            apply_baseline_gate(
                [_finding(rule="a"), _finding(rule="b")], str(base),
                fail_on_new=True, quiet=True,
            )
        assert exc.value.code == 1

    def test_gate_no_exit_when_no_new(self, tmp_path):
        base = tmp_path / "b.json"
        generate_baseline([_finding(rule="a"), _finding(rule="b")]).save(base)
        # returns normally (no SystemExit) when nothing new
        result = apply_baseline_gate(
            [_finding(rule="a")], str(base), fail_on_new=True, quiet=True
        )
        assert result["new"] == []
        assert len(result["fixed"]) == 1

    def test_gate_no_exit_without_fail_flag(self, tmp_path):
        base = tmp_path / "b.json"
        generate_baseline([_finding(rule="a")]).save(base)
        # new finding present but fail_on_new=False -> no exit
        result = apply_baseline_gate(
            [_finding(rule="a"), _finding(rule="b")], str(base),
            fail_on_new=False, quiet=True,
        )
        assert len(result["new"]) == 1

    def test_gate_missing_baseline_exits_2(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            apply_baseline_gate([_finding()], str(tmp_path / "nope.json"),
                                fail_on_new=True, quiet=True)
        assert exc.value.code == 2
