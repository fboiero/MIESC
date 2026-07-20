"""Tests for the --fail-on-confidence CI gate.

``--fail-on-confidence`` is distinct from ``--min-confidence``: it hides nothing
from the report, it only narrows which findings can trip the CI exit code. The
gate counts only findings whose calibrated confidence meets the threshold, while
the reported/saved findings still reflect everything.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.scan import scan
from miesc.core.confidence import filter_results_by_confidence

SCAN = "miesc.cli.commands.scan"


# ===========================================================================
# Unit: filter_results_by_confidence
# ===========================================================================


class TestFilterResultsByConfidence:
    def test_filters_per_result(self):
        results = [
            {"tool": "a", "findings": [{"confidence": 0.9}, {"confidence": 0.2}]},
            {"tool": "b", "findings": [{"confidence": 0.6}, {"confidence": 0.1}]},
        ]
        out = filter_results_by_confidence(results, 0.5)
        assert [len(r["findings"]) for r in out] == [1, 1]
        assert out[0]["findings"][0]["confidence"] == 0.9
        assert out[1]["findings"][0]["confidence"] == 0.6

    def test_keeps_unscored_findings(self):
        results = [{"tool": "a", "findings": [{"type": "x"}, {"confidence": 0.1}]}]
        out = filter_results_by_confidence(results, 0.5)
        # The unscored finding defaults to 1.0 and is kept; the low one is dropped.
        assert len(out[0]["findings"]) == 1
        assert out[0]["findings"][0]["type"] == "x"

    def test_noop_at_zero(self):
        results = [{"tool": "a", "findings": [{"confidence": 0.1}, {"confidence": 0.9}]}]
        out = filter_results_by_confidence(results, 0.0)
        assert [f["confidence"] for f in out[0]["findings"]] == [0.1, 0.9]

    def test_does_not_mutate_inputs(self):
        low = {"confidence": 0.1}
        results = [{"tool": "a", "findings": [{"confidence": 0.9}, low]}]
        out = filter_results_by_confidence(results, 0.5)
        # Input list, dict, and its findings list are untouched.
        assert len(results[0]["findings"]) == 2
        assert low in results[0]["findings"]
        # Output holds fresh result dicts and finding lists.
        assert out[0] is not results[0]
        assert out[0]["findings"] is not results[0]["findings"]


# ===========================================================================
# CLI: scan --ci --fail-on-confidence
# ===========================================================================


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _run_scan(runner, tmp_path, *, confidence: float, extra_args: list[str]):
    """Invoke `miesc scan` on a one-file project with a single CRITICAL finding
    carrying the given confidence. All analysis collaborators are mocked so the
    injected confidence survives to the gate untouched."""
    contract = tmp_path / "C.sol"
    contract.write_text("pragma solidity ^0.8.0; contract C {}")

    finding = {
        "type": "reentrancy",
        "title": "Reentrancy in withdraw",
        "severity": "CRITICAL",
        "message": "state updated after external call",
        "confidence": confidence,
        "location": {"file": str(contract), "line": 1},
    }

    def fake_run(tool, *a, **k):
        if tool == "slither":
            return {"tool": "slither", "status": "success", "findings": [finding]}
        return {"tool": tool, "status": "success", "findings": []}

    with (
        patch(f"{SCAN}.run_tool", side_effect=fake_run),
        # Keep findings as-is through the intelligence engine.
        patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        # Do NOT recompute confidence — preserve the injected score.
        patch("miesc.core.confidence.annotate_confidence", lambda *a, **k: None),
    ):
        return runner.invoke(
            scan,
            [str(contract), "--fp-strictness", "off", *extra_args],
        )


def test_low_confidence_critical_does_not_trip_ci(runner, tmp_path):
    out = tmp_path / "r.json"
    result = _run_scan(
        runner,
        tmp_path,
        confidence=0.2,
        extra_args=["--ci", "--fail-on-confidence", "0.5", "-o", str(out)],
    )
    # Below the gate threshold -> CI must NOT fail.
    assert result.exit_code == 0, result.output
    # ...but the finding is still reported in full (not hidden).
    data = json.loads(out.read_text())
    criticals = [f for f in data["findings"] if f.get("severity") == "CRITICAL"]
    assert len(criticals) == 1
    assert data["summary"]["CRITICAL"] == 1


def test_high_confidence_critical_trips_ci(runner, tmp_path):
    result = _run_scan(
        runner,
        tmp_path,
        confidence=0.9,
        extra_args=["--ci", "--fail-on-confidence", "0.5"],
    )
    # At/above the gate threshold -> CI must fail.
    assert result.exit_code == 1, result.output
