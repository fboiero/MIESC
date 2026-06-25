"""
Tests for the CLI triage-rank integration helpers (recall-safe reordering, never drops):
  - scan.py::_apply_triage_rank   (ranks each result's findings)
  - audit.py::_rank_report_findings (ranks a correlation report's finding buckets)

Both no-op gracefully without a trained model. Model-dependent assertions skip if the
bundled model / sklearn is unavailable.
"""

import os

import pytest

from miesc.cli.commands.audit import _rank_report_findings
from miesc.cli.commands.scan import _apply_triage_rank
from src.ml.triage_ranker import DEFAULT_MODEL_PATH, TriageRanker

REAL_CODE = ("pragma solidity ^0.4.24; contract C {"
             " function w() public { msg.sender.call.value(1)(); } }")
BENIGN_CODE = ("pragma solidity ^0.8.0; contract C {"
               " function a(uint x) public pure returns (uint) { return x + 1; } }")


def _model_ready():
    if not os.path.exists(DEFAULT_MODEL_PATH):
        return False
    try:
        import joblib  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError:
        return False
    return TriageRanker().available()


needs_model = pytest.mark.skipif(not _model_ready(), reason="no trained triage model / sklearn")


def _f(vtype, fn, file):
    return {"type": vtype, "check": vtype, "severity": "high",
            "location": {"function": fn, "line": 1, "file": file}}


# --------------------------------------------------------------------------- #
# scan._apply_triage_rank
# --------------------------------------------------------------------------- #
class TestApplyTriageRank:
    @needs_model
    def test_ranks_and_is_recall_safe(self, tmp_path):
        sol = tmp_path / "C.sol"
        sol.write_text(REAL_CODE)
        results = [{"tool": "t", "findings": [_f("arithmetic", "a", str(sol)),
                                              _f("reentrancy", "w", str(sol))]}]
        _apply_triage_rank(results, contract=str(sol), quiet=True)
        fs = results[0]["findings"]
        assert len(fs) == 2  # recall-safe: nothing dropped
        assert all("triage_score" in f for f in fs)
        scores = [f["triage_score"] for f in fs]
        assert scores == sorted(scores, reverse=True)

    def test_no_model_is_noop(self, tmp_path, monkeypatch):
        import src.ml.triage_ranker as tr

        class _NoModel:
            def available(self):
                return False

        monkeypatch.setattr(tr, "TriageRanker", lambda *a, **k: _NoModel())
        results = [{"findings": [_f("reentrancy", "w", "x.sol")]}]
        _apply_triage_rank(results, contract="x.sol", quiet=True)
        assert len(results[0]["findings"]) == 1  # unchanged


# --------------------------------------------------------------------------- #
# audit._rank_report_findings
# --------------------------------------------------------------------------- #
class TestRankReportFindings:
    @needs_model
    def test_ranks_each_bucket_recall_safe(self, tmp_path):
        sol = tmp_path / "C.sol"
        sol.write_text(REAL_CODE)
        findings = {
            "actionable": [_f("arithmetic", "a", str(sol)), _f("reentrancy", "w", str(sol))],
            "summary_count": 2,  # non-list value must be ignored, not crash
        }
        _rank_report_findings(findings, contract=str(sol))
        act = findings["actionable"]
        assert len(act) == 2  # recall-safe
        assert [f["triage_score"] for f in act] == sorted(
            [f["triage_score"] for f in act], reverse=True)
        assert findings["summary_count"] == 2  # untouched

    def test_no_model_is_noop(self, monkeypatch):
        import src.ml.triage_ranker as tr

        class _NoModel:
            def available(self):
                return False

        monkeypatch.setattr(tr, "TriageRanker", lambda *a, **k: _NoModel())
        findings = {"actionable": [_f("reentrancy", "w", "x.sol")]}
        _rank_report_findings(findings, contract="x.sol")
        assert len(findings["actionable"]) == 1  # unchanged
