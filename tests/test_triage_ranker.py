"""
Tests for the recall-safe triage ranker (src/ml/triage_ranker.py).

Invariants under test:
  - RANKING NEVER DROPS a finding (recall stays 1.0) — it only reorders.
  - findings are ordered by P(real) descending, with a `triage_score` annotation.
  - graceful: with no trained model (or no sklearn) score() is None and rank() is a no-op,
    so callers degrade to the existing order instead of breaking.
"""

import os

import pytest

from src.ml.triage_ranker import DEFAULT_MODEL_PATH, TriageRanker, features_for

REAL_CODE = ("pragma solidity ^0.4.24; contract C {"
             " function w() public { msg.sender.call.value(1)(); } }")
BENIGN_CODE = ("pragma solidity ^0.8.0; contract C {"
               " function a(uint x) public pure returns (uint) { return x + 1; } }")


def _f(vtype, fn, line=1):
    return {"type": vtype, "check": vtype, "severity": "high",
            "location": {"function": fn, "line": line}}


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
def test_features_are_29_dimensional():
    v = features_for(_f("reentrancy", "w"), REAL_CODE)
    assert len(v) == 29  # 17 coarse + 12 structural
    assert all(isinstance(x, float) for x in v)


def test_structural_features_flag_deterministic_benign():
    from src.ml.triage_ranker import _structural_features
    # arithmetic on Solidity 0.8 -> a deterministic benign signal must fire
    v = _structural_features({"type": "arithmetic", "check": "arithmetic",
                              "location": {"function": "a", "line": 1}}, BENIGN_CODE)
    assert v[0] == 1.0  # has_benign
    assert v[2] == 1.0  # is_deterministic


# --------------------------------------------------------------------------- #
# Graceful fallback (no model) — must never break a scan
# --------------------------------------------------------------------------- #
class TestGracefulNoModel:
    R = TriageRanker(model_path="/nonexistent/triage_model.joblib")

    def test_not_available(self):
        assert self.R.available() is False

    def test_score_is_none(self):
        assert self.R.score(_f("reentrancy", "w"), REAL_CODE) is None

    def test_rank_is_identity(self):
        findings = [_f("arithmetic", "a"), _f("reentrancy", "w")]
        out = self.R.rank(findings, lambda f: "")
        assert out == findings  # unchanged order, nothing dropped


# --------------------------------------------------------------------------- #
# With the bundled trained model (skip if absent / sklearn missing)
# --------------------------------------------------------------------------- #
def _model_ready() -> bool:
    if not os.path.exists(DEFAULT_MODEL_PATH):
        return False
    try:
        import joblib  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError:
        return False
    return TriageRanker().available()


needs_model = pytest.mark.skipif(not _model_ready(), reason="no trained triage model / sklearn")


class TestRankingWithModel:
    @needs_model
    def test_score_in_unit_interval(self):
        s = TriageRanker().score(_f("reentrancy", "w"), REAL_CODE)
        assert s is not None and 0.0 <= s <= 1.0

    @needs_model
    def test_rank_is_recall_safe(self):
        # the cardinal property: rank NEVER drops a finding
        r = TriageRanker()
        findings = [_f("arithmetic", "a"), _f("reentrancy", "w"), _f("access_control", "w")]
        out = r.rank(findings, lambda f: REAL_CODE)
        assert len(out) == len(findings)
        assert {id(f) for f in out} == {id(f) for f in findings}

    @needs_model
    def test_rank_orders_by_triage_score_desc(self):
        r = TriageRanker()
        files = {"w": REAL_CODE, "a": BENIGN_CODE}
        findings = [_f("arithmetic", "a"), _f("reentrancy", "w")]
        out = r.rank(findings, lambda f: files[f["location"]["function"]])
        scores = [f["triage_score"] for f in out]
        assert scores == sorted(scores, reverse=True)
        assert all("triage_score" in f for f in out)
