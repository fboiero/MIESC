"""
Behavioural coverage for the recall-safe triage ranker (miesc/ml/triage_ranker.py).

These tests exercise the real code paths with real 29-dimensional feature vectors
and a deterministic duck-typed model (the module is designed around a `predict_proba`
seam). Every test asserts a meaningful property of ranking, scoring, feature
extraction, model loading, or the `rank_results` orchestration.

Note: `train()` imports scikit-learn/numpy/joblib, none of which are installed in
this environment, so only its loud-failure contract (ImportError) is asserted here
rather than fabricating heavy numeric stubs.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from miesc.ml import triage_ranker as tr
from miesc.ml.triage_ranker import (
    DEFAULT_MODEL_PATH,
    TriageRanker,
    _structural_features,
    features_for,
    rank_results,
)

# A finding under a <0.8 pragma (pragma08 == 0.0) and one under ^0.8 (pragma08 == 1.0).
# pragma08 is index 24 of the 29-d feature vector (coarse 17 + structural[7]).
PRAGMA08_INDEX = 24

VULN_04 = {
    "type": "reentrancy",
    "check": "reentrancy-eth",
    "function": "w",
    "line": 1,
}
CODE_04 = (
    "pragma solidity ^0.4.24; contract C {" " function w() public { msg.sender.call.value(1)(); } }"
)
VULN_08 = {
    "type": "arithmetic",
    "check": "divide-before-multiply",
    "function": "a",
    "line": 1,
}
CODE_08 = (
    "pragma solidity ^0.8.0; contract C {"
    " function a(uint x) public pure returns (uint) { return x + 1; } }"
)


class _FakeModel:
    """P(real) decreases when pragma08 is set, so the ^0.4.24 finding outranks ^0.8.

    Asserts the vector it receives is the real 29-d feature vector.
    """

    def predict_proba(self, X):
        row = X[0]
        assert len(row) == 29  # real feature vector, not a shortcut
        p = 0.9 - 0.5 * row[PRAGMA08_INDEX]
        return [[1.0 - p, p]]


class _ConstModel:
    def predict_proba(self, X):
        return [[0.5, 0.5]]


class _RaisingModel:
    def predict_proba(self, X):
        raise RuntimeError("boom")


def _ranker_with(model, tmp_path):
    """A TriageRanker with no on-disk model, then a model injected via the seam."""
    r = TriageRanker(model_path=str(tmp_path / "does-not-exist.joblib"))
    assert r.model is None  # _load short-circuited on a missing path
    r.model = model
    return r


# --------------------------------------------------------------------------- #
# score()
# --------------------------------------------------------------------------- #


def test_score_none_without_model(tmp_path):
    r = _ranker_with(None, tmp_path)
    r.model = None
    assert r.score(VULN_04, CODE_04) is None


def test_score_returns_model_probability(tmp_path):
    r = _ranker_with(_FakeModel(), tmp_path)
    s04 = r.score(VULN_04, CODE_04)
    s08 = r.score(VULN_08, CODE_08)
    assert s04 == pytest.approx(0.9)
    assert s08 == pytest.approx(0.4)
    assert s04 > s08  # lower pragma -> higher P(real)


def test_score_swallows_model_exception(tmp_path):
    r = _ranker_with(_RaisingModel(), tmp_path)
    assert r.score(VULN_04, CODE_04) is None  # scoring must never break a scan


# --------------------------------------------------------------------------- #
# rank()
# --------------------------------------------------------------------------- #


def test_rank_without_model_returns_same_list_object(tmp_path):
    r = _ranker_with(None, tmp_path)
    r.model = None
    findings = [dict(VULN_08), dict(VULN_04)]
    out = r.rank(findings, lambda f: "")
    assert out is findings  # no-op passthrough, order untouched
    assert "triage_score" not in out[0]


def test_rank_orders_by_probability_descending_and_annotates(tmp_path):
    r = _ranker_with(_FakeModel(), tmp_path)
    f08, f04 = dict(VULN_08), dict(VULN_04)
    code = {id(f08): CODE_08, id(f04): CODE_04}
    out = r.rank([f08, f04], lambda f: code[id(f)])
    # reordered so the higher-probability (^0.4.24) finding is first
    assert out[0] is f04
    assert out[1] is f08
    assert out[0]["triage_score"] == 0.9
    assert out[1]["triage_score"] == 0.4
    # recall-safe: same findings, same identities, nothing dropped
    assert len(out) == 2
    assert {id(x) for x in out} == {id(f04), id(f08)}


def test_rank_rounds_triage_score_to_four_dp(tmp_path):
    class _OddModel:
        def predict_proba(self, X):
            return [[1.0 - 0.123456, 0.123456]]

    r = _ranker_with(_OddModel(), tmp_path)
    f = dict(VULN_04)
    out = r.rank([f], lambda _f: CODE_04)
    assert out[0]["triage_score"] == 0.1235


def test_rank_is_stable_on_ties(tmp_path):
    r = _ranker_with(_ConstModel(), tmp_path)
    findings = [dict(VULN_04, id=i) for i in range(4)]
    out = r.rank(findings, lambda _f: CODE_04)
    assert [f["id"] for f in out] == [0, 1, 2, 3]  # stable order under equal scores
    assert all(f["triage_score"] == 0.5 for f in out)


def test_rank_code_lookup_none_does_not_crash(tmp_path):
    r = _ranker_with(_FakeModel(), tmp_path)
    f = dict(VULN_04)
    out = r.rank([f], lambda _f: None)  # None -> "" inside rank
    assert len(out) == 1
    assert "triage_score" in out[0]


def test_rank_unscored_finding_sorts_below_zero_scored(tmp_path):
    """A finding whose score() raises (None) carries the -1.0 sentinel, so it ranks
    below a finding explicitly scored 0.0 and gets NO triage_score annotation."""

    class _Mixed:
        def predict_proba(self, X):
            if X[0][PRAGMA08_INDEX] == 1.0:  # the ^0.8 finding -> real 0.0
                return [[1.0, 0.0]]
            raise RuntimeError("no score for this one")  # the ^0.4.24 finding

    r = _ranker_with(_Mixed(), tmp_path)
    f04, f08 = dict(VULN_04), dict(VULN_08)
    code = {id(f04): CODE_04, id(f08): CODE_08}
    out = r.rank([f04, f08], lambda f: code[id(f)])
    assert out[0] is f08  # scored 0.0 beats the -1.0 sentinel
    assert out[1] is f04
    assert out[0]["triage_score"] == 0.0
    assert "triage_score" not in out[1]  # unscored finding left unannotated


# --------------------------------------------------------------------------- #
# _load() / available()
# --------------------------------------------------------------------------- #


def test_available_false_when_path_missing(tmp_path):
    r = TriageRanker(model_path=str(tmp_path / "nope.joblib"))
    assert r.available() is False


def test_load_success_via_joblib(tmp_path, monkeypatch):
    model_file = tmp_path / "model.joblib"
    model_file.write_bytes(b"ignored-by-fake-loader")
    fake = _FakeModel()
    monkeypatch.setitem(sys.modules, "joblib", SimpleNamespace(load=lambda _p: fake))
    r = TriageRanker(model_path=str(model_file))
    assert r.available() is True
    assert r.model is fake


def test_load_failure_degrades_to_none(tmp_path):
    """File exists but joblib is unavailable (or load fails) -> model stays None."""
    model_file = tmp_path / "broken.joblib"
    model_file.write_bytes(b"not a real joblib payload")
    r = TriageRanker(model_path=str(model_file))
    assert r.available() is False


# --------------------------------------------------------------------------- #
# rank_results() orchestration
# --------------------------------------------------------------------------- #


def test_rank_results_minus_one_without_model(monkeypatch, tmp_path):
    monkeypatch.setattr(tr, "TriageRanker", lambda *a, **k: _ranker_with(None, tmp_path))
    results = [{"findings": [dict(VULN_04)]}]
    assert rank_results(results) == -1
    assert "triage_score" not in results[0]["findings"][0]  # order untouched


def test_rank_results_counts_and_reorders_in_place(monkeypatch, tmp_path):
    ranker = _ranker_with(_FakeModel(), tmp_path)
    monkeypatch.setattr(tr, "TriageRanker", lambda *a, **k: ranker)

    sol04 = tmp_path / "C04.sol"
    sol04.write_text(CODE_04)
    sol08 = tmp_path / "C08.sol"
    sol08.write_text(CODE_08)

    # Both point at the ^0.8 source (score 0.4). If either resolution silently fell
    # through to "" the finding would score 0.9 instead, so each path is proven.
    f_file = dict(VULN_08, file=str(sol08))  # resolved via `file`
    f_loc = dict(VULN_04, location={"file": str(sol08)})  # resolved via location.file
    results = [
        {"findings": [f_file, f_loc]},
        {"findings": []},  # skipped
        {},  # no findings key -> skipped
    ]
    total = rank_results(results)
    assert total == 2  # only the two real findings counted
    assert f_file["triage_score"] == 0.4  # `file` was read (not the "" fallback)
    assert f_loc["triage_score"] == 0.4  # `location.file` was read
    # equal scores -> stable order preserved, nothing dropped
    assert results[0]["findings"] == [f_file, f_loc]


def test_rank_results_uses_contract_fallback_and_missing_path(monkeypatch, tmp_path):
    ranker = _ranker_with(_FakeModel(), tmp_path)
    monkeypatch.setattr(tr, "TriageRanker", lambda *a, **k: ranker)

    sol = tmp_path / "Main.sol"
    sol.write_text(CODE_08)  # ^0.8 source -> score 0.4, distinct from the "" fallback

    # no file / no location -> falls back to the `contract` argument (reads CODE_08)
    f_fallback = dict(VULN_04)
    # a file that does not exist -> code resolves to "" without crashing (pragma08=0 -> 0.9)
    f_missing = dict(VULN_08, file=str(tmp_path / "ghost.sol"))
    results = [{"findings": [f_fallback, f_missing]}]
    total = rank_results(results, contract=str(sol))
    assert total == 2
    assert f_fallback["triage_score"] == 0.4  # contract fallback actually read the file
    assert f_missing["triage_score"] == 0.9  # missing path -> "" without crashing
    # 0.9 outranks 0.4
    assert results[0]["findings"] == [f_missing, f_fallback]


# --------------------------------------------------------------------------- #
# features_for / _structural_features edges
# --------------------------------------------------------------------------- #


def test_features_for_has_29_dimensions():
    assert len(features_for(VULN_04, CODE_04)) == 29


def test_structural_bad_line_coerces_to_zero():
    v = _structural_features({"type": "x", "line": "abc"}, "contract C {}")
    assert v == [0.0] * 12  # non-int line -> 0, no pragma, nothing scoped


def test_structural_location_not_a_dict():
    v = _structural_features({"type": "x", "location": "oops", "line": 1}, "contract C {}")
    assert len(v) == 12
    assert v[3] == 0.0  # scoped


_CODE_BODY = (
    "pragma solidity ^0.8.0;\n"
    "contract C {\n"
    "  function foo() public onlyOwner {\n"
    "    uint x = block.timestamp;\n"
    "    payable(msg.sender).transfer(1);\n"
    "  }\n"
    "}"
)


def test_structural_function_unknown_falls_back_to_line_lookup():
    # fn == "unknown" is treated as absent -> body resolved via _function_at_line(line)
    v = _structural_features({"type": "x", "function": "unknown", "line": 4}, _CODE_BODY)
    assert v[3] == 1.0  # scoped (a body was located by line)
    assert v[7] == 1.0  # pragma08
    assert v[11] > 0.0  # body_len non-zero


def test_structural_no_function_no_line_leaves_body_empty():
    v = _structural_features({"type": "x"}, _CODE_BODY)
    assert v[3] == 0.0  # scoped
    assert v[11] == 0.0  # body_len
    assert v[7] == 1.0  # pragma08 still detected from whole code


def test_structural_guard_signature_flagged():
    v = _structural_features({"type": "x", "function": "foo", "line": 3}, _CODE_BODY)
    assert v[4] == 1.0  # has_guard (onlyOwner in signature)


_CODE_TRANSFER = (
    "pragma solidity ^0.8.0;\n"
    "contract C {\n"
    "  function p() public {\n"
    "    token.transfer(to, amt);\n"
    "    payable(x).transfer(1);\n"
    "  }\n"
    "}"
)


def test_structural_native_transfer_single_arg_only():
    two_arg = _structural_features({"type": "x", "function": "p", "line": 4}, _CODE_TRANSFER)
    native = _structural_features({"type": "x", "function": "p", "line": 5}, _CODE_TRANSFER)
    assert two_arg[9] == 0.0  # token.transfer(to, amt) is not a native send
    assert native[9] == 1.0  # payable(x).transfer(1) is


def test_structural_checked_window_detects_require():
    code = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function q() public {\n"
        "    (bool ok,) = a.call('');\n"
        '    require(ok, "fail");\n'
        "  }\n"
        "}"
    )
    v = _structural_features({"type": "x", "function": "q", "line": 4}, code)
    assert v[8] == 1.0  # checked: require(ok ...) within the flagged window


def test_structural_safeerc_flagged():
    code = (
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  function s() public {\n"
        "    IERC20(t).safeTransfer(to, amt);\n"
        "  }\n"
        "}"
    )
    v = _structural_features({"type": "x", "function": "s", "line": 4}, code)
    assert v[10] == 1.0  # safeerc


def test_structural_body_len_clamped_to_one():
    big = "function big() public {\n" + "    uint a = 1;\n" * 300 + "}"
    code = "pragma solidity ^0.8.0;\ncontract C {\n" + big + "\n}"
    v = _structural_features({"type": "x", "function": "big", "line": 3}, code)
    assert v[11] == 1.0  # body_len min(len/2000, 1.0) clamps a huge body


# --------------------------------------------------------------------------- #
# train() loud-failure contract (scikit-learn absent in this environment)
# --------------------------------------------------------------------------- #


def test_train_requires_dependencies(monkeypatch, tmp_path):
    # Force the import to fail deterministically regardless of the installed env.
    monkeypatch.setitem(sys.modules, "joblib", None)
    dataset = tmp_path / "data.jsonl"
    dataset.write_text("")
    with pytest.raises(ImportError):
        tr.train(str(dataset))


def test_default_model_path_points_into_models_dir():
    assert DEFAULT_MODEL_PATH.endswith("triage_model.joblib")
    assert "models" in DEFAULT_MODEL_PATH
