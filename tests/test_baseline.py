"""
Tests for the finding baseline & suppression engine (miesc.core.baseline).

Covers:
- Content-based fingerprints (rule_id + normalized file + message hash)
- Line-shift stability (same finding at a different line == same fingerprint)
- Deterministic, golden-file serialization (same findings -> identical JSON)
- generate / save / load round-trip
- diff_against_baseline: new / known / fixed partitioning

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json

import pytest

from miesc.core.baseline import (
    Baseline,
    diff_against_baseline,
    fingerprint,
    generate_baseline,
    load_baseline,
    normalize_finding,
)


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


# =============================================================================
# Fingerprinting
# =============================================================================


class TestFingerprint:
    def test_fingerprint_is_deterministic(self):
        f = _finding()
        assert fingerprint(f) == fingerprint(dict(f))

    def test_fingerprint_is_line_shift_stable(self):
        """Same finding at a different line must yield the SAME fingerprint."""
        top = _finding(line=15)
        shifted = _finding(line=137)
        assert fingerprint(top) == fingerprint(shifted)

    def test_fingerprint_changes_with_rule_id(self):
        assert fingerprint(_finding(rule="reentrancy")) != fingerprint(
            _finding(rule="unchecked-call")
        )

    def test_fingerprint_changes_with_file(self):
        assert fingerprint(_finding(file="A.sol")) != fingerprint(_finding(file="B.sol"))

    def test_fingerprint_changes_with_message(self):
        assert fingerprint(_finding(message="one")) != fingerprint(_finding(message="two"))

    def test_fingerprint_ignores_message_whitespace(self):
        a = _finding(message="Reentrancy in   withdraw()")
        b = _finding(message="Reentrancy in withdraw()")
        assert fingerprint(a) == fingerprint(b)

    def test_normalized_path_equivalence(self):
        """./contracts/Bank.sol and contracts/Bank.sol match."""
        a = _finding(file="./contracts/Bank.sol")
        b = _finding(file="contracts/Bank.sol")
        assert fingerprint(a) == fingerprint(b)

    def test_flat_file_key_supported(self):
        """A finding using flat 'file' instead of nested location still resolves."""
        nested = _finding(file="X.sol")
        flat = {"type": "reentrancy", "severity": "high",
                "message": "Reentrancy in withdraw()", "file": "X.sol"}
        assert fingerprint(nested) == fingerprint(flat)

    def test_normalize_finding_fields(self):
        norm = normalize_finding(_finding(rule="reentrancy", file="a/b.sol"))
        assert norm["rule_id"] == "reentrancy"
        assert norm["file"] == "a/b.sol"
        assert norm["severity"] == "high"
        assert len(norm["message_hash"]) == 16


# =============================================================================
# Serialization determinism (golden-file property)
# =============================================================================


class TestSerialization:
    def test_same_findings_produce_identical_json(self):
        findings = [_finding(rule="a"), _finding(rule="b"), _finding(rule="c")]
        j1 = generate_baseline(findings).to_json()
        j2 = generate_baseline(findings).to_json()
        assert j1 == j2

    def test_input_order_does_not_change_output(self):
        """Serialization is sorted by fingerprint -> input order is irrelevant."""
        a, b, c = _finding(rule="a"), _finding(rule="b"), _finding(rule="c")
        j1 = generate_baseline([a, b, c]).to_json()
        j2 = generate_baseline([c, a, b]).to_json()
        assert j1 == j2

    def test_json_is_sorted_and_valid(self):
        findings = [_finding(rule="zzz"), _finding(rule="aaa")]
        payload = generate_baseline(findings).to_json()
        data = json.loads(payload)
        assert data["version"]
        assert data["count"] == 2
        fps = list(data["fingerprints"].keys())
        assert fps == sorted(fps)
        assert payload.endswith("\n")

    def test_duplicate_findings_collapse(self):
        findings = [_finding(), _finding(), _finding()]
        baseline = generate_baseline(findings)
        assert len(baseline) == 1


# =============================================================================
# Save / load round-trip
# =============================================================================


class TestRoundTrip:
    def test_save_and_load(self, tmp_path):
        findings = [_finding(rule="a"), _finding(rule="b")]
        original = generate_baseline(findings)
        path = tmp_path / ".miesc-baseline.json"
        original.save(path)

        loaded = load_baseline(path)
        assert isinstance(loaded, Baseline)
        assert set(loaded.entries) == set(original.entries)
        assert loaded.to_json() == original.to_json()

    def test_loaded_entry_metadata_preserved(self, tmp_path):
        f = _finding(rule="reentrancy", file="contracts/Bank.sol")
        path = tmp_path / "b.json"
        generate_baseline([f]).save(path)

        loaded = load_baseline(path)
        entry = next(iter(loaded.entries.values()))
        assert entry.rule_id == "reentrancy"
        assert entry.file == "contracts/Bank.sol"
        assert entry.severity == "high"


# =============================================================================
# diff_against_baseline
# =============================================================================


class TestDiff:
    def test_all_known_when_identical(self):
        findings = [_finding(rule="a"), _finding(rule="b")]
        baseline = generate_baseline(findings)
        diff = diff_against_baseline(findings, baseline)
        assert len(diff["known"]) == 2
        assert diff["new"] == []
        assert diff["fixed"] == []

    def test_new_finding_detected(self):
        baseline = generate_baseline([_finding(rule="a")])
        current = [_finding(rule="a"), _finding(rule="b")]
        diff = diff_against_baseline(current, baseline)
        assert len(diff["new"]) == 1
        assert diff["new"][0]["type"] == "b"
        assert len(diff["known"]) == 1
        assert diff["fixed"] == []

    def test_fixed_finding_detected(self):
        baseline = generate_baseline([_finding(rule="a"), _finding(rule="b")])
        current = [_finding(rule="a")]
        diff = diff_against_baseline(current, baseline)
        assert diff["new"] == []
        assert len(diff["known"]) == 1
        assert len(diff["fixed"]) == 1
        assert diff["fixed"][0].rule_id == "b"

    def test_line_shift_stays_known(self):
        """A known finding that moved to a new line is NOT re-flagged as new."""
        baseline = generate_baseline([_finding(line=15)])
        current = [_finding(line=142)]  # same finding, shifted down
        diff = diff_against_baseline(current, baseline)
        assert diff["new"] == []
        assert len(diff["known"]) == 1
        assert diff["fixed"] == []

    def test_mixed_partition(self):
        baseline = generate_baseline([_finding(rule="a"), _finding(rule="b")])
        current = [
            _finding(rule="a", line=99),  # known (line-shifted)
            _finding(rule="c"),           # new
        ]
        diff = diff_against_baseline(current, baseline)
        assert [f["type"] for f in diff["known"]] == ["a"]
        assert [f["type"] for f in diff["new"]] == ["c"]
        assert [e.rule_id for e in diff["fixed"]] == ["b"]

    def test_empty_current_all_fixed(self):
        baseline = generate_baseline([_finding(rule="a"), _finding(rule="b")])
        diff = diff_against_baseline([], baseline)
        assert diff["new"] == []
        assert diff["known"] == []
        assert len(diff["fixed"]) == 2

    def test_empty_baseline_all_new(self):
        empty = Baseline(entries={})
        current = [_finding(rule="a"), _finding(rule="b")]
        diff = diff_against_baseline(current, empty)
        assert len(diff["new"]) == 2
        assert diff["known"] == []
        assert diff["fixed"] == []
