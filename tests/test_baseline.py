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

from miesc.core.baseline import (
    Baseline,
    _get,
    _normalize_message,
    _normalize_symbol,
    diff_against_baseline,
    fingerprint,
    generate_baseline,
    load_baseline,
    normalize_finding,
)

# =============================================================================
# Helpers
# =============================================================================


def _finding(
    rule="reentrancy",
    file="contracts/Bank.sol",
    line=15,
    message="Reentrancy in withdraw()",
    function="",
):
    location = {"file": file, "line": line}
    if function:
        location["function"] = function
    return {
        "type": rule,
        "severity": "high",
        "message": message,
        "location": location,
        "tool": "slither",
    }


class _AttrFinding:
    """Attribute-based finding shape (e.g. a dataclass), as opposed to a dict."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


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

    def test_fingerprint_ignores_embedded_message_line_reference(self):
        a = _finding(message="Reentrancy in withdraw() line 42")
        b = _finding(message="Reentrancy in withdraw() line 137")
        assert fingerprint(a) == fingerprint(b)

    def test_fingerprint_changes_with_function_symbol(self):
        a = _finding(message="Unchecked external call", function="withdraw")
        b = _finding(message="Unchecked external call", function="claim")
        assert fingerprint(a) != fingerprint(b)

    def test_normalized_path_equivalence(self):
        """./contracts/Bank.sol and contracts/Bank.sol match."""
        a = _finding(file="./contracts/Bank.sol")
        b = _finding(file="contracts/Bank.sol")
        assert fingerprint(a) == fingerprint(b)

    def test_flat_file_key_supported(self):
        """A finding using flat 'file' instead of nested location still resolves."""
        nested = _finding(file="X.sol")
        flat = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Reentrancy in withdraw()",
            "file": "X.sol",
        }
        assert fingerprint(nested) == fingerprint(flat)

    def test_normalize_finding_fields(self):
        norm = normalize_finding(_finding(rule="reentrancy", file="a/b.sol", function="withdraw"))
        assert norm["rule_id"] == "reentrancy"
        assert norm["file"] == "a/b.sol"
        assert norm["symbol"] == "withdraw"
        assert norm["severity"] == "high"
        assert len(norm["message_hash"]) == 16


# =============================================================================
# Attribute-based findings (non-dict FindingLike shape)
# =============================================================================


class TestAttributeBasedFindings:
    def test_reads_fields_from_attributes(self):
        f = _AttrFinding(type="reentrancy", message="Reentrancy in withdraw()", severity="HIGH")
        norm = normalize_finding(f)
        assert norm["rule_id"] == "reentrancy"
        assert norm["message"] == "Reentrancy in withdraw()"
        assert norm["severity"] == "high"

    def test_defaults_when_no_attributes_present(self):
        norm = normalize_finding(_AttrFinding())
        assert norm["rule_id"] == "unknown"
        assert norm["message"] == ""
        assert norm["file"] == ""
        assert norm["symbol"] == ""
        assert norm["severity"] == ""

    def test_falls_back_through_attribute_key_order(self):
        # No "function" attribute -> falls through to "function_name".
        norm = normalize_finding(_AttrFinding(function_name="claim"))
        assert norm["symbol"] == "claim"


# =============================================================================
# Field fallback keys (rule_id / message / file / symbol resolution order)
# =============================================================================


class TestFieldFallbackKeys:
    def test_rule_id_falls_back_to_rule_id_key(self):
        assert normalize_finding({"rule_id": "unchecked-call"})["rule_id"] == "unchecked-call"

    def test_rule_id_falls_back_to_check_key(self):
        assert normalize_finding({"check": "unchecked-call"})["rule_id"] == "unchecked-call"

    def test_rule_id_falls_back_to_title_key(self):
        assert normalize_finding({"title": "Unchecked Call"})["rule_id"] == "Unchecked Call"

    def test_message_falls_back_to_description_key(self):
        norm = normalize_finding({"description": "External call is unchecked"})
        assert norm["message"] == "External call is unchecked"

    def test_message_falls_back_to_title_key(self):
        norm = normalize_finding({"title": "Unchecked Call"})
        assert norm["message"] == "Unchecked Call"

    def test_severity_is_lowercased(self):
        assert normalize_finding({"severity": "HIGH"})["severity"] == "high"

    def test_extract_file_falls_back_to_file_path_key_in_location(self):
        f = {"location": {"file_path": "contracts/Bank.sol"}}
        assert normalize_finding(f)["file"] == "contracts/Bank.sol"

    def test_extract_file_falls_back_to_filename_key_in_location(self):
        f = {"location": {"filename": "contracts/Bank.sol"}}
        assert normalize_finding(f)["file"] == "contracts/Bank.sol"

    def test_extract_file_falls_back_to_flat_file_path_key(self):
        assert (
            normalize_finding({"file_path": "contracts/Bank.sol"})["file"] == "contracts/Bank.sol"
        )

    def test_extract_file_falls_back_to_flat_filename_key(self):
        assert normalize_finding({"filename": "contracts/Bank.sol"})["file"] == "contracts/Bank.sol"

    def test_extract_symbol_falls_back_to_function_name_key_in_location(self):
        f = {"location": {"function_name": "withdraw"}}
        assert normalize_finding(f)["symbol"] == "withdraw"

    def test_extract_symbol_falls_back_to_symbol_key_in_location(self):
        f = {"location": {"symbol": "withdraw"}}
        assert normalize_finding(f)["symbol"] == "withdraw"

    def test_extract_symbol_falls_back_to_contract_key_in_location(self):
        f = {"location": {"contract": "Bank"}}
        assert normalize_finding(f)["symbol"] == "Bank"

    def test_extract_symbol_falls_back_to_flat_function_name_key(self):
        assert normalize_finding({"function_name": "withdraw"})["symbol"] == "withdraw"

    def test_extract_symbol_falls_back_to_flat_symbol_key(self):
        assert normalize_finding({"symbol": "withdraw"})["symbol"] == "withdraw"

    def test_extract_symbol_falls_back_to_flat_contract_key(self):
        assert normalize_finding({"contract": "Bank"})["symbol"] == "Bank"

    def test_extract_symbol_prefers_function_over_function_name(self):
        f = {"function": "withdraw", "function_name": "other"}
        assert normalize_finding(f)["symbol"] == "withdraw"


# =============================================================================
# Private normalization helpers: normalize_finding()/fingerprint() only expose
# a one-way message_hash, not the normalized string, so whitespace-collapse
# and line-ref-stripping behavior can only be pinned by testing the private
# helpers directly.
# =============================================================================


class TestPrivateNormalizationHelpers:
    def test_get_treats_empty_string_dict_value_as_missing(self):
        assert _get({"message": "", "title": "fallback"}, "message", "title") == "fallback"

    def test_get_treats_empty_string_attribute_value_as_missing(self):
        f = _AttrFinding(message="", title="fallback")
        assert _get(f, "message", "title") == "fallback"

    def test_normalize_symbol_collapses_whitespace_to_single_space(self):
        assert _normalize_symbol("with   draw") == "with draw"

    def test_normalize_message_strips_line_reference_entirely(self):
        assert _normalize_message("Reentrancy (line 42)") == "Reentrancy ()"

    def test_normalize_message_collapses_whitespace_to_single_space(self):
        assert _normalize_message("a   b") == "a b"

    def test_fingerprint_is_16_hex_chars(self):
        assert len(fingerprint(_finding())) == 16


# =============================================================================
# _normalize_path edge cases (via normalize_finding()["file"])
# =============================================================================


class TestNormalizePathEdgeCases:
    def test_empty_path_stays_empty(self):
        assert normalize_finding({"file": ""})["file"] == ""

    def test_backslashes_become_forward_slashes(self):
        assert normalize_finding({"file": "contracts\\Bank.sol"})["file"] == "contracts/Bank.sol"

    def test_absolute_path_prefix_preserved(self):
        assert normalize_finding({"file": "/contracts/Bank.sol"})["file"] == "/contracts/Bank.sol"

    def test_double_slashes_collapse(self):
        assert normalize_finding({"file": "contracts//Bank.sol"})["file"] == "contracts/Bank.sol"

    def test_mid_path_dot_segment_collapses(self):
        f = {"file": "contracts/./Bank.sol"}
        assert normalize_finding(f)["file"] == "contracts/Bank.sol"


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
            _finding(rule="c"),  # new
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
