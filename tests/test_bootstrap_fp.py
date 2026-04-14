"""
Unit tests for scripts/bootstrap_fp_dataset.py label_finding() heuristic.

The bootstrap script labels MIESC scan findings as TP/FP using three rules:
  1. Known noise types (useless-public-function, constants-...) -> FP
  2. HIGH/CRITICAL finding whose canonical category matches GT -> TP
  3. Info severity with unrelated type -> FP

Testing the heuristic in isolation lets us catch mislabels without running
a full MIESC scan.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

# scripts/ isn't a package — load the module directly
_spec = importlib.util.spec_from_file_location(
    "bootstrap_fp_dataset",
    Path(__file__).parent.parent / "scripts" / "bootstrap_fp_dataset.py",
)
bootstrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bootstrap)

label_finding = bootstrap.label_finding
FP_TYPES = bootstrap.FP_TYPES


# ---------------------------------------------------------------------------
# Rule 1: known-noise types -> FP
# ---------------------------------------------------------------------------


class TestNoiseTypes:
    @pytest.mark.parametrize("ftype", [
        "solc-version",
        "naming-convention",
        "useless-public-function",
        "constants-instead-of-literals",
        "push-zero-opcode",
        "unspecific-solidity-pragma",
        "magic-number",
    ])
    def test_known_noise_types_marked_fp(self, ftype):
        f = {"type": ftype, "severity": "low"}
        label, reason = label_finding(f, gt_class="reentrancy")
        assert label is False
        assert "noise-type" in reason or "noise-substring" in reason

    def test_noise_wins_over_severity(self):
        """Even HIGH severity on a known-noise type stays as FP — the
        type is what matters for these detectors."""
        f = {"type": "useless-public-function", "severity": "HIGH"}
        label, reason = label_finding(f, gt_class="access_control")
        assert label is False

    def test_noise_substring_match(self):
        """Unknown detectors that contain a known noise substring should
        still be marked as FP."""
        f = {"type": "custom-useless-public-function-variant", "severity": "low"}
        label, reason = label_finding(f, gt_class="reentrancy")
        assert label is False


# ---------------------------------------------------------------------------
# Rule 2a: canonical-category match (any severity) -> TP
# ---------------------------------------------------------------------------


class TestCanonicalMatch:
    def test_reentrancy_eth_matches_reentrancy_class(self):
        f = {"type": "reentrancy-eth", "severity": "High"}
        label, reason = label_finding(f, gt_class="reentrancy")
        assert label is True
        assert "canonical-match" in reason

    def test_arbitrary_send_eth_matches_access_control(self):
        """Before v5.1.7 Gate 2, this would have missed because the old
        heuristic substring-matched 'access' in ftype. Now taxonomy
        knows arbitrary-send-eth -> ACCESS_CONTROL."""
        f = {"type": "arbitrary-send-eth", "severity": "High"}
        label, reason = label_finding(f, gt_class="access_control")
        assert label is True
        assert "canonical-match:access_control" in reason

    def test_medium_severity_still_counts_as_tp_on_match(self):
        """SmartBugs contracts are victim-side — any detector finding the
        intended vuln is a TP regardless of reported severity."""
        f = {"type": "reentrancy-eth", "severity": "Medium"}
        label, reason = label_finding(f, gt_class="reentrancy", source="smartbugs")
        assert label is True


# ---------------------------------------------------------------------------
# Rule 2b: keyword fallback for unmapped taxonomy
# ---------------------------------------------------------------------------


class TestKeywordFallback:
    def test_unknown_type_with_matching_substring(self):
        f = {"type": "custom-reentrancy-variant", "severity": "critical"}
        label, reason = label_finding(f, gt_class="reentrancy")
        # Canonical taxonomy catches this via the substring fallback -> TP
        assert label is True

    def test_unknown_type_without_matching_substring(self):
        f = {"type": "exotic-custom-detector", "severity": "High"}
        # No canonical match, no keyword match -> None (skipped)
        result = label_finding(f, gt_class="reentrancy")
        assert result is None


# ---------------------------------------------------------------------------
# Rule 3b: info severity on off-category -> FP
# ---------------------------------------------------------------------------


class TestInfoOffClass:
    def test_info_severity_unrelated_type_fp(self):
        f = {"type": "different-detector", "severity": "info"}
        result = label_finding(f, gt_class="reentrancy")
        # Info-severity detector unrelated to GT class → FP (noise)
        if result is not None:
            label, reason = result
            assert label is False

    def test_info_severity_matching_type_NOT_fp(self):
        """An info-level finding that DOES match the GT class is NOT dropped
        as off-class-info; it's either canonical-match or None."""
        f = {"type": "reentrancy-benign", "severity": "info"}
        result = label_finding(f, gt_class="reentrancy")
        # Either canonical-match (TP) or None — but MUST NOT be an FP label
        if result is not None:
            label, _ = result
            assert label is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_type_returns_none(self):
        f = {"type": "", "severity": "High"}
        assert label_finding(f, gt_class="reentrancy") is None

    def test_missing_type_falls_back_to_check(self):
        f = {"check": "reentrancy-eth", "severity": "High"}
        label, _ = label_finding(f, gt_class="reentrancy")
        assert label is True

    def test_no_gt_class_still_labels_known_noise(self):
        """Without GT class we can't compute TPs, but we can still mark
        universal noise as FP."""
        f = {"type": "useless-public-function", "severity": "low"}
        label, _ = label_finding(f, gt_class=None)
        assert label is False


# ---------------------------------------------------------------------------
# FP_TYPES registry contract
# ---------------------------------------------------------------------------


class TestFpTypesRegistry:
    def test_all_entries_are_strings(self):
        for t in FP_TYPES:
            assert isinstance(t, str)
            assert t

    def test_no_duplicates(self):
        assert len(FP_TYPES) == len(set(FP_TYPES))

    def test_covers_common_aderyn_noise(self):
        """Aderyn's top info detectors must be in the noise set — otherwise
        the bootstrap generates too many unlabeled rows and imbalances
        the classifier seed."""
        expected = {
            "useless-public-function",
            "constants-instead-of-literals",
            "unspecific-solidity-pragma",
            "push-zero-opcode",
        }
        assert expected.issubset(FP_TYPES)
