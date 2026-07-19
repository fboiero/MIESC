"""Unit tests for the per-finding confidence calibrator.

The calibrator blends detector reliability priors (reused from the correlation
engine), cross-tool agreement, and the false-positive signal. These tests pin the
invariants that make the score meaningful: agreement raises it, the FP signal
lowers it, single-tool critical findings are capped, and levels bucket correctly.
"""

import unittest

from miesc.core.confidence import (
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    ConfidenceCalibrator,
    confidence_level,
)


class TestConfidenceCalibrator(unittest.TestCase):
    def setUp(self):
        self.cal = ConfidenceCalibrator()

    def test_more_tools_raise_confidence(self):
        one = self.cal.calibrate(["slither"], "unchecked-call").score
        three = self.cal.calibrate(["slither", "mythril", "aderyn"], "unchecked-call").score
        self.assertGreater(three, one, "cross-tool agreement must raise confidence")

    def test_fp_signal_lowers_confidence(self):
        clean = self.cal.calibrate(["slither"], "solc-version", fp_probability=0.0).score
        benign = self.cal.calibrate(["slither"], "solc-version", fp_probability=0.8).score
        self.assertLess(benign, clean, "a high FP probability must pull confidence down")
        self.assertLess(benign, 0.3, "a likely-benign single-tool finding should score low")

    def test_benign_single_tool_is_low_level(self):
        # The motivating case: solc-version on modern code, one tool, likely benign.
        r = self.cal.calibrate(["slither"], "solc-version", fp_probability=0.8)
        self.assertEqual(r.level, "low")

    def test_agreeing_real_vuln_is_high_level(self):
        # Three tools agree on reentrancy with a low FP signal -> high confidence.
        r = self.cal.calibrate(
            ["slither", "mythril", "aderyn"], "reentrancy-eth", fp_probability=0.05
        )
        self.assertEqual(r.level, "high")
        self.assertEqual(r.tool_count, 3)
        self.assertEqual(set(r.contributing_tools), {"slither", "mythril", "aderyn"})

    def test_single_tool_cross_validation_pattern_is_capped(self):
        # reentrancy is cross-validation-required: one tool cannot exceed the cap
        # even with a perfect prior and no FP signal.
        r = self.cal.calibrate(["certora"], "reentrancy", fp_probability=0.0)
        self.assertLessEqual(r.score, 0.60, "single tool on a critical pattern must be capped")

    def test_multi_tool_cross_validation_pattern_not_capped(self):
        # With two tools the cap no longer applies.
        r = self.cal.calibrate(["slither", "mythril"], "reentrancy", fp_probability=0.0)
        self.assertGreater(r.score, 0.60)

    def test_unknown_tool_uses_neutral_prior(self):
        r = self.cal.calibrate(["some-unknown-tool"], "reentrancy-events", fp_probability=0.0)
        # neutral prior 0.50, single-tool critical cap 0.60 -> stays at prior
        self.assertAlmostEqual(r.score, 0.50, places=2)

    def test_empty_tools_does_not_crash(self):
        r = self.cal.calibrate([], "", fp_probability=None)
        self.assertEqual(r.tool_count, 1)
        self.assertGreaterEqual(r.score, 0.0)

    def test_duplicate_tools_counted_once(self):
        r = self.cal.calibrate(["slither", "slither"], "unchecked-call")
        self.assertEqual(r.tool_count, 1)

    def test_score_is_bounded(self):
        r = self.cal.calibrate(
            ["certora", "smtchecker", "echidna", "foundry"], "unchecked-call", fp_probability=0.0
        )
        self.assertLessEqual(r.score, 0.99)
        self.assertGreaterEqual(r.score, 0.0)

    def test_level_thresholds(self):
        self.assertEqual(confidence_level(HIGH_THRESHOLD), "high")
        self.assertEqual(confidence_level(MEDIUM_THRESHOLD), "medium")
        self.assertEqual(confidence_level(MEDIUM_THRESHOLD - 0.01), "low")


if __name__ == "__main__":
    unittest.main()
