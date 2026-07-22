"""Unit tests for the composite security score + badge.

Pin the invariants that make the score meaningful and stable: a clean contract is
100/A, severity and confidence both move the number in the right direction, the
score never leaves [0, 100], and the badge is well-formed self-contained SVG.
"""

import unittest

from miesc.core.scoring import (
    SEVERITY_PENALTY,
    badge_endpoint,
    badge_svg,
    compute_score,
    extract_findings,
)


def _f(severity, confidence=None):
    d = {"severity": severity}
    if confidence is not None:
        d["confidence"] = confidence
    return d


class TestComputeScore(unittest.TestCase):
    def test_clean_contract_is_perfect(self):
        s = compute_score([])
        self.assertEqual(s.score, 100)
        self.assertEqual(s.grade, "A")
        self.assertEqual(s.total_findings, 0)

    def test_confident_critical_fails_the_grade(self):
        s = compute_score([_f("critical", 1.0)])
        self.assertLess(s.score, 70)
        self.assertIn(s.grade, ("D", "F"))

    def test_confidence_softens_the_penalty(self):
        confident = compute_score([_f("critical", 1.0)]).score
        unsure = compute_score([_f("critical", 0.2)]).score
        self.assertGreater(unsure, confident, "a low-confidence critical hurts less")

    def test_more_severe_hurts_more(self):
        high = compute_score([_f("high", 1.0)]).score
        low = compute_score([_f("low", 1.0)]).score
        self.assertLess(high, low)

    def test_score_is_bounded_below_at_zero(self):
        s = compute_score([_f("critical", 1.0) for _ in range(50)])
        self.assertEqual(s.score, 0)
        self.assertEqual(s.grade, "F")

    def test_unscored_findings_treated_as_confident(self):
        s = compute_score([_f("high")])  # no confidence key
        self.assertFalse(s.weighted_by_confidence)
        self.assertEqual(s.penalty, SEVERITY_PENALTY["high"])

    def test_weighted_flag_set_when_confidence_present(self):
        s = compute_score([_f("high", 0.5)])
        self.assertTrue(s.weighted_by_confidence)

    def test_severity_counts_and_unknown_severity(self):
        s = compute_score([_f("high", 1.0), _f("high", 1.0), _f("weird", 1.0)])
        self.assertEqual(s.severity_counts["high"], 2)
        self.assertEqual(s.severity_counts["weird"], 1)

    def test_grade_boundaries(self):
        self.assertEqual(compute_score([]).grade, "A")  # 100
        # a single medium (5 pts) -> 95 -> still A
        self.assertEqual(compute_score([_f("medium", 1.0)]).grade, "A")

    def test_bad_confidence_value_falls_back(self):
        s = compute_score([{"severity": "high", "confidence": "oops"}])
        self.assertEqual(s.penalty, SEVERITY_PENALTY["high"])


class TestExtractFindings(unittest.TestCase):
    def test_flattens_results(self):
        results = [
            {"tool": "slither", "findings": [_f("high"), _f("low")]},
            {"tool": "mythril", "findings": [_f("critical")]},
            {"tool": "empty", "findings": []},
        ]
        self.assertEqual(len(extract_findings(results)), 3)

    def test_missing_findings_key(self):
        self.assertEqual(extract_findings([{"tool": "x"}]), [])


class TestBadge(unittest.TestCase):
    def test_endpoint_schema(self):
        s = compute_score([_f("high", 0.9)])
        b = badge_endpoint(s)
        self.assertEqual(b["schemaVersion"], 1)
        self.assertEqual(b["label"], "MIESC security")
        self.assertTrue(b["message"].startswith(str(s.score)))
        self.assertTrue(b["color"].startswith("#"))

    def test_svg_is_wellformed_and_self_contained(self):
        s = compute_score([_f("medium", 0.5)])
        svg = badge_svg(s)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.rstrip().endswith("</svg>"))
        self.assertIn("MIESC security", svg)
        self.assertIn(f"{s.score} {s.grade}", svg)
        self.assertNotIn("http://", svg.replace("http://www.w3.org", ""))  # no external refs

    def test_to_dict_roundtrip(self):
        s = compute_score([_f("high", 0.9)])
        d = s.to_dict()
        self.assertEqual(d["score"], s.score)
        self.assertEqual(d["grade"], s.grade)


if __name__ == "__main__":
    unittest.main()
