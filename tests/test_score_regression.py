"""Tests for the `miesc score` regression gate (--against / --fail-on-regression).

The regression gate must: show the delta vs a baseline, exit non-zero only when the
score actually dropped beyond tolerance, accept both a results JSON and a score JSON
as the baseline, and never fire on an improvement or a within-tolerance dip.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from click.testing import CliRunner

from miesc.cli.commands.score import _load_baseline_score, score


def _results(*findings):
    return {"results": [{"tool": "slither", "findings": list(findings)}]}


def _f(severity, confidence=1.0):
    return {"severity": severity, "confidence": confidence, "title": severity}


class TestRegressionGate(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name, obj):
        p = self.dir / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def test_regression_fails_the_gate(self):
        # baseline: clean (score 100). current: a confident critical (much lower).
        baseline = self._write("base.json", _results())
        current = self._write("cur.json", _results(_f("critical", 1.0)))
        res = self.runner.invoke(score, [current, "--against", baseline, "--fail-on-regression"])
        self.assertEqual(res.exit_code, 1, res.output)
        self.assertIn("regress", res.output.lower())

    def test_improvement_passes(self):
        # baseline: a critical. current: clean -> improved, must not fail.
        baseline = self._write("base.json", _results(_f("critical", 1.0)))
        current = self._write("cur.json", _results())
        res = self.runner.invoke(score, [current, "--against", baseline, "--fail-on-regression"])
        self.assertEqual(res.exit_code, 0, res.output)

    def test_within_tolerance_passes(self):
        # a single medium (~5 pt drop) tolerated when tolerance covers it.
        baseline = self._write("base.json", _results())
        current = self._write("cur.json", _results(_f("medium", 1.0)))
        res = self.runner.invoke(
            score,
            [current, "--against", baseline, "--fail-on-regression", "--tolerance", "10"],
        )
        self.assertEqual(res.exit_code, 0, res.output)

    def test_delta_shown_without_gate(self):
        # --against alone shows the delta but never fails.
        baseline = self._write("base.json", _results(_f("high", 1.0)))
        current = self._write("cur.json", _results(_f("critical", 1.0)))
        res = self.runner.invoke(score, [current, "--against", baseline])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertIn("baseline", res.output.lower())

    def test_baseline_can_be_a_score_json(self):
        # a score JSON (from `miesc score --json`) is a valid baseline.
        score_json = self._write("score.json", {"score": 100, "grade": "A"})
        current = self._write("cur.json", _results(_f("high", 1.0)))
        res = self.runner.invoke(score, [current, "--against", score_json, "--fail-on-regression"])
        self.assertEqual(res.exit_code, 1, res.output)


class TestLoadBaselineScore(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, obj):
        p = self.dir / "b.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def test_score_json_used_directly(self):
        self.assertEqual(_load_baseline_score(self._write({"score": 73, "grade": "C"})), 73)

    def test_results_json_scored(self):
        # clean results -> 100
        self.assertEqual(_load_baseline_score(self._write({"results": []})), 100)


if __name__ == "__main__":
    unittest.main()
