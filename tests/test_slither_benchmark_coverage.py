"""Coverage tests for SlitherBenchmarkRunner.

Exercises the full run/analyze/parse/match/aggregate pipeline with the real
module logic. The only boundary mocked is ``subprocess.run`` (the Slither
invocation); every Slither output is a realistic JSON payload and every test
asserts a meaningful parsed/aggregated property rather than mere execution.
No network, no LLM, no real Slither binary.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from miesc.benchmark.dataset_loader import (
    GroundTruth,
    VulnerabilityCategory,
    VulnerableContract,
)
from miesc.benchmark.slither_benchmark import (
    SlitherBenchmarkRunner,
    run_slither_benchmark,
)


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #
def _contract(path: str, category=VulnerabilityCategory.REENTRANCY, lines=None):
    """A VulnerableContract with one ground-truth annotation."""
    gt = GroundTruth(category=category, lines=lines or [10])
    return VulnerableContract(
        name=Path(path).stem,
        path=path,
        source_code="contract C {}",
        pragma_version="0.8.0",
        vulnerabilities=[gt],
        source_url="",
        dataset="test",
    )


def _detector(check="reentrancy-eth", filename="reentrancy.sol", lines=None, **extra):
    """A Slither detector dict as it appears under results.detectors."""
    det = {
        "check": check,
        "impact": "High",
        "confidence": "Medium",
        "description": f"{check} finding",
        "elements": [
            {
                "type": "function",
                "name": "withdraw",
                "source_mapping": {
                    "filename_relative": filename,
                    "filename_absolute": f"/abs/{filename}",
                    "lines": lines if lines is not None else [10, 11, 12],
                },
            }
        ],
    }
    det.update(extra)
    return det


def _slither_json(detectors, success=True):
    """Single-line Slither JSON payload (one JSON object per line)."""
    return json.dumps({"success": success, "error": None, "results": {"detectors": detectors}})


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["slither"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# --------------------------------------------------------------------------- #
# _analyze_with_slither: happy path + output routing                          #
# --------------------------------------------------------------------------- #
class TestAnalyzeHappyPath:
    def test_parses_stdout_json_into_true_positive(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])
        payload = _slither_json([_detector(filename="reentrancy.sol", lines=[10])])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            result = runner._analyze_with_slither(contract)

        assert result.error is None
        assert len(result.detected_findings) == 1
        assert result.detected_findings[0]["type"] == "reentrancy-eth"
        # reentrancy detector on a reentrancy ground truth at line 10 -> TP
        assert len(result.true_positives) == 1
        assert len(result.false_positives) == 0
        assert len(result.false_negatives) == 0
        assert result.analysis_time_ms >= 0

    def test_json_on_stderr_is_used_when_stdout_empty(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        payload = _slither_json([_detector(lines=[10])])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stderr=payload)):
            result = runner._analyze_with_slither(_contract(path, lines=[10]))

        assert result.error is None
        assert len(result.detected_findings) == 1

    def test_trailing_non_json_line_is_skipped(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        payload = _slither_json([_detector(lines=[10])]) + "\nCompilation warnings here"

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            result = runner._analyze_with_slither(_contract(path, lines=[10]))

        assert result.error is None
        assert len(result.detected_findings) == 1


# --------------------------------------------------------------------------- #
# _analyze_with_slither: graceful degradation (each error is None + full FN)   #
# --------------------------------------------------------------------------- #
class TestAnalyzeDegradation:
    def test_empty_output_yields_no_findings(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed()):
            result = runner._analyze_with_slither(contract)

        assert result.error is None
        assert result.detected_findings == []
        # nothing detected -> the single ground truth is a false negative
        assert result.false_negatives == contract.vulnerabilities

    def test_malformed_json_line_is_swallowed(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout="{not valid json")):
            result = runner._analyze_with_slither(contract)

        assert result.error is None
        assert result.detected_findings == []
        assert result.false_negatives == contract.vulnerabilities

    def test_valid_json_without_results_key(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])
        payload = json.dumps({"success": False, "error": "compile failed"})

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            result = runner._analyze_with_slither(contract)

        assert result.error is None
        assert result.detected_findings == []
        assert result.false_negatives == contract.vulnerabilities

    def test_timeout_sets_timeout_error(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])

        runner = SlitherBenchmarkRunner()
        with patch.object(
            subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="slither", timeout=60)
        ):
            result = runner._analyze_with_slither(contract)

        assert result.error == "timeout"
        assert result.detected_findings == []
        assert result.analysis_time_ms >= 0

    def test_generic_exception_captured_as_error(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", side_effect=RuntimeError("boom")):
            result = runner._analyze_with_slither(contract)

        assert result.error == "boom"
        assert result.detected_findings == []
        assert result.analysis_time_ms >= 0


# --------------------------------------------------------------------------- #
# run(): serial and parallel orchestration                                    #
# --------------------------------------------------------------------------- #
class TestRunOrchestration:
    def test_serial_run_aggregates(self, tmp_path):
        path = str(tmp_path / "reentrancy.sol")
        contract = _contract(path, lines=[10])
        payload = _slither_json([_detector(lines=[10])])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            bench = runner.run([contract], parallel=False, verbose=False)

        assert bench.total_contracts == 1
        assert bench.analyzed_contracts == 1
        assert bench.failed_contracts == 0
        assert bench.overall_metrics.true_positives == 1
        # total_ground_truth sums over contracts; total_detected sums over results
        assert bench.total_ground_truth == 1
        assert bench.total_detected == 1
        assert bench.miesc_version == "slither-only"

    def test_parallel_run_indexes_by_name_and_prints(self, tmp_path, capsys):
        c1 = _contract(str(tmp_path / "reentrancy.sol"), lines=[10])
        c2 = _contract(
            str(tmp_path / "access.sol"),
            category=VulnerabilityCategory.ACCESS_CONTROL,
            lines=[20],
        )

        def fake_run(cmd, **kwargs):
            # cmd[1] is the contract path passed to slither
            if "reentrancy" in cmd[1]:
                return _completed(
                    stdout=_slither_json([_detector(filename="reentrancy.sol", lines=[10])])
                )
            return _completed(
                stdout=_slither_json(
                    [_detector(check="suicidal", filename="access.sol", lines=[20])]
                )
            )

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", side_effect=fake_run):
            bench = runner.run([c1, c2], parallel=True, max_workers=2, verbose=True)

        by_name = {r.contract_name: r for r in bench.contract_results}
        assert set(by_name) == {"reentrancy", "access"}
        assert len(by_name["reentrancy"].true_positives) == 1
        assert len(by_name["access"].true_positives) == 1
        assert bench.analyzed_contracts == 2
        assert bench.overall_metrics.true_positives == 2

        out = capsys.readouterr().out
        assert "TP=1" in out and "FP=0" in out and "FN=0" in out

    def test_serial_run_prints_status_when_verbose(self, tmp_path, capsys):
        contract = _contract(str(tmp_path / "reentrancy.sol"), lines=[10])
        payload = _slither_json([_detector(lines=[10])])

        runner = SlitherBenchmarkRunner()
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            runner.run([contract], parallel=False, verbose=True)

        out = capsys.readouterr().out
        assert "reentrancy" in out
        assert "OK" in out

    def test_parallel_run_handles_worker_exception(self, tmp_path, monkeypatch):
        contract = _contract(str(tmp_path / "reentrancy.sol"), lines=[10])

        def raiser(_c):
            raise RuntimeError("worker exploded")

        runner = SlitherBenchmarkRunner()
        monkeypatch.setattr(runner, "_analyze_with_slither", raiser)
        bench = runner.run([contract], parallel=True, max_workers=1, verbose=False)

        assert bench.analyzed_contracts == 0
        assert bench.failed_contracts == 1
        assert bench.contract_results[0].error == "worker exploded"


# --------------------------------------------------------------------------- #
# _match_findings branches not covered by the helpers file                    #
# --------------------------------------------------------------------------- #
class TestMatchFindingBranches:
    def test_scalar_lines_are_wrapped(self):
        runner = SlitherBenchmarkRunner()
        gt = [GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[5])]
        # "lines" is a scalar int, not a list -> must be wrapped before overlap check
        findings = [{"type": "reentrancy-eth", "lines": 5, "location": {"line": 5}}]
        tp, fp, fn = runner._match_findings(gt, findings)
        assert len(tp) == 1
        assert len(fn) == 0

    def test_second_finding_on_same_ground_truth_is_false_positive(self):
        runner = SlitherBenchmarkRunner()
        gt = [GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[5])]
        findings = [
            {"type": "reentrancy-eth", "lines": [5], "location": {"line": 5}},
            {"type": "reentrancy-eth", "lines": [5], "location": {"line": 5}},
        ]
        tp, fp, fn = runner._match_findings(gt, findings)
        assert len(tp) == 1
        assert len(fp) == 1  # the already-matched GT cannot absorb the second finding
        assert len(fn) == 0

    def test_related_category_match_is_true_positive(self):
        runner = SlitherBenchmarkRunner()
        # unchecked-lowlevel maps to unchecked_low_level_calls, related to reentrancy
        gt = [GroundTruth(category=VulnerabilityCategory.REENTRANCY, lines=[7])]
        findings = [{"type": "unchecked-lowlevel", "lines": [7], "location": {"line": 7}}]
        tp, fp, fn = runner._match_findings(gt, findings)
        assert len(tp) == 1
        assert len(fn) == 0


# --------------------------------------------------------------------------- #
# _parse_slither_finding edge values                                          #
# --------------------------------------------------------------------------- #
class TestParseFindingEdges:
    def test_defaults_when_fields_missing(self):
        runner = SlitherBenchmarkRunner()
        det = {
            "check": "suicidal",
            # no impact/confidence/description, source_mapping without "lines"
            "elements": [{"source_mapping": {"filename_relative": "myc.sol"}}],
        }
        out = runner._parse_slither_finding(det, "MyC.sol")
        assert out is not None
        assert out["severity"] == "Medium"  # default impact
        assert out["confidence"] == "Medium"  # default confidence
        assert out["lines"] == []
        assert out["location"]["line"] == 0  # no lines -> 0

    def test_finding_outside_target_contract_is_dropped(self):
        runner = SlitherBenchmarkRunner()
        det = _detector(filename="SomeOtherLib.sol", lines=[3])
        # none of the detector elements reference the target contract stem
        assert runner._parse_slither_finding(det, "reentrancy.sol") is None


# --------------------------------------------------------------------------- #
# _cats_related: negative branch                                              #
# --------------------------------------------------------------------------- #
class TestCategoriesUnrelated:
    def test_distinct_groups_are_unrelated(self):
        runner = SlitherBenchmarkRunner()
        assert runner._cats_related("reentrancy", "arithmetic") is False
        assert runner._cats_related("access_control", "bad_randomness") is False


# --------------------------------------------------------------------------- #
# _calculate_results: category-keyed aggregation asymmetry                     #
# --------------------------------------------------------------------------- #
class TestCalculateResultsAggregation:
    def test_tp_keyed_by_detector_category_fn_by_ground_truth(self, tmp_path):
        runner = SlitherBenchmarkRunner()
        # Build one contract whose single reentrancy GT is matched by an
        # unchecked-lowlevel finding (related category) -> TP counted under
        # unchecked_low_level_calls, while a separate unmatched GT stays FN
        # under its own ground-truth category.
        contract = _contract(str(tmp_path / "reentrancy.sol"), lines=[7])
        payload = _slither_json(
            [_detector(check="unchecked-lowlevel", filename="reentrancy.sol", lines=[7])]
        )
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            bench = runner.run([contract], parallel=False, verbose=False)

        assert bench.overall_metrics.true_positives == 1
        # TP bucketed by the detector-mapped category, not the GT category
        assert "unchecked_low_level_calls" in bench.metrics_by_category
        assert bench.metrics_by_category["unchecked_low_level_calls"].true_positives == 1

    def test_false_positive_bucketed_by_detector_category(self, tmp_path):
        runner = SlitherBenchmarkRunner()
        # GT reentrancy at line 10, but Slither reports a reentrancy finding at
        # line 99 (outside tolerance) -> no overlap -> false positive.
        contract = _contract(str(tmp_path / "reentrancy.sol"), lines=[10])
        payload = _slither_json([_detector(filename="reentrancy.sol", lines=[99])])
        with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
            bench = runner.run([contract], parallel=False, verbose=False)

        assert bench.overall_metrics.false_positives == 1
        assert bench.overall_metrics.false_negatives == 1  # GT went unmatched
        assert "reentrancy" in bench.metrics_by_category
        assert bench.metrics_by_category["reentrancy"].false_positives == 1

    def test_false_negative_bucketed_under_ground_truth_category(self, tmp_path):
        runner = SlitherBenchmarkRunner()
        contract = _contract(
            str(tmp_path / "access.sol"),
            category=VulnerabilityCategory.ACCESS_CONTROL,
            lines=[20],
        )
        # Slither finds nothing -> the access_control GT becomes a false negative
        with patch.object(subprocess, "run", return_value=_completed()):
            bench = runner.run([contract], parallel=False, verbose=False)

        assert bench.overall_metrics.false_negatives == 1
        assert "access_control" in bench.metrics_by_category
        assert bench.metrics_by_category["access_control"].false_negatives == 1


# --------------------------------------------------------------------------- #
# run_slither_benchmark convenience wrapper                                    #
# --------------------------------------------------------------------------- #
def test_run_slither_benchmark_convenience(tmp_path):
    contract = _contract(str(tmp_path / "reentrancy.sol"), lines=[10])
    payload = _slither_json([_detector(lines=[10])])

    with patch.object(subprocess, "run", return_value=_completed(stdout=payload)):
        bench = run_slither_benchmark([contract], parallel=False, verbose=False)

    assert bench.total_contracts == 1
    assert bench.overall_metrics.true_positives == 1
    assert bench.miesc_version == "slither-only"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
