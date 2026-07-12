"""
Tests for miesc.formal.unified_report — the unified formal-verification report.

Covers:
  - Aggregation of mixed per-prover results (verified/violated/unavailable) into
    one structure with the correct overall verdict.
  - JSON determinism (stable + sorted).
  - SARIF mapping: violated property -> valid SARIF result with a source
    location, and counterexample -> finding linkage via relatedLocations.
"""

from __future__ import annotations

import json

from miesc.core.exporters import Finding
from miesc.formal import UNAVAILABLE
from miesc.formal import normalize_status as public_normalize_status
from miesc.formal.spec_runner import VerificationResult
from miesc.formal.unified_report import (
    Counterexample,
    ProverVerdict,
    UnifiedVerificationReport,
    normalize_status,
)

# ---------------------------------------------------------------------------
# Status normalization
# ---------------------------------------------------------------------------


class TestNormalizeStatus:
    def test_maps_known_statuses(self):
        assert normalize_status("passed") == "verified"
        assert normalize_status("failed") == "violated"
        assert normalize_status("error") == "error"
        assert normalize_status("timeout") == "timeout"
        assert normalize_status("no_tests") == "no_tests"

    def test_unknown_status_falls_back(self):
        assert normalize_status("weird") == "unknown"

    def test_public_formal_facade_exports_status_helpers(self):
        assert public_normalize_status("passed") == "verified"
        assert UNAVAILABLE == "unavailable"


# ---------------------------------------------------------------------------
# Counterexample source-line parsing
# ---------------------------------------------------------------------------


class TestCounterexampleParsing:
    def test_parses_line_from_smtchecker_text(self):
        cex = Counterexample.from_text("smtchecker", "CHC: Overflow at line 22")
        assert cex.source_line == 22
        assert cex.prover == "smtchecker"

    def test_no_line_when_absent(self):
        cex = Counterexample.from_text("halmos", "amount = 2**256 - 1")
        assert cex.source_line is None


# ---------------------------------------------------------------------------
# Aggregation + overall verdict
# ---------------------------------------------------------------------------


def _vr(tool, status, **kw):
    return VerificationResult(tool=tool, spec_file=f"{tool}.spec", status=status, **kw)


class TestAggregation:
    def test_mixed_results_build_expected_structure(self):
        results = {
            "certora": _vr("certora", "passed", rules_passed=3, rules_total=3),
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["CHC: Overflow at line 10"],
            ),
        }
        report = UnifiedVerificationReport.from_runner_results(
            "C.sol", results, availability={"certora": True, "smtchecker": True, "halmos": False}
        )
        provers = {p.prover: p for p in report.provers}
        assert set(provers) == {"certora", "smtchecker", "halmos"}
        assert provers["certora"].status == "verified"
        assert provers["smtchecker"].status == "violated"
        assert provers["halmos"].status == "unavailable"
        # counterexample was parsed with its source line
        assert provers["smtchecker"].counterexamples[0].source_line == 10

    def test_verdict_violated_dominates(self):
        results = {
            "certora": _vr("certora", "passed", rules_passed=1, rules_total=1),
            "smtchecker": _vr("smtchecker", "failed", rules_failed=1, rules_total=1),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        assert report.overall_verdict == "violated"

    def test_verdict_verified_when_all_pass(self):
        results = {
            "certora": _vr("certora", "passed", rules_passed=1, rules_total=1),
            "smtchecker": _vr("smtchecker", "passed", rules_total=0),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        assert report.overall_verdict == "verified"

    def test_verdict_inconclusive_on_mix_without_violation(self):
        results = {
            "certora": _vr("certora", "passed", rules_passed=1, rules_total=1),
            "halmos": _vr("halmos", "error"),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        assert report.overall_verdict == "inconclusive"

    def test_verdict_no_provers_when_only_unavailable(self):
        report = UnifiedVerificationReport.from_runner_results(
            "C.sol", {}, availability={"certora": False, "halmos": False, "smtchecker": False}
        )
        assert report.overall_verdict == "no_provers"

    def test_available_but_absent_provers_are_recorded(self):
        results = {"smtchecker": _vr("smtchecker", "passed", rules_total=0)}
        report = UnifiedVerificationReport.from_runner_results(
            "C.sol", results, availability={"certora": True, "smtchecker": True}
        )
        provers = {p.prover: p for p in report.provers}
        assert provers["smtchecker"].status == "verified"
        assert provers["certora"].status == UNAVAILABLE

    def test_summary_counters(self):
        results = {
            "certora": _vr("certora", "passed", rules_passed=2, rules_total=2),
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["Overflow at line 5"],
            ),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        s = report.summary()
        assert s["verified"] == 1
        assert s["violated"] == 1
        assert s["total_properties"] == 3
        assert s["violated_properties"] == 1
        assert s["counterexamples"] == 1


# ---------------------------------------------------------------------------
# JSON determinism
# ---------------------------------------------------------------------------


class TestJSONDeterminism:
    def _report(self):
        results = {
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["Overflow at line 3"],
            ),
            "certora": _vr("certora", "passed", rules_passed=1, rules_total=1),
        }
        return UnifiedVerificationReport.from_runner_results("C.sol", results)

    def test_json_is_stable_across_builds(self):
        a = self._report().to_json()
        b = self._report().to_json()
        assert a == b

    def test_json_keys_are_sorted(self):
        data_str = self._report().to_json()
        # sort_keys=True => a re-dump with sort_keys must be identical
        reparsed = json.loads(data_str)
        assert json.dumps(reparsed, indent=2, sort_keys=True) == data_str

    def test_json_has_no_wallclock_by_default(self):
        assert "generated_at" not in json.loads(self._report().to_json())

    def test_generated_at_included_when_set(self):
        results = {"certora": _vr("certora", "passed", rules_total=1, rules_passed=1)}
        report = UnifiedVerificationReport.from_runner_results(
            "C.sol", results, generated_at="2026-07-12T00:00:00Z"
        )
        assert json.loads(report.to_json())["generated_at"] == "2026-07-12T00:00:00Z"

    def test_to_json_writes_file(self, tmp_path):
        out = tmp_path / "report.json"
        self._report().to_json(str(out))
        assert out.exists()
        assert json.loads(out.read_text())["overall_verdict"] == "violated"


# ---------------------------------------------------------------------------
# SARIF mapping
# ---------------------------------------------------------------------------


class TestSARIFMapping:
    def test_violated_property_becomes_sarif_result_with_location(self):
        results = {
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["CHC: Overflow at line 42"],
            ),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        sarif = json.loads(report.to_sarif())

        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "MIESC-Formal"
        assert len(run["results"]) == 1
        result = run["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert result["properties"]["prover"] == "smtchecker"
        assert result["properties"]["verificationLayer"] == "formal"
        assert "Overflow at line 42" in result["properties"]["counterexample"]

    def test_verified_only_yields_no_results(self):
        results = {"certora": _vr("certora", "passed", rules_passed=1, rules_total=1)}
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        sarif = json.loads(report.to_sarif())
        assert sarif["runs"][0]["results"] == []

    def test_violation_without_counterexample_emits_summary_result(self):
        results = {"certora": _vr("certora", "failed", rules_failed=2, rules_total=2)}
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        sarif = json.loads(report.to_sarif())
        results_out = sarif["runs"][0]["results"]
        assert len(results_out) == 1
        assert results_out[0]["properties"]["prover"] == "certora"

    def test_counterexample_links_to_finding(self):
        results = {
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["CHC: reentrancy reachable at line 15"],
            ),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        finding = Finding(
            id="F1",
            type="reentrancy",
            severity="high",
            title="Reentrancy in withdraw",
            description="external call before state update",
            file_path="C.sol",
            line_start=15,
            cwe="CWE-841",
            swc="SWC-107",
        )
        linked = report.link_findings([finding])
        assert linked == 1

        # counterexample carries the linked finding id
        cex = report.provers[0].counterexamples[0]
        assert cex.linked_finding_id == "F1"

        sarif = json.loads(report.to_sarif())
        result = sarif["runs"][0]["results"][0]
        # linkage is surfaced both as a property and a relatedLocation
        assert result["properties"]["linkedFindingId"] == "F1"
        related = result["relatedLocations"][0]
        assert related["physicalLocation"]["region"]["startLine"] == 15
        assert "F1" in related["message"]["text"]
        # reused the original finding's rule identity
        assert result["ruleId"] == "MIESC-REENTRANCY"

    def test_link_findings_no_match_when_line_differs(self):
        results = {
            "smtchecker": _vr(
                "smtchecker",
                "failed",
                rules_failed=1,
                rules_total=1,
                counterexamples=["Overflow at line 99"],
            ),
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        finding = Finding(
            id="F2",
            type="overflow",
            severity="medium",
            title="Overflow",
            description="x",
            file_path="C.sol",
            line_start=3,
        )
        assert report.link_findings([finding]) == 0
        assert report.provers[0].counterexamples[0].linked_finding_id is None

    def test_to_sarif_writes_file(self, tmp_path):
        out = tmp_path / "report.sarif"
        results = {
            "smtchecker": _vr(
                "smtchecker", "failed", rules_failed=1, rules_total=1, counterexamples=["line 1"]
            )
        }
        report = UnifiedVerificationReport.from_runner_results("C.sol", results)
        report.to_sarif(str(out))
        assert out.exists()
        assert json.loads(out.read_text())["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# ProverVerdict round-trip
# ---------------------------------------------------------------------------


class TestProverVerdict:
    def test_from_runner_result_carries_error_message(self):
        vr = VerificationResult(
            tool="certora", spec_file="c.spec", status="error", stderr="boom happened"
        )
        pv = ProverVerdict.from_runner_result(vr)
        assert pv.status == "error"
        assert "boom" in pv.message

    def test_to_dict_shape(self):
        pv = ProverVerdict(prover="halmos", status="verified", properties_checked=2)
        d = pv.to_dict()
        assert d["prover"] == "halmos"
        assert d["status"] == "verified"
        assert d["properties_checked"] == 2
        assert d["counterexamples"] == []
