"""
Regression tests for exporting ``audit full`` JSON.

``audit full -f json`` emits findings under ``ml_enhanced`` / ``raw_findings`` (dicts with a
``findings`` key), not a top-level ``findings`` list. The exporters iterate ``result["findings"]``,
so before the fix ``export -f sarif`` produced an empty SARIF (0 results) for a real audit. These
tests pin the normalization that lifts the consolidated findings into the shape the exporters read.
"""

from __future__ import annotations

from miesc.cli.commands.audit import _to_sarif
from miesc.cli.commands.export import _audit_findings, _normalize_results

F1 = {"title": "Reentrancy", "type": "reentrancy", "severity": "high", "description": "d1"}
F2 = {"title": "Overflow", "type": "arithmetic", "severity": "medium", "description": "d2"}


class TestAuditFindings:
    def test_ml_enhanced_findings(self):
        assert _audit_findings({"ml_enhanced": {"findings": [F1, F2]}}) == [F1, F2]

    def test_ml_enhanced_top_findings(self):
        assert _audit_findings({"ml_enhanced": {"top_findings": [F1]}}) == [F1]

    def test_raw_findings_dict(self):
        assert _audit_findings({"raw_findings": {"findings": [F1]}}) == [F1]

    def test_raw_findings_list(self):
        assert _audit_findings({"raw_findings": [F1, F2]}) == [F1, F2]

    def test_ml_enhanced_precedence_over_raw(self):
        data = {"ml_enhanced": {"findings": [F1]}, "raw_findings": {"findings": [F2]}}
        assert _audit_findings(data) == [F1]

    def test_scan_shape_returns_empty(self):
        assert _audit_findings({"findings": [F1]}) == []
        assert _audit_findings({"results": [{"findings": [F1]}]}) == []


class TestNormalizeResults:
    def test_scan_results_list_passthrough(self):
        data = {"results": [{"tool": "slither", "findings": [F1]}]}
        assert _normalize_results(data) == data["results"]

    def test_top_level_findings_passthrough(self):
        data = {"findings": [F1]}
        assert _normalize_results(data) == [data]

    def test_audit_full_is_lifted(self):
        data = {"contract_path": "C.sol", "ml_enhanced": {"findings": [F1, F2]}}
        out = _normalize_results(data)
        assert len(out) == 1
        assert out[0]["findings"] == [F1, F2]
        assert out[0]["contract_path"] == "C.sol"  # other keys preserved

    def test_no_findings_falls_back(self):
        assert _normalize_results({"metrics": {}}) == [{"metrics": {}}]


class TestSarifRegression:
    def test_audit_full_sarif_has_results(self):
        # the bug: this used to yield 0 results
        audit = {
            "contract_path": "C.sol",
            "raw_findings": {"findings": [F1]},
            "ml_enhanced": {"findings": [F1, F2]},
            "metrics": {},
        }
        sarif = _to_sarif(_normalize_results(audit))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 2  # F1 + F2, not 0

    def test_scan_sarif_still_works(self):
        scan = {"results": [{"tool": "slither", "findings": [F1]}]}
        sarif = _to_sarif(_normalize_results(scan))
        assert len(sarif["runs"][0]["results"]) == 1
