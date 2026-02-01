#!/usr/bin/env python3
"""
Unit tests for MIESC Remediation Engine.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from security.remediation_engine import (  # noqa: E402
    EnrichedFinding,
    FixEffort,
    FixRisk,
    RemediationEngine,
    RemediationReport,
    enrich_with_remediations,
)
from security.remediations import (  # noqa: E402
    get_all_remediations,
    get_remediation,
    get_remediation_by_type,
)


class TestRemediationDatabase:
    """Tests for remediation database."""

    def test_get_remediation_by_swc(self):
        """Test getting remediation by SWC ID."""
        rem = get_remediation("SWC-107")
        assert rem is not None
        assert rem.swc_id == "SWC-107"
        assert "reentrancy" in rem.title.lower()

    def test_get_remediation_by_type(self):
        """Test getting remediation by vulnerability type."""
        rem = get_remediation_by_type("reentrancy")
        assert rem is not None
        assert rem.swc_id == "SWC-107"

    def test_get_remediation_by_type_variations(self):
        """Test type variations are handled."""
        # Test various type formats
        types_to_test = [
            ("reentrancy-eth", "SWC-107"),
            ("overflow", "SWC-101"),
            ("unchecked-call", "SWC-104"),
            ("tx-origin", "SWC-115"),
        ]
        for vuln_type, expected_swc in types_to_test:
            rem = get_remediation_by_type(vuln_type)
            assert rem is not None, f"No remediation for {vuln_type}"
            assert rem.swc_id == expected_swc

    def test_get_all_remediations(self):
        """Test getting all remediations."""
        all_rems = get_all_remediations()
        assert len(all_rems) >= 15  # Should have at least 15 SWC entries


class TestEnrichedFinding:
    """Tests for EnrichedFinding class."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        finding = EnrichedFinding(
            id="TEST-001",
            type="reentrancy",
            severity="high",
            message="Test vulnerability",
            location={"file": "test.sol", "line": 42},
            swc_id="SWC-107",
            remediation=get_remediation("SWC-107"),
            fix_effort=FixEffort.HIGH,
            fix_risk=FixRisk.MEDIUM,
            priority_score=8.5,
            priority_rank=1,
        )

        d = finding.to_dict()

        assert d["id"] == "TEST-001"
        assert d["type"] == "reentrancy"
        assert d["severity"] == "high"
        assert d["swc_id"] == "SWC-107"
        assert d["fix"]["effort"] == "high"
        assert d["fix"]["risk"] == "medium"
        assert d["priority"]["score"] == 8.5
        assert "remediation" in d
        assert "example_fixed" in d["remediation"]


class TestRemediationEngine:
    """Tests for RemediationEngine class."""

    @pytest.fixture
    def engine(self):
        """Create a fresh engine for each test."""
        return RemediationEngine()

    @pytest.fixture
    def sample_findings(self):
        """Sample findings for testing."""
        return [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy vulnerability in withdraw()",
                "location": {"file": "Contract.sol", "line": 42, "function": "withdraw"},
                "swc_id": "SWC-107",
            },
            {
                "type": "unchecked-call",
                "severity": "medium",
                "message": "Return value of send() not checked",
                "location": {"file": "Contract.sol", "line": 55},
                "swc_id": "SWC-104",
            },
            {
                "type": "tx-origin",
                "severity": "high",
                "message": "Use of tx.origin for authentication",
                "location": {"file": "Contract.sol", "line": 30, "function": "transferOwnership"},
                "swc_id": "SWC-115",
            },
        ]

    def test_enrich_single_finding(self, engine):
        """Test enriching a single finding."""
        finding = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Test reentrancy",
            "location": {"file": "test.sol", "line": 10},
            "swc_id": "SWC-107",
        }

        enriched = engine.enrich_finding(finding)

        assert enriched.type == "reentrancy"
        assert enriched.severity == "high"
        assert enriched.swc_id == "SWC-107"
        assert enriched.remediation is not None
        assert enriched.fix_effort == FixEffort.HIGH
        assert enriched.priority_score > 0

    def test_enrich_multiple_findings(self, engine, sample_findings):
        """Test enriching multiple findings."""
        enriched = engine.enrich_findings(sample_findings)

        assert len(enriched) == 3
        # Should be sorted by priority
        assert enriched[0].priority_rank == 1
        assert enriched[1].priority_rank == 2
        assert enriched[2].priority_rank == 3

    def test_priority_scoring(self, engine):
        """Test priority scoring calculation."""
        critical = engine.enrich_finding(
            {
                "type": "reentrancy",
                "severity": "critical",
                "message": "Test",
                "location": {},
                "swc_id": "SWC-107",
            }
        )

        low = engine.enrich_finding(
            {
                "type": "floating-pragma",
                "severity": "low",
                "message": "Test",
                "location": {},
                "swc_id": "SWC-103",
            }
        )

        assert critical.priority_score > low.priority_score

    def test_generate_fix_plan(self, engine, sample_findings):
        """Test fix plan generation."""
        engine.enrich_findings(sample_findings)
        fix_plan = engine.generate_fix_plan()

        assert len(fix_plan) > 0
        assert "step" in fix_plan[0]
        assert "swc_id" in fix_plan[0]
        assert "action" in fix_plan[0]
        assert "example" in fix_plan[0]

    def test_estimate_total_effort(self, engine, sample_findings):
        """Test effort estimation."""
        engine.enrich_findings(sample_findings)
        effort = engine.estimate_total_effort()

        assert isinstance(effort, str)
        assert any(unit in effort for unit in ["minutes", "hours", "days", "weeks"])

    def test_security_checklist(self, engine, sample_findings):
        """Test security checklist generation."""
        engine.enrich_findings(sample_findings)
        checklist = engine.check_security_checklist()

        assert isinstance(checklist, dict)
        assert "No reentrancy vulnerabilities" in checklist
        # Should be False because we have reentrancy finding
        assert not checklist["No reentrancy vulnerabilities"]
        # tx.origin finding
        assert not checklist["No tx.origin for authentication"]

    def test_security_checklist_with_source(self, engine):
        """Test checklist with source code analysis."""
        engine.enrich_findings([])
        source_code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        """
        checklist = engine.check_security_checklist(source_code)

        assert checklist["Uses Solidity 0.8+"]
        assert checklist["Has ReentrancyGuard"]

    def test_generate_report(self, engine, sample_findings):
        """Test full report generation."""
        engine.enrich_findings(sample_findings)
        report = engine.generate_report("TestContract")

        assert isinstance(report, RemediationReport)
        assert report.contract_name == "TestContract"
        assert report.total_findings == 3
        assert report.high_count == 2  # reentrancy + tx.origin
        assert len(report.fix_plan) > 0

    def test_report_to_dict(self, engine, sample_findings):
        """Test report serialization."""
        engine.enrich_findings(sample_findings)
        report = engine.generate_report("TestContract")
        d = report.to_dict()

        assert "contract" in d
        assert "summary" in d
        assert "findings" in d
        assert "fix_plan" in d
        assert "estimated_effort" in d

    def test_get_quick_wins(self, engine):
        """Test quick wins filtering."""
        findings = [
            {
                "type": "floating-pragma",
                "severity": "low",
                "message": "Test",
                "location": {},
                "swc_id": "SWC-103",
            },
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Test",
                "location": {},
                "swc_id": "SWC-107",
            },
        ]
        engine.enrich_findings(findings)
        quick_wins = engine.get_quick_wins(FixEffort.LOW)

        # Floating pragma is trivial, reentrancy is high effort
        assert len(quick_wins) == 1
        assert quick_wins[0].swc_id == "SWC-103"

    def test_get_critical_fixes(self, engine, sample_findings):
        """Test critical fixes filtering."""
        engine.enrich_findings(sample_findings)
        critical = engine.get_critical_fixes()

        assert len(critical) == 2  # high severity findings
        for f in critical:
            assert f.severity in ["critical", "high"]

    def test_empty_findings(self, engine):
        """Test handling of empty findings."""
        enriched = engine.enrich_findings([])

        assert enriched == []
        assert engine.estimate_total_effort() == "No findings to fix"
        assert engine.generate_fix_plan() == []


class TestConvenienceFunction:
    """Tests for enrich_with_remediations convenience function."""

    def test_enrich_with_remediations(self):
        """Test the convenience function."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Test",
                "location": {"file": "test.sol"},
            },
        ]

        report = enrich_with_remediations(findings, "TestContract")

        assert "contract" in report
        assert report["contract"] == "TestContract"
        assert "findings" in report
        assert len(report["findings"]) == 1
        assert "fix_plan" in report


class TestFixEffortAndRisk:
    """Tests for effort and risk enums."""

    def test_fix_effort_values(self):
        """Test FixEffort enum values."""
        assert FixEffort.TRIVIAL.value == "trivial"
        assert FixEffort.LOW.value == "low"
        assert FixEffort.MEDIUM.value == "medium"
        assert FixEffort.HIGH.value == "high"
        assert FixEffort.COMPLEX.value == "complex"

    def test_fix_risk_values(self):
        """Test FixRisk enum values."""
        assert FixRisk.SAFE.value == "safe"
        assert FixRisk.LOW.value == "low"
        assert FixRisk.MEDIUM.value == "medium"
        assert FixRisk.HIGH.value == "high"


class TestRemediationEngineCoverage:
    """Additional tests for full coverage of remediation_engine.py."""

    @pytest.fixture
    def engine(self):
        """Create a fresh engine for each test."""
        return RemediationEngine()

    def test_enriched_finding_to_dict_with_related_findings(self):
        """Test to_dict includes related_findings when populated (line 102)."""
        finding = EnrichedFinding(
            id="TEST-001",
            type="reentrancy",
            severity="high",
            message="Test vulnerability",
            location={"file": "test.sol", "line": 42},
            swc_id="SWC-107",
            remediation=get_remediation("SWC-107"),
            fix_effort=FixEffort.HIGH,
            fix_risk=FixRisk.MEDIUM,
            priority_score=8.5,
            priority_rank=1,
            related_findings=["TEST-002", "TEST-003"],  # Populate related_findings
        )

        d = finding.to_dict()

        assert "related_findings" in d
        assert d["related_findings"] == ["TEST-002", "TEST-003"]

    def test_enriched_finding_to_dict_with_affected_functions(self):
        """Test to_dict includes affected_functions when populated."""
        finding = EnrichedFinding(
            id="TEST-001",
            type="reentrancy",
            severity="high",
            message="Test vulnerability",
            location={"file": "test.sol", "line": 42},
            affected_functions=["withdraw", "transfer"],
        )

        d = finding.to_dict()

        assert "affected_functions" in d
        assert d["affected_functions"] == ["withdraw", "transfer"]

    def test_enrich_finding_fallback_to_finding_type(self, engine):
        """Test remediation fallback to original finding_type (line 272)."""
        # Create a finding with a type that's in TYPE_CANONICAL mapping
        # but canonical version returns no remediation, while original does
        finding = {
            "type": "reentrancy-eth",  # Maps to 'reentrancy' canonical
            "severity": "high",
            "message": "Test reentrancy eth",
            "location": {"file": "test.sol", "line": 10},
            # No swc_id - force fallback path
        }

        enriched = engine.enrich_finding(finding)

        # Should still get remediation through canonical type fallback
        assert enriched.remediation is not None

    def test_enrich_finding_with_no_swc_uses_type_fallback(self, engine):
        """Test finding without swc_id falls back to type-based lookup."""
        finding = {
            "type": "overflow",
            "severity": "high",
            "message": "Integer overflow",
            "location": {},
        }

        enriched = engine.enrich_finding(finding)

        assert enriched.remediation is not None
        assert enriched.swc_id == "SWC-101"  # Gets SWC from remediation

    def test_fix_plan_skips_unknown_swc(self, engine):
        """Test fix plan skips findings with unknown SWC (line 395)."""
        # Create findings - one with valid SWC, one with unknown
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "Valid finding",
                "location": {"file": "test.sol", "line": 10},
                "swc_id": "SWC-107",
            },
            {
                "type": "unknown-vuln",
                "severity": "medium",
                "message": "Unknown finding",
                "location": {},
                # No swc_id - will be 'unknown'
            },
        ]

        engine.enrich_findings(findings)
        fix_plan = engine.generate_fix_plan()

        # Only the SWC-107 finding should be in fix plan
        swc_ids = [step["swc_id"] for step in fix_plan]
        assert "SWC-107" in swc_ids
        assert "unknown" not in swc_ids

    def test_fix_plan_skips_findings_without_remediation(self, engine):
        """Test fix plan skips findings without remediation (line 399)."""
        # Create a finding that will have no remediation
        finding = EnrichedFinding(
            id="TEST-001",
            type="custom-vuln",
            severity="medium",
            message="Custom vulnerability",
            location={},
            swc_id="SWC-999",  # Non-existent SWC
            remediation=None,  # No remediation
            fix_effort=FixEffort.MEDIUM,
            fix_risk=FixRisk.LOW,
            priority_score=4.0,
            priority_rank=1,
        )

        engine._enriched_findings = [finding]
        fix_plan = engine.generate_fix_plan()

        # Should be empty since no valid remediation
        assert len(fix_plan) == 0

    def test_estimate_effort_returns_minutes(self, engine):
        """Test effort estimate returns minutes for small efforts (line 463)."""
        # Create a single trivial finding (0.5 hours = 30 minutes)
        findings = [
            {
                "type": "floating-pragma",
                "severity": "low",
                "message": "Trivial fix",
                "location": {},
                "swc_id": "SWC-103",  # TRIVIAL effort
            },
        ]

        engine.enrich_findings(findings)
        effort = engine.estimate_total_effort()

        assert "minutes" in effort

    def test_estimate_effort_returns_weeks(self, engine):
        """Test effort estimate returns weeks for large efforts (line 469)."""
        # Create many complex findings to exceed 40 hours
        findings = []
        for i in range(5):
            findings.append(
                {
                    "type": "reentrancy",
                    "severity": "critical",
                    "message": f"Complex finding {i}",
                    "location": {},
                    "swc_id": "SWC-107",  # HIGH effort = 12 hours each
                }
            )

        engine.enrich_findings(findings)
        effort = engine.estimate_total_effort()

        # 5 * 12 hours = 60 hours > 40 hours threshold
        assert "weeks" in effort

    def test_estimate_effort_returns_days(self, engine):
        """Test effort estimate returns days for medium efforts."""
        # Create findings to be between 8-40 hours
        findings = []
        for i in range(3):
            findings.append(
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "message": f"Finding {i}",
                    "location": {},
                    "swc_id": "SWC-107",  # HIGH effort = 12 hours each
                }
            )

        engine.enrich_findings(findings)
        effort = engine.estimate_total_effort()

        # 3 * 12 hours = 36 hours, should be ~4.5 days
        assert "days" in effort

    def test_generate_report_with_informational_severity(self, engine):
        """Test report handles 'informational' severity (lines 542-543)."""
        findings = [
            {
                "type": "best-practice",
                "severity": "informational",
                "message": "Informational finding",
                "location": {},
            },
            {
                "type": "style",
                "severity": "info",
                "message": "Info level finding",
                "location": {},
            },
        ]

        engine.enrich_findings(findings)
        report = engine.generate_report("TestContract")

        # Both informational/info should be counted as low
        assert report.low_count == 2
        assert report.medium_count == 0

    def test_enrich_findings_populates_related_findings(self, engine):
        """Test that related findings are populated for same type."""
        findings = [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "First reentrancy",
                "location": {"file": "a.sol"},
                "swc_id": "SWC-107",
            },
            {
                "type": "reentrancy-eth",  # Maps to same canonical type
                "severity": "high",
                "message": "Second reentrancy",
                "location": {"file": "b.sol"},
                "swc_id": "SWC-107",
            },
        ]

        enriched = engine.enrich_findings(findings)

        # Each should have the other as related
        assert len(enriched[0].related_findings) == 1
        assert len(enriched[1].related_findings) == 1

    def test_fix_plan_with_location_variants(self, engine):
        """Test fix plan handles different location formats."""
        findings = [
            {
                "type": "tx-origin",
                "severity": "high",
                "message": "Finding with full location",
                "location": {"file": "test.sol", "line": 10, "function": "auth"},
                "swc_id": "SWC-115",
            },
            {
                "type": "tx-origin",
                "severity": "high",
                "message": "Finding with minimal location",
                "location": {"file": "test2.sol"},
                "swc_id": "SWC-115",
            },
            {
                "type": "tx-origin",
                "severity": "high",
                "message": "Finding with empty location",
                "location": {},
                "swc_id": "SWC-115",
            },
        ]

        engine.enrich_findings(findings)
        fix_plan = engine.generate_fix_plan()

        assert len(fix_plan) == 1  # All grouped under same SWC
        assert fix_plan[0]["instances"] == 3
        # Should have 2 locations (empty one is skipped)
        assert len(fix_plan[0]["locations"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
