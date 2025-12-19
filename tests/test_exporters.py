"""
Tests for MIESC Exporters Module

Tests SARIF, SonarQube, Checkmarx, Markdown, and JSON exporters.
"""

import pytest
import json
from pathlib import Path

from src.core.exporters import (
    Finding,
    SARIFExporter,
    SonarQubeExporter,
    CheckmarxExporter,
    MarkdownExporter,
    JSONExporter,
    ReportExporter,
)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="F001",
            type="reentrancy",
            severity="critical",
            title="Reentrancy Vulnerability",
            description="External call before state update allows reentrancy attack.",
            file_path="contracts/Vulnerable.sol",
            line_start=25,
            line_end=30,
            tool="slither",
            layer=1,
            cwe="CWE-841",
            swc="SWC-107",
            confidence=0.95,
            remediation="Use checks-effects-interactions pattern.",
        ),
        Finding(
            id="F002",
            type="unchecked_return",
            severity="high",
            title="Unchecked Return Value",
            description="Return value of external call not checked.",
            file_path="contracts/Token.sol",
            line_start=42,
            tool="mythril",
            layer=3,
            confidence=0.85,
        ),
        Finding(
            id="F003",
            type="access_control",
            severity="medium",
            title="Missing Access Control",
            description="Function lacks access control modifier.",
            file_path="contracts/Vault.sol",
            line_start=15,
            tool="aderyn",
            layer=1,
            confidence=0.80,
        ),
    ]


class TestSARIFExporter:
    """Tests for SARIF exporter."""

    def test_export_creates_valid_sarif(self, sample_findings):
        """Test that export creates valid SARIF structure."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)

        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_contains_rules(self, sample_findings):
        """Test that SARIF contains extracted rules."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        assert len(rules) == 3
        rule_ids = [r["id"] for r in rules]
        assert "MIESC-REENTRANCY" in rule_ids

    def test_sarif_contains_results(self, sample_findings):
        """Test that SARIF contains all findings as results."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)
        results = sarif["runs"][0]["results"]

        assert len(results) == 3

    def test_sarif_severity_mapping(self, sample_findings):
        """Test severity to SARIF level mapping."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)
        results = sarif["runs"][0]["results"]

        # Critical/High -> error, Medium -> warning
        levels = [r["level"] for r in results]
        assert "error" in levels
        assert "warning" in levels

    def test_sarif_includes_location(self, sample_findings):
        """Test that results include location information."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)
        first_result = sarif["runs"][0]["results"][0]

        assert "locations" in first_result
        location = first_result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in location
        assert "region" in location

    def test_sarif_fingerprints(self, sample_findings):
        """Test that results have fingerprints for deduplication."""
        exporter = SARIFExporter()
        result = exporter.export(sample_findings)

        sarif = json.loads(result)
        first_result = sarif["runs"][0]["results"][0]

        assert "fingerprints" in first_result
        assert "partialFingerprints" in first_result


class TestSonarQubeExporter:
    """Tests for SonarQube exporter."""

    def test_export_creates_valid_structure(self, sample_findings):
        """Test that export creates valid SonarQube structure."""
        exporter = SonarQubeExporter()
        result = exporter.export(sample_findings)

        data = json.loads(result)
        assert "issues" in data
        assert len(data["issues"]) == 3

    def test_sonarqube_issue_format(self, sample_findings):
        """Test SonarQube issue format."""
        exporter = SonarQubeExporter()
        result = exporter.export(sample_findings)

        data = json.loads(result)
        issue = data["issues"][0]

        assert issue["engineId"] == "miesc"
        assert "ruleId" in issue
        assert "severity" in issue
        assert issue["type"] == "VULNERABILITY"
        assert "primaryLocation" in issue

    def test_sonarqube_severity_mapping(self, sample_findings):
        """Test severity mapping to SonarQube format."""
        exporter = SonarQubeExporter()
        result = exporter.export(sample_findings)

        data = json.loads(result)
        severities = [i["severity"] for i in data["issues"]]

        # critical -> BLOCKER, high -> CRITICAL, medium -> MAJOR
        assert "BLOCKER" in severities
        assert "CRITICAL" in severities
        assert "MAJOR" in severities


class TestCheckmarxExporter:
    """Tests for Checkmarx exporter."""

    def test_export_creates_valid_xml(self, sample_findings):
        """Test that export creates valid XML."""
        exporter = CheckmarxExporter()
        result = exporter.export(sample_findings)

        assert result.startswith("<CxXMLResults")
        assert "</CxXMLResults>" in result

    def test_checkmarx_contains_queries(self, sample_findings):
        """Test that XML contains Query elements."""
        exporter = CheckmarxExporter()
        result = exporter.export(sample_findings)

        assert "<Query" in result
        assert 'name="reentrancy"' in result


class TestMarkdownExporter:
    """Tests for Markdown exporter."""

    def test_export_creates_markdown(self, sample_findings):
        """Test that export creates Markdown content."""
        exporter = MarkdownExporter()
        result = exporter.export(sample_findings)

        assert "# MIESC Security Audit Report" in result
        assert "## Summary" in result
        assert "## Findings" in result

    def test_markdown_contains_summary_table(self, sample_findings):
        """Test that Markdown contains summary table."""
        exporter = MarkdownExporter()
        result = exporter.export(sample_findings)

        assert "| Severity | Count |" in result
        assert "| Critical |" in result

    def test_markdown_groups_by_severity(self, sample_findings):
        """Test that findings are grouped by severity."""
        exporter = MarkdownExporter()
        result = exporter.export(sample_findings)

        assert "### CRITICAL" in result
        assert "### HIGH" in result
        assert "### MEDIUM" in result

    def test_markdown_includes_remediation(self, sample_findings):
        """Test that remediation is included when available."""
        exporter = MarkdownExporter()
        result = exporter.export(sample_findings, include_remediation=True)

        assert "**Remediation:**" in result
        assert "checks-effects-interactions" in result


class TestJSONExporter:
    """Tests for JSON exporter."""

    def test_export_creates_valid_json(self, sample_findings):
        """Test that export creates valid JSON."""
        exporter = JSONExporter()
        result = exporter.export(sample_findings)

        data = json.loads(result)
        assert "findings" in data

    def test_json_includes_metadata(self, sample_findings):
        """Test that JSON includes metadata."""
        exporter = JSONExporter()
        result = exporter.export(sample_findings, include_metadata=True)

        data = json.loads(result)
        assert "metadata" in data
        assert data["metadata"]["tool"] == "MIESC"
        assert "version" in data["metadata"]
        assert "generated_at" in data["metadata"]
        assert "severity_counts" in data["metadata"]

    def test_json_severity_counts(self, sample_findings):
        """Test severity count calculation."""
        exporter = JSONExporter()
        result = exporter.export(sample_findings)

        data = json.loads(result)
        counts = data["metadata"]["severity_counts"]

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1


class TestReportExporter:
    """Tests for unified ReportExporter."""

    def test_supports_all_formats(self):
        """Test that all formats are supported."""
        exporter = ReportExporter()

        expected_formats = ["sarif", "sonarqube", "checkmarx", "markdown", "json"]
        for fmt in expected_formats:
            assert fmt in exporter.exporters

    def test_export_sarif(self, sample_findings):
        """Test export in SARIF format."""
        exporter = ReportExporter()
        result = exporter.export(sample_findings, "sarif")

        data = json.loads(result)
        assert data["version"] == "2.1.0"

    def test_export_invalid_format_raises(self, sample_findings):
        """Test that invalid format raises ValueError."""
        exporter = ReportExporter()

        with pytest.raises(ValueError) as exc_info:
            exporter.export(sample_findings, "invalid_format")

        assert "Unsupported format" in str(exc_info.value)

    def test_export_all_creates_all_files(self, sample_findings, tmp_path):
        """Test export_all creates files in all formats."""
        exporter = ReportExporter()
        results = exporter.export_all(sample_findings, str(tmp_path))

        assert len(results) == 5
        for format_name, file_path in results.items():
            assert Path(file_path).exists()


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test Finding creation with required fields."""
        finding = Finding(
            id="F001",
            type="reentrancy",
            severity="high",
            title="Test",
            description="Test description",
            file_path="test.sol",
            line_start=1,
        )

        assert finding.id == "F001"
        assert finding.severity == "high"
        assert finding.confidence == 0.8  # default

    def test_finding_optional_fields(self):
        """Test Finding with optional fields."""
        finding = Finding(
            id="F001",
            type="test",
            severity="low",
            title="Test",
            description="Test",
            file_path="test.sol",
            line_start=1,
            line_end=10,
            column_start=5,
            column_end=20,
            cwe="CWE-123",
            swc="SWC-100",
            remediation="Fix it",
        )

        assert finding.line_end == 10
        assert finding.cwe == "CWE-123"
        assert finding.remediation == "Fix it"
