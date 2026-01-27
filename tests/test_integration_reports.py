"""
MIESC Integration Tests - Report Generation
Tests report generation across all formats (JSON, Markdown, HTML, SARIF).
"""

import json
import os
import tempfile

import pytest

from src.reports.audit_report import AuditReportGenerator, AuditMetadata, Finding
from src.core.exporters import (
    Finding as ExportFinding,
    SARIFExporter,
    MarkdownExporter,
    JSONExporter,
    ReportExporter,
)


# ============================================================================
# TestReportGeneration - Report generation across formats
# ============================================================================


@pytest.mark.integration
class TestReportGeneration:
    """Integration tests for report generation across all formats."""

    def test_json_report_valid_schema(self, report_findings, report_metadata):
        """JSON report should have required keys."""
        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=report_findings,
        )

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            generator.save_json(output_path)

            with open(output_path) as out:
                data = json.load(out)

            assert 'metadata' in data
            assert 'findings' in data
            assert 'summary' in data
            assert 'generated_at' in data

            # Metadata fields
            meta = data['metadata']
            assert 'project_name' in meta
            assert 'contract_name' in meta
            assert 'version' in meta
            assert 'contract_hash' in meta
            assert 'audit_date' in meta

            # Summary fields
            summary = data['summary']
            assert 'risk_score' in summary
            assert 'total_findings' in summary
            assert 'by_severity' in summary

            # Findings
            assert len(data['findings']) == len(report_findings)
        finally:
            os.unlink(output_path)

    def test_markdown_report_contains_sections(self, report_findings, report_metadata):
        """Markdown report should have headers for each section."""
        # Use MarkdownExporter
        export_findings = [
            ExportFinding(
                id=f.id,
                type=f.category.lower().replace(' ', '-'),
                severity=f.severity.lower(),
                title=f.title,
                description=f.description,
                file_path=f.location.split(':')[0] if ':' in f.location else f.location,
                line_start=f.line_number or 1,
                tool=f.tool,
                layer=f.layer,
                cwe=f.cwe_id,
                swc=f.swc_id,
                remediation=f.remediation,
            )
            for f in report_findings
        ]

        exporter = MarkdownExporter()
        md_content = exporter.export(export_findings)

        # Should have key sections
        assert '# MIESC Security Audit Report' in md_content
        assert '## Summary' in md_content
        assert '## Findings' in md_content
        assert '|' in md_content  # Table present

        # Should contain severity sections
        assert 'CRITICAL' in md_content or 'HIGH' in md_content

    def test_html_report_valid_structure(self, report_findings, report_metadata):
        """HTML report should have proper tags and structure."""
        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=report_findings,
        )

        html = generator.generate_html()

        assert '<!DOCTYPE html>' in html
        assert '<html' in html
        assert '</html>' in html
        assert '<head>' in html
        assert '<body>' in html
        assert '<style>' in html

        # Should contain report sections
        assert 'Security Audit Report' in html
        assert 'Executive Summary' in html
        assert 'Methodology' in html
        assert 'Detailed Findings' in html

        # Should contain metadata
        assert report_metadata.contract_name in html
        assert report_metadata.project_name in html
        assert report_metadata.auditor in html

        # Should have finding cards with severity badges
        assert 'severity-badge' in html
        assert 'finding-header' in html

    def test_sarif_report_valid_schema(self, report_findings):
        """SARIF output should conform to SARIF 2.1.0 schema."""
        export_findings = [
            ExportFinding(
                id=f.id,
                type=f.category.lower().replace(' ', '-'),
                severity=f.severity.lower(),
                title=f.title,
                description=f.description,
                file_path=f.location.split(':')[0] if ':' in f.location else f.location,
                line_start=f.line_number or 1,
                tool=f.tool,
                layer=f.layer,
                cwe=f.cwe_id,
                swc=f.swc_id,
            )
            for f in report_findings
        ]

        exporter = SARIFExporter()
        sarif_json = exporter.export(export_findings)

        data = json.loads(sarif_json)

        # SARIF 2.1.0 required fields
        assert data['version'] == '2.1.0'
        assert '$schema' in data
        assert 'runs' in data
        assert len(data['runs']) == 1

        run = data['runs'][0]
        assert 'tool' in run
        assert 'driver' in run['tool']
        assert 'name' in run['tool']['driver']
        assert 'results' in run

        # Verify results
        assert len(run['results']) == len(export_findings)

        for result in run['results']:
            assert 'ruleId' in result
            assert 'level' in result
            assert 'message' in result
            assert 'locations' in result

            # Verify location structure
            loc = result['locations'][0]
            assert 'physicalLocation' in loc
            assert 'artifactLocation' in loc['physicalLocation']
            assert 'region' in loc['physicalLocation']

    def test_report_with_empty_findings(self, report_metadata):
        """Report should handle 0 findings gracefully."""
        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=[],
        )

        # JSON
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            generator.save_json(output_path)
            with open(output_path) as out:
                data = json.load(out)

            assert data['summary']['total_findings'] == 0
            assert len(data['findings']) == 0
            assert data['summary']['risk_score'] == 0
        finally:
            os.unlink(output_path)

        # HTML
        html = generator.generate_html()
        assert 'No security vulnerabilities detected' in html

        # SARIF
        sarif_exporter = SARIFExporter()
        sarif_json = sarif_exporter.export([])
        sarif_data = json.loads(sarif_json)
        assert len(sarif_data['runs'][0]['results']) == 0

    def test_report_with_high_severity_findings(self, report_metadata):
        """Critical/High findings should be highlighted correctly."""
        findings = [
            Finding(
                id='CRIT-001',
                title='Critical Vulnerability',
                severity='Critical',
                category='Reentrancy',
                description='This is a critical finding.',
                location='test.sol:10',
                line_number=10,
                tool='slither',
                layer=1,
            ),
            Finding(
                id='HIGH-001',
                title='High Severity Issue',
                severity='High',
                category='Access Control',
                description='This is a high severity finding.',
                location='test.sol:20',
                line_number=20,
                tool='mythril',
                layer=3,
            ),
        ]

        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=findings,
        )

        # JSON: risk score should be high
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            generator.save_json(output_path)
            with open(output_path) as out:
                data = json.load(out)

            assert data['summary']['risk_score'] > 0
            assert data['summary']['by_severity']['Critical'] == 1
            assert data['summary']['by_severity']['High'] == 1
        finally:
            os.unlink(output_path)

        # HTML: should contain severity colors/badges
        html = generator.generate_html()
        assert '#dc2626' in html  # Critical red color
        assert 'Critical' in html

    def test_report_metadata_populated(self, report_findings, report_metadata):
        """Metadata (project, version, hash, date) should be present."""
        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=report_findings,
        )

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            generator.save_json(output_path)
            with open(output_path) as out:
                data = json.load(out)

            meta = data['metadata']
            assert meta['project_name'] == 'Test Project'
            assert meta['contract_name'] == 'VulnerableBank.sol'
            assert meta['version'] == '1.0.0'
            assert meta['contract_hash'] == 'abc123def456'
            assert meta['audit_date'] == '2026-01-27'
            assert meta['solidity_version'] == '0.8.0'
            assert meta['lines_of_code'] == 30
        finally:
            os.unlink(output_path)


# ============================================================================
# TestReportExporterUnified
# ============================================================================


@pytest.mark.integration
class TestReportExporterUnified:
    """Tests for the unified ReportExporter."""

    def _make_export_findings(self):
        """Create sample export findings."""
        return [
            ExportFinding(
                id='F-001',
                type='reentrancy',
                severity='critical',
                title='Reentrancy Vulnerability',
                description='State change after external call.',
                file_path='contract.sol',
                line_start=15,
                tool='slither',
                layer=1,
                cwe='CWE-841',
                swc='SWC-107',
            ),
        ]

    def test_unified_exporter_sarif(self):
        """Unified exporter handles SARIF format."""
        exporter = ReportExporter()
        findings = self._make_export_findings()

        result = exporter.export(findings, 'sarif')
        data = json.loads(result)
        assert data['version'] == '2.1.0'

    def test_unified_exporter_json(self):
        """Unified exporter handles JSON format."""
        exporter = ReportExporter()
        findings = self._make_export_findings()

        result = exporter.export(findings, 'json')
        data = json.loads(result)
        assert 'findings' in data
        assert 'metadata' in data

    def test_unified_exporter_markdown(self):
        """Unified exporter handles Markdown format."""
        exporter = ReportExporter()
        findings = self._make_export_findings()

        result = exporter.export(findings, 'markdown')
        assert '# MIESC Security Audit Report' in result
        assert 'Reentrancy Vulnerability' in result


# ============================================================================
# TestHTMLReportSave
# ============================================================================


@pytest.mark.integration
class TestHTMLReportSave:
    """Tests for saving HTML reports to file."""

    def test_save_html_creates_file(self, report_findings, report_metadata):
        """save_html should create a valid HTML file."""
        generator = AuditReportGenerator(
            metadata=report_metadata,
            findings=report_findings,
        )

        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            output_path = f.name

        try:
            result_path = generator.save_html(output_path)
            assert os.path.exists(str(result_path))

            with open(str(result_path)) as out:
                content = out.read()
            assert '<!DOCTYPE html>' in content
            assert len(content) > 1000  # Non-trivial HTML
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
