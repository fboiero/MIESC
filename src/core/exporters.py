"""
MIESC Report Exporters

Exports audit results in multiple formats for integration with various tools.
Supports SARIF (GitHub), SonarQube, Checkmarx, and custom formats.

Author: Fernando Boiero
License: GPL-3.0
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    type: str
    severity: str
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    tool: str = "miesc"
    layer: int = 1
    cwe: Optional[str] = None
    swc: Optional[str] = None
    confidence: float = 0.8
    remediation: Optional[str] = None


class SARIFExporter:
    """
    Exports findings in SARIF 2.1.0 format for GitHub Code Scanning.

    SARIF (Static Analysis Results Interchange Format) is the standard
    format for GitHub security alerts and code scanning results.
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, tool_name: str = "MIESC", tool_version: str = "4.1.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def export(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        """
        Export findings to SARIF format.

        Args:
            findings: List of security findings
            output_path: Optional path to write the SARIF file

        Returns:
            SARIF JSON string
        """
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(findings)]
        }

        sarif_json = json.dumps(sarif, indent=2)

        if output_path:
            Path(output_path).write_text(sarif_json)

        return sarif_json

    def _create_run(self, findings: List[Finding]) -> Dict[str, Any]:
        """Create a SARIF run object."""
        # Collect unique rules from findings
        rules = self._extract_rules(findings)

        return {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/fboiero/miesc",
                    "rules": rules,
                    "properties": {
                        "layers": 7,
                        "techniques": [
                            "static-analysis",
                            "fuzzing",
                            "symbolic-execution",
                            "formal-verification",
                            "ai-analysis",
                            "ml-detection",
                            "correlation"
                        ]
                    }
                }
            },
            "results": [self._finding_to_result(f) for f in findings],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }]
        }

    def _extract_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Extract unique rules from findings."""
        rules_map = {}

        for finding in findings:
            rule_id = self._get_rule_id(finding)
            if rule_id not in rules_map:
                rules_map[rule_id] = self._create_rule(finding)

        return list(rules_map.values())

    def _get_rule_id(self, finding: Finding) -> str:
        """Generate a rule ID from finding type."""
        return f"MIESC-{finding.type.upper().replace(' ', '-').replace('_', '-')}"

    def _create_rule(self, finding: Finding) -> Dict[str, Any]:
        """Create a SARIF rule from a finding."""
        rule = {
            "id": self._get_rule_id(finding),
            "name": finding.type.replace("_", " ").title(),
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.description
            },
            "defaultConfiguration": {
                "level": self._severity_to_level(finding.severity)
            },
            "properties": {
                "tags": [
                    "security",
                    "smart-contract",
                    f"layer-{finding.layer}"
                ],
                "precision": "high" if finding.confidence > 0.8 else "medium"
            }
        }

        # Add CWE reference if available
        if finding.cwe:
            rule["properties"]["cwe"] = finding.cwe

        # Add SWC reference if available
        if finding.swc:
            rule["properties"]["swc"] = finding.swc

        # Add help text with remediation
        if finding.remediation:
            rule["help"] = {
                "text": finding.remediation,
                "markdown": f"## Remediation\n\n{finding.remediation}"
            }

        return rule

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        result = {
            "ruleId": self._get_rule_id(finding),
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": finding.description
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": self._create_region(finding)
                }
            }],
            "fingerprints": {
                "primaryLocationLineHash": self._create_fingerprint(finding)
            },
            "properties": {
                "confidence": finding.confidence,
                "tool": finding.tool,
                "layer": finding.layer
            }
        }

        # Add partial fingerprints for deduplication
        result["partialFingerprints"] = {
            "primaryLocationLineHash": self._create_fingerprint(finding)
        }

        return result

    def _create_region(self, finding: Finding) -> Dict[str, int]:
        """Create a SARIF region object."""
        region = {
            "startLine": finding.line_start
        }

        if finding.line_end:
            region["endLine"] = finding.line_end

        if finding.column_start:
            region["startColumn"] = finding.column_start

        if finding.column_end:
            region["endColumn"] = finding.column_end

        return region

    def _severity_to_level(self, severity: str) -> str:
        """Convert MIESC severity to SARIF level."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity.lower(), "warning")

    def _create_fingerprint(self, finding: Finding) -> str:
        """Create a unique fingerprint for the finding."""
        content = f"{finding.file_path}:{finding.line_start}:{finding.type}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class SonarQubeExporter:
    """
    Exports findings in SonarQube Generic Issue Import format.

    Reference: https://docs.sonarqube.org/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
    """

    def export(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        """Export findings to SonarQube format."""
        issues = {
            "issues": [self._finding_to_issue(f) for f in findings]
        }

        json_str = json.dumps(issues, indent=2)

        if output_path:
            Path(output_path).write_text(json_str)

        return json_str

    def _finding_to_issue(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a SonarQube issue."""
        return {
            "engineId": "miesc",
            "ruleId": finding.type,
            "severity": self._severity_to_sonar(finding.severity),
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": finding.description,
                "filePath": finding.file_path,
                "textRange": {
                    "startLine": finding.line_start,
                    "endLine": finding.line_end or finding.line_start,
                    "startColumn": finding.column_start or 0,
                    "endColumn": finding.column_end or 0
                }
            },
            "effortMinutes": self._estimate_effort(finding.severity)
        }

    def _severity_to_sonar(self, severity: str) -> str:
        """Convert MIESC severity to SonarQube severity."""
        mapping = {
            "critical": "BLOCKER",
            "high": "CRITICAL",
            "medium": "MAJOR",
            "low": "MINOR",
            "info": "INFO"
        }
        return mapping.get(severity.lower(), "MAJOR")

    def _estimate_effort(self, severity: str) -> int:
        """Estimate remediation effort in minutes."""
        efforts = {
            "critical": 120,
            "high": 60,
            "medium": 30,
            "low": 15,
            "info": 5
        }
        return efforts.get(severity.lower(), 30)


class CheckmarxExporter:
    """Exports findings in Checkmarx-compatible XML format."""

    def export(self, findings: List[Finding], output_path: Optional[str] = None) -> str:
        """Export findings to Checkmarx XML format."""
        from xml.etree import ElementTree as ET

        root = ET.Element("CxXMLResults")
        root.set("InitiatorName", "MIESC")
        root.set("ScanStart", datetime.now(timezone.utc).isoformat())

        for finding in findings:
            query = ET.SubElement(root, "Query")
            query.set("name", finding.type)
            query.set("Severity", finding.severity.capitalize())
            query.set("CweId", finding.cwe or "")

            result = ET.SubElement(query, "Result")
            result.set("FileName", finding.file_path)
            result.set("Line", str(finding.line_start))
            result.set("Column", str(finding.column_start or 0))
            result.set("DeepLink", "")

            path = ET.SubElement(result, "Path")
            node = ET.SubElement(path, "PathNode")
            ET.SubElement(node, "FileName").text = finding.file_path
            ET.SubElement(node, "Line").text = str(finding.line_start)
            ET.SubElement(node, "Column").text = str(finding.column_start or 0)
            ET.SubElement(node, "Name").text = finding.title
            ET.SubElement(node, "Snippet").text = finding.description

        xml_str = ET.tostring(root, encoding="unicode")

        if output_path:
            Path(output_path).write_text(xml_str)

        return xml_str


class MarkdownExporter:
    """Exports findings as a Markdown report."""

    def export(
        self,
        findings: List[Finding],
        output_path: Optional[str] = None,
        include_remediation: bool = True
    ) -> str:
        """Export findings to Markdown format."""
        lines = [
            "# MIESC Security Audit Report",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Summary",
            "",
            self._create_summary_table(findings),
            "",
            "## Findings",
            ""
        ]

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {}
        for finding in findings:
            sev = finding.severity.lower()
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(finding)

        for severity in severity_order:
            if severity in grouped:
                lines.append(f"### {severity.upper()} ({len(grouped[severity])})")
                lines.append("")

                for finding in grouped[severity]:
                    lines.extend(self._format_finding(finding, include_remediation))
                    lines.append("")

        markdown = "\n".join(lines)

        if output_path:
            Path(output_path).write_text(markdown)

        return markdown

    def _create_summary_table(self, findings: List[Finding]) -> str:
        """Create summary statistics table."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1

        return f"""| Severity | Count |
|----------|-------|
| Critical | {counts['critical']} |
| High | {counts['high']} |
| Medium | {counts['medium']} |
| Low | {counts['low']} |
| Info | {counts['info']} |
| **Total** | **{len(findings)}** |"""

    def _format_finding(self, finding: Finding, include_remediation: bool) -> List[str]:
        """Format a single finding."""
        lines = [
            f"#### {finding.title}",
            "",
            f"**Type:** {finding.type}  ",
            f"**Location:** `{finding.file_path}:{finding.line_start}`  ",
            f"**Tool:** {finding.tool} (Layer {finding.layer})  ",
            f"**Confidence:** {finding.confidence:.0%}  ",
        ]

        if finding.cwe:
            lines.append(f"**CWE:** [{finding.cwe}](https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html)  ")

        if finding.swc:
            lines.append(f"**SWC:** [{finding.swc}](https://swcregistry.io/{finding.swc})  ")

        lines.extend(["", finding.description, ""])

        if include_remediation and finding.remediation:
            lines.extend([
                "**Remediation:**",
                "",
                finding.remediation,
                ""
            ])

        return lines


class JSONExporter:
    """Exports findings as structured JSON."""

    def export(
        self,
        findings: List[Finding],
        output_path: Optional[str] = None,
        include_metadata: bool = True
    ) -> str:
        """Export findings to JSON format."""
        data = {
            "findings": [asdict(f) for f in findings]
        }

        if include_metadata:
            data["metadata"] = {
                "tool": "MIESC",
                "version": "4.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "total_findings": len(findings),
                "severity_counts": self._count_severities(findings)
            }

        json_str = json.dumps(data, indent=2)

        if output_path:
            Path(output_path).write_text(json_str)

        return json_str

    def _count_severities(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for f in findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


class ReportExporter:
    """
    Unified report exporter supporting multiple formats.

    Usage:
        exporter = ReportExporter()
        exporter.export(findings, "sarif", "report.sarif")
        exporter.export(findings, "sonarqube", "report.json")
        exporter.export(findings, "markdown", "report.md")
    """

    def __init__(self):
        self.exporters = {
            "sarif": SARIFExporter(),
            "sonarqube": SonarQubeExporter(),
            "checkmarx": CheckmarxExporter(),
            "markdown": MarkdownExporter(),
            "json": JSONExporter()
        }

    def export(
        self,
        findings: List[Finding],
        format: str,
        output_path: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Export findings in the specified format.

        Args:
            findings: List of security findings
            format: Export format (sarif, sonarqube, checkmarx, markdown, json)
            output_path: Optional path to write the report
            **kwargs: Additional format-specific options

        Returns:
            Exported report string

        Raises:
            ValueError: If format is not supported
        """
        if format not in self.exporters:
            raise ValueError(
                f"Unsupported format: {format}. "
                f"Supported formats: {', '.join(self.exporters.keys())}"
            )

        exporter = self.exporters[format]
        return exporter.export(findings, output_path, **kwargs)

    def export_all(
        self,
        findings: List[Finding],
        output_dir: str,
        base_name: str = "report"
    ) -> Dict[str, str]:
        """
        Export findings in all supported formats.

        Args:
            findings: List of security findings
            output_dir: Directory to write reports
            base_name: Base name for report files

        Returns:
            Dictionary mapping format to file path
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        extensions = {
            "sarif": ".sarif",
            "sonarqube": ".sonarqube.json",
            "checkmarx": ".checkmarx.xml",
            "markdown": ".md",
            "json": ".json"
        }

        results = {}
        for format, ext in extensions.items():
            file_path = output_path / f"{base_name}{ext}"
            self.export(findings, format, str(file_path))
            results[format] = str(file_path)

        return results
