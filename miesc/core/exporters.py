"""
MIESC Report Exporters

Exports audit results in multiple formats for integration with various tools.
Supports SARIF (GitHub), SonarQube, Checkmarx, and custom formats.

Author: Fernando Boiero
License: AGPL-3.0
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast, Any, Dict, List, Optional

# Import version from miesc package
try:
    from miesc import __version__ as MIESC_VERSION
except ImportError:  # pragma: no cover - fallback when running outside the package
    MIESC_VERSION = "5.1.2"  # Fallback version


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

    def __init__(self, tool_name: str = "MIESC", tool_version: Optional[str] = None):
        self.tool_name = tool_name
        self.tool_version = tool_version or MIESC_VERSION

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
            "runs": [self._create_run(findings)],
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
                            "correlation",
                        ],
                    },
                }
            },
            "results": [self._finding_to_result(f) for f in findings],
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                }
            ],
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
        rule: Dict[str, Any] = {
            "id": self._get_rule_id(finding),
            "name": finding.type.replace("_", " ").title(),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": self._severity_to_level(finding.severity)},
            "properties": {
                "tags": ["security", "smart-contract", f"layer-{finding.layer}"],
                "precision": "high" if finding.confidence > 0.8 else "medium",
            },
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
                "markdown": f"## Remediation\n\n{finding.remediation}",
            }

        return rule

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        result = {
            "ruleId": self._get_rule_id(finding),
            "level": self._severity_to_level(finding.severity),
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": self._create_region(finding),
                    }
                }
            ],
            "fingerprints": {"primaryLocationLineHash": self._create_fingerprint(finding)},
            "properties": {
                "confidence": finding.confidence,
                "tool": finding.tool,
                "layer": finding.layer,
            },
        }

        # Add partial fingerprints for deduplication
        result["partialFingerprints"] = {
            "primaryLocationLineHash": self._create_fingerprint(finding)
        }

        return result

    def _create_region(self, finding: Finding) -> Dict[str, int]:
        """Create a SARIF region object."""
        region = {"startLine": finding.line_start}

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
            "info": "note",
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
        issues = {"issues": [self._finding_to_issue(f) for f in findings]}

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
                    "endColumn": finding.column_end or 0,
                },
            },
            "effortMinutes": self._estimate_effort(finding.severity),
        }

    def _severity_to_sonar(self, severity: str) -> str:
        """Convert MIESC severity to SonarQube severity."""
        mapping = {
            "critical": "BLOCKER",
            "high": "CRITICAL",
            "medium": "MAJOR",
            "low": "MINOR",
            "info": "INFO",
        }
        return mapping.get(severity.lower(), "MAJOR")

    def _estimate_effort(self, severity: str) -> int:
        """Estimate remediation effort in minutes."""
        efforts = {"critical": 120, "high": 60, "medium": 30, "low": 15, "info": 5}
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
        include_remediation: bool = True,
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
            "",
        ]

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: Dict[str, List[Finding]] = {}
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
            lines.append(
                f"**CWE:** [{finding.cwe}](https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html)  "
            )

        if finding.swc:
            lines.append(f"**SWC:** [{finding.swc}](https://swcregistry.io/{finding.swc})  ")

        lines.extend(["", finding.description, ""])

        if include_remediation and finding.remediation:
            lines.extend(["**Remediation:**", "", finding.remediation, ""])

        return lines


class JSONExporter:
    """Exports findings as structured JSON."""

    def export(
        self,
        findings: List[Finding],
        output_path: Optional[str] = None,
        include_metadata: bool = True,
    ) -> str:
        """Export findings to JSON format."""
        data: Dict[str, Any] = {"findings": [asdict(f) for f in findings]}

        if include_metadata:
            data["metadata"] = {
                "tool": "MIESC",
                "version": MIESC_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "total_findings": len(findings),
                "severity_counts": self._count_severities(findings),
            }

        json_str = json.dumps(data, indent=2)

        if output_path:
            Path(output_path).write_text(json_str)

        return json_str

    def _count_severities(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


class GitHubAnnotationsExporter:
    """
    Emits GitHub Actions workflow-command annotations for inline PR review.

    Each finding becomes a ``::error`` / ``::warning`` / ``::notice`` line of the
    form::

        ::error file=<path>,line=<n>,title=<rule>::<message>

    When GitHub Actions reads these lines from a step's stdout it renders them
    inline on the pull-request diff (and in the Checks tab), giving per-finding
    feedback that the summary comment alone cannot.

    Two properties make this production-safe:

    * **Severity ordering + a hard cap.** GitHub only surfaces a limited number
      of annotations inline (10 per level, per step, is the practical visible
      limit), so findings are sorted most-severe-first and capped. When the cap
      truncates, the count is logged *and* an extra ``::notice`` line is emitted
      so the suppression is never silent.
    * **Correct escaping.** Message data and property values are escaped exactly
      as GitHub's ``@actions/core`` toolkit does (``escapeData`` /
      ``escapeProperty``), so commas, colons, percent signs and newlines in a
      finding message can never break out of the command or corrupt a property.
    """

    #: Default number of annotations emitted inline before the cap kicks in.
    #: GitHub renders at most ~10 annotations of a given level per step.
    DEFAULT_MAX_ANNOTATIONS = 10

    #: MIESC severity -> GitHub Actions annotation level.
    LEVEL_BY_SEVERITY = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "warning",
        "info": "notice",
    }

    #: Most-severe-first ordering used when applying the cap.
    _SEVERITY_RANK = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(self, max_annotations: int = DEFAULT_MAX_ANNOTATIONS) -> None:
        self.max_annotations = max_annotations

    # -- public API --------------------------------------------------------

    def to_github_annotations(
        self, findings: List[Any], max_annotations: Optional[int] = None
    ) -> List[str]:
        """Render ``findings`` as GitHub Actions annotation command lines.

        Args:
            findings: Findings as MIESC ``Finding`` dataclasses or plain dicts
                (flat ``file``/``line`` or nested ``location={file,line}``).
            max_annotations: Override the instance cap for this call.

        Returns:
            A list of ``::level ...::message`` strings. When more findings are
            supplied than the cap allows, only the most severe are rendered and
            a trailing ``::notice`` line reports how many were suppressed.
        """
        import logging

        cap = self.max_annotations if max_annotations is None else max_annotations

        # Sort most-severe-first; stable so same-severity input order is kept.
        ordered = sorted(findings, key=self._severity_rank)

        shown = ordered if cap is None or cap < 0 else ordered[:cap]
        suppressed = len(ordered) - len(shown)

        lines = [self._finding_to_annotation(f) for f in shown]

        if suppressed > 0:
            logging.getLogger(__name__).warning(
                "GitHub annotations capped at %d: %d additional finding(s) "
                "suppressed from inline view (see the full report / Security tab).",
                len(shown),
                suppressed,
            )
            lines.append(
                "::notice::MIESC: "
                f"{suppressed} additional finding(s) not shown inline "
                f"(annotation cap {len(shown)}); see the full SARIF report "
                "in the Security tab."
            )

        return lines

    def export(
        self,
        findings: List[Any],
        output_path: Optional[str] = None,
        max_annotations: Optional[int] = None,
    ) -> str:
        """Return the annotation lines joined by newlines (dispatcher-compatible)."""
        lines = self.to_github_annotations(findings, max_annotations=max_annotations)
        text = "\n".join(lines) + ("\n" if lines else "")
        if output_path:
            Path(output_path).write_text(text)
        return text

    # -- helpers -----------------------------------------------------------

    def _finding_to_annotation(self, finding: Any) -> str:
        """Render a single finding to a ``::level file=,line=,title=::msg`` line."""
        from miesc.core import baseline as _baseline

        norm = _baseline.normalize_finding(finding)
        severity = norm.get("severity", "") or "info"
        level = self.LEVEL_BY_SEVERITY.get(severity.lower(), "warning")

        file_path = norm.get("file", "")
        title = norm.get("rule_id", "") or "finding"
        message = norm.get("message", "") or title
        line = self._extract_line(finding)

        props = []
        if file_path:
            props.append(f"file={self._escape_property(file_path)}")
        if line is not None:
            props.append(f"line={line}")
        props.append(f"title={self._escape_property(title)}")

        prop_str = ",".join(props)
        return f"::{level} {prop_str}::{self._escape_data(message)}"

    @staticmethod
    def _extract_line(finding: Any) -> Optional[int]:
        """Resolve a 1-based source line across the known finding shapes."""
        candidates: List[Any] = []
        if isinstance(finding, dict):
            loc = finding.get("location")
            if isinstance(loc, dict):
                candidates += [loc.get("line"), loc.get("line_start"), loc.get("start_line")]
            candidates += [
                finding.get("line"),
                finding.get("line_start"),
                finding.get("start_line"),
            ]
        else:
            candidates += [
                getattr(finding, "line_start", None),
                getattr(finding, "line", None),
            ]
        for value in candidates:
            if value in (None, ""):
                continue
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            if parsed > 0:
                return parsed
        return None

    @staticmethod
    def _escape_data(value: str) -> str:
        """Escape a workflow-command message body (GitHub ``escapeData``)."""
        return (
            str(value)
            .replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )

    @staticmethod
    def _escape_property(value: str) -> str:
        """Escape a workflow-command property value (GitHub ``escapeProperty``)."""
        return (
            str(value)
            .replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
            .replace(":", "%3A")
            .replace(",", "%2C")
        )

    def _severity_rank(self, finding: Any) -> int:
        from miesc.core import baseline as _baseline

        severity = _baseline.normalize_finding(finding).get("severity", "")
        return self._SEVERITY_RANK.get(severity.lower(), 99)


class ReportExporter:
    """
    Unified report exporter supporting multiple formats.

    Usage:
        exporter = ReportExporter()
        exporter.export(findings, "sarif", "report.sarif")
        exporter.export(findings, "sonarqube", "report.json")
        exporter.export(findings, "markdown", "report.md")
    """

    def __init__(self) -> None:
        self.exporters: Dict[str, Any] = {
            "sarif": SARIFExporter(),
            "sonarqube": SonarQubeExporter(),
            "checkmarx": CheckmarxExporter(),
            "markdown": MarkdownExporter(),
            "json": JSONExporter(),
            "github": GitHubAnnotationsExporter(),
        }

    def export(
        self, findings: List[Finding], format: str, output_path: Optional[str] = None, **kwargs: Any
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
        return cast(str, exporter.export(findings, output_path, **kwargs))

    def export_all(
        self, findings: List[Finding], output_dir: str, base_name: str = "report"
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
            "json": ".json",
        }

        results = {}
        for format, ext in extensions.items():
            file_path = output_path / f"{base_name}{ext}"
            self.export(findings, format, str(file_path))
            results[format] = str(file_path)

        return results
