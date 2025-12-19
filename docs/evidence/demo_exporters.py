#!/usr/bin/env python3
"""
MIESC v4.2.0 - Demo: Exporters Module
=====================================
Demonstrates multi-format export capabilities:
- SARIF (GitHub/GitLab Integration)
- SonarQube (Enterprise CI/CD)
- Checkmarx (Enterprise SAST)
- Markdown (Human-readable)
- JSON (API Integration)

Author: Fernando Boiero
License: GPL-3.0
"""

import json
import sys
sys.path.insert(0, '/Users/fboiero/Documents/GitHub/MIESC')

from src.core.exporters import (
    Finding,
    SARIFExporter,
    SonarQubeExporter,
    CheckmarxExporter,
    MarkdownExporter,
    JSONExporter,
)

# Sample findings from a MIESC audit using Finding dataclass
SAMPLE_FINDINGS = [
    Finding(
        id="MIESC-001",
        type="reentrancy",
        severity="critical",
        title="Reentrancy Vulnerability",
        description="External call before state update allows reentrancy attack",
        file_path="contracts/Vault.sol",
        line_start=42,
        line_end=48,
        column_start=8,
        tool="slither",
        layer=1,
        cwe="CWE-841",
        swc="SWC-107",
        confidence=0.95,
        remediation="Use ReentrancyGuard or checks-effects-interactions pattern"
    ),
    Finding(
        id="MIESC-002",
        type="overflow",
        severity="high",
        title="Integer Overflow",
        description="Arithmetic operation may overflow",
        file_path="contracts/Token.sol",
        line_start=156,
        column_start=12,
        tool="mythril",
        layer=3,
        cwe="CWE-190",
        confidence=0.88,
        remediation="Use SafeMath or Solidity 0.8.x built-in overflow checks"
    ),
    Finding(
        id="MIESC-003",
        type="unchecked_call",
        severity="medium",
        title="Unchecked Return Value",
        description="Return value of low-level call not checked",
        file_path="contracts/Utils.sol",
        line_start=78,
        tool="slither",
        layer=1,
        cwe="CWE-252",
        confidence=0.82,
        remediation="Check return value or use require()"
    ),
    Finding(
        id="MIESC-004",
        type="gas",
        severity="low",
        title="Gas Optimization",
        description="Loop can be optimized to save gas",
        file_path="contracts/Staking.sol",
        line_start=234,
        tool="aderyn",
        layer=1,
        confidence=0.75,
        remediation="Cache array length outside loop"
    )
]

def print_separator(title: str):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def demo_sarif_export():
    """Demo SARIF export for GitHub/GitLab integration."""
    print_separator("SARIF Export (GitHub/GitLab)")

    exporter = SARIFExporter()
    sarif_output = exporter.export(SAMPLE_FINDINGS, "contracts/Vault.sol")

    # Parse and pretty print
    sarif_data = json.loads(sarif_output)

    print(f"SARIF Version: {sarif_data['version']}")
    print(f"Schema: {sarif_data['$schema']}")
    print(f"\nTool: {sarif_data['runs'][0]['tool']['driver']['name']}")
    print(f"Rules defined: {len(sarif_data['runs'][0]['tool']['driver']['rules'])}")
    print(f"Results: {len(sarif_data['runs'][0]['results'])}")

    print("\nSample Result:")
    result = sarif_data['runs'][0]['results'][0]
    print(json.dumps(result, indent=2)[:500] + "...")

    # Save file
    with open('/Users/fboiero/Documents/GitHub/MIESC/docs/evidence/output_sarif.json', 'w') as f:
        f.write(sarif_output)
    print("\n[Saved to: docs/evidence/output_sarif.json]")


def demo_sonarqube_export():
    """Demo SonarQube export for enterprise CI/CD."""
    print_separator("SonarQube Export (Enterprise CI/CD)")

    exporter = SonarQubeExporter()
    sonar_output = exporter.export(SAMPLE_FINDINGS)  # No output path = return string

    sonar_data = json.loads(sonar_output)

    print(f"Total Issues: {len(sonar_data['issues'])}")
    print("\nSeverity Distribution:")
    severities = {}
    for issue in sonar_data['issues']:
        sev = issue['severity']
        severities[sev] = severities.get(sev, 0) + 1
    for sev, count in sorted(severities.items()):
        print(f"  - {sev}: {count}")

    print("\nSample Issue:")
    print(json.dumps(sonar_data['issues'][0], indent=2))

    with open('/Users/fboiero/Documents/GitHub/MIESC/docs/evidence/output_sonarqube.json', 'w') as f:
        f.write(sonar_output)
    print("\n[Saved to: docs/evidence/output_sonarqube.json]")


def demo_checkmarx_export():
    """Demo Checkmarx export for enterprise SAST (XML format)."""
    print_separator("Checkmarx Export (Enterprise SAST - XML)")

    exporter = CheckmarxExporter()
    checkmarx_output = exporter.export(SAMPLE_FINDINGS)

    # Parse XML
    from xml.etree import ElementTree as ET
    root = ET.fromstring(checkmarx_output)

    print(f"Initiator: {root.get('InitiatorName')}")
    print(f"Scan Start: {root.get('ScanStart')}")
    print(f"Total Queries: {len(root.findall('Query'))}")

    print("\nSample Query (XML):")
    first_query = root.find('Query')
    if first_query is not None:
        print(f"  Name: {first_query.get('name')}")
        print(f"  Severity: {first_query.get('Severity')}")
        print(f"  CWE: {first_query.get('CweId')}")

    with open('/Users/fboiero/Documents/GitHub/MIESC/docs/evidence/output_checkmarx.xml', 'w') as f:
        f.write(checkmarx_output)
    print("\n[Saved to: docs/evidence/output_checkmarx.xml]")


def demo_markdown_export():
    """Demo Markdown export for human-readable reports."""
    print_separator("Markdown Export (Human-Readable)")

    exporter = MarkdownExporter()
    md_output = exporter.export(SAMPLE_FINDINGS)  # No output path = return string

    # Show first part of markdown
    print(md_output[:1500])
    print("\n... [truncated] ...")

    with open('/Users/fboiero/Documents/GitHub/MIESC/docs/evidence/output_report.md', 'w') as f:
        f.write(md_output)
    print("\n[Saved to: docs/evidence/output_report.md]")


def demo_json_export():
    """Demo JSON export for API integration."""
    print_separator("JSON Export (API Integration)")

    exporter = JSONExporter()
    json_output = exporter.export(SAMPLE_FINDINGS)

    data = json.loads(json_output)

    print(f"Tool: {data['metadata']['tool']}")
    print(f"Version: {data['metadata']['version']}")
    print(f"Generated: {data['metadata']['generated_at']}")
    print(f"Total Findings: {data['metadata']['total_findings']}")
    print(f"\nSeverity Summary:")
    for sev, count in data['metadata']['severity_counts'].items():
        if count > 0:
            print(f"  - {sev}: {count}")

    with open('/Users/fboiero/Documents/GitHub/MIESC/docs/evidence/output_json.json', 'w') as f:
        f.write(json_output)
    print("\n[Saved to: docs/evidence/output_json.json]")


def demo_unified_export():
    """Demo unified export function."""
    print_separator("Unified Export - All Formats")

    exporters = {
        "sarif": SARIFExporter(),
        "sonarqube": SonarQubeExporter(),
        "checkmarx": CheckmarxExporter(),
        "markdown": MarkdownExporter(),
        "json": JSONExporter(),
    }

    print("Available formats:")
    for name in exporters:
        print(f"  - {name}")

    print("\nExporting to all formats...")

    for name, exporter in exporters.items():
        output = exporter.export(SAMPLE_FINDINGS)
        print(f"  [{name}] Generated {len(output)} bytes")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("       MIESC v4.2.0 'Fortress' - Exporters Demo")
    print("       Multi-format Security Report Export")
    print("=" * 60)

    demo_sarif_export()
    demo_sonarqube_export()
    demo_checkmarx_export()
    demo_markdown_export()
    demo_json_export()
    demo_unified_export()

    print("\n" + "=" * 60)
    print("  Demo Complete! Check docs/evidence/ for output files")
    print("=" * 60 + "\n")
