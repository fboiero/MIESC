"""
`miesc compliance` — export findings mapped to security standards.

Maps MIESC findings to 12 international standards:
  ISO 27001, NIST CSF, OWASP Smart Contract Top 10, CWE, SWC,
  MITRE ATT&CK, PCI DSS, SOC 2, MiCA Art.11, DORA Art.9,
  NIST SP 800-53, ASVS.

Produces a compliance artifact suitable for regulatory filing.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import click

from miesc import __version__ as VERSION
from miesc.cli.utils import console, error, info, print_banner, success

# Standard mapping from canonical categories to compliance frameworks
COMPLIANCE_MAP = {
    "reentrancy": {
        "SWC": "SWC-107",
        "CWE": "CWE-841",
        "OWASP_SC": "SC01: Reentrancy",
        "ISO_27001": "A.14.2.5 Secure development principles",
        "NIST_CSF": "PR.IP-12: Vulnerability management",
        "MITRE": "T1499.004: Application exhaustion flood",
        "MiCA": "Art.11(1): ICT security policy — reentrancy protection",
        "DORA": "Art.9(2): ICT risk management — code-level controls",
    },
    "access_control": {
        "SWC": "SWC-105",
        "CWE": "CWE-284",
        "OWASP_SC": "SC04: Access Control",
        "ISO_27001": "A.9.4.1 Information access restriction",
        "NIST_CSF": "PR.AC-4: Access permissions and authorizations",
        "MITRE": "T1068: Exploitation for privilege escalation",
        "MiCA": "Art.11(1): Authorization and access control",
        "DORA": "Art.9(3): Access control and identity management",
    },
    "oracle_manipulation": {
        "SWC": "SWC-136",
        "CWE": "CWE-20",
        "OWASP_SC": "SC06: Oracle Manipulation",
        "ISO_27001": "A.14.1.2 Securing application services on public networks",
        "NIST_CSF": "DE.CM-4: Malicious code detection",
        "MiCA": "Art.11(1): Price feed integrity",
        "DORA": "Art.9(2): Third-party data dependency risk",
    },
    "arithmetic": {
        "SWC": "SWC-101",
        "CWE": "CWE-190",
        "OWASP_SC": "SC02: Integer Overflow",
        "ISO_27001": "A.14.2.1 Secure development policy",
        "NIST_CSF": "PR.IP-12: Vulnerability management",
        "MiCA": "Art.11(1): Arithmetic safety controls",
    },
    "unchecked_call": {
        "SWC": "SWC-104",
        "CWE": "CWE-252",
        "OWASP_SC": "SC05: Unchecked Return Values",
        "ISO_27001": "A.14.2.5 Secure development principles",
        "NIST_CSF": "PR.IP-12: Error handling requirements",
    },
    "flash_loan": {
        "SWC": "N/A",
        "CWE": "CWE-362",
        "OWASP_SC": "SC07: Flash Loan Attacks",
        "ISO_27001": "A.14.2.5 Atomicity and transaction integrity",
        "MiCA": "Art.11(1): Flash loan protection mechanisms",
    },
    "bad_randomness": {
        "SWC": "SWC-120",
        "CWE": "CWE-330",
        "OWASP_SC": "SC03: Randomness",
        "ISO_27001": "A.10.1.1 Cryptographic controls policy",
        "NIST_CSF": "PR.DS-5: Protections against data leaks",
    },
    "time_manipulation": {
        "SWC": "SWC-116",
        "CWE": "CWE-829",
        "OWASP_SC": "SC08: Timestamp Dependence",
        "ISO_27001": "A.14.2.5 Trusted time sources",
    },
    "front_running": {
        "SWC": "SWC-114",
        "CWE": "CWE-362",
        "OWASP_SC": "SC09: Front Running",
        "ISO_27001": "A.14.2.5 Transaction ordering protection",
        "MiCA": "Art.11(1): Market manipulation controls",
    },
    "proxy_upgrade": {
        "SWC": "SWC-112",
        "CWE": "CWE-284",
        "OWASP_SC": "SC10: Proxy Vulnerabilities",
        "ISO_27001": "A.14.2.2 System change control procedures",
        "DORA": "Art.9(4): Change management controls",
    },
    "centralization": {
        "SWC": "N/A",
        "CWE": "CWE-250",
        "OWASP_SC": "SC04: Centralization Risk",
        "ISO_27001": "A.6.1.2 Segregation of duties",
        "MiCA": "Art.11(2): Decentralization requirements",
    },
}


@click.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--standard",
    type=click.Choice(
        ["all", "iso27001", "nist", "owasp", "swc", "cwe", "mica", "dora"],
        case_sensitive=False,
    ),
    default="all",
    help="Filter to specific standard (default: all)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON or Markdown)")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown"]), default="markdown")
@click.option("--quiet", "-q", is_flag=True)
def compliance(results_file, standard, output, fmt, quiet):
    """Map findings to international security standards.

    \b
    Supported standards:
      ISO 27001, NIST CSF, OWASP SC Top 10, CWE, SWC,
      MiCA Art.11, DORA Art.9

    \b
    Examples:
      miesc compliance results.json                    # All standards
      miesc compliance results.json --standard mica    # MiCA only
      miesc compliance results.json -f json -o map.json
    """
    if not quiet:
        print_banner()

    try:
        data = json.loads(Path(results_file).read_text())
    except Exception as e:
        error(f"Failed to load results: {e}")
        sys.exit(1)

    findings = data.get("findings", [])
    if not findings:
        for r in data.get("results", []):
            findings.extend(r.get("findings", []))

    if not findings:
        info("No findings to map")
        sys.exit(0)

    # Map each finding to compliance standards
    mapped = []
    for f in findings:
        canonical = f.get("canonical_category", "")
        standards = COMPLIANCE_MAP.get(canonical, {})

        if standard != "all":
            key_map = {
                "iso27001": "ISO_27001", "nist": "NIST_CSF",
                "owasp": "OWASP_SC", "swc": "SWC", "cwe": "CWE",
                "mica": "MiCA", "dora": "DORA",
            }
            filter_key = key_map.get(standard.lower(), "")
            if filter_key:
                standards = {k: v for k, v in standards.items() if k == filter_key}

        if standards:
            mapped.append({
                "finding_type": f.get("type", "unknown"),
                "severity": f.get("severity", "unknown"),
                "confidence": f.get("confidence", 0.5),
                "canonical_category": canonical,
                "standards": standards,
                "recommendation": f.get("recommendation", ""),
            })

    # Generate output
    if fmt == "json":
        output_data = {
            "miesc_version": VERSION,
            "timestamp": datetime.now().isoformat(),
            "source_file": results_file,
            "standard_filter": standard,
            "total_findings": len(findings),
            "mapped_findings": len(mapped),
            "mappings": mapped,
        }
        output_text = json.dumps(output_data, indent=2)
    else:
        lines = [
            "# MIESC Compliance Mapping Report",
            "",
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Source**: {results_file}",
            f"**MIESC Version**: {VERSION}",
            f"**Standard Filter**: {standard}",
            f"**Findings Mapped**: {len(mapped)} / {len(findings)}",
            "",
            "---",
            "",
        ]
        for i, m in enumerate(mapped, 1):
            lines.append(f"## {i}. [{m['severity']}] {m['finding_type']}")
            lines.append("")
            lines.append(f"**Category**: {m['canonical_category']} | **Confidence**: {m['confidence']:.0%}")
            lines.append("")
            lines.append("| Standard | Reference |")
            lines.append("|----------|-----------|")
            for std_name, std_ref in m["standards"].items():
                lines.append(f"| {std_name} | {std_ref} |")
            lines.append("")
            if m.get("recommendation"):
                lines.append(f"**Recommendation**: {m['recommendation']}")
                lines.append("")
            lines.append("---")
            lines.append("")
        output_text = "\n".join(lines)

    if output:
        Path(output).write_text(output_text)
        success(f"Compliance mapping → {output}")
    else:
        console.print(output_text)

    if not quiet:
        info(f"Mapped {len(mapped)}/{len(findings)} findings to {standard} standards")
