"""
MIESC CLI - Export Command

Export JSON audit results to different formats (SARIF, Markdown, CSV, HTML).

Author: Fernando Boiero
License: AGPL-3.0
"""

import csv
import io
import json
from datetime import datetime
from pathlib import Path

import click

from miesc import __version__ as VERSION
from miesc.cli.commands.audit import _to_markdown, _to_sarif
from miesc.cli.utils import (
    error,
    print_banner,
    success,
    summarize_findings,
)


# =============================================================================
# Export Command
# =============================================================================


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["sarif", "markdown", "csv", "html"]),
    required=True,
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export(input_file, fmt, output):
    """Export JSON results to different formats.

    Converts MIESC JSON audit results to various output formats
    for integration with other tools and reporting systems.

    Supported formats:
      - sarif: SARIF 2.1.0 for GitHub Code Scanning
      - markdown: Human-readable Markdown report
      - csv: Spreadsheet-compatible CSV
      - html: Standalone HTML report

    Examples:
      miesc export results.json -f sarif -o results.sarif.json
      miesc export results.json -f markdown -o report.md
      miesc export results.json -f csv -o findings.csv
      miesc export results.json -f html -o report.html
    """
    print_banner()

    with open(input_file) as f:
        data = json.load(f)

    results = data.get("results", [data])
    contract = data.get("contract", input_file)

    if fmt == "sarif":
        output_data = _to_sarif(results)
        output_str = json.dumps(output_data, indent=2)
        ext = ".sarif.json"
    elif fmt == "markdown":
        output_str = _to_markdown(results, contract)
        ext = ".md"
    elif fmt == "csv":
        output_io = io.StringIO()
        writer = csv.writer(output_io)
        writer.writerow(["Tool", "Severity", "Title", "Description", "Location", "Line"])
        for result in results:
            for finding in result.get("findings", []):
                location = finding.get("location", {})
                if isinstance(location, dict):
                    loc_file = location.get("file", "")
                    loc_line = location.get("line", 0)
                else:
                    loc_file = str(location)
                    loc_line = 0

                writer.writerow(
                    [
                        result.get("tool", ""),
                        finding.get("severity", ""),
                        finding.get("title", finding.get("type", "")),
                        finding.get("description", finding.get("message", ""))[:100],
                        loc_file,
                        loc_line,
                    ]
                )
        output_str = output_io.getvalue()
        ext = ".csv"
    elif fmt == "html":
        output_str = f"""<!DOCTYPE html>
<html>
<head>
    <title>MIESC Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #1a73e8; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px 20px; margin: 10px 0; }}
        .finding.critical {{ border-color: #dc3545; }}
        .finding.high {{ border-color: #fd7e14; }}
        .finding.medium {{ border-color: #ffc107; }}
        .finding.low {{ border-color: #28a745; }}
    </style>
</head>
<body>
    <h1>MIESC Security Report</h1>
    <div class="summary">
        <strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
        <strong>Contract:</strong> {contract}<br>
        <strong>MIESC Version:</strong> {VERSION}
    </div>
"""
        summary = summarize_findings(results)
        output_str += f"""
    <h2>Summary</h2>
    <ul>
        <li>Critical: {summary['CRITICAL']}</li>
        <li>High: {summary['HIGH']}</li>
        <li>Medium: {summary['MEDIUM']}</li>
        <li>Low: {summary['LOW']}</li>
        <li>Info: {summary['INFO']}</li>
    </ul>
    <h2>Findings</h2>
"""
        for result in results:
            for finding in result.get("findings", []):
                severity = str(finding.get("severity", "info")).lower()
                output_str += f"""
    <div class="finding {severity}">
        <strong>[{finding.get("severity", "INFO")}] {finding.get("title", finding.get("type", "Finding"))}</strong>
        <p>{finding.get("description", finding.get("message", ""))}</p>
    </div>
"""
        output_str += "</body></html>"
        ext = ".html"
    else:
        error(f"Format {fmt} not supported")
        return

    # Determine output path
    if not output:
        output = str(Path(input_file).with_suffix(ext))

    with open(output, "w") as f:
        f.write(output_str)

    success(f"Exported to {output}")
