#!/usr/bin/env python3
"""
MIESC CLI - Command-Line Interface for Smart Contract Security

A developer-friendly CLI for multi-tool security analysis,
formal verification, and AI-powered vulnerability classification.

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
License: GPL-3.0

Usage:
    miesc analyze <contract> [--type slither|mythril|all]
    miesc verify <contract> [--level basic|smt|certora]
    miesc classify <report> [--ai]
    miesc server [--host 0.0.0.0] [--port 8000]
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional

from miesc.core.analyzer import analyze_contract
from miesc.core.verifier import verify_contract
from miesc.core.classifier import classify_vulnerabilities


@click.group()
@click.version_option(version="3.3.0", prog_name="miesc")
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose logging')
def cli(verbose):
    """
    MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

    A production-grade blockchain security framework with MCP support.

    \b
    Examples:
        miesc analyze contract.sol --type slither
        miesc verify contract.sol --level basic
        miesc classify report.json --ai
        miesc server --port 8000

    \b
    For more information:
        Documentation: https://fboiero.github.io/MIESC
        GitHub: https://github.com/fboiero/MIESC
    """
    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option(
    '--type',
    default='slither',
    type=click.Choice(['slither', 'mythril', 'echidna', 'aderyn', 'all']),
    help='Analysis tool to use'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Output file path (default: stdout)'
)
@click.option(
    '--format',
    default='json',
    type=click.Choice(['json', 'text', 'html']),
    help='Output format'
)
@click.option(
    '--timeout',
    default=300,
    type=int,
    help='Analysis timeout in seconds'
)
def analyze(contract_path, type, output, format, timeout):
    """
    Run static/dynamic analysis on a smart contract.

    Executes security tools (Slither, Mythril, etc.) on the specified contract
    and generates a vulnerability report.

    \b
    Examples:
        miesc analyze MyToken.sol
        miesc analyze MyToken.sol --type mythril --output report.json
        miesc analyze contracts/ --type all --timeout 600
    """
    try:
        click.echo(f"🔍 Analyzing {contract_path} with {type}...")

        result = analyze_contract(
            contract_code=contract_path,
            analysis_type=type,
            timeout=timeout
        )

        # Format output
        if format == 'json':
            output_str = json.dumps(result, indent=2)
        elif format == 'text':
            output_str = _format_text_report(result)
        elif format == 'html':
            output_str = _format_html_report(result)
        else:
            output_str = json.dumps(result, indent=2)

        # Write output
        if output:
            Path(output).write_text(output_str)
            click.echo(f"✅ Report saved to {output}")
        else:
            click.echo(output_str)

        # Exit code based on findings
        critical = result.get('findings_by_severity', {}).get('critical', 0)
        high = result.get('findings_by_severity', {}).get('high', 0)

        if critical > 0:
            click.echo(f"🔴 Found {critical} critical vulnerabilities", err=True)
            sys.exit(1)
        elif high > 0:
            click.echo(f"🟡 Found {high} high severity vulnerabilities", err=True)
            sys.exit(2)
        else:
            click.echo("✅ No critical or high severity vulnerabilities found")
            sys.exit(0)

    except Exception as e:
        click.echo(f"❌ Analysis failed: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option(
    '--level',
    default='basic',
    type=click.Choice(['basic', 'smt', 'certora', 'halmos']),
    help='Verification depth/method'
)
@click.option(
    '--properties',
    multiple=True,
    help='Properties to verify (can specify multiple)'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Output file path (default: stdout)'
)
@click.option(
    '--timeout',
    default=600,
    type=int,
    help='Verification timeout in seconds'
)
def verify(contract_path, level, properties, output, timeout):
    """
    Run formal verification on a smart contract.

    Uses formal methods (SMTChecker, Z3, Certora, Halmos) to verify
    contract properties and invariants.

    \b
    Examples:
        miesc verify MyToken.sol --level basic
        miesc verify Vault.sol --level smt --properties "balance >= 0"
        miesc verify Governance.sol --level certora --timeout 1200
    """
    try:
        click.echo(f"🔬 Verifying {contract_path} with {level} method...")

        # Read contract
        contract_code = Path(contract_path).read_text()

        result = verify_contract(
            contract_code=contract_code,
            verification_level=level,
            properties=list(properties) if properties else None,
            timeout=timeout
        )

        # Format and output
        output_str = json.dumps(result, indent=2)

        if output:
            Path(output).write_text(output_str)
            click.echo(f"✅ Verification report saved to {output}")
        else:
            click.echo(output_str)

        # Check status
        status = result.get('status', 'unknown')
        if status == 'completed':
            click.echo("✅ Verification completed successfully")
        elif status == 'simulated':
            click.echo("⚠️  Verification simulated (full implementation pending)")
        else:
            click.echo(f"⚠️  Verification status: {status}")

    except Exception as e:
        click.echo(f"❌ Verification failed: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('report_path', type=click.Path(exists=True))
@click.option(
    '--ai',
    is_flag=True,
    help='Enable AI-powered false positive reduction'
)
@click.option(
    '--api-key',
    envvar='OPENAI_API_KEY',
    help='OpenAI API key for AI triage (or set OPENAI_API_KEY env var)'
)
@click.option(
    '--output',
    type=click.Path(),
    help='Output file path (default: stdout)'
)
def classify(report_path, ai, api_key, output):
    """
    Classify and score vulnerabilities using AI/ML.

    Enhances vulnerability reports with CVSS scores, OWASP mappings,
    and optional AI-powered triage.

    \b
    Examples:
        miesc classify report.json
        miesc classify report.json --ai --api-key sk-...
        miesc classify report.json --output classified.json
    """
    try:
        click.echo(f"🤖 Classifying vulnerabilities from {report_path}...")

        if ai and not api_key:
            click.echo("⚠️  AI triage requested but no API key provided", err=True)
            click.echo("Set OPENAI_API_KEY environment variable or use --api-key")

        # Load report
        report = json.loads(Path(report_path).read_text())

        result = classify_vulnerabilities(
            report=report,
            enable_ai_triage=ai,
            ai_api_key=api_key
        )

        # Format output
        output_str = json.dumps(result, indent=2)

        if output:
            Path(output).write_text(output_str)
            click.echo(f"✅ Classification report saved to {output}")
        else:
            click.echo(output_str)

        # Summary
        stats = result.get('statistics', {})
        click.echo(f"\n📊 Summary:")
        click.echo(f"   Total findings: {stats.get('total_findings', 0)}")
        click.echo(f"   Average CVSS: {stats.get('avg_cvss', 0):.1f}")
        click.echo(f"   AI triage: {'Enabled' if result.get('ai_triage_enabled') else 'Disabled'}")

    except Exception as e:
        click.echo(f"❌ Classification failed: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--host',
    default='127.0.0.1',
    help='Server host address (default: 127.0.0.1 for security, use 0.0.0.0 for Docker)'
)
@click.option(
    '--port',
    default=8000,
    type=int,
    help='Server port'
)
@click.option(
    '--reload',
    is_flag=True,
    help='Enable auto-reload (development only)'
)
def server(host, port, reload):
    """
    Start the MIESC MCP API server.

    Launches a FastAPI server providing MCP-compatible REST endpoints
    for contract analysis, verification, and classification.

    \b
    Examples:
        miesc server
        miesc server --port 8080 --reload
        miesc server --host 127.0.0.1 --port 5000

    \b
    Once started, access:
        API Docs: http://localhost:8000/docs
        MCP Capabilities: http://localhost:8000/mcp/capabilities
    """
    try:
        import uvicorn
        from miesc.api.server import app

        click.echo(f"🚀 Starting MIESC MCP Server")
        click.echo(f"   Host: {host}")
        click.echo(f"   Port: {port}")
        click.echo(f"   Docs: http://{host}:{port}/docs")
        click.echo(f"   MCP:  http://{host}:{port}/mcp/capabilities")
        click.echo()

        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )

    except Exception as e:
        click.echo(f"❌ Server failed to start: {str(e)}", err=True)
        sys.exit(1)


def _format_text_report(result: dict) -> str:
    """Format analysis results as human-readable text"""
    lines = []
    lines.append("=" * 60)
    lines.append("MIESC Security Analysis Report")
    lines.append("=" * 60)
    lines.append(f"Contract: {result.get('contract', 'N/A')}")
    lines.append(f"Timestamp: {result.get('timestamp', 'N/A')}")
    lines.append(f"Tools: {', '.join(result.get('tools_executed', []))}")
    lines.append("")
    lines.append("Summary:")
    lines.append(f"  Total findings: {result.get('total_findings', 0)}")

    severity = result.get('findings_by_severity', {})
    lines.append(f"  Critical: {severity.get('critical', 0)}")
    lines.append(f"  High:     {severity.get('high', 0)}")
    lines.append(f"  Medium:   {severity.get('medium', 0)}")
    lines.append(f"  Low:      {severity.get('low', 0)}")
    lines.append("")

    for i, finding in enumerate(result.get('findings', []), 1):
        lines.append(f"Finding #{i}:")
        lines.append(f"  Tool: {finding.get('tool', 'N/A')}")
        lines.append(f"  Type: {finding.get('vulnerability_type', 'N/A')}")
        lines.append(f"  Severity: {finding.get('severity', 'N/A')}")
        lines.append(f"  Location: {finding.get('location', {})}")
        lines.append(f"  Description: {finding.get('description', 'N/A')}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def _format_html_report(result: dict) -> str:
    """Format analysis results as HTML (simplified)"""
    html = f"""
    <html>
    <head><title>MIESC Analysis Report</title></head>
    <body>
        <h1>MIESC Security Analysis Report</h1>
        <p><strong>Contract:</strong> {result.get('contract', 'N/A')}</p>
        <p><strong>Timestamp:</strong> {result.get('timestamp', 'N/A')}</p>
        <p><strong>Total Findings:</strong> {result.get('total_findings', 0)}</p>
        <h2>Findings</h2>
        <ul>
    """

    for finding in result.get('findings', []):
        html += f"""
        <li>
            <strong>{finding.get('severity', 'N/A')}</strong>:
            {finding.get('vulnerability_type', 'N/A')}
            - {finding.get('description', 'N/A')}
        </li>
        """

    html += """
        </ul>
    </body>
    </html>
    """
    return html


if __name__ == '__main__':
    cli()
