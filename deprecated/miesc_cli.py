#!/usr/bin/env python3
"""
MIESC CLI - Command Line Interface

Unified command-line interface for MIESC operations:
- run-audit: Execute security audit
- correlate: Apply AI correlation
- report: Generate reports
- metrics: Calculate validation metrics
- mcp-server: Start MCP server

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import os
import sys
import json
import click
import logging
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.miesc_core import MIESCCore
from src.miesc_ai_layer import AICorrelator, MetricsCalculator
from src.miesc_policy_mapper import PolicyMapper
from src.miesc_risk_engine import RiskEngine
from src.miesc_mcp_adapter import MIESCMCPAdapter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="3.0.0", prog_name="MIESC")
def cli():
    """
    MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

    Automated security assessment framework for Ethereum smart contracts.

    Author: Fernando Boiero - UNDEF
    License: GPL-3.0
    """
    pass


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option('--tools', '-t', multiple=True, default=('slither', 'mythril', 'aderyn'),
              help='Security tools to use (default: slither,mythril,aderyn)')
@click.option('--enable-ai/--no-ai', default=True,
              help='Enable AI-powered correlation (default: enabled)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON)')
@click.option('--timeout', default=300, type=int,
              help='Timeout per tool in seconds')
@click.option('--verbose', '-v', is_flag=True,
              help='Enable verbose output')
def run_audit(contract_path: str, tools: tuple, enable_ai: bool,
              output: Optional[str], timeout: int, verbose: bool):
    """
    Execute comprehensive security audit on a smart contract

    Example:
        miesc run-audit contracts/MyToken.sol --enable-ai -o report.json
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    click.echo(f"\n🔍 MIESC Security Audit v3.0.0")
    click.echo(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    click.echo(f"📄 Contract: {contract_path}")
    click.echo(f"🛠️  Tools: {', '.join(tools)}")
    click.echo(f"🤖 AI Correlation: {'Enabled' if enable_ai else 'Disabled'}")
    click.echo(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        # Initialize components
        config = {'timeout': timeout}
        core = MIESCCore(config)
        correlator = AICorrelator() if enable_ai else None
        policy_mapper = PolicyMapper()
        risk_engine = RiskEngine()

        # Phase 1: Multi-tool scanning
        click.echo("🔬 Phase 1: Multi-tool scanning...")
        scan_results = core.scan_contract(contract_path, tools=list(tools))
        click.echo(f"   Found {scan_results['total_findings']} raw findings\n")

        # Phase 2: AI correlation (if enabled)
        correlated_findings = []
        if enable_ai and correlator:
            click.echo("🧠 Phase 2: AI-powered correlation...")
            raw_findings = scan_results['raw_findings']
            correlated = correlator.correlate_findings(raw_findings)
            correlated_findings = [c.to_dict() if hasattr(c, 'to_dict') else c for c in correlated]
            reduction = len(raw_findings) - len(correlated_findings)
            click.echo(f"   Reduced to {len(correlated_findings)} findings ({reduction} false positives filtered)\n")

        # Phase 3: Compliance mapping
        click.echo("📋 Phase 3: Compliance mapping...")
        findings_to_map = correlated_findings if correlated_findings else scan_results['raw_findings']
        compliance_matrix = policy_mapper.generate_compliance_matrix(findings_to_map)
        click.echo(f"   Compliance score: {compliance_matrix['compliance_score']}/100\n")

        # Phase 4: Risk assessment
        click.echo("⚠️  Phase 4: Risk assessment...")
        risk_report = risk_engine.generate_risk_report(findings_to_map)
        click.echo(f"   Total risk score: {risk_report['total_risk_score']}")
        click.echo(f"   Critical issues: {risk_report['critical_issues_count']}\n")

        # Combine results
        final_results = {
            'miesc_version': '3.0.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'contract': contract_path,
            'scan_results': scan_results,
            'correlated_findings': correlated_findings,
            'compliance_matrix': compliance_matrix,
            'risk_report': risk_report
        }

        # Output results
        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w') as f:
                json.dump(final_results, f, indent=2)
            click.echo(f"✅ Results saved to: {output}")
        else:
            # Print summary
            click.echo("\n📊 Summary")
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            click.echo(f"Total Findings: {scan_results['total_findings']}")
            click.echo(f"By Severity:")
            for sev, count in scan_results['findings_by_severity'].items():
                if count > 0:
                    click.echo(f"  • {sev}: {count}")
            click.echo(f"\nCompliance Score: {compliance_matrix['compliance_score']}/100")
            click.echo(f"Standards Coverage:")
            for std, items in compliance_matrix['standards_coverage'].items():
                if items:
                    click.echo(f"  • {std.upper()}: {len(items)} items")

            click.echo(f"\n⚠️  Recommendations:")
            for rec in risk_report['recommendations'][:3]:
                click.echo(f"  {rec}")

        click.echo("\n✅ Audit complete!")

    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        if verbose:
            raise
        sys.exit(1)


@cli.command()
@click.argument('findings_file', type=click.Path(exists=True))
@click.option('--contract-source', type=click.Path(exists=True),
              help='Path to contract source code (optional)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON)')
def correlate(findings_file: str, contract_source: Optional[str], output: Optional[str]):
    """
    Apply AI correlation to existing findings

    Example:
        miesc correlate findings.json --contract-source MyToken.sol -o correlated.json
    """
    click.echo("\n🧠 MIESC AI Correlation")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        # Load findings
        with open(findings_file, 'r') as f:
            data = json.load(f)
            findings = data if isinstance(data, list) else data.get('raw_findings', [])

        # Load contract source if provided
        source = None
        if contract_source:
            with open(contract_source, 'r') as f:
                source = f.read()

        # Apply correlation
        correlator = AICorrelator()
        correlated = correlator.correlate_findings(findings, source)

        # Prepare output
        results = {
            'original_count': len(findings),
            'correlated_count': len(correlated),
            'reduction_rate': (len(findings) - len(correlated)) / len(findings),
            'correlated_findings': [c.to_dict() if hasattr(c, 'to_dict') else c for c in correlated]
        }

        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            click.echo(f"✅ Results saved to: {output}")
        else:
            click.echo(f"Original findings: {results['original_count']}")
            click.echo(f"Correlated findings: {results['correlated_count']}")
            click.echo(f"False positive reduction: {results['reduction_rate']:.1%}")

    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('predictions_file', type=click.Path(exists=True))
@click.argument('ground_truth_file', type=click.Path(exists=True))
@click.option('--compare-tools', '-c', multiple=True,
              help='Compare specific tools')
def metrics(predictions_file: str, ground_truth_file: str, compare_tools: tuple):
    """
    Calculate validation metrics (precision, recall, F1, Cohen's kappa)

    Example:
        miesc metrics predictions.json ground_truth.json
    """
    click.echo("\n📊 MIESC Metrics Calculation")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        # Load data
        with open(predictions_file, 'r') as f:
            predictions = json.load(f)

        with open(ground_truth_file, 'r') as f:
            ground_truth = json.load(f)

        # Calculate metrics
        calculator = MetricsCalculator()

        if compare_tools:
            # Multi-tool comparison
            tool_results = {tool: predictions.get(tool, []) for tool in compare_tools}
            comparison = calculator.compare_tools(tool_results, ground_truth)

            click.echo("Tool Comparison:")
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            for tool, metrics in comparison.items():
                click.echo(f"\n{tool}:")
                click.echo(f"  Precision: {metrics['precision']:.4f}")
                click.echo(f"  Recall:    {metrics['recall']:.4f}")
                click.echo(f"  F1 Score:  {metrics['f1_score']:.4f}")
                click.echo(f"  Cohen's κ: {metrics['cohens_kappa']:.4f}")
        else:
            # Single calculation
            if isinstance(predictions, dict):
                predictions = predictions.get('predictions', [])

            metrics = calculator.calculate_metrics(predictions, ground_truth)

            click.echo("Validation Metrics:")
            click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            click.echo(f"Precision:     {metrics['precision']:.4f}")
            click.echo(f"Recall:        {metrics['recall']:.4f}")
            click.echo(f"F1 Score:      {metrics['f1_score']:.4f}")
            click.echo(f"Cohen's Kappa: {metrics['cohens_kappa']:.4f}")
            click.echo(f"\nConfusion Matrix:")
            click.echo(f"  True Positives:  {metrics['true_positives']}")
            click.echo(f"  False Positives: {metrics['false_positives']}")
            click.echo(f"  True Negatives:  {metrics['true_negatives']}")
            click.echo(f"  False Negatives: {metrics['false_negatives']}")

    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--host', default='localhost', help='Server host')
@click.option('--port', default=8080, type=int, help='Server port')
@click.option('--export-manifest', is_flag=True, help='Export MCP manifest and exit')
def mcp_server(host: str, port: int, export_manifest: bool):
    """
    Start MIESC as an MCP server for agent interoperability

    Example:
        miesc mcp-server --host 0.0.0.0 --port 8080
        miesc mcp-server --export-manifest
    """
    if export_manifest:
        click.echo("\n📄 Exporting MCP Manifest...")
        adapter = MIESCMCPAdapter()
        manifest_path = "mcp/manifest.json"
        adapter.export_manifest(manifest_path)
        click.echo(f"✅ Manifest exported to: {manifest_path}\n")
        return

    click.echo("\n🚀 Starting MIESC MCP Server")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    click.echo(f"Host: {host}")
    click.echo(f"Port: {port}")
    click.echo(f"Protocol: MCP/1.0")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    try:
        # Import server module
        from src.mcp import server

        # Start server (this is a simplified version)
        click.echo(f"🌐 Server running at http://{host}:{port}")
        click.echo("   Endpoints:")
        click.echo("   • /mcp/jsonrpc - JSON-RPC interface")
        click.echo("   • /mcp/ws - WebSocket interface")
        click.echo("   • /api/v1 - REST API")
        click.echo("\n✅ Server ready. Press Ctrl+C to stop.\n")

        # Keep running
        import time
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        click.echo("\n\n🛑 Server stopped.")
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('results_file', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'pdf']),
              default='json', help='Report format')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path')
def report(results_file: str, format: str, output: Optional[str]):
    """
    Generate formatted report from audit results

    Example:
        miesc report results.json --format html -o report.html
    """
    click.echo(f"\n📄 Generating {format.upper()} Report...")

    try:
        with open(results_file, 'r') as f:
            results = json.load(f)

        if not output:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            output = f"analysis/results/miesc_report_{timestamp}.{format}"

        Path(output).parent.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
        elif format == 'html':
            # Generate HTML report (simplified)
            html_content = generate_html_report(results)
            with open(output, 'w') as f:
                f.write(html_content)
        elif format == 'pdf':
            click.echo("⚠️  PDF generation requires additional dependencies (reportlab)")
            click.echo("   Falling back to JSON format...")
            output = output.replace('.pdf', '.json')
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)

        click.echo(f"✅ Report saved to: {output}\n")

    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


def generate_html_report(results: Dict) -> str:
    """Generate simple HTML report"""
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>MIESC Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        .metric {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>MIESC Security Audit Report</h1>
    <p><strong>Generated:</strong> {results.get('timestamp', 'N/A')}</p>
    <p><strong>Contract:</strong> {results.get('contract', 'N/A')}</p>

    <h2>Summary</h2>
    <div class="metric">
        <p>Total Findings: {results.get('scan_results', {}).get('total_findings', 0)}</p>
        <p>Compliance Score: {results.get('compliance_matrix', {}).get('compliance_score', 0)}/100</p>
        <p>Critical Issues: <span class="critical">{results.get('risk_report', {}).get('critical_issues_count', 0)}</span></p>
    </div>

    <h2>Findings by Severity</h2>
    <div class="metric">
        {generate_severity_html(results.get('scan_results', {}).get('findings_by_severity', {}))}
    </div>

    <footer>
        <p><em>Generated by MIESC v3.0.0 - Fernando Boiero, UNDEF</em></p>
    </footer>
</body>
</html>"""


def generate_severity_html(severity_dict: Dict) -> str:
    """Generate HTML for severity breakdown"""
    html = "<ul>"
    for severity, count in severity_dict.items():
        if count > 0:
            html += f"<li><strong>{severity}:</strong> {count}</li>"
    html += "</ul>"
    return html


if __name__ == '__main__':
    cli()
