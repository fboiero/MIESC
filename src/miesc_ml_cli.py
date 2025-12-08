#!/usr/bin/env python3
"""
MIESC ML CLI - ML-Enhanced Command Line Interface

New ML-powered commands:
- ml-analyze: Analyze with ML enhancements
- ml-scan: Batch scan with ML
- ml-feedback: Submit feedback
- ml-report: ML system status
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core import (
    MLOrchestrator,
    get_ml_orchestrator,
    get_tool_discovery,
    HealthChecker,
)
from src.ml import FeedbackType


def print_banner():
    """Print MIESC ML banner."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║   MIESC v4.0.0 - ML Enhanced Analysis                         ║
    ║   Multi-layer Intelligent Evaluation for Smart Contracts      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def print_progress(stage: str, message: str, progress: float):
    """Print progress indicator."""
    bar_width = 30
    filled = int(bar_width * progress)
    bar = '=' * filled + '-' * (bar_width - filled)
    print(f"\r[{bar}] {progress*100:.0f}% - {message}", end='', flush=True)
    if progress >= 1.0:
        print()


def cmd_ml_analyze(args):
    """ML-enhanced contract analysis."""
    contract_path = args.contract

    if not os.path.exists(contract_path):
        print(f"Error: Contract file not found: {contract_path}")
        return 1

    print(f"\nML-Enhanced Analysis: {contract_path}")
    print("-" * 60)

    orchestrator = get_ml_orchestrator()

    # Determine scan type
    if args.quick:
        print("Mode: Quick Scan (static analysis only)")
        result = orchestrator.quick_scan(contract_path, timeout=args.timeout)
    elif args.deep:
        print("Mode: Deep Scan (all layers)")
        result = orchestrator.deep_scan(contract_path, timeout=args.timeout)
    else:
        print("Mode: Standard Scan")
        result = orchestrator.analyze(
            contract_path,
            timeout=args.timeout,
            progress_callback=print_progress if not args.quiet else None,
        )

    summary = result.get_summary()

    print("\n" + "=" * 60)
    print("ML-ENHANCED RESULTS")
    print("=" * 60)

    # Risk level with color
    risk_colors = {
        'CRITICAL': '\033[91m',
        'HIGH': '\033[93m',
        'MEDIUM': '\033[94m',
        'LOW': '\033[92m',
    }
    reset = '\033[0m'
    risk_color = risk_colors.get(summary['risk_level'], '')
    print(f"\nRisk Level: {risk_color}{summary['risk_level']}{reset}")

    print(f"\nFindings:")
    print(f"  Total: {summary['total_findings']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")

    print(f"\nML Enhancements:")
    print(f"  FPs Removed: {summary['fp_removed']} ({summary['reduction_rate']:.1f}%)")
    print(f"  Clusters: {summary['clusters']}")
    print(f"  Priority Actions: {summary['priority_actions']}")

    print(f"\nPerformance:")
    print(f"  Tools: {len(result.tools_success)}/{len(result.tools_run)}")
    print(f"  Time: {result.execution_time_ms:.0f}ms")
    print(f"  ML Time: {result.ml_processing_time_ms:.0f}ms")

    # Show clusters
    if result.clusters and not args.quiet:
        print("\n" + "-" * 60)
        print("CLUSTERS")
        print("-" * 60)
        for cluster in result.clusters[:3]:
            print(f"\n  [{cluster.severity.upper()}] {cluster.category}")
            print(f"  Findings: {len(cluster.findings)}")
            print(f"  Fix: {cluster.remediation[:50]}...")

    # Output to file
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\nSaved to: {args.output}")

    return 0 if summary['risk_level'] == 'LOW' else 1


def cmd_ml_scan(args):
    """Batch scan with ML."""
    directory = args.directory

    if not os.path.isdir(directory):
        print(f"Error: Directory not found: {directory}")
        return 1

    pattern = "**/*.sol" if args.recursive else "*.sol"
    contracts = list(Path(directory).glob(pattern))

    if not contracts:
        print(f"No Solidity files found")
        return 0

    print(f"\nScanning {len(contracts)} contracts")
    print("-" * 60)

    orchestrator = get_ml_orchestrator()
    total_findings = 0

    for i, contract in enumerate(contracts, 1):
        print(f"\n[{i}/{len(contracts)}] {contract.name}")
        result = orchestrator.quick_scan(str(contract), timeout=args.timeout)
        summary = result.get_summary()
        total_findings += summary['total_findings']
        print(f"  Risk: {summary['risk_level']}, Findings: {summary['total_findings']}")

    print(f"\n{'='*60}")
    print(f"Total Findings: {total_findings}")
    return 0


def cmd_ml_feedback(args):
    """Submit finding feedback."""
    orchestrator = get_ml_orchestrator()

    feedback_types = {
        'tp': FeedbackType.TRUE_POSITIVE,
        'fp': FeedbackType.FALSE_POSITIVE,
        'severity_correct': FeedbackType.SEVERITY_CORRECT,
        'severity_high': FeedbackType.SEVERITY_TOO_HIGH,
        'severity_low': FeedbackType.SEVERITY_TOO_LOW,
    }

    feedback_type = feedback_types.get(args.type.lower())
    if not feedback_type:
        print(f"Error: Unknown type. Use: tp, fp, severity_correct, severity_high, severity_low")
        return 1

    finding = {'_id': args.finding_id}
    result = orchestrator.submit_feedback(finding, feedback_type, notes=args.notes or "")
    print(f"Feedback: {result.get('status')}")
    return 0


def cmd_ml_report(args):
    """ML system report."""
    orchestrator = get_ml_orchestrator()
    report = orchestrator.get_ml_report()

    print("\nML System Report")
    print("=" * 60)

    if 'feedback' in report:
        fb = report['feedback'].get('summary', {})
        print(f"\nFeedback (30 days): {fb.get('total_feedback_30d', 0)}")

    if 'recommendations' in report:
        print(f"\nRecommendations:")
        for rec in report.get('recommendations', [])[:5]:
            print(f"  [{rec.get('severity', 'info')}] {rec.get('message', '')}")

    return 0


def cmd_tools(args):
    """List available tools."""
    discovery = get_tool_discovery()

    if args.layers:
        tools_by_layer = discovery.get_tools_by_layer()
        print("\nTools by Layer:")
        for layer, tools in sorted(tools_by_layer.items()):
            print(f"\n{layer}:")
            for tool in tools:
                status = "OK" if tool.available else "N/A"
                print(f"  [{status}] {tool.name}")
    else:
        tools = discovery.get_available_tools()
        print(f"\nAvailable: {len(tools)}")
        for tool in tools:
            print(f"  {tool.name} ({tool.layer})")

    return 0


def cmd_health(args):
    """System health check."""
    checker = HealthChecker()
    health = checker.check_all()

    if args.json:
        print(json.dumps({
            'status': health.status.value,
            'healthy': health.healthy_tools,
            'unhealthy': health.unhealthy_tools,
        }, indent=2))
    else:
        print(f"\nHealth: {health.status.value.upper()}")
        print(f"Healthy: {health.healthy_tools}")
        print(f"Unhealthy: {health.unhealthy_tools}")

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='MIESC ML-Enhanced CLI v4.0.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # ml-analyze
    p = subparsers.add_parser('ml-analyze', help='ML-enhanced analysis')
    p.add_argument('contract', help='Contract path')
    p.add_argument('--quick', action='store_true', help='Quick scan')
    p.add_argument('--deep', action='store_true', help='Deep scan')
    p.add_argument('--timeout', type=int, default=120, help='Timeout')
    p.add_argument('--output', '-o', help='Output file')
    p.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')

    # ml-scan
    p = subparsers.add_parser('ml-scan', help='Batch ML scan')
    p.add_argument('directory', help='Directory path')
    p.add_argument('--recursive', '-r', action='store_true', help='Recursive')
    p.add_argument('--timeout', type=int, default=60, help='Timeout')

    # ml-feedback
    p = subparsers.add_parser('ml-feedback', help='Submit feedback')
    p.add_argument('finding_id', help='Finding ID')
    p.add_argument('type', help='Feedback type')
    p.add_argument('--notes', help='Notes')

    # ml-report
    subparsers.add_parser('ml-report', help='ML report')

    # tools
    p = subparsers.add_parser('tools', help='List tools')
    p.add_argument('--layers', action='store_true', help='By layer')

    # health
    p = subparsers.add_parser('health', help='Health check')
    p.add_argument('--json', action='store_true', help='JSON output')

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    commands = {
        'ml-analyze': cmd_ml_analyze,
        'ml-scan': cmd_ml_scan,
        'ml-feedback': cmd_ml_feedback,
        'ml-report': cmd_ml_report,
        'tools': cmd_tools,
        'health': cmd_health,
    }

    return commands.get(args.command, lambda x: parser.print_help())(args)


if __name__ == '__main__':
    sys.exit(main())
