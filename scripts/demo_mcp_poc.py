#!/usr/bin/env python3
"""
MCP Proof of Concept Demo

Demonstrates multi-agent audit workflow using Model Context Protocol.
This POC shows:
1. Context Bus pub/sub messaging
2. Agent collaboration via MCP
3. Coordinator-driven workflow
4. Real-time progress monitoring
5. Compliance-mapped audit summary

Usage:
    python demo_mcp_poc.py examples/voting.sol
"""
import sys
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.mcp.context_bus import get_context_bus
from src.agents.static_agent import StaticAgent
from src.agents.ai_agent import AIAgent
from src.agents.coordinator_agent import CoordinatorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print MCP demo banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    MCP Multi-Agent Audit Framework - Proof of Concept           ║
║    Marco Integrado de Evaluación de Seguridad (MIESC)           ║
║                                                                  ║
║    Protocol: Model Context Protocol (MCP) v1.0                  ║
║    Standards: ISO/IEC 27001:2022, NIST SSDF, OWASP SC Top 10    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title: str):
    """Print section header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def demo_context_bus():
    """Demonstrate Context Bus functionality"""
    print_section("Phase 1: Context Bus Initialization")

    bus = get_context_bus()
    logger.info("✓ Context Bus singleton initialized")

    stats = bus.get_stats()
    print(f"Context Bus Status:")
    print(f"  - Total messages: {stats['total_messages']}")
    print(f"  - Active context types: {stats['active_context_types']}")
    print(f"  - Subscribers: {stats['subscribers']}")


def demo_static_agent(contract_path: str):
    """Demonstrate StaticAgent execution"""
    print_section("Phase 2: StaticAgent Execution (Layer 1)")

    agent = StaticAgent()
    logger.info(f"✓ StaticAgent initialized with capabilities: {agent.capabilities}")

    print(f"Running static analysis on: {contract_path}")
    print(f"Tools: Slither, Solhint, Surya")

    # Run analysis
    results = agent.run(contract_path, solc_version="0.8.0")

    # Display results
    if "static_findings" in results and results["static_findings"]:
        print(f"\n✓ Analysis complete. Findings summary:")
        print(f"  - Total findings: {len(results['static_findings'])}")

        # Count by severity
        severity_counts = {}
        for finding in results["static_findings"]:
            severity = finding.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"  - By severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"    • {severity}: {count}")

        # Show first 3 findings
        print(f"\n  Top findings:")
        for i, finding in enumerate(results["static_findings"][:3], 1):
            print(f"    {i}. [{finding.get('severity')}] {finding.get('id')}")
            print(f"       {finding.get('description', 'No description')[:80]}...")
            if finding.get("swc_id"):
                print(f"       SWC: {finding['swc_id']}, OWASP: {finding.get('owasp_category', 'N/A')}")
    else:
        print("✓ No issues detected by static analysis")

    return results


def demo_ai_agent(contract_path: str, static_findings: list):
    """Demonstrate AIAgent triage"""
    print_section("Phase 3: AIAgent Triage (Layer 6)")

    # Note: AI agent requires OpenAI API key
    # For POC, we'll demonstrate without actual API calls
    agent = AIAgent(api_key=None)  # Set to None for demo
    logger.info(f"✓ AIAgent initialized with capabilities: {agent.capabilities}")

    print(f"AI Triage Configuration:")
    print(f"  - Model: gpt-4")
    print(f"  - Input: {len(static_findings)} findings from StaticAgent")
    print(f"  - Subscribed to: static_findings, dynamic_findings, formal_findings")

    # In real scenario with API key, would perform:
    # results = agent.run(contract_path, aggregated_findings=static_findings)

    print(f"\n✓ AI Agent ready (API key required for actual triage)")
    print(f"  - Would classify findings as real vulnerabilities or false positives")
    print(f"  - Would perform root cause analysis on critical issues")
    print(f"  - Would generate remediation recommendations")

    return agent


def demo_coordinator_agent(contract_path: str):
    """Demonstrate CoordinatorAgent orchestration"""
    print_section("Phase 4: CoordinatorAgent Orchestration")

    coordinator = CoordinatorAgent(api_key=None)  # Set to None for demo
    logger.info(f"✓ CoordinatorAgent initialized with capabilities: {coordinator.capabilities}")

    print(f"Generating audit plan for: {contract_path}")

    # Generate audit plan
    results = coordinator.analyze(
        contract_path,
        priority="balanced",
        audit_scope=["static", "ai"],
        time_budget=600
    )

    # Display audit plan
    if "audit_plan" in results:
        plan = results["audit_plan"]
        print(f"\n✓ Audit Plan Generated:")
        print(f"  - Priority: {plan['priority']}")
        print(f"  - Scope: {', '.join(plan['scope'])}")
        print(f"  - Time Budget: {plan['time_budget']}s")
        print(f"  - Estimated Duration: {plan['estimated_duration']}s")
        print(f"\n  Execution Phases:")
        for i, phase in enumerate(plan["phases"], 1):
            print(f"    {i}. {phase['agent']} (Layer: {phase['layer']}) - ~{phase['estimated_time']}s")

    # Display execution progress
    if "audit_progress" in results:
        print(f"\n✓ Execution Log:")
        for event in results["audit_progress"]:
            status_icon = "▶️" if event["status"] == "started" else "✅"
            print(f"  {status_icon} {event['agent']}: {event['status']}")

    # Display audit summary
    if "audit_summary" in results:
        summary = results["audit_summary"]
        print(f"\n✓ Audit Summary:")
        print(f"  - Total Findings: {summary['total_findings']}")
        print(f"  - By Severity: {summary['findings_by_severity']}")
        print(f"  - By Layer: {summary['findings_by_layer']}")

        if summary.get("owasp_coverage"):
            print(f"\n  OWASP SC Top 10 Coverage:")
            for category, count in summary["owasp_coverage"].items():
                print(f"    • {category}: {count} findings")

        if summary.get("compliance"):
            print(f"\n  Compliance Mapping:")
            print(f"    • ISO/IEC 27001:2022: {', '.join(summary['compliance']['iso27001'])}")
            print(f"    • NIST SSDF: {', '.join(summary['compliance']['nist_ssdf'])}")

        if summary.get("recommendations"):
            print(f"\n  Recommendations:")
            for rec in summary["recommendations"]:
                print(f"    • {rec}")

    return results


def demo_context_bus_audit_trail():
    """Demonstrate audit trail export for compliance"""
    print_section("Phase 5: Compliance Audit Trail")

    bus = get_context_bus()

    # Get statistics
    stats = bus.get_stats()
    print(f"Context Bus Final Statistics:")
    print(f"  - Total messages exchanged: {stats['total_messages']}")
    print(f"  - Active context types: {stats['active_context_types']}")
    print(f"  - Context counts:")
    for context_type, count in stats['context_counts'].items():
        print(f"    • {context_type}: {count} messages")

    # Export audit trail (for ISO 27001 A.8.15 - Logging)
    output_dir = Path("outputs/evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_trail_path = output_dir / "mcp_audit_trail.json"

    bus.export_audit_trail(str(audit_trail_path))
    print(f"\n✓ Audit trail exported to: {audit_trail_path}")
    print(f"  - Compliant with ISO/IEC 27001:2022 Control A.8.15 (Logging)")
    print(f"  - Contains complete message history for forensic analysis")


def main():
    """Main demo execution"""
    print_banner()

    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python demo_mcp_poc.py <contract_path>")
        print("Example: python demo_mcp_poc.py examples/voting.sol")
        sys.exit(1)

    contract_path = sys.argv[1]

    # Validate contract exists
    if not Path(contract_path).exists():
        print(f"Error: Contract not found: {contract_path}")
        sys.exit(1)

    print(f"Target Contract: {contract_path}\n")

    try:
        # Phase 1: Context Bus
        demo_context_bus()

        # Phase 2: StaticAgent
        static_results = demo_static_agent(contract_path)
        static_findings = static_results.get("static_findings", [])

        # Phase 3: AIAgent
        demo_ai_agent(contract_path, static_findings)

        # Phase 4: CoordinatorAgent
        coordinator_results = demo_coordinator_agent(contract_path)

        # Phase 5: Audit Trail
        demo_context_bus_audit_trail()

        # Final summary
        print_section("MCP POC Complete")
        print("✓ Demonstrated MCP multi-agent architecture")
        print("✓ Context Bus pub/sub messaging operational")
        print("✓ Agent collaboration via standardized MCP messages")
        print("✓ Compliance mapping to ISO/NIST/OWASP")
        print("\nNext Steps:")
        print("  1. Add DynamicAgent (Echidna, Medusa, Foundry)")
        print("  2. Add FormalAgent (Certora Prover)")
        print("  3. Add SymbolicAgent (Mythril, Manticore)")
        print("  4. Integrate with CI/CD pipeline")
        print("  5. Deploy as MCP server for Claude Desktop integration")

    except Exception as e:
        logger.error(f"Demo error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
