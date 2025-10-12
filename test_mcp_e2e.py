#!/usr/bin/env python3
"""
End-to-End Testing for MCP Multi-Agent Architecture

Tests complete workflow:
1. Context Bus initialization
2. Agent registration and communication
3. Multi-layer analysis execution
4. Cross-agent messaging
5. Compliance report generation
6. Audit trail export

Usage:
    python test_mcp_e2e.py
"""
import sys
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp.context_bus import get_context_bus, MCPMessage
from agents.static_agent import StaticAgent
from agents.dynamic_agent import DynamicAgent
from agents.symbolic_agent import SymbolicAgent
from agents.formal_agent import FormalAgent
from agents.ai_agent import AIAgent
from agents.policy_agent import PolicyAgent
from agents.coordinator_agent import CoordinatorAgent

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def add_test(self, name: str, passed: bool, message: str = ""):
        self.tests.append({"name": name, "passed": passed, "message": message})
        if passed:
            self.passed += 1
            logger.info(f"✅ PASS: {name}")
        else:
            self.failed += 1
            logger.error(f"❌ FAIL: {name} - {message}")

    def summary(self):
        total = self.passed + self.failed
        logger.info(f"\n{'='*70}")
        logger.info(f"Test Summary: {self.passed}/{total} passed")
        logger.info(f"{'='*70}")
        return self.failed == 0


def test_context_bus_initialization(results: TestResults):
    """Test 1: Context Bus initialization and singleton pattern"""
    logger.info("\n--- Test 1: Context Bus Initialization ---")

    try:
        bus1 = get_context_bus()
        bus2 = get_context_bus()

        # Test singleton
        results.add_test(
            "Context Bus Singleton",
            bus1 is bus2,
            "Multiple calls should return same instance"
        )

        # Test initial state
        stats = bus1.get_stats()
        results.add_test(
            "Context Bus Initial State",
            stats["total_messages"] == 0,
            f"Expected 0 messages, got {stats['total_messages']}"
        )

    except Exception as e:
        results.add_test("Context Bus Initialization", False, str(e))


def test_agent_initialization(results: TestResults):
    """Test 2: All agents initialize correctly"""
    logger.info("\n--- Test 2: Agent Initialization ---")

    agents_to_test = [
        ("StaticAgent", StaticAgent),
        ("DynamicAgent", DynamicAgent),
        ("SymbolicAgent", SymbolicAgent),
        ("FormalAgent", FormalAgent),
        ("AIAgent", AIAgent),
        ("PolicyAgent", PolicyAgent),
        ("CoordinatorAgent", CoordinatorAgent)
    ]

    for agent_name, agent_class in agents_to_test:
        try:
            agent = agent_class()

            results.add_test(
                f"{agent_name} Initialization",
                agent.agent_name is not None and agent.status == "initialized",
                f"Agent status: {agent.status}"
            )

            # Test context types
            context_types = agent.get_context_types()
            results.add_test(
                f"{agent_name} Context Types",
                len(context_types) > 0,
                f"Expected context types, got {len(context_types)}"
            )

        except Exception as e:
            results.add_test(f"{agent_name} Initialization", False, str(e))


def test_context_bus_messaging(results: TestResults):
    """Test 3: Pub/Sub messaging works correctly"""
    logger.info("\n--- Test 3: Context Bus Messaging ---")

    try:
        bus = get_context_bus()

        # Clear any previous state
        bus.message_history.clear()
        bus.context_store.clear()

        # Create test message
        test_message = MCPMessage(
            agent="TestAgent",
            context_type="test_findings",
            contract="test.sol",
            data={"test": "data"}
        )

        # Test publish
        bus.publish(test_message)

        results.add_test(
            "Message Publishing",
            len(bus.message_history) == 1,
            f"Expected 1 message, got {len(bus.message_history)}"
        )

        # Test retrieval
        retrieved = bus.get_context("test_findings")
        results.add_test(
            "Message Retrieval",
            len(retrieved) == 1 and retrieved[0].agent == "TestAgent",
            f"Expected TestAgent message"
        )

        # Test subscribe callback
        callback_triggered = {"value": False}

        def test_callback(msg: MCPMessage):
            callback_triggered["value"] = True

        bus.subscribe("test_callback", test_callback)

        test_message2 = MCPMessage(
            agent="TestAgent2",
            context_type="test_callback",
            contract="test.sol",
            data={"test": "callback"}
        )
        bus.publish(test_message2)

        results.add_test(
            "Subscriber Callback",
            callback_triggered["value"],
            "Callback should be triggered on publish"
        )

    except Exception as e:
        results.add_test("Context Bus Messaging", False, str(e))


def test_static_agent_execution(results: TestResults):
    """Test 4: StaticAgent execution on real contract"""
    logger.info("\n--- Test 4: StaticAgent Execution ---")

    # Check if voting.sol exists
    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        results.add_test(
            "StaticAgent Execution",
            False,
            f"Test contract not found: {contract_path}"
        )
        return

    try:
        agent = StaticAgent()

        # Run analysis
        analysis_results = agent.run(contract_path, solc_version="0.8.0")

        results.add_test(
            "StaticAgent Execution",
            "static_findings" in analysis_results,
            f"Expected static_findings in results"
        )

        # Check if findings were published to Context Bus
        bus = get_context_bus()
        static_contexts = bus.get_context("static_findings")

        results.add_test(
            "StaticAgent Context Publishing",
            len(static_contexts) > 0,
            f"Expected published findings, got {len(static_contexts)}"
        )

        # Check findings structure
        if analysis_results.get("static_findings"):
            first_finding = analysis_results["static_findings"][0]
            has_required_fields = all(
                key in first_finding
                for key in ["source", "severity", "layer"]
            )
            results.add_test(
                "StaticAgent Finding Structure",
                has_required_fields,
                "Findings should have required fields"
            )

    except Exception as e:
        results.add_test("StaticAgent Execution", False, str(e))


def test_policy_agent_compliance(results: TestResults):
    """Test 5: PolicyAgent compliance checking"""
    logger.info("\n--- Test 5: PolicyAgent Compliance ---")

    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        results.add_test(
            "PolicyAgent Compliance",
            False,
            f"Test contract not found: {contract_path}"
        )
        return

    try:
        # First run StaticAgent to generate findings
        static_agent = StaticAgent()
        static_agent.run(contract_path, solc_version="0.8.0")

        # Now run PolicyAgent
        policy_agent = PolicyAgent()
        compliance_results = policy_agent.run(contract_path)

        results.add_test(
            "PolicyAgent Execution",
            "compliance_report" in compliance_results,
            "Expected compliance_report in results"
        )

        # Check ISO 27001 compliance
        iso_status = compliance_results.get("iso27001_status", {})
        results.add_test(
            "ISO 27001 Check",
            "controls" in iso_status and "compliance_score" in iso_status,
            "Expected ISO 27001 controls and score"
        )

        # Check NIST SSDF compliance
        nist_status = compliance_results.get("nist_ssdf_status", {})
        results.add_test(
            "NIST SSDF Check",
            "practices" in nist_status and "compliance_score" in nist_status,
            "Expected NIST practices and score"
        )

        # Check OWASP coverage
        owasp_coverage = compliance_results.get("owasp_coverage", {})
        results.add_test(
            "OWASP Coverage Check",
            "categories" in owasp_coverage and "coverage_score" in owasp_coverage,
            "Expected OWASP categories and coverage"
        )

    except Exception as e:
        results.add_test("PolicyAgent Compliance", False, str(e))


def test_coordinator_orchestration(results: TestResults):
    """Test 6: CoordinatorAgent orchestration"""
    logger.info("\n--- Test 6: CoordinatorAgent Orchestration ---")

    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        results.add_test(
            "CoordinatorAgent Orchestration",
            False,
            f"Test contract not found: {contract_path}"
        )
        return

    try:
        coordinator = CoordinatorAgent()

        # Generate audit plan
        orchestration_results = coordinator.run(
            contract_path,
            priority="fast",
            audit_scope=["static", "ai"]
        )

        results.add_test(
            "CoordinatorAgent Execution",
            "audit_plan" in orchestration_results,
            "Expected audit_plan in results"
        )

        # Check audit plan structure
        audit_plan = orchestration_results.get("audit_plan", {})
        results.add_test(
            "Audit Plan Structure",
            "phases" in audit_plan and "priority" in audit_plan,
            "Audit plan should have phases and priority"
        )

        # Check execution progress
        progress = orchestration_results.get("audit_progress", [])
        results.add_test(
            "Audit Progress Tracking",
            len(progress) > 0,
            f"Expected progress events, got {len(progress)}"
        )

        # Check audit summary
        summary = orchestration_results.get("audit_summary", {})
        results.add_test(
            "Audit Summary Generation",
            "total_findings" in summary and "compliance" in summary,
            "Summary should have findings and compliance data"
        )

    except Exception as e:
        results.add_test("CoordinatorAgent Orchestration", False, str(e))


def test_audit_trail_export(results: TestResults):
    """Test 7: Audit trail export for compliance"""
    logger.info("\n--- Test 7: Audit Trail Export ---")

    try:
        bus = get_context_bus()

        # Ensure output directory exists
        output_dir = Path("outputs/evidence")
        output_dir.mkdir(parents=True, exist_ok=True)

        audit_trail_path = output_dir / "test_audit_trail.json"

        # Export audit trail
        bus.export_audit_trail(str(audit_trail_path))

        results.add_test(
            "Audit Trail Export",
            audit_trail_path.exists(),
            f"Audit trail should be exported to {audit_trail_path}"
        )

        # Verify JSON structure
        with open(audit_trail_path, 'r') as f:
            audit_data = json.load(f)

        results.add_test(
            "Audit Trail Structure",
            "protocol" in audit_data and "messages" in audit_data,
            "Audit trail should have protocol and messages"
        )

        results.add_test(
            "Audit Trail Messages",
            len(audit_data["messages"]) > 0,
            f"Expected messages in audit trail, got {len(audit_data['messages'])}"
        )

    except Exception as e:
        results.add_test("Audit Trail Export", False, str(e))


def test_cross_layer_integration(results: TestResults):
    """Test 8: Cross-layer agent integration"""
    logger.info("\n--- Test 8: Cross-Layer Integration ---")

    try:
        bus = get_context_bus()

        # Get all context types
        all_contexts = bus.aggregate_contexts([
            "static_findings",
            "dynamic_findings",
            "symbolic_findings",
            "formal_findings",
            "ai_triage",
            "compliance_report"
        ])

        # Count active context types
        active_types = sum(1 for msgs in all_contexts.values() if msgs)

        results.add_test(
            "Multi-Layer Context Aggregation",
            active_types >= 2,  # At least static and compliance should be active
            f"Expected multiple active layers, got {active_types}"
        )

        # Test context retrieval from different layers
        static_msgs = all_contexts.get("static_findings", [])
        compliance_msgs = all_contexts.get("compliance_report", [])

        results.add_test(
            "Cross-Layer Message Flow",
            len(static_msgs) > 0 or len(compliance_msgs) > 0,
            "At least one layer should have messages"
        )

    except Exception as e:
        results.add_test("Cross-Layer Integration", False, str(e))


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  MCP Multi-Agent Architecture - End-to-End Testing")
    print("="*70 + "\n")

    results = TestResults()

    # Run test suite
    test_context_bus_initialization(results)
    test_agent_initialization(results)
    test_context_bus_messaging(results)
    test_static_agent_execution(results)
    test_policy_agent_compliance(results)
    test_coordinator_orchestration(results)
    test_audit_trail_export(results)
    test_cross_layer_integration(results)

    # Print summary
    success = results.summary()

    # Print detailed results
    print("\nDetailed Results:")
    for test in results.tests:
        status = "✅ PASS" if test["passed"] else "❌ FAIL"
        print(f"  {status}: {test['name']}")
        if test["message"] and not test["passed"]:
            print(f"    → {test['message']}")

    # Exit code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
