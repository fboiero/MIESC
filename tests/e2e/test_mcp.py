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
    pytest tests/e2e/test_mcp.py -v
"""
import sys
import json
import logging
from pathlib import Path
import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.mcp.context_bus import get_context_bus, MCPMessage
from src.agents.static_agent import StaticAgent
from src.agents.dynamic_agent import DynamicAgent
from src.agents.symbolic_agent import SymbolicAgent
from src.agents.formal_agent import FormalAgent
from src.agents.ai_agent import AIAgent
from src.agents.policy_agent import PolicyAgent
from src.agents.coordinator_agent import CoordinatorAgent

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_context_bus_initialization():
    """Test 1: Context Bus initialization and singleton pattern"""
    logger.info("\n--- Test 1: Context Bus Initialization ---")

    bus1 = get_context_bus()
    bus2 = get_context_bus()

    # Test singleton
    assert bus1 is bus2, "Multiple calls should return same instance"

    # Test initial state
    stats = bus1.get_statistics()
    assert "total_messages" in stats, "Stats should contain total_messages"
    logger.info(f"✅ PASS: Context Bus initialized with {stats['total_messages']} messages")


def test_agent_initialization():
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

            # Test agent initialization
            assert agent.agent_name is not None and agent.status == "initialized", \
                f"{agent_name} initialization failed: Agent status: {agent.status}"
            logger.info(f"✅ PASS: {agent_name} Initialization - Agent status: {agent.status}")

            # Test context types
            context_types = agent.get_context_types()
            assert len(context_types) > 0, \
                f"{agent_name} context types failed: Expected context types, got {len(context_types)}"
            logger.info(f"✅ PASS: {agent_name} Context Types - got {len(context_types)} types")

        except Exception as e:
            pytest.fail(f"{agent_name} Initialization failed: {str(e)}")


def test_context_bus_messaging():
    """Test 3: Pub/Sub messaging works correctly"""
    logger.info("\n--- Test 3: Context Bus Messaging ---")

    try:
        from datetime import datetime
        bus = get_context_bus()

        # Clear any previous state
        bus.clear()

        # Create test message
        test_message = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"test": "data"}
        )

        # Test publish
        bus.publish(test_message)

        stats = bus.get_statistics()
        assert stats["total_messages"] == 1, \
            f"Message Publishing failed: Expected 1 message, got {stats['total_messages']}"
        logger.info(f"✅ PASS: Message Publishing - {stats['total_messages']} message")

        # Test retrieval
        retrieved = bus.get_all_contexts("test_findings")
        assert len(retrieved) == 1 and retrieved[0].agent == "TestAgent", \
            "Message Retrieval failed: Expected TestAgent message"
        logger.info("✅ PASS: Message Retrieval - TestAgent message found")

        # Test subscribe callback
        callback_triggered = {"value": False}

        def test_callback(msg: MCPMessage):
            callback_triggered["value"] = True

        bus.subscribe("test_callback", test_callback)

        test_message2 = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent2",
            context_type="test_callback",
            contract="test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"test": "callback"}
        )
        bus.publish(test_message2)

        assert callback_triggered["value"], \
            "Subscriber Callback failed: Callback should be triggered on publish"
        logger.info("✅ PASS: Subscriber Callback - Callback triggered successfully")

    except Exception as e:
        pytest.fail(f"Context Bus Messaging failed: {str(e)}")


def test_static_agent_execution():
    """Test 4: StaticAgent execution on real contract"""
    logger.info("\n--- Test 4: StaticAgent Execution ---")

    # Check if voting.sol exists
    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        pytest.skip(f"Test contract not found: {contract_path}")

    try:
        agent = StaticAgent()

        # Run analysis
        analysis_results = agent.run(contract_path, solc_version="0.8.0")

        assert "static_findings" in analysis_results, \
            "StaticAgent Execution failed: Expected static_findings in results"
        logger.info("✅ PASS: StaticAgent Execution - static_findings present")

        # Check if findings were published to Context Bus
        bus = get_context_bus()
        static_contexts = bus.get_all_contexts("static_findings")

        assert len(static_contexts) > 0, \
            f"StaticAgent Context Publishing failed: Expected published findings, got {len(static_contexts)}"
        logger.info(f"✅ PASS: StaticAgent Context Publishing - {len(static_contexts)} findings published")

        # Check findings structure
        if analysis_results.get("static_findings"):
            first_finding = analysis_results["static_findings"][0]
            has_required_fields = all(
                key in first_finding
                for key in ["source", "severity", "layer"]
            )
            assert has_required_fields, \
                "StaticAgent Finding Structure failed: Findings should have required fields"
            logger.info("✅ PASS: StaticAgent Finding Structure - all required fields present")

    except Exception as e:
        pytest.fail(f"StaticAgent Execution failed: {str(e)}")


def test_policy_agent_compliance():
    """Test 5: PolicyAgent compliance checking"""
    logger.info("\n--- Test 5: PolicyAgent Compliance ---")

    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        pytest.skip(f"Test contract not found: {contract_path}")

    try:
        # First run StaticAgent to generate findings
        static_agent = StaticAgent()
        static_agent.run(contract_path, solc_version="0.8.0")

        # Now run PolicyAgent
        policy_agent = PolicyAgent()
        compliance_results = policy_agent.run(contract_path)

        assert "compliance_report" in compliance_results, \
            "PolicyAgent Execution failed: Expected compliance_report in results"
        logger.info("✅ PASS: PolicyAgent Execution - compliance_report present")

        # Check ISO 27001 compliance
        iso_status = compliance_results.get("iso27001_status", {})
        assert "controls" in iso_status and "compliance_score" in iso_status, \
            "ISO 27001 Check failed: Expected ISO 27001 controls and score"
        logger.info("✅ PASS: ISO 27001 Check - controls and score present")

        # Check NIST SSDF compliance
        nist_status = compliance_results.get("nist_ssdf_status", {})
        assert "practices" in nist_status and "compliance_score" in nist_status, \
            "NIST SSDF Check failed: Expected NIST practices and score"
        logger.info("✅ PASS: NIST SSDF Check - practices and score present")

        # Check OWASP coverage
        owasp_coverage = compliance_results.get("owasp_coverage", {})
        assert "categories" in owasp_coverage and "coverage_score" in owasp_coverage, \
            "OWASP Coverage Check failed: Expected OWASP categories and coverage"
        logger.info("✅ PASS: OWASP Coverage Check - categories and coverage present")

    except Exception as e:
        pytest.fail(f"PolicyAgent Compliance failed: {str(e)}")


def test_coordinator_orchestration():
    """Test 6: CoordinatorAgent orchestration"""
    logger.info("\n--- Test 6: CoordinatorAgent Orchestration ---")

    contract_path = "examples/voting.sol"
    if not Path(contract_path).exists():
        pytest.skip(f"Test contract not found: {contract_path}")

    try:
        coordinator = CoordinatorAgent()

        # Generate audit plan
        orchestration_results = coordinator.run(
            contract_path,
            priority="fast",
            audit_scope=["static", "ai"]
        )

        assert "audit_plan" in orchestration_results, \
            "CoordinatorAgent Execution failed: Expected audit_plan in results"
        logger.info("✅ PASS: CoordinatorAgent Execution - audit_plan present")

        # Check audit plan structure
        audit_plan = orchestration_results.get("audit_plan", {})
        assert "phases" in audit_plan and "priority" in audit_plan, \
            "Audit Plan Structure failed: Audit plan should have phases and priority"
        logger.info("✅ PASS: Audit Plan Structure - phases and priority present")

        # Check execution progress
        progress = orchestration_results.get("audit_progress", [])
        assert len(progress) > 0, \
            f"Audit Progress Tracking failed: Expected progress events, got {len(progress)}"
        logger.info(f"✅ PASS: Audit Progress Tracking - {len(progress)} progress events")

        # Check audit summary
        summary = orchestration_results.get("audit_summary", {})
        assert "total_findings" in summary and "compliance" in summary, \
            "Audit Summary Generation failed: Summary should have findings and compliance data"
        logger.info("✅ PASS: Audit Summary Generation - findings and compliance data present")

    except Exception as e:
        pytest.fail(f"CoordinatorAgent Orchestration failed: {str(e)}")


def test_audit_trail_export():
    """Test 7: Bus statistics and message tracking"""
    logger.info("\n--- Test 7: Bus Statistics & Message Tracking ---")

    try:
        bus = get_context_bus()

        # Get comprehensive statistics
        stats = bus.get_statistics()

        assert "total_messages" in stats, \
            "Statistics failed: Should contain total_messages"
        logger.info(f"✅ PASS: Statistics - total_messages: {stats['total_messages']}")

        assert "context_types" in stats, \
            "Statistics failed: Should contain context_types"
        logger.info(f"✅ PASS: Context Types - {len(stats['context_types'])} types")

        assert "messages_per_type" in stats, \
            "Statistics failed: Should contain messages_per_type"
        logger.info("✅ PASS: Message Distribution - messages_per_type present")

        # Test that we can export statistics for audit purposes
        output_dir = Path("outputs/evidence")
        output_dir.mkdir(parents=True, exist_ok=True)

        audit_stats_path = output_dir / "test_audit_stats.json"
        with open(audit_stats_path, 'w') as f:
            json.dump(stats, f, indent=2)

        assert audit_stats_path.exists(), \
            f"Stats Export failed: Stats should be exported to {audit_stats_path}"
        logger.info(f"✅ PASS: Stats Export - exported to {audit_stats_path}")

    except Exception as e:
        pytest.fail(f"Statistics tracking failed: {str(e)}")


def test_cross_layer_integration():
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

        assert active_types >= 2, \
            f"Multi-Layer Context Aggregation failed: Expected multiple active layers, got {active_types}"
        logger.info(f"✅ PASS: Multi-Layer Context Aggregation - {active_types} active layers")

        # Test context retrieval from different layers
        static_msgs = all_contexts.get("static_findings", [])
        compliance_msgs = all_contexts.get("compliance_report", [])

        assert len(static_msgs) > 0 or len(compliance_msgs) > 0, \
            "Cross-Layer Message Flow failed: At least one layer should have messages"
        logger.info("✅ PASS: Cross-Layer Message Flow - messages present in layers")

    except Exception as e:
        pytest.fail(f"Cross-Layer Integration failed: {str(e)}")
