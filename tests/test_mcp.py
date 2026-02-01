"""
MIESC MCP Module Tests
Tests for context_bus and MCP message protocol.
"""

import pytest

# =============================================================================
# MCP MESSAGE TESTS
# =============================================================================


class TestMCPMessage:
    """Tests for MCPMessage dataclass."""

    def test_mcp_message_import(self):
        """Test that MCPMessage can be imported."""
        from src.mcp.context_bus import MCPMessage

        assert MCPMessage is not None

    def test_mcp_message_creation(self):
        """Test creating a valid MCP message."""
        from src.mcp.context_bus import MCPMessage

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data={"findings": []},
            metadata={"version": "1.0"},
        )

        assert msg.protocol == "mcp/1.0"
        assert msg.agent == "TestAgent"
        assert msg.context_type == "test_findings"
        assert msg.contract == "Test.sol"
        assert msg.timestamp == "2024-01-01T00:00:00Z"
        assert msg.data == {"findings": []}
        assert msg.metadata == {"version": "1.0"}

    def test_mcp_message_default_metadata(self):
        """Test MCPMessage with default metadata."""
        from src.mcp.context_bus import MCPMessage

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[],
        )

        assert msg.metadata == {}

    def test_mcp_message_auto_timestamp(self):
        """Test MCPMessage auto-generates timestamp if empty."""
        from src.mcp.context_bus import MCPMessage

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="",
            data=[],
        )

        # Should have generated a timestamp
        assert msg.timestamp != ""
        assert "T" in msg.timestamp  # ISO format

    def test_mcp_message_non_standard_protocol(self):
        """Test MCPMessage warns on non-standard protocol."""
        from src.mcp.context_bus import MCPMessage

        # Should not raise, but logs a warning
        msg = MCPMessage(
            protocol="custom/2.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[],
        )

        assert msg.protocol == "custom/2.0"


# =============================================================================
# CONTEXT BUS TESTS
# =============================================================================


class TestContextBus:
    """Tests for ContextBus class."""

    def test_context_bus_import(self):
        """Test that ContextBus can be imported."""
        from src.mcp.context_bus import ContextBus

        assert ContextBus is not None

    def test_context_bus_initialization(self):
        """Test ContextBus can be initialized."""
        from src.mcp.context_bus import ContextBus

        bus = ContextBus()
        assert bus is not None
        assert hasattr(bus, "_messages")
        assert hasattr(bus, "_subscribers")
        assert hasattr(bus, "_lock")

    def test_context_bus_publish(self):
        """Test publishing a message to the bus."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[{"severity": "High"}],
        )

        bus.publish(msg)

        # Verify message was stored
        messages = bus.get_all_contexts("test_findings")
        assert len(messages) == 1
        assert messages[0].agent == "TestAgent"

    def test_context_bus_publish_multiple(self):
        """Test publishing multiple messages."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        for i in range(3):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent=f"Agent{i}",
                context_type="test_findings",
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={"index": i},
            )
            bus.publish(msg)

        messages = bus.get_all_contexts("test_findings")
        assert len(messages) == 3

    def test_context_bus_subscribe(self):
        """Test subscribing to context type."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()
        received_messages = []

        def callback(msg):
            received_messages.append(msg)

        bus.subscribe("test_findings", callback)

        # Publish a message
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[],
        )
        bus.publish(msg)

        # Callback should have been called
        assert len(received_messages) == 1
        assert received_messages[0].agent == "TestAgent"

    def test_context_bus_subscribe_multiple_callbacks(self):
        """Test multiple subscribers to same context type."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()
        callback1_called = []
        callback2_called = []

        bus.subscribe("test_findings", lambda m: callback1_called.append(m))
        bus.subscribe("test_findings", lambda m: callback2_called.append(m))

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[],
        )
        bus.publish(msg)

        assert len(callback1_called) == 1
        assert len(callback2_called) == 1

    def test_context_bus_subscribe_error_handling(self):
        """Test that subscriber errors don't crash the bus."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        def failing_callback(msg):
            raise ValueError("Test error")

        bus.subscribe("test_findings", failing_callback)

        # Should not raise despite callback error
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[],
        )
        bus.publish(msg)  # Should not raise

    def test_context_bus_get_latest_context(self):
        """Test getting the latest message of a context type."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        # Publish multiple messages
        for i in range(3):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent=f"Agent{i}",
                context_type="test_findings",
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={"index": i},
            )
            bus.publish(msg)

        latest = bus.get_latest_context("test_findings")
        assert latest is not None
        assert latest.agent == "Agent2"  # Last one published
        assert latest.data["index"] == 2

    def test_context_bus_get_latest_context_empty(self):
        """Test getting latest from empty context type."""
        from src.mcp.context_bus import ContextBus

        bus = ContextBus()
        latest = bus.get_latest_context("nonexistent_type")
        assert latest is None

    def test_context_bus_get_all_contexts(self):
        """Test getting all messages of a context type."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        for i in range(3):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent=f"Agent{i}",
                context_type="test_findings",
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={},
            )
            bus.publish(msg)

        messages = bus.get_all_contexts("test_findings")
        assert len(messages) == 3
        assert all(isinstance(m, MCPMessage) for m in messages)

    def test_context_bus_get_all_contexts_empty(self):
        """Test getting all from empty context type."""
        from src.mcp.context_bus import ContextBus

        bus = ContextBus()
        messages = bus.get_all_contexts("nonexistent_type")
        assert messages == []

    def test_context_bus_aggregate_contexts(self):
        """Test aggregating multiple context types."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        # Publish to different context types
        for ct in ["static_findings", "dynamic_findings", "ai_findings"]:
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent="TestAgent",
                context_type=ct,
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={"type": ct},
            )
            bus.publish(msg)

        result = bus.aggregate_contexts(["static_findings", "dynamic_findings"])

        assert "static_findings" in result
        assert "dynamic_findings" in result
        assert len(result["static_findings"]) == 1
        assert len(result["dynamic_findings"]) == 1

    def test_context_bus_aggregate_contexts_with_missing(self):
        """Test aggregating with some missing context types."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="existing",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data={},
        )
        bus.publish(msg)

        result = bus.aggregate_contexts(["existing", "nonexistent"])

        assert "existing" in result
        assert "nonexistent" in result
        assert len(result["existing"]) == 1
        assert len(result["nonexistent"]) == 0

    def test_context_bus_clear(self):
        """Test clearing the bus."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        # Add some messages and subscribers
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data={},
        )
        bus.publish(msg)
        bus.subscribe("test", lambda m: None)

        # Clear the bus
        bus.clear()

        # Should be empty
        assert bus.get_all_contexts("test") == []
        stats = bus.get_statistics()
        assert stats["total_messages"] == 0

    def test_context_bus_get_statistics(self):
        """Test getting bus statistics."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        # Publish to different context types
        for _i in range(2):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent="TestAgent",
                context_type="type_a",
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={},
            )
            bus.publish(msg)

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="type_b",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data={},
        )
        bus.publish(msg)

        # Add subscriber
        bus.subscribe("type_a", lambda m: None)

        stats = bus.get_statistics()

        assert "context_types" in stats
        assert "total_messages" in stats
        assert "messages_per_type" in stats
        assert "subscriber_count" in stats
        assert stats["total_messages"] == 3
        assert stats["messages_per_type"]["type_a"] == 2
        assert stats["messages_per_type"]["type_b"] == 1
        assert stats["subscriber_count"]["type_a"] == 1


# =============================================================================
# SINGLETON TESTS
# =============================================================================


class TestContextBusSingleton:
    """Tests for singleton functions."""

    def test_get_context_bus(self):
        """Test getting singleton instance."""
        from src.mcp.context_bus import get_context_bus, reset_context_bus

        # Reset to ensure clean state
        reset_context_bus()

        bus1 = get_context_bus()
        bus2 = get_context_bus()

        assert bus1 is bus2  # Same instance

    def test_reset_context_bus(self):
        """Test resetting singleton instance."""
        from src.mcp.context_bus import MCPMessage, get_context_bus, reset_context_bus

        bus1 = get_context_bus()

        # Add some data
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data={},
        )
        bus1.publish(msg)

        # Reset
        reset_context_bus()

        bus2 = get_context_bus()

        # Should be a new instance
        assert bus2.get_all_contexts("test") == []


# =============================================================================
# THREAD SAFETY TESTS
# =============================================================================


class TestContextBusThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_publish(self):
        """Test concurrent message publishing."""
        from concurrent.futures import ThreadPoolExecutor

        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()

        def publish_message(index):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent=f"Agent{index}",
                context_type="concurrent_test",
                contract="Test.sol",
                timestamp="2024-01-01T00:00:00Z",
                data={"index": index},
            )
            bus.publish(msg)
            return True

        # Publish from multiple threads
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(publish_message, range(100)))

        assert all(results)
        messages = bus.get_all_contexts("concurrent_test")
        assert len(messages) == 100


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestContextBusIntegration:
    """Integration tests for context bus with agents."""

    def test_multi_agent_communication(self):
        """Test communication between multiple agents via bus."""
        from src.mcp.context_bus import ContextBus, MCPMessage

        bus = ContextBus()
        received_by_coordinator = []

        # Coordinator subscribes to all findings
        bus.subscribe("static_findings", lambda m: received_by_coordinator.append(m))
        bus.subscribe("dynamic_findings", lambda m: received_by_coordinator.append(m))

        # Static agent publishes
        static_msg = MCPMessage(
            protocol="mcp/1.0",
            agent="StaticAgent",
            context_type="static_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[{"type": "reentrancy", "severity": "High"}],
        )
        bus.publish(static_msg)

        # Dynamic agent publishes
        dynamic_msg = MCPMessage(
            protocol="mcp/1.0",
            agent="DynamicAgent",
            context_type="dynamic_findings",
            contract="Test.sol",
            timestamp="2024-01-01T00:00:00Z",
            data=[{"type": "assertion_failure", "severity": "Medium"}],
        )
        bus.publish(dynamic_msg)

        # Coordinator should have received both
        assert len(received_by_coordinator) == 2
        agents = [m.agent for m in received_by_coordinator]
        assert "StaticAgent" in agents
        assert "DynamicAgent" in agents


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
