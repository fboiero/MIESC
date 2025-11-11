"""
Unit Tests for MCP Context Bus

Tests the ContextBus and MCPMessage implementations for correctness,
thread safety, and integration with the agent system.

Test Coverage:
- MCPMessage creation and validation
- ContextBus singleton pattern
- Publish/subscribe mechanism
- Message storage and retrieval
- Context aggregation
- Error handling
- Thread safety
"""

import pytest
import threading
import time
from datetime import datetime
from src.mcp.context_bus import (
    ContextBus, MCPMessage, get_context_bus, reset_context_bus
)


class TestMCPMessage:
    """Tests for MCPMessage dataclass."""

    def test_message_creation(self):
        """Test basic message creation."""
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_context",
            contract="Test.sol",
            timestamp="2025-11-08T00:00:00Z",
            data={"test": "data"},
            metadata={"version": "1.0"}
        )

        assert msg.protocol == "mcp/1.0"
        assert msg.agent == "TestAgent"
        assert msg.context_type == "test_context"
        assert msg.contract == "Test.sol"
        assert msg.data == {"test": "data"}
        assert msg.metadata == {"version": "1.0"}

    def test_auto_timestamp_generation(self):
        """Test automatic timestamp generation when not provided."""
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="",
            data={}
        )

        assert msg.timestamp != ""
        assert "T" in msg.timestamp  # ISO 8601 format
        assert msg.timestamp.endswith("Z")  # UTC timezone

    def test_protocol_validation_warning(self, caplog):
        """Test warning for non-standard protocol."""
        msg = MCPMessage(
            protocol="invalid/1.0",  # Should start with "mcp/"
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2025-11-08T00:00:00Z",
            data={}
        )

        # Check that warning was logged
        assert any("Non-standard protocol" in record.message for record in caplog.records)

    def test_metadata_optional(self):
        """Test that metadata is optional with default empty dict."""
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp="2025-11-08T00:00:00Z",
            data={}
        )

        assert msg.metadata == {}


class TestContextBusSingleton:
    """Tests for ContextBus singleton pattern."""

    def test_singleton_instance(self):
        """Test that get_context_bus returns the same instance."""
        reset_context_bus()
        bus1 = get_context_bus()
        bus2 = get_context_bus()

        assert bus1 is bus2

    def test_reset_creates_new_instance(self):
        """Test that reset_context_bus creates a fresh instance."""
        reset_context_bus()
        bus1 = get_context_bus()

        reset_context_bus()
        bus2 = get_context_bus()

        assert bus1 is not bus2


class TestContextBusPublishSubscribe:
    """Tests for publish/subscribe functionality."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_publish_message(self):
        """Test publishing a message to the bus."""
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"key": "value"}
        )

        self.bus.publish(msg)

        latest = self.bus.get_latest_context("test")
        assert latest is not None
        assert latest.agent == "TestAgent"
        assert latest.data == {"key": "value"}

    def test_subscribe_callback(self):
        """Test subscription callback mechanism."""
        received_messages = []

        def callback(msg):
            received_messages.append(msg)

        self.bus.subscribe("test_callback", callback)

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_callback",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"test": "data"}
        )

        self.bus.publish(msg)

        assert len(received_messages) == 1
        assert received_messages[0].agent == "TestAgent"

    def test_multiple_subscribers(self):
        """Test multiple subscribers to same context type."""
        received1 = []
        received2 = []

        def callback1(msg):
            received1.append(msg)

        def callback2(msg):
            received2.append(msg)

        self.bus.subscribe("test", callback1)
        self.bus.subscribe("test", callback2)

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={}
        )

        self.bus.publish(msg)

        assert len(received1) == 1
        assert len(received2) == 1
        assert received1[0] is received2[0]  # Same message object

    def test_callback_error_handling(self):
        """Test that callback errors don't break the bus."""
        received_ok = []

        def failing_callback(msg):
            raise ValueError("Intentional error")

        def ok_callback(msg):
            received_ok.append(msg)

        self.bus.subscribe("test_error", failing_callback)
        self.bus.subscribe("test_error", ok_callback)

        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test_error",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={}
        )

        # Should not raise exception
        self.bus.publish(msg)

        # ok_callback should still have received the message
        assert len(received_ok) == 1


class TestContextBusStorage:
    """Tests for message storage and retrieval."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_get_latest_context(self):
        """Test retrieving the latest message."""
        msg1 = MCPMessage(
            protocol="mcp/1.0",
            agent="Agent1",
            context_type="test",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"num": 1}
        )
        msg2 = MCPMessage(
            protocol="mcp/1.0",
            agent="Agent2",
            context_type="test",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={"num": 2}
        )

        self.bus.publish(msg1)
        self.bus.publish(msg2)

        latest = self.bus.get_latest_context("test")
        assert latest.agent == "Agent2"
        assert latest.data == {"num": 2}

    def test_get_all_contexts(self):
        """Test retrieving all messages of a context type."""
        for i in range(5):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent=f"Agent{i}",
                context_type="test_all",
                contract="Test.sol",
                timestamp=datetime.utcnow().isoformat() + "Z",
                data={"num": i}
            )
            self.bus.publish(msg)

        all_msgs = self.bus.get_all_contexts("test_all")
        assert len(all_msgs) == 5
        assert all_msgs[0].data["num"] == 0
        assert all_msgs[4].data["num"] == 4

    def test_get_nonexistent_context(self):
        """Test retrieving context that doesn't exist."""
        latest = self.bus.get_latest_context("nonexistent")
        assert latest is None

        all_msgs = self.bus.get_all_contexts("nonexistent")
        assert all_msgs == []


class TestContextBusAggregation:
    """Tests for context aggregation functionality."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_aggregate_multiple_contexts(self):
        """Test aggregating messages from multiple context types."""
        # Publish to different context types
        msg1 = MCPMessage(
            protocol="mcp/1.0",
            agent="StaticAgent",
            context_type="static_findings",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=[{"severity": "High"}]
        )
        msg2 = MCPMessage(
            protocol="mcp/1.0",
            agent="DynamicAgent",
            context_type="dynamic_findings",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=[{"severity": "Medium"}]
        )

        self.bus.publish(msg1)
        self.bus.publish(msg2)

        aggregated = self.bus.aggregate_contexts([
            "static_findings",
            "dynamic_findings",
            "nonexistent"
        ])

        assert "static_findings" in aggregated
        assert "dynamic_findings" in aggregated
        assert "nonexistent" in aggregated
        assert len(aggregated["static_findings"]) == 1
        assert len(aggregated["dynamic_findings"]) == 1
        assert len(aggregated["nonexistent"]) == 0


class TestContextBusStatistics:
    """Tests for statistics functionality."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_statistics(self):
        """Test bus statistics generation."""
        # Publish some messages
        for i in range(3):
            msg = MCPMessage(
                protocol="mcp/1.0",
                agent="TestAgent",
                context_type="test",
                contract="Test.sol",
                timestamp=datetime.utcnow().isoformat() + "Z",
                data={}
            )
            self.bus.publish(msg)

        msg2 = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="other",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={}
        )
        self.bus.publish(msg2)

        stats = self.bus.get_statistics()

        assert stats["total_messages"] == 4
        assert "test" in stats["context_types"]
        assert "other" in stats["context_types"]
        assert stats["messages_per_type"]["test"] == 3
        assert stats["messages_per_type"]["other"] == 1


class TestContextBusClear:
    """Tests for clear functionality."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_clear_all(self):
        """Test clearing all messages and subscriptions."""
        # Publish some messages
        msg = MCPMessage(
            protocol="mcp/1.0",
            agent="TestAgent",
            context_type="test",
            contract="Test.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data={}
        )
        self.bus.publish(msg)

        # Subscribe
        self.bus.subscribe("test", lambda m: None)

        # Clear
        self.bus.clear()

        # Verify everything is cleared
        assert self.bus.get_latest_context("test") is None
        stats = self.bus.get_statistics()
        assert stats["total_messages"] == 0


class TestThreadSafety:
    """Tests for thread safety."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_concurrent_publish(self):
        """Test concurrent publishing from multiple threads."""
        num_threads = 10
        messages_per_thread = 10
        threads = []

        def publish_messages(thread_id):
            for i in range(messages_per_thread):
                msg = MCPMessage(
                    protocol="mcp/1.0",
                    agent=f"Agent{thread_id}",
                    context_type="concurrent_test",
                    contract="Test.sol",
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    data={"thread": thread_id, "msg": i}
                )
                self.bus.publish(msg)

        # Start threads
        for i in range(num_threads):
            t = threading.Thread(target=publish_messages, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Verify all messages were published
        all_msgs = self.bus.get_all_contexts("concurrent_test")
        assert len(all_msgs) == num_threads * messages_per_thread

    def test_concurrent_subscribe_publish(self):
        """Test concurrent subscribing and publishing."""
        received_counts = {}

        def callback(thread_id):
            def cb(msg):
                if thread_id not in received_counts:
                    received_counts[thread_id] = 0
                received_counts[thread_id] += 1
            return cb

        def subscribe_and_wait(thread_id):
            self.bus.subscribe("thread_test", callback(thread_id))
            time.sleep(0.1)  # Give time for other threads

        def publish_messages():
            for i in range(5):
                msg = MCPMessage(
                    protocol="mcp/1.0",
                    agent="PublishAgent",
                    context_type="thread_test",
                    contract="Test.sol",
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    data={"msg": i}
                )
                self.bus.publish(msg)
                time.sleep(0.05)

        # Start subscriber threads
        sub_threads = []
        for i in range(3):
            t = threading.Thread(target=subscribe_and_wait, args=(i,))
            sub_threads.append(t)
            t.start()

        # Start publisher thread
        pub_thread = threading.Thread(target=publish_messages)
        pub_thread.start()

        # Wait for all threads
        for t in sub_threads:
            t.join()
        pub_thread.join()

        # All subscribers should have received all messages
        time.sleep(0.1)  # Give time for callbacks
        for thread_id in received_counts:
            assert received_counts[thread_id] == 5


class TestIntegrationWithAgents:
    """Integration tests with actual agents."""

    def setup_method(self):
        """Setup fresh ContextBus for each test."""
        reset_context_bus()
        self.bus = get_context_bus()

    def test_agent_import_and_bus_access(self):
        """Test that agents can import and access the bus."""
        from src.agents.static_agent import StaticAgent

        agent = StaticAgent()
        assert agent.bus is not None
        assert agent.bus is self.bus

    def test_agent_publish_findings(self):
        """Test agent publishing findings via the bus."""
        from src.agents.static_agent import StaticAgent

        agent = StaticAgent()
        agent.contract_path = "test.sol"

        agent.publish_findings(
            context_type="test_findings",
            findings={"findings": [{"severity": "High"}]},
            metadata={"tool": "test"}
        )

        latest = self.bus.get_latest_context("test_findings")
        assert latest is not None
        assert latest.agent == "StaticAgent"
        assert latest.context_type == "test_findings"

    def test_cross_agent_communication(self):
        """Test communication between different agents."""
        from src.agents.static_agent import StaticAgent
        from src.agents.ai_agent import AIAgent

        static_agent = StaticAgent()
        ai_agent = AIAgent()

        # Set up subscription
        received = []

        def callback(msg):
            received.append(msg)

        ai_agent.subscribe_to(["cross_test"], callback)

        # Publish from static agent
        static_agent.contract_path = "test.sol"
        static_agent.publish_findings(
            context_type="cross_test",
            findings={"findings": [{"test": "data"}]}
        )

        # Verify AI agent received it
        assert len(received) == 1
        assert received[0].agent == "StaticAgent"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
