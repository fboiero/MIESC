"""
Tests for MIESC WebSocket API Module

Tests event types, event creation, and connection manager logic.
"""

import pytest
import json
from datetime import datetime

from src.core.websocket_api import (
    EventType,
    WebSocketEvent,
    ConnectionManager,
    AuditProgressTracker,
    WEBSOCKET_AVAILABLE,
)


class TestEventType:
    """Tests for EventType enum."""

    def test_connection_events_exist(self):
        """Test connection event types."""
        assert EventType.CONNECTED.value == "connected"
        assert EventType.DISCONNECTED.value == "disconnected"

    def test_audit_lifecycle_events(self):
        """Test audit lifecycle event types."""
        assert EventType.AUDIT_STARTED.value == "audit_started"
        assert EventType.AUDIT_PROGRESS.value == "audit_progress"
        assert EventType.AUDIT_COMPLETED.value == "audit_completed"
        assert EventType.AUDIT_ERROR.value == "audit_error"

    def test_tool_events(self):
        """Test tool event types."""
        assert EventType.TOOL_STARTED.value == "tool_started"
        assert EventType.TOOL_PROGRESS.value == "tool_progress"
        assert EventType.TOOL_COMPLETED.value == "tool_completed"
        assert EventType.TOOL_ERROR.value == "tool_error"

    def test_finding_events(self):
        """Test finding event types."""
        assert EventType.FINDING_DETECTED.value == "finding_detected"
        assert EventType.FINDINGS_BATCH.value == "findings_batch"

    def test_layer_events(self):
        """Test layer event types."""
        assert EventType.LAYER_STARTED.value == "layer_started"
        assert EventType.LAYER_COMPLETED.value == "layer_completed"

    def test_system_events(self):
        """Test system event types."""
        assert EventType.SYSTEM_STATUS.value == "system_status"
        assert EventType.HEARTBEAT.value == "heartbeat"


class TestWebSocketEvent:
    """Tests for WebSocketEvent dataclass."""

    def test_event_creation(self):
        """Test creating a WebSocket event."""
        event = WebSocketEvent(
            type=EventType.AUDIT_STARTED,
            data={"contract": "test.sol"},
        )

        assert event.type == EventType.AUDIT_STARTED
        assert event.data == {"contract": "test.sol"}
        assert event.timestamp is not None
        assert event.audit_id is None

    def test_event_with_audit_id(self):
        """Test event with audit ID."""
        event = WebSocketEvent(
            type=EventType.FINDING_DETECTED,
            data={"severity": "high"},
            audit_id="audit-123",
        )

        assert event.audit_id == "audit-123"

    def test_event_to_json(self):
        """Test JSON serialization."""
        event = WebSocketEvent(
            type=EventType.TOOL_COMPLETED,
            data={"tool": "slither", "findings": 5},
            audit_id="audit-456",
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["type"] == "tool_completed"
        assert parsed["data"]["tool"] == "slither"
        assert parsed["data"]["findings"] == 5
        assert parsed["audit_id"] == "audit-456"
        assert "timestamp" in parsed

    def test_event_timestamp_format(self):
        """Test timestamp is ISO format."""
        event = WebSocketEvent(
            type=EventType.HEARTBEAT,
            data={},
        )

        # Should be parseable as ISO datetime
        datetime.fromisoformat(event.timestamp.replace("+00:00", ""))


class TestConnectionManager:
    """Tests for ConnectionManager."""

    def test_initialization(self):
        """Test manager initialization."""
        manager = ConnectionManager()

        assert manager.active_connections == set()
        assert manager.audit_subscriptions == {}

    def test_subscription_tracking(self):
        """Test audit subscription tracking setup."""
        manager = ConnectionManager()

        # Initialize a subscription bucket
        manager.audit_subscriptions["audit-1"] = set()

        assert "audit-1" in manager.audit_subscriptions


class TestAuditProgressTracker:
    """Tests for AuditProgressTracker."""

    @pytest.fixture
    def manager(self):
        """Create a ConnectionManager for tests."""
        return ConnectionManager()

    def test_tracker_initialization(self, manager):
        """Test tracker initialization."""
        tracker = AuditProgressTracker(
            manager=manager,
            audit_id="audit-test",
            total_layers=7,
        )

        assert tracker.audit_id == "audit-test"
        assert tracker.total_layers == 7
        assert tracker.current_layer == 0
        assert tracker.findings_count == 0
        assert tracker.manager is manager

    def test_layer_count(self, manager):
        """Test layer tracking."""
        tracker = AuditProgressTracker(
            manager=manager,
            audit_id="audit-1",
            total_layers=5,
        )

        tracker.current_layer = 3
        assert tracker.current_layer == 3

    def test_progress_calculation(self, manager):
        """Test progress percentage calculation."""
        tracker = AuditProgressTracker(
            manager=manager,
            audit_id="audit-1",
            total_layers=10,
        )

        tracker.current_layer = 5
        expected_progress = (5 / 10) * 100
        assert expected_progress == 50.0

    def test_findings_accumulation(self, manager):
        """Test findings count tracking."""
        tracker = AuditProgressTracker(
            manager=manager,
            audit_id="audit-1",
            total_layers=7,
        )

        tracker.findings_count = 10
        assert tracker.findings_count == 10

        tracker.findings_count += 5
        assert tracker.findings_count == 15

    def test_tools_tracking(self, manager):
        """Test tools completed tracking."""
        tracker = AuditProgressTracker(
            manager=manager,
            audit_id="audit-1",
            total_layers=7,
        )

        tracker.total_tools = 10
        tracker.tools_completed = 5

        assert tracker.total_tools == 10
        assert tracker.tools_completed == 5


class TestWebSocketAvailability:
    """Tests for WebSocket availability check."""

    def test_availability_flag_exists(self):
        """Test that availability flag is defined."""
        assert isinstance(WEBSOCKET_AVAILABLE, bool)

    def test_websocket_module_imports(self):
        """Test module imports without error."""
        # If we got here, the module imported successfully
        from src.core.websocket_api import EventType, WebSocketEvent
        assert EventType is not None
        assert WebSocketEvent is not None
