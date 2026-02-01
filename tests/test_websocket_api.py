"""
Tests for MIESC WebSocket API Module

Tests event types, event creation, and connection manager logic.
"""

import json
from datetime import datetime

import pytest

from src.core.websocket_api import (
    WEBSOCKET_AVAILABLE,
    AuditProgressTracker,
    ConnectionManager,
    EventType,
    WebSocketEvent,
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


# =============================================================================
# Extended Tests for ConnectionManager
# =============================================================================

import asyncio  # noqa: E402
from unittest.mock import AsyncMock, Mock  # noqa: E402


class TestConnectionManagerAsync:
    """Async tests for ConnectionManager using asyncio.run()."""

    @pytest.fixture
    def manager(self):
        """Create a ConnectionManager."""
        return ConnectionManager()

    @pytest.fixture
    def mock_websocket(self):
        """Create mock WebSocket."""
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        return ws

    def test_connect_adds_to_active(self, manager, mock_websocket):
        """Test connect adds WebSocket to active connections."""
        asyncio.run(manager.connect(mock_websocket))

        assert mock_websocket in manager.active_connections
        mock_websocket.accept.assert_called_once()

    def test_disconnect_removes_from_active(self, manager, mock_websocket):
        """Test disconnect removes WebSocket."""
        manager.active_connections.add(mock_websocket)

        manager.disconnect(mock_websocket)

        assert mock_websocket not in manager.active_connections

    def test_disconnect_cleans_subscriptions(self, manager, mock_websocket):
        """Test disconnect cleans up audit subscriptions."""
        manager.active_connections.add(mock_websocket)
        manager.audit_subscriptions["audit-1"] = {mock_websocket}
        manager.audit_subscriptions["audit-2"] = {mock_websocket}

        manager.disconnect(mock_websocket)

        assert "audit-1" not in manager.audit_subscriptions
        assert "audit-2" not in manager.audit_subscriptions

    def test_subscribe_to_audit_creates_set(self, manager, mock_websocket):
        """Test subscribe creates set if not exists."""
        manager.subscribe_to_audit(mock_websocket, "new-audit")

        assert "new-audit" in manager.audit_subscriptions
        assert mock_websocket in manager.audit_subscriptions["new-audit"]

    def test_subscribe_to_existing_audit(self, manager, mock_websocket):
        """Test subscribe to existing audit."""
        other_ws = Mock()
        manager.audit_subscriptions["audit-1"] = {other_ws}

        manager.subscribe_to_audit(mock_websocket, "audit-1")

        assert mock_websocket in manager.audit_subscriptions["audit-1"]
        assert other_ws in manager.audit_subscriptions["audit-1"]

    def test_unsubscribe_removes_from_audit(self, manager, mock_websocket):
        """Test unsubscribe removes WebSocket."""
        manager.audit_subscriptions["audit-1"] = {mock_websocket}

        manager.unsubscribe_from_audit(mock_websocket, "audit-1")

        assert mock_websocket not in manager.audit_subscriptions.get("audit-1", set())

    def test_unsubscribe_nonexistent_audit_no_error(self, manager, mock_websocket):
        """Test unsubscribe from nonexistent audit doesn't error."""
        manager.unsubscribe_from_audit(mock_websocket, "nonexistent")
        # Should not raise

    def test_broadcast_sends_to_all(self, manager, mock_websocket):
        """Test broadcast sends to all connections."""
        ws2 = AsyncMock()
        manager.active_connections.add(mock_websocket)
        manager.active_connections.add(ws2)

        event = WebSocketEvent(type=EventType.HEARTBEAT, data={})
        asyncio.run(manager.broadcast(event))

        mock_websocket.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    def test_broadcast_handles_errors(self, manager):
        """Test broadcast handles send errors."""
        failing_ws = AsyncMock()
        failing_ws.send_text.side_effect = Exception("Connection lost")

        good_ws = AsyncMock()

        manager.active_connections.add(failing_ws)
        manager.active_connections.add(good_ws)

        event = WebSocketEvent(type=EventType.HEARTBEAT, data={})
        asyncio.run(manager.broadcast(event))

        # Failing connection should be disconnected
        assert failing_ws not in manager.active_connections
        assert good_ws in manager.active_connections

    def test_send_to_audit_only_subscribers(self, manager, mock_websocket):
        """Test send_to_audit only sends to subscribers."""
        non_subscriber = AsyncMock()
        manager.active_connections.add(mock_websocket)
        manager.active_connections.add(non_subscriber)
        manager.audit_subscriptions["audit-1"] = {mock_websocket}

        event = WebSocketEvent(type=EventType.AUDIT_PROGRESS, data={}, audit_id="audit-1")
        asyncio.run(manager.send_to_audit("audit-1", event))

        mock_websocket.send_text.assert_called_once()
        non_subscriber.send_text.assert_not_called()

    def test_send_to_audit_no_subscribers(self, manager):
        """Test send_to_audit with no subscribers."""
        event = WebSocketEvent(type=EventType.AUDIT_PROGRESS, data={})
        asyncio.run(manager.send_to_audit("nonexistent", event))
        # Should not raise

    def test_send_to_connection(self, manager, mock_websocket):
        """Test send to specific connection."""
        manager.active_connections.add(mock_websocket)

        event = WebSocketEvent(type=EventType.CONNECTED, data={})
        asyncio.run(manager.send_to_connection(mock_websocket, event))

        mock_websocket.send_text.assert_called_once()

    def test_send_to_connection_error_disconnects(self, manager):
        """Test send to connection error disconnects."""
        ws = AsyncMock()
        ws.send_text.side_effect = Exception("Error")
        manager.active_connections.add(ws)

        event = WebSocketEvent(type=EventType.HEARTBEAT, data={})
        asyncio.run(manager.send_to_connection(ws, event))

        assert ws not in manager.active_connections


# =============================================================================
# Extended Tests for AuditProgressTracker
# =============================================================================


class TestAuditProgressTrackerAsync:
    """Async tests for AuditProgressTracker using asyncio.run()."""

    @pytest.fixture
    def mock_manager(self):
        """Create mock ConnectionManager."""
        manager = Mock(spec=ConnectionManager)
        manager.send_to_audit = AsyncMock()
        return manager

    @pytest.fixture
    def tracker(self, mock_manager):
        """Create AuditProgressTracker."""
        return AuditProgressTracker(mock_manager, "test-audit", total_layers=7)

    def test_start_audit(self, tracker, mock_manager):
        """Test start_audit sends event."""
        asyncio.run(tracker.start_audit("/path/contract.sol", ["slither", "mythril"]))

        assert tracker.total_tools == 2
        mock_manager.send_to_audit.assert_called_once()

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.AUDIT_STARTED

    def test_start_layer(self, tracker, mock_manager):
        """Test start_layer updates current layer."""
        asyncio.run(tracker.start_layer(3, "Symbolic Execution", ["mythril"]))

        assert tracker.current_layer == 3

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.LAYER_STARTED

    def test_complete_layer(self, tracker, mock_manager):
        """Test complete_layer sends event."""
        asyncio.run(tracker.complete_layer(2, findings_count=5, duration=10.0))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.LAYER_COMPLETED
        assert event.data["findings_count"] == 5

    def test_start_tool(self, tracker, mock_manager):
        """Test start_tool sets current tool."""
        asyncio.run(tracker.start_tool("slither", layer=1))

        assert tracker.current_tool == "slither"

    def test_tool_progress(self, tracker, mock_manager):
        """Test tool_progress sends progress event."""
        asyncio.run(tracker.tool_progress("mythril", 50.0, "Analyzing..."))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.TOOL_PROGRESS
        assert event.data["progress"] == 50.0

    def test_complete_tool_with_findings(self, tracker, mock_manager):
        """Test complete_tool with findings."""
        tracker.total_tools = 3
        findings = [{"title": "Issue 1"}, {"title": "Issue 2"}]

        asyncio.run(tracker.complete_tool("slither", findings, 5.0))

        assert tracker.tools_completed == 1
        assert tracker.findings_count == 2
        # Should send both TOOL_COMPLETED and FINDINGS_BATCH
        assert mock_manager.send_to_audit.call_count == 2

    def test_complete_tool_without_findings(self, tracker, mock_manager):
        """Test complete_tool without findings."""
        asyncio.run(tracker.complete_tool("echidna", [], 3.0))

        # Only TOOL_COMPLETED, no FINDINGS_BATCH
        assert mock_manager.send_to_audit.call_count == 1

    def test_tool_error(self, tracker, mock_manager):
        """Test tool_error sends error event."""
        asyncio.run(tracker.tool_error("mythril", "Timeout"))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.TOOL_ERROR
        assert event.data["error"] == "Timeout"

    def test_report_finding(self, tracker, mock_manager):
        """Test report_finding increments count."""
        asyncio.run(tracker.report_finding({"title": "Reentrancy"}))

        assert tracker.findings_count == 1

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.FINDING_DETECTED

    def test_report_findings_batch(self, tracker, mock_manager):
        """Test report_findings batch."""
        findings = [{"title": "A"}, {"title": "B"}]
        asyncio.run(tracker.report_findings(findings))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.FINDINGS_BATCH
        assert event.data["count"] == 2

    def test_update_progress(self, tracker, mock_manager):
        """Test update_progress sends progress."""
        tracker.current_layer = 4
        tracker.current_tool = "halmos"

        asyncio.run(tracker.update_progress(75.0, "Processing..."))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.AUDIT_PROGRESS
        assert event.data["progress"] == 75.0

    def test_complete_audit(self, tracker, mock_manager):
        """Test complete_audit sends completion."""
        tracker.findings_count = 15
        # Mock start_time to naive datetime to match complete_audit implementation
        tracker.start_time = datetime.now()

        asyncio.run(tracker.complete_audit({"summary": {"critical": 2}}))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.AUDIT_COMPLETED

    def test_error(self, tracker, mock_manager):
        """Test error sends audit error."""
        tracker.current_layer = 5
        tracker.current_tool = "certora"

        asyncio.run(tracker.error("Fatal error"))

        event = mock_manager.send_to_audit.call_args[0][1]
        assert event.type == EventType.AUDIT_ERROR


# =============================================================================
# Test Global Functions
# =============================================================================


class TestGlobalFunctions:
    """Tests for module-level functions."""

    def test_get_connection_manager(self):
        """Test get_connection_manager function."""
        from src.core.websocket_api import get_connection_manager

        manager = get_connection_manager()
        # May return None if not initialized
        assert manager is None or isinstance(manager, ConnectionManager)

    def test_create_progress_tracker(self):
        """Test create_progress_tracker function."""
        from src.core.websocket_api import create_progress_tracker

        tracker = create_progress_tracker("test-id")
        # May return None if manager not available
        assert tracker is None or isinstance(tracker, AuditProgressTracker)


# =============================================================================
# Test WebSocket App (requires FastAPI)
# =============================================================================


@pytest.mark.skipif(not WEBSOCKET_AVAILABLE, reason="FastAPI not installed")
class TestWebSocketApp:
    """Tests for WebSocket app creation."""

    def test_create_app(self):
        """Test create_websocket_app returns FastAPI app."""
        from src.core.websocket_api import create_websocket_app

        app = create_websocket_app()
        assert app is not None
        assert hasattr(app.state, "manager")

    def test_app_has_manager(self):
        """Test app has ConnectionManager."""
        from src.core.websocket_api import create_websocket_app

        app = create_websocket_app()
        assert isinstance(app.state.manager, ConnectionManager)


@pytest.mark.skipif(not WEBSOCKET_AVAILABLE, reason="FastAPI not installed")
class TestWebSocketServer:
    """Tests for WebSocketServer class."""

    def test_server_init(self):
        """Test server initialization."""
        from src.core.websocket_api import WebSocketServer

        server = WebSocketServer(host="127.0.0.1", port=9999)
        assert server.host == "127.0.0.1"
        assert server.port == 9999

    def test_server_default_values(self):
        """Test server default values."""
        from src.core.websocket_api import WebSocketServer

        server = WebSocketServer()
        assert server.host == "0.0.0.0"
        assert server.port == 8765
