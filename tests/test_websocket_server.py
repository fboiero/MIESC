"""
Tests for MIESC WebSocket Server

Tests for real-time audit streaming functionality.

Author: Fernando Boiero
"""

import pytest
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch, AsyncMock

import asyncio

# Helper to run async tests without pytest-asyncio
def run_async(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


class TestEventType:
    """Tests for EventType enum."""

    def test_event_type_values(self):
        """Test that all event types have correct string values."""
        from src.mcp.websocket_server import EventType

        assert EventType.CONNECTED.value == "connected"
        assert EventType.AUDIT_STARTED.value == "audit_started"
        assert EventType.AUDIT_COMPLETED.value == "audit_completed"
        assert EventType.LAYER_STARTED.value == "layer_started"
        assert EventType.FINDING_DISCOVERED.value == "finding_discovered"
        assert EventType.HEARTBEAT.value == "heartbeat"
        assert EventType.ERROR.value == "error"


class TestAuditSession:
    """Tests for AuditSession dataclass."""

    def test_session_creation(self):
        """Test creating an audit session."""
        from src.mcp.websocket_server import AuditSession

        session = AuditSession(
            session_id="test-123",
            contract_path="/tmp/Token.sol",
            layers=[1, 2, 3, 7],
            started_at=datetime.now(timezone.utc)
        )

        assert session.session_id == "test-123"
        assert session.contract_path == "/tmp/Token.sol"
        assert session.layers == [1, 2, 3, 7]
        assert session.status == "running"
        assert session.current_layer == 0
        assert session.findings_count == 0

    def test_session_to_dict(self):
        """Test session serialization to dict."""
        from src.mcp.websocket_server import AuditSession

        now = datetime.now(timezone.utc)
        session = AuditSession(
            session_id="test-456",
            contract_path="/tmp/Vault.sol",
            layers=[1, 3],
            started_at=now,
            findings_count=5,
            progress_percent=50.0
        )

        result = session.to_dict()

        assert result["session_id"] == "test-456"
        assert result["contract_path"] == "/tmp/Vault.sol"
        assert result["layers"] == [1, 3]
        assert result["started_at"] == now.isoformat()
        assert result["findings_count"] == 5
        assert result["progress_percent"] == 50.0


class TestStreamEvent:
    """Tests for StreamEvent dataclass."""

    def test_event_creation(self):
        """Test creating a stream event."""
        from src.mcp.websocket_server import StreamEvent, EventType

        event = StreamEvent(
            event_type=EventType.AUDIT_STARTED,
            session_id="session-1",
            timestamp=datetime.now(timezone.utc),
            data={"contract_path": "/tmp/Test.sol"}
        )

        assert event.event_type == EventType.AUDIT_STARTED
        assert event.session_id == "session-1"
        assert "contract_path" in event.data

    def test_event_to_json(self):
        """Test event serialization to JSON."""
        from src.mcp.websocket_server import StreamEvent, EventType

        now = datetime.now(timezone.utc)
        event = StreamEvent(
            event_type=EventType.FINDING_DISCOVERED,
            session_id="session-2",
            timestamp=now,
            data={"severity": "high", "type": "reentrancy"}
        )

        json_str = event.to_json()
        parsed = json.loads(json_str)

        assert parsed["event"] == "finding_discovered"
        assert parsed["session_id"] == "session-2"
        assert parsed["timestamp"] == now.isoformat()
        assert parsed["data"]["severity"] == "high"


class TestMIESCWebSocketServer:
    """Tests for MIESCWebSocketServer class."""

    def test_server_initialization(self):
        """Test server initialization with default params."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        server = MIESCWebSocketServer()

        assert server.host == "localhost"
        assert server.port == 8765
        assert server.heartbeat_interval == 30
        assert len(server._clients) == 0
        assert len(server._sessions) == 0

    def test_server_custom_params(self):
        """Test server initialization with custom params."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        server = MIESCWebSocketServer(
            host="0.0.0.0",
            port=9000,
            heartbeat_interval=60
        )

        assert server.host == "0.0.0.0"
        assert server.port == 9000
        assert server.heartbeat_interval == 60

    def test_get_layer_name(self):
        """Test getting human-readable layer names."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        server = MIESCWebSocketServer()

        assert server._get_layer_name(1) == "Static Analysis"
        assert server._get_layer_name(2) == "Fuzzing"
        assert server._get_layer_name(3) == "Symbolic Execution"
        assert server._get_layer_name(4) == "Invariant Testing"
        assert server._get_layer_name(5) == "Formal Verification"
        assert server._get_layer_name(6) == "Property Testing"
        assert server._get_layer_name(7) == "AI Analysis"
        assert server._get_layer_name(99) == "Layer 99"

    def test_server_requires_websockets(self):
        """Test that server raises ImportError if websockets not installed."""
        # This test is conditional - skip if websockets is installed
        try:
            import websockets
            pytest.skip("websockets is installed, cannot test ImportError")
        except ImportError:
            with pytest.raises(ImportError) as exc_info:
                from src.mcp.websocket_server import MIESCWebSocketServer
                MIESCWebSocketServer()
            assert "websockets package not installed" in str(exc_info.value)


class TestWebSocketServerAsync:
    """Async tests for WebSocket server functionality."""

    def test_send_event(self):
        """Test sending event to a client."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import (
            MIESCWebSocketServer,
            StreamEvent,
            EventType
        )

        async def _test():
            server = MIESCWebSocketServer()

            # Mock websocket
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()

            event = StreamEvent(
                event_type=EventType.HEARTBEAT,
                session_id="system",
                timestamp=datetime.now(timezone.utc),
                data={"test": True}
            )

            await server._send_event(mock_ws, event)

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["event"] == "heartbeat"

        run_async(_test())

    def test_send_error(self):
        """Test sending error event to client."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        async def _test():
            server = MIESCWebSocketServer()

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()

            await server._send_error(mock_ws, "Test error message")

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["event"] == "error"
            assert sent_data["data"]["error"] == "Test error message"

        run_async(_test())

    def test_broadcast_event(self):
        """Test broadcasting event to subscribed clients."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import (
            MIESCWebSocketServer,
            StreamEvent,
            EventType
        )

        async def _test():
            server = MIESCWebSocketServer()

            # Create mock clients
            mock_ws1 = AsyncMock()
            mock_ws1.send = AsyncMock()
            mock_ws2 = AsyncMock()
            mock_ws2.send = AsyncMock()

            # Add clients to server
            server._clients.add(mock_ws1)
            server._clients.add(mock_ws2)

            # Subscribe ws1 to session, ws2 not subscribed
            server._subscriptions[mock_ws1] = {"session-abc"}
            server._subscriptions[mock_ws2] = set()

            event = StreamEvent(
                event_type=EventType.LAYER_STARTED,
                session_id="session-abc",
                timestamp=datetime.now(timezone.utc),
                data={"layer": 1}
            )

            await server._broadcast_event("session-abc", event)

            # Only subscribed client should receive
            mock_ws1.send.assert_called_once()
            mock_ws2.send.assert_not_called()

        run_async(_test())

    def test_send_sessions_list(self):
        """Test sending list of sessions to client."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import (
            MIESCWebSocketServer,
            AuditSession
        )

        async def _test():
            server = MIESCWebSocketServer()

            # Add a session
            session = AuditSession(
                session_id="test-session",
                contract_path="/tmp/Test.sol",
                layers=[1, 2],
                started_at=datetime.now(timezone.utc)
            )
            server._sessions["test-session"] = session

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()

            await server._send_sessions_list(mock_ws)

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert "sessions" in sent_data["data"]
            assert len(sent_data["data"]["sessions"]) == 1

        run_async(_test())

    def test_handle_message_subscribe(self):
        """Test handling subscribe command."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        async def _test():
            server = MIESCWebSocketServer()

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            server._subscriptions[mock_ws] = set()

            message = json.dumps({
                "command": "subscribe",
                "session_id": "session-xyz"
            })

            await server._handle_message(mock_ws, message)

            assert "session-xyz" in server._subscriptions[mock_ws]

        run_async(_test())

    def test_handle_message_unsubscribe(self):
        """Test handling unsubscribe command."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        async def _test():
            server = MIESCWebSocketServer()

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            server._subscriptions[mock_ws] = {"session-xyz"}

            message = json.dumps({
                "command": "unsubscribe",
                "session_id": "session-xyz"
            })

            await server._handle_message(mock_ws, message)

            assert "session-xyz" not in server._subscriptions[mock_ws]

        run_async(_test())

    def test_handle_message_invalid_json(self):
        """Test handling invalid JSON message."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        async def _test():
            server = MIESCWebSocketServer()

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            server._subscriptions[mock_ws] = set()

            await server._handle_message(mock_ws, "not valid json")

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["event"] == "error"
            assert "Invalid JSON" in sent_data["data"]["error"]

        run_async(_test())

    def test_handle_message_unknown_command(self):
        """Test handling unknown command."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import MIESCWebSocketServer

        async def _test():
            server = MIESCWebSocketServer()

            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            server._subscriptions[mock_ws] = set()

            message = json.dumps({"command": "unknown_command"})

            await server._handle_message(mock_ws, message)

            mock_ws.send.assert_called_once()
            sent_data = json.loads(mock_ws.send.call_args[0][0])
            assert sent_data["event"] == "error"
            assert "Unknown command" in sent_data["data"]["error"]

        run_async(_test())


class TestRunServer:
    """Tests for run_server convenience function."""

    def test_run_server_function_exists(self):
        """Test that run_server function exists."""
        pytest.importorskip("websockets")
        from src.mcp.websocket_server import run_server

        assert callable(run_server)
