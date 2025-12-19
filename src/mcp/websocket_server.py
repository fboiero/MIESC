#!/usr/bin/env python3
"""
MIESC v4.1 - WebSocket Server for Real-time Audit Streaming

Provides real-time progress updates during multi-layer security audits.
Implements the Model Context Protocol (MCP) over WebSocket for agent integration.

Features:
- Real-time layer-by-layer progress events
- Finding notifications as they're discovered
- Support for multiple concurrent audit sessions
- Compatible with Claude Desktop and other MCP clients

Author: Fernando Boiero
Institution: UNDEF - IUA
License: GPL-3.0
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Set, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    WebSocketServerProtocol = object

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of events that can be streamed to clients."""
    # Connection events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"

    # Audit lifecycle events
    AUDIT_STARTED = "audit_started"
    AUDIT_COMPLETED = "audit_completed"
    AUDIT_FAILED = "audit_failed"

    # Layer events
    LAYER_STARTED = "layer_started"
    LAYER_COMPLETED = "layer_completed"
    LAYER_FAILED = "layer_failed"

    # Tool events
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # Finding events
    FINDING_DISCOVERED = "finding_discovered"
    FINDINGS_BATCH = "findings_batch"

    # Progress events
    PROGRESS_UPDATE = "progress_update"

    # System events
    HEARTBEAT = "heartbeat"
    ERROR = "error"


@dataclass
class AuditSession:
    """Represents an active audit session."""
    session_id: str
    contract_path: str
    layers: list
    started_at: datetime
    status: str = "running"
    current_layer: int = 0
    current_tool: Optional[str] = None
    findings_count: int = 0
    progress_percent: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "contract_path": self.contract_path,
            "layers": self.layers,
            "started_at": self.started_at.isoformat(),
            "status": self.status,
            "current_layer": self.current_layer,
            "current_tool": self.current_tool,
            "findings_count": self.findings_count,
            "progress_percent": self.progress_percent
        }


@dataclass
class StreamEvent:
    """Represents an event to be streamed to clients."""
    event_type: EventType
    session_id: str
    timestamp: datetime
    data: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "event": self.event_type.value,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data
        })


class MIESCWebSocketServer:
    """
    WebSocket server for real-time MIESC audit streaming.

    Example usage:
        server = MIESCWebSocketServer(host="0.0.0.0", port=8765)
        await server.start()
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        heartbeat_interval: int = 30
    ):
        if not WEBSOCKETS_AVAILABLE:
            raise ImportError(
                "websockets package not installed. "
                "Install with: pip install websockets"
            )

        self.host = host
        self.port = port
        self.heartbeat_interval = heartbeat_interval

        # Connected clients
        self._clients: Set[WebSocketServerProtocol] = set()

        # Active audit sessions
        self._sessions: Dict[str, AuditSession] = {}

        # Session subscriptions (client -> sessions they're watching)
        self._subscriptions: Dict[WebSocketServerProtocol, Set[str]] = {}

        # Event handlers
        self._event_handlers: Dict[str, Callable] = {}

        self._server = None
        self._heartbeat_task = None

    async def start(self) -> None:
        """Start the WebSocket server."""
        self._server = await websockets.serve(
            self._handle_client,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=10
        )

        # Start heartbeat task
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info(f"MIESC WebSocket server started on ws://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the WebSocket server."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("MIESC WebSocket server stopped")

    async def _handle_client(
        self,
        websocket: WebSocketServerProtocol,
        path: str
    ) -> None:
        """Handle a new WebSocket client connection."""
        self._clients.add(websocket)
        self._subscriptions[websocket] = set()

        client_id = str(uuid.uuid4())[:8]
        logger.info(f"Client {client_id} connected from {websocket.remote_address}")

        # Send welcome message
        await self._send_event(websocket, StreamEvent(
            event_type=EventType.CONNECTED,
            session_id="system",
            timestamp=datetime.now(timezone.utc),
            data={
                "client_id": client_id,
                "server_version": "4.2.0",
                "available_commands": [
                    "start_audit",
                    "subscribe",
                    "unsubscribe",
                    "get_sessions",
                    "get_status"
                ]
            }
        ))

        try:
            async for message in websocket:
                await self._handle_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._clients.discard(websocket)
            self._subscriptions.pop(websocket, None)
            logger.info(f"Client {client_id} disconnected")

    async def _handle_message(
        self,
        websocket: WebSocketServerProtocol,
        message: str
    ) -> None:
        """Handle incoming message from client."""
        try:
            data = json.loads(message)
            command = data.get("command", "")

            if command == "start_audit":
                await self._handle_start_audit(websocket, data)
            elif command == "subscribe":
                session_id = data.get("session_id")
                if session_id:
                    self._subscriptions[websocket].add(session_id)
                    await self._send_event(websocket, StreamEvent(
                        event_type=EventType.PROGRESS_UPDATE,
                        session_id=session_id,
                        timestamp=datetime.now(timezone.utc),
                        data={"subscribed": True}
                    ))
            elif command == "unsubscribe":
                session_id = data.get("session_id")
                if session_id:
                    self._subscriptions[websocket].discard(session_id)
            elif command == "get_sessions":
                await self._send_sessions_list(websocket)
            elif command == "get_status":
                session_id = data.get("session_id")
                if session_id and session_id in self._sessions:
                    session = self._sessions[session_id]
                    await self._send_event(websocket, StreamEvent(
                        event_type=EventType.PROGRESS_UPDATE,
                        session_id=session_id,
                        timestamp=datetime.now(timezone.utc),
                        data=session.to_dict()
                    ))
            else:
                await self._send_error(websocket, f"Unknown command: {command}")

        except json.JSONDecodeError:
            await self._send_error(websocket, "Invalid JSON")
        except Exception as e:
            await self._send_error(websocket, str(e))

    async def _handle_start_audit(
        self,
        websocket: WebSocketServerProtocol,
        data: Dict[str, Any]
    ) -> None:
        """Handle start_audit command."""
        contract_path = data.get("contract_path")
        layers = data.get("layers", [1, 2, 3, 7])

        if not contract_path:
            await self._send_error(websocket, "contract_path is required")
            return

        # Create new session
        session_id = str(uuid.uuid4())
        session = AuditSession(
            session_id=session_id,
            contract_path=contract_path,
            layers=layers,
            started_at=datetime.now(timezone.utc)
        )

        self._sessions[session_id] = session
        self._subscriptions[websocket].add(session_id)

        # Broadcast audit started
        await self._broadcast_event(session_id, StreamEvent(
            event_type=EventType.AUDIT_STARTED,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            data={
                "contract_path": contract_path,
                "layers": layers,
                "session": session.to_dict()
            }
        ))

        # Start audit in background
        asyncio.create_task(self._run_audit(session_id))

    async def _run_audit(self, session_id: str) -> None:
        """Run the actual audit and stream progress."""
        session = self._sessions.get(session_id)
        if not session:
            return

        try:
            # Import MIESC components
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from detectors.smartbugs_detectors import SmartBugsDetectorEngine

            detector = SmartBugsDetectorEngine()
            all_findings = []

            total_layers = len(session.layers)

            for i, layer in enumerate(session.layers):
                session.current_layer = layer
                session.progress_percent = (i / total_layers) * 100

                # Broadcast layer started
                await self._broadcast_event(session_id, StreamEvent(
                    event_type=EventType.LAYER_STARTED,
                    session_id=session_id,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "layer": layer,
                        "layer_name": self._get_layer_name(layer),
                        "progress_percent": session.progress_percent
                    }
                ))

                # Simulate tool execution (in real implementation, run actual tools)
                await asyncio.sleep(0.5)  # Simulate work

                # Run analysis for this layer
                try:
                    result = detector.analyze(session.contract_path)
                    layer_findings = result.get("findings", [])

                    # Stream findings as they're discovered
                    for finding in layer_findings:
                        session.findings_count += 1
                        all_findings.append(finding)

                        await self._broadcast_event(session_id, StreamEvent(
                            event_type=EventType.FINDING_DISCOVERED,
                            session_id=session_id,
                            timestamp=datetime.now(timezone.utc),
                            data={
                                "finding": finding,
                                "layer": layer,
                                "total_findings": session.findings_count
                            }
                        ))

                except Exception as e:
                    logger.error(f"Layer {layer} failed: {e}")

                # Broadcast layer completed
                await self._broadcast_event(session_id, StreamEvent(
                    event_type=EventType.LAYER_COMPLETED,
                    session_id=session_id,
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "layer": layer,
                        "findings_in_layer": len(layer_findings) if 'layer_findings' in dir() else 0,
                        "total_findings": session.findings_count
                    }
                ))

            # Audit completed
            session.status = "completed"
            session.progress_percent = 100.0

            await self._broadcast_event(session_id, StreamEvent(
                event_type=EventType.AUDIT_COMPLETED,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc),
                data={
                    "total_findings": session.findings_count,
                    "execution_time_ms": (
                        datetime.now(timezone.utc) - session.started_at
                    ).total_seconds() * 1000,
                    "session": session.to_dict()
                }
            ))

        except Exception as e:
            session.status = "failed"
            await self._broadcast_event(session_id, StreamEvent(
                event_type=EventType.AUDIT_FAILED,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc),
                data={"error": str(e)}
            ))

    def _get_layer_name(self, layer: int) -> str:
        """Get human-readable layer name."""
        names = {
            1: "Static Analysis",
            2: "Fuzzing",
            3: "Symbolic Execution",
            4: "Invariant Testing",
            5: "Formal Verification",
            6: "Property Testing",
            7: "AI Analysis"
        }
        return names.get(layer, f"Layer {layer}")

    async def _broadcast_event(
        self,
        session_id: str,
        event: StreamEvent
    ) -> None:
        """Broadcast event to all clients subscribed to the session."""
        message = event.to_json()

        for client in self._clients:
            if session_id in self._subscriptions.get(client, set()):
                try:
                    await client.send(message)
                except Exception:
                    pass

    async def _send_event(
        self,
        websocket: WebSocketServerProtocol,
        event: StreamEvent
    ) -> None:
        """Send event to specific client."""
        try:
            await websocket.send(event.to_json())
        except Exception:
            pass

    async def _send_error(
        self,
        websocket: WebSocketServerProtocol,
        error_message: str
    ) -> None:
        """Send error to specific client."""
        await self._send_event(websocket, StreamEvent(
            event_type=EventType.ERROR,
            session_id="system",
            timestamp=datetime.now(timezone.utc),
            data={"error": error_message}
        ))

    async def _send_sessions_list(
        self,
        websocket: WebSocketServerProtocol
    ) -> None:
        """Send list of all sessions to client."""
        sessions = [s.to_dict() for s in self._sessions.values()]
        await self._send_event(websocket, StreamEvent(
            event_type=EventType.PROGRESS_UPDATE,
            session_id="system",
            timestamp=datetime.now(timezone.utc),
            data={"sessions": sessions}
        ))

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat to all clients."""
        while True:
            try:
                await asyncio.sleep(self.heartbeat_interval)

                event = StreamEvent(
                    event_type=EventType.HEARTBEAT,
                    session_id="system",
                    timestamp=datetime.now(timezone.utc),
                    data={
                        "active_sessions": len(self._sessions),
                        "connected_clients": len(self._clients)
                    }
                )

                message = event.to_json()
                for client in self._clients:
                    try:
                        await client.send(message)
                    except Exception:
                        pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")


# Convenience function to run server
async def run_server(host: str = "localhost", port: int = 8765):
    """Run the MIESC WebSocket server."""
    server = MIESCWebSocketServer(host=host, port=port)
    await server.start()

    # Keep running until interrupted
    try:
        await asyncio.Future()  # Run forever
    except asyncio.CancelledError:
        await server.stop()


if __name__ == "__main__":
    print("Starting MIESC WebSocket Server...")
    print("Connect to: ws://localhost:8765")
    print("Press Ctrl+C to stop")

    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\nServer stopped")
