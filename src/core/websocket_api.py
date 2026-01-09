"""
MIESC WebSocket API for Real-Time Dashboard

Provides real-time updates during security audits using WebSocket connections.
Supports progress tracking, live findings, and tool status updates.

Author: Fernando Boiero
License: GPL-3.0
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Try to import WebSocket dependencies
try:
    import uvicorn
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware

    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    FastAPI = None  # type: ignore
    WebSocket = None  # type: ignore
    WebSocketDisconnect = None  # type: ignore
    CORSMiddleware = None  # type: ignore
    uvicorn = None  # type: ignore
    logger.warning("FastAPI/uvicorn not installed. WebSocket API unavailable.")


class EventType(str, Enum):
    """Types of WebSocket events."""

    # Connection events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"

    # Audit lifecycle
    AUDIT_STARTED = "audit_started"
    AUDIT_PROGRESS = "audit_progress"
    AUDIT_COMPLETED = "audit_completed"
    AUDIT_ERROR = "audit_error"

    # Tool events
    TOOL_STARTED = "tool_started"
    TOOL_PROGRESS = "tool_progress"
    TOOL_COMPLETED = "tool_completed"
    TOOL_ERROR = "tool_error"

    # Finding events
    FINDING_DETECTED = "finding_detected"
    FINDINGS_BATCH = "findings_batch"

    # Layer events
    LAYER_STARTED = "layer_started"
    LAYER_COMPLETED = "layer_completed"

    # System events
    SYSTEM_STATUS = "system_status"
    HEARTBEAT = "heartbeat"


@dataclass
class WebSocketEvent:
    """Represents a WebSocket event."""

    type: EventType
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_id: Optional[str] = None

    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(
            {
                "type": self.type.value,
                "data": self.data,
                "timestamp": self.timestamp,
                "audit_id": self.audit_id,
            }
        )


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.audit_subscriptions: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        # Remove from all audit subscriptions
        for audit_id in list(self.audit_subscriptions.keys()):
            self.audit_subscriptions[audit_id].discard(websocket)
            if not self.audit_subscriptions[audit_id]:
                del self.audit_subscriptions[audit_id]
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    def subscribe_to_audit(self, websocket: WebSocket, audit_id: str) -> None:
        """Subscribe a connection to audit updates."""
        if audit_id not in self.audit_subscriptions:
            self.audit_subscriptions[audit_id] = set()
        self.audit_subscriptions[audit_id].add(websocket)

    def unsubscribe_from_audit(self, websocket: WebSocket, audit_id: str) -> None:
        """Unsubscribe from audit updates."""
        if audit_id in self.audit_subscriptions:
            self.audit_subscriptions[audit_id].discard(websocket)

    async def broadcast(self, event: WebSocketEvent) -> None:
        """Broadcast event to all connected clients."""
        message = event.to_json()
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)

        # Clean up disconnected
        for conn in disconnected:
            self.disconnect(conn)

    async def send_to_audit(self, audit_id: str, event: WebSocketEvent) -> None:
        """Send event to clients subscribed to specific audit."""
        if audit_id not in self.audit_subscriptions:
            return

        message = event.to_json()
        disconnected = set()

        for connection in self.audit_subscriptions[audit_id]:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)

        # Clean up disconnected
        for conn in disconnected:
            self.disconnect(conn)

    async def send_to_connection(self, websocket: WebSocket, event: WebSocketEvent) -> None:
        """Send event to a specific connection."""
        try:
            await websocket.send_text(event.to_json())
        except Exception:
            self.disconnect(websocket)


class AuditProgressTracker:
    """Tracks audit progress and emits events."""

    def __init__(self, manager: ConnectionManager, audit_id: str, total_layers: int = 7):
        self.manager = manager
        self.audit_id = audit_id
        self.total_layers = total_layers
        self.current_layer = 0
        self.current_tool = None
        self.findings_count = 0
        self.tools_completed = 0
        self.total_tools = 0
        self.start_time = datetime.now(timezone.utc)

    async def start_audit(self, contract_path: str, tools: List[str]) -> None:
        """Signal audit start."""
        self.total_tools = len(tools)
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.AUDIT_STARTED,
                data={"contract": contract_path, "tools": tools, "total_layers": self.total_layers},
                audit_id=self.audit_id,
            ),
        )

    async def start_layer(self, layer: int, layer_name: str, tools: List[str]) -> None:
        """Signal layer start."""
        self.current_layer = layer
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.LAYER_STARTED,
                data={"layer": layer, "name": layer_name, "tools": tools},
                audit_id=self.audit_id,
            ),
        )

    async def complete_layer(self, layer: int, findings_count: int, duration: float) -> None:
        """Signal layer completion."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.LAYER_COMPLETED,
                data={
                    "layer": layer,
                    "findings_count": findings_count,
                    "duration_seconds": duration,
                },
                audit_id=self.audit_id,
            ),
        )

    async def start_tool(self, tool: str, layer: int) -> None:
        """Signal tool execution start."""
        self.current_tool = tool
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.TOOL_STARTED,
                data={"tool": tool, "layer": layer},
                audit_id=self.audit_id,
            ),
        )

    async def tool_progress(self, tool: str, progress: float, message: str = "") -> None:
        """Report tool progress (0-100)."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.TOOL_PROGRESS,
                data={"tool": tool, "progress": progress, "message": message},
                audit_id=self.audit_id,
            ),
        )

    async def complete_tool(self, tool: str, findings: List[Dict], duration: float) -> None:
        """Signal tool completion."""
        self.tools_completed += 1
        self.findings_count += len(findings)

        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.TOOL_COMPLETED,
                data={
                    "tool": tool,
                    "findings_count": len(findings),
                    "duration_seconds": duration,
                    "tools_completed": self.tools_completed,
                    "total_tools": self.total_tools,
                },
                audit_id=self.audit_id,
            ),
        )

        # Send findings batch
        if findings:
            await self.report_findings(findings)

    async def tool_error(self, tool: str, error: str) -> None:
        """Report tool error."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.TOOL_ERROR,
                data={"tool": tool, "error": error},
                audit_id=self.audit_id,
            ),
        )

    async def report_finding(self, finding: Dict) -> None:
        """Report a single finding."""
        self.findings_count += 1
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.FINDING_DETECTED,
                data={"finding": finding, "total_findings": self.findings_count},
                audit_id=self.audit_id,
            ),
        )

    async def report_findings(self, findings: List[Dict]) -> None:
        """Report a batch of findings."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.FINDINGS_BATCH,
                data={
                    "findings": findings,
                    "count": len(findings),
                    "total_findings": self.findings_count,
                },
                audit_id=self.audit_id,
            ),
        )

    async def update_progress(self, progress: float, message: str = "") -> None:
        """Update overall audit progress (0-100)."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.AUDIT_PROGRESS,
                data={
                    "progress": progress,
                    "message": message,
                    "current_layer": self.current_layer,
                    "current_tool": self.current_tool,
                    "findings_count": self.findings_count,
                    "tools_completed": self.tools_completed,
                    "total_tools": self.total_tools,
                },
                audit_id=self.audit_id,
            ),
        )

    async def complete_audit(self, results: Dict) -> None:
        """Signal audit completion."""
        duration = (datetime.utcnow() - self.start_time).total_seconds()

        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.AUDIT_COMPLETED,
                data={
                    "total_findings": self.findings_count,
                    "duration_seconds": duration,
                    "summary": results.get("summary", {}),
                    "layers_analyzed": self.current_layer,
                },
                audit_id=self.audit_id,
            ),
        )

    async def error(self, error: str) -> None:
        """Signal audit error."""
        await self.manager.send_to_audit(
            self.audit_id,
            WebSocketEvent(
                type=EventType.AUDIT_ERROR,
                data={
                    "error": error,
                    "progress_at_error": {
                        "layer": self.current_layer,
                        "tool": self.current_tool,
                        "findings_count": self.findings_count,
                    },
                },
                audit_id=self.audit_id,
            ),
        )


def create_websocket_app() -> Optional["FastAPI"]:
    """Create FastAPI application with WebSocket support."""
    if not WEBSOCKET_AVAILABLE:
        logger.error("Cannot create WebSocket app: dependencies not installed")
        return None

    app = FastAPI(
        title="MIESC Real-Time API",
        description="WebSocket API for real-time audit updates",
        version="4.1.0",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Connection manager
    manager = ConnectionManager()
    app.state.manager = manager

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """Main WebSocket endpoint."""
        await manager.connect(websocket)

        # Send welcome event
        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                type=EventType.CONNECTED, data={"message": "Connected to MIESC Real-Time API"}
            ),
        )

        try:
            while True:
                # Receive messages
                data = await websocket.receive_text()
                message = json.loads(data)

                # Handle subscription requests
                if message.get("action") == "subscribe":
                    audit_id = message.get("audit_id")
                    if audit_id:
                        manager.subscribe_to_audit(websocket, audit_id)
                        await manager.send_to_connection(
                            websocket,
                            WebSocketEvent(
                                type=EventType.SYSTEM_STATUS, data={"subscribed_to": audit_id}
                            ),
                        )

                elif message.get("action") == "unsubscribe":
                    audit_id = message.get("audit_id")
                    if audit_id:
                        manager.unsubscribe_from_audit(websocket, audit_id)

                elif message.get("action") == "ping":
                    await manager.send_to_connection(
                        websocket, WebSocketEvent(type=EventType.HEARTBEAT, data={"pong": True})
                    )

        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            manager.disconnect(websocket)

    @app.websocket("/ws/audit/{audit_id}")
    async def audit_websocket(websocket: WebSocket, audit_id: str):
        """WebSocket endpoint for specific audit."""
        await manager.connect(websocket)
        manager.subscribe_to_audit(websocket, audit_id)

        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                type=EventType.CONNECTED,
                data={"message": f"Subscribed to audit {audit_id}", "audit_id": audit_id},
            ),
        )

        try:
            while True:
                data = await websocket.receive_text()
                message = json.loads(data)

                if message.get("action") == "ping":
                    await manager.send_to_connection(
                        websocket,
                        WebSocketEvent(
                            type=EventType.HEARTBEAT, data={"pong": True}, audit_id=audit_id
                        ),
                    )

        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"Audit WebSocket error: {e}")
            manager.disconnect(websocket)

    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "connections": len(manager.active_connections),
            "active_audits": len(manager.audit_subscriptions),
        }

    @app.get("/status")
    async def system_status():
        """System status endpoint."""
        return {
            "websocket_available": True,
            "connections": len(manager.active_connections),
            "subscribed_audits": list(manager.audit_subscriptions.keys()),
            "version": "4.1.0",
        }

    return app


class WebSocketServer:
    """WebSocket server manager."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.app = create_websocket_app()
        self._server = None

    def run(self) -> None:
        """Run the WebSocket server (blocking)."""
        if not self.app:
            logger.error("Cannot run server: WebSocket not available")
            return

        uvicorn.run(self.app, host=self.host, port=self.port)

    async def start(self) -> None:
        """Start the server asynchronously."""
        if not self.app or not WEBSOCKET_AVAILABLE:
            return

        config = uvicorn.Config(self.app, host=self.host, port=self.port)
        self._server = uvicorn.Server(config)
        await self._server.serve()

    async def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.should_exit = True


# Global instances for easy access
_manager: Optional[ConnectionManager] = None
_app: Optional["FastAPI"] = None


def get_connection_manager() -> Optional[ConnectionManager]:
    """Get the global connection manager."""
    global _manager, _app
    if _manager is None and WEBSOCKET_AVAILABLE:
        _app = create_websocket_app()
        if _app:
            _manager = _app.state.manager
    return _manager


def create_progress_tracker(audit_id: str) -> Optional[AuditProgressTracker]:
    """Create a progress tracker for an audit."""
    manager = get_connection_manager()
    if manager:
        return AuditProgressTracker(manager, audit_id)
    return None


# Example usage
if __name__ == "__main__":
    if WEBSOCKET_AVAILABLE:
        server = WebSocketServer(port=8765)
        print("Starting MIESC WebSocket server on ws://0.0.0.0:8765")
        server.run()
    else:
        print("WebSocket dependencies not installed. Run: pip install fastapi uvicorn")
