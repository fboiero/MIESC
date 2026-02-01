#!/usr/bin/env python3
"""
MIESC v4.2.0 - Demo: WebSocket API Module
==========================================
Demonstrates the real-time WebSocket API system:
- Event types and WebSocket events
- Connection manager functionality
- Audit progress tracking
- Real-time event serialization

Author: Fernando Boiero
License: GPL-3.0
"""

import json
import sys

sys.path.insert(0, "/Users/fboiero/Documents/GitHub/MIESC")

from src.core.websocket_api import (
    WEBSOCKET_AVAILABLE,
    AuditProgressTracker,
    ConnectionManager,
    EventType,
    WebSocketEvent,
)


def print_separator(title: str):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def demo_event_types():
    """Demo all available event types."""
    print_separator("WebSocket Event Types")

    event_categories = {
        "Connection Events": [EventType.CONNECTED, EventType.DISCONNECTED],
        "Audit Lifecycle": [
            EventType.AUDIT_STARTED,
            EventType.AUDIT_PROGRESS,
            EventType.AUDIT_COMPLETED,
            EventType.AUDIT_ERROR,
        ],
        "Tool Events": [
            EventType.TOOL_STARTED,
            EventType.TOOL_PROGRESS,
            EventType.TOOL_COMPLETED,
            EventType.TOOL_ERROR,
        ],
        "Finding Events": [EventType.FINDING_DETECTED, EventType.FINDINGS_BATCH],
        "Layer Events": [EventType.LAYER_STARTED, EventType.LAYER_COMPLETED],
        "System Events": [EventType.SYSTEM_STATUS, EventType.HEARTBEAT],
    }

    for category, events in event_categories.items():
        print(f"{category}:")
        for event in events:
            print(f'  - {event.name:20} -> "{event.value}"')
        print()


def demo_websocket_event():
    """Demo WebSocket event creation and serialization."""
    print_separator("WebSocket Event Serialization")

    # Create various events
    events = [
        WebSocketEvent(
            type=EventType.AUDIT_STARTED,
            data={
                "contract": "contracts/Vault.sol",
                "tools": ["slither", "mythril", "echidna"],
                "total_layers": 7,
            },
            audit_id="audit-demo-001",
        ),
        WebSocketEvent(
            type=EventType.TOOL_COMPLETED,
            data={
                "tool": "slither",
                "findings_count": 5,
                "duration_seconds": 2.5,
                "tools_completed": 1,
                "total_tools": 3,
            },
            audit_id="audit-demo-001",
        ),
        WebSocketEvent(
            type=EventType.FINDING_DETECTED,
            data={
                "finding": {
                    "id": "MIESC-001",
                    "severity": "critical",
                    "type": "reentrancy",
                    "title": "Reentrancy Vulnerability",
                    "file": "contracts/Vault.sol",
                    "line": 42,
                },
                "total_findings": 1,
            },
            audit_id="audit-demo-001",
        ),
        WebSocketEvent(
            type=EventType.HEARTBEAT,
            data={"pong": True},
        ),
    ]

    for event in events:
        print(f"Event: {event.type.value}")
        print(f"  Audit ID: {event.audit_id or 'N/A'}")
        print(f"  Timestamp: {event.timestamp}")
        print("  JSON Preview:")
        json_data = json.loads(event.to_json())
        print(f"    {json.dumps(json_data, indent=4)[:300]}...")
        print()


def demo_connection_manager():
    """Demo connection manager functionality."""
    print_separator("Connection Manager")

    manager = ConnectionManager()

    print("Initial State:")
    print(f"  Active connections: {len(manager.active_connections)}")
    print(f"  Audit subscriptions: {len(manager.audit_subscriptions)}")

    # Simulate subscription tracking
    print("\nSubscription Tracking Demo:")
    manager.audit_subscriptions["audit-001"] = set()
    manager.audit_subscriptions["audit-002"] = set()
    manager.audit_subscriptions["audit-003"] = set()

    print(f"  Tracked audits: {list(manager.audit_subscriptions.keys())}")

    # Show available methods
    print("\nAvailable Methods:")
    methods = [
        ("connect(websocket)", "Accept new WebSocket connection"),
        ("disconnect(websocket)", "Remove WebSocket connection"),
        ("subscribe_to_audit(ws, audit_id)", "Subscribe to audit updates"),
        ("unsubscribe_from_audit(ws, audit_id)", "Unsubscribe from audit"),
        ("broadcast(event)", "Send event to all clients"),
        ("send_to_audit(audit_id, event)", "Send to audit subscribers"),
        ("send_to_connection(ws, event)", "Send to specific client"),
    ]

    for method, description in methods:
        print(f"  {method:40} - {description}")


def demo_audit_progress_tracker():
    """Demo audit progress tracker."""
    print_separator("Audit Progress Tracker")

    manager = ConnectionManager()
    tracker = AuditProgressTracker(
        manager=manager,
        audit_id="audit-demo-001",
        total_layers=7,
    )

    print("Tracker Initialized:")
    print(f"  Audit ID: {tracker.audit_id}")
    print(f"  Total Layers: {tracker.total_layers}")
    print(f"  Current Layer: {tracker.current_layer}")
    print(f"  Findings Count: {tracker.findings_count}")
    print(f"  Tools Completed: {tracker.tools_completed}")
    print(f"  Total Tools: {tracker.total_tools}")

    # Simulate progress
    print("\nSimulated Progress:")

    # Layer 1
    tracker.current_layer = 1
    tracker.total_tools = 3
    tracker.tools_completed = 1
    tracker.findings_count = 5
    print(
        f"  Layer {tracker.current_layer}: {tracker.tools_completed}/{tracker.total_tools} tools, {tracker.findings_count} findings"
    )

    # Layer 2
    tracker.current_layer = 2
    tracker.tools_completed = 2
    tracker.findings_count = 8
    print(
        f"  Layer {tracker.current_layer}: {tracker.tools_completed}/{tracker.total_tools} tools, {tracker.findings_count} findings"
    )

    # Layer 3
    tracker.current_layer = 3
    tracker.tools_completed = 3
    tracker.findings_count = 12
    print(
        f"  Layer {tracker.current_layer}: {tracker.tools_completed}/{tracker.total_tools} tools, {tracker.findings_count} findings"
    )

    # Show async methods
    print("\nAsync Event Methods:")
    async_methods = [
        "start_audit(contract_path, tools)",
        "start_layer(layer, name, tools)",
        "complete_layer(layer, findings_count, duration)",
        "start_tool(tool, layer)",
        "tool_progress(tool, progress, message)",
        "complete_tool(tool, findings, duration)",
        "tool_error(tool, error)",
        "report_finding(finding)",
        "report_findings(findings)",
        "update_progress(progress, message)",
        "complete_audit(results)",
        "error(error)",
    ]

    for method in async_methods:
        print(f"  - await tracker.{method}")


def demo_websocket_availability():
    """Demo WebSocket availability check."""
    print_separator("WebSocket Availability")

    print(f"FastAPI/uvicorn Available: {WEBSOCKET_AVAILABLE}")

    if WEBSOCKET_AVAILABLE:
        print("\nWebSocket Features:")
        print("  - Real-time audit progress updates")
        print("  - Live finding notifications")
        print("  - Tool execution streaming")
        print("  - Client subscription management")
        print("  - Health check endpoints")

        print("\nEndpoints Available:")
        print("  GET  /health       - Health check")
        print("  GET  /status       - System status")
        print("  WS   /ws           - Main WebSocket endpoint")
        print("  WS   /ws/audit/{id} - Audit-specific endpoint")
    else:
        print("\nTo enable WebSocket support, install:")
        print("  pip install fastapi uvicorn")


def demo_sample_workflow():
    """Demo a complete audit workflow event sequence."""
    print_separator("Sample Audit Workflow Events")

    audit_id = "audit-demo-001"

    workflow_events = [
        (
            "Client connects",
            WebSocketEvent(
                type=EventType.CONNECTED,
                data={"message": "Connected to MIESC Real-Time API"},
            ),
        ),
        (
            "Audit starts",
            WebSocketEvent(
                type=EventType.AUDIT_STARTED,
                data={
                    "contract": "contracts/Vault.sol",
                    "tools": ["slither", "mythril", "echidna"],
                    "total_layers": 7,
                },
                audit_id=audit_id,
            ),
        ),
        (
            "Layer 1 begins",
            WebSocketEvent(
                type=EventType.LAYER_STARTED,
                data={"layer": 1, "name": "Static Analysis", "tools": ["slither", "aderyn"]},
                audit_id=audit_id,
            ),
        ),
        (
            "Slither starts",
            WebSocketEvent(
                type=EventType.TOOL_STARTED,
                data={"tool": "slither", "layer": 1},
                audit_id=audit_id,
            ),
        ),
        (
            "Finding detected",
            WebSocketEvent(
                type=EventType.FINDING_DETECTED,
                data={
                    "finding": {
                        "severity": "critical",
                        "type": "reentrancy",
                        "title": "Reentrancy in withdraw()",
                    },
                    "total_findings": 1,
                },
                audit_id=audit_id,
            ),
        ),
        (
            "Slither completes",
            WebSocketEvent(
                type=EventType.TOOL_COMPLETED,
                data={"tool": "slither", "findings_count": 3, "duration_seconds": 2.5},
                audit_id=audit_id,
            ),
        ),
        (
            "Layer 1 completes",
            WebSocketEvent(
                type=EventType.LAYER_COMPLETED,
                data={"layer": 1, "findings_count": 5, "duration_seconds": 8.2},
                audit_id=audit_id,
            ),
        ),
        (
            "Progress update",
            WebSocketEvent(
                type=EventType.AUDIT_PROGRESS,
                data={
                    "progress": 42.5,
                    "message": "Layer 3/7 - Running Mythril",
                    "current_layer": 3,
                    "findings_count": 8,
                },
                audit_id=audit_id,
            ),
        ),
        (
            "Audit completes",
            WebSocketEvent(
                type=EventType.AUDIT_COMPLETED,
                data={
                    "total_findings": 12,
                    "duration_seconds": 245.8,
                    "summary": {
                        "critical": 2,
                        "high": 3,
                        "medium": 4,
                        "low": 3,
                    },
                    "layers_analyzed": 7,
                },
                audit_id=audit_id,
            ),
        ),
    ]

    for step, event in workflow_events:
        print(f"[{event.type.value}] {step}")
        json_preview = event.to_json()[:100] + "..."
        print(f"    {json_preview}")
        print()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("       MIESC v4.2.0 'Fortress' - WebSocket API Demo")
    print("       Real-Time Dashboard Communication")
    print("=" * 60)

    demo_event_types()
    demo_websocket_event()
    demo_connection_manager()
    demo_audit_progress_tracker()
    demo_websocket_availability()
    demo_sample_workflow()

    print("\n" + "=" * 60)
    print("  WebSocket API Demo Complete!")
    print("=" * 60 + "\n")
