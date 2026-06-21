"""Tests for mcp_core websocket server pure helpers (serializers + layer names)."""

from __future__ import annotations

import json
from datetime import datetime

from src.mcp_core.websocket_server import (
    AuditSession,
    EventType,
    MIESCWebSocketServer,
    StreamEvent,
)


def test_audit_session_to_dict():
    s = AuditSession(
        session_id="s1",
        contract_path="C.sol",
        layers=[1, 2],
        started_at=datetime(2026, 6, 21, 12, 0),
    )
    d = s.to_dict()
    assert d["session_id"] == "s1"
    assert d["contract_path"] == "C.sol"


def test_stream_event_to_json():
    ev = StreamEvent(
        event_type=EventType.AUDIT_STARTED,
        session_id="s1",
        timestamp=datetime(2026, 6, 21, 12, 0),
        data={"k": "v"},
    )
    out = ev.to_json()
    parsed = json.loads(out)
    assert parsed["session_id"] == "s1"
    assert parsed["data"] == {"k": "v"}


def test_get_layer_name():
    s = MIESCWebSocketServer()
    assert s._get_layer_name(1) == "Static Analysis"
    assert "99" in s._get_layer_name(99)  # unknown layer falls back to "Layer N"
