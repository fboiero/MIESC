"""Tests for websocket_api pure helpers: token validation, ConnectionManager
bookkeeping (incl. async broadcast cleanup), event serialization, factories."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import miesc.core.websocket_api as ws
from miesc.core.websocket_api import (
    ConnectionManager,
    EventType,
    WebSocketEvent,
    _validate_websocket_token,
    create_progress_tracker,
    get_connection_manager,
)


class TestTokenValidation:
    def test_auth_not_required_allows_any(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", False)
        assert _validate_websocket_token(None) is True

    def test_required_without_configured_token_denies(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", True)
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_TOKEN", "")
        assert _validate_websocket_token("anything") is False

    def test_required_missing_token_denies(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", True)
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_TOKEN", "secret")
        assert _validate_websocket_token(None) is False

    def test_required_wrong_token_denies(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", True)
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_TOKEN", "secret")
        assert _validate_websocket_token("wrong") is False

    def test_required_correct_token_allows(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", True)
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_TOKEN", "secret")
        assert _validate_websocket_token("secret") is True


class TestConnectionManager:
    def test_subscribe_and_unsubscribe(self):
        m = ConnectionManager()
        sock = MagicMock()
        m.subscribe_to_audit(sock, "a1")
        assert sock in m.audit_subscriptions["a1"]
        m.unsubscribe_from_audit(sock, "a1")
        assert sock not in m.audit_subscriptions["a1"]

    def test_disconnect_cleans_subscriptions(self):
        m = ConnectionManager()
        sock = MagicMock()
        m.active_connections.add(sock)
        m.subscribe_to_audit(sock, "a1")
        m.disconnect(sock)
        assert sock not in m.active_connections
        assert "a1" not in m.audit_subscriptions  # emptied subscription dropped

    def test_broadcast_drops_failed_connection(self):
        m = ConnectionManager()
        good = MagicMock()
        good.send_text = AsyncMock()
        bad = MagicMock()
        bad.send_text = AsyncMock(side_effect=RuntimeError("closed"))
        m.active_connections.update({good, bad})
        event = WebSocketEvent(type=EventType.AUDIT_STARTED, data={})
        asyncio.run(m.broadcast(event))
        assert bad not in m.active_connections  # failed connection cleaned up
        assert good in m.active_connections

    def test_send_to_audit_unknown_is_noop(self):
        m = ConnectionManager()
        event = WebSocketEvent(type=EventType.AUDIT_STARTED, data={})
        asyncio.run(m.send_to_audit("missing", event))  # no error


class TestEventAndFactories:
    def test_event_to_json_roundtrip(self):
        event = WebSocketEvent(type=EventType.AUDIT_STARTED, data={"k": "v"})
        out = event.to_json()
        assert isinstance(out, str)
        assert "audit" in out.lower()

    def test_factories_when_unavailable(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AVAILABLE", False)
        monkeypatch.setattr(ws, "_manager", None)
        assert get_connection_manager() is None
        assert create_progress_tracker("a1") is None


class TestFastAPIRoutes:
    """Exercise the FastAPI app routes via TestClient (requires fastapi)."""

    def _client(self):
        import pytest

        if not ws.WEBSOCKET_AVAILABLE:
            pytest.skip("fastapi not installed")
        from fastapi.testclient import TestClient

        app = ws.create_websocket_app()
        return TestClient(app)

    def test_health_endpoint(self):
        resp = self._client().get("/health")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_status_endpoint(self):
        resp = self._client().get("/status")
        assert resp.status_code == 200

    def test_ws_welcome_and_ping(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", False)
        client = self._client()
        with client.websocket_connect("/ws") as conn:
            welcome = conn.receive_json()
            assert welcome["type"] == ws.EventType.CONNECTED.value
            conn.send_json({"action": "ping"})
            pong = conn.receive_json()
            assert pong["type"] == ws.EventType.HEARTBEAT.value

    def test_ws_subscribe_and_unsubscribe(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", False)
        client = self._client()
        with client.websocket_connect("/ws") as conn:
            conn.receive_json()  # welcome
            conn.send_json({"action": "subscribe", "audit_id": "a1"})
            msg = conn.receive_json()
            assert msg["data"].get("subscribed_to") == "a1"
            # unsubscribe path (no response expected) — then ping to confirm liveness
            conn.send_json({"action": "unsubscribe", "audit_id": "a1"})
            conn.send_json({"action": "ping"})
            assert conn.receive_json()["type"] == ws.EventType.HEARTBEAT.value

    def test_ws_audit_endpoint(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", False)
        client = self._client()
        with client.websocket_connect("/ws/audit/job42") as conn:
            welcome = conn.receive_json()
            assert welcome["type"] == ws.EventType.CONNECTED.value
            assert welcome["data"].get("audit_id") == "job42"
            conn.send_json({"action": "ping"})
            pong = conn.receive_json()
            assert pong["type"] == ws.EventType.HEARTBEAT.value
            assert pong["audit_id"] == "job42"

    def test_ws_unauthorized_rejected(self, monkeypatch):
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_REQUIRED", True)
        monkeypatch.setattr(ws, "WEBSOCKET_AUTH_TOKEN", "secret")
        client = self._client()
        import pytest

        with pytest.raises(Exception):
            with client.websocket_connect("/ws") as conn:
                conn.receive_json()  # closed before welcome -> raises
