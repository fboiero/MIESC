"""
Tests for src.core.websocket_api — WebSocket real-time audit events.
Coverage target: 69% → 80%+.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

fastapi = pytest.importorskip("fastapi")

from src.core.websocket_api import (
    AuditProgressTracker,
    ConnectionManager,
    EventType,
    WebSocketEvent,
)


class TestWebSocketEvent:
    def test_create_event(self):
        event = WebSocketEvent(
            type=EventType.AUDIT_PROGRESS,
            data={"layer": 1},
            audit_id="test-123",
        )
        assert event.type == EventType.AUDIT_PROGRESS
        assert event.audit_id == "test-123"

    def test_to_json(self):
        event = WebSocketEvent(type=EventType.FINDING_DETECTED, data={"x": 1})
        j = event.to_json()
        assert isinstance(j, str)
        assert "finding_detected" in j

    def test_event_has_timestamp(self):
        event = WebSocketEvent(type=EventType.HEARTBEAT, data={})
        assert event.timestamp


class TestConnectionManager:
    @pytest.fixture
    def manager(self):
        return ConnectionManager()

    def test_initial_empty(self, manager):
        assert len(manager.active_connections) == 0

    @pytest.mark.asyncio
    async def test_connect(self, manager):
        ws = AsyncMock()
        await manager.connect(ws)
        assert ws in manager.active_connections

    def test_disconnect(self, manager):
        ws = MagicMock()
        manager.active_connections.add(ws)
        manager.disconnect(ws)
        assert ws not in manager.active_connections

    def test_disconnect_missing_ok(self, manager):
        manager.disconnect(MagicMock())

    def test_subscribe(self, manager):
        ws = MagicMock()
        manager.subscribe_to_audit(ws, "a1")
        assert ws in manager.audit_subscriptions["a1"]

    def test_unsubscribe(self, manager):
        ws = MagicMock()
        manager.audit_subscriptions["a1"] = {ws}
        manager.unsubscribe_from_audit(ws, "a1")
        # After last subscriber removed, key should be cleaned up
        assert ws not in manager.audit_subscriptions.get("a1", set())

    @pytest.mark.asyncio
    async def test_broadcast(self, manager):
        ws1, ws2 = AsyncMock(), AsyncMock()
        manager.active_connections = {ws1, ws2}
        await manager.broadcast(WebSocketEvent(type=EventType.HEARTBEAT, data={}))
        assert ws1.send_text.called or ws2.send_text.called

    @pytest.mark.asyncio
    async def test_broadcast_handles_error(self, manager):
        ws = AsyncMock()
        ws.send_text.side_effect = Exception("gone")
        manager.active_connections = {ws}
        await manager.broadcast(WebSocketEvent(type=EventType.HEARTBEAT, data={}))

    @pytest.mark.asyncio
    async def test_send_to_audit(self, manager):
        ws = AsyncMock()
        manager.audit_subscriptions["a1"] = {ws}
        await manager.send_to_audit(
            "a1", WebSocketEvent(type=EventType.AUDIT_PROGRESS, data={}, audit_id="a1")
        )
        assert ws.send_text.called

    @pytest.mark.asyncio
    async def test_send_to_audit_no_subs(self, manager):
        await manager.send_to_audit("none", WebSocketEvent(type=EventType.HEARTBEAT, data={}))


class TestAuditProgressTracker:
    @pytest.fixture
    def tracker(self):
        return AuditProgressTracker(manager=ConnectionManager(), audit_id="t1", total_layers=9)

    def test_init(self, tracker):
        assert tracker.audit_id == "t1"
        assert tracker.current_layer == 0

    @pytest.mark.asyncio
    async def test_start_layer(self, tracker):
        with patch.object(tracker.manager, "send_to_audit", new_callable=AsyncMock):
            await tracker.start_layer(1, "Static", ["slither"])
            assert tracker.current_layer == 1

    @pytest.mark.asyncio
    async def test_complete_layer(self, tracker):
        with patch.object(tracker.manager, "send_to_audit", new_callable=AsyncMock):
            await tracker.complete_layer(1, findings_count=3, duration=1.0)

    @pytest.mark.asyncio
    async def test_start_tool(self, tracker):
        with patch.object(tracker.manager, "send_to_audit", new_callable=AsyncMock):
            await tracker.start_tool("slither", layer=1)
            assert tracker.current_tool == "slither"

    @pytest.mark.asyncio
    async def test_complete_tool(self, tracker):
        with patch.object(tracker.manager, "send_to_audit", new_callable=AsyncMock):
            await tracker.complete_tool("slither", [{"type": "x"}], 0.5)
            assert tracker.tools_completed == 1
            assert tracker.findings_count == 1

    @pytest.mark.asyncio
    async def test_complete_audit(self, tracker):
        from datetime import datetime, timezone

        # Prime start_time with timezone-aware datetime (matches internal timezone.utc)
        tracker.start_time = datetime.now(timezone.utc)
        with patch.object(tracker.manager, "send_to_audit", new_callable=AsyncMock):
            await tracker.complete_audit(results={"findings": [], "total": 0})


# --------------------------------------------------------------------------- #
# Server lifecycle + unavailable-deps branches.
# --------------------------------------------------------------------------- #
import asyncio as _aio  # noqa: E402

import src.core.websocket_api as wa  # noqa: E402


def test_create_app_returns_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(wa, "WEBSOCKET_AVAILABLE", False)
    assert wa.create_websocket_app() is None


def test_server_run_without_app_returns():
    server = wa.WebSocketServer()
    server.app = None  # force the unavailable branch
    server.run()  # returns without raising


def test_server_run_invokes_uvicorn(monkeypatch):
    called = {}
    monkeypatch.setattr(wa, "uvicorn", type("U", (), {
        "run": staticmethod(lambda app, host, port: called.update(host=host, port=port))})())
    server = wa.WebSocketServer(host="127.0.0.1", port=9000)
    server.app = object()  # truthy app
    server.run()
    assert called == {"host": "127.0.0.1", "port": 9000}


def test_server_start_and_stop(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    fake_server = MagicMock()
    fake_server.serve = AsyncMock()
    fake_uvicorn = type("U", (), {
        "Config": staticmethod(lambda *a, **k: MagicMock()),
        "Server": staticmethod(lambda cfg: fake_server)})()
    monkeypatch.setattr(wa, "uvicorn", fake_uvicorn)

    async def _run():
        server = wa.WebSocketServer()
        server.app = object()
        await server.start()
        fake_server.serve.assert_awaited()
        await server.stop()  # sets should_exit
        assert server._server.should_exit is True

    _aio.run(_run())


def test_server_start_noop_without_app():
    async def _run():
        server = wa.WebSocketServer()
        server.app = None
        await server.start()  # returns immediately, no error

    _aio.run(_run())


def test_get_connection_manager():
    mgr = wa.get_connection_manager()
    # returns a ConnectionManager (deps available) or None — must not raise
    assert mgr is None or isinstance(mgr, wa.ConnectionManager)


def test_broadcast_disconnects_failed_connection():
    from unittest.mock import AsyncMock
    async def _run():
        m = wa.ConnectionManager()
        good = AsyncMock()
        bad = AsyncMock()
        bad.send_text.side_effect = Exception("gone")
        m.active_connections.update({good, bad})
        evt = wa.WebSocketEvent(type=list(wa.EventType)[0], data={"x": 1})
        await m.broadcast(evt)
        assert bad not in m.active_connections  # cleaned up
        good.send_text.assert_awaited()
    _aio.run(_run())


def test_send_to_audit_disconnects_failed_connection():
    from unittest.mock import AsyncMock
    async def _run():
        m = wa.ConnectionManager()
        bad = AsyncMock()
        bad.send_text.side_effect = Exception("gone")
        m.subscribe_to_audit(bad, "audit-1")
        evt = wa.WebSocketEvent(type=list(wa.EventType)[0], data={}, audit_id="audit-1")
        await m.send_to_audit("audit-1", evt)
        assert bad not in m.active_connections
        # missing-audit branch: no-op, no raise
        await m.send_to_audit("nope", evt)
    _aio.run(_run())
