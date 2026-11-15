"""Tests for the remote MCP transport auth boundary (M5).

The pure-ASGI bearer guard, token resolution, app wiring and fail-closed serve
guards are unit-tested here with a tiny in-process ASGI harness (no MCP SDK, no
uvicorn). The live Streamable HTTP server is integration-tested at the bottom
behind ``importorskip("mcp")``; the uvicorn bind itself is not unit-tested.
"""

import asyncio

import pytest

from miesc.mcp_remote import (
    DEFAULT_BIND,
    DEFAULT_PORT,
    MIN_TOKEN_LENGTH,
    BearerAuthMiddleware,
    RemoteAuthError,
    _load_streamable_http_app,
    build_remote_app,
    resolve_bearer_token,
    serve,
)

TOKEN = "unit-test-token-abcdef123456"  # >= 16 chars


# ---------------------------------------------------------------------------
# In-process ASGI harness (no SDK, no uvicorn)
# ---------------------------------------------------------------------------


class RecordingApp:
    """Inner ASGI app that records the scope types it is invoked with."""

    def __init__(self) -> None:
        self.calls = []

    async def __call__(self, scope, receive, send) -> None:
        stype = scope.get("type")
        self.calls.append(stype)
        if stype == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        elif stype == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return


def _http_scope(auth=None):
    headers = []
    if auth is not None:
        headers.append((b"authorization", auth if isinstance(auth, bytes) else auth.encode()))
    return {"type": "http", "method": "POST", "path": "/mcp", "headers": headers}


def _drive(app, scope, incoming=None):
    """Run one ASGI invocation, returning the list of sent messages."""
    incoming = list(incoming or [])
    sent = []

    async def receive():
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent


def _status(sent):
    for m in sent:
        if m["type"] == "http.response.start":
            return m["status"]
    return None


def _has_header(sent, name: bytes):
    for m in sent:
        if m["type"] == "http.response.start":
            return any(k.lower() == name.lower() for k, _ in m["headers"])
    return False


# ---------------------------------------------------------------------------
# Token resolution — fail-closed
# ---------------------------------------------------------------------------


class TestResolveToken:
    def test_missing_token_raises(self, monkeypatch):
        monkeypatch.delenv("MIESC_MCP_BEARER_TOKEN", raising=False)
        with pytest.raises(RemoteAuthError):
            resolve_bearer_token()

    def test_short_token_raises(self):
        with pytest.raises(RemoteAuthError):
            resolve_bearer_token("short")

    def test_explicit_valid_token_returned(self):
        assert resolve_bearer_token(TOKEN) == TOKEN

    def test_env_token_is_read_and_stripped(self, monkeypatch):
        monkeypatch.setenv("MIESC_MCP_BEARER_TOKEN", f"  {TOKEN}  ")
        assert resolve_bearer_token() == TOKEN

    def test_min_length_is_enforced(self):
        assert MIN_TOKEN_LENGTH >= 16


# ---------------------------------------------------------------------------
# Bearer auth middleware
# ---------------------------------------------------------------------------


class TestBearerAuthMiddleware:
    def test_no_header_is_401_and_inner_not_called(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(mw, _http_scope())
        assert _status(sent) == 401
        assert inner.calls == []
        assert _has_header(sent, b"www-authenticate")

    def test_wrong_token_is_401_and_inner_not_called(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(mw, _http_scope(f"Bearer {TOKEN}x"))
        assert _status(sent) == 401
        assert inner.calls == []

    def test_correct_token_passes_through(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(mw, _http_scope(f"Bearer {TOKEN}"))
        assert _status(sent) == 200
        assert inner.calls == ["http"]

    def test_scheme_is_case_insensitive(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        for scheme in ("bearer", "BEARER", "BeArEr"):
            inner.calls.clear()
            sent = _drive(mw, _http_scope(f"{scheme} {TOKEN}"))
            assert _status(sent) == 200
            assert inner.calls == ["http"]

    def test_malformed_header_is_401(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        for value in ("Basic abc", TOKEN, "Bearer", "Bearer  "):
            inner.calls.clear()
            sent = _drive(mw, _http_scope(value))
            assert _status(sent) == 401, value
            assert inner.calls == []

    def test_non_ascii_header_does_not_500(self):
        # hmac.compare_digest on bytes is safe; a non-ASCII token must 401, not crash.
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(mw, _http_scope(b"Bearer \xff\xfe\xfdnonascii"))
        assert _status(sent) == 401
        assert inner.calls == []

    def test_lifespan_passes_through_untouched(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(
            mw,
            {"type": "lifespan"},
            incoming=[{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}],
        )
        assert inner.calls == ["lifespan"]
        types = [m["type"] for m in sent]
        assert "lifespan.startup.complete" in types
        assert "lifespan.shutdown.complete" in types

    def test_websocket_is_rejected_without_reaching_inner(self):
        inner = RecordingApp()
        mw = BearerAuthMiddleware(inner, TOKEN)
        sent = _drive(
            mw, {"type": "websocket", "headers": []}, incoming=[{"type": "websocket.connect"}]
        )
        assert inner.calls == []
        assert any(m["type"] == "websocket.close" for m in sent)

    def test_empty_token_refused_at_construction(self):
        with pytest.raises(RemoteAuthError):
            BearerAuthMiddleware(RecordingApp(), "")


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------


class TestBuildRemoteApp:
    def test_wraps_injected_inner_and_enforces_auth(self):
        inner = RecordingApp()
        app = build_remote_app(TOKEN, inner_app=inner)
        assert isinstance(app, BearerAuthMiddleware)
        # Unauthed request is blocked before the inner app.
        sent = _drive(app, _http_scope())
        assert _status(sent) == 401
        assert inner.calls == []


# ---------------------------------------------------------------------------
# Serve guards — fail-closed (raise before any bind)
# ---------------------------------------------------------------------------


class TestServeGuards:
    def test_serve_without_token_refuses(self, monkeypatch):
        monkeypatch.delenv("MIESC_MCP_BEARER_TOKEN", raising=False)
        with pytest.raises(RemoteAuthError):
            serve(host="127.0.0.1")

    def test_serve_non_loopback_without_optin_refuses(self, monkeypatch):
        monkeypatch.setenv("MIESC_MCP_BEARER_TOKEN", TOKEN)
        with pytest.raises(RemoteAuthError) as exc:
            serve(host="0.0.0.0", allow_external_bind=False)
        assert "loopback" in str(exc.value).lower()


class TestSecureDefaults:
    def test_default_bind_is_loopback(self):
        assert DEFAULT_BIND == "127.0.0.1"

    def test_default_port_is_set(self):
        assert isinstance(DEFAULT_PORT, int) and DEFAULT_PORT > 0


class TestSdkPresenceGuard:
    def test_load_app_without_sdk_raises(self):
        from miesc.mcp_server import mcp as instance

        if callable(getattr(instance, "streamable_http_app", None)):
            pytest.skip("MCP SDK present; the streamable app builds (integration-tested below)")
        with pytest.raises(RemoteAuthError):
            _load_streamable_http_app()


# ---------------------------------------------------------------------------
# Integration — the real Streamable HTTP app behind the guard
# ---------------------------------------------------------------------------


class TestRemoteHTTPIntegration:
    """Drives the SDK's real streamable_http_app wrapped by our guard.

    Uses Starlette's TestClient as a context manager so the session-manager
    lifespan runs; the loopback base_url satisfies the SDK's DNS-rebinding guard.
    """

    @pytest.fixture(scope="class")
    def client(self):
        pytest.importorskip("mcp")
        pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.testclient import TestClient

        try:
            app = build_remote_app(TOKEN)  # wraps the real streamable_http_app()
        except RemoteAuthError as exc:
            # `mcp` imports but is too old to provide streamable_http_app() (needs the
            # Streamable HTTP SDK installed via `miesc[mcp]`). importorskip("mcp")
            # cannot see that, so skip the live integration here rather than error.
            pytest.skip(f"installed MCP SDK lacks streamable_http_app(): {exc}")
        # test_mcp_server.py injects a MagicMock 'mcp' into sys.modules only when the
        # real SDK is absent; if that mock still wins (import order), the wrapped app
        # is a Mock, not Starlette — skip rather than report a false pass/fail.
        if not isinstance(app.app, Starlette):
            pytest.skip(
                "real MCP SDK not exclusively present (mcp is mocked for unit tests); "
                "run `pytest tests/test_mcp_remote.py` in isolation to exercise this"
            )
        # One entered TestClient shared across the class: the SDK's
        # StreamableHTTPSessionManager.run() may be started only once per instance,
        # so a fresh client per test would raise "can only be called once".
        with TestClient(app, base_url="http://127.0.0.1:8766") as entered:
            yield entered

    @property
    def _init_payload(self):
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }

    @property
    def _headers(self):
        return {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        }

    def test_no_auth_is_401(self, client):
        r = client.post("/mcp", json=self._init_payload, headers=self._headers)
        assert r.status_code == 401

    def test_valid_bearer_reaches_the_sdk_and_initializes(self, client):
        r = client.post(
            "/mcp",
            json=self._init_payload,
            headers={**self._headers, "Authorization": f"Bearer {TOKEN}"},
        )
        assert r.status_code == 200
        assert "protocolVersion" in r.text

    def test_wrong_bearer_is_401(self, client):
        r = client.post(
            "/mcp",
            json=self._init_payload,
            headers={**self._headers, "Authorization": "Bearer nope-wrong-token-1234"},
        )
        assert r.status_code == 401
