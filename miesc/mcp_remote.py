"""
MIESC Remote MCP Transport (M5) — the MCP server's own Streamable HTTP transport
behind a bearer token, for remote agents.

Design principles (non-negotiable):

- **stdio stays the default.** Claude Desktop and local use keep the zero-auth
  stdio server (``miesc-mcp``). This module is a separate, opt-in surface.
- **Fail-closed.** The transport refuses to serve without a bearer token (from
  the environment only), and refuses a non-loopback bind unless the operator
  explicitly opts in — the bearer travels in cleartext over plain HTTP, so TLS
  must be terminated in front.
- **The bearer is only half a boundary.** The MCP tools do raw filesystem reads
  (``contract_path``) and writes (``output_path``). Remote mode therefore also
  sets a **workspace root** (``miesc.mcp_server.set_workspace_root``) so an
  authenticated remote caller cannot reach arbitrary host files. Auth without
  confinement would be a façade.

The auth boundary is a pure-ASGI middleware with **no dependency on the MCP SDK,
Starlette or uvicorn**, so it is fully unit-testable. The live HTTP server
(``serve``) wraps the SDK's own ``streamable_http_app()`` and needs
``pip install 'miesc[mcp]'``; it is integration-tested separately.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from typing import Any, Awaitable, Callable, List, Optional, Sequence, Tuple

logger = logging.getLogger("miesc.mcp_remote")

# Environment is the only token source: a --token CLI flag would leak through
# `ps` and shell history.
BEARER_ENV = "MIESC_MCP_BEARER_TOKEN"
WORKSPACE_ENV = "MIESC_MCP_WORKSPACE_ROOT"

DEFAULT_BIND = "127.0.0.1"  # loopback only by default; never 0.0.0.0
DEFAULT_PORT = 8766  # distinct from the custom WebSocket server's 8765
MIN_TOKEN_LENGTH = 16

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

ASGIApp = Callable[[Any, Any, Any], Awaitable[None]]


class RemoteAuthError(RuntimeError):
    """Raised when the remote transport cannot be served safely."""


def resolve_bearer_token(explicit: Optional[str] = None) -> str:
    """Return a usable bearer token from ``explicit`` or the environment.

    Fail-closed: raises :class:`RemoteAuthError` when no token is set or the
    token is implausibly short. Never logs the value.
    """
    raw = explicit if explicit is not None else os.environ.get(BEARER_ENV, "")
    token = (raw or "").strip()
    if not token:
        raise RemoteAuthError(
            f"no bearer token configured: set {BEARER_ENV}. The remote MCP "
            "transport is fail-closed and will not serve unauthenticated."
        )
    if len(token) < MIN_TOKEN_LENGTH:
        raise RemoteAuthError(
            f"bearer token is too short ({len(token)} chars); require at least "
            f"{MIN_TOKEN_LENGTH} characters."
        )
    return token


def _bearer_from_headers(headers: Sequence[Tuple[bytes, bytes]]) -> Optional[bytes]:
    """Extract the token bytes from an ASGI ``authorization: Bearer <token>``.

    ASGI header names are lowercased bytes. The scheme match is
    case-insensitive. Returns ``None`` when absent or malformed.
    """
    for key, value in headers or []:
        if key == b"authorization":
            parts = value.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == b"bearer":
                return parts[1].strip()
            return None
    return None


async def _send_json(
    send: Any,
    status: int,
    payload: dict,
    extra_headers: Sequence[Tuple[bytes, bytes]] = (),
) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers: List[Tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class BearerAuthMiddleware:
    """Pure-ASGI bearer-token guard around an inner ASGI app.

    Only ``http`` requests are authenticated. ``lifespan`` scopes pass through
    untouched (the SDK's session manager starts there); any other transport
    (e.g. ``websocket``) is refused — the streamable-HTTP app never uses one, so
    this is defense-in-depth.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        if not token:
            raise RemoteAuthError(
                "refusing to build the remote MCP transport without a bearer token"
            )
        self.app = app
        # Compare bytes: hmac.compare_digest raises on non-ASCII str, which would
        # surface as a 500 instead of a clean 401.
        self._expected = token.encode("utf-8")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        stype = scope.get("type")
        if stype == "lifespan":
            await self.app(scope, receive, send)
            return
        if stype != "http":
            await self._reject_non_http(stype, send)
            return

        provided = _bearer_from_headers(scope.get("headers") or [])
        if provided is None or not hmac.compare_digest(provided, self._expected):
            await _send_json(
                send,
                401,
                {"error": "unauthorized", "detail": "a valid bearer token is required"},
                extra_headers=[(b"www-authenticate", b"Bearer")],
            )
            return

        await self.app(scope, receive, send)

    async def _reject_non_http(self, stype: Any, send: Any) -> None:
        if stype == "websocket":
            # Reject before accept → the client sees an HTTP 403.
            await send({"type": "websocket.close", "code": 1008})
        # Unknown scope types get no response; the connection is dropped.


def _load_streamable_http_app() -> ASGIApp:
    """Build the SDK's own streamable-HTTP ASGI app from the MIESC server.

    Raises :class:`RemoteAuthError` with an actionable message when the SDK is
    absent or too old (``streamable_http_app`` arrived in a recent 1.x line,
    ~1.8+, well above the 1.2.0 floor).
    """
    try:
        from miesc.mcp_server import mcp as _mcp_instance
    except Exception as exc:  # pragma: no cover - defensive
        raise RemoteAuthError(f"MCP server module unavailable: {exc}") from exc

    factory = getattr(_mcp_instance, "streamable_http_app", None)
    if not callable(factory):
        raise RemoteAuthError(
            "the installed MCP SDK does not provide streamable_http_app(); the "
            "remote transport needs a recent 1.x SDK (streamable HTTP, ~1.8+). "
            "Install with: pip install 'miesc[mcp]'"
        )
    return factory()


def build_remote_app(token: str, inner_app: Optional[ASGIApp] = None) -> BearerAuthMiddleware:
    """Wrap the streamable-HTTP app (or an injected ``inner_app``) with auth.

    ``inner_app`` injection keeps the wiring unit-testable without the SDK.
    """
    inner = inner_app if inner_app is not None else _load_streamable_http_app()
    return BearerAuthMiddleware(inner, token)


def serve(
    host: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
    token: Optional[str] = None,
    workspace_root: Optional[str] = None,
    allow_external_bind: bool = False,
) -> None:
    """Serve the remote MCP transport over Streamable HTTP (integration path).

    Not exercised by unit tests (needs the MCP SDK and uvicorn); the auth
    boundary and wiring around it are. Fail-closed on token and on a
    non-loopback bind without an explicit opt-in.
    """
    resolved_token = resolve_bearer_token(token)

    if host not in _LOOPBACK_HOSTS and not allow_external_bind:
        raise RemoteAuthError(
            f"refusing to bind the remote MCP transport to non-loopback host "
            f"{host!r} without an explicit opt-in. The bearer token travels in "
            "cleartext over plain HTTP — terminate TLS in front and pass "
            "allow_external_bind (CLI: --allow-external-bind)."
        )

    # Confine tool file access before serving. Remote callers never get raw host
    # filesystem reach through contract_path / output_path.
    from miesc.mcp_server import set_workspace_root

    root = workspace_root or os.environ.get(WORKSPACE_ENV) or os.getcwd()
    set_workspace_root(root)

    app = build_remote_app(resolved_token)

    try:
        import uvicorn
    except ImportError as exc:
        raise RemoteAuthError(
            "uvicorn is required to serve the remote transport; "
            "install with: pip install 'miesc[mcp]'"
        ) from exc

    logger.warning(
        "Serving MIESC remote MCP (Streamable HTTP) on http://%s:%s (workspace root: %s)",
        host,
        port,
        root,
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")
