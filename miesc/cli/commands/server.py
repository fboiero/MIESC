"""
MIESC CLI - Server Commands

Commands for starting MIESC API servers.

Author: Fernando Boiero
License: AGPL-3.0
"""

import sys

import click

from miesc.cli.utils import error, info, print_banner


@click.group()
def server() -> None:
    """Start MIESC API servers."""
    pass


@server.command("rest")
@click.option("--port", "-p", type=int, default=5001, help="Port number")
@click.option("--host", "-h", type=str, default="0.0.0.0", help="Host address")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def server_rest(port: int, host: str, debug: bool) -> None:
    """Start the Django REST API server."""
    print_banner()
    info(f"Starting Django REST API on http://{host}:{port}")
    info("Endpoints:")
    info("  - POST /api/v1/analyze/quick/  - Quick 4-tool scan")
    info("  - POST /api/v1/analyze/full/   - Complete 9-layer audit")
    info("  - GET  /api/v1/tools/          - List available tools")
    info("  - GET  /api/v1/layers/         - Layer information")
    info("  - GET  /api/v1/health/         - System health check")

    try:
        from miesc.api.rest import run_server

        run_server(host, port, debug)
    except ImportError as e:
        error(f"Django REST Framework not available: {e}")
        info("Install with: pip install django djangorestframework django-cors-headers")
        sys.exit(1)
    except Exception as e:
        error(f"Server error: {e}")
        sys.exit(1)


@server.command("mcp")
@click.option("--port", "-p", type=int, default=8765, help="WebSocket port number")
@click.option("--host", "-h", type=str, default="localhost", help="Host to bind to")
def server_mcp(port: int, host: str) -> None:
    """Start the real-time audit-streaming WebSocket server.

    This serves MIESC's own WebSocket event stream (progress and findings) for
    dashboards and agent integrations over a custom protocol. It is NOT the Model
    Context Protocol and is not usable by MCP clients such as Claude Desktop; for
    MCP, use the stdio server ``miesc-mcp`` (``python -m miesc.mcp_server``).

    Example:
        miesc server mcp
        miesc server mcp --port 9000 --host 0.0.0.0
    """
    print_banner()
    info(f"Starting MIESC audit-streaming WebSocket server on ws://{host}:{port}")
    info("Custom WebSocket event protocol (not MCP; for MCP use `miesc-mcp`)")

    try:
        import asyncio

        from miesc.mcp_core.websocket_server import run_server

        info("Press Ctrl+C to stop the server")
        asyncio.run(run_server(host=host, port=port))
    except ImportError as e:
        error(f"MCP dependencies not installed: {e}")
        info("Install with: pip install websockets")
        sys.exit(1)
    except KeyboardInterrupt:
        info("MCP server stopped")
    except Exception as e:
        error(f"MCP server error: {e}")
        sys.exit(1)


@server.command("mcp-remote")
@click.option("--port", "-p", type=int, default=8766, help="HTTP port number")
@click.option(
    "--host", "-h", type=str, default="127.0.0.1", help="Host to bind to (loopback by default)"
)
@click.option(
    "--workspace",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=None,
    help="Workspace root to confine tool file access to (defaults to the current directory)",
)
@click.option(
    "--allow-external-bind",
    is_flag=True,
    help="Permit a non-loopback bind. The bearer travels in cleartext over plain HTTP; terminate TLS in front.",
)
def server_mcp_remote(port: int, host: str, workspace: str, allow_external_bind: bool) -> None:
    """Start the real MCP server over Streamable HTTP, behind a bearer token.

    This is the genuine Model Context Protocol (the SDK's own Streamable HTTP
    transport) for *remote* agents — distinct from the local stdio server
    (``miesc-mcp``) and from the custom WebSocket bus (``miesc server mcp``).

    Fail-closed: it refuses to start without a bearer token and will not bind to
    a non-loopback host without ``--allow-external-bind``. The token is read from
    the environment only (never a flag), and tool file access is confined to the
    workspace root.

    Example:
        export MIESC_MCP_BEARER_TOKEN="$(openssl rand -hex 24)"
        miesc server mcp-remote --workspace ./audits
    """
    print_banner()

    try:
        from miesc.mcp_remote import DEFAULT_PORT, resolve_bearer_token, serve

        # Resolve the token first so a misconfiguration fails before binding.
        resolve_bearer_token()
        info(f"Starting MIESC remote MCP (Streamable HTTP) on http://{host}:{port}")
        info("Genuine MCP over HTTP; bearer-authenticated (token from MIESC_MCP_BEARER_TOKEN)")
        if host not in {"127.0.0.1", "::1", "localhost"}:
            info(
                "Non-loopback bind: ensure TLS is terminated in front (cleartext bearer otherwise)"
            )
        info("Press Ctrl+C to stop the server")
        serve(
            host=host,
            port=port or DEFAULT_PORT,
            workspace_root=workspace,
            allow_external_bind=allow_external_bind,
        )
    except ImportError as e:
        error(f"MCP SDK not installed: {e}")
        info("Install with: pip install 'miesc[mcp]'")
        sys.exit(1)
    except KeyboardInterrupt:
        info("Remote MCP server stopped")
    except Exception as e:
        error(f"Remote MCP server error: {e}")
        sys.exit(1)
