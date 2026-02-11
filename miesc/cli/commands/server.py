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
def server():
    """Start MIESC API servers."""
    pass


@server.command("rest")
@click.option("--port", "-p", type=int, default=5001, help="Port number")
@click.option("--host", "-h", type=str, default="0.0.0.0", help="Host address")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def server_rest(port, host, debug):
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
def server_mcp(port, host):
    """Start the MCP WebSocket server for AI agent integration.

    The MCP (Model Context Protocol) server enables real-time communication
    with AI agents like Claude Desktop for collaborative security analysis.

    Example:
        miesc server mcp
        miesc server mcp --port 9000 --host 0.0.0.0
    """
    print_banner()
    info(f"Starting MCP WebSocket server on ws://{host}:{port}")
    info("Compatible with Claude Desktop and other MCP clients")

    try:
        import asyncio

        from src.mcp_core.websocket_server import run_server

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
