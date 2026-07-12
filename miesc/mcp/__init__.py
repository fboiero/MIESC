"""
MIESC MCP Module

Model Context Protocol implementation for tool coordination.
"""

try:
    from miesc.mcp_core.context_bus import ContextBus
    from miesc.mcp_core.tool_registry import ToolRegistry
    from miesc.mcp_core.websocket_server import MIESCWebSocketServer
except ImportError:
    ToolRegistry = None
    MIESCWebSocketServer = None
    ContextBus = None

__all__ = [
    "ToolRegistry",
    "MIESCWebSocketServer",
    "ContextBus",
]
