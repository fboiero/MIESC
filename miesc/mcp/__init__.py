"""
MIESC MCP Module

Model Context Protocol implementation for tool coordination.
"""

try:
    from miesc.mcp_core.context_bus import ContextBus

    # The registry class is named ``MCPToolRegistry``; expose it under the
    # historical ``ToolRegistry`` alias so this shim's public API stays stable.
    from miesc.mcp_core.tool_registry import MCPToolRegistry as ToolRegistry
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
