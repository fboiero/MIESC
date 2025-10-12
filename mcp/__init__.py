"""
MCP (Model Context Protocol) Module

Implements pub/sub messaging infrastructure for multi-agent communication
"""
from mcp.context_bus import ContextBus, MCPMessage, get_context_bus

__all__ = [
    "ContextBus",
    "MCPMessage",
    "get_context_bus"
]

__version__ = "1.0.0"
__protocol__ = "mcp/1.0"
