"""
MCP (Model Context Protocol) Infrastructure for MIESC v4.1.0

Provides inter-agent communication, context sharing, and tool discovery
capabilities following the Anthropic MCP specification.

Components:
- ContextBus: Pub/sub message bus for inter-agent communication
- MCPToolRegistry: Tool discovery following MCP tools/list specification
- MCPMessage: Standard message format for MCP communication

Reference: https://modelcontextprotocol.io/specification
"""

from src.mcp.context_bus import ContextBus, MCPMessage, get_context_bus
from src.mcp.tool_registry import (
    MCPToolRegistry,
    MCPTool,
    MCPToolParameter,
    ToolCategory,
    get_tool_registry,
    reset_tool_registry,
)

__all__ = [
    # Context Bus
    'ContextBus',
    'MCPMessage',
    'get_context_bus',
    # Tool Registry
    'MCPToolRegistry',
    'MCPTool',
    'MCPToolParameter',
    'ToolCategory',
    'get_tool_registry',
    'reset_tool_registry',
]
__version__ = '2.0.0'
