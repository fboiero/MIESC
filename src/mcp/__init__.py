"""
MCP (Model Context Protocol) Infrastructure for MIESC v3.3.0

Provides inter-agent communication and context sharing capabilities.
This is a minimal but functional implementation of the MCP pattern.
"""

from src.mcp.context_bus import ContextBus, MCPMessage, get_context_bus

__all__ = ['ContextBus', 'MCPMessage', 'get_context_bus']
__version__ = '1.0.0'
