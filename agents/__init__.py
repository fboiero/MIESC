"""
MCP Agents Module

Specialized agents for multi-agent audit framework
"""
from agents.base_agent import BaseAgent
from agents.static_agent import StaticAgent
from agents.ai_agent import AIAgent
from agents.coordinator_agent import CoordinatorAgent

__all__ = [
    "BaseAgent",
    "StaticAgent",
    "AIAgent",
    "CoordinatorAgent"
]

__version__ = "1.0.0"
