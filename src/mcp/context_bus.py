"""
Context Bus Implementation for MCP (Model Context Protocol)

Provides a publish-subscribe message bus for inter-agent communication.
Agents can publish findings to context types and subscribe to receive
findings from other agents.

Design Philosophy:
- Minimal but functional implementation
- Thread-safe message storage
- Supports both synchronous and asynchronous communication patterns
- Compatible with MIESC's 7-layer architecture
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from collections import defaultdict
from threading import RLock

logger = logging.getLogger(__name__)


@dataclass
class MCPMessage:
    """
    MCP Message Format (Model Context Protocol)

    Represents a message exchanged between agents via the Context Bus.
    Based on Anthropic's MCP specification adapted for security analysis.

    Attributes:
        protocol: MCP protocol version (e.g., "mcp/1.0")
        agent: Name of the agent publishing the message
        context_type: Type of context (e.g., "static_findings", "ai_triage")
        contract: Contract being analyzed
        timestamp: ISO 8601 timestamp of message creation
        data: Actual findings/analysis data
        metadata: Additional metadata (tool versions, execution time, etc.)
    """
    protocol: str
    agent: str
    context_type: str
    contract: str
    timestamp: str
    data: Any
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate message after creation."""
        if not self.protocol.startswith("mcp/"):
            logger.warning(f"MCPMessage: Non-standard protocol '{self.protocol}'")

        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


class ContextBus:
    """
    Context Bus - Publish/Subscribe Message Bus for Agent Communication

    Implements a simple but functional message bus pattern:
    - Agents publish messages to context types
    - Agents subscribe to context types to receive messages
    - Messages are stored in-memory (no persistence)
    - Thread-safe operations

    Usage:
        bus = ContextBus()

        # Agent 1: Publish findings
        message = MCPMessage(
            protocol="mcp/1.0",
            agent="StaticAgent",
            context_type="static_findings",
            contract="MyContract.sol",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=[{"severity": "High", "title": "Reentrancy"}]
        )
        bus.publish(message)

        # Agent 2: Subscribe to findings
        def handle_findings(message: MCPMessage):
            print(f"Received {len(message.data)} findings")

        bus.subscribe("static_findings", handle_findings)
    """

    def __init__(self):
        """Initialize the Context Bus."""
        # Storage: context_type -> List[MCPMessage]
        self._messages: Dict[str, List[MCPMessage]] = defaultdict(list)

        # Subscriptions: context_type -> List[callback]
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Thread safety
        self._lock = RLock()

        logger.info("ContextBus initialized")

    def publish(self, message: MCPMessage) -> None:
        """
        Publish a message to the bus.

        Args:
            message: MCPMessage to publish
        """
        with self._lock:
            context_type = message.context_type

            # Store message
            self._messages[context_type].append(message)

            # Notify subscribers
            if context_type in self._subscribers:
                for callback in self._subscribers[context_type]:
                    try:
                        callback(message)
                    except Exception as e:
                        logger.error(
                            f"ContextBus: Subscriber callback error for {context_type}: {e}",
                            exc_info=True
                        )

            logger.debug(
                f"ContextBus: Published {context_type} from {message.agent} "
                f"(contract: {message.contract})"
            )

    def subscribe(self, context_type: str, callback: Callable[[MCPMessage], None]) -> None:
        """
        Subscribe to messages of a specific context type.

        Args:
            context_type: Type of context to subscribe to
            callback: Function to call when message received (must accept MCPMessage)
        """
        with self._lock:
            self._subscribers[context_type].append(callback)
            logger.debug(f"ContextBus: Subscribed to {context_type}")

    def get_latest_context(self, context_type: str) -> Optional[MCPMessage]:
        """
        Get the most recent message of a specific context type.

        Args:
            context_type: Type of context to retrieve

        Returns:
            Latest MCPMessage or None if no messages exist
        """
        with self._lock:
            messages = self._messages.get(context_type, [])
            return messages[-1] if messages else None

    def get_all_contexts(self, context_type: str) -> List[MCPMessage]:
        """
        Get all messages of a specific context type.

        Args:
            context_type: Type of context to retrieve

        Returns:
            List of MCPMessages (may be empty)
        """
        with self._lock:
            return list(self._messages.get(context_type, []))

    def aggregate_contexts(self, context_types: List[str]) -> Dict[str, List[MCPMessage]]:
        """
        Aggregate messages from multiple context types.

        Args:
            context_types: List of context types to aggregate

        Returns:
            Dictionary mapping context_type -> List[MCPMessage]
        """
        with self._lock:
            result = {}
            for context_type in context_types:
                result[context_type] = list(self._messages.get(context_type, []))
            return result

    def clear(self) -> None:
        """Clear all messages and subscriptions (useful for testing)."""
        with self._lock:
            self._messages.clear()
            self._subscribers.clear()
            logger.info("ContextBus: Cleared all messages and subscriptions")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get bus statistics (for monitoring/debugging).

        Returns:
            Dictionary with message counts per context type
        """
        with self._lock:
            return {
                "context_types": list(self._messages.keys()),
                "total_messages": sum(len(msgs) for msgs in self._messages.values()),
                "messages_per_type": {
                    ct: len(msgs) for ct, msgs in self._messages.items()
                },
                "subscriber_count": {
                    ct: len(subs) for ct, subs in self._subscribers.items()
                }
            }


# Singleton instance for global access
_context_bus_instance: Optional[ContextBus] = None


def get_context_bus() -> ContextBus:
    """
    Get the singleton ContextBus instance.

    Returns:
        Shared ContextBus instance
    """
    global _context_bus_instance
    if _context_bus_instance is None:
        _context_bus_instance = ContextBus()
        logger.info("ContextBus: Created singleton instance")
    return _context_bus_instance


def reset_context_bus() -> None:
    """
    Reset the singleton ContextBus (useful for testing).

    Creates a fresh ContextBus instance, discarding all messages and subscriptions.
    """
    global _context_bus_instance
    _context_bus_instance = ContextBus()
    logger.info("ContextBus: Reset singleton instance")
