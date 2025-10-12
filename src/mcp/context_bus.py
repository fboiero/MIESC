"""
MCP Context Bus - Message-based communication for multi-agent auditing
Implements pub/sub pattern for agent interoperability
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, asdict
from queue import Queue
from threading import Lock

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MCPMessage:
    """Standard MCP message format"""
    protocol: str = "mcp/1.0"
    agent: str = ""
    context_type: str = ""
    contract: str = ""
    timestamp: str = ""
    data: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        if self.data is None:
            self.data = {}
        if self.metadata is None:
            self.metadata = {}

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'MCPMessage':
        """Deserialize from JSON"""
        data = json.loads(json_str)
        return cls(**data)


class ContextBus:
    """
    MCP Context Bus for agent communication

    Features:
    - Pub/Sub messaging
    - Context storage
    - Message history
    - Event logging for audit trail
    """

    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.context_store: Dict[str, List[MCPMessage]] = {}
        self.message_history: List[MCPMessage] = []
        self.lock = Lock()
        logger.info("MCP Context Bus initialized")

    def publish(self, message: MCPMessage) -> None:
        """
        Publish message to all subscribers of context_type

        Args:
            message: MCPMessage instance
        """
        with self.lock:
            # Store message
            self.message_history.append(message)

            if message.context_type not in self.context_store:
                self.context_store[message.context_type] = []
            self.context_store[message.context_type].append(message)

            # Notify subscribers
            if message.context_type in self.subscribers:
                logger.info(f"Publishing {message.context_type} from {message.agent}")
                for callback in self.subscribers[message.context_type]:
                    try:
                        callback(message)
                    except Exception as e:
                        logger.error(f"Subscriber callback error: {e}")

    def subscribe(self, context_type: str, callback: Callable[[MCPMessage], None]) -> None:
        """
        Subscribe to messages of specific context_type

        Args:
            context_type: Type of context to listen for
            callback: Function to call when message received
        """
        with self.lock:
            if context_type not in self.subscribers:
                self.subscribers[context_type] = []
            self.subscribers[context_type].append(callback)
            logger.info(f"New subscriber for {context_type}")

    def get_context(self, context_type: str) -> List[MCPMessage]:
        """
        Retrieve all messages of specific context_type

        Args:
            context_type: Type of context to retrieve

        Returns:
            List of MCPMessage instances
        """
        with self.lock:
            return self.context_store.get(context_type, [])

    def get_latest_context(self, context_type: str) -> Optional[MCPMessage]:
        """Get most recent message of context_type"""
        messages = self.get_context(context_type)
        return messages[-1] if messages else None

    def aggregate_contexts(self, context_types: List[str]) -> Dict[str, List[MCPMessage]]:
        """
        Aggregate multiple context types

        Args:
            context_types: List of context types to aggregate

        Returns:
            Dictionary mapping context_type to messages
        """
        with self.lock:
            return {
                ct: self.context_store.get(ct, [])
                for ct in context_types
            }

    def get_message_history(self, agent: Optional[str] = None) -> List[MCPMessage]:
        """
        Get message history, optionally filtered by agent

        Args:
            agent: Optional agent name to filter by

        Returns:
            List of MCPMessage instances
        """
        with self.lock:
            if agent:
                return [m for m in self.message_history if m.agent == agent]
            return self.message_history.copy()

    def clear_context(self, context_type: Optional[str] = None) -> None:
        """
        Clear context store

        Args:
            context_type: Optional specific type to clear, or all if None
        """
        with self.lock:
            if context_type:
                self.context_store.pop(context_type, None)
                logger.info(f"Cleared context: {context_type}")
            else:
                self.context_store.clear()
                logger.info("Cleared all contexts")

    def export_audit_trail(self, filepath: str) -> None:
        """
        Export complete message history as audit trail

        Args:
            filepath: Path to save JSON audit trail
        """
        with self.lock:
            audit_data = {
                "protocol": "mcp/1.0",
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_messages": len(self.message_history),
                "context_types": list(self.context_store.keys()),
                "messages": [asdict(m) for m in self.message_history]
            }

            with open(filepath, 'w') as f:
                json.dump(audit_data, f, indent=2)

            logger.info(f"Audit trail exported to {filepath}")

    def get_stats(self) -> Dict[str, Any]:
        """Get bus statistics"""
        with self.lock:
            return {
                "total_messages": len(self.message_history),
                "active_context_types": len(self.context_store),
                "subscribers": {ct: len(cbs) for ct, cbs in self.subscribers.items()},
                "context_counts": {ct: len(msgs) for ct, msgs in self.context_store.items()}
            }


# Global singleton instance
_bus_instance: Optional[ContextBus] = None


def get_context_bus() -> ContextBus:
    """Get or create global ContextBus singleton"""
    global _bus_instance
    if _bus_instance is None:
        _bus_instance = ContextBus()
    return _bus_instance
