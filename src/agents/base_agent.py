"""
Base Agent Class for MCP Architecture

Provides abstract interface for all specialized agents in MIESC framework.
Each agent wraps one or more security tools and communicates via MCP Context Bus.
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from src.mcp.context_bus import get_context_bus, MCPMessage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Abstract base class for all MCP agents

    Features:
    - Connection to Context Bus singleton
    - Standardized MCP message publishing
    - Context subscription management
    - Status tracking and logging
    - Error handling
    """

    def __init__(self, agent_name: str, capabilities: List[str], agent_type: str):
        """
        Initialize base agent

        Args:
            agent_name: Unique identifier for this agent (e.g., "StaticAgent")
            capabilities: List of capabilities (e.g., ["static_analysis", "pattern_detection"])
            agent_type: Agent category (e.g., "static", "dynamic", "ai")
        """
        self.agent_name = agent_name
        self.capabilities = capabilities
        self.agent_type = agent_type
        self.bus = get_context_bus()
        self.status = "initialized"
        self.contract_path: Optional[str] = None
        self.execution_count = 0

        logger.info(f"{self.agent_name} initialized with capabilities: {capabilities}")

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Perform analysis on contract

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Tool-specific parameters

        Returns:
            Dictionary with analysis results
        """
        pass

    @abstractmethod
    def get_context_types(self) -> List[str]:
        """
        Return list of context types this agent publishes

        Returns:
            List of context_type strings (e.g., ["static_findings", "slither_results"])
        """
        pass

    def publish_findings(self, context_type: str, findings: Dict[str, Any],
                        metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Publish findings to Context Bus as MCP message

        Args:
            context_type: Type of context (e.g., "static_findings")
            findings: Analysis results data
            metadata: Optional metadata (tool versions, execution time, etc.)
        """
        message = MCPMessage(
            protocol="mcp/1.0",
            agent=self.agent_name,
            context_type=context_type,
            contract=self.contract_path or "unknown",
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=findings,
            metadata=metadata or {}
        )

        self.bus.publish(message)
        logger.info(f"{self.agent_name} published {context_type} with {len(findings)} items")

    def subscribe_to(self, context_types: List[str], callback) -> None:
        """
        Subscribe to context types from other agents

        Args:
            context_types: List of context types to listen for
            callback: Function to call when message received (must accept MCPMessage)
        """
        for ct in context_types:
            self.bus.subscribe(ct, callback)
            logger.info(f"{self.agent_name} subscribed to {ct}")

    def get_latest_context(self, context_type: str) -> Optional[MCPMessage]:
        """
        Retrieve most recent message of specific context type

        Args:
            context_type: Type of context to retrieve

        Returns:
            Latest MCPMessage or None if no messages exist
        """
        return self.bus.get_latest_context(context_type)

    def aggregate_contexts(self, context_types: List[str]) -> Dict[str, List[MCPMessage]]:
        """
        Aggregate multiple context types for cross-layer analysis

        Args:
            context_types: List of context types to aggregate

        Returns:
            Dictionary mapping context_type to list of messages
        """
        return self.bus.aggregate_contexts(context_types)

    def set_status(self, status: str) -> None:
        """
        Update agent status

        Args:
            status: One of "initialized", "analyzing", "idle", "error"
        """
        self.status = status
        logger.info(f"{self.agent_name} status: {status}")

    def handle_error(self, error: Exception, context: str) -> None:
        """
        Standardized error handling

        Args:
            error: Exception that occurred
            context: Description of what was being done
        """
        self.set_status("error")
        logger.error(f"{self.agent_name} error during {context}: {str(error)}")

        # Publish error context for monitoring
        self.publish_findings(
            context_type="agent_error",
            findings={
                "error_type": type(error).__name__,
                "error_message": str(error),
                "context": context
            },
            metadata={"status": "error"}
        )

    def run(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Main execution method with standardized workflow

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Tool-specific parameters

        Returns:
            Analysis results
        """
        self.contract_path = contract_path
        self.execution_count += 1
        self.set_status("analyzing")

        try:
            logger.info(f"{self.agent_name} starting analysis of {contract_path}")
            results = self.analyze(contract_path, **kwargs)

            # Publish results for each context type
            for context_type in self.get_context_types():
                if context_type in results:
                    self.publish_findings(
                        context_type=context_type,
                        findings=results[context_type],
                        metadata={
                            "execution_count": self.execution_count,
                            "capabilities": self.capabilities
                        }
                    )

            self.set_status("idle")
            logger.info(f"{self.agent_name} completed analysis")
            return results

        except Exception as e:
            self.handle_error(e, f"analyze({contract_path})")
            return {"error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """
        Get agent statistics

        Returns:
            Dictionary with agent metrics
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "capabilities": self.capabilities,
            "status": self.status,
            "execution_count": self.execution_count,
            "context_types": self.get_context_types()
        }

    def __repr__(self) -> str:
        return f"{self.agent_name}(status={self.status}, executions={self.execution_count})"
