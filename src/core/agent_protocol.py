"""
MIESC Agent Protocol
====================

Standard interface for security analysis agents in MIESC.
Any tool can implement this protocol to integrate with MIESC.

Version: 1.0.0
License: MIT
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class AgentCapability(Enum):
    """Standard capabilities that agents can provide"""
    STATIC_ANALYSIS = "static_analysis"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    AI_ANALYSIS = "ai_analysis"
    FUZZING = "fuzzing"
    FORMAL_VERIFICATION = "formal_verification"
    GAS_OPTIMIZATION = "gas_optimization"
    PATTERN_MATCHING = "pattern_matching"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    CODE_QUALITY = "code_quality"
    CUSTOM_RULES = "custom_rules"


class AgentSpeed(Enum):
    """Speed categories for agent execution"""
    FAST = "fast"          # < 10 seconds
    MEDIUM = "medium"      # 10-60 seconds
    SLOW = "slow"          # > 60 seconds


class AnalysisStatus(Enum):
    """Status of analysis execution"""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class FindingSeverity(Enum):
    """Standard severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AgentMetadata:
    """Complete metadata for an agent"""
    name: str
    version: str
    description: str
    author: str
    license: str
    capabilities: List[AgentCapability]
    supported_languages: List[str]
    cost: float  # USD per analysis, 0 = free
    speed: AgentSpeed
    homepage: Optional[str] = None
    repository: Optional[str] = None
    documentation: Optional[str] = None
    installation: Optional[str] = None
    requires: Optional[List[str]] = None  # Dependencies


@dataclass
class Finding:
    """Standard finding format"""
    type: str
    severity: FindingSeverity
    location: str
    message: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    reference: Optional[str] = None
    confidence: Optional[str] = None
    impact: Optional[str] = None
    code_snippet: Optional[str] = None


@dataclass
class AnalysisResult:
    """Standard analysis result format"""
    agent: str
    version: str
    status: AnalysisStatus
    timestamp: datetime
    execution_time: float  # seconds
    findings: List[Finding]
    summary: Dict[str, int]  # {'critical': 2, 'high': 5, ...}
    metadata: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class SecurityAgent(ABC):
    """
    Abstract base class for MIESC security agents.

    All agents must implement this interface to be compatible
    with the MIESC orchestration system.

    Example:
        class MyAgent(SecurityAgent):
            @property
            def name(self) -> str:
                return "my-agent"

            def analyze(self, contract: str, **kwargs) -> AnalysisResult:
                # Perform analysis
                return AnalysisResult(...)
    """

    # ==========================================
    # Required Properties
    # ==========================================

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for the agent.
        Must be lowercase, alphanumeric with hyphens only.

        Example: "slither", "my-custom-agent"
        """
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """
        Semantic version of the agent.

        Example: "1.2.3"
        """
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Short description of what the agent does.

        Example: "Static analysis with 87 detectors"
        """
        pass

    @property
    @abstractmethod
    def author(self) -> str:
        """
        Author or organization name.

        Example: "Trail of Bits"
        """
        pass

    @property
    @abstractmethod
    def license(self) -> str:
        """
        License type.

        Example: "AGPL-3.0", "MIT"
        """
        pass

    @property
    @abstractmethod
    def capabilities(self) -> List[AgentCapability]:
        """
        List of capabilities this agent provides.

        Example: [AgentCapability.STATIC_ANALYSIS, AgentCapability.PATTERN_MATCHING]
        """
        pass

    @property
    @abstractmethod
    def supported_languages(self) -> List[str]:
        """
        Programming languages this agent can analyze.

        Example: ["solidity", "vyper", "rust"]
        """
        pass

    @property
    @abstractmethod
    def cost(self) -> float:
        """
        Cost per analysis in USD. Use 0 for free tools.

        Example: 0.0, 0.50, 5.00
        """
        pass

    @property
    @abstractmethod
    def speed(self) -> AgentSpeed:
        """
        Typical execution speed.

        Example: AgentSpeed.FAST
        """
        pass

    # ==========================================
    # Required Methods
    # ==========================================

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the agent is available and can run.

        This should verify:
        - Required binaries are installed
        - Dependencies are available
        - Configuration is valid

        Returns:
            bool: True if agent can run, False otherwise
        """
        pass

    @abstractmethod
    def can_analyze(self, file_path: str) -> bool:
        """
        Check if this agent can analyze the given file.

        Args:
            file_path: Path to the contract file

        Returns:
            bool: True if agent can analyze this file
        """
        pass

    @abstractmethod
    def analyze(self, contract: str, **kwargs) -> AnalysisResult:
        """
        Perform security analysis on the contract.

        Args:
            contract: Path to the contract file
            **kwargs: Additional agent-specific parameters

        Returns:
            AnalysisResult: Standardized analysis results

        Raises:
            Exception: If analysis fails
        """
        pass

    # ==========================================
    # Optional Methods (with defaults)
    # ==========================================

    def get_metadata(self) -> AgentMetadata:
        """
        Get complete agent metadata.

        Returns:
            AgentMetadata: All agent information
        """
        return AgentMetadata(
            name=self.name,
            version=self.version,
            description=self.description,
            author=self.author,
            license=self.license,
            capabilities=self.capabilities,
            supported_languages=self.supported_languages,
            cost=self.cost,
            speed=self.speed,
            homepage=getattr(self, 'homepage', None),
            repository=getattr(self, 'repository', None),
            documentation=getattr(self, 'documentation', None),
            installation=getattr(self, 'installation', None),
            requires=getattr(self, 'requires', None)
        )

    def validate(self) -> bool:
        """
        Validate agent implementation.

        Returns:
            bool: True if agent is properly implemented
        """
        try:
            # Check required properties
            assert self.name and isinstance(self.name, str)
            assert self.version and isinstance(self.version, str)
            assert self.description and isinstance(self.description, str)
            assert self.author and isinstance(self.author, str)
            assert self.license and isinstance(self.license, str)
            assert isinstance(self.capabilities, list)
            assert isinstance(self.supported_languages, list)
            assert isinstance(self.cost, (int, float)) and self.cost >= 0
            assert isinstance(self.speed, AgentSpeed)

            # Check name format (lowercase, alphanumeric, hyphens)
            import re
            assert re.match(r'^[a-z0-9-]+$', self.name), "Name must be lowercase alphanumeric with hyphens"

            return True
        except Exception as e:
            return False

    def get_config_schema(self) -> Dict[str, Any]:
        """
        Get configuration schema for this agent.

        Returns:
            Dict: JSON schema for agent configuration
        """
        return {}

    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the agent with custom settings.

        Args:
            config: Configuration dictionary
        """
        pass

    def __str__(self) -> str:
        return f"{self.name} v{self.version}"

    def __repr__(self) -> str:
        return f"<SecurityAgent: {self.name} v{self.version}>"


class AgentPlugin:
    """
    Helper class for creating agent plugins.

    Example:
        @AgentPlugin.register
        class MyAgent(SecurityAgent):
            # Implementation
            pass
    """

    _registry: List[type] = []

    @classmethod
    def register(cls, agent_class: type) -> type:
        """Decorator to register an agent class"""
        if not issubclass(agent_class, SecurityAgent):
            raise TypeError(f"{agent_class} must inherit from SecurityAgent")
        cls._registry.append(agent_class)
        return agent_class

    @classmethod
    def get_registered_agents(cls) -> List[type]:
        """Get all registered agent classes"""
        return cls._registry.copy()
