"""
Tests for Agent Registry module.

Tests the agent registry and discovery system.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.agent_protocol import (
    AgentCapability,
    AgentMetadata,
    AgentSpeed,
    AnalysisResult,
    AnalysisStatus,
    Finding,
    FindingSeverity,
    SecurityAgent,
)
from src.core.agent_registry import AgentRegistry


class TestAgentCapability:
    """Test AgentCapability enum."""

    def test_all_capabilities(self):
        """Test all capabilities exist."""
        assert AgentCapability.STATIC_ANALYSIS.value == "static_analysis"
        assert AgentCapability.SYMBOLIC_EXECUTION.value == "symbolic_execution"
        assert AgentCapability.AI_ANALYSIS.value == "ai_analysis"
        assert AgentCapability.FUZZING.value == "fuzzing"
        assert AgentCapability.FORMAL_VERIFICATION.value == "formal_verification"
        assert AgentCapability.GAS_OPTIMIZATION.value == "gas_optimization"
        assert AgentCapability.PATTERN_MATCHING.value == "pattern_matching"
        assert AgentCapability.DEPENDENCY_ANALYSIS.value == "dependency_analysis"
        assert AgentCapability.CODE_QUALITY.value == "code_quality"
        assert AgentCapability.CUSTOM_RULES.value == "custom_rules"


class TestAgentSpeed:
    """Test AgentSpeed enum."""

    def test_all_speeds(self):
        """Test all speeds exist."""
        assert AgentSpeed.FAST.value == "fast"
        assert AgentSpeed.MEDIUM.value == "medium"
        assert AgentSpeed.SLOW.value == "slow"


class TestAnalysisStatus:
    """Test AnalysisStatus enum."""

    def test_all_statuses(self):
        """Test all statuses exist."""
        assert AnalysisStatus.SUCCESS.value == "success"
        assert AnalysisStatus.ERROR.value == "error"
        assert AnalysisStatus.TIMEOUT.value == "timeout"
        assert AnalysisStatus.SKIPPED.value == "skipped"


class TestFindingSeverity:
    """Test FindingSeverity enum."""

    def test_all_severities(self):
        """Test all severities exist."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"


class TestAgentMetadata:
    """Test AgentMetadata dataclass."""

    def test_create_metadata(self):
        """Test creating metadata."""
        meta = AgentMetadata(
            name="test-agent",
            version="1.0.0",
            description="Test agent",
            author="Test Author",
            license="MIT",
            capabilities=[AgentCapability.STATIC_ANALYSIS],
            supported_languages=["solidity"],
            cost=0.0,
            speed=AgentSpeed.FAST,
        )
        assert meta.name == "test-agent"
        assert meta.version == "1.0.0"
        assert len(meta.capabilities) == 1
        assert meta.cost == 0.0

    def test_metadata_optional_fields(self):
        """Test optional fields."""
        meta = AgentMetadata(
            name="test",
            version="1.0",
            description="desc",
            author="author",
            license="MIT",
            capabilities=[],
            supported_languages=[],
            cost=0,
            speed=AgentSpeed.FAST,
        )
        assert meta.homepage is None
        assert meta.repository is None
        assert meta.requires is None


class TestFinding:
    """Test Finding dataclass."""

    def test_create_finding(self):
        """Test creating finding."""
        f = Finding(
            type="reentrancy",
            severity=FindingSeverity.HIGH,
            location="Token.sol:42",
            message="Reentrancy vulnerability found",
        )
        assert f.type == "reentrancy"
        assert f.severity == FindingSeverity.HIGH
        assert f.location == "Token.sol:42"

    def test_finding_optional_fields(self):
        """Test optional fields."""
        f = Finding(
            type="test",
            severity=FindingSeverity.LOW,
            location="test.sol:1",
            message="test",
        )
        assert f.description is None
        assert f.recommendation is None
        assert f.confidence is None


class TestAnalysisResult:
    """Test AnalysisResult dataclass."""

    def test_create_result_success(self):
        """Test creating success result."""
        from datetime import datetime

        result = AnalysisResult(
            agent="test-agent",
            version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            timestamp=datetime.now(),
            execution_time=1.5,
            findings=[],
            summary={"critical": 0, "high": 0},
        )
        assert result.status == AnalysisStatus.SUCCESS
        assert result.findings == []
        assert result.execution_time == 1.5

    def test_create_result_with_findings(self):
        """Test result with findings."""
        from datetime import datetime

        finding = Finding(
            type="overflow",
            severity=FindingSeverity.MEDIUM,
            location="Token.sol:10",
            message="Integer overflow",
        )
        result = AnalysisResult(
            agent="test-agent",
            version="1.0.0",
            status=AnalysisStatus.SUCCESS,
            timestamp=datetime.now(),
            execution_time=2.0,
            findings=[finding],
            summary={"medium": 1},
            metadata={"tool": "test"},
        )
        assert len(result.findings) == 1


class MockSecurityAgent(SecurityAgent):
    """Mock agent for testing."""

    def __init__(self, name="mock-agent", available=True, valid=True):
        self._name = name
        self._available = available
        self._valid = valid

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Mock agent for testing"

    @property
    def author(self) -> str:
        return "Test Author"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def capabilities(self):
        return [AgentCapability.STATIC_ANALYSIS]

    @property
    def supported_languages(self):
        return ["solidity"]

    @property
    def cost(self) -> float:
        return 0.0

    @property
    def speed(self):
        return AgentSpeed.FAST

    def is_available(self) -> bool:
        return self._available

    def can_analyze(self, file_path: str) -> bool:
        return file_path.endswith(".sol")

    def validate(self) -> bool:
        return self._valid

    def analyze(self, contract, **kwargs):
        from datetime import datetime

        return AnalysisResult(
            agent=self.name,
            version=self.version,
            status=AnalysisStatus.SUCCESS,
            timestamp=datetime.now(),
            execution_time=0.1,
            findings=[],
            summary={},
        )

    def get_metadata(self):
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
        )


class TestAgentRegistry:
    """Test AgentRegistry class."""

    @pytest.fixture
    def registry(self):
        """Create fresh registry."""
        return AgentRegistry()

    def test_init(self, registry):
        """Test initialization."""
        assert registry.agents == {}

    def test_register_agent(self, registry):
        """Test registering agent."""
        agent = MockSecurityAgent(name="test-agent")
        result = registry.register(agent)
        assert result is True
        assert "test-agent" in registry.agents

    def test_register_duplicate_fails(self, registry):
        """Test registering duplicate fails."""
        agent1 = MockSecurityAgent(name="dup-agent")
        agent2 = MockSecurityAgent(name="dup-agent")
        registry.register(agent1)

        with pytest.raises(ValueError, match="already registered"):
            registry.register(agent2)

    def test_register_duplicate_force(self, registry):
        """Test force registering duplicate."""
        agent1 = MockSecurityAgent(name="dup-agent")
        agent2 = MockSecurityAgent(name="dup-agent")
        registry.register(agent1)
        result = registry.register(agent2, force=True)
        assert result is True

    def test_register_invalid_type(self, registry):
        """Test registering invalid type."""
        with pytest.raises(TypeError):
            registry.register("not an agent")

    def test_register_invalid_agent(self, registry):
        """Test registering invalid agent."""
        agent = MockSecurityAgent(name="invalid", valid=False)
        with pytest.raises(ValueError, match="failed validation"):
            registry.register(agent)

    def test_unregister(self, registry):
        """Test unregistering agent."""
        agent = MockSecurityAgent(name="to-remove")
        registry.register(agent)

        result = registry.unregister("to-remove")
        assert result is True
        assert "to-remove" not in registry.agents

    def test_unregister_nonexistent(self, registry):
        """Test unregistering nonexistent agent."""
        result = registry.unregister("nonexistent")
        assert result is False

    def test_get(self, registry):
        """Test getting agent."""
        agent = MockSecurityAgent(name="get-agent")
        registry.register(agent)

        result = registry.get("get-agent")
        assert result is agent

    def test_get_nonexistent(self, registry):
        """Test getting nonexistent agent."""
        result = registry.get("nonexistent")
        assert result is None

    def test_list_agents(self, registry):
        """Test listing agents."""
        agent1 = MockSecurityAgent(name="agent1")
        agent2 = MockSecurityAgent(name="agent2")
        registry.register(agent1)
        registry.register(agent2)

        agents = registry.list_agents()
        assert len(agents) == 2

    def test_list_agents_available_only(self, registry):
        """Test listing available agents only."""
        agent1 = MockSecurityAgent(name="available", available=True)
        agent2 = MockSecurityAgent(name="unavailable", available=False)
        registry.register(agent1)
        registry.register(agent2)

        agents = registry.list_agents(available_only=True)
        assert len(agents) == 1
        assert agents[0].name == "available"


class TestAgentRegistryFilter:
    """Test agent filtering."""

    @pytest.fixture
    def registry_with_agents(self):
        """Create registry with multiple agents."""
        reg = AgentRegistry()
        reg.register(MockSecurityAgent(name="agent1", available=True))
        reg.register(MockSecurityAgent(name="agent2", available=False))
        return reg

    def test_filter_available_only(self, registry_with_agents):
        """Test filtering by availability."""
        agents = registry_with_agents.filter_agents(available_only=True)
        assert len(agents) == 1

    def test_filter_language(self, registry_with_agents):
        """Test filtering by language."""
        agents = registry_with_agents.filter_agents(language="solidity", available_only=False)
        assert len(agents) == 2

    def test_filter_unknown_language(self, registry_with_agents):
        """Test filtering by unknown language."""
        agents = registry_with_agents.filter_agents(language="unknown", available_only=False)
        assert len(agents) == 0

    def test_filter_free_only(self, registry_with_agents):
        """Test filtering free agents."""
        agents = registry_with_agents.filter_agents(free_only=True, available_only=False)
        assert len(agents) == 2


class TestAgentRegistryStatistics:
    """Test statistics generation."""

    @pytest.fixture
    def registry(self):
        """Create registry."""
        reg = AgentRegistry()
        reg.register(MockSecurityAgent(name="agent1", available=True))
        reg.register(MockSecurityAgent(name="agent2", available=False))
        return reg

    def test_get_statistics(self, registry):
        """Test getting statistics."""
        stats = registry.get_statistics()
        assert stats["total_agents"] == 2
        assert stats["available_agents"] == 1
        assert stats["free_agents"] == 2
        assert stats["paid_agents"] == 0
        assert "capabilities" in stats
        assert "languages" in stats


class TestAgentRegistryValidate:
    """Test validation."""

    @pytest.fixture
    def registry(self):
        """Create registry."""
        reg = AgentRegistry()
        reg.register(MockSecurityAgent(name="valid"))
        return reg

    def test_validate_all(self, registry):
        """Test validating all agents."""
        results = registry.validate_all()
        assert "valid" in results
        assert results["valid"] is True


class TestAgentRegistryDunder:
    """Test dunder methods."""

    @pytest.fixture
    def registry(self):
        """Create registry."""
        reg = AgentRegistry()
        reg.register(MockSecurityAgent(name="agent1"))
        reg.register(MockSecurityAgent(name="agent2"))
        return reg

    def test_len(self, registry):
        """Test len."""
        assert len(registry) == 2

    def test_contains(self, registry):
        """Test contains."""
        assert "agent1" in registry
        assert "nonexistent" not in registry

    def test_iter(self, registry):
        """Test iteration."""
        names = list(registry)
        assert "agent1" in names
        assert "agent2" in names

    def test_repr(self, registry):
        """Test repr."""
        r = repr(registry)
        assert "AgentRegistry" in r
        assert "2" in r
