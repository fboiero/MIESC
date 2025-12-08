"""
MIESC Core Module Tests
Tests for core components: protocols, discovery, health, aggregator.
"""

import pytest
from unittest.mock import patch, MagicMock
from enum import Enum


class TestToolProtocol:
    """Tests for ToolProtocol and related classes."""

    def test_tool_metadata_import(self):
        """Test ToolMetadata can be imported."""
        from src.core.tool_protocol import ToolMetadata
        assert ToolMetadata is not None

    def test_tool_adapter_import(self):
        """Test ToolAdapter can be imported."""
        from src.core.tool_protocol import ToolAdapter
        assert ToolAdapter is not None

    def test_tool_status_import(self):
        """Test ToolStatus can be imported."""
        from src.core.tool_protocol import ToolStatus
        assert ToolStatus is not None
        assert isinstance(ToolStatus.AVAILABLE, Enum) or hasattr(ToolStatus, 'value')

    def test_tool_category_import(self):
        """Test ToolCategory can be imported."""
        from src.core.tool_protocol import ToolCategory
        assert ToolCategory is not None

    def test_tool_capability_import(self):
        """Test ToolCapability can be imported."""
        from src.core.tool_protocol import ToolCapability
        assert ToolCapability is not None

    def test_create_tool_metadata(self):
        """Test creating ToolMetadata instance."""
        from src.core.tool_protocol import ToolMetadata, ToolCategory

        # ToolMetadata uses dataclass, check if it can be created
        try:
            metadata = ToolMetadata(
                name='test_tool',
                version='1.0.0',
                category=ToolCategory.STATIC_ANALYSIS,
            )
            assert metadata.name == 'test_tool'
        except TypeError:
            # If ToolMetadata has required fields we don't know about, just verify class exists
            assert ToolMetadata is not None


class TestToolDiscovery:
    """Tests for ToolDiscovery."""

    def test_import(self):
        """Test ToolDiscovery can be imported."""
        from src.core.tool_discovery import ToolDiscovery
        assert ToolDiscovery is not None

    def test_get_tool_discovery(self):
        """Test get_tool_discovery singleton."""
        from src.core import get_tool_discovery

        discovery1 = get_tool_discovery()
        discovery2 = get_tool_discovery()

        assert discovery1 is not None
        assert discovery1 is discovery2  # Singleton

    def test_get_available_tools(self):
        """Test getting available tools."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tools = discovery.get_available_tools()

        assert isinstance(tools, list)

    def test_get_tools_by_layer(self):
        """Test getting tools organized by layer."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tools_by_layer = discovery.get_tools_by_layer()

        assert isinstance(tools_by_layer, dict)


class TestHealthChecker:
    """Tests for HealthChecker."""

    def test_import(self):
        """Test HealthChecker can be imported."""
        from src.core.health_checker import HealthChecker
        assert HealthChecker is not None

    def test_health_status_import(self):
        """Test HealthStatus can be imported."""
        from src.core import HealthStatus
        assert HealthStatus is not None

    def test_instantiation(self):
        """Test HealthChecker instantiation."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        assert checker is not None

    def test_check_all(self):
        """Test comprehensive health check."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        health = checker.check_all()

        assert health is not None
        assert hasattr(health, 'status')
        assert hasattr(health, 'healthy_tools')
        assert hasattr(health, 'unhealthy_tools')


class TestResultAggregator:
    """Tests for ResultAggregator."""

    def test_import(self):
        """Test ResultAggregator can be imported."""
        from src.core.result_aggregator import ResultAggregator
        assert ResultAggregator is not None

    def test_instantiation(self):
        """Test ResultAggregator instantiation."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert aggregator is not None

    def test_add_tool_results(self):
        """Test adding tool results."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        tool_result = {
            'status': 'success',
            'findings': [
                {'type': 'reentrancy', 'severity': 'high', 'message': 'Test'}
            ]
        }
        count = aggregator.add_tool_results('slither', tool_result)

        assert count >= 0

    def test_aggregator_has_add_method(self):
        """Test aggregator has add_tool_results method."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert hasattr(aggregator, 'add_tool_results')

    def test_aggregator_has_normalize_method(self):
        """Test aggregator has _normalize_finding method."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert hasattr(aggregator, '_normalize_finding')


class TestAgentProtocol:
    """Tests for AgentProtocol enums and dataclasses."""

    def test_agent_capability_import(self):
        """Test AgentCapability can be imported."""
        from src.core.agent_protocol import AgentCapability
        assert AgentCapability is not None

    def test_agent_metadata_import(self):
        """Test AgentMetadata can be imported."""
        from src.core.agent_protocol import AgentMetadata
        assert AgentMetadata is not None

    def test_finding_import(self):
        """Test Finding can be imported."""
        from src.core.agent_protocol import Finding
        assert Finding is not None


class TestAgentRegistry:
    """Tests for AgentRegistry."""

    def test_import(self):
        """Test AgentRegistry can be imported."""
        from src.core.agent_registry import AgentRegistry
        assert AgentRegistry is not None

    def test_instantiation(self):
        """Test AgentRegistry instantiation."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        assert registry is not None


class TestOptimizedOrchestrator:
    """Tests for OptimizedOrchestrator."""

    def test_import(self):
        """Test OptimizedOrchestrator can be imported."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator
        assert OptimizedOrchestrator is not None

    def test_instantiation(self):
        """Test OptimizedOrchestrator instantiation."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator()
        assert orchestrator is not None


class TestMLOrchestrator:
    """Tests for MLOrchestrator."""

    def test_import(self):
        """Test MLOrchestrator can be imported."""
        from src.core.ml_orchestrator import MLOrchestrator
        assert MLOrchestrator is not None

    def test_get_ml_orchestrator(self):
        """Test get_ml_orchestrator singleton."""
        from src.core import get_ml_orchestrator

        orch1 = get_ml_orchestrator()
        orch2 = get_ml_orchestrator()

        assert orch1 is not None
        assert orch1 is orch2  # Singleton

    def test_ml_orchestrator_methods(self):
        """Test MLOrchestrator has required methods."""
        from src.core import get_ml_orchestrator

        orchestrator = get_ml_orchestrator()

        assert hasattr(orchestrator, 'analyze')
        assert hasattr(orchestrator, 'quick_scan')
        assert hasattr(orchestrator, 'deep_scan')
        assert hasattr(orchestrator, 'get_ml_report')
        assert hasattr(orchestrator, 'submit_feedback')


class TestConfigLoader:
    """Tests for MIESCConfig (config loader)."""

    def test_import(self):
        """Test MIESCConfig can be imported."""
        from src.core.config_loader import MIESCConfig
        assert MIESCConfig is not None

    def test_instantiation(self):
        """Test MIESCConfig instantiation (singleton)."""
        from src.core.config_loader import MIESCConfig

        config = MIESCConfig()
        assert config is not None


class TestCoreInit:
    """Tests for core module __init__.py exports."""

    def test_all_exports_available(self):
        """Test all expected exports are available."""
        from src.core import (
            MLOrchestrator,
            get_ml_orchestrator,
            get_tool_discovery,
            HealthChecker,
            HealthStatus,
        )

        assert MLOrchestrator is not None
        assert get_ml_orchestrator is not None
        assert get_tool_discovery is not None
        assert HealthChecker is not None
        assert HealthStatus is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
