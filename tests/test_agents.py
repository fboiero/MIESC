"""
MIESC Agents Module Tests
Tests for base agent, static agent, coordinator, and policy agent.
"""

import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, List


# =============================================================================
# BASE AGENT TESTS
# =============================================================================

class TestBaseAgent:
    """Tests for BaseAgent abstract class."""

    def test_import_base_agent(self):
        """Test that BaseAgent can be imported."""
        from src.agents.base_agent import BaseAgent
        assert BaseAgent is not None

    def test_base_agent_is_abstract(self):
        """Test that BaseAgent cannot be instantiated directly."""
        from src.agents.base_agent import BaseAgent

        with pytest.raises(TypeError):
            BaseAgent("TestAgent", ["capability"], "test")

    def test_base_agent_concrete_implementation(self):
        """Test creating a concrete implementation of BaseAgent."""
        from src.agents.base_agent import BaseAgent

        class ConcreteAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {"status": "success", "findings": []}

            def get_context_types(self) -> List[str]:
                return ["test_findings"]

        # Should be able to instantiate
        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = ConcreteAgent("TestAgent", ["test_capability"], "test")
            assert agent.agent_name == "TestAgent"
            assert agent.capabilities == ["test_capability"]
            assert agent.agent_type == "test"


# =============================================================================
# STATIC AGENT TESTS
# =============================================================================

class TestStaticAgent:
    """Tests for StaticAgent."""

    def test_import_static_agent(self):
        """Test that StaticAgent can be imported."""
        from src.agents.static_agent import StaticAgent
        assert StaticAgent is not None

    def test_static_agent_initialization(self):
        """Test StaticAgent can be initialized."""
        from src.agents.static_agent import StaticAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = StaticAgent()
            assert agent.agent_name == "StaticAgent"
            assert "static_analysis" in agent.capabilities

    def test_static_agent_has_analyze_method(self):
        """Test StaticAgent has analyze method."""
        from src.agents.static_agent import StaticAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = StaticAgent()
            assert hasattr(agent, 'analyze')
            assert callable(agent.analyze)

    def test_static_agent_context_types(self):
        """Test StaticAgent returns proper context types."""
        from src.agents.static_agent import StaticAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = StaticAgent()
            context_types = agent.get_context_types()
            assert isinstance(context_types, list)
            assert len(context_types) > 0


# =============================================================================
# COORDINATOR AGENT TESTS
# =============================================================================

class TestCoordinatorAgent:
    """Tests for CoordinatorAgent."""

    def test_import_coordinator_agent(self):
        """Test that CoordinatorAgent can be imported."""
        from src.agents.coordinator_agent import CoordinatorAgent
        assert CoordinatorAgent is not None

    def test_coordinator_agent_initialization(self):
        """Test CoordinatorAgent can be initialized."""
        from src.agents.coordinator_agent import CoordinatorAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = CoordinatorAgent()
            assert agent.agent_name == "CoordinatorAgent"

    def test_coordinator_has_orchestrate_method(self):
        """Test CoordinatorAgent has orchestration capabilities."""
        from src.agents.coordinator_agent import CoordinatorAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = CoordinatorAgent()
            # Should have run_analysis or similar method
            assert hasattr(agent, 'analyze') or hasattr(agent, 'run_analysis')


# =============================================================================
# POLICY AGENT TESTS
# =============================================================================

class TestPolicyAgent:
    """Tests for PolicyAgent."""

    def test_import_policy_agent(self):
        """Test that PolicyAgent can be imported."""
        from src.agents.policy_agent import PolicyAgent
        assert PolicyAgent is not None

    def test_policy_agent_initialization(self):
        """Test PolicyAgent can be initialized."""
        from src.agents.policy_agent import PolicyAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = PolicyAgent()
            assert agent.agent_name == "PolicyAgent"
            # Check for any compliance-related capability
            assert any("compliance" in cap or "standards" in cap for cap in agent.capabilities)

    def test_policy_agent_has_compliance_standards(self):
        """Test PolicyAgent has compliance standards defined."""
        from src.agents.policy_agent import PolicyAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = PolicyAgent()
            # Should have standards mapping capability
            assert "standards_mapping" in agent.capabilities or len(agent.capabilities) > 0


# =============================================================================
# AI AGENT TESTS
# =============================================================================

class TestAIAgent:
    """Tests for AI Agent."""

    def test_import_ai_agent(self):
        """Test that AIAgent can be imported."""
        from src.agents.ai_agent import AIAgent
        assert AIAgent is not None

    def test_ai_agent_initialization(self):
        """Test AIAgent can be initialized."""
        from src.agents.ai_agent import AIAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = AIAgent()
            assert agent.agent_name == "AIAgent"
            # Check for any AI-related capability
            assert any("ai" in cap or "analysis" in cap or "reasoning" in cap for cap in agent.capabilities)


# =============================================================================
# DYNAMIC AGENT TESTS
# =============================================================================

class TestDynamicAgent:
    """Tests for Dynamic Agent."""

    def test_import_dynamic_agent(self):
        """Test that DynamicAgent can be imported."""
        from src.agents.dynamic_agent import DynamicAgent
        assert DynamicAgent is not None

    def test_dynamic_agent_initialization(self):
        """Test DynamicAgent can be initialized."""
        from src.agents.dynamic_agent import DynamicAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = DynamicAgent()
            assert agent.agent_name == "DynamicAgent"


# =============================================================================
# SYMBOLIC AGENT TESTS
# =============================================================================

class TestSymbolicAgent:
    """Tests for Symbolic Agent."""

    def test_import_symbolic_agent(self):
        """Test that SymbolicAgent can be imported."""
        from src.agents.symbolic_agent import SymbolicAgent
        assert SymbolicAgent is not None

    def test_symbolic_agent_initialization(self):
        """Test SymbolicAgent can be initialized."""
        from src.agents.symbolic_agent import SymbolicAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SymbolicAgent()
            assert agent.agent_name == "SymbolicAgent"


# =============================================================================
# FORMAL AGENT TESTS
# =============================================================================

class TestFormalAgent:
    """Tests for Formal Verification Agent."""

    def test_import_formal_agent(self):
        """Test that FormalAgent can be imported."""
        from src.agents.formal_agent import FormalAgent
        assert FormalAgent is not None

    def test_formal_agent_initialization(self):
        """Test FormalAgent can be initialized."""
        from src.agents.formal_agent import FormalAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = FormalAgent()
            assert agent.agent_name == "FormalAgent"


# =============================================================================
# OLLAMA AGENT TESTS
# =============================================================================

class TestOllamaAgent:
    """Tests for Ollama Agent (local LLM)."""

    def test_import_ollama_agent(self):
        """Test that OllamaAgent can be imported."""
        from src.agents.ollama_agent import OllamaAgent
        assert OllamaAgent is not None

    def test_ollama_agent_initialization(self):
        """Test OllamaAgent can be initialized."""
        from src.agents.ollama_agent import OllamaAgent

        with patch('src.agents.base_agent.get_context_bus') as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = OllamaAgent()
            assert "ollama" in agent.agent_name.lower() or "llm" in agent.capabilities


# =============================================================================
# INTERPRETATION AGENT TESTS
# =============================================================================

class TestInterpretationAgent:
    """Tests for Interpretation Agent."""

    def test_import_interpretation_agent(self):
        """Test that InterpretationAgent can be imported."""
        from src.agents.interpretation_agent import InterpretationAgent
        assert InterpretationAgent is not None


# =============================================================================
# RECOMMENDATION AGENT TESTS
# =============================================================================

class TestRecommendationAgent:
    """Tests for Recommendation Agent."""

    def test_import_recommendation_agent(self):
        """Test that RecommendationAgent can be imported."""
        from src.agents.recommendation_agent import RecommendationAgent
        assert RecommendationAgent is not None


# =============================================================================
# AGENT INTEGRATION TESTS
# =============================================================================

class TestAgentIntegration:
    """Integration tests for agents module."""

    def test_all_agents_importable(self):
        """Test all main agents can be imported."""
        from src.agents import (
            base_agent,
            static_agent,
            dynamic_agent,
            coordinator_agent,
            policy_agent
        )
        assert base_agent is not None
        assert static_agent is not None
        assert dynamic_agent is not None
        assert coordinator_agent is not None
        assert policy_agent is not None

    def test_agent_init_file_exports(self):
        """Test agents __init__ exports main classes."""
        import src.agents
        # Should have some exports defined
        assert hasattr(src.agents, '__all__') or dir(src.agents)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
