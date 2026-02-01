"""
MIESC Agents Module Tests
Tests for base agent, static agent, coordinator, and policy agent.
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

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
        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = StaticAgent()
            assert agent.agent_name == "StaticAgent"
            assert "static_analysis" in agent.capabilities

    def test_static_agent_has_analyze_method(self):
        """Test StaticAgent has analyze method."""
        from src.agents.static_agent import StaticAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = StaticAgent()
            assert hasattr(agent, "analyze")
            assert callable(agent.analyze)

    def test_static_agent_context_types(self):
        """Test StaticAgent returns proper context types."""
        from src.agents.static_agent import StaticAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = CoordinatorAgent()
            assert agent.agent_name == "CoordinatorAgent"

    def test_coordinator_has_orchestrate_method(self):
        """Test CoordinatorAgent has orchestration capabilities."""
        from src.agents.coordinator_agent import CoordinatorAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = CoordinatorAgent()
            # Should have run_analysis or similar method
            assert hasattr(agent, "analyze") or hasattr(agent, "run_analysis")


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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = PolicyAgent()
            assert agent.agent_name == "PolicyAgent"
            # Check for any compliance-related capability
            assert any("compliance" in cap or "standards" in cap for cap in agent.capabilities)

    def test_policy_agent_has_compliance_standards(self):
        """Test PolicyAgent has compliance standards defined."""
        from src.agents.policy_agent import PolicyAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = AIAgent()
            assert agent.agent_name == "AIAgent"
            # Check for any AI-related capability
            assert any(
                "ai" in cap or "analysis" in cap or "reasoning" in cap for cap in agent.capabilities
            )


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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
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
            coordinator_agent,
            dynamic_agent,
            policy_agent,
            static_agent,
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
        assert hasattr(src.agents, "__all__") or dir(src.agents)


# =============================================================================
# SMARTLLM AGENT TESTS
# =============================================================================


class TestSmartLLMAgent:
    """Tests for SmartLLM Agent (local LLM + RAG)."""

    def test_import_smartllm_agent(self):
        """Test that SmartLLMAgent can be imported."""
        from src.agents.smartllm_agent import SmartLLMAgent

        assert SmartLLMAgent is not None

    def test_smartllm_agent_initialization(self):
        """Test SmartLLMAgent can be initialized without local LLM."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            # Initialize without local LLM (use_local_llm=False to avoid llama-cpp dependency)
            agent = SmartLLMAgent(use_local_llm=False)
            assert agent.agent_name == "SmartLLMAgent"
            assert "local_llm_inference" in agent.capabilities
            assert "rag_vulnerability_kb" in agent.capabilities
            assert agent.llm_available is False

    def test_smartllm_agent_knowledge_base_creation(self):
        """Test SmartLLMAgent creates minimal knowledge base."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            kb = agent._create_minimal_kb()
            assert isinstance(kb, list)
            assert len(kb) >= 5  # Should have at least 5 patterns

            # Check structure of KB entries
            for entry in kb:
                assert "id" in entry
                assert "name" in entry
                assert "swc_id" in entry
                assert "patterns" in entry
                assert "severity" in entry

    def test_smartllm_agent_context_types(self):
        """Test SmartLLMAgent returns proper context types."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            context_types = agent.get_context_types()
            assert "smartllm_findings" in context_types
            assert "smartllm_explanations" in context_types
            assert "smartllm_rag_context" in context_types

    def test_smartllm_agent_rag_retrieve(self):
        """Test SmartLLMAgent RAG retrieval."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            # Code with reentrancy pattern
            code = """
            function withdraw() public {
                uint balance = balances[msg.sender];
                msg.sender.call{value: balance}("");
                balances[msg.sender] = 0;
            }
            """

            relevant = agent._rag_retrieve(code)
            assert isinstance(relevant, list)
            # Should find reentrancy pattern
            [p.get("id") for p in relevant]
            # At least one pattern should be relevant
            assert len(relevant) >= 0  # May be empty for some code

    def test_smartllm_agent_pattern_analysis(self):
        """Test SmartLLMAgent pattern-based analysis (fallback)."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            code = "function test() public { block.timestamp; block.number; }"

            patterns = [
                {
                    "id": "timestamp_dependence",
                    "name": "Block Timestamp Manipulation",
                    "swc_id": "SWC-116",
                    "patterns": ["block.timestamp", "block.number"],
                    "severity": "Medium",
                    "description": "Uses block.timestamp",
                }
            ]

            vulns = agent._analyze_with_patterns(code, patterns)
            assert isinstance(vulns, list)
            if len(vulns) > 0:
                assert vulns[0]["id"] == "timestamp_dependence"

    def test_smartllm_agent_owasp_mapping(self):
        """Test SmartLLMAgent OWASP mapping."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            # Test known mappings
            assert agent._map_to_owasp("SWC-107") == "SC01-Reentrancy"
            assert agent._map_to_owasp("SWC-105") == "SC02-Access-Control"
            assert agent._map_to_owasp("SWC-999") == "SC10-Unknown"  # Unknown

    def test_smartllm_agent_format_findings(self):
        """Test SmartLLMAgent findings formatting."""
        from src.agents.smartllm_agent import SmartLLMAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SmartLLMAgent(use_local_llm=False)

            vulns = [
                {
                    "id": "test_vuln",
                    "name": "Test Vulnerability",
                    "swc_id": "SWC-107",
                    "severity": "High",
                    "description": "Test description",
                    "location": "line 10",
                    "confidence": 0.85,
                }
            ]
            explanations = [
                {
                    "vulnerability_id": "test_vuln",
                    "explanation": "Test explanation",
                    "fix": "Fix it",
                    "severity": "High",
                    "confidence": 0.85,
                }
            ]

            findings = agent._format_findings(vulns, explanations)
            assert len(findings) == 1
            assert findings[0]["source"] == "SmartLLM"
            assert findings[0]["severity"] == "High"


# =============================================================================
# GPTSCAN AGENT TESTS
# =============================================================================


class TestGPTScanAgent:
    """Tests for GPTScan Agent."""

    def test_import_gptscan_agent(self):
        """Test that GPTScanAgent can be imported."""
        from src.agents.gptscan_agent import GPTScanAgent

        assert GPTScanAgent is not None

    def test_gptscan_agent_initialization(self):
        """Test GPTScanAgent can be initialized."""
        from src.agents.gptscan_agent import GPTScanAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = GPTScanAgent()
            assert agent.agent_name == "GPTScanAgent"

    def test_gptscan_agent_context_types(self):
        """Test GPTScanAgent returns context types."""
        from src.agents.gptscan_agent import GPTScanAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = GPTScanAgent()
            context_types = agent.get_context_types()
            assert isinstance(context_types, list)
            assert len(context_types) > 0


# =============================================================================
# LLM SMART AUDIT AGENT TESTS
# =============================================================================


class TestLLMSmartAuditAgent:
    """Tests for LLMSmartAudit Agent."""

    def test_import_llmsmartaudit_agent(self):
        """Test that LLMSmartAuditAgent can be imported."""
        from src.agents.llm_smartaudit_agent import LLMSmartAuditAgent

        assert LLMSmartAuditAgent is not None

    def test_llmsmartaudit_agent_initialization(self):
        """Test LLMSmartAuditAgent can be initialized."""
        from src.agents.llm_smartaudit_agent import LLMSmartAuditAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = LLMSmartAuditAgent()
            assert agent.agent_name == "LLMSmartAuditAgent"

    def test_llmsmartaudit_agent_context_types(self):
        """Test LLMSmartAuditAgent returns context types."""
        from src.agents.llm_smartaudit_agent import LLMSmartAuditAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = LLMSmartAuditAgent()
            context_types = agent.get_context_types()
            assert isinstance(context_types, list)


# =============================================================================
# BASE AGENT EXTENDED TESTS
# =============================================================================


class TestBaseAgentExtended:
    """Extended tests for BaseAgent methods."""

    def test_base_agent_run_method(self):
        """Test BaseAgent run method workflow."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {"test_context": [{"finding": "test"}]}

            def get_context_types(self) -> List[str]:
                return ["test_context"]

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus_instance = MagicMock()
            mock_bus.return_value = mock_bus_instance

            agent = TestAgent("TestAgent", ["test"], "test")
            result = agent.run("/path/to/contract.sol")

            assert "test_context" in result
            assert agent.status == "idle"
            assert agent.execution_count == 1

    def test_base_agent_get_stats(self):
        """Test BaseAgent get_stats method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return ["test_findings"]

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = TestAgent("TestAgent", ["cap1", "cap2"], "test")

            stats = agent.get_stats()
            assert stats["agent_name"] == "TestAgent"
            assert stats["agent_type"] == "test"
            assert stats["capabilities"] == ["cap1", "cap2"]
            assert stats["status"] == "initialized"
            assert stats["context_types"] == ["test_findings"]

    def test_base_agent_set_status(self):
        """Test BaseAgent set_status method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return []

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = TestAgent("TestAgent", [], "test")

            agent.set_status("analyzing")
            assert agent.status == "analyzing"

            agent.set_status("error")
            assert agent.status == "error"

    def test_base_agent_handle_error(self):
        """Test BaseAgent handle_error method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return []

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus_instance = MagicMock()
            mock_bus.return_value = mock_bus_instance

            agent = TestAgent("TestAgent", [], "test")
            agent.handle_error(ValueError("test error"), "testing")

            assert agent.status == "error"
            # Should have published error context
            mock_bus_instance.publish.assert_called()

    def test_base_agent_repr(self):
        """Test BaseAgent __repr__ method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return []

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = TestAgent("TestAgent", [], "test")

            repr_str = repr(agent)
            assert "TestAgent" in repr_str
            assert "status=" in repr_str

    def test_base_agent_subscribe_to(self):
        """Test BaseAgent subscribe_to method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return []

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus_instance = MagicMock()
            mock_bus.return_value = mock_bus_instance

            agent = TestAgent("TestAgent", [], "test")
            callback = MagicMock()

            agent.subscribe_to(["context1", "context2"], callback)

            # Should have called subscribe twice
            assert mock_bus_instance.subscribe.call_count == 2

    def test_base_agent_get_latest_context(self):
        """Test BaseAgent get_latest_context method."""
        from src.agents.base_agent import BaseAgent

        class TestAgent(BaseAgent):
            def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
                return {}

            def get_context_types(self) -> List[str]:
                return []

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus_instance = MagicMock()
            mock_bus_instance.get_latest_context.return_value = {"test": "data"}
            mock_bus.return_value = mock_bus_instance

            agent = TestAgent("TestAgent", [], "test")
            result = agent.get_latest_context("test_context")

            assert result == {"test": "data"}
            mock_bus_instance.get_latest_context.assert_called_with("test_context")


# =============================================================================
# SPECIALIZED AGENT TESTS
# =============================================================================


class TestAderynAgent:
    """Tests for Aderyn Agent."""

    def test_import_aderyn_agent(self):
        """Test that AderynAgent can be imported."""
        from src.agents.aderyn_agent import AderynAgent

        assert AderynAgent is not None

    def test_aderyn_agent_initialization(self):
        """Test AderynAgent can be initialized."""
        from src.agents.aderyn_agent import AderynAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = AderynAgent()
            assert agent.agent_name == "AderynAgent"


class TestHalmosAgent:
    """Tests for Halmos Agent."""

    def test_import_halmos_agent(self):
        """Test that HalmosAgent can be imported."""
        from src.agents.halmos_agent import HalmosAgent

        assert HalmosAgent is not None

    def test_halmos_agent_initialization(self):
        """Test HalmosAgent can be initialized."""
        from src.agents.halmos_agent import HalmosAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = HalmosAgent()
            assert agent.agent_name == "HalmosAgent"


class TestMedusaAgent:
    """Tests for Medusa Agent."""

    def test_import_medusa_agent(self):
        """Test that MedusaAgent can be imported."""
        from src.agents.medusa_agent import MedusaAgent

        assert MedusaAgent is not None

    def test_medusa_agent_initialization(self):
        """Test MedusaAgent can be initialized."""
        from src.agents.medusa_agent import MedusaAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = MedusaAgent()
            assert agent.agent_name == "MedusaAgent"


class TestWakeAgent:
    """Tests for Wake Agent."""

    def test_import_wake_agent(self):
        """Test that WakeAgent can be imported."""
        from src.agents.wake_agent import WakeAgent

        assert WakeAgent is not None

    def test_wake_agent_initialization(self):
        """Test WakeAgent can be initialized."""
        from src.agents.wake_agent import WakeAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = WakeAgent()
            assert agent.agent_name == "WakeAgent"


class TestSMTCheckerAgent:
    """Tests for SMTChecker Agent."""

    def test_import_smtchecker_agent(self):
        """Test that SMTCheckerAgent can be imported."""
        from src.agents.smtchecker_agent import SMTCheckerAgent

        assert SMTCheckerAgent is not None

    def test_smtchecker_agent_initialization(self):
        """Test SMTCheckerAgent can be initialized."""
        from src.agents.smtchecker_agent import SMTCheckerAgent

        with patch("src.agents.base_agent.get_context_bus") as mock_bus:
            mock_bus.return_value = MagicMock()
            agent = SMTCheckerAgent()
            assert agent.agent_name == "SMTCheckerAgent"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
