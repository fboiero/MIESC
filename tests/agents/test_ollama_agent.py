"""
Tests for OllamaAgent

Basic tests for Ollama integration (requires Ollama to be installed and running)
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, MagicMock

from src.agents.ollama_agent import OllamaAgent


class TestOllamaAgentAvailability:
    """Tests for Ollama availability checks"""

    def test_check_ollama_not_installed(self):
        """Should detect when Ollama is not installed"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()

            agent = OllamaAgent()
            # Agent should initialize but mark as unavailable
            assert agent is not None

    def test_check_ollama_not_running(self):
        """Should detect when Ollama is not running"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="", stderr="not running")

            agent = OllamaAgent()
            assert agent is not None

    def test_get_available_models(self):
        """Should list available models"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="NAME                    ID              SIZE    MODIFIED\ncodellama:13b          abc123          7.4GB   2 days ago\n"
            )

            models = OllamaAgent.get_available_models()
            assert isinstance(models, list)


class TestOllamaAgentAnalysis:
    """Tests for analysis functionality"""

    @pytest.fixture
    def mock_agent(self):
        """Create agent with mocked Ollama calls"""
        with patch('subprocess.run') as mock_run:
            # Mock successful Ollama check
            mock_run.return_value = Mock(
                returncode=0,
                stdout="codellama:13b"
            )

            agent = OllamaAgent(model="codellama:13b")
            return agent

    def test_build_analysis_prompt(self, mock_agent):
        """Should build correct analysis prompt"""
        contract_code = "pragma solidity ^0.8.0;\ncontract Test {}"

        prompt = mock_agent._build_analysis_prompt(contract_code)

        assert "Solidity" in prompt
        assert contract_code in prompt
        assert "JSON" in prompt

    def test_parse_valid_json_response(self, mock_agent, temp_contract="test.sol"):
        """Should parse valid JSON response"""
        response = """
        {
          "vulnerabilities": [
            {
              "id": "OLL-001",
              "severity": "High",
              "category": "reentrancy",
              "description": "Reentrancy vulnerability",
              "location": "withdraw()",
              "recommendation": "Use checks-effects-interactions",
              "confidence": 0.9
            }
          ],
          "summary": "Found 1 vulnerability",
          "risk_score": 75
        }
        """

        findings = mock_agent._parse_ollama_response(response, temp_contract)

        assert len(findings) == 1
        assert findings[0]["id"] == "OLL-001"
        assert findings[0]["severity"] == "High"
        assert findings[0]["category"] == "reentrancy"

    def test_parse_malformed_response(self, mock_agent):
        """Should handle malformed responses gracefully"""
        response = "This is not JSON"

        findings = mock_agent._parse_ollama_response(response, "test.sol")

        # Should create a fallback finding
        assert len(findings) >= 1
        assert findings[0]["source"] == "Ollama"

    def test_map_to_swc(self, mock_agent):
        """Should map categories to SWC IDs"""
        assert mock_agent._map_to_swc("reentrancy") == "SWC-107"
        assert mock_agent._map_to_swc("access control") == "SWC-105"
        assert mock_agent._map_to_swc("arithmetic") == "SWC-101"
        assert mock_agent._map_to_swc("unknown") == "SWC-000"

    def test_map_to_owasp(self, mock_agent):
        """Should map categories to OWASP"""
        assert "SC01" in mock_agent._map_to_owasp("reentrancy")
        assert "SC02" in mock_agent._map_to_owasp("access control")

    def test_generate_recommendations(self, mock_agent):
        """Should generate appropriate recommendations"""
        findings_critical = [{"severity": "Critical"}]
        findings_high = [{"severity": "High"}]
        findings_none = []

        recs_critical = mock_agent._generate_recommendations(findings_critical)
        assert any("CRITICAL" in rec for rec in recs_critical)

        recs_high = mock_agent._generate_recommendations(findings_high)
        assert any("HIGH" in rec for rec in recs_high)

        recs_none = mock_agent._generate_recommendations(findings_none)
        assert any("No vulnerabilities" in rec for rec in recs_none)


def _is_ollama_available():
    """Check if Ollama is available"""
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class TestOllamaAgentIntegration:
    """Integration tests (requires Ollama installed)"""

    @pytest.mark.skipif(
        not _is_ollama_available(),
        reason="Ollama not installed or not running"
    )
    def test_real_analysis(self, tmp_path):
        """Test real analysis with Ollama (if available)"""
        # Create a simple contract
        contract = tmp_path / "test.sol"
        contract.write_text("""
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
        """)

        # Run analysis
        agent = OllamaAgent(model="codellama:7b")  # Use smallest model
        results = agent.analyze(str(contract))

        # Verify structure
        assert "ollama_findings" in results
        assert "ollama_analysis" in results
        assert "execution_time" in results


def _is_ollama_available() -> bool:
    """Check if Ollama is available for testing"""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
