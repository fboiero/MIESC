"""
Tests for the LLM Report Interpreter module.

Tests cover:
- LLMInterpreterConfig dataclass
- LLMReportInterpreter class methods
- Convenience functions
All tests use mocking to avoid external LLM calls.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.reports.llm_interpreter import (
    LLMInterpreterConfig,
    LLMReportInterpreter,
    generate_llm_report_insights,
    generate_premium_report_insights,
)

# =============================================================================
# LLMInterpreterConfig Tests
# =============================================================================


class TestLLMInterpreterConfig:
    """Tests for LLMInterpreterConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = LLMInterpreterConfig()
        assert config.model == "mistral:latest"
        assert config.ollama_host == "http://localhost:11434"
        assert config.temperature == 0.2
        assert config.max_tokens == 2000
        assert config.timeout == 180
        assert config.retry_attempts == 2
        assert config.retry_delay == 2.0

    def test_custom_values(self):
        """Test custom configuration values."""
        config = LLMInterpreterConfig(
            model="deepseek-coder:6.7b",
            ollama_host="http://custom:8080",
            temperature=0.5,
            max_tokens=4000,
            timeout=300,
            retry_attempts=3,
            retry_delay=5.0,
        )
        assert config.model == "deepseek-coder:6.7b"
        assert config.ollama_host == "http://custom:8080"
        assert config.temperature == 0.5
        assert config.max_tokens == 4000
        assert config.timeout == 300
        assert config.retry_attempts == 3
        assert config.retry_delay == 5.0


# =============================================================================
# LLMReportInterpreter Tests
# =============================================================================


class TestLLMReportInterpreterInit:
    """Tests for LLMReportInterpreter initialization."""

    def test_default_init(self):
        """Test default initialization."""
        interpreter = LLMReportInterpreter()
        assert interpreter.config.model == "mistral:latest"
        assert interpreter.config.ollama_host == "http://localhost:11434"
        assert interpreter._available is None

    def test_custom_config(self):
        """Test initialization with custom config."""
        config = LLMInterpreterConfig(model="llama2:7b")
        interpreter = LLMReportInterpreter(config)
        assert interpreter.config.model == "llama2:7b"

    @patch.dict("os.environ", {"OLLAMA_HOST": "http://env-host:11434"})
    def test_env_override_host(self):
        """Test environment variable overrides host."""
        interpreter = LLMReportInterpreter()
        assert interpreter.config.ollama_host == "http://env-host:11434"

    @patch.dict("os.environ", {"MIESC_LLM_MODEL": "env-model:latest"})
    def test_env_override_model(self):
        """Test environment variable overrides model."""
        interpreter = LLMReportInterpreter()
        assert interpreter.config.model == "env-model:latest"


class TestLLMReportInterpreterAvailability:
    """Tests for is_available method."""

    def test_is_available_caches_result(self):
        """Test that availability check is cached."""
        interpreter = LLMReportInterpreter()
        interpreter._available = True
        assert interpreter.is_available() is True

        interpreter._available = False
        assert interpreter.is_available() is False

    @patch("urllib.request.urlopen")
    def test_is_available_model_found(self, mock_urlopen):
        """Test availability when model is found."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"models": [{"name": "mistral:latest"}, {"name": "llama2:7b"}]}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        interpreter = LLMReportInterpreter()
        assert interpreter.is_available() is True

    @patch("urllib.request.urlopen")
    def test_is_available_model_not_found_but_ollama_running(self, mock_urlopen):
        """Test availability when Ollama is running but model not found."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"models": [{"name": "llama2:7b"}]}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        interpreter = LLMReportInterpreter()
        # Should still return True (will attempt to use anyway)
        assert interpreter.is_available() is True

    @patch("urllib.request.urlopen")
    def test_is_available_url_error(self, mock_urlopen):
        """Test availability when URL error occurs."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        interpreter = LLMReportInterpreter()
        assert interpreter.is_available() is False

    @patch("urllib.request.urlopen")
    def test_is_available_generic_exception(self, mock_urlopen):
        """Test availability when generic exception occurs."""
        mock_urlopen.side_effect = Exception("Some error")

        interpreter = LLMReportInterpreter()
        assert interpreter.is_available() is False


class TestGenerateExecutiveInterpretation:
    """Tests for generate_executive_interpretation method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty string when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_executive_interpretation(
            [{"type": "reentrancy"}], {"critical": 1}, "TestContract"
        )
        assert result == ""

    def test_returns_empty_when_no_findings(self, interpreter):
        """Test returns empty string when no findings."""
        result = interpreter.generate_executive_interpretation([], {"critical": 0}, "TestContract")
        assert result == ""

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_generates_summary(self, mock_call_llm, interpreter):
        """Test generates executive summary."""
        mock_call_llm.return_value = "This is an executive summary."

        findings = [
            {"type": "reentrancy", "severity": "critical", "title": "Reentrancy Attack"},
            {"type": "access-control", "severity": "high", "message": "Missing check"},
        ]
        summary = {"critical": 1, "high": 1, "medium": 0, "low": 0}

        result = interpreter.generate_executive_interpretation(findings, summary, "VaultContract")

        assert result == "This is an executive summary."
        mock_call_llm.assert_called_once()
        # Verify prompt contains contract name
        call_args = mock_call_llm.call_args[0][0]
        assert "VaultContract" in call_args
        assert "Critical: 1" in call_args

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_returns_empty_when_llm_returns_none(self, mock_call_llm, interpreter):
        """Test returns empty string when LLM returns None."""
        mock_call_llm.return_value = None

        result = interpreter.generate_executive_interpretation(
            [{"type": "reentrancy"}], {"critical": 1}, "Contract"
        )
        assert result == ""


class TestGenerateRiskNarrative:
    """Tests for generate_risk_narrative method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty string when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_risk_narrative({"critical": 1}, [{"type": "reentrancy"}])
        assert result == ""

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_generates_narrative(self, mock_call_llm, interpreter):
        """Test generates risk narrative."""
        mock_call_llm.return_value = "Risk narrative text."

        findings = [
            {"type": "reentrancy", "category": "Reentrancy"},
            {"category": "Access Control"},
            {"type": "gas", "category": "Gas Optimization"},
        ]
        summary = {"critical": 1, "high": 0, "medium": 2}

        result = interpreter.generate_risk_narrative(summary, findings)

        assert result == "Risk narrative text."
        mock_call_llm.assert_called_once()


class TestInterpretCriticalFindings:
    """Tests for interpret_critical_findings method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_original_when_not_available(self):
        """Test returns original findings when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        findings = [{"type": "reentrancy", "severity": "critical"}]
        result = interpreter.interpret_critical_findings(findings)
        assert result == findings

    def test_returns_original_when_empty_findings(self, interpreter):
        """Test returns original (empty) when no findings."""
        result = interpreter.interpret_critical_findings([])
        assert result == []

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_interprets_findings(self, mock_call_llm, interpreter):
        """Test interprets critical findings."""
        mock_call_llm.return_value = "This vulnerability is dangerous because..."

        findings = [
            {
                "title": "Reentrancy",
                "severity": "critical",
                "description": "Reentrancy attack possible",
                "location": {"file": "Vault.sol", "line": 42},
            }
        ]

        result = interpreter.interpret_critical_findings(findings)

        assert len(result) == 1
        assert result[0]["title"] == "Reentrancy"
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["location"] == "Vault.sol:42"
        assert result[0]["llm_interpretation"] == "This vulnerability is dangerous because..."

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_handles_string_location(self, mock_call_llm, interpreter):
        """Test handles string location format."""
        mock_call_llm.return_value = "Analysis"

        findings = [{"type": "access-control", "severity": "high", "location": "Line 50"}]

        result = interpreter.interpret_critical_findings(findings)

        assert result[0]["location"] == "Line 50"

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_limits_to_five_findings(self, mock_call_llm, interpreter):
        """Test limits interpretation to 5 findings."""
        mock_call_llm.return_value = "Analysis"

        findings = [{"type": f"vuln-{i}", "severity": "critical"} for i in range(10)]

        result = interpreter.interpret_critical_findings(findings)

        assert len(result) == 5


class TestSuggestRemediationPriority:
    """Tests for suggest_remediation_priority method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty list when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.suggest_remediation_priority([{"type": "reentrancy"}])
        assert result == []

    def test_returns_empty_when_no_findings(self, interpreter):
        """Test returns empty list when no findings."""
        result = interpreter.suggest_remediation_priority([])
        assert result == []

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_parses_priority_response(self, mock_call_llm, interpreter):
        """Test parses priority response correctly."""
        mock_call_llm.return_value = json.dumps(
            {
                "priorities": [
                    {"index": 1, "priority": 1, "reason": "Most critical"},
                    {"index": 2, "priority": 2, "reason": "High severity"},
                ]
            }
        )

        findings = [
            {"title": "Reentrancy", "severity": "critical"},
            {"title": "Access Control", "severity": "high"},
        ]

        result = interpreter.suggest_remediation_priority(findings)

        assert len(result) == 2
        assert result[0]["priority"] == 1
        assert result[0]["title"] == "Reentrancy"
        assert result[1]["priority"] == 2

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_returns_empty_when_llm_returns_none(self, mock_call_llm, interpreter):
        """Test returns empty list when LLM returns None."""
        mock_call_llm.return_value = None

        result = interpreter.suggest_remediation_priority([{"type": "reentrancy"}])
        assert result == []

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_returns_empty_on_invalid_json(self, mock_call_llm, interpreter):
        """Test returns empty list on invalid JSON."""
        mock_call_llm.return_value = "Not valid JSON {"

        result = interpreter.suggest_remediation_priority([{"type": "reentrancy"}])
        assert result == []


class TestGenerateToolOutputExplanation:
    """Tests for generate_tool_output_explanation method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty string when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_tool_output_explanation("Slither", "output")
        assert result == ""

    def test_returns_empty_when_no_output(self, interpreter):
        """Test returns empty string when no tool output."""
        result = interpreter.generate_tool_output_explanation("Slither", "")
        assert result == ""

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_generates_explanation(self, mock_call_llm, interpreter):
        """Test generates tool output explanation."""
        mock_call_llm.return_value = "The tool found a reentrancy issue."

        result = interpreter.generate_tool_output_explanation(
            "Slither", "Reentrancy vulnerability detected in withdraw()"
        )

        assert result == "The tool found a reentrancy issue."
        mock_call_llm.assert_called_once()


class TestGenerateAttackScenario:
    """Tests for generate_attack_scenario method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty dict when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_attack_scenario({"type": "reentrancy"})
        assert result == {}

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_parses_attack_scenario(self, mock_call_llm, interpreter):
        """Test parses attack scenario response."""
        mock_call_llm.return_value = json.dumps(
            {
                "scenario_description": "Attacker exploits reentrancy",
                "prerequisites": ["ETH in contract"],
                "attack_steps": ["Deploy malicious contract", "Call withdraw"],
                "expected_outcome": "Drain funds",
                "financial_impact": "Total loss",
                "difficulty": "Medium",
            }
        )

        finding = {
            "title": "Reentrancy",
            "severity": "critical",
            "description": "Reentrancy vulnerability",
            "location": {"file": "Vault.sol", "line": 42},
        }

        result = interpreter.generate_attack_scenario(finding)

        assert result["scenario_description"] == "Attacker exploits reentrancy"
        assert result["difficulty"] == "Medium"
        assert len(result["attack_steps"]) == 2

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_returns_empty_on_invalid_json(self, mock_call_llm, interpreter):
        """Test returns empty dict on invalid JSON."""
        mock_call_llm.return_value = "Invalid {json"

        result = interpreter.generate_attack_scenario({"type": "reentrancy"})
        assert result == {}


class TestGenerateCodeRemediation:
    """Tests for generate_code_remediation method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_empty_when_not_available(self):
        """Test returns empty dict when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_code_remediation({"type": "reentrancy"}, "contract code")
        assert result == {}

    def test_returns_empty_when_no_code(self, interpreter):
        """Test returns empty dict when no contract code."""
        result = interpreter.generate_code_remediation({"type": "reentrancy"}, "")
        assert result == {}

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_parses_remediation(self, mock_call_llm, interpreter):
        """Test parses code remediation response."""
        mock_call_llm.return_value = json.dumps(
            {
                "vulnerable_code": "call{value: amount}('')",
                "fixed_code": "nonReentrant call{value: amount}('')",
                "diff": "- call{value: amount}('')\n+ nonReentrant call{value: amount}('')",
                "explanation": "Add reentrancy guard",
                "effort": "Low",
                "fix_time": "30 min",
            }
        )

        finding = {
            "title": "Reentrancy",
            "description": "Reentrancy issue",
            "location": {"line": 50},
        }
        code = "\n".join([f"line {i}" for i in range(100)])

        result = interpreter.generate_code_remediation(finding, code)

        assert result["effort"] == "Low"
        assert result["fix_time"] == "30 min"


class TestGenerateDeploymentRecommendation:
    """Tests for generate_deployment_recommendation method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    def test_returns_unknown_when_not_available(self):
        """Test returns UNKNOWN when LLM not available."""
        interpreter = LLMReportInterpreter()
        interpreter._available = False

        result = interpreter.generate_deployment_recommendation([], {})

        assert result["recommendation"] == "UNKNOWN"
        assert "not available" in result["justification"]

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_parses_go_recommendation(self, mock_call_llm, interpreter):
        """Test parses GO recommendation."""
        mock_call_llm.return_value = json.dumps(
            {
                "recommendation": "GO",
                "justification": "No critical issues",
                "risk_level": "Low",
                "action_items": ["Deploy to testnet first"],
                "conditions": [],
                "timeline": "Immediate",
            }
        )

        result = interpreter.generate_deployment_recommendation([], {"critical": 0})

        assert result["recommendation"] == "GO"
        assert result["risk_level"] == "Low"

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_parses_nogo_recommendation(self, mock_call_llm, interpreter):
        """Test parses NO-GO recommendation."""
        mock_call_llm.return_value = json.dumps(
            {
                "recommendation": "NO-GO",
                "justification": "Critical issues found",
                "risk_level": "Critical",
                "action_items": ["Fix reentrancy", "Fix access control"],
                "conditions": [],
                "timeline": "2-3 weeks",
            }
        )

        findings = [{"type": "reentrancy", "severity": "critical"}]
        summary = {"critical": 1, "high": 2}

        result = interpreter.generate_deployment_recommendation(findings, summary)

        assert result["recommendation"] == "NO-GO"
        assert result["risk_level"] == "Critical"

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_returns_conditional_on_llm_failure(self, mock_call_llm, interpreter):
        """Test returns CONDITIONAL when LLM returns None."""
        mock_call_llm.return_value = None

        result = interpreter.generate_deployment_recommendation([], {})

        assert result["recommendation"] == "CONDITIONAL"


class TestGeneratePremiumFindingAnalysis:
    """Tests for generate_premium_finding_analysis method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    @patch.object(LLMReportInterpreter, "generate_attack_scenario")
    @patch.object(LLMReportInterpreter, "generate_code_remediation")
    def test_generates_complete_analysis(self, mock_remediation, mock_scenario, interpreter):
        """Test generates complete premium analysis."""
        mock_scenario.return_value = {
            "scenario_description": "Attack scenario",
            "attack_steps": ["Step 1", "Step 2"],
            "difficulty": "Medium",
        }
        mock_remediation.return_value = {
            "diff": "- old\n+ new",
            "effort": "Low",
            "fix_time": "1 hour",
        }

        finding = {
            "id": "VULN-001",
            "title": "Reentrancy",
            "severity": "critical",
        }
        code = "contract Vault { ... }"

        result = interpreter.generate_premium_finding_analysis(finding, code)

        assert result["finding_id"] == "VULN-001"
        assert result["title"] == "Reentrancy"
        assert result["attack_scenario"] == "Attack scenario"
        assert result["remediation_code"] == "- old\n+ new"

    @patch.object(LLMReportInterpreter, "generate_attack_scenario")
    def test_skips_attack_scenario_for_low_severity(self, mock_scenario, interpreter):
        """Test skips attack scenario for low/medium severity."""
        finding = {
            "id": "VULN-002",
            "title": "Gas Optimization",
            "severity": "low",
        }

        result = interpreter.generate_premium_finding_analysis(finding)

        mock_scenario.assert_not_called()
        assert "attack_scenario" not in result


class TestCallLLM:
    """Tests for _call_llm private method."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter instance."""
        return LLMReportInterpreter()

    @patch("urllib.request.urlopen")
    def test_successful_call(self, mock_urlopen, interpreter):
        """Test successful LLM call."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"response": "Generated text"}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = interpreter._call_llm("Test prompt")

        assert result == "Generated text"

    @patch("urllib.request.urlopen")
    def test_empty_response_triggers_retry(self, mock_urlopen, interpreter):
        """Test empty response triggers retry."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"response": ""}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = interpreter._call_llm("Test prompt")

        assert result is None
        # Should have called twice (retry_attempts=2)
        assert mock_urlopen.call_count == 2

    @patch("urllib.request.urlopen")
    @patch("time.sleep")
    def test_url_error_triggers_retry(self, mock_sleep, mock_urlopen, interpreter):
        """Test URL error triggers retry with delay."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        result = interpreter._call_llm("Test prompt")

        assert result is None
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once_with(2.0)

    @patch("urllib.request.urlopen")
    @patch("time.sleep")
    def test_timeout_triggers_retry(self, mock_sleep, mock_urlopen, interpreter):
        """Test timeout triggers retry."""
        mock_urlopen.side_effect = TimeoutError("Timeout")

        result = interpreter._call_llm("Test prompt")

        assert result is None


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestGenerateLLMReportInsights:
    """Tests for generate_llm_report_insights convenience function."""

    @patch.object(LLMReportInterpreter, "is_available")
    def test_returns_unavailable_when_llm_not_available(self, mock_available):
        """Test returns unavailable when LLM not available."""
        mock_available.return_value = False

        result = generate_llm_report_insights([], {}, "Contract")

        assert result["available"] is False

    @patch.object(LLMReportInterpreter, "is_available")
    @patch.object(LLMReportInterpreter, "generate_executive_interpretation")
    @patch.object(LLMReportInterpreter, "generate_risk_narrative")
    @patch.object(LLMReportInterpreter, "interpret_critical_findings")
    @patch.object(LLMReportInterpreter, "suggest_remediation_priority")
    def test_generates_all_insights(
        self,
        mock_priority,
        mock_interpret,
        mock_narrative,
        mock_executive,
        mock_available,
    ):
        """Test generates all insights when available."""
        mock_available.return_value = True
        mock_executive.return_value = "Executive summary"
        mock_narrative.return_value = "Risk narrative"
        mock_interpret.return_value = [{"title": "Reentrancy", "llm_interpretation": "Analysis"}]
        mock_priority.return_value = [{"priority": 1, "title": "Reentrancy"}]

        findings = [{"type": "reentrancy", "severity": "critical"}]
        summary = {"critical": 1}

        result = generate_llm_report_insights(findings, summary, "Contract")

        assert result["available"] is True
        assert result["executive_summary"] == "Executive summary"
        assert result["risk_narrative"] == "Risk narrative"
        assert len(result["critical_interpretations"]) == 1
        assert len(result["remediation_priority"]) == 1


class TestGeneratePremiumReportInsights:
    """Tests for generate_premium_report_insights convenience function."""

    @patch.object(LLMReportInterpreter, "is_available")
    def test_returns_unavailable_when_llm_not_available(self, mock_available):
        """Test returns unavailable when LLM not available."""
        mock_available.return_value = False

        result = generate_premium_report_insights([], {}, "Contract")

        assert result["available"] is False

    @patch("src.reports.llm_interpreter.generate_llm_report_insights")
    @patch.object(LLMReportInterpreter, "is_available")
    @patch.object(LLMReportInterpreter, "generate_deployment_recommendation")
    @patch.object(LLMReportInterpreter, "generate_attack_scenario")
    @patch.object(LLMReportInterpreter, "generate_code_remediation")
    def test_generates_premium_insights(
        self,
        mock_remediation,
        mock_scenario,
        mock_deployment,
        mock_available,
        mock_standard,
    ):
        """Test generates premium insights."""
        mock_available.return_value = True
        mock_standard.return_value = {
            "available": True,
            "executive_summary": "Summary",
            "risk_narrative": "Narrative",
            "critical_interpretations": [],
            "remediation_priority": [],
        }
        mock_deployment.return_value = {
            "recommendation": "CONDITIONAL",
            "justification": "Some issues",
            "risk_level": "Medium",
            "action_items": ["Fix issues"],
            "conditions": ["After fixing"],
            "timeline": "1 week",
        }
        mock_scenario.return_value = {
            "scenario_description": "Attack",
            "attack_steps": ["Step 1"],
        }
        mock_remediation.return_value = {}

        findings = [{"type": "reentrancy", "severity": "critical", "id": "001"}]
        summary = {"critical": 1}

        result = generate_premium_report_insights(findings, summary, "Contract", "code")

        assert result["available"] is True
        assert result["deployment_recommendation"] == "CONDITIONAL"
        assert result["deployment_justification"] == "Some issues"
        assert len(result["attack_scenarios"]) == 1


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Edge case tests for LLM Interpreter."""

    @pytest.fixture
    def interpreter(self):
        """Create interpreter with mocked availability."""
        interp = LLMReportInterpreter()
        interp._available = True
        return interp

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_handles_very_long_description(self, mock_call_llm, interpreter):
        """Test handles very long description."""
        mock_call_llm.return_value = "Analysis"

        finding = {
            "title": "Reentrancy",
            "description": "A" * 10000,
            "severity": "critical",
        }

        result = interpreter.interpret_critical_findings([finding])

        assert len(result) == 1
        # Description should be truncated
        assert len(result[0]["original_description"]) <= 500

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_handles_unicode_in_findings(self, mock_call_llm, interpreter):
        """Test handles unicode characters."""
        mock_call_llm.return_value = "Analysis"

        finding = {
            "title": "Vulnerabilidad de reentrancy",
            "description": "Vulnerabilidad detectada",
            "severity": "high",
        }

        result = interpreter.interpret_critical_findings([finding])

        assert len(result) == 1
        assert result[0]["title"] == "Vulnerabilidad de reentrancy"

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_handles_missing_optional_fields(self, mock_call_llm, interpreter):
        """Test handles missing optional fields in finding."""
        mock_call_llm.return_value = "Analysis"

        finding = {}  # Empty finding

        result = interpreter.interpret_critical_findings([finding])

        assert len(result) == 1
        assert result[0]["title"] == "Unknown"
        assert result[0]["severity"] == "UNKNOWN"

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_extracts_json_from_mixed_response(self, mock_call_llm, interpreter):
        """Test extracts JSON from response with text around it."""
        mock_call_llm.return_value = """
        Here is the analysis:
        {"priorities": [{"index": 1, "priority": 1, "reason": "Critical"}]}
        Based on the above...
        """

        findings = [{"title": "Reentrancy", "severity": "critical"}]
        result = interpreter.suggest_remediation_priority(findings)

        assert len(result) == 1
        assert result[0]["priority"] == 1

    @patch.object(LLMReportInterpreter, "_call_llm")
    def test_handles_invalid_index_in_priority(self, mock_call_llm, interpreter):
        """Test handles invalid index in priority response."""
        mock_call_llm.return_value = json.dumps(
            {
                "priorities": [
                    {"index": 1, "priority": 1, "reason": "Valid"},
                    {"index": 999, "priority": 2, "reason": "Invalid index"},
                ]
            }
        )

        findings = [{"title": "Reentrancy", "severity": "critical"}]
        result = interpreter.suggest_remediation_priority(findings)

        # Should only include valid index
        assert len(result) == 1

    def test_config_values_are_configurable(self):
        """Test all config values can be customized."""
        config = LLMInterpreterConfig(
            model="custom-model",
            ollama_host="http://custom:1234",
            temperature=0.9,
            max_tokens=8000,
            timeout=600,
            retry_attempts=5,
            retry_delay=10.0,
        )
        interpreter = LLMReportInterpreter(config)

        assert interpreter.config.model == "custom-model"
        assert interpreter.config.max_tokens == 8000
        assert interpreter.config.retry_attempts == 5
