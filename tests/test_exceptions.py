"""
Tests for MIESC exception module.

Tests the centralized exception handling system including:
- Exception hierarchy
- Error codes
- Suggestions system
- Factory functions
"""

import pytest
from src.core.exceptions import (
    MIESCException,
    ToolAdapterError,
    AnalysisError,
    AnalysisTimeoutError,
    ConfigurationError,
    SecurityError,
    ContractError,
    APIError,
    ModelError,
    ErrorCode,
    tool_not_available,
    contract_not_found,
    analysis_timeout,
    TOOL_INSTALL_SUGGESTIONS,
)


class TestMIESCException:
    """Test base exception class."""

    def test_basic_exception(self):
        """Test creating a basic exception."""
        exc = MIESCException("Test error")
        assert exc.message == "Test error"
        assert exc.error_code == ErrorCode.UNKNOWN_ERROR.value
        assert exc.suggestions == []
        assert exc.context == {}

    def test_exception_with_code(self):
        """Test exception with specific error code."""
        exc = MIESCException("Test", error_code=ErrorCode.TOOL_NOT_FOUND)
        assert exc.error_code == "E101"

    def test_exception_with_suggestions(self):
        """Test exception with suggestions."""
        exc = MIESCException(
            "Test",
            suggestions=["Try this", "Or this"]
        )
        assert len(exc.suggestions) == 2
        assert "Try this" in exc.suggestions

    def test_exception_with_context(self):
        """Test exception with context."""
        exc = MIESCException(
            "Test",
            context={"tool": "slither", "version": "0.10.0"}
        )
        assert exc.context["tool"] == "slither"
        assert exc.context["version"] == "0.10.0"

    def test_str_representation(self):
        """Test string representation."""
        exc = MIESCException(
            "Test error",
            error_code=ErrorCode.TOOL_NOT_FOUND,
            suggestions=["Try pip install"]
        )
        str_repr = str(exc)
        assert "[E101]" in str_repr
        assert "Test error" in str_repr
        assert "Try pip install" in str_repr

    def test_to_dict(self):
        """Test dictionary conversion."""
        exc = MIESCException(
            "Test",
            error_code=ErrorCode.ANALYSIS_FAILED,
            suggestions=["Check logs"],
            context={"layer": 1}
        )
        d = exc.to_dict()
        assert d["error"] is True
        assert d["error_code"] == "E201"
        assert d["message"] == "Test"
        assert d["suggestions"] == ["Check logs"]
        assert d["context"]["layer"] == 1


class TestToolAdapterError:
    """Test tool adapter exceptions."""

    def test_basic_tool_error(self):
        """Test basic tool adapter error."""
        exc = ToolAdapterError(
            "Slither failed",
            tool_name="slither"
        )
        assert exc.tool_name == "slither"
        assert exc.error_code == ErrorCode.TOOL_EXECUTION_FAILED.value

    def test_tool_with_version(self):
        """Test tool error with version info."""
        exc = ToolAdapterError(
            "Failed",
            tool_name="mythril",
            tool_version="0.24.0"
        )
        assert exc.tool_version == "0.24.0"
        assert exc.context["tool_version"] == "0.24.0"

    def test_auto_suggestions_for_not_found(self):
        """Test automatic installation suggestions."""
        exc = ToolAdapterError(
            "Not installed",
            tool_name="slither",
            error_code=ErrorCode.TOOL_NOT_FOUND
        )
        assert any("pip install slither-analyzer" in s for s in exc.suggestions)

    def test_mythril_suggestions(self):
        """Test Mythril-specific suggestions."""
        exc = ToolAdapterError(
            "Not available",
            tool_name="mythril",
            error_code=ErrorCode.TOOL_NOT_AVAILABLE
        )
        assert any("pip install mythril" in s for s in exc.suggestions)
        assert any("docker" in s for s in exc.suggestions)

    def test_unknown_tool_no_suggestions(self):
        """Test unknown tool has no auto-suggestions."""
        exc = ToolAdapterError(
            "Failed",
            tool_name="unknown_tool",
            error_code=ErrorCode.TOOL_NOT_FOUND
        )
        # Should not crash, just have empty or custom suggestions
        assert isinstance(exc.suggestions, list)


class TestAnalysisError:
    """Test analysis exceptions."""

    def test_basic_analysis_error(self):
        """Test basic analysis error."""
        exc = AnalysisError("Analysis failed")
        assert exc.error_code == ErrorCode.ANALYSIS_FAILED.value

    def test_with_contract_path(self):
        """Test with contract path."""
        exc = AnalysisError(
            "Failed",
            contract_path="/path/to/Token.sol"
        )
        assert exc.contract_path == "/path/to/Token.sol"
        assert exc.context["contract_path"] == "/path/to/Token.sol"

    def test_with_layer(self):
        """Test with layer information."""
        exc = AnalysisError(
            "Layer 3 failed",
            layer=3
        )
        assert exc.layer == 3
        assert exc.context["layer"] == 3


class TestAnalysisTimeoutError:
    """Test timeout exceptions."""

    def test_timeout_error(self):
        """Test timeout error creation."""
        exc = AnalysisTimeoutError(
            "Timed out",
            timeout_seconds=300
        )
        assert exc.timeout_seconds == 300
        assert exc.error_code == ErrorCode.ANALYSIS_TIMEOUT.value

    def test_timeout_suggestions(self):
        """Test timeout has helpful suggestions."""
        exc = AnalysisTimeoutError(
            "Timed out",
            timeout_seconds=300,
            tool_name="mythril"
        )
        assert any("600" in s for s in exc.suggestions)  # 2x timeout
        assert any("smaller contract" in s for s in exc.suggestions)

    def test_timeout_context(self):
        """Test timeout context includes tool."""
        exc = AnalysisTimeoutError(
            "Timed out",
            timeout_seconds=120,
            tool_name="manticore",
            contract_path="/path/test.sol"
        )
        assert exc.context["tool_name"] == "manticore"
        assert exc.context["timeout_seconds"] == 120


class TestConfigurationError:
    """Test configuration exceptions."""

    def test_basic_config_error(self):
        """Test basic configuration error."""
        exc = ConfigurationError("Invalid config")
        assert exc.error_code == ErrorCode.CONFIG_INVALID.value

    def test_with_config_key(self):
        """Test with config key."""
        exc = ConfigurationError(
            "Missing key",
            config_key="layers.static.timeout"
        )
        assert exc.config_key == "layers.static.timeout"

    def test_with_config_file(self):
        """Test with config file path."""
        exc = ConfigurationError(
            "Invalid YAML",
            config_file="/path/miesc.yaml"
        )
        assert any("miesc.yaml" in s for s in exc.suggestions)

    def test_validate_suggestion(self):
        """Test suggests validation command."""
        exc = ConfigurationError("Bad config")
        assert any("miesc config validate" in s for s in exc.suggestions)


class TestSecurityError:
    """Test security exceptions."""

    def test_security_error(self):
        """Test security error."""
        exc = SecurityError(
            "Path traversal detected",
            error_code=ErrorCode.PATH_TRAVERSAL_DETECTED
        )
        assert exc.error_code == "E402"


class TestContractError:
    """Test contract exceptions."""

    def test_contract_not_found(self):
        """Test contract not found error."""
        exc = ContractError(
            "File not found",
            contract_path="/path/Token.sol"
        )
        assert exc.contract_path == "/path/Token.sol"
        assert any("ls -la" in s for s in exc.suggestions)
        assert any(".sol" in s for s in exc.suggestions)


class TestAPIError:
    """Test API exceptions."""

    def test_api_error(self):
        """Test API error with status code."""
        exc = APIError(
            "Request failed",
            status_code=500,
            endpoint="/api/v1/analyze"
        )
        assert exc.status_code == 500
        assert exc.endpoint == "/api/v1/analyze"
        assert exc.context["status_code"] == 500


class TestModelError:
    """Test ML/AI model exceptions."""

    def test_model_error(self):
        """Test model error."""
        exc = ModelError(
            "Inference failed",
            model_name="deepseek-coder"
        )
        assert exc.model_name == "deepseek-coder"

    def test_ollama_suggestions(self):
        """Test Ollama-specific suggestions."""
        exc = ModelError(
            "Model not found",
            model_name="ollama:deepseek"
        )
        assert any("ollama serve" in s for s in exc.suggestions)
        assert any("ollama pull" in s for s in exc.suggestions)


class TestFactoryFunctions:
    """Test exception factory functions."""

    def test_tool_not_available_factory(self):
        """Test tool_not_available factory."""
        exc = tool_not_available("slither", "not installed")
        assert isinstance(exc, ToolAdapterError)
        assert "slither" in exc.message
        assert "not installed" in exc.message

    def test_contract_not_found_factory(self):
        """Test contract_not_found factory."""
        exc = contract_not_found("/path/Token.sol")
        assert isinstance(exc, ContractError)
        assert "/path/Token.sol" in exc.message

    def test_analysis_timeout_factory(self):
        """Test analysis_timeout factory."""
        exc = analysis_timeout("mythril", 300, "/path/test.sol")
        assert isinstance(exc, AnalysisTimeoutError)
        assert exc.timeout_seconds == 300
        assert "mythril" in exc.message


class TestErrorCodes:
    """Test error code enum."""

    def test_all_codes_unique(self):
        """Test all error codes are unique."""
        values = [code.value for code in ErrorCode]
        assert len(values) == len(set(values))

    def test_code_format(self):
        """Test error code format."""
        for code in ErrorCode:
            assert code.value.startswith("E")
            assert len(code.value) == 4
            assert code.value[1:].isdigit()

    def test_code_categories(self):
        """Test error codes are categorized correctly."""
        # Tool errors: 1xx
        assert ErrorCode.TOOL_NOT_FOUND.value.startswith("E1")
        # Analysis errors: 2xx
        assert ErrorCode.ANALYSIS_FAILED.value.startswith("E2")
        # Config errors: 3xx
        assert ErrorCode.CONFIG_INVALID.value.startswith("E3")
        # Security errors: 4xx
        assert ErrorCode.SECURITY_VALIDATION_FAILED.value.startswith("E4")


class TestToolInstallSuggestions:
    """Test tool installation suggestions dictionary."""

    def test_common_tools_have_suggestions(self):
        """Test common tools have suggestions."""
        common_tools = ["slither", "mythril", "echidna", "foundry"]
        for tool in common_tools:
            assert tool in TOOL_INSTALL_SUGGESTIONS
            assert len(TOOL_INSTALL_SUGGESTIONS[tool]) > 0

    def test_suggestions_are_strings(self):
        """Test all suggestions are strings."""
        for tool, suggestions in TOOL_INSTALL_SUGGESTIONS.items():
            assert isinstance(suggestions, list)
            for s in suggestions:
                assert isinstance(s, str)


class TestExceptionInheritance:
    """Test exception inheritance."""

    def test_all_inherit_from_base(self):
        """Test all exceptions inherit from MIESCException."""
        exceptions = [
            ToolAdapterError("test", "tool"),
            AnalysisError("test"),
            AnalysisTimeoutError("test", 100),
            ConfigurationError("test"),
            SecurityError("test"),
            ContractError("test", "/path"),
            APIError("test"),
            ModelError("test"),
        ]
        for exc in exceptions:
            assert isinstance(exc, MIESCException)
            assert isinstance(exc, Exception)

    def test_can_catch_with_base(self):
        """Test can catch all with base exception."""
        def raise_tool_error():
            raise ToolAdapterError("test", "tool")

        with pytest.raises(MIESCException):
            raise_tool_error()
