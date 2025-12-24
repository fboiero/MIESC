"""
MIESC - Centralized Exception Module

This module provides a hierarchical exception system for MIESC with:
- Domain-specific exceptions for better error handling
- Error codes for programmatic error identification
- Suggestions for remediation
- Structured error context for debugging

Usage:
    from src.core.exceptions import ToolAdapterError, AnalysisTimeoutError

    raise ToolAdapterError(
        message="Slither not found",
        error_code="TOOL_NOT_FOUND",
        tool_name="slither",
        suggestions=["pip install slither-analyzer"]
    )
"""

from typing import List, Optional, Dict, Any
from enum import Enum


class ErrorCode(str, Enum):
    """Standard error codes for MIESC exceptions."""

    # Tool Adapter Errors (1xx)
    TOOL_NOT_FOUND = "E101"
    TOOL_NOT_AVAILABLE = "E102"
    TOOL_EXECUTION_FAILED = "E103"
    TOOL_OUTPUT_PARSE_ERROR = "E104"
    TOOL_TIMEOUT = "E105"
    TOOL_DEPENDENCY_MISSING = "E106"

    # Analysis Errors (2xx)
    ANALYSIS_FAILED = "E201"
    ANALYSIS_TIMEOUT = "E202"
    ANALYSIS_CANCELLED = "E203"
    CONTRACT_NOT_FOUND = "E204"
    CONTRACT_INVALID = "E205"
    LAYER_NOT_FOUND = "E206"

    # Configuration Errors (3xx)
    CONFIG_NOT_FOUND = "E301"
    CONFIG_INVALID = "E302"
    CONFIG_MISSING_KEY = "E303"
    CONFIG_TYPE_ERROR = "E304"

    # Security Errors (4xx)
    SECURITY_VALIDATION_FAILED = "E401"
    PATH_TRAVERSAL_DETECTED = "E402"
    RATE_LIMIT_EXCEEDED = "E403"
    UNAUTHORIZED_ACCESS = "E404"

    # API Errors (5xx)
    API_REQUEST_FAILED = "E501"
    API_RESPONSE_INVALID = "E502"
    API_CONNECTION_ERROR = "E503"

    # ML/AI Errors (6xx)
    MODEL_NOT_FOUND = "E601"
    MODEL_INFERENCE_FAILED = "E602"
    CORRELATION_FAILED = "E603"

    # General Errors (9xx)
    INTERNAL_ERROR = "E901"
    NOT_IMPLEMENTED = "E902"
    UNKNOWN_ERROR = "E999"


# Installation suggestions for common tools
TOOL_INSTALL_SUGGESTIONS: Dict[str, List[str]] = {
    "slither": [
        "pip install slither-analyzer",
        "See: https://github.com/crytic/slither#how-to-install"
    ],
    "mythril": [
        "pip install mythril",
        "Note: mythril may conflict with slither-analyzer",
        "Alternative: docker run -it mythril/myth analyze <contract.sol>"
    ],
    "echidna": [
        "brew install echidna (macOS)",
        "See: https://github.com/crytic/echidna#installation"
    ],
    "medusa": [
        "go install github.com/crytic/medusa@latest",
        "Requires Go 1.19+"
    ],
    "foundry": [
        "curl -L https://foundry.paradigm.xyz | bash && foundryup",
        "See: https://book.getfoundry.sh/getting-started/installation"
    ],
    "halmos": [
        "pip install halmos",
        "See: https://github.com/a16z/halmos"
    ],
    "certora": [
        "pip install certora-cli",
        "Requires CERTORA_KEY environment variable"
    ],
    "aderyn": [
        "cargo install aderyn",
        "Requires Rust 1.70+"
    ],
    "solhint": [
        "npm install -g solhint",
        "Requires Node.js 14+"
    ],
    "wake": [
        "pip install eth-wake",
        "See: https://github.com/Ackee-Blockchain/wake"
    ],
    "manticore": [
        "pip install manticore[native]",
        "Note: Requires Python 3.11 or earlier"
    ],
    "ollama": [
        "brew install ollama (macOS)",
        "curl -fsSL https://ollama.com/install.sh | sh (Linux)",
        "Then: ollama pull deepseek-coder"
    ]
}


class MIESCException(Exception):
    """
    Base exception for all MIESC errors.

    Provides structured error information including:
    - Error message
    - Error code for programmatic handling
    - Suggestions for remediation
    - Additional context for debugging

    Attributes:
        message: Human-readable error description
        error_code: Standardized error code (ErrorCode enum or string)
        suggestions: List of remediation suggestions
        context: Additional debugging context
    """

    def __init__(
        self,
        message: str,
        error_code: str | ErrorCode = ErrorCode.UNKNOWN_ERROR,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code.value if isinstance(error_code, ErrorCode) else error_code
        self.suggestions = suggestions or []
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """Format exception as user-friendly string."""
        parts = [f"[{self.error_code}] {self.message}"]
        if self.suggestions:
            parts.append("\nSuggestions:")
            for suggestion in self.suggestions:
                parts.append(f"  - {suggestion}")
        return "".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error": True,
            "error_code": self.error_code,
            "message": self.message,
            "suggestions": self.suggestions,
            "context": self.context
        }


class ToolAdapterError(MIESCException):
    """
    Exception for tool adapter errors.

    Raised when a security analysis tool fails to load, execute, or parse output.

    Attributes:
        tool_name: Name of the tool that failed
        tool_version: Version of the tool (if available)
    """

    def __init__(
        self,
        message: str,
        tool_name: str,
        error_code: str | ErrorCode = ErrorCode.TOOL_EXECUTION_FAILED,
        tool_version: Optional[str] = None,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.tool_name = tool_name
        self.tool_version = tool_version

        # Auto-add installation suggestions if tool not found
        if error_code in (ErrorCode.TOOL_NOT_FOUND, ErrorCode.TOOL_NOT_AVAILABLE,
                          ErrorCode.TOOL_DEPENDENCY_MISSING):
            tool_suggestions = TOOL_INSTALL_SUGGESTIONS.get(tool_name.lower(), [])
            suggestions = (suggestions or []) + tool_suggestions

        context = context or {}
        context.update({
            "tool_name": tool_name,
            "tool_version": tool_version
        })

        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class AnalysisError(MIESCException):
    """
    Exception for analysis execution errors.

    Raised when an analysis operation fails.

    Attributes:
        contract_path: Path to the contract being analyzed
        layer: Layer number where the error occurred
    """

    def __init__(
        self,
        message: str,
        contract_path: Optional[str] = None,
        layer: Optional[int] = None,
        error_code: str | ErrorCode = ErrorCode.ANALYSIS_FAILED,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.contract_path = contract_path
        self.layer = layer

        context = context or {}
        if contract_path:
            context["contract_path"] = contract_path
        if layer is not None:
            context["layer"] = layer

        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class AnalysisTimeoutError(AnalysisError):
    """
    Exception for analysis timeout.

    Raised when an analysis operation exceeds the configured timeout.

    Attributes:
        timeout_seconds: The timeout that was exceeded
    """

    def __init__(
        self,
        message: str,
        timeout_seconds: int,
        contract_path: Optional[str] = None,
        layer: Optional[int] = None,
        tool_name: Optional[str] = None,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.timeout_seconds = timeout_seconds

        suggestions = suggestions or []
        suggestions.extend([
            f"Increase timeout: --timeout {timeout_seconds * 2}",
            "Try analyzing a smaller contract or specific functions",
            "Use --layers quick for faster analysis"
        ])

        context = context or {}
        context.update({
            "timeout_seconds": timeout_seconds,
            "tool_name": tool_name
        })

        super().__init__(
            message=message,
            contract_path=contract_path,
            layer=layer,
            error_code=ErrorCode.ANALYSIS_TIMEOUT,
            suggestions=suggestions,
            context=context
        )


class ConfigurationError(MIESCException):
    """
    Exception for configuration errors.

    Raised when configuration is invalid or missing.

    Attributes:
        config_key: The configuration key that caused the error
        config_file: Path to the configuration file
    """

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_file: Optional[str] = None,
        error_code: str | ErrorCode = ErrorCode.CONFIG_INVALID,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.config_key = config_key
        self.config_file = config_file

        suggestions = suggestions or []
        if config_file:
            suggestions.append(f"Check configuration file: {config_file}")
        suggestions.append("Run 'miesc config validate' to check configuration")

        context = context or {}
        if config_key:
            context["config_key"] = config_key
        if config_file:
            context["config_file"] = config_file

        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class SecurityError(MIESCException):
    """
    Exception for security validation errors.

    Raised when a security check fails (path traversal, rate limiting, etc.)
    """

    def __init__(
        self,
        message: str,
        error_code: str | ErrorCode = ErrorCode.SECURITY_VALIDATION_FAILED,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class ContractError(AnalysisError):
    """
    Exception for contract-related errors.

    Raised when a contract file cannot be found, read, or is invalid.
    """

    def __init__(
        self,
        message: str,
        contract_path: str,
        error_code: str | ErrorCode = ErrorCode.CONTRACT_NOT_FOUND,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        suggestions = suggestions or []
        suggestions.extend([
            f"Verify file exists: ls -la {contract_path}",
            "Ensure file has .sol extension",
            "Check file permissions"
        ])

        super().__init__(
            message=message,
            contract_path=contract_path,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class APIError(MIESCException):
    """
    Exception for API-related errors.

    Raised when an API request fails.

    Attributes:
        status_code: HTTP status code (if applicable)
        endpoint: API endpoint that failed
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        error_code: str | ErrorCode = ErrorCode.API_REQUEST_FAILED,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.status_code = status_code
        self.endpoint = endpoint

        context = context or {}
        if status_code:
            context["status_code"] = status_code
        if endpoint:
            context["endpoint"] = endpoint

        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


class ModelError(MIESCException):
    """
    Exception for ML/AI model errors.

    Raised when a model fails to load or inference fails.

    Attributes:
        model_name: Name of the model that failed
    """

    def __init__(
        self,
        message: str,
        model_name: Optional[str] = None,
        error_code: str | ErrorCode = ErrorCode.MODEL_INFERENCE_FAILED,
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.model_name = model_name

        suggestions = suggestions or []
        if model_name and "ollama" in model_name.lower():
            suggestions.extend([
                "Ensure Ollama is running: ollama serve",
                f"Pull the model: ollama pull {model_name}",
                "Check Ollama logs: ollama logs"
            ])

        context = context or {}
        if model_name:
            context["model_name"] = model_name

        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions,
            context=context
        )


# Exception factory for common cases
def tool_not_available(tool_name: str, reason: Optional[str] = None) -> ToolAdapterError:
    """Create a ToolAdapterError for when a tool is not available."""
    message = f"Tool '{tool_name}' is not available"
    if reason:
        message += f": {reason}"
    return ToolAdapterError(
        message=message,
        tool_name=tool_name,
        error_code=ErrorCode.TOOL_NOT_AVAILABLE
    )


def contract_not_found(path: str) -> ContractError:
    """Create a ContractError for when a contract file is not found."""
    return ContractError(
        message=f"Contract file not found: {path}",
        contract_path=path,
        error_code=ErrorCode.CONTRACT_NOT_FOUND
    )


def analysis_timeout(
    tool_name: str,
    timeout_seconds: int,
    contract_path: Optional[str] = None
) -> AnalysisTimeoutError:
    """Create an AnalysisTimeoutError for when analysis times out."""
    return AnalysisTimeoutError(
        message=f"Analysis with {tool_name} timed out after {timeout_seconds}s",
        timeout_seconds=timeout_seconds,
        contract_path=contract_path,
        tool_name=tool_name
    )


__all__ = [
    # Base exception
    "MIESCException",
    # Domain exceptions
    "ToolAdapterError",
    "AnalysisError",
    "AnalysisTimeoutError",
    "ConfigurationError",
    "SecurityError",
    "ContractError",
    "APIError",
    "ModelError",
    # Error codes
    "ErrorCode",
    # Factory functions
    "tool_not_available",
    "contract_not_found",
    "analysis_timeout",
    # Installation suggestions
    "TOOL_INSTALL_SUGGESTIONS",
]
