"""
Tool adapter protocol for heterogeneous security tool integration.

Defines abstract interface that all tool adapters must implement.
Enables loose coupling and avoids vendor lock-in (DPGA requirement).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import json
import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

logger = logging.getLogger(__name__)

# Type for subprocess result
SubprocessResult = Tuple[int, str, str]  # returncode, stdout, stderr


class ToolCategory(Enum):
    """Tool categories per MIESC 9-layer architecture"""

    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_TESTING = "dynamic_testing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    FORMAL_VERIFICATION = "formal_verification"
    AI_ANALYSIS = "ai_analysis"
    ML_DETECTION = "ml_detection"
    SPECIALIZED = "specialized"
    CROSSCHAIN_ZK = "crosschain_zk"
    ADVANCED_AI_ENSEMBLE = "advanced_ai_ensemble"
    COMPLIANCE = "compliance"
    AUDIT_READINESS = "audit_readiness"
    GAS_OPTIMIZATION = "gas_optimization"
    MEV_DETECTION = "mev_detection"
    PRIVACY_ANALYSIS = "privacy_analysis"


class ToolStatus(Enum):
    """Tool availability status"""

    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"
    CONFIGURATION_ERROR = "configuration_error"
    LICENSE_REQUIRED = "license_required"
    DEPRECATED = "deprecated"


@dataclass
class ToolCapability:
    """Specific capability of a tool"""

    name: str
    description: str
    supported_languages: List[str]
    detection_types: List[str]  # e.g., ["reentrancy", "overflow", "access_control"]


@dataclass
class ToolMetadata:
    """Tool metadata"""

    name: str
    version: str
    category: ToolCategory
    author: str
    license: str
    homepage: str
    repository: str
    documentation: str
    installation_cmd: str
    capabilities: List[ToolCapability]
    cost: float = 0.0  # 0.0 = free, >0 = paid/API cost
    requires_api_key: bool = False
    is_optional: bool = True  # Default: all tools are optional (no vendor lock-in)


class ToolAdapter(ABC):
    """
    Base interface for tool adapters.

    All tools must implement this protocol to integrate with MIESC.
    This design enables:
    - Decoupling from specific tools
    - Swapping implementations without changing core code
    - Adding new tools without modifying core
    - Satisfying DPGA requirements

    Example usage:

    ```python
    class MyToolAdapter(ToolAdapter):
        def get_metadata(self) -> ToolMetadata:
            return ToolMetadata(
                name="mytool",
                version="1.0.0",
                category=ToolCategory.STATIC_ANALYSIS,
                ...
            )

        def is_available(self) -> ToolStatus:
            # Check if tool is installed
            return ToolStatus.AVAILABLE

        def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
            # Run tool and return normalized results
            return {"findings": [...]}
    ```
    """

    @abstractmethod
    def get_metadata(self) -> ToolMetadata:
        """
        Return tool metadata.

        REQUIRED: Must be implemented for MIESC to recognize the tool.
        """
        pass

    @abstractmethod
    def is_available(self) -> ToolStatus:
        """
        Check if tool is available and configured.

        REQUIRED: Allows MIESC to determine if tool can be used.

        Returns:
            ToolStatus indicating availability
        """
        pass

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute analysis with the tool.

        REQUIRED: Main entry point for using the tool.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Additional tool-specific parameters

        Returns:
            Normalized results dictionary:
            {
                "tool": str,  # Tool name
                "version": str,
                "status": "success" | "error",
                "findings": List[Dict],  # Normalized findings
                "metadata": Dict,  # Additional information
                "execution_time": float,
                "error": Optional[str]  # If status == "error"
            }
        """
        pass

    @abstractmethod
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings from tool-specific format to MIESC format.

        REQUIRED: Enables MIESC to process findings uniformly.

        Args:
            raw_output: Raw output from the tool

        Returns:
            List of normalized findings with structure:
            {
                "id": str,  # Unique identifier
                "type": str,  # Vulnerability type
                "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
                "confidence": float,  # 0.0-1.0
                "location": {
                    "file": str,
                    "line": int,
                    "function": str
                },
                "message": str,
                "description": str,
                "recommendation": str,
                "swc_id": Optional[str],  # SWC-XXX
                "cwe_id": Optional[str],  # CWE-XXX
                "owasp_category": Optional[str]  # OWASP SC Top 10
            }
        """
        pass

    def get_installation_instructions(self) -> str:
        """
        Return tool installation instructions.

        OPTIONAL: Helps users install optional tools.
        """
        metadata = self.get_metadata()
        return f"""
# Installing {metadata.name}

**License**: {metadata.license}
**Cost**: {'Free' if metadata.cost == 0 else f'${metadata.cost}'}

## Installation command

```bash
{metadata.installation_cmd}
```

## Official documentation

- Homepage: {metadata.homepage}
- Repository: {metadata.repository}
- Docs: {metadata.documentation}

## Verification

After installation, verify availability:

```python
from src.adapters.{metadata.name}_adapter import {metadata.name.title()}Adapter

adapter = {metadata.name.title()}Adapter()
status = adapter.is_available()
print(f"Status: {{status}}")
```
"""

    def can_analyze(self, contract_path: str) -> bool:
        """
        Check if tool can analyze the given contract.

        OPTIONAL: Allows filtering tools by contract type.
        Default: accepts all .sol files
        """
        return contract_path.endswith(".sol")

    def get_default_config(self) -> Dict[str, Any]:
        """
        Return default tool configuration.

        OPTIONAL: Allows configuring tool without knowing details.
        """
        return {}

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate tool configuration.

        OPTIONAL: Prevents configuration errors.
        """
        return True

    # =========================================================================
    # Helper Methods - Reduce boilerplate in adapters
    # =========================================================================

    def check_binary_available(
        self,
        binary_name: str,
        version_flag: str = "--version",
        timeout: int = 10,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolStatus:
        """
        Check if a binary is available in PATH and working.

        This is a helper method to implement is_available() with less boilerplate.

        Args:
            binary_name: Name of the binary to check (e.g., "slither", "myth")
            version_flag: Flag to get version (default: "--version")
            timeout: Timeout in seconds for the version check
            env: Optional environment variables

        Returns:
            ToolStatus indicating availability

        Example:
            def is_available(self) -> ToolStatus:
                return self.check_binary_available("slither", "--version")
        """
        try:
            result = subprocess.run(
                [binary_name, version_flag],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )

            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                logger.info(f"{binary_name} available: {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"{binary_name} command found but returned error")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info(f"{binary_name} not installed (optional tool)")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning(f"{binary_name} version check timed out")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking {binary_name} availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def run_subprocess(
        self,
        cmd: List[str],
        timeout: int = 120,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> SubprocessResult:
        """
        Run a subprocess with standard error handling.

        Args:
            cmd: Command as list of strings
            timeout: Timeout in seconds (default: 120)
            env: Optional environment variables
            cwd: Optional working directory

        Returns:
            Tuple of (returncode, stdout, stderr)

        Raises:
            subprocess.TimeoutExpired: If command times out
            FileNotFoundError: If binary not found

        Example:
            returncode, stdout, stderr = self.run_subprocess(
                ["slither", "contract.sol", "--json", "-"],
                timeout=300
            )
        """
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        return result.returncode, result.stdout, result.stderr

    def parse_json_safely(self, text: str) -> Tuple[Optional[Any], Optional[str]]:
        """
        Safely parse JSON from command output.

        Handles common issues like ANSI codes, BOM, etc.

        Args:
            text: JSON text to parse

        Returns:
            Tuple of (parsed_data, error_message)
            If successful: (data, None)
            If failed: (None, error_message)

        Example:
            data, error = self.parse_json_safely(stdout)
            if error:
                return {"status": "error", "error": error}
        """
        if not text or not text.strip():
            return None, "Empty output"

        # Remove ANSI escape codes
        import re
        clean_text = re.sub(r'\x1b\[[0-9;]*m', '', text)

        # Remove BOM if present
        clean_text = clean_text.lstrip('\ufeff')

        # Try to find JSON in the output (some tools mix text with JSON)
        json_match = re.search(r'[\[{].*[\]}]', clean_text, re.DOTALL)
        if json_match:
            clean_text = json_match.group()

        try:
            return json.loads(clean_text), None
        except json.JSONDecodeError as e:
            return None, f"JSON parse error: {e}"

    def normalize_severity(
        self,
        severity: str,
        severity_map: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Normalize severity to MIESC standard levels.

        MIESC standard levels: Critical, High, Medium, Low, Info

        Args:
            severity: Original severity string from tool
            severity_map: Optional custom mapping. If None, uses default mapping.

        Returns:
            Normalized severity string

        Example:
            severity = self.normalize_severity(raw_severity, self.SEVERITY_MAP)
        """
        default_map = {
            # Common variations
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
            "information": "Info",
            "warning": "Medium",
            "warn": "Medium",
            "note": "Info",
            "optimization": "Info",
            "gas": "Info",
            "nc": "Info",  # Non-Critical
            "suggestion": "Info",
        }

        if severity_map:
            # Merge custom map with defaults (custom takes priority)
            full_map = {**default_map, **{k.lower(): v for k, v in severity_map.items()}}
        else:
            full_map = default_map

        normalized = full_map.get(severity.lower(), "Info")
        return normalized

    def create_finding(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        message: str,
        file_path: str = "",
        line: int = 0,
        function: str = "",
        confidence: float = 0.8,
        description: str = "",
        recommendation: str = "",
        swc_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a normalized finding dictionary.

        Helper to ensure all findings have consistent structure.

        Args:
            finding_id: Unique identifier for the finding
            finding_type: Type of vulnerability (e.g., "reentrancy")
            severity: Severity level (will be normalized)
            message: Short description of the issue
            file_path: Path to the affected file
            line: Line number (0 if unknown)
            function: Function name (empty if unknown)
            confidence: Confidence score 0.0-1.0
            description: Detailed description
            recommendation: How to fix the issue
            swc_id: Optional SWC identifier (e.g., "SWC-107")
            cwe_id: Optional CWE identifier (e.g., "CWE-841")

        Returns:
            Normalized finding dictionary
        """
        return {
            "id": finding_id,
            "type": finding_type,
            "severity": self.normalize_severity(severity),
            "confidence": max(0.0, min(1.0, confidence)),
            "location": {
                "file": file_path,
                "line": line,
                "function": function,
            },
            "message": message,
            "description": description or message,
            "recommendation": recommendation,
            "swc_id": swc_id,
            "cwe_id": cwe_id,
        }

    def create_result(
        self,
        status: str = "success",
        findings: Optional[List[Dict[str, Any]]] = None,
        error: Optional[str] = None,
        execution_time: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a normalized result dictionary.

        Helper to ensure all analyze() results have consistent structure.

        Args:
            status: "success" or "error"
            findings: List of normalized findings
            error: Error message if status is "error"
            execution_time: Time taken for analysis
            metadata: Additional tool-specific metadata

        Returns:
            Normalized result dictionary
        """
        tool_metadata = self.get_metadata()
        return {
            "tool": tool_metadata.name,
            "version": tool_metadata.version,
            "status": status,
            "findings": findings or [],
            "metadata": metadata or {},
            "execution_time": execution_time,
            "error": error,
        }

    def find_binary(
        self,
        binary_name: str,
        priority_paths: Optional[List[str]] = None,
        version_flag: str = "--version",
    ) -> str:
        """
        Find the best binary path, preferring user installations.

        Args:
            binary_name: Name of the binary to find
            priority_paths: Optional list of paths to check first
            version_flag: Flag to verify the binary works

        Returns:
            Path to the binary (or just binary_name if not found in priority paths)

        Example:
            slither_path = self.find_binary(
                "slither",
                priority_paths=[
                    os.path.expanduser("~/.local/bin/slither"),
                    os.path.expanduser("~/Library/Python/3.11/bin/slither"),
                ]
            )
        """
        # Check priority paths first
        if priority_paths:
            for path in priority_paths:
                if path and Path(path).is_file() and Path(path).stat().st_mode & 0o111:
                    try:
                        result = subprocess.run(
                            [path, version_flag],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            logger.debug(f"Found {binary_name} at priority path: {path}")
                            return path
                    except Exception:
                        continue

        # Fall back to shutil.which (PATH-based lookup)
        which_path = shutil.which(binary_name)
        if which_path:
            return which_path

        # Default to binary name and let caller handle if not found
        return binary_name


class ToolRegistry:
    """
    Central registry of available tools.

    Enables dynamic tool discovery without modifying core code.
    """

    def __init__(self):
        self._tools: Dict[str, ToolAdapter] = {}
        self._initialized = False

    def register(self, adapter: ToolAdapter) -> None:
        """
        Register a tool in the system.

        Args:
            adapter: Adapter implementing ToolAdapter
        """
        metadata = adapter.get_metadata()
        tool_name = metadata.name

        if tool_name in self._tools:
            logger.warning(f"Tool {tool_name} already registered, overwriting")

        self._tools[tool_name] = adapter
        logger.info(f"Tool registered: {tool_name} v{metadata.version}")

    def get_tool(self, name: str) -> Optional[ToolAdapter]:
        """Get tool adapter by name"""
        return self._tools.get(name)

    def get_all_tools(self) -> List[ToolAdapter]:
        """Return all registered tools"""
        return list(self._tools.values())

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolAdapter]:
        """Return tools of a specific category"""
        return [tool for tool in self._tools.values() if tool.get_metadata().category == category]

    def get_available_tools(self) -> List[ToolAdapter]:
        """Return only available tools (installed and configured)"""
        available = []
        for tool in self._tools.values():
            status = tool.is_available()
            if status == ToolStatus.AVAILABLE:
                available.append(tool)
        return available

    def get_tool_status_report(self) -> Dict[str, Any]:
        """
        Generate status report for all tools.

        Useful for diagnostics and installation verification.
        """
        report = {
            "total_tools": len(self._tools),
            "available": 0,
            "not_installed": 0,
            "configuration_error": 0,
            "tools": [],
        }

        for tool in self._tools.values():
            metadata = tool.get_metadata()
            status = tool.is_available()

            tool_info = {
                "name": metadata.name,
                "version": metadata.version,
                "category": metadata.category.value,
                "status": status.value,
                "cost": metadata.cost,
                "optional": metadata.is_optional,
            }

            report["tools"].append(tool_info)

            if status == ToolStatus.AVAILABLE:
                report["available"] += 1
            elif status == ToolStatus.NOT_INSTALLED:
                report["not_installed"] += 1
            elif status == ToolStatus.CONFIGURATION_ERROR:
                report["configuration_error"] += 1

        return report


# Singleton del registro
_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Get singleton instance of tool registry"""
    return _registry
