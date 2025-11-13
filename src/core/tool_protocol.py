"""
Tool adapter protocol for heterogeneous security tool integration.

Defines abstract interface that all tool adapters must implement.
Enables loose coupling and avoids vendor lock-in (DPGA requirement).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Tool categories per MIESC 7-layer architecture"""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_TESTING = "dynamic_testing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    FORMAL_VERIFICATION = "formal_verification"
    AI_ANALYSIS = "ai_analysis"
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
        return contract_path.endswith('.sol')

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
        return [
            tool for tool in self._tools.values()
            if tool.get_metadata().category == category
        ]

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
            "tools": []
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
                "optional": metadata.is_optional
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
