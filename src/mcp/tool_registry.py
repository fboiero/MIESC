"""
MIESC MCP Tool Registry - Model Context Protocol Tool Discovery

Implements the MCP tools/list specification for tool discovery and
capability negotiation with AI agents (Claude, GPT, etc.)

MCP Specification: https://modelcontextprotocol.io/specification/server/tools
Scientific Context: Agent interoperability in distributed security systems

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
Version: 4.1.0
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """MCP Tool categories for MIESC."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_TESTING = "dynamic_testing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    FORMAL_VERIFICATION = "formal_verification"
    PROPERTY_TESTING = "property_testing"
    AI_ANALYSIS = "ai_analysis"
    SPECIALIZED = "specialized"
    CORRELATION = "correlation"
    REMEDIATION = "remediation"
    COMPLIANCE = "compliance"
    REPORTING = "reporting"


@dataclass
class MCPToolParameter:
    """
    MCP Tool Parameter Definition (JSON Schema format).

    Follows JSON Schema specification for parameter definitions
    as required by MCP tools/list response.
    """
    name: str
    type: str  # "string", "number", "boolean", "array", "object"
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[List[str]] = None
    items: Optional[Dict[str, Any]] = None  # For array types

    def to_json_schema(self) -> Dict[str, Any]:
        """Convert to JSON Schema format."""
        schema = {
            "type": self.type,
            "description": self.description,
        }
        if self.default is not None:
            schema["default"] = self.default
        if self.enum:
            schema["enum"] = self.enum
        if self.items:
            schema["items"] = self.items
        return schema


@dataclass
class MCPTool:
    """
    MCP Tool Definition following the Model Context Protocol specification.

    This represents a tool that can be invoked by an AI agent through MCP.
    Each tool has a name, description, and input schema for parameters.

    Attributes:
        name: Unique tool identifier (e.g., "miesc_run_audit")
        description: Human-readable description of what the tool does
        category: Tool category for organization
        parameters: List of tool parameters
        handler: Optional callable that implements the tool
        layer: MIESC defense layer (1-7)
        available: Whether the tool is currently available
    """
    name: str
    description: str
    category: ToolCategory
    parameters: List[MCPToolParameter] = field(default_factory=list)
    handler: Optional[Callable] = None
    layer: Optional[int] = None
    available: bool = True
    version: str = "1.0.0"

    def to_mcp_format(self) -> Dict[str, Any]:
        """
        Convert to MCP tools/list response format.

        Returns format compliant with MCP specification:
        {
            "name": "tool_name",
            "description": "Tool description",
            "inputSchema": {
                "type": "object",
                "properties": {...},
                "required": [...]
            }
        }
        """
        properties = {}
        required = []

        for param in self.parameters:
            properties[param.name] = param.to_json_schema()
            if param.required:
                required.append(param.name)

        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            }
        }

    def to_extended_format(self) -> Dict[str, Any]:
        """
        Extended format with MIESC-specific metadata.

        Includes additional fields useful for the thesis documentation
        and agent capability discovery.
        """
        base = self.to_mcp_format()
        base["metadata"] = {
            "category": self.category.value,
            "layer": self.layer,
            "version": self.version,
            "available": self.available,
        }
        return base


class MCPToolRegistry:
    """
    MCP Tool Registry - Central registry for all MIESC tools.

    Implements the tools/list endpoint for MCP specification compliance.
    Provides tool discovery, registration, and invocation capabilities.

    Usage:
        registry = MCPToolRegistry()

        # Register a tool
        registry.register(MCPTool(
            name="miesc_run_audit",
            description="Execute smart contract security audit",
            category=ToolCategory.STATIC_ANALYSIS,
            parameters=[
                MCPToolParameter("contract_path", "string", "Path to .sol file"),
            ]
        ))

        # List all tools (MCP format)
        tools = registry.list_tools()

        # Call a tool
        result = await registry.call_tool("miesc_run_audit", {"contract_path": "Token.sol"})
    """

    def __init__(self):
        """Initialize the tool registry."""
        self._tools: Dict[str, MCPTool] = {}
        self._handlers: Dict[str, Callable] = {}
        self._register_default_tools()
        logger.info("MCPToolRegistry initialized with default tools")

    def _register_default_tools(self) -> None:
        """Register MIESC's default tools for MCP discovery."""

        # Tool 1: Run Audit (Primary capability)
        self.register(MCPTool(
            name="miesc_run_audit",
            description=(
                "Execute comprehensive multi-layer security audit on a Solidity smart contract. "
                "Uses 7-layer defense-in-depth approach with static analysis, symbolic execution, "
                "fuzzing, and AI-powered correlation. Returns normalized findings with severity, "
                "confidence scores, and compliance mapping."
            ),
            category=ToolCategory.STATIC_ANALYSIS,
            layer=1,
            parameters=[
                MCPToolParameter(
                    name="contract_path",
                    type="string",
                    description="Path to the Solidity contract file (.sol)"
                ),
                MCPToolParameter(
                    name="tools",
                    type="array",
                    description="List of tools to run (default: all enabled)",
                    required=False,
                    items={"type": "string"}
                ),
                MCPToolParameter(
                    name="layers",
                    type="array",
                    description="Specific layers to execute (1-7)",
                    required=False,
                    items={"type": "integer", "minimum": 1, "maximum": 7}
                ),
                MCPToolParameter(
                    name="enable_ai_triage",
                    type="boolean",
                    description="Enable AI-powered finding triage and correlation",
                    required=False,
                    default=True
                ),
            ]
        ))

        # Tool 2: Correlate Findings
        self.register(MCPTool(
            name="miesc_correlate",
            description=(
                "Correlate security findings from multiple tools using the Smart Correlation Engine. "
                "Applies cross-validation, deduplication, and false positive filtering. "
                "Outputs unified findings with enhanced confidence scores."
            ),
            category=ToolCategory.CORRELATION,
            parameters=[
                MCPToolParameter(
                    name="findings",
                    type="object",
                    description="Dict mapping tool names to their findings arrays"
                ),
                MCPToolParameter(
                    name="min_tools_for_validation",
                    type="integer",
                    description="Minimum tools to confirm a finding (default: 2)",
                    required=False,
                    default=2
                ),
                MCPToolParameter(
                    name="confidence_threshold",
                    type="number",
                    description="Minimum confidence score (0.0-1.0, default: 0.5)",
                    required=False,
                    default=0.5
                ),
            ]
        ))

        # Tool 3: Map Compliance
        self.register(MCPTool(
            name="miesc_map_compliance",
            description=(
                "Map security findings to international compliance frameworks. "
                "Supports ISO/IEC 27001, NIST CSF, OWASP, CWE, SWC, and MITRE ATT&CK. "
                "Returns compliance matrix with coverage scores and identified gaps."
            ),
            category=ToolCategory.COMPLIANCE,
            parameters=[
                MCPToolParameter(
                    name="findings",
                    type="array",
                    description="List of security findings to map"
                ),
                MCPToolParameter(
                    name="frameworks",
                    type="array",
                    description="Target frameworks (default: all)",
                    required=False,
                    items={"type": "string", "enum": ["ISO27001", "NIST", "OWASP", "CWE", "SWC", "MITRE"]}
                ),
            ]
        ))

        # Tool 4: Get Remediation
        self.register(MCPTool(
            name="miesc_remediate",
            description=(
                "Enrich vulnerabilities with remediation suggestions. "
                "Provides SWC-based fix patterns, code examples, effort estimates, "
                "and prioritized fix plans based on severity and exploitability."
            ),
            category=ToolCategory.REMEDIATION,
            parameters=[
                MCPToolParameter(
                    name="findings",
                    type="array",
                    description="List of vulnerability findings"
                ),
                MCPToolParameter(
                    name="contract_name",
                    type="string",
                    description="Name of the contract for context",
                    required=False
                ),
                MCPToolParameter(
                    name="source_code",
                    type="string",
                    description="Source code for contextual analysis",
                    required=False
                ),
            ]
        ))

        # Tool 5: Generate Report
        self.register(MCPTool(
            name="miesc_generate_report",
            description=(
                "Generate structured security audit report. "
                "Supports JSON, Markdown, HTML, and PDF formats. "
                "Includes executive summary, detailed findings, and compliance status."
            ),
            category=ToolCategory.REPORTING,
            parameters=[
                MCPToolParameter(
                    name="audit_results",
                    type="object",
                    description="Complete audit results object"
                ),
                MCPToolParameter(
                    name="format",
                    type="string",
                    description="Output format",
                    required=False,
                    default="json",
                    enum=["json", "markdown", "html", "pdf", "sarif"]
                ),
                MCPToolParameter(
                    name="include_compliance",
                    type="boolean",
                    description="Include compliance mapping section",
                    required=False,
                    default=True
                ),
            ]
        ))

        # Tool 6: Quick Scan
        self.register(MCPTool(
            name="miesc_quick_scan",
            description=(
                "Fast security scan using only static analysis tools. "
                "Ideal for CI/CD pipelines and quick feedback. "
                "Uses Slither, Aderyn, and Solhint."
            ),
            category=ToolCategory.STATIC_ANALYSIS,
            layer=1,
            parameters=[
                MCPToolParameter(
                    name="contract_path",
                    type="string",
                    description="Path to the Solidity contract file"
                ),
                MCPToolParameter(
                    name="timeout",
                    type="integer",
                    description="Timeout in seconds (default: 60)",
                    required=False,
                    default=60
                ),
            ]
        ))

        # Tool 7: Deep Scan
        self.register(MCPTool(
            name="miesc_deep_scan",
            description=(
                "Comprehensive security scan using all 7 defense layers. "
                "Includes symbolic execution, fuzzing, formal verification, and AI analysis. "
                "Recommended for pre-deployment audits."
            ),
            category=ToolCategory.SYMBOLIC_EXECUTION,
            layer=3,
            parameters=[
                MCPToolParameter(
                    name="contract_path",
                    type="string",
                    description="Path to the Solidity contract file"
                ),
                MCPToolParameter(
                    name="timeout",
                    type="integer",
                    description="Timeout per tool in seconds (default: 300)",
                    required=False,
                    default=300
                ),
            ]
        ))

        # Tool 8: Get Metrics
        self.register(MCPTool(
            name="miesc_get_metrics",
            description=(
                "Retrieve MIESC's scientific validation metrics. "
                "Returns precision, recall, F1-score, and Cohen's kappa from thesis experiments. "
                "Based on analysis of 5,127 smart contracts."
            ),
            category=ToolCategory.REPORTING,
            parameters=[]
        ))

        # Tool 9: Get Status
        self.register(MCPTool(
            name="miesc_get_status",
            description=(
                "Get MIESC agent status, available tools, and health information. "
                "Returns version, active capabilities, and component health."
            ),
            category=ToolCategory.REPORTING,
            parameters=[]
        ))

        # Tool 10: Analyze DeFi
        self.register(MCPTool(
            name="miesc_analyze_defi",
            description=(
                "Specialized DeFi vulnerability analysis. "
                "Detects flash loan attacks, oracle manipulation, MEV vulnerabilities, "
                "reentrancy in DeFi contexts, and protocol-specific issues."
            ),
            category=ToolCategory.SPECIALIZED,
            layer=7,
            parameters=[
                MCPToolParameter(
                    name="contract_path",
                    type="string",
                    description="Path to the DeFi contract file"
                ),
                MCPToolParameter(
                    name="protocol_type",
                    type="string",
                    description="DeFi protocol type for targeted analysis",
                    required=False,
                    enum=["lending", "dex", "yield", "bridge", "nft", "dao", "generic"]
                ),
            ]
        ))

        # Tool 11: Detect Exploit Chains
        self.register(MCPTool(
            name="miesc_detect_exploit_chains",
            description=(
                "Analyze findings to detect exploit chains - combinations of "
                "vulnerabilities that create more severe attack paths. "
                "Identifies critical multi-step attack scenarios."
            ),
            category=ToolCategory.CORRELATION,
            parameters=[
                MCPToolParameter(
                    name="findings",
                    type="object",
                    description="Dict of tool findings to analyze"
                ),
            ]
        ))

    def register(self, tool: MCPTool) -> None:
        """
        Register a tool in the registry.

        Args:
            tool: MCPTool to register
        """
        self._tools[tool.name] = tool
        if tool.handler:
            self._handlers[tool.name] = tool.handler
        logger.debug(f"Registered MCP tool: {tool.name}")

    def unregister(self, tool_name: str) -> bool:
        """
        Unregister a tool from the registry.

        Args:
            tool_name: Name of tool to remove

        Returns:
            True if tool was removed, False if not found
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            self._handlers.pop(tool_name, None)
            logger.debug(f"Unregistered MCP tool: {tool_name}")
            return True
        return False

    def get_tool(self, tool_name: str) -> Optional[MCPTool]:
        """Get a specific tool by name."""
        return self._tools.get(tool_name)

    def list_tools(self, category: Optional[ToolCategory] = None) -> List[Dict[str, Any]]:
        """
        List all registered tools in MCP format.

        This is the response format for the MCP tools/list endpoint.

        Args:
            category: Optional filter by category

        Returns:
            List of tools in MCP specification format
        """
        tools = []
        for tool in self._tools.values():
            if tool.available:
                if category is None or tool.category == category:
                    tools.append(tool.to_mcp_format())
        return tools

    def list_tools_extended(self, category: Optional[ToolCategory] = None) -> List[Dict[str, Any]]:
        """
        List tools with extended MIESC metadata.

        Args:
            category: Optional filter by category

        Returns:
            List of tools with extended metadata
        """
        tools = []
        for tool in self._tools.values():
            if tool.available:
                if category is None or tool.category == category:
                    tools.append(tool.to_extended_format())
        return tools

    def get_tools_by_layer(self, layer: int) -> List[MCPTool]:
        """Get all tools for a specific defense layer."""
        return [t for t in self._tools.values() if t.layer == layer and t.available]

    def set_handler(self, tool_name: str, handler: Callable) -> bool:
        """
        Set the handler function for a tool.

        Args:
            tool_name: Name of the tool
            handler: Callable to handle tool invocations

        Returns:
            True if handler was set, False if tool not found
        """
        if tool_name in self._tools:
            self._handlers[tool_name] = handler
            self._tools[tool_name].handler = handler
            return True
        return False

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a registered tool with arguments.

        Implements MCP tools/call behavior.

        Args:
            tool_name: Name of tool to call
            arguments: Tool arguments

        Returns:
            Tool result or error response
        """
        if tool_name not in self._tools:
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"Unknown tool: {tool_name}"
                }]
            }

        tool = self._tools[tool_name]

        if not tool.available:
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"Tool '{tool_name}' is currently unavailable"
                }]
            }

        if tool_name not in self._handlers:
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"No handler registered for tool: {tool_name}"
                }]
            }

        try:
            handler = self._handlers[tool_name]

            # Call handler (support both sync and async)
            import asyncio
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**arguments)
            else:
                result = handler(**arguments)

            return {
                "content": [{
                    "type": "text",
                    "text": str(result) if not isinstance(result, dict) else None,
                    "data": result if isinstance(result, dict) else None
                }]
            }

        except Exception as e:
            logger.error(f"Tool '{tool_name}' execution failed: {e}", exc_info=True)
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": f"Tool execution error: {str(e)}"
                }]
            }

    def get_mcp_response(self) -> Dict[str, Any]:
        """
        Get full MCP tools/list response.

        Returns the complete response format for the MCP tools/list endpoint
        as specified in the Model Context Protocol.

        Returns:
            MCP-compliant tools/list response
        """
        return {
            "tools": self.list_tools()
        }

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Get MIESC agent capabilities for MCP initialize response.

        Returns capabilities object for MCP handshake.
        """
        return {
            "tools": {
                "listChanged": True  # We support tools/list_changed notifications
            },
            "experimental": {
                "miesc": {
                    "version": "4.1.0",
                    "layers": 7,
                    "adapters": 29,
                    "frameworks": ["ISO27001", "NIST", "OWASP", "CWE", "SWC"]
                }
            }
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics."""
        categories = {}
        for tool in self._tools.values():
            cat = tool.category.value
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_tools": len(self._tools),
            "available_tools": sum(1 for t in self._tools.values() if t.available),
            "tools_with_handlers": len(self._handlers),
            "categories": categories,
            "layers_covered": list(set(t.layer for t in self._tools.values() if t.layer)),
        }


# Singleton instance
_registry_instance: Optional[MCPToolRegistry] = None


def get_tool_registry() -> MCPToolRegistry:
    """Get the singleton MCPToolRegistry instance."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = MCPToolRegistry()
    return _registry_instance


def reset_tool_registry() -> None:
    """Reset the singleton registry (for testing)."""
    global _registry_instance
    _registry_instance = MCPToolRegistry()
