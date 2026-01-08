"""
Tests for MIESC MCP Tool Registry

Tests the Model Context Protocol tool discovery and registration.

Author: Fernando Boiero
License: AGPL-3.0
"""

from src.mcp.tool_registry import (
    MCPTool,
    MCPToolParameter,
    MCPToolRegistry,
    ToolCategory,
)


class TestToolCategory:
    """Tests for ToolCategory enum."""

    def test_category_values(self):
        """Test all tool categories exist."""
        assert ToolCategory.STATIC_ANALYSIS.value == "static_analysis"
        assert ToolCategory.DYNAMIC_TESTING.value == "dynamic_testing"
        assert ToolCategory.SYMBOLIC_EXECUTION.value == "symbolic_execution"
        assert ToolCategory.FORMAL_VERIFICATION.value == "formal_verification"
        assert ToolCategory.AI_ANALYSIS.value == "ai_analysis"
        assert ToolCategory.CORRELATION.value == "correlation"
        assert ToolCategory.REMEDIATION.value == "remediation"
        assert ToolCategory.COMPLIANCE.value == "compliance"
        assert ToolCategory.REPORTING.value == "reporting"


class TestMCPToolParameter:
    """Tests for MCPToolParameter dataclass."""

    def test_parameter_creation(self):
        """Test creating a tool parameter."""
        param = MCPToolParameter(
            name="contract_path",
            type="string",
            description="Path to the Solidity contract",
            required=True,
        )

        assert param.name == "contract_path"
        assert param.type == "string"
        assert param.description == "Path to the Solidity contract"
        assert param.required is True

    def test_parameter_defaults(self):
        """Test parameter default values."""
        param = MCPToolParameter(
            name="option",
            type="string",
            description="Optional setting",
        )

        assert param.required is True  # Default is True
        assert param.default is None
        assert param.enum is None
        assert param.items is None

    def test_parameter_with_default_value(self):
        """Test parameter with default value."""
        param = MCPToolParameter(
            name="timeout",
            type="number",
            description="Timeout in seconds",
            required=False,
            default=60,
        )

        assert param.default == 60
        assert param.required is False

    def test_parameter_with_enum(self):
        """Test parameter with enum options."""
        param = MCPToolParameter(
            name="format",
            type="string",
            description="Output format",
            enum=["json", "markdown", "html"],
        )

        assert param.enum == ["json", "markdown", "html"]

    def test_parameter_to_json_schema(self):
        """Test conversion to JSON Schema format."""
        param = MCPToolParameter(
            name="timeout",
            type="number",
            description="Timeout in seconds",
            default=60,
        )

        schema = param.to_json_schema()

        assert schema["type"] == "number"
        assert schema["description"] == "Timeout in seconds"
        assert schema["default"] == 60

    def test_parameter_to_json_schema_with_enum(self):
        """Test JSON Schema with enum."""
        param = MCPToolParameter(
            name="level",
            type="string",
            description="Log level",
            enum=["debug", "info", "warning"],
        )

        schema = param.to_json_schema()

        assert schema["enum"] == ["debug", "info", "warning"]

    def test_parameter_to_json_schema_with_items(self):
        """Test JSON Schema for array type."""
        param = MCPToolParameter(
            name="tools",
            type="array",
            description="List of tools",
            items={"type": "string"},
        )

        schema = param.to_json_schema()

        assert schema["type"] == "array"
        assert schema["items"] == {"type": "string"}


class TestMCPTool:
    """Tests for MCPTool dataclass."""

    def test_tool_creation(self):
        """Test creating a tool."""
        tool = MCPTool(
            name="miesc_test",
            description="Test tool",
            category=ToolCategory.STATIC_ANALYSIS,
        )

        assert tool.name == "miesc_test"
        assert tool.description == "Test tool"
        assert tool.category == ToolCategory.STATIC_ANALYSIS
        assert tool.available is True

    def test_tool_with_parameters(self):
        """Test tool with parameters."""
        tool = MCPTool(
            name="miesc_audit",
            description="Run security audit",
            category=ToolCategory.STATIC_ANALYSIS,
            parameters=[
                MCPToolParameter("path", "string", "Contract path"),
                MCPToolParameter("timeout", "number", "Timeout", required=False),
            ],
            layer=1,
        )

        assert len(tool.parameters) == 2
        assert tool.layer == 1

    def test_tool_to_mcp_format(self):
        """Test conversion to MCP format."""
        tool = MCPTool(
            name="test_tool",
            description="A test tool",
            category=ToolCategory.REPORTING,
            parameters=[
                MCPToolParameter("input", "string", "Input data"),
                MCPToolParameter("optional", "boolean", "Optional flag", required=False),
            ],
        )

        mcp_format = tool.to_mcp_format()

        assert mcp_format["name"] == "test_tool"
        assert mcp_format["description"] == "A test tool"
        assert "inputSchema" in mcp_format
        assert mcp_format["inputSchema"]["type"] == "object"
        assert "input" in mcp_format["inputSchema"]["properties"]
        assert "input" in mcp_format["inputSchema"]["required"]
        assert "optional" not in mcp_format["inputSchema"]["required"]

    def test_tool_to_extended_format(self):
        """Test conversion to extended format."""
        tool = MCPTool(
            name="miesc_analyze",
            description="Analyze contract",
            category=ToolCategory.AI_ANALYSIS,
            layer=5,
            version="2.0.0",
            available=True,
        )

        extended = tool.to_extended_format()

        assert extended["name"] == "miesc_analyze"
        assert "metadata" in extended
        assert extended["metadata"]["category"] == "ai_analysis"
        assert extended["metadata"]["layer"] == 5
        assert extended["metadata"]["version"] == "2.0.0"
        assert extended["metadata"]["available"] is True

    def test_tool_with_handler(self):
        """Test tool with callable handler."""

        def my_handler(params):
            return {"result": "success"}

        tool = MCPTool(
            name="handled_tool",
            description="Tool with handler",
            category=ToolCategory.CORRELATION,
            handler=my_handler,
        )

        assert tool.handler is not None
        assert tool.handler({}) == {"result": "success"}


class TestMCPToolRegistry:
    """Tests for MCPToolRegistry class."""

    def test_registry_initialization(self):
        """Test registry initializes with default tools."""
        registry = MCPToolRegistry()

        # Should have default tools registered
        tools = registry.list_tools()
        assert len(tools) > 0

    def test_registry_has_default_tools(self):
        """Test that default tools are registered."""
        registry = MCPToolRegistry()

        # Check some expected default tools
        tool_names = [t["name"] for t in registry.list_tools()]
        assert "miesc_run_audit" in tool_names
        assert "miesc_correlate" in tool_names
        assert "miesc_generate_report" in tool_names

    def test_register_tool(self):
        """Test registering a new tool."""
        registry = MCPToolRegistry()

        custom_tool = MCPTool(
            name="custom_test_tool",
            description="Custom tool for testing",
            category=ToolCategory.SPECIALIZED,
        )

        registry.register(custom_tool)

        tool_names = [t["name"] for t in registry.list_tools()]
        assert "custom_test_tool" in tool_names

    def test_get_tool(self):
        """Test getting a tool by name."""
        registry = MCPToolRegistry()

        tool = registry.get_tool("miesc_run_audit")

        assert tool is not None
        assert tool.name == "miesc_run_audit"

    def test_get_nonexistent_tool(self):
        """Test getting a non-existent tool."""
        registry = MCPToolRegistry()

        tool = registry.get_tool("nonexistent_tool")

        assert tool is None

    def test_unregister_tool(self):
        """Test unregistering a tool."""
        registry = MCPToolRegistry()

        # Register a tool
        custom_tool = MCPTool(
            name="to_remove",
            description="Will be removed",
            category=ToolCategory.SPECIALIZED,
        )
        registry.register(custom_tool)

        # Verify it's registered
        assert registry.get_tool("to_remove") is not None

        # Unregister
        registry.unregister("to_remove")

        # Verify it's gone
        assert registry.get_tool("to_remove") is None

    def test_list_tools_mcp_format(self):
        """Test listing tools returns MCP format."""
        registry = MCPToolRegistry()

        tools = registry.list_tools()

        assert isinstance(tools, list)
        assert len(tools) > 0

        # Each tool should have required MCP fields
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_list_tools_extended_format(self):
        """Test listing tools with extended metadata."""
        registry = MCPToolRegistry()

        tools = registry.list_tools_extended()

        assert len(tools) > 0

        # Extended format should include metadata
        for tool in tools:
            assert "metadata" in tool
            assert "category" in tool["metadata"]

    def test_list_tools_by_category(self):
        """Test filtering tools by category."""
        registry = MCPToolRegistry()

        static_tools = registry.list_tools(category=ToolCategory.STATIC_ANALYSIS)

        for tool in static_tools:
            # Get the actual tool to check category
            actual_tool = registry.get_tool(tool["name"])
            if actual_tool:
                assert actual_tool.category == ToolCategory.STATIC_ANALYSIS

    def test_get_tools_by_layer(self):
        """Test filtering tools by layer."""
        registry = MCPToolRegistry()

        layer1_tools = registry.get_tools_by_layer(1)

        for tool in layer1_tools:
            assert tool.layer == 1

    def test_set_handler(self):
        """Test setting a tool handler."""
        registry = MCPToolRegistry()

        def custom_handler(**kwargs):
            return {"status": "ok"}

        result = registry.set_handler("miesc_run_audit", custom_handler)

        # Handler should be set
        assert result is True
        assert "miesc_run_audit" in registry._handlers

    def test_call_tool_async(self):
        """Test calling a tool asynchronously."""
        import asyncio

        registry = MCPToolRegistry()

        async def async_handler(value=0):
            return {"result": value * 2}

        # Register the tool first
        registry.register(
            MCPTool(
                name="test_async",
                description="Async test",
                category=ToolCategory.SPECIALIZED,
                parameters=[MCPToolParameter("value", "number", "Value")],
            )
        )

        # Set handler
        registry.set_handler("test_async", async_handler)

        result = asyncio.run(registry.call_tool("test_async", {"value": 21}))

        assert result["content"][0]["data"]["result"] == 42

    def test_call_tool_not_found(self):
        """Test calling non-existent tool."""
        import asyncio

        registry = MCPToolRegistry()

        result = asyncio.run(registry.call_tool("nonexistent", {}))

        assert result["isError"] is True
        assert "unknown tool" in result["content"][0]["text"].lower()

    def test_call_tool_no_handler(self):
        """Test calling tool without handler."""
        import asyncio

        registry = MCPToolRegistry()

        # Register tool without handler
        registry.register(
            MCPTool(
                name="no_handler_tool",
                description="Tool without handler",
                category=ToolCategory.SPECIALIZED,
            )
        )

        result = asyncio.run(registry.call_tool("no_handler_tool", {}))

        assert result["isError"] is True
        assert "no handler" in result["content"][0]["text"].lower()

    def test_get_mcp_response(self):
        """Test getting full MCP response."""
        registry = MCPToolRegistry()

        response = registry.get_mcp_response()

        assert "tools" in response
        assert len(response["tools"]) > 0

        # Verify tool format
        tool = response["tools"][0]
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool

    def test_tool_count(self):
        """Test counting tools."""
        registry = MCPToolRegistry()

        count = len(registry._tools)
        assert count > 0

    def test_list_tools_excludes_unavailable(self):
        """Test that list_tools excludes unavailable tools."""
        registry = MCPToolRegistry()

        # Register unavailable tool
        registry.register(
            MCPTool(
                name="unavailable_tool",
                description="Not available",
                category=ToolCategory.SPECIALIZED,
                available=False,
            )
        )

        # list_tools automatically filters out unavailable tools
        tools = registry.list_tools()
        tool_names = [t["name"] for t in tools]

        assert "unavailable_tool" not in tool_names

    def test_get_capabilities(self):
        """Test getting MCP capabilities."""
        registry = MCPToolRegistry()

        capabilities = registry.get_capabilities()

        assert "tools" in capabilities
        assert capabilities["tools"]["listChanged"] is True
        assert "experimental" in capabilities
        assert "miesc" in capabilities["experimental"]
        assert "version" in capabilities["experimental"]["miesc"]

    def test_get_statistics(self):
        """Test getting registry statistics."""
        registry = MCPToolRegistry()

        stats = registry.get_statistics()

        assert "total_tools" in stats
        assert "available_tools" in stats
        assert "tools_with_handlers" in stats
        assert "categories" in stats
        assert stats["total_tools"] > 0

    def test_set_handler_nonexistent_tool(self):
        """Test setting handler for non-existent tool returns False."""
        registry = MCPToolRegistry()

        def handler(**kwargs):
            return {}

        result = registry.set_handler("nonexistent_tool", handler)

        assert result is False

    def test_unregister_nonexistent_tool(self):
        """Test unregistering non-existent tool returns False."""
        registry = MCPToolRegistry()

        result = registry.unregister("nonexistent_tool")

        assert result is False


class TestRegistryIntegration:
    """Integration tests for the tool registry."""

    def test_full_workflow(self):
        """Test complete registration and listing workflow."""
        registry = MCPToolRegistry()

        # Register a complete tool
        tool = MCPTool(
            name="integration_test_tool",
            description="Tool for integration testing",
            category=ToolCategory.AI_ANALYSIS,
            layer=5,
            parameters=[
                MCPToolParameter(
                    name="input_data",
                    type="string",
                    description="Input data for analysis",
                ),
                MCPToolParameter(
                    name="threshold",
                    type="number",
                    description="Confidence threshold",
                    required=False,
                    default=0.5,
                ),
            ],
        )

        registry.register(tool)

        # Verify registration
        retrieved = registry.get_tool("integration_test_tool")
        assert retrieved is not None
        assert retrieved.name == "integration_test_tool"

        # Verify MCP format
        mcp = retrieved.to_mcp_format()
        assert mcp["name"] == "integration_test_tool"
        assert "input_data" in mcp["inputSchema"]["properties"]
        assert "threshold" in mcp["inputSchema"]["properties"]
        assert "input_data" in mcp["inputSchema"]["required"]
        assert "threshold" not in mcp["inputSchema"]["required"]

        # Verify extended format
        extended = retrieved.to_extended_format()
        assert extended["metadata"]["layer"] == 5
        assert extended["metadata"]["category"] == "ai_analysis"

    def test_multiple_categories(self):
        """Test tools across multiple categories."""
        registry = MCPToolRegistry()

        # Get tools by different categories
        categories = [
            ToolCategory.STATIC_ANALYSIS,
            ToolCategory.CORRELATION,
            ToolCategory.REPORTING,
        ]

        for category in categories:
            tools = registry.list_tools(category=category)
            # Each category should have at least some tools (from defaults)
            assert isinstance(tools, list)
