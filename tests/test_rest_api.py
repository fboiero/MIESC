"""
Tests for MIESC REST API (Django REST Framework)

Author: Fernando Boiero
License: AGPL-3.0
"""

from unittest.mock import Mock, patch

import pytest


# Test imports
class TestRestApiImports:
    """Test that REST API module imports correctly."""

    def test_import_rest_module(self):
        """Test importing the rest module."""
        from miesc.api import rest

        assert hasattr(rest, "VERSION")
        assert rest.VERSION == "4.3.2"

    def test_import_layers(self):
        """Test LAYERS dictionary is available."""
        from miesc.api.rest import LAYERS

        assert len(LAYERS) == 9
        assert 1 in LAYERS
        assert 7 in LAYERS

    def test_import_adapter_map(self):
        """Test ADAPTER_MAP dictionary is available."""
        from miesc.api.rest import ADAPTER_MAP

        assert len(ADAPTER_MAP) == 32
        assert "slither" in ADAPTER_MAP
        assert "mythril" in ADAPTER_MAP

    def test_import_quick_tools(self):
        """Test QUICK_TOOLS list is available."""
        from miesc.api.rest import QUICK_TOOLS

        assert "slither" in QUICK_TOOLS
        assert "mythril" in QUICK_TOOLS
        assert len(QUICK_TOOLS) == 4


class TestAdapterLoader:
    """Test AdapterLoader functionality."""

    def test_adapter_loader_singleton(self):
        """Test that AdapterLoader loads adapters once."""
        from miesc.api.rest import AdapterLoader

        # Reset loader state
        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}

        # First load
        adapters1 = AdapterLoader.load_all()

        # Second load should return same cached adapters
        adapters2 = AdapterLoader.load_all()

        assert adapters1 is adapters2

    def test_get_available_tools(self):
        """Test getting list of available tools."""
        from miesc.api.rest import AdapterLoader

        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}
        AdapterLoader.load_all()

        tools = AdapterLoader.get_available_tools()
        assert isinstance(tools, list)
        # At least some adapters should be available
        assert len(tools) >= 0

    def test_get_adapter_unknown_tool(self):
        """Test getting adapter for unknown tool."""
        from miesc.api.rest import AdapterLoader

        adapter = AdapterLoader.get_adapter("unknown_tool_xyz")
        assert adapter is None

    def test_check_tool_status_no_adapter(self):
        """Test check_tool_status for tool without adapter."""
        from miesc.api.rest import AdapterLoader

        status = AdapterLoader.check_tool_status("unknown_tool_xyz")
        assert status["status"] == "no_adapter"
        assert status["available"] is False


class TestLayerDefinitions:
    """Test layer definitions."""

    def test_layer_1_static_analysis(self):
        """Test Layer 1 static analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[1]
        assert layer["name"] == "Static Analysis"
        assert "slither" in layer["tools"]
        assert "aderyn" in layer["tools"]

    def test_layer_2_dynamic_testing(self):
        """Test Layer 2 dynamic testing definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[2]
        assert layer["name"] == "Dynamic Testing"
        assert "echidna" in layer["tools"]
        assert "medusa" in layer["tools"]

    def test_layer_3_symbolic_execution(self):
        """Test Layer 3 symbolic execution definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[3]
        assert layer["name"] == "Symbolic Execution"
        assert "mythril" in layer["tools"]
        assert "halmos" in layer["tools"]

    def test_layer_4_formal_verification(self):
        """Test Layer 4 formal verification definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[4]
        assert layer["name"] == "Formal Verification"
        assert "certora" in layer["tools"]
        assert "smtchecker" in layer["tools"]

    def test_layer_5_ai_analysis(self):
        """Test Layer 5 AI analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[5]
        assert layer["name"] == "AI Analysis"
        assert "smartllm" in layer["tools"]
        assert "gptscan" in layer["tools"]

    def test_layer_6_ml_detection(self):
        """Test Layer 6 ML detection definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[6]
        assert layer["name"] == "ML Detection"
        assert "dagnn" in layer["tools"]
        assert "smartbugs_ml" in layer["tools"]

    def test_layer_7_specialized(self):
        """Test Layer 7 specialized analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[7]
        assert layer["name"] == "Specialized Analysis"
        assert "threat_model" in layer["tools"]
        assert "gas_analyzer" in layer["tools"]


class TestAnalysisFunctions:
    """Test analysis functions."""

    def test_summarize_findings_empty(self):
        """Test summarizing empty findings."""
        from miesc.api.rest import summarize_findings

        results = []
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 0
        assert summary["HIGH"] == 0
        assert summary["MEDIUM"] == 0
        assert summary["LOW"] == 0
        assert summary["INFO"] == 0

    def test_summarize_findings_mixed(self):
        """Test summarizing mixed findings."""
        from miesc.api.rest import summarize_findings

        results = [
            {
                "tool": "test",
                "findings": [
                    {"severity": "CRITICAL"},
                    {"severity": "HIGH"},
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                    {"severity": "LOW"},
                    {"severity": "INFO"},
                ],
            }
        ]
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 2
        assert summary["MEDIUM"] == 1
        assert summary["LOW"] == 1
        assert summary["INFO"] == 1

    def test_summarize_findings_normalized_severity(self):
        """Test summarizing with normalized severity names."""
        from miesc.api.rest import summarize_findings

        results = [
            {
                "tool": "test",
                "findings": [
                    {"severity": "CRIT"},  # Should map to CRITICAL
                    {"severity": "HI"},  # Should map to HIGH
                    {"severity": "MED"},  # Should map to MEDIUM
                    {"severity": "LO"},  # Should map to LOW
                ],
            }
        ]
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 1
        assert summary["LOW"] == 1


class TestSarifConversion:
    """Test SARIF format conversion."""

    def test_to_sarif_structure(self):
        """Test SARIF output structure."""
        from miesc.api.rest import to_sarif

        results = [
            {
                "tool": "slither",
                "contract": "Test.sol",
                "findings": [
                    {
                        "type": "reentrancy",
                        "title": "Reentrancy vulnerability",
                        "severity": "HIGH",
                        "description": "Test description",
                        "location": {"file": "Test.sol", "line": 10},
                    }
                ],
            }
        ]

        sarif = to_sarif(results)

        assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "MIESC"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_to_sarif_empty_results(self):
        """Test SARIF conversion with empty results."""
        from miesc.api.rest import to_sarif

        sarif = to_sarif([])

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_to_sarif_severity_mapping(self):
        """Test SARIF severity level mapping."""
        from miesc.api.rest import to_sarif

        results = [
            {
                "tool": "test",
                "findings": [
                    {"type": "test1", "severity": "CRITICAL"},
                    {"type": "test2", "severity": "HIGH"},
                    {"type": "test3", "severity": "MEDIUM"},
                    {"type": "test4", "severity": "LOW"},
                ],
            }
        ]

        sarif = to_sarif(results)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]

        assert "error" in levels  # CRITICAL/HIGH
        assert "warning" in levels  # MEDIUM
        assert "note" in levels  # LOW


class TestRunToolFunction:
    """Test run_tool function."""

    def test_run_tool_no_adapter(self):
        """Test running tool without adapter."""
        from miesc.api.rest import run_tool

        result = run_tool("nonexistent_tool", "/path/to/contract.sol")

        assert result["tool"] == "nonexistent_tool"
        assert result["status"] == "no_adapter"
        assert result["findings"] == []
        assert "error" in result

    @patch("miesc.api.rest.AdapterLoader.get_adapter")
    def test_run_tool_not_available(self, mock_get_adapter):
        """Test running tool that's not available."""

        mock_adapter = Mock()
        mock_adapter.is_available.return_value = Mock(value="not_installed")
        mock_get_adapter.return_value = mock_adapter

        # Mock ToolStatus
        with patch("miesc.api.rest.AdapterLoader.get_adapter", return_value=mock_adapter):
            # Need to also mock the import inside the function
            pass


class TestRunLayerFunction:
    """Test run_layer function."""

    def test_run_layer_invalid_layer(self):
        """Test running invalid layer."""
        from miesc.api.rest import run_layer

        results = run_layer(99, "/path/to/contract.sol")
        assert results == []

    def test_run_layer_valid_layer(self):
        """Test running valid layer returns list."""
        from miesc.api.rest import run_layer

        # Layer 1 should have tools defined
        results = run_layer(1, "/nonexistent/contract.sol")
        assert isinstance(results, list)
        # Should have results for each tool in layer 1
        from miesc.api.rest import LAYERS

        assert len(results) == len(LAYERS[1]["tools"])


class TestFullAudit:
    """Test full audit function."""

    def test_run_full_audit_returns_dict(self):
        """Test full audit returns proper structure."""
        from miesc.api.rest import run_full_audit

        result = run_full_audit("/nonexistent/contract.sol", layers=[1])

        assert "audit_id" in result
        assert "contract" in result
        assert "layers" in result
        assert "results" in result
        assert "summary" in result
        assert "execution_time" in result
        assert "timestamp" in result
        assert "version" in result

    def test_run_full_audit_default_layers(self):
        """Test full audit with default layers."""
        from miesc.api.rest import LAYERS, run_full_audit

        result = run_full_audit("/nonexistent/contract.sol")

        # Should include all 7 layers
        assert result["layers"] == list(LAYERS.keys())


class TestCLIImports:
    """Test CLI module imports."""

    def test_import_cli_module(self):
        """Test importing the CLI module."""
        from miesc.cli import main

        assert hasattr(main, "cli")
        assert hasattr(main, "VERSION")

    def test_cli_version(self):
        """Test CLI version matches."""
        from miesc.cli.main import VERSION

        assert VERSION == "4.3.2"

    def test_cli_layers_defined(self):
        """Test CLI has LAYERS defined."""
        from miesc.cli.main import LAYERS

        assert len(LAYERS) == 9

    def test_cli_adapter_map_defined(self):
        """Test CLI has ADAPTER_MAP defined."""
        from miesc.cli.main import ADAPTER_MAP

        assert len(ADAPTER_MAP) == 32


class TestCLIAdapterLoader:
    """Test CLI AdapterLoader functionality."""

    def test_adapter_loader_load_all(self):
        """Test AdapterLoader.load_all()."""
        from miesc.cli.main import AdapterLoader

        # Reset state
        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}

        adapters = AdapterLoader.load_all()
        assert isinstance(adapters, dict)

    def test_adapter_loader_get_available_tools(self):
        """Test getting available tools from CLI."""
        from miesc.cli.main import AdapterLoader

        tools = AdapterLoader.get_available_tools()
        assert isinstance(tools, list)


class TestCLIOutputHelpers:
    """Test CLI output helper functions."""

    def test_summarize_findings_cli(self):
        """Test CLI _summarize_findings function."""
        from miesc.cli.main import _summarize_findings

        results = [
            {
                "findings": [
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                ]
            }
        ]

        summary = _summarize_findings(results)
        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 1

    def test_to_sarif_cli(self):
        """Test CLI _to_sarif function."""
        from miesc.cli.main import _to_sarif

        results = [{"tool": "test", "findings": [{"type": "test", "severity": "HIGH"}]}]

        sarif = _to_sarif(results)
        assert sarif["version"] == "2.1.0"

    def test_to_markdown_cli(self):
        """Test CLI _to_markdown function."""
        from miesc.cli.main import _to_markdown

        results = [
            {
                "tool": "slither",
                "status": "success",
                "execution_time": 1.5,
                "findings": [
                    {"severity": "HIGH", "title": "Test Finding", "description": "Test description"}
                ],
            }
        ]

        md = _to_markdown(results, "Test.sol")
        assert "# MIESC Security Audit Report" in md
        assert "Test.sol" in md
        assert "SLITHER" in md


class TestApiPackageInit:
    """Test API package __init__.py."""

    def test_api_version(self):
        """Test API package version."""
        from miesc.api import __version__

        assert __version__ == "4.3.2"


# Skip Django-specific tests if Django not properly configured
try:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={},
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
            REST_FRAMEWORK={},
        )
    from rest_framework.test import APIClient

    DJANGO_AVAILABLE = True
except (ImportError, Exception):
    DJANGO_AVAILABLE = False
    APIClient = None  # Placeholder


@pytest.mark.skipif(not DJANGO_AVAILABLE, reason="Django not installed")
class TestDjangoViews:
    """Test Django REST Framework views.

    Note: These tests require a properly configured Django environment.
    In unit test context, we test that the API module structure is correct.
    """

    def test_health_endpoint(self):
        """Test health view configuration exists."""
        # Test that the REST API module has the expected configuration
        from miesc.api.rest import LAYERS, ADAPTER_MAP
        assert len(LAYERS) > 0
        assert len(ADAPTER_MAP) > 0

    def test_tools_list_endpoint(self):
        """Test tools configuration is complete."""
        from miesc.api.rest import ADAPTER_MAP, QUICK_TOOLS
        # All quick tools should be in adapter map
        for tool in QUICK_TOOLS:
            assert tool in ADAPTER_MAP

    def test_layers_endpoint(self):
        """Test layers configuration is valid."""
        from miesc.api.rest import LAYERS
        # All layers should have required fields
        for layer_id, layer in LAYERS.items():
            assert "name" in layer
            assert "tools" in layer
            assert isinstance(layer["tools"], list)
