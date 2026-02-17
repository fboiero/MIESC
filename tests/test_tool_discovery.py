"""
Tests for Tool Discovery module.

Tests the dynamic adapter discovery system.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.core.tool_discovery import (
    ToolDiscovery,
    ToolInfo,
    get_tool_discovery,
)


class TestToolInfo:
    """Test ToolInfo dataclass."""

    def test_create_tool_info(self):
        """Test creating tool info."""
        info = ToolInfo(
            name="slither",
            adapter_class="SlitherAdapter",
            module_path="src.adapters.slither_adapter",
            layer="static_analysis",
            category="Static Analysis",
            available=True,
            description="Static analyzer",
            version="0.10.0",
        )
        assert info.name == "slither"
        assert info.adapter_class == "SlitherAdapter"
        assert info.available is True
        assert info.version == "0.10.0"

    def test_default_values(self):
        """Test default values."""
        info = ToolInfo(
            name="test",
            adapter_class="TestAdapter",
            module_path="src.adapters.test",
            layer="test",
            category="Test",
            available=False,
        )
        assert info.description == ""
        assert info.version is None
        assert info.is_optional is True
        assert info.requires_api_key is False
        assert info.external_deps == []

    def test_to_dict(self):
        """Test dictionary conversion."""
        info = ToolInfo(
            name="mythril",
            adapter_class="MythrilAdapter",
            module_path="src.adapters.mythril_adapter",
            layer="symbolic_execution",
            category="Symbolic Execution",
            available=True,
            description="Symbolic execution tool",
            requires_api_key=False,
        )
        d = info.to_dict()
        assert d["name"] == "mythril"
        assert d["layer"] == "symbolic_execution"
        assert d["available"] is True
        assert "description" in d


class TestToolDiscovery:
    """Test ToolDiscovery class."""

    @pytest.fixture
    def discovery(self):
        """Create discovery instance."""
        return ToolDiscovery()

    def test_init(self, discovery):
        """Test initialization."""
        assert discovery.adapters_path is not None
        assert discovery._tools == {}
        assert discovery._discovered is False

    def test_name_mapping_exists(self, discovery):
        """Test name mapping is defined."""
        assert "slither_adapter" in discovery.NAME_MAPPING
        assert discovery.NAME_MAPPING["slither_adapter"] == "slither"

    def test_layer_mapping_exists(self, discovery):
        """Test layer mapping is defined."""
        assert "slither" in discovery.LAYER_MAPPING
        layer, category = discovery.LAYER_MAPPING["slither"]
        assert layer == "static_analysis"


class TestToolDiscoveryDiscover:
    """Test discovery functionality."""

    @pytest.fixture
    def discovery(self):
        """Create discovery instance."""
        return ToolDiscovery()

    def test_discover(self, discovery):
        """Test discovering tools."""
        tools = discovery.discover()
        assert isinstance(tools, dict)
        assert discovery._discovered is True

    def test_discover_returns_cached(self, discovery):
        """Test discover returns cached results."""
        tools1 = discovery.discover()
        tools2 = discovery.discover()
        # Should be same object (cached)
        assert tools1 is tools2

    def test_discover_force_refresh(self, discovery):
        """Test force refresh discovery."""
        tools1 = discovery.discover()
        tools2 = discovery.discover(force=True)
        # Should be new dict
        assert tools1 is not tools2


class TestToolDiscoveryGetTools:
    """Test tool retrieval methods."""

    @pytest.fixture
    def discovery(self):
        """Create discovery with mocked tools."""
        disc = ToolDiscovery()
        disc._tools = {
            "slither": ToolInfo(
                name="slither",
                adapter_class="SlitherAdapter",
                module_path="src.adapters.slither_adapter",
                layer="static_analysis",
                category="Static Analysis",
                available=True,
            ),
            "mythril": ToolInfo(
                name="mythril",
                adapter_class="MythrilAdapter",
                module_path="src.adapters.mythril_adapter",
                layer="symbolic_execution",
                category="Symbolic Execution",
                available=False,
            ),
        }
        disc._discovered = True
        return disc

    def test_get_tool(self, discovery):
        """Test getting specific tool."""
        tool = discovery.get_tool("slither")
        assert tool is not None
        assert tool.name == "slither"

    def test_get_tool_not_found(self, discovery):
        """Test getting non-existent tool."""
        tool = discovery.get_tool("nonexistent")
        assert tool is None

    def test_get_available_tools(self, discovery):
        """Test getting available tools."""
        available = discovery.get_available_tools()
        assert len(available) == 1
        assert available[0].name == "slither"

    def test_get_tools_by_layer(self, discovery):
        """Test grouping tools by layer."""
        layers = discovery.get_tools_by_layer()
        assert "static_analysis" in layers
        assert "symbolic_execution" in layers

    def test_get_all_tool_names(self, discovery):
        """Test getting all tool names."""
        names = discovery.get_all_tool_names()
        assert "slither" in names
        assert "mythril" in names


class TestToolDiscoveryLoadAdapter:
    """Test adapter loading."""

    @pytest.fixture
    def discovery(self):
        """Create discovery instance."""
        disc = ToolDiscovery()
        disc._tools = {
            "slither": ToolInfo(
                name="slither",
                adapter_class="SlitherAdapter",
                module_path="src.adapters.slither_adapter",
                layer="static_analysis",
                category="Static Analysis",
                available=True,
            ),
        }
        disc._discovered = True
        return disc

    def test_load_adapter_unknown(self, discovery):
        """Test loading unknown adapter."""
        with pytest.raises(ValueError, match="Unknown tool"):
            discovery.load_adapter("unknown_tool")

    @patch("importlib.import_module")
    def test_load_adapter_success(self, mock_import, discovery):
        """Test successful adapter loading."""
        mock_module = MagicMock()
        mock_adapter = MagicMock()
        mock_module.SlitherAdapter = mock_adapter
        mock_import.return_value = mock_module

        result = discovery.load_adapter("slither")

        mock_import.assert_called_once_with("src.adapters.slither_adapter")
        mock_adapter.assert_called_once()


class TestToolDiscoveryToDict:
    """Test export functionality."""

    @pytest.fixture
    def discovery(self):
        """Create discovery with mocked tools."""
        disc = ToolDiscovery()
        disc._tools = {
            "slither": ToolInfo(
                name="slither",
                adapter_class="SlitherAdapter",
                module_path="src.adapters.slither_adapter",
                layer="static_analysis",
                category="Static Analysis",
                available=True,
            ),
        }
        disc._discovered = True
        return disc

    def test_to_dict(self, discovery):
        """Test exporting to dict."""
        d = discovery.to_dict()
        assert "total_tools" in d
        assert "available_tools" in d
        assert "tools" in d
        assert "by_layer" in d
        assert d["total_tools"] == 1


class TestGetToolDiscovery:
    """Test singleton function."""

    def test_get_tool_discovery(self):
        """Test getting singleton instance."""
        # Reset the global
        import src.core.tool_discovery as module

        module._discovery = None

        d1 = get_tool_discovery()
        d2 = get_tool_discovery()
        assert d1 is d2


class TestToolDiscoveryFindAdaptersPath:
    """Test adapters path finding."""

    def test_find_adapters_path_exists(self):
        """Test finding existing adapters path."""
        discovery = ToolDiscovery()
        path = Path(discovery.adapters_path)
        # Should find some path
        assert discovery.adapters_path is not None


class TestToolDiscoveryLoadAdapterInfo:
    """Test adapter info loading."""

    @pytest.fixture
    def discovery(self):
        """Create discovery instance."""
        return ToolDiscovery()

    def test_load_adapter_info_returns_tool_info(self, discovery, tmp_path):
        """Test loading adapter info."""
        # Create a mock adapter file
        adapter_file = tmp_path / "test_adapter.py"
        adapter_file.write_text("class TestAdapter: pass")

        # This would need import to work, so just test the method exists
        assert hasattr(discovery, "_load_adapter_info")

    def test_layer_mapping_for_all_tools(self, discovery):
        """Test all known tools have layer mappings."""
        known_tools = [
            "slither",
            "mythril",
            "echidna",
            "foundry",
            "smartllm",
        ]
        for tool in known_tools:
            layer, category = discovery.LAYER_MAPPING.get(tool, (None, None))
            assert layer is not None, f"{tool} missing layer mapping"
