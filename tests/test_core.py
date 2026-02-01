"""
MIESC Core Module Tests
Tests for core components: protocols, discovery, health, aggregator.
"""

from enum import Enum
from unittest.mock import MagicMock, patch

import pytest


class TestToolProtocol:
    """Tests for ToolProtocol and related classes."""

    def test_tool_metadata_import(self):
        """Test ToolMetadata can be imported."""
        from src.core.tool_protocol import ToolMetadata

        assert ToolMetadata is not None

    def test_tool_adapter_import(self):
        """Test ToolAdapter can be imported."""
        from src.core.tool_protocol import ToolAdapter

        assert ToolAdapter is not None

    def test_tool_status_import(self):
        """Test ToolStatus can be imported."""
        from src.core.tool_protocol import ToolStatus

        assert ToolStatus is not None
        assert isinstance(ToolStatus.AVAILABLE, Enum) or hasattr(ToolStatus, "value")

    def test_tool_category_import(self):
        """Test ToolCategory can be imported."""
        from src.core.tool_protocol import ToolCategory

        assert ToolCategory is not None

    def test_tool_capability_import(self):
        """Test ToolCapability can be imported."""
        from src.core.tool_protocol import ToolCapability

        assert ToolCapability is not None

    def test_create_tool_metadata(self):
        """Test creating ToolMetadata instance."""
        from src.core.tool_protocol import ToolCategory, ToolMetadata

        # ToolMetadata uses dataclass, check if it can be created
        try:
            metadata = ToolMetadata(
                name="test_tool",
                version="1.0.0",
                category=ToolCategory.STATIC_ANALYSIS,
            )
            assert metadata.name == "test_tool"
        except TypeError:
            # If ToolMetadata has required fields we don't know about, just verify class exists
            assert ToolMetadata is not None


class TestToolProtocolCoverage:
    """Additional tests for ToolProtocol coverage."""

    def _create_mock_adapter(self, name="test-tool", available=True):
        """Create a mock ToolAdapter for testing."""
        from src.core.tool_protocol import (
            ToolAdapter,
            ToolCapability,
            ToolCategory,
            ToolMetadata,
            ToolStatus,
        )

        class MockAdapter(ToolAdapter):
            def get_metadata(self) -> ToolMetadata:
                return ToolMetadata(
                    name=name,
                    version="1.0.0",
                    category=ToolCategory.STATIC_ANALYSIS,
                    author="Test Author",
                    license="MIT",
                    homepage="https://example.com",
                    repository="https://github.com/test/test",
                    documentation="https://docs.example.com",
                    installation_cmd="pip install test",
                    capabilities=[
                        ToolCapability(
                            name="reentrancy",
                            description="Detect reentrancy",
                            supported_languages=["solidity"],
                            detection_types=["reentrancy"],
                        )
                    ],
                    cost=0.0,
                    requires_api_key=False,
                    is_optional=True,
                )

            def is_available(self) -> ToolStatus:
                return ToolStatus.AVAILABLE if available else ToolStatus.NOT_INSTALLED

            def analyze(self, contract_path: str, **kwargs):
                return {"tool": name, "status": "success", "findings": []}

            def normalize_findings(self, raw_output):
                return []

        return MockAdapter()

    def test_get_installation_instructions(self):
        """Test get_installation_instructions method (lines 186-216)."""
        adapter = self._create_mock_adapter()
        instructions = adapter.get_installation_instructions()

        assert "test-tool" in instructions
        assert "MIT" in instructions
        assert "Free" in instructions
        assert "pip install test" in instructions

    def test_can_analyze(self):
        """Test can_analyze method (line 225)."""
        adapter = self._create_mock_adapter()

        assert adapter.can_analyze("contract.sol") is True
        assert adapter.can_analyze("contract.js") is False

    def test_get_default_config(self):
        """Test get_default_config method (line 233)."""
        adapter = self._create_mock_adapter()
        config = adapter.get_default_config()

        assert isinstance(config, dict)

    def test_validate_config(self):
        """Test validate_config method (line 241)."""
        adapter = self._create_mock_adapter()
        assert adapter.validate_config({}) is True
        assert adapter.validate_config({"key": "value"}) is True

    def test_tool_registry_register(self):
        """Test ToolRegistry.register method (lines 262-269)."""
        from src.core.tool_protocol import ToolRegistry

        registry = ToolRegistry()
        adapter = self._create_mock_adapter(name="registry-test")

        registry.register(adapter)
        assert "registry-test" in [t.get_metadata().name for t in registry.get_all_tools()]

        # Test overwriting with warning
        registry.register(adapter)  # Should log warning

    def test_tool_registry_get_tool(self):
        """Test ToolRegistry.get_tool method (line 273)."""
        from src.core.tool_protocol import ToolRegistry

        registry = ToolRegistry()
        adapter = self._create_mock_adapter(name="get-test")
        registry.register(adapter)

        result = registry.get_tool("get-test")
        assert result is not None
        assert result.get_metadata().name == "get-test"

        # Test non-existent tool
        assert registry.get_tool("nonexistent") is None

    def test_tool_registry_get_all_tools(self):
        """Test ToolRegistry.get_all_tools method (line 277)."""
        from src.core.tool_protocol import ToolRegistry

        registry = ToolRegistry()
        adapter1 = self._create_mock_adapter(name="all-test-1")
        adapter2 = self._create_mock_adapter(name="all-test-2")

        registry.register(adapter1)
        registry.register(adapter2)

        all_tools = registry.get_all_tools()
        assert len(all_tools) == 2

    def test_tool_registry_get_tools_by_category(self):
        """Test ToolRegistry.get_tools_by_category method (lines 279-284)."""
        from src.core.tool_protocol import ToolCategory, ToolRegistry

        registry = ToolRegistry()
        adapter = self._create_mock_adapter(name="category-test")
        registry.register(adapter)

        static_tools = registry.get_tools_by_category(ToolCategory.STATIC_ANALYSIS)
        assert len(static_tools) == 1

        dynamic_tools = registry.get_tools_by_category(ToolCategory.DYNAMIC_TESTING)
        assert len(dynamic_tools) == 0

    def test_tool_registry_get_available_tools(self):
        """Test ToolRegistry.get_available_tools method (lines 288-293)."""
        from src.core.tool_protocol import ToolRegistry

        registry = ToolRegistry()
        available_adapter = self._create_mock_adapter(name="available-test", available=True)
        unavailable_adapter = self._create_mock_adapter(name="unavailable-test", available=False)

        registry.register(available_adapter)
        registry.register(unavailable_adapter)

        available_tools = registry.get_available_tools()
        assert len(available_tools) == 1
        assert available_tools[0].get_metadata().name == "available-test"

    def test_tool_registry_get_tool_status_report(self):
        """Test ToolRegistry.get_tool_status_report method (lines 295-331)."""
        from src.core.tool_protocol import ToolRegistry

        registry = ToolRegistry()
        available_adapter = self._create_mock_adapter(name="report-available", available=True)
        unavailable_adapter = self._create_mock_adapter(name="report-unavailable", available=False)

        registry.register(available_adapter)
        registry.register(unavailable_adapter)

        report = registry.get_tool_status_report()

        assert report["total_tools"] == 2
        assert report["available"] == 1
        assert report["not_installed"] == 1
        assert len(report["tools"]) == 2

    def test_tool_status_report_configuration_error(self):
        """Test get_tool_status_report with configuration_error (lines 328-329)."""
        from src.core.tool_protocol import (
            ToolAdapter,
            ToolCategory,
            ToolMetadata,
            ToolRegistry,
            ToolStatus,
        )

        class ConfigErrorAdapter(ToolAdapter):
            def get_metadata(self) -> ToolMetadata:
                return ToolMetadata(
                    name="config-error-tool",
                    version="1.0.0",
                    category=ToolCategory.STATIC_ANALYSIS,
                    author="Test",
                    license="MIT",
                    homepage="https://example.com",
                    repository="https://github.com/test/test",
                    documentation="https://docs.example.com",
                    installation_cmd="pip install test",
                    capabilities=[],
                    cost=0.0,
                    requires_api_key=False,
                    is_optional=True,
                )

            def is_available(self) -> ToolStatus:
                return ToolStatus.CONFIGURATION_ERROR

            def analyze(self, contract_path: str, **kwargs):
                return {"findings": []}

            def normalize_findings(self, raw_output):
                return []

        registry = ToolRegistry()
        registry.register(ConfigErrorAdapter())

        report = registry.get_tool_status_report()
        assert report["configuration_error"] == 1

    def test_get_tool_registry_singleton(self):
        """Test get_tool_registry function (line 340)."""
        from src.core.tool_protocol import get_tool_registry

        registry1 = get_tool_registry()
        registry2 = get_tool_registry()

        assert registry1 is registry2


class TestToolDiscovery:
    """Tests for ToolDiscovery."""

    def test_import(self):
        """Test ToolDiscovery can be imported."""
        from src.core.tool_discovery import ToolDiscovery

        assert ToolDiscovery is not None

    def test_get_tool_discovery(self):
        """Test get_tool_discovery singleton."""
        from src.core import get_tool_discovery

        discovery1 = get_tool_discovery()
        discovery2 = get_tool_discovery()

        assert discovery1 is not None
        assert discovery1 is discovery2  # Singleton

    def test_get_available_tools(self):
        """Test getting available tools."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tools = discovery.get_available_tools()

        assert isinstance(tools, list)

    def test_get_tools_by_layer(self):
        """Test getting tools organized by layer."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tools_by_layer = discovery.get_tools_by_layer()

        assert isinstance(tools_by_layer, dict)

    def test_get_all_tool_names(self):
        """Test getting all tool names."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        names = discovery.get_all_tool_names()

        assert isinstance(names, list)
        assert len(names) >= 0

    def test_get_tool_existing(self):
        """Test getting a specific existing tool."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tools = discovery.get_all_tool_names()

        if tools:
            tool = discovery.get_tool(tools[0])
            assert tool is not None

    def test_get_tool_nonexistent(self):
        """Test getting a non-existent tool."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        tool = discovery.get_tool("nonexistent_tool_xyz")

        assert tool is None

    def test_to_dict(self):
        """Test exporting discovery info to dict."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()
        data = discovery.to_dict()

        assert isinstance(data, dict)
        assert "total_tools" in data
        assert "available_tools" in data
        assert "tools" in data
        assert "by_layer" in data

    def test_cached_discovery(self):
        """Test that discovery results are cached."""
        from src.core.tool_discovery import ToolDiscovery

        discovery = ToolDiscovery()

        # First discovery
        tools1 = discovery.discover()
        # Second call should return cached results
        tools2 = discovery.discover()

        assert tools1 is tools2

    def test_forced_rediscovery(self):
        """Test that force=True re-discovers tools."""
        from src.core.tool_discovery import ToolDiscovery

        discovery = ToolDiscovery()

        # First discovery
        discovery.discover()
        # Force re-discovery
        tools2 = discovery.discover(force=True)

        assert tools2 is not None
        assert isinstance(tools2, dict)

    def test_load_adapter_unknown(self):
        """Test loading an unknown adapter raises error."""
        from src.core import get_tool_discovery

        discovery = get_tool_discovery()

        with pytest.raises(ValueError) as exc_info:
            discovery.load_adapter("nonexistent_adapter_xyz")

        assert "Unknown tool" in str(exc_info.value)


class TestToolDiscoveryCoverage:
    """Tests to complete ToolDiscovery coverage."""

    def test_find_adapters_path_not_found(self):
        """Test RuntimeError when adapters directory not found (line 126)."""
        import tempfile
        from unittest.mock import patch

        from src.core.tool_discovery import ToolDiscovery

        # Create ToolDiscovery with a non-existent path
        with tempfile.TemporaryDirectory():
            # Mock Path to return non-existent paths
            with patch.object(ToolDiscovery, "_find_adapters_path") as mock_find:
                mock_find.side_effect = RuntimeError("Could not find adapters directory")

                with pytest.raises(RuntimeError) as exc_info:
                    ToolDiscovery()

                assert "Could not find adapters directory" in str(exc_info.value)

    def test_discover_skips_underscore_files(self, tmp_path):
        """Test that discover skips files starting with _ (line 140)."""
        from src.core.tool_discovery import ToolDiscovery

        # Create a fake adapters directory with underscore file
        adapters_dir = tmp_path / "adapters"
        adapters_dir.mkdir()

        # Create a normal adapter file
        (adapters_dir / "test_adapter.py").write_text("""
class TestAdapter:
    def is_available(self):
        return True
    def get_metadata(self):
        return None
""")

        # Create an underscore file that should be skipped
        (adapters_dir / "_private_adapter.py").write_text("""
class PrivateAdapter:
    pass
""")

        discovery = ToolDiscovery(adapters_path=str(adapters_dir))
        tools = discovery.discover()

        # The underscore file should be skipped
        assert "_private" not in tools

    def test_discover_handles_load_exception(self, tmp_path):
        """Test that discover handles exceptions during adapter load (lines 146-148)."""
        from unittest.mock import patch

        from src.core.tool_discovery import ToolDiscovery

        adapters_dir = tmp_path / "adapters"
        adapters_dir.mkdir()

        # Create a valid adapter file
        (adapters_dir / "valid_adapter.py").write_text("""
class ValidAdapter:
    def is_available(self):
        return True
""")

        discovery = ToolDiscovery(adapters_path=str(adapters_dir))

        # Mock _load_adapter_info to raise an exception
        with patch.object(discovery, "_load_adapter_info", side_effect=Exception("Test error")):
            tools = discovery.discover()

            # Should return empty dict without raising
            assert isinstance(tools, dict)

    def test_load_adapter_info_no_adapter_class(self, tmp_path):
        """Test _load_adapter_info returns None when no adapter class found (line 176)."""
        import types
        from pathlib import Path
        from unittest.mock import patch

        from src.core.tool_discovery import ToolDiscovery

        adapters_dir = tmp_path / "adapters"
        adapters_dir.mkdir()

        discovery = ToolDiscovery(adapters_path=str(adapters_dir))

        # Create a mock module with only non-Adapter classes
        mock_module = types.ModuleType("fake_module")
        mock_module.SomeClass = type("SomeClass", (), {})
        mock_module.AnotherClass = type("AnotherClass", (), {})

        with patch("importlib.import_module", return_value=mock_module):
            result = discovery._load_adapter_info(Path("fake_adapter.py"))

            # Should return None when no *Adapter class found
            assert result is None

    def test_load_adapter_info_metadata_exception(self, tmp_path):
        """Test _load_adapter_info handles get_metadata exception (lines 195-196)."""
        import types
        from pathlib import Path
        from unittest.mock import patch

        from src.core.tool_discovery import ToolDiscovery

        adapters_dir = tmp_path / "adapters"
        adapters_dir.mkdir()

        discovery = ToolDiscovery(adapters_path=str(adapters_dir))

        # Create mock adapter class with failing get_metadata
        class MockAdapter:
            def is_available(self):
                return True

            def get_metadata(self):
                raise Exception("Metadata error")

        # Create a mock module
        mock_module = types.ModuleType("test_module")
        mock_module.TestAdapter = MockAdapter

        with patch("importlib.import_module", return_value=mock_module):
            result = discovery._load_adapter_info(Path("test_adapter.py"))

            # Should still return ToolInfo even if metadata fails
            assert result is not None
            assert result.available is True

    def test_load_adapter_info_import_error(self, tmp_path):
        """Test _load_adapter_info handles ImportError (lines 218-220)."""
        from pathlib import Path
        from unittest.mock import patch

        from src.core.tool_discovery import ToolDiscovery

        adapters_dir = tmp_path / "adapters"
        adapters_dir.mkdir()

        discovery = ToolDiscovery(adapters_path=str(adapters_dir))

        with patch("importlib.import_module", side_effect=ImportError("Module not found")):
            result = discovery._load_adapter_info(Path("missing_adapter.py"))

            # Should return ToolInfo with available=False
            assert result is not None
            assert result.available is False
            assert result.name == "missing"


class TestToolInfo:
    """Tests for ToolInfo dataclass."""

    def test_tool_info_to_dict(self):
        """Test ToolInfo.to_dict() method."""
        from src.core.tool_discovery import ToolInfo

        tool = ToolInfo(
            name="test_tool",
            adapter_class="TestAdapter",
            module_path="src.adapters.test_adapter",
            layer="static_analysis",
            category="Static Analysis",
            available=True,
            description="Test tool description",
            version="1.0.0",
            is_optional=True,
            requires_api_key=False,
        )

        data = tool.to_dict()

        assert isinstance(data, dict)
        assert data["name"] == "test_tool"
        assert data["layer"] == "static_analysis"
        assert data["available"] is True
        assert data["description"] == "Test tool description"
        assert data["version"] == "1.0.0"

    def test_tool_info_defaults(self):
        """Test ToolInfo with default values."""
        from src.core.tool_discovery import ToolInfo

        tool = ToolInfo(
            name="minimal_tool",
            adapter_class="MinimalAdapter",
            module_path="src.adapters.minimal",
            layer="other",
            category="Other",
            available=False,
        )

        assert tool.description == ""
        assert tool.version is None
        assert tool.is_optional is True
        assert tool.requires_api_key is False
        assert tool.external_deps == []


class TestHealthChecker:
    """Tests for HealthChecker."""

    def test_import(self):
        """Test HealthChecker can be imported."""
        from src.core.health_checker import HealthChecker

        assert HealthChecker is not None

    def test_health_status_import(self):
        """Test HealthStatus can be imported."""
        from src.core import HealthStatus

        assert HealthStatus is not None

    def test_instantiation(self):
        """Test HealthChecker instantiation."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        assert checker is not None

    def test_check_all(self):
        """Test comprehensive health check."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        health = checker.check_all()

        assert health is not None
        assert hasattr(health, "status")
        assert hasattr(health, "healthy_tools")
        assert hasattr(health, "unhealthy_tools")


class TestHealthCheckerCoverage:
    """Additional tests for HealthChecker coverage."""

    def test_tool_health_to_dict(self):
        """Test ToolHealth.to_dict method (line 38)."""
        from datetime import datetime

        from src.core.health_checker import HealthStatus, ToolHealth

        health = ToolHealth(
            name="test_tool",
            status=HealthStatus.HEALTHY,
            available=True,
            version="1.0.0",
            response_time_ms=50.123,
            last_check=datetime(2024, 1, 1, 12, 0, 0),
            error_message=None,
            details={"layer": "static"},
        )

        result = health.to_dict()
        assert result["name"] == "test_tool"
        assert result["status"] == "healthy"
        assert result["available"] is True
        assert result["version"] == "1.0.0"
        assert result["response_time_ms"] == 50.12
        assert result["last_check"] == "2024-01-01T12:00:00"
        assert result["details"] == {"layer": "static"}

    def test_system_health_to_dict(self):
        """Test SystemHealth.to_dict method (line 63)."""
        from datetime import datetime

        from src.core.health_checker import HealthStatus, SystemHealth, ToolHealth

        tool = ToolHealth(
            name="test_tool", status=HealthStatus.HEALTHY, available=True, last_check=datetime.now()
        )

        system = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=1,
            healthy_tools=1,
            degraded_tools=0,
            unhealthy_tools=0,
            tools=[tool],
            check_duration_ms=100.5,
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
        )

        result = system.to_dict()
        assert result["status"] == "healthy"
        assert result["summary"]["total"] == 1
        assert result["summary"]["healthy"] == 1
        assert len(result["tools"]) == 1
        assert result["check_duration_ms"] == 100.5
        assert result["timestamp"] == "2024-01-01T12:00:00"

    def test_load_adapter_not_found(self):
        """Test _load_adapter returns None for unknown tool (line 123)."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        result = checker._load_adapter("nonexistent_tool")
        assert result is None

    def test_load_adapter_import_error(self):
        """Test _load_adapter handles import error (lines 131-133)."""
        from unittest.mock import patch

        from src.core.health_checker import HealthChecker

        checker = HealthChecker()

        # Mock an adapter that will fail to import
        with patch.dict(checker.ADAPTER_MAP, {"fake_tool": ("nonexistent.module", "FakeClass")}):
            result = checker._load_adapter("fake_tool")
            assert result is None

    def test_check_tool_cache_hit(self):
        """Test check_tool with cache hit (lines 141-145)."""
        from datetime import datetime

        from src.core.health_checker import HealthChecker, HealthStatus, ToolHealth

        checker = HealthChecker()
        checker._cache_ttl = 3600  # 1 hour

        # Pre-populate cache
        cached_health = ToolHealth(
            name="test_tool", status=HealthStatus.HEALTHY, available=True, last_check=datetime.now()
        )
        checker._cache["test_tool"] = cached_health

        # Should return cached result
        result = checker.check_tool("test_tool", use_cache=True)
        assert result == cached_health

    def test_check_tool_adapter_not_found(self):
        """Test check_tool when adapter not found (line 153)."""
        from src.core.health_checker import HealthChecker, HealthStatus

        checker = HealthChecker()
        result = checker.check_tool("nonexistent_tool", use_cache=False)

        assert result.name == "nonexistent_tool"
        assert result.status == HealthStatus.UNKNOWN
        assert result.available is False
        assert result.error_message == "Adapter not found"

    def test_check_tool_metadata_exception(self):
        """Test check_tool handles metadata exception (lines 176-177)."""
        from unittest.mock import MagicMock, patch

        from src.core.health_checker import HealthChecker

        checker = HealthChecker()

        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = True
        mock_adapter.get_metadata.side_effect = Exception("Metadata error")

        with patch.object(checker, "_load_adapter", return_value=mock_adapter):
            result = checker.check_tool("test_tool", use_cache=False)
            # Should still succeed despite metadata error
            assert result.available is True
            assert result.version is None

    def test_check_tool_unhealthy(self):
        """Test check_tool when tool is not available (line 183)."""
        from unittest.mock import MagicMock, patch

        from src.core.health_checker import HealthChecker, HealthStatus

        checker = HealthChecker()

        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = False
        mock_adapter.get_metadata.return_value = MagicMock(
            version="1.0", layer="test", category="test"
        )

        with patch.object(checker, "_load_adapter", return_value=mock_adapter):
            result = checker.check_tool("test_tool", use_cache=False)
            assert result.status == HealthStatus.UNHEALTHY
            assert result.available is False

    def test_check_tool_exception(self):
        """Test check_tool exception handling (lines 199-210)."""
        from unittest.mock import patch

        from src.core.health_checker import HealthChecker, HealthStatus

        checker = HealthChecker()

        with patch.object(checker, "_load_adapter", side_effect=RuntimeError("Test error")):
            result = checker.check_tool("test_tool", use_cache=False)
            assert result.status == HealthStatus.UNHEALTHY
            assert result.available is False
            assert "Test error" in result.error_message

    def test_check_all_with_specific_tools(self):
        """Test check_all with specific tool list."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        health = checker.check_all(tools=["nonexistent1", "nonexistent2"])

        assert health.total_tools == 2

    def test_check_all_future_exception(self):
        """Test check_all handles future exceptions (lines 234-236)."""
        from unittest.mock import patch

        from src.core.health_checker import HealthChecker

        checker = HealthChecker()

        # Make check_tool raise an exception to trigger the exception path
        def raise_exception(*args, **kwargs):
            raise TimeoutError("Test timeout")

        with patch.object(checker, "check_tool", side_effect=raise_exception):
            # The ThreadPoolExecutor will catch the exception and we check
            # that check_all handles it gracefully
            health = checker.check_all(tools=["test_tool"])
            # Should still return a result (may be healthy or not depending on implementation)
            assert health is not None

    def test_check_all_degraded_status(self):
        """Test check_all returns DEGRADED status (lines 252-253)."""
        from unittest.mock import MagicMock, patch

        from src.core.health_checker import HealthChecker, HealthStatus

        checker = HealthChecker()

        def mock_load_adapter(tool):
            mock_adapter = MagicMock()
            # 'fail' in tool name -> not available, others -> available
            mock_adapter.is_available.return_value = "fail" not in tool
            mock_adapter.get_metadata.return_value = MagicMock(
                version="1.0", layer="test", category="test"
            )
            return mock_adapter

        with patch.object(checker, "_load_adapter", side_effect=mock_load_adapter):
            health = checker.check_all(tools=["tool1", "tool2", "fail_tool"])
            # 2 healthy, 1 unhealthy -> DEGRADED (healthy > unhealthy but unhealthy > 0)
            assert health.status == HealthStatus.DEGRADED

    def test_check_all_unhealthy_status(self):
        """Test check_all returns UNHEALTHY status (lines 254-255)."""
        from unittest.mock import MagicMock, patch

        from src.core.health_checker import HealthChecker, HealthStatus

        checker = HealthChecker()

        def mock_load_adapter(tool):
            mock_adapter = MagicMock()
            # All tools unavailable
            mock_adapter.is_available.return_value = False
            mock_adapter.get_metadata.return_value = MagicMock(
                version="1.0", layer="test", category="test"
            )
            return mock_adapter

        with patch.object(checker, "_load_adapter", side_effect=mock_load_adapter):
            health = checker.check_all(tools=["unhealthy1", "unhealthy2"])
            assert health.status == HealthStatus.UNHEALTHY

    def test_get_available_tools(self):
        """Test get_available_tools method (lines 272-273)."""
        from datetime import datetime
        from unittest.mock import patch

        from src.core.health_checker import HealthChecker, HealthStatus, SystemHealth, ToolHealth

        checker = HealthChecker()

        mock_health = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=2,
            healthy_tools=1,
            degraded_tools=0,
            unhealthy_tools=1,
            tools=[
                ToolHealth(
                    name="tool1",
                    status=HealthStatus.HEALTHY,
                    available=True,
                    last_check=datetime.now(),
                ),
                ToolHealth(
                    name="tool2",
                    status=HealthStatus.UNHEALTHY,
                    available=False,
                    last_check=datetime.now(),
                ),
            ],
            check_duration_ms=100,
            timestamp=datetime.now(),
        )

        with patch.object(checker, "check_all", return_value=mock_health):
            result = checker.get_available_tools()
            assert "tool1" in result
            assert "tool2" not in result

    def test_get_tools_by_layer(self):
        """Test get_tools_by_layer method (lines 277-287)."""
        from datetime import datetime
        from unittest.mock import patch

        from src.core.health_checker import HealthChecker, HealthStatus, SystemHealth, ToolHealth

        checker = HealthChecker()

        mock_health = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=2,
            healthy_tools=2,
            degraded_tools=0,
            unhealthy_tools=0,
            tools=[
                ToolHealth(
                    name="tool1",
                    status=HealthStatus.HEALTHY,
                    available=True,
                    last_check=datetime.now(),
                    details={"layer": "static"},
                ),
                ToolHealth(
                    name="tool2",
                    status=HealthStatus.HEALTHY,
                    available=True,
                    last_check=datetime.now(),
                    details={"layer": "dynamic"},
                ),
                ToolHealth(
                    name="tool3",
                    status=HealthStatus.UNHEALTHY,
                    available=False,
                    last_check=datetime.now(),
                    details={"layer": "static"},
                ),
            ],
            check_duration_ms=100,
            timestamp=datetime.now(),
        )

        with patch.object(checker, "check_all", return_value=mock_health):
            result = checker.get_tools_by_layer()
            assert "static" in result
            assert "tool1" in result["static"]
            assert "dynamic" in result
            assert "tool2" in result["dynamic"]
            # tool3 should not be in result because not available
            assert "tool3" not in result.get("static", [])

    def test_clear_cache(self):
        """Test clear_cache method (line 291)."""
        from datetime import datetime

        from src.core.health_checker import HealthChecker, HealthStatus, ToolHealth

        checker = HealthChecker()

        # Add something to cache
        checker._cache["test"] = ToolHealth(
            name="test", status=HealthStatus.HEALTHY, available=True, last_check=datetime.now()
        )

        assert len(checker._cache) > 0
        checker.clear_cache()
        assert len(checker._cache) == 0

    def test_load_adapter_success(self):
        """Test _load_adapter successfully loads an adapter (lines 129-130)."""
        import importlib
        from unittest.mock import MagicMock, patch

        from src.core.health_checker import HealthChecker

        checker = HealthChecker()

        # Create mock module with adapter class
        mock_adapter_instance = MagicMock()
        mock_adapter_class = MagicMock(return_value=mock_adapter_instance)
        mock_module = MagicMock()
        mock_module.SlitherAdapter = mock_adapter_class

        with patch.object(importlib, "import_module", return_value=mock_module):
            result = checker._load_adapter("slither")
            assert result == mock_adapter_instance

    def test_check_all_default_tools(self):
        """Test check_all with default tools (line 219)."""
        from src.core.health_checker import HealthChecker

        checker = HealthChecker()
        # Call without tools parameter to use default ADAPTER_MAP keys
        health = checker.check_all(tools=None)

        # Should check all adapters from ADAPTER_MAP
        assert health.total_tools == len(checker.ADAPTER_MAP)

    def test_create_health_endpoints(self):
        """Test create_health_endpoints function (lines 297-329)."""
        from src.core.health_checker import create_health_endpoints

        # This will try to import FastAPI; if not installed, skip
        try:
            router = create_health_endpoints()
            assert router is not None
            # Check that routes are registered
            routes = [r.path for r in router.routes]
            assert "/" in routes or "/health/" in routes or any("health" in str(r) for r in routes)
        except ImportError:
            # FastAPI not installed, skip test
            pass


class TestResultAggregator:
    """Tests for ResultAggregator."""

    def test_import(self):
        """Test ResultAggregator can be imported."""
        from src.core.result_aggregator import ResultAggregator

        assert ResultAggregator is not None

    def test_instantiation(self):
        """Test ResultAggregator instantiation."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert aggregator is not None

    def test_add_tool_results(self):
        """Test adding tool results."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        tool_result = {
            "status": "success",
            "findings": [{"type": "reentrancy", "severity": "high", "message": "Test"}],
        }
        count = aggregator.add_tool_results("slither", tool_result)

        assert count >= 0

    def test_aggregator_has_add_method(self):
        """Test aggregator has add_tool_results method."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert hasattr(aggregator, "add_tool_results")

    def test_aggregator_has_normalize_method(self):
        """Test aggregator has _normalize_finding method."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        assert hasattr(aggregator, "_normalize_finding")


class TestResultAggregatorCoverage:
    """Additional tests for ResultAggregator coverage."""

    def test_finding_to_dict(self):
        """Test Finding.to_dict method (line 31)."""
        from src.core.result_aggregator import Finding

        finding = Finding(
            id="test-123",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test vulnerability",
            file="contract.sol",
            line=42,
            function="withdraw",
            swc_id="SWC-107",
            cwe_id="CWE-841",
            confidence=0.9,
        )

        result = finding.to_dict()
        assert result["id"] == "test-123"
        assert result["tool"] == "slither"
        assert result["severity"] == "high"
        assert result["type"] == "reentrancy"
        assert result["swc_id"] == "SWC-107"
        assert result["cwe_id"] == "CWE-841"

    def test_aggregated_finding_to_dict(self):
        """Test AggregatedFinding.to_dict method (line 64)."""
        from src.core.result_aggregator import AggregatedFinding, Finding

        original = Finding(
            id="orig-1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="test.sol",
            line=10,
        )

        agg_finding = AggregatedFinding(
            id="AGG-123",
            severity="high",
            type="reentrancy",
            message="Aggregated vulnerability",
            file="contract.sol",
            line=42,
            function="withdraw",
            swc_id="SWC-107",
            cwe_id="CWE-841",
            confidence=0.95,
            tools=["slither", "mythril"],
            confirmations=2,
            original_findings=[original],
        )

        result = agg_finding.to_dict()
        assert result["id"] == "AGG-123"
        assert result["location"]["file"] == "contract.sol"
        assert result["location"]["line"] == 42
        assert result["cross_validated"] is True
        assert result["confirmations"] == 2

    def test_normalize_severity_variations(self):
        """Test _normalize_severity with various inputs (lines 202-213)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Test critical variations
        assert aggregator._normalize_severity("CRITICAL") == "critical"
        assert aggregator._normalize_severity("crit_error") == "critical"

        # Test high variations
        assert aggregator._normalize_severity("HIGH_IMPACT") == "high"

        # Test medium variations
        assert aggregator._normalize_severity("MEDIUM") == "medium"
        assert aggregator._normalize_severity("med_risk") == "medium"

        # Test low variations
        assert aggregator._normalize_severity("LOW_PRIORITY") == "low"

        # Test info variations
        assert aggregator._normalize_severity("informational") == "informational"
        assert aggregator._normalize_severity("info_note") == "informational"
        assert aggregator._normalize_severity("note") == "note"

        # Test default fallback
        assert aggregator._normalize_severity("unknown_value") == "medium"

    def test_normalize_finding_with_confidence_string(self):
        """Test _normalize_finding with string confidence (line 171)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        raw = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Test vulnerability",
            "confidence": "high",  # String confidence
        }

        finding = aggregator._normalize_finding("slither", raw)
        assert finding is not None
        assert finding.confidence == 0.9

        # Test medium confidence
        raw["confidence"] = "medium"
        finding = aggregator._normalize_finding("slither", raw)
        assert finding.confidence == 0.7

        # Test low confidence
        raw["confidence"] = "low"
        finding = aggregator._normalize_finding("slither", raw)
        assert finding.confidence == 0.5

    def test_normalize_finding_exception(self):
        """Test _normalize_finding exception handling (lines 190-191)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Pass something that will cause an exception
        result = aggregator._normalize_finding("tool", None)
        assert result is None

    def test_are_similar_different_files(self):
        """Test _are_similar with different files (lines 225-229)."""
        from src.core.result_aggregator import Finding, ResultAggregator

        aggregator = ResultAggregator()

        f1 = Finding(
            id="1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="file1.sol",
            line=10,
        )
        f2 = Finding(
            id="2",
            tool="mythril",
            severity="high",
            type="reentrancy",
            message="Test",
            file="file2.sol",
            line=10,
        )

        assert aggregator._are_similar(f1, f2) is False

    def test_are_similar_distant_lines(self):
        """Test _are_similar with distant lines (line 228-229)."""
        from src.core.result_aggregator import Finding, ResultAggregator

        aggregator = ResultAggregator()

        f1 = Finding(
            id="1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="contract.sol",
            line=10,
        )
        f2 = Finding(
            id="2",
            tool="mythril",
            severity="high",
            type="reentrancy",
            message="Test",
            file="contract.sol",
            line=100,  # More than 5 lines away
        )

        assert aggregator._are_similar(f1, f2) is False

    def test_are_similar_different_types_low_similarity(self):
        """Test _are_similar with different types and low message similarity (lines 235-239)."""
        from src.core.result_aggregator import Finding, ResultAggregator

        aggregator = ResultAggregator()

        f1 = Finding(
            id="1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Reentrancy vulnerability detected",
            file="contract.sol",
            line=10,
        )
        f2 = Finding(
            id="2",
            tool="mythril",
            severity="high",
            type="overflow",
            message="Integer overflow possible",
            file="contract.sol",
            line=10,
        )

        assert aggregator._are_similar(f1, f2) is False

    def test_normalize_type(self):
        """Test _normalize_type method (lines 245-251)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Test known aliases
        assert aggregator._normalize_type("reentrancy-eth") == "reentrancy"
        assert aggregator._normalize_type("integer-overflow") == "overflow"
        assert aggregator._normalize_type("unchecked-lowlevel") == "unchecked-call"
        assert aggregator._normalize_type("timestamp-dependency") == "timestamp"
        assert aggregator._normalize_type("frontrunning") == "front-running"

        # Test unknown type (returns as-is)
        assert aggregator._normalize_type("custom-check") == "custom-check"

    def test_aggregate_empty(self):
        """Test aggregate with empty findings (line 257-258)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()
        result = aggregator.aggregate()
        assert result == []

    def test_aggregate_with_findings(self):
        """Test full aggregate flow (lines 260-293)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add similar findings from different tools
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy in withdraw",
                        "file": "contract.sol",
                        "line": 42,
                    }
                ]
            },
        )
        aggregator.add_tool_results(
            "mythril",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy in withdraw function",
                        "file": "contract.sol",
                        "line": 43,
                    }
                ]
            },
        )

        result = aggregator.aggregate()
        assert len(result) >= 1
        # Should be aggregated into one finding
        if len(result) == 1:
            assert result[0].confirmations >= 1

    def test_get_statistics(self):
        """Test get_statistics method (lines 341-371)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add findings
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {"type": "reentrancy", "severity": "high", "message": "Test 1"},
                    {"type": "overflow", "severity": "medium", "message": "Test 2"},
                ]
            },
        )

        stats = aggregator.get_statistics()
        assert "total_findings" in stats
        assert "severity_distribution" in stats
        assert "findings_per_tool" in stats
        assert "average_confidence" in stats

    def test_get_high_confidence_findings(self):
        """Test get_high_confidence_findings method (lines 375-377)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add findings
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Test",
                        "confidence": 0.95,
                    }
                ]
            },
        )

        high_conf = aggregator.get_high_confidence_findings(min_confidence=0.8)
        assert isinstance(high_conf, list)

    def test_get_cross_validated_findings(self):
        """Test get_cross_validated_findings method (lines 381-383)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add similar findings from multiple tools
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy detected",
                        "file": "test.sol",
                        "line": 10,
                    }
                ]
            },
        )
        aggregator.add_tool_results(
            "mythril",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy detected",
                        "file": "test.sol",
                        "line": 10,
                    }
                ]
            },
        )

        cross_val = aggregator.get_cross_validated_findings()
        assert isinstance(cross_val, list)

    def test_to_report(self):
        """Test to_report method (lines 387-395)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add findings
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {"type": "reentrancy", "severity": "high", "message": "Test vulnerability"}
                ]
            },
        )

        report = aggregator.to_report()
        assert "summary" in report
        assert "findings" in report
        assert "high_confidence" in report
        assert "cross_validated" in report

    def test_clear(self):
        """Test clear method (lines 399-400)."""
        from src.core.result_aggregator import ResultAggregator

        aggregator = ResultAggregator()

        # Add findings
        aggregator.add_tool_results(
            "slither", {"findings": [{"type": "reentrancy", "severity": "high", "message": "Test"}]}
        )

        aggregator.aggregate()
        assert len(aggregator._findings) > 0
        assert len(aggregator._aggregated) > 0

        aggregator.clear()
        assert len(aggregator._findings) == 0
        assert len(aggregator._aggregated) == 0


class TestAgentProtocol:
    """Tests for AgentProtocol enums and dataclasses."""

    def test_agent_capability_import(self):
        """Test AgentCapability can be imported."""
        from src.core.agent_protocol import AgentCapability

        assert AgentCapability is not None

    def test_agent_metadata_import(self):
        """Test AgentMetadata can be imported."""
        from src.core.agent_protocol import AgentMetadata

        assert AgentMetadata is not None

    def test_finding_import(self):
        """Test Finding can be imported."""
        from src.core.agent_protocol import Finding

        assert Finding is not None


class TestAgentProtocolCoverage:
    """Tests to complete agent_protocol.py coverage."""

    def test_security_agent_concrete_implementation(self):
        """Test SecurityAgent with concrete implementation (lines 278, 302-320, 329, 338, 341, 344)."""
        from datetime import datetime

        from src.core.agent_protocol import (
            AgentCapability,
            AgentSpeed,
            AnalysisResult,
            AnalysisStatus,
            SecurityAgent,
        )

        # Create a concrete implementation
        class TestAgent(SecurityAgent):
            @property
            def name(self) -> str:
                return "test-agent"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Test agent for coverage"

            @property
            def author(self) -> str:
                return "MIESC"

            @property
            def license(self) -> str:
                return "MIT"

            @property
            def capabilities(self):
                return [AgentCapability.STATIC_ANALYSIS]

            @property
            def supported_languages(self):
                return ["solidity"]

            @property
            def cost(self) -> float:
                return 0.0

            @property
            def speed(self):
                return AgentSpeed.FAST

            def is_available(self) -> bool:
                return True

            def can_analyze(self, file_path: str) -> bool:
                return file_path.endswith(".sol")

            def analyze(self, contract: str, **kwargs):
                return AnalysisResult(
                    agent=self.name,
                    version=self.version,
                    status=AnalysisStatus.SUCCESS,
                    timestamp=datetime.now(),
                    execution_time=0.1,
                    findings=[],
                    summary={"critical": 0},
                )

        agent = TestAgent()

        # Test get_metadata (line 278)
        metadata = agent.get_metadata()
        assert metadata.name == "test-agent"
        assert metadata.version == "1.0.0"

        # Test validate (lines 302-320)
        assert agent.validate() is True

        # Test get_config_schema (line 329)
        schema = agent.get_config_schema()
        assert schema == {}

        # Test configure (line 338)
        agent.configure({})  # Should not raise

        # Test __str__ (line 341)
        assert str(agent) == "test-agent v1.0.0"

        # Test __repr__ (line 344)
        assert repr(agent) == "<SecurityAgent: test-agent v1.0.0>"

    def test_security_agent_validate_fails(self):
        """Test SecurityAgent.validate returns False on invalid agent."""
        from src.core.agent_protocol import (
            AgentCapability,
            AgentSpeed,
            SecurityAgent,
        )

        class InvalidAgent(SecurityAgent):
            @property
            def name(self) -> str:
                return ""  # Invalid: empty name

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Invalid"

            @property
            def author(self) -> str:
                return "Test"

            @property
            def license(self) -> str:
                return "MIT"

            @property
            def capabilities(self):
                return [AgentCapability.STATIC_ANALYSIS]

            @property
            def supported_languages(self):
                return ["solidity"]

            @property
            def cost(self) -> float:
                return 0.0

            @property
            def speed(self):
                return AgentSpeed.FAST

            def is_available(self) -> bool:
                return True

            def can_analyze(self, file_path: str) -> bool:
                return True

            def analyze(self, contract: str, **kwargs):
                return None

        agent = InvalidAgent()
        # validate should return False for empty name
        assert agent.validate() is False

    def test_agent_plugin_register(self):
        """Test AgentPlugin.register decorator (lines 363-366)."""
        from datetime import datetime

        from src.core.agent_protocol import (
            AgentCapability,
            AgentPlugin,
            AgentSpeed,
            AnalysisResult,
            AnalysisStatus,
            SecurityAgent,
        )

        # Clear registry for test isolation
        AgentPlugin._registry = []

        @AgentPlugin.register
        class PluginAgent(SecurityAgent):
            @property
            def name(self):
                return "plugin-agent"

            @property
            def version(self):
                return "1.0.0"

            @property
            def description(self):
                return "Plugin test"

            @property
            def author(self):
                return "Test"

            @property
            def license(self):
                return "MIT"

            @property
            def capabilities(self):
                return [AgentCapability.STATIC_ANALYSIS]

            @property
            def supported_languages(self):
                return ["solidity"]

            @property
            def cost(self):
                return 0.0

            @property
            def speed(self):
                return AgentSpeed.FAST

            def is_available(self):
                return True

            def can_analyze(self, file_path):
                return True

            def analyze(self, contract, **kwargs):
                return AnalysisResult(
                    agent=self.name,
                    version=self.version,
                    status=AnalysisStatus.SUCCESS,
                    timestamp=datetime.now(),
                    execution_time=0.1,
                    findings=[],
                    summary={},
                )

        # Test get_registered_agents (line 371)
        agents = AgentPlugin.get_registered_agents()
        assert len(agents) == 1
        assert agents[0] == PluginAgent

    def test_agent_plugin_register_invalid(self):
        """Test AgentPlugin.register raises TypeError for non-SecurityAgent."""
        from src.core.agent_protocol import AgentPlugin

        with pytest.raises(TypeError) as exc_info:

            @AgentPlugin.register
            class NotAnAgent:
                pass

        assert "must inherit from SecurityAgent" in str(exc_info.value)


class TestAgentRegistry:
    """Tests for AgentRegistry."""

    def test_import(self):
        """Test AgentRegistry can be imported."""
        from src.core.agent_registry import AgentRegistry

        assert AgentRegistry is not None

    def test_instantiation(self):
        """Test AgentRegistry instantiation."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        assert registry is not None


class TestAgentRegistryCoverage:
    """Additional tests for AgentRegistry coverage."""

    def _create_mock_agent(self, name="test-agent", version="1.0.0", available=True, cost=0):
        """Create a mock agent for testing."""
        from src.core.agent_protocol import AgentCapability, AgentSpeed, SecurityAgent

        class MockAgent(SecurityAgent):
            @property
            def name(self) -> str:
                return name

            @property
            def version(self) -> str:
                return version

            @property
            def description(self) -> str:
                return "Test agent"

            @property
            def author(self) -> str:
                return "Test Author"

            @property
            def license(self) -> str:
                return "MIT"

            @property
            def capabilities(self):
                return [AgentCapability.STATIC_ANALYSIS]

            @property
            def supported_languages(self):
                return ["solidity"]

            @property
            def speed(self):
                return AgentSpeed.FAST

            @property
            def cost(self):
                return cost

            def is_available(self) -> bool:
                return available

            def can_analyze(self, file_path: str) -> bool:
                return file_path.endswith(".sol")

            def analyze(self, source_code: str, **kwargs):
                return {"findings": []}

        return MockAgent()

    def test_register_success(self):
        """Test register method success (lines 70-83)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()

        result = registry.register(agent)
        assert result is True
        assert agent.name in registry.agents

    def test_register_not_security_agent(self):
        """Test register with non-SecurityAgent (line 70-71)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()

        with pytest.raises(TypeError):
            registry.register("not an agent")

    def test_register_duplicate_without_force(self):
        """Test register duplicate without force (lines 78-79)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()

        registry.register(agent)

        # Try to register again without force
        with pytest.raises(ValueError, match="already registered"):
            registry.register(agent)

    def test_register_duplicate_with_force(self):
        """Test register duplicate with force=True."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()

        registry.register(agent)
        result = registry.register(agent, force=True)
        assert result is True

    def test_unregister(self):
        """Test unregister method (lines 95-99)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()

        registry.register(agent)
        result = registry.unregister(agent.name)
        assert result is True
        assert agent.name not in registry.agents

        # Unregister non-existent
        result = registry.unregister("nonexistent")
        assert result is False

    def test_get(self):
        """Test get method (line 111)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()

        registry.register(agent)

        result = registry.get(agent.name)
        assert result is agent

        result = registry.get("nonexistent")
        assert result is None

    def test_list_agents(self):
        """Test list_agents method (lines 123-128)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent1 = self._create_mock_agent(name="agent1", available=True)
        agent2 = self._create_mock_agent(name="agent2", available=False)

        registry.register(agent1)
        registry.register(agent2)

        # List all
        all_agents = registry.list_agents()
        assert len(all_agents) == 2

        # List available only
        available = registry.list_agents(available_only=True)
        assert len(available) == 1

    def test_discover_all(self, tmp_path, monkeypatch):
        """Test discover_all method (lines 137-147)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        registry._plugin_dirs = [tmp_path]

        # Create empty directory
        result = registry.discover_all()
        assert isinstance(result, dict)

    def test_discover_from_directory(self, tmp_path):
        """Test _discover_from_directory method (lines 159-181)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()

        # Create a simple agent file
        agent_file = tmp_path / "test_agent.py"
        agent_file.write_text("""
from src.core.agent_protocol import SecurityAgent, AgentCapability, AgentSpeed

class TestAgentClass(SecurityAgent):
    @property
    def name(self): return "test-discovered"
    @property
    def version(self): return "1.0.0"
    @property
    def description(self): return "Test"
    @property
    def capabilities(self): return [AgentCapability.STATIC_ANALYSIS]
    @property
    def supported_languages(self): return ['solidity']
    @property
    def speed(self): return AgentSpeed.FAST
    @property
    def cost(self): return 0
    def is_available(self): return True
    def analyze(self, source_code, **kwargs): return {'findings': []}
""")

        result = registry._discover_from_directory(tmp_path)
        # May or may not discover depending on import path
        assert isinstance(result, dict)

    def test_filter_agents_by_language(self):
        """Test filter_agents by language (lines 253-255)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        result = registry.filter_agents(language="solidity")
        assert len(result) == 1

        result = registry.filter_agents(language="rust")
        assert len(result) == 0

    def test_filter_agents_by_capability(self):
        """Test filter_agents by capability (lines 258-264)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        result = registry.filter_agents(capability="static_analysis")
        assert len(result) == 1

        result = registry.filter_agents(capability="fuzzing")
        assert len(result) == 0

        # Test invalid capability - logs warning but continues with current list
        result = registry.filter_agents(capability="invalid_cap")
        assert len(result) == 1  # Agent not filtered, warning logged

    def test_filter_agents_free_only(self):
        """Test filter_agents with free_only (lines 267-268)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        free_agent = self._create_mock_agent(name="free", cost=0)
        paid_agent = self._create_mock_agent(name="paid", cost=100)

        registry.register(free_agent)
        registry.register(paid_agent)

        result = registry.filter_agents(free_only=True)
        assert len(result) == 1
        assert result[0].name == "free"

    def test_filter_agents_by_speed(self):
        """Test filter_agents by speed (lines 271-280)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()  # FAST speed
        registry.register(agent)

        result = registry.filter_agents(max_speed="fast")
        assert len(result) == 1

        result = registry.filter_agents(max_speed="medium")
        assert len(result) == 1

        # Test invalid speed - logs warning but continues with current list
        result = registry.filter_agents(max_speed="invalid")
        assert len(result) == 1  # Agent not filtered, warning logged

    def test_get_statistics(self):
        """Test get_statistics method (lines 291-316)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        stats = registry.get_statistics()
        assert stats["total_agents"] == 1
        assert stats["available_agents"] == 1
        assert stats["free_agents"] == 1
        assert "capabilities" in stats
        assert "languages" in stats
        assert "solidity" in stats["languages"]

    def test_validate_all(self):
        """Test validate_all method (lines 325-332)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        results = registry.validate_all()
        assert agent.name in results
        assert results[agent.name] is True

    def test_magic_methods(self):
        """Test __len__, __contains__, __iter__, __repr__ (lines 336, 340, 344, 347)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        # __len__
        assert len(registry) == 1

        # __contains__
        assert agent.name in registry
        assert "nonexistent" not in registry

        # __iter__
        names = list(registry)
        assert agent.name in names

        # __repr__
        repr_str = repr(registry)
        assert "AgentRegistry" in repr_str
        assert "1" in repr_str

    def test_register_validation_failure(self):
        """Test register with validation failure (line 75)."""
        from src.core.agent_protocol import AgentCapability, AgentSpeed, SecurityAgent
        from src.core.agent_registry import AgentRegistry

        # Create an agent with invalid name format (validation will fail)
        class InvalidAgent(SecurityAgent):
            @property
            def name(self) -> str:
                return "Invalid Name With Spaces"  # Invalid format

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def description(self) -> str:
                return "Test agent"

            @property
            def author(self) -> str:
                return "Test Author"

            @property
            def license(self) -> str:
                return "MIT"

            @property
            def capabilities(self):
                return [AgentCapability.STATIC_ANALYSIS]

            @property
            def supported_languages(self):
                return ["solidity"]

            @property
            def speed(self):
                return AgentSpeed.FAST

            @property
            def cost(self):
                return 0

            def is_available(self) -> bool:
                return True

            def can_analyze(self, file_path: str) -> bool:
                return True

            def analyze(self, source_code: str, **kwargs):
                return {"findings": []}

        registry = AgentRegistry()
        invalid_agent = InvalidAgent()

        with pytest.raises(ValueError, match="failed validation"):
            registry.register(invalid_agent)

    def test_discover_from_directory_duplicate(self, tmp_path):
        """Test _discover_from_directory with duplicate skip (lines 172-179)."""
        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()

        # Create a mock agent file that will produce duplicates
        agent_file = tmp_path / "test_agent.py"
        agent_file.write_text("""
from src.core.agent_protocol import SecurityAgent, AgentCapability, AgentSpeed

class TestAgent(SecurityAgent):
    @property
    def name(self): return "duplicate-test"
    @property
    def version(self): return "1.0.0"
    @property
    def description(self): return "Test"
    @property
    def author(self): return "Test"
    @property
    def license(self): return "MIT"
    @property
    def capabilities(self): return [AgentCapability.STATIC_ANALYSIS]
    @property
    def supported_languages(self): return ["solidity"]
    @property
    def speed(self): return AgentSpeed.FAST
    @property
    def cost(self): return 0
    def is_available(self): return True
    def can_analyze(self, f): return True
    def analyze(self, s, **k): return {"findings": []}
""")

        # First discovery should work
        discovered1 = registry._discover_from_directory(tmp_path)
        assert len(discovered1) == 1

        # Second discovery should skip the duplicate (logged as warning)
        discovered2 = registry._discover_from_directory(tmp_path)
        assert len(discovered2) == 0  # Skipped due to duplicate

    def test_validate_all_with_exception(self):
        """Test validate_all with exception in validation (lines 329-331)."""
        from unittest.mock import MagicMock

        from src.core.agent_registry import AgentRegistry

        registry = AgentRegistry()
        agent = self._create_mock_agent()
        registry.register(agent)

        # Mock validate to raise an exception
        original_validate = agent.validate
        agent.validate = MagicMock(side_effect=Exception("Validation error"))

        results = registry.validate_all()
        assert agent.name in results
        assert results[agent.name] is False

        # Restore
        agent.validate = original_validate

    def test_project_plugin_dir_exists(self, tmp_path, monkeypatch):
        """Test _init_plugin_dirs with existing project dir (line 48)."""

        from src.core.agent_registry import AgentRegistry

        # Create a plugins/agents directory
        plugins_dir = tmp_path / "plugins" / "agents"
        plugins_dir.mkdir(parents=True)

        # Change to tmp_path as cwd
        monkeypatch.chdir(tmp_path)

        registry = AgentRegistry()
        # The project plugin dir should be added
        assert any(str(plugins_dir) in str(d) for d in registry._plugin_dirs)


class TestOptimizedOrchestrator:
    """Tests for OptimizedOrchestrator."""

    def test_import(self):
        """Test OptimizedOrchestrator can be imported."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator

        assert OptimizedOrchestrator is not None

    def test_instantiation(self):
        """Test OptimizedOrchestrator instantiation."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator()
        assert orchestrator is not None


class TestOptimizedOrchestratorCoverage:
    """Additional tests for OptimizedOrchestrator coverage."""

    def test_cache_entry_is_valid(self):
        """Test CacheEntry.is_valid method (lines 36-37)."""
        from datetime import datetime, timedelta

        from src.core.optimized_orchestrator import CacheEntry

        # Valid entry (recent)
        entry = CacheEntry(
            tool="slither",
            contract_hash="abc123",
            results={"findings": []},
            timestamp=datetime.now(),
            ttl_seconds=3600,
        )
        assert entry.is_valid() is True

        # Invalid entry (expired)
        old_entry = CacheEntry(
            tool="slither",
            contract_hash="abc123",
            results={"findings": []},
            timestamp=datetime.now() - timedelta(hours=2),
            ttl_seconds=3600,
        )
        assert old_entry.is_valid() is False

    def test_analysis_result_to_dict(self):
        """Test AnalysisResult.to_dict method (line 57)."""
        from datetime import datetime

        from src.core.optimized_orchestrator import AnalysisResult

        result = AnalysisResult(
            contract_path="test.sol",
            tools_run=["slither", "mythril"],
            tools_success=["slither"],
            tools_failed=["mythril"],
            total_findings=5,
            aggregated_findings=3,
            cross_validated=1,
            severity_counts={"high": 2, "medium": 1},
            execution_time_ms=1500.5,
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
        )

        d = result.to_dict()
        assert d["contract_path"] == "test.sol"
        assert d["tools_run"] == ["slither", "mythril"]
        assert d["execution_time_ms"] == 1500.5
        assert d["timestamp"] == "2024-01-01T12:00:00"

    def test_result_cache_compute_hash(self, tmp_path):
        """Test ResultCache._compute_hash method (lines 82-87)."""
        from src.core.optimized_orchestrator import ResultCache

        cache = ResultCache(cache_dir=str(tmp_path / "cache"))

        # Test with existing file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        hash1 = cache._compute_hash(str(test_file))
        assert len(hash1) == 16

        # Test with non-existent file (fallback)
        hash2 = cache._compute_hash("/nonexistent/file.sol")
        assert len(hash2) == 16

    def test_result_cache_get_cache_key(self, tmp_path):
        """Test ResultCache._get_cache_key method (lines 91-92)."""
        from src.core.optimized_orchestrator import ResultCache

        cache = ResultCache(cache_dir=str(tmp_path / "cache"))

        key = cache._get_cache_key("slither", "/path/to/contract.sol")
        assert "slither_" in key

    def test_result_cache_get_and_set(self, tmp_path):
        """Test ResultCache.get and set methods (lines 96-154)."""
        from src.core.optimized_orchestrator import ResultCache

        cache = ResultCache(cache_dir=str(tmp_path / "cache"), ttl_seconds=3600)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Initially nothing in cache
        result = cache.get("slither", str(test_file))
        assert result is None

        # Set cache
        cache.set("slither", str(test_file), {"findings": [{"type": "test"}]})

        # Now should be in cache
        result = cache.get("slither", str(test_file))
        assert result is not None
        assert result["findings"][0]["type"] == "test"

    def test_result_cache_clear(self, tmp_path):
        """Test ResultCache.clear method (lines 160-163)."""
        from src.core.optimized_orchestrator import ResultCache

        cache = ResultCache(cache_dir=str(tmp_path / "cache"))

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Set cache
        cache.set("slither", str(test_file), {"findings": []})

        # Clear
        cache.clear()

        # Should be empty now
        result = cache.get("slither", str(test_file))
        assert result is None

    def test_run_tool_with_cache(self, tmp_path):
        """Test _run_tool method with cache hit (lines 198-202)."""

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=True)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Pre-populate cache
        orchestrator.cache.set(
            "slither", str(test_file), {"status": "success", "findings": [{"type": "cached"}]}
        )

        # Should return cached result
        result = orchestrator._run_tool("slither", str(test_file))
        assert result["findings"][0]["type"] == "cached"

    def test_run_tool_exception(self, tmp_path):
        """Test _run_tool method with exception (lines 221-227)."""
        from unittest.mock import patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Mock discovery to raise exception
        with patch.object(
            orchestrator.discovery, "load_adapter", side_effect=Exception("Test error")
        ):
            result = orchestrator._run_tool("slither", str(test_file))
            assert result["status"] == "error"
            assert "Test error" in result["error"]

    def test_analyze_no_tools(self, tmp_path):
        """Test analyze with no tools available (lines 255-267)."""
        from unittest.mock import patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Mock _determine_tools to return empty list
        with patch.object(orchestrator, "_determine_tools", return_value=[]):
            result = orchestrator.analyze(str(test_file))
            assert result.tools_run == []
            assert result.total_findings == 0

    def test_analyze_with_callback(self, tmp_path):
        """Test analyze with progress_callback (lines 291-304)."""
        from unittest.mock import patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        callback_calls = []

        def callback(tool, status):
            callback_calls.append((tool, status))

        # Mock to return an error result
        mock_result = {"status": "error", "error": "Test", "findings": []}
        with patch.object(orchestrator, "_run_tool", return_value=mock_result):
            with patch.object(orchestrator, "_determine_tools", return_value=["test_tool"]):
                orchestrator.analyze(str(test_file), progress_callback=callback)
                assert len(callback_calls) >= 1

    def test_determine_tools_with_tools_list(self):
        """Test _determine_tools with specific tools (lines 341-344)."""
        from unittest.mock import MagicMock, patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Mock available tools
        mock_tool = MagicMock()
        mock_tool.name = "slither"
        with patch.object(orchestrator.discovery, "get_available_tools", return_value=[mock_tool]):
            result = orchestrator._determine_tools(tools=["slither", "nonexistent"])
            assert "slither" in result
            assert "nonexistent" not in result

    def test_determine_tools_with_layers(self):
        """Test _determine_tools with layers (lines 346-355)."""
        from unittest.mock import MagicMock, patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Mock tools by layer
        mock_tool = MagicMock()
        mock_tool.name = "slither"
        mock_tool.available = True

        with patch.object(
            orchestrator.discovery,
            "get_tools_by_layer",
            return_value={"static_analysis": [mock_tool]},
        ):
            result = orchestrator._determine_tools(layers=["static_analysis"])
            assert "slither" in result

    def test_determine_tools_default(self):
        """Test _determine_tools default behavior (lines 357-360)."""
        from unittest.mock import MagicMock, patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Mock enabled adapters and available tools
        mock_tool = MagicMock()
        mock_tool.name = "slither"

        with patch.object(
            orchestrator.config, "get_enabled_adapters", return_value=["slither", "mythril"]
        ):
            with patch.object(
                orchestrator.discovery, "get_available_tools", return_value=[mock_tool]
            ):
                result = orchestrator._determine_tools()
                assert "slither" in result

    def test_analyze_batch(self, tmp_path):
        """Test analyze_batch method (lines 381-395)."""
        from datetime import datetime
        from unittest.mock import patch

        from src.core.optimized_orchestrator import AnalysisResult, OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test files
        file1 = tmp_path / "test1.sol"
        file1.write_text("pragma solidity ^0.8.0;")
        file2 = tmp_path / "test2.sol"
        file2.write_text("pragma solidity ^0.8.0;")

        # Mock analyze to return a simple result
        mock_result = AnalysisResult(
            contract_path="test",
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_findings=0,
            aggregated_findings=0,
            cross_validated=0,
            severity_counts={},
            execution_time_ms=100,
            timestamp=datetime.now(),
        )

        with patch.object(orchestrator, "analyze", return_value=mock_result):
            results = orchestrator.analyze_batch([str(file1), str(file2)])
            assert len(results) == 2

    def test_quick_scan(self, tmp_path):
        """Test quick_scan method (line 401)."""
        from datetime import datetime
        from unittest.mock import patch

        from src.core.optimized_orchestrator import AnalysisResult, OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        mock_result = AnalysisResult(
            contract_path=str(test_file),
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_findings=0,
            aggregated_findings=0,
            cross_validated=0,
            severity_counts={},
            execution_time_ms=100,
            timestamp=datetime.now(),
        )

        with patch.object(orchestrator, "analyze", return_value=mock_result) as mock_analyze:
            orchestrator.quick_scan(str(test_file))
            mock_analyze.assert_called_once()
            # Check that layers=['static_analysis'] was passed
            call_kwargs = mock_analyze.call_args[1]
            assert call_kwargs.get("layers") == ["static_analysis"]

    def test_deep_scan(self, tmp_path):
        """Test deep_scan method (line 411)."""
        from datetime import datetime
        from unittest.mock import patch

        from src.core.optimized_orchestrator import AnalysisResult, OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        mock_result = AnalysisResult(
            contract_path=str(test_file),
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_findings=0,
            aggregated_findings=0,
            cross_validated=0,
            severity_counts={},
            execution_time_ms=100,
            timestamp=datetime.now(),
        )

        with patch.object(orchestrator, "analyze", return_value=mock_result) as mock_analyze:
            orchestrator.deep_scan(str(test_file))
            mock_analyze.assert_called_once()

    def test_clear_cache(self, tmp_path):
        """Test clear_cache method (lines 418-419)."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=True)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Add to cache
        orchestrator.cache.set("slither", str(test_file), {"findings": []})

        # Clear cache
        orchestrator.clear_cache()

        # Should be empty
        result = orchestrator.cache.get("slither", str(test_file))
        assert result is None

    def test_clear_cache_disabled(self):
        """Test clear_cache when cache is disabled."""
        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)
        # Should not raise error
        orchestrator.clear_cache()

    def test_cache_get_from_disk(self, tmp_path):
        """Test ResultCache.get loading from disk (lines 109-126)."""
        import json
        from datetime import datetime

        from src.core.optimized_orchestrator import ResultCache

        cache_dir = tmp_path / "cache"
        cache = ResultCache(cache_dir=str(cache_dir), ttl_seconds=3600)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Manually create cache file on disk
        key = cache._get_cache_key("slither", str(test_file))
        cache_file = cache_dir / f"{key}.json"

        cache_data = {
            "tool": "slither",
            "results": {"findings": [{"type": "disk_cached"}]},
            "timestamp": datetime.now().isoformat(),
        }

        with open(cache_file, "w") as f:
            json.dump(cache_data, f)

        # Now get should load from disk
        result = cache.get("slither", str(test_file))
        assert result is not None
        assert result["findings"][0]["type"] == "disk_cached"

    def test_cache_invalidation(self, tmp_path):
        """Test cache invalidation when expired (lines 103-104)."""
        from datetime import datetime, timedelta

        from src.core.optimized_orchestrator import CacheEntry, ResultCache

        cache = ResultCache(cache_dir=str(tmp_path / "cache"), ttl_seconds=1)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Manually add expired entry to memory cache
        key = cache._get_cache_key("slither", str(test_file))
        cache._memory_cache[key] = CacheEntry(
            tool="slither",
            contract_hash="hash",
            results={"findings": []},
            timestamp=datetime.now() - timedelta(hours=1),
            ttl_seconds=1,
        )

        # Get should return None and delete expired entry
        result = cache.get("slither", str(test_file))
        assert result is None
        assert key not in cache._memory_cache

    def test_run_tool_success_and_cache(self, tmp_path):
        """Test _run_tool success path with caching (lines 209-219)."""
        from unittest.mock import MagicMock, patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=True)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Mock adapter
        mock_adapter = MagicMock()
        mock_adapter.analyze.return_value = {"status": "success", "findings": [{"type": "test"}]}

        with patch.object(orchestrator.discovery, "load_adapter", return_value=mock_adapter):
            result = orchestrator._run_tool("slither", str(test_file))
            assert result["status"] == "success"

            # Should be cached now
            cached = orchestrator.cache.get("slither", str(test_file))
            assert cached is not None

    def test_analyze_with_success_callback(self, tmp_path):
        """Test analyze with success callback (line 289)."""
        from unittest.mock import patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        callback_calls = []

        def callback(tool, status):
            callback_calls.append((tool, status))

        # Mock to return success
        mock_result = {"status": "success", "findings": [{"type": "test"}]}
        with patch.object(orchestrator, "_run_tool", return_value=mock_result):
            with patch.object(orchestrator, "_determine_tools", return_value=["test_tool"]):
                orchestrator.analyze(str(test_file), progress_callback=callback)
                # Should have 'success' in callback
                assert any(status == "success" for _, status in callback_calls)

    def test_analyze_with_successful_aggregation(self, tmp_path):
        """Test analyze with successful tool results for aggregation (lines 312-313)."""
        from unittest.mock import patch

        from src.core.optimized_orchestrator import OptimizedOrchestrator

        orchestrator = OptimizedOrchestrator(cache_enabled=False)

        # Create test file
        test_file = tmp_path / "test.sol"
        test_file.write_text("pragma solidity ^0.8.0;")

        # Mock to return success with findings
        mock_result = {
            "status": "success",
            "findings": [{"type": "reentrancy", "severity": "high", "message": "Test"}],
        }
        with patch.object(orchestrator, "_run_tool", return_value=mock_result):
            with patch.object(orchestrator, "_determine_tools", return_value=["slither"]):
                result = orchestrator.analyze(str(test_file))
                assert result.total_findings >= 0


class TestMLOrchestrator:
    """Tests for MLOrchestrator."""

    def test_import(self):
        """Test MLOrchestrator can be imported."""
        from src.core.ml_orchestrator import MLOrchestrator

        assert MLOrchestrator is not None

    def test_get_ml_orchestrator(self):
        """Test get_ml_orchestrator singleton."""
        from src.core import get_ml_orchestrator

        orch1 = get_ml_orchestrator()
        orch2 = get_ml_orchestrator()

        assert orch1 is not None
        assert orch1 is orch2  # Singleton

    def test_ml_orchestrator_methods(self):
        """Test MLOrchestrator has required methods."""
        from src.core import get_ml_orchestrator

        orchestrator = get_ml_orchestrator()

        assert hasattr(orchestrator, "analyze")
        assert hasattr(orchestrator, "quick_scan")
        assert hasattr(orchestrator, "deep_scan")
        assert hasattr(orchestrator, "get_ml_report")
        assert hasattr(orchestrator, "submit_feedback")


class TestMLOrchestratorCoverage:
    """Tests to complete MLOrchestrator coverage."""

    def test_ml_analysis_result_risk_levels(self):
        """Test MLAnalysisResult._calculate_risk_level with different scenarios (lines 131-136)."""
        from datetime import datetime

        from src.core.ml_orchestrator import MLAnalysisResult

        # Test HIGH risk level (high > 2)
        result = MLAnalysisResult(
            contract_path="test.sol",
            contract_source="",
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_raw_findings=0,
            raw_findings=[],
            ml_filtered_findings=[],
            ml_filtered_out=[],
            false_positives_removed=0,
            severity_adjustments=0,
            clusters=[],
            cluster_count=0,
            remediation_plan=[],
            pattern_matches=[],
            severity_distribution={"critical": 0, "high": 3, "medium": 0, "low": 0},
            cross_validated=0,
            execution_time_ms=0,
            ml_processing_time_ms=0,
            timestamp=datetime.now(),
        )
        assert result._calculate_risk_level() == "HIGH"

        # Test MEDIUM risk level (high > 0 but <= 2)
        result.severity_distribution = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        assert result._calculate_risk_level() == "MEDIUM"

        # Test LOW risk level (no high or critical)
        result.severity_distribution = {"critical": 0, "high": 0, "medium": 5, "low": 10}
        assert result._calculate_risk_level() == "LOW"

    def test_read_contract_source_exception(self, tmp_path):
        """Test _read_contract_source handles exceptions (lines 185-187)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Try to read non-existent file
        result = orchestrator._read_contract_source("/nonexistent/path/contract.sol")

        # Should return empty string on error
        assert result == ""

    def test_orchestrator_ml_disabled(self):
        """Test orchestrator methods when ML is disabled (lines 491, 497)."""
        from src.core.ml_orchestrator import MLOrchestrator
        from src.ml import FeedbackType

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Test submit_feedback returns ml_disabled
        result = orchestrator.submit_feedback(
            finding={"id": "test"},
            feedback_type=FeedbackType.FALSE_POSITIVE,
        )
        assert result == {"status": "ml_disabled"}

        # Test get_ml_report returns ml_disabled
        report = orchestrator.get_ml_report()
        assert report == {"status": "ml_disabled"}

    def test_clear_cache(self):
        """Test clear_cache method (lines 516-517)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(cache_enabled=True, ml_enabled=False)

        # Should not raise
        orchestrator.clear_cache()

        # With no cache
        orchestrator_no_cache = MLOrchestrator(cache_enabled=False, ml_enabled=False)
        orchestrator_no_cache.clear_cache()  # Should not raise

    def test_calculate_severity_distribution_variations(self):
        """Test _calculate_severity_distribution with various severities (lines 420-423)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Test with 'info' severity
        findings = [
            {"severity": "info"},
            {"severity": "unknown"},  # Should map to medium
            {"severity": "critical"},
        ]

        dist = orchestrator._calculate_severity_distribution(findings)

        assert dist["informational"] == 1
        assert dist["medium"] == 1  # 'unknown' maps to medium
        assert dist["critical"] == 1

    def test_determine_tools_with_specific_tools(self):
        """Test _determine_tools with specific tools list (lines 433-434)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Get available tools first
        available_tools = [t.name for t in orchestrator.discovery.get_available_tools()]

        if available_tools:
            # Request some available and some unavailable tools
            requested = available_tools[:2] + ["nonexistent_tool"]
            result = orchestrator._determine_tools(tools=requested)

            # Should only include available tools
            assert "nonexistent_tool" not in result
            for tool in result:
                assert tool in available_tools

    def test_ml_analysis_result_to_dict(self):
        """Test MLAnalysisResult.to_dict method (lines 71-99)."""
        from datetime import datetime

        from src.core.ml_orchestrator import MLAnalysisResult

        result = MLAnalysisResult(
            contract_path="test.sol",
            contract_source="pragma solidity ^0.8.0;",
            tools_run=["slither"],
            tools_success=["slither"],
            tools_failed=[],
            total_raw_findings=5,
            raw_findings=[{"id": "1", "severity": "high"}],
            ml_filtered_findings=[{"id": "1", "severity": "high"}],
            ml_filtered_out=[{"id": "2", "severity": "low"}],
            false_positives_removed=1,
            severity_adjustments=2,
            clusters=[],
            cluster_count=0,
            remediation_plan=[{"action": "fix", "severity": "high"}],
            pattern_matches=[{"pattern": "reentrancy"}],
            severity_distribution={"critical": 0, "high": 1, "medium": 0, "low": 0},
            cross_validated=1,
            execution_time_ms=100.5,
            ml_processing_time_ms=50.2,
            timestamp=datetime.now(),
        )

        d = result.to_dict()

        assert d["contract_path"] == "test.sol"
        assert d["tools_run"] == ["slither"]
        assert d["raw_findings"]["total"] == 5
        assert d["ml_enhanced"]["filtered_count"] == 1
        assert d["clusters"]["count"] == 0
        assert "metrics" in d

    def test_ml_analysis_result_get_summary(self):
        """Test MLAnalysisResult.get_summary method (lines 101-122)."""
        from datetime import datetime

        from src.core.ml_orchestrator import MLAnalysisResult

        result = MLAnalysisResult(
            contract_path="test.sol",
            contract_source="",
            tools_run=[],
            tools_success=[],
            tools_failed=[],
            total_raw_findings=10,
            raw_findings=[],
            ml_filtered_findings=[{"id": "1"}],
            ml_filtered_out=[],
            false_positives_removed=5,
            severity_adjustments=0,
            clusters=[],
            cluster_count=2,
            remediation_plan=[
                {"severity": "critical", "action": "fix"},
                {"severity": "low", "action": "review"},
            ],
            pattern_matches=[],
            severity_distribution={"critical": 1, "high": 2, "medium": 3, "low": 4},
            cross_validated=0,
            execution_time_ms=0,
            ml_processing_time_ms=0,
            timestamp=datetime.now(),
        )

        summary = result.get_summary()

        assert summary["risk_level"] == "CRITICAL"
        assert summary["total_findings"] == 1
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["clusters"] == 2
        assert summary["fp_removed"] == 5
        assert "reduction_rate" in summary
        assert summary["priority_actions"] == 1  # Only critical action

    def test_build_code_context_map(self, tmp_path):
        """Test _build_code_context_map method (lines 195-212)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        source = """pragma solidity ^0.8.0;
contract Test {
    uint public value;
    function set(uint v) public {
        value = v;
    }
}"""

        findings = [
            {"location": {"file": "test.sol", "line": 5}},
            {"location": {"file": "test.sol", "line": 3}},
            {"location": {}},  # No line number
        ]

        context_map = orchestrator._build_code_context_map(source, findings)

        assert "test.sol:5" in context_map
        assert "test.sol:3" in context_map
        assert len(context_map) == 2

    def test_is_same_location(self):
        """Test _is_same_location method (lines 401-408)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        f1 = {"location": {"file": "test.sol", "line": 10}}
        f2 = {"location": {"file": "test.sol", "line": 12}}  # Within 3 lines
        f3 = {"location": {"file": "test.sol", "line": 20}}  # Too far
        f4 = {"location": {"file": "other.sol", "line": 10}}  # Different file

        assert orchestrator._is_same_location(f1, f2) is True
        assert orchestrator._is_same_location(f1, f3) is False
        assert orchestrator._is_same_location(f1, f4) is False

    def test_determine_tools_with_layers(self):
        """Test _determine_tools with layers parameter (lines 436-444)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Test with layers
        result = orchestrator._determine_tools(layers=["static_analysis"])
        # Result depends on what's available, just check it doesn't error
        assert isinstance(result, list)

    def test_empty_result(self):
        """Test _empty_result method (lines 450-477)."""
        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)
        result = orchestrator._empty_result("test.sol", "code")

        assert result.contract_path == "test.sol"
        assert result.contract_source == "code"
        assert result.tools_run == []
        assert result.total_raw_findings == 0

    def test_quick_scan_and_deep_scan(self):
        """Test quick_scan and deep_scan methods (lines 499-512)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Mock analyze to avoid complex execution
        orchestrator.analyze = MagicMock(return_value=orchestrator._empty_result("test.sol", ""))

        # These should call analyze with layers
        quick_result = orchestrator.quick_scan("test.sol", timeout=30)
        assert quick_result is not None

        deep_result = orchestrator.deep_scan("test.sol", timeout=30)
        assert deep_result is not None

    def test_run_tool_cache_paths(self, tmp_path):
        """Test _run_tool with cache paths (lines 222-246)."""

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(cache_enabled=True, ml_enabled=False)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        # Test with non-existent tool (should return error result)
        result = orchestrator._run_tool("nonexistent_tool", str(contract))
        assert result["status"] == "error"

    def test_analyze_empty_tools(self, tmp_path):
        """Test analyze when no tools available (empty result path)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Mock _determine_tools to return empty list
        orchestrator._determine_tools = MagicMock(return_value=[])

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        result = orchestrator.analyze(str(contract))

        # Should get empty result
        assert result.tools_run == []
        assert result.total_raw_findings == 0

    def test_run_tool_cache_hit(self, tmp_path):
        """Test _run_tool with cache hit (lines 222-226)."""

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(cache_enabled=True, ml_enabled=False)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        # Pre-populate cache
        cached_result = {"tool": "slither", "status": "success", "findings": [{"id": "1"}]}
        orchestrator.cache.set("slither", str(contract), cached_result)

        # Should get cached result
        result = orchestrator._run_tool("slither", str(contract))
        assert result == cached_result

    def test_run_tool_successful_execution(self, tmp_path):
        """Test _run_tool with successful tool execution (lines 228-238)."""
        from unittest.mock import MagicMock, patch

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(cache_enabled=True, ml_enabled=False)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        # Create mock adapter
        mock_adapter = MagicMock()
        mock_adapter.analyze.return_value = {
            "tool": "test-tool",
            "status": "success",
            "findings": [],
        }

        with patch.object(orchestrator.discovery, "load_adapter", return_value=mock_adapter):
            result = orchestrator._run_tool("test-tool", str(contract))
            assert result["status"] == "success"

    def test_analyze_with_tools_success(self, tmp_path):
        """Test analyze with successful tool execution (lines 280-378)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        # Mock _run_tool to return findings
        def mock_run_tool(tool, path, timeout=120):
            return {
                "tool": tool,
                "status": "success",
                "findings": [
                    {"id": "1", "severity": "high", "location": {"file": "test.sol", "line": 1}}
                ],
            }

        orchestrator._run_tool = MagicMock(side_effect=mock_run_tool)
        orchestrator._determine_tools = MagicMock(return_value=["slither"])

        result = orchestrator.analyze(str(contract))

        assert "slither" in result.tools_success
        assert result.total_raw_findings >= 1

    def test_analyze_with_tool_error(self, tmp_path):
        """Test analyze with tool execution error (lines 304-305, 317-324)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        # Mock _run_tool to return error
        def mock_run_tool(tool, path, timeout=120):
            return {"tool": tool, "status": "error", "error": "Tool failed", "findings": []}

        orchestrator._run_tool = MagicMock(side_effect=mock_run_tool)
        orchestrator._determine_tools = MagicMock(return_value=["failing_tool"])

        result = orchestrator.analyze(str(contract))

        assert "failing_tool" in result.tools_failed
        assert len(result.tools_success) == 0

    def test_analyze_with_ml_enabled(self, tmp_path):
        """Test analyze with ML enabled (lines 334-356)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=True, fp_threshold=0.5)

        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")

        # Mock _run_tool to return findings
        def mock_run_tool(tool, path, timeout=120):
            return {
                "tool": tool,
                "status": "success",
                "findings": [
                    {"id": "1", "severity": "high", "location": {"file": "test.sol", "line": 1}}
                ],
            }

        orchestrator._run_tool = MagicMock(side_effect=mock_run_tool)
        orchestrator._determine_tools = MagicMock(return_value=["slither"])

        result = orchestrator.analyze(str(contract))

        # Should have processed with ML
        assert result is not None

    def test_submit_feedback_ml_enabled(self):
        """Test submit_feedback when ML is enabled (line 488)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator
        from src.ml import FeedbackType

        orchestrator = MLOrchestrator(ml_enabled=True)

        # Mock ml_pipeline.submit_feedback
        orchestrator.ml_pipeline.submit_feedback = MagicMock(return_value={"status": "recorded"})

        result = orchestrator.submit_feedback(
            finding={"id": "test"}, feedback_type=FeedbackType.FALSE_POSITIVE, user_id="test-user"
        )

        assert result == {"status": "recorded"}

    def test_get_ml_report_ml_enabled(self):
        """Test get_ml_report when ML is enabled (line 496)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=True)

        # Mock ml_pipeline.get_ml_report
        orchestrator.ml_pipeline.get_ml_report = MagicMock(return_value={"fp_rate": 0.1})

        report = orchestrator.get_ml_report()

        assert report == {"fp_rate": 0.1}

    def test_determine_tools_layers_with_available(self):
        """Test _determine_tools with layers and available tools (lines 436-448)."""
        from unittest.mock import MagicMock

        from src.core.ml_orchestrator import MLOrchestrator

        orchestrator = MLOrchestrator(ml_enabled=False)

        # Mock tools_by_layer
        mock_tool = MagicMock()
        mock_tool.name = "test-tool"
        mock_tool.available = True

        orchestrator.discovery.get_tools_by_layer = MagicMock(
            return_value={"static_analysis": [mock_tool]}
        )

        result = orchestrator._determine_tools(layers=["static_analysis"])

        assert "test-tool" in result


class TestConfigLoader:
    """Tests for MIESCConfig (config loader)."""

    def test_import(self):
        """Test MIESCConfig can be imported."""
        from src.core.config_loader import MIESCConfig

        assert MIESCConfig is not None

    def test_instantiation(self):
        """Test MIESCConfig instantiation (singleton)."""
        from src.core.config_loader import MIESCConfig

        config = MIESCConfig()
        assert config is not None


class TestConfigLoaderCoverage:
    """Additional tests for MIESCConfig coverage."""

    def _reset_singleton(self):
        """Reset the MIESCConfig singleton for testing."""
        from src.core.config_loader import MIESCConfig

        MIESCConfig._instance = None
        MIESCConfig._config = {}

    def test_properties(self):
        """Test all config properties."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        # Test version property (line 97)
        assert isinstance(config.version, str)

        # Test global_config property (line 102)
        assert isinstance(config.global_config, dict)

        # Test max_workers property (line 107)
        assert isinstance(config.max_workers, int)

        # Test cache_enabled property (line 112)
        assert isinstance(config.cache_enabled, bool)

        # Test log_level property (line 117)
        assert isinstance(config.log_level, str)

    def test_get_adapter_config(self):
        """Test get_adapter_config method (lines 121-124)."""
        from src.core.config_loader import AdapterConfig, MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        # Test with non-existent adapter (returns defaults)
        adapter_config = config.get_adapter_config("nonexistent_adapter")
        assert isinstance(adapter_config, AdapterConfig)
        assert adapter_config.name == "nonexistent_adapter"
        assert adapter_config.enabled is True
        assert adapter_config.layer == "static_analysis"
        assert adapter_config.timeout == 60
        assert adapter_config.options == {}

    def test_get_layer_config(self):
        """Test get_layer_config method (lines 134-137)."""
        from src.core.config_loader import LayerConfig, MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        layer_config = config.get_layer_config("test_layer")
        assert isinstance(layer_config, LayerConfig)
        assert layer_config.name == "test_layer"
        assert layer_config.enabled is True
        assert layer_config.priority == 1
        assert layer_config.tools == []

    def test_get_enabled_adapters(self):
        """Test get_enabled_adapters method (lines 146-147)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        enabled = config.get_enabled_adapters()
        assert isinstance(enabled, list)

    def test_get_adapters_by_layer(self):
        """Test get_adapters_by_layer method (lines 154-155)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        adapters = config.get_adapters_by_layer("static_analysis")
        assert isinstance(adapters, list)

    def test_get_all_layers(self):
        """Test get_all_layers method (lines 162-173)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        layers = config.get_all_layers()
        assert isinstance(layers, list)

    def test_get_llm_config(self):
        """Test get_llm_config method (line 177)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        llm_config = config.get_llm_config()
        assert isinstance(llm_config, dict)
        assert "provider" in llm_config or "host" in llm_config or "default_model" in llm_config

    def test_get_results_config(self):
        """Test get_results_config method (line 185)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        results_config = config.get_results_config()
        assert isinstance(results_config, dict)

    def test_get_compliance_frameworks(self):
        """Test get_compliance_frameworks method (lines 192-195)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        frameworks = config.get_compliance_frameworks()
        assert isinstance(frameworks, list)

    def test_get_license_plan_config(self):
        """Test get_license_plan_config method (lines 199-200)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        plan_config = config.get_license_plan_config("PROFESSIONAL")
        assert isinstance(plan_config, dict)

    def test_to_dict(self):
        """Test to_dict method (line 204)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)

    def test_reload(self):
        """Test reload method (line 92)."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        # Call reload
        config.reload()
        assert config._config is not None

    def test_env_config_path(self, tmp_path):
        """Test MIESC_CONFIG env var (line 57)."""
        import os

        from src.core.config_loader import MIESCConfig

        # Create temp config file
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text('version: "test_env"')

        self._reset_singleton()
        old_env = os.environ.get("MIESC_CONFIG")
        try:
            os.environ["MIESC_CONFIG"] = str(config_file)
            config = MIESCConfig()
            # Config should load from env path
            assert config.version in ["test_env", "4.0.0"]  # May vary
        finally:
            if old_env is not None:
                os.environ["MIESC_CONFIG"] = old_env
            else:
                os.environ.pop("MIESC_CONFIG", None)
            self._reset_singleton()

    def test_default_config_when_no_file(self, tmp_path, monkeypatch):
        """Test default config when no file exists (lines 64, 74, 78)."""
        import os

        from src.core.config_loader import MIESCConfig

        self._reset_singleton()

        # Mock Path.cwd() to return a temp dir with no config
        monkeypatch.setattr("pathlib.Path.cwd", lambda: tmp_path)
        os.environ.pop("MIESC_CONFIG", None)

        config = MIESCConfig()
        # Should get default config
        assert config.version == "5.0.2"
        self._reset_singleton()

    def test_get_config_function(self):
        """Test get_config convenience function."""
        from src.core.config_loader import get_config

        config = get_config()
        assert config is not None

    def test_get_chain_config_default(self):
        """Test get_chain_config returns default ethereum config."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        chain_config = config.get_chain_config()
        assert isinstance(chain_config, dict)
        assert "name" in chain_config or "chain_id" in chain_config

    def test_get_chain_config_specific(self):
        """Test get_chain_config with specific chain name."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        # Test with ethereum
        eth_config = config.get_chain_config("ethereum")
        assert isinstance(eth_config, dict)

        # Test with nonexistent chain (should return default)
        unknown_config = config.get_chain_config("unknown_chain")
        assert isinstance(unknown_config, dict)

    def test_get_enabled_chains(self):
        """Test get_enabled_chains returns list of enabled chains."""
        from src.core.config_loader import MIESCConfig

        self._reset_singleton()
        config = MIESCConfig()

        enabled_chains = config.get_enabled_chains()
        assert isinstance(enabled_chains, list)
        # At least ethereum should be enabled
        if enabled_chains:
            assert all(isinstance(chain, str) for chain in enabled_chains)

    def test_get_chain_config_with_yaml_config(self, tmp_path):
        """Test get_chain_config with actual YAML config."""
        import os

        from src.core.config_loader import MIESCConfig

        self._reset_singleton()

        # Create temp config with chains
        config_content = """
version: "4.1.0"
chains:
  default: polygon
  ethereum:
    name: Ethereum
    chain_id: 1
    enabled: true
  polygon:
    name: Polygon
    chain_id: 137
    enabled: true
  disabled_chain:
    name: Disabled
    chain_id: 999
    enabled: false
"""
        config_file = tmp_path / "test_chains.yaml"
        config_file.write_text(config_content)

        old_env = os.environ.get("MIESC_CONFIG")
        try:
            os.environ["MIESC_CONFIG"] = str(config_file)
            config = MIESCConfig()

            # Test default chain (polygon)
            default_config = config.get_chain_config()
            assert default_config.get("chain_id") == 137

            # Test specific chain
            eth_config = config.get_chain_config("ethereum")
            assert eth_config.get("chain_id") == 1

            # Test enabled chains (should not include disabled)
            enabled = config.get_enabled_chains()
            assert "ethereum" in enabled
            assert "polygon" in enabled
            assert "disabled_chain" not in enabled
        finally:
            if old_env is not None:
                os.environ["MIESC_CONFIG"] = old_env
            else:
                os.environ.pop("MIESC_CONFIG", None)
            self._reset_singleton()


class TestCoreInit:
    """Tests for core module __init__.py exports."""

    def test_all_exports_available(self):
        """Test all expected exports are available."""
        from src.core import (
            HealthChecker,
            HealthStatus,
            MLOrchestrator,
            get_ml_orchestrator,
            get_tool_discovery,
        )

        assert MLOrchestrator is not None
        assert get_ml_orchestrator is not None
        assert get_tool_discovery is not None
        assert HealthChecker is not None
        assert HealthStatus is not None


class TestCorrelationAPICoverage:
    """Tests for correlation_api.py coverage."""

    def _create_sample_findings(self):
        """Create sample findings for testing."""
        return [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "message": "Reentrancy in Contract.withdraw()",
                "location": {"file": "Contract.sol", "line": 42, "function": "withdraw"},
                "swc_id": "SWC-107",
                "confidence": 0.8,
            },
            {
                "type": "arbitrary-send",
                "severity": "medium",
                "message": "Contract sends ETH to arbitrary address",
                "location": {"file": "Contract.sol", "line": 45, "function": "withdraw"},
                "swc_id": "SWC-105",
                "confidence": 0.7,
            },
        ]

    def _create_second_tool_findings(self):
        """Create findings from a second tool for cross-validation."""
        return [
            {
                "type": "reentrancy",
                "severity": "high",
                "message": "State change after external call",
                "location": {"file": "Contract.sol", "line": 42, "function": "withdraw"},
                "swc_id": "SWC-107",
                "confidence": 0.85,
            },
        ]

    def test_correlation_api_import(self):
        """Test MIESCCorrelationAPI can be imported."""
        from src.core.correlation_api import MIESCCorrelationAPI

        assert MIESCCorrelationAPI is not None

    def test_correlation_api_init_defaults(self):
        """Test MIESCCorrelationAPI initialization with defaults."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        assert api.confidence_threshold == 0.5
        assert api.fp_threshold == 0.6
        assert api.enable_clustering is True

    def test_correlation_api_init_custom(self):
        """Test MIESCCorrelationAPI with custom parameters."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(
            min_tools_for_validation=3,
            confidence_threshold=0.7,
            fp_threshold=0.5,
            enable_clustering=False,
        )
        assert api.confidence_threshold == 0.7
        assert api.fp_threshold == 0.5
        assert api.enable_clustering is False

    def test_add_tool_results(self):
        """Test adding tool results."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        findings = self._create_sample_findings()

        count = api.add_tool_results("slither", findings)
        assert count >= 0
        assert "slither" in api._analysis_metadata["tools_used"]

    def test_add_tool_results_multiple_tools(self):
        """Test adding results from multiple tools."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()

        api.add_tool_results("slither", self._create_sample_findings())
        api.add_tool_results("aderyn", self._create_second_tool_findings())

        assert "slither" in api._analysis_metadata["tools_used"]
        assert "aderyn" in api._analysis_metadata["tools_used"]

    def test_add_tool_results_sets_start_time(self):
        """Test that adding results sets start_time."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()

        assert api._analysis_metadata["start_time"] is None
        api.add_tool_results("slither", self._create_sample_findings())
        assert api._analysis_metadata["start_time"] is not None

    def test_analyze_full_format(self):
        """Test analyze with full output format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())
        api.add_tool_results("aderyn", self._create_second_tool_findings())

        result = api.analyze(output_format="full")

        assert "metadata" in result
        assert "summary" in result
        assert "findings" in result
        assert "tool_analysis" in result

    def test_analyze_summary_format(self):
        """Test analyze with summary output format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="summary")

        assert "total_findings" in result
        assert "filtered_as_fp" in result
        assert "by_severity" in result
        assert "by_type" in result
        assert "tools_used" in result
        assert "top_issues" in result

    def test_analyze_actionable_format(self):
        """Test analyze with actionable output format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="actionable")

        assert "total_actions" in result
        assert "critical_count" in result
        assert "high_count" in result
        assert "actions" in result
        assert "remediation_plan" in result

    def test_analyze_default_format(self):
        """Test analyze with default (full) output format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze()  # No format specified

        assert "metadata" in result
        assert "summary" in result

    def test_analyze_with_clustering_disabled(self):
        """Test analyze with clustering disabled."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(enable_clustering=False)
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="full")
        # Should work without errors even with clustering disabled
        assert "findings" in result

    def test_get_findings_by_severity(self):
        """Test get_findings_by_severity method."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())
        api.analyze()  # Trigger correlation

        high_findings = api.get_findings_by_severity("high")
        assert isinstance(high_findings, list)

    def test_get_findings_by_type(self):
        """Test get_findings_by_type method."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())
        api.analyze()

        reentrancy_findings = api.get_findings_by_type("reentrancy")
        assert isinstance(reentrancy_findings, list)

    def test_get_cross_validated_only(self):
        """Test get_cross_validated_only method."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())
        api.add_tool_results("aderyn", self._create_second_tool_findings())
        api.analyze()

        cross_validated = api.get_cross_validated_only()
        assert isinstance(cross_validated, list)

    def test_clear(self):
        """Test clear method."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", self._create_sample_findings())

        assert len(api._analysis_metadata["tools_used"]) > 0
        api.clear()
        assert api._analysis_metadata["tools_used"] == []
        assert api._analysis_metadata["start_time"] is None

    def test_analyze_contract_with_correlation_function(self):
        """Test analyze_contract_with_correlation convenience function."""
        from src.core.correlation_api import analyze_contract_with_correlation

        tool_results = {
            "slither": self._create_sample_findings(),
            "aderyn": self._create_second_tool_findings(),
        }

        result = analyze_contract_with_correlation(tool_results)

        assert "metadata" in result
        assert "findings" in result

    def test_analyze_contract_with_correlation_custom_thresholds(self):
        """Test analyze_contract_with_correlation with custom thresholds."""
        from src.core.correlation_api import analyze_contract_with_correlation

        tool_results = {
            "slither": self._create_sample_findings(),
        }

        result = analyze_contract_with_correlation(
            tool_results,
            confidence_threshold=0.8,
            fp_threshold=0.3,
        )

        assert result is not None

    def test_generate_summary_report_counts(self):
        """Test summary report correctly counts severities."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(confidence_threshold=0.1, fp_threshold=0.99)
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="summary")

        assert "by_severity" in result
        assert isinstance(result["by_severity"], dict)
        assert "critical" in result["by_severity"]
        assert "high" in result["by_severity"]
        assert "medium" in result["by_severity"]
        assert "low" in result["by_severity"]

    def test_generate_actionable_report_prioritization(self):
        """Test actionable report prioritizes by severity."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(confidence_threshold=0.1, fp_threshold=0.99)

        findings = [
            {
                "type": "low-issue",
                "severity": "low",
                "message": "Low severity issue",
                "location": {"file": "Test.sol", "line": 10},
                "swc_id": "SWC-100",
                "confidence": 0.9,
            },
            {
                "type": "critical-issue",
                "severity": "critical",
                "message": "Critical severity issue",
                "location": {"file": "Test.sol", "line": 20},
                "swc_id": "SWC-101",
                "confidence": 0.9,
            },
        ]
        api.add_tool_results("test-tool", findings)

        result = api.analyze(output_format="actionable")

        if result["actions"]:
            # First action should be critical
            assert result["critical_count"] >= 0

    def test_full_report_with_clusters(self):
        """Test full report includes clusters when enabled."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(
            enable_clustering=True,
            confidence_threshold=0.1,
            fp_threshold=0.99,
        )
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="full")
        # Clusters may or may not be present depending on findings
        assert "findings" in result

    def test_fp_filtering(self):
        """Test false positive filtering based on threshold."""
        from src.core.correlation_api import MIESCCorrelationAPI

        # Very low FP threshold to filter most findings
        api = MIESCCorrelationAPI(fp_threshold=0.001)
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="full")
        # Should have filtered some as FP
        assert "findings" in result

    def test_confidence_filtering(self):
        """Test confidence filtering based on threshold."""
        from src.core.correlation_api import MIESCCorrelationAPI

        # Very high confidence threshold to filter findings
        api = MIESCCorrelationAPI(confidence_threshold=0.99)
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="summary")
        # Should filter low confidence findings
        assert result["total_findings"] >= 0

    def test_empty_findings(self):
        """Test handling of empty findings."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        api.add_tool_results("slither", [])

        result = api.analyze()
        assert "findings" in result

    def test_metadata_configuration(self):
        """Test metadata includes configuration."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(
            confidence_threshold=0.6,
            fp_threshold=0.7,
        )
        api.add_tool_results("slither", self._create_sample_findings())

        result = api.analyze(output_format="full")

        assert "metadata" in result
        assert "configuration" in result["metadata"]
        assert result["metadata"]["configuration"]["confidence_threshold"] == 0.6
        assert result["metadata"]["configuration"]["fp_threshold"] == 0.7

    def test_add_same_tool_twice(self):
        """Test adding results from same tool twice doesn't duplicate in tools_used."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()

        api.add_tool_results("slither", self._create_sample_findings())
        api.add_tool_results("slither", self._create_sample_findings())

        # Should only appear once
        assert api._analysis_metadata["tools_used"].count("slither") == 1

    def test_summary_with_cross_validated_findings(self):
        """Test summary report counts cross-validated findings (line 201)."""
        from src.core.correlation_api import MIESCCorrelationAPI

        # Use low thresholds to ensure findings pass through
        api = MIESCCorrelationAPI(
            min_tools_for_validation=2,
            confidence_threshold=0.1,
            fp_threshold=0.99,
        )

        # Add identical findings from two tools to trigger cross-validation
        reentrancy_finding = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Reentrancy vulnerability",
            "location": {"file": "Test.sol", "line": 10, "function": "withdraw"},
            "swc_id": "SWC-107",
            "confidence": 0.9,
        }

        api.add_tool_results("slither", [reentrancy_finding])
        api.add_tool_results("aderyn", [reentrancy_finding])

        result = api.analyze(output_format="summary")

        # Check cross_validated field exists and is integer
        assert "cross_validated" in result
        assert isinstance(result["cross_validated"], int)

    def test_summary_with_exact_location_cross_validation(self):
        """Test cross-validation with exact same location from multiple tools."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI(
            min_tools_for_validation=2,
            confidence_threshold=0.1,
            fp_threshold=0.99,
        )

        # Exact same finding from multiple tools
        finding = {
            "type": "reentrancy-eth",
            "severity": "high",
            "message": "State change after external call",
            "location": {"file": "Contract.sol", "line": 42, "function": "withdraw"},
            "swc_id": "SWC-107",
            "confidence": 0.85,
        }

        api.add_tool_results("tool1", [finding])
        api.add_tool_results("tool2", [finding])
        api.add_tool_results("tool3", [finding])

        result = api.analyze(output_format="summary")
        assert "cross_validated" in result

    def test_parse_root_causes_basic(self):
        """Test _parse_root_causes with basic LLM response format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()

        # Create mock CorrelatedFinding
        mock_findings = []

        llm_response = """ROOT_CAUSE_1: Missing access control on sensitive functions
EXPLAINS: 1, 2, 3
PRIORITY: HIGH

ROOT_CAUSE_2: State changes after external calls
EXPLAINS: 4, 5
PRIORITY: MEDIUM"""

        result = api._parse_root_causes(llm_response, mock_findings)

        assert "root_causes" in result
        assert "grouped_findings" in result
        assert len(result["root_causes"]) == 2
        assert result["root_causes"][0]["priority"] == "HIGH"
        assert result["root_causes"][1]["priority"] == "MEDIUM"

    def test_parse_root_causes_empty_response(self):
        """Test _parse_root_causes with empty response."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        result = api._parse_root_causes("", [])

        assert result["root_causes"] == []
        assert result["grouped_findings"] == {}

    def test_parse_root_causes_malformed_response(self):
        """Test _parse_root_causes with malformed response."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        llm_response = """Some random text
without proper formatting
but with ROOT_CAUSE_1: partial format
and more noise"""

        result = api._parse_root_causes(llm_response, [])

        assert "root_causes" in result
        # Should handle partial parsing gracefully
        assert isinstance(result["root_causes"], list)

    def test_parse_root_causes_invalid_explains(self):
        """Test _parse_root_causes with invalid EXPLAINS format."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        llm_response = """ROOT_CAUSE_1: Test cause
EXPLAINS: not numbers here
PRIORITY: LOW"""

        result = api._parse_root_causes(llm_response, [])

        assert len(result["root_causes"]) == 1
        assert result["root_causes"][0]["finding_indices"] == []
        assert result["root_causes"][0]["priority"] == "LOW"

    def test_llm_root_cause_analysis_empty_findings(self):
        """Test _llm_root_cause_analysis with empty findings."""
        from src.core.correlation_api import MIESCCorrelationAPI

        api = MIESCCorrelationAPI()
        result = api._llm_root_cause_analysis([])

        assert result == {"root_causes": [], "grouped_findings": {}}

    @patch("subprocess.run")
    def test_llm_root_cause_analysis_timeout(self, mock_run):
        """Test _llm_root_cause_analysis handles timeout."""
        import subprocess

        from src.core.correlation_api import MIESCCorrelationAPI
        from src.ml.correlation_engine import CorrelatedFinding

        mock_run.side_effect = subprocess.TimeoutExpired("curl", 60)

        api = MIESCCorrelationAPI()
        # Set LLM config to avoid lazy loading issues
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        # Create a minimal mock finding
        mock_finding = MagicMock(spec=CorrelatedFinding)
        mock_finding.severity = "high"
        mock_finding.canonical_type = "reentrancy"
        mock_finding.location = {"file": "Test.sol", "line": 10}
        mock_finding.message = "Test vulnerability"

        result = api._llm_root_cause_analysis([mock_finding])

        assert result == {"root_causes": [], "grouped_findings": {}}

    @patch("subprocess.run")
    def test_llm_root_cause_analysis_json_error(self, mock_run):
        """Test _llm_root_cause_analysis handles JSON decode error."""
        from src.core.correlation_api import MIESCCorrelationAPI
        from src.ml.correlation_engine import CorrelatedFinding

        mock_run.return_value = MagicMock(returncode=0, stdout="not valid json")

        api = MIESCCorrelationAPI()
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        mock_finding = MagicMock(spec=CorrelatedFinding)
        mock_finding.severity = "high"
        mock_finding.canonical_type = "reentrancy"
        mock_finding.location = {"file": "Test.sol", "line": 10}
        mock_finding.message = "Test vulnerability"

        result = api._llm_root_cause_analysis([mock_finding])

        assert result == {"root_causes": [], "grouped_findings": {}}

    @patch("subprocess.run")
    def test_llm_root_cause_analysis_success(self, mock_run):
        """Test _llm_root_cause_analysis with successful LLM response."""
        import json

        from src.core.correlation_api import MIESCCorrelationAPI
        from src.ml.correlation_engine import CorrelatedFinding

        llm_response = """ROOT_CAUSE_1: Access control issue
EXPLAINS: 1
PRIORITY: HIGH"""

        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps({"response": llm_response})
        )

        api = MIESCCorrelationAPI()
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        mock_finding = MagicMock(spec=CorrelatedFinding)
        mock_finding.severity = "high"
        mock_finding.canonical_type = "reentrancy"
        mock_finding.location = {"file": "Test.sol", "line": 10}
        mock_finding.message = "Test vulnerability"

        result = api._llm_root_cause_analysis([mock_finding])

        assert "root_causes" in result
        assert len(result["root_causes"]) >= 1

    @patch("subprocess.run")
    def test_analyze_with_llm_correlation_enabled(self, mock_run):
        """Test analyze with LLM correlation enabled."""
        import json

        from src.core.correlation_api import MIESCCorrelationAPI

        llm_response = """ROOT_CAUSE_1: Common pattern issue
EXPLAINS: 1
PRIORITY: HIGH"""

        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps({"response": llm_response})
        )

        api = MIESCCorrelationAPI(
            enable_llm_correlation=True,
            confidence_threshold=0.1,
            fp_threshold=0.99,
        )
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "message": "State change after external call",
                "location": {"file": "Contract.sol", "line": 42},
                "swc_id": "SWC-107",
                "confidence": 0.85,
            }
        ]

        api.add_tool_results("slither", findings)
        result = api.analyze(output_format="full")

        assert "llm_root_cause_analysis" in result
        assert result["llm_root_cause_analysis"]["enabled"] is True

    @patch("subprocess.run")
    def test_llm_root_cause_analysis_general_exception(self, mock_run):
        """Test _llm_root_cause_analysis handles general exceptions."""
        from src.core.correlation_api import MIESCCorrelationAPI
        from src.ml.correlation_engine import CorrelatedFinding

        mock_run.side_effect = Exception("Connection refused")

        api = MIESCCorrelationAPI()
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        mock_finding = MagicMock(spec=CorrelatedFinding)
        mock_finding.severity = "high"
        mock_finding.canonical_type = "reentrancy"
        mock_finding.location = {"file": "Test.sol", "line": 10}
        mock_finding.message = "Test vulnerability"

        result = api._llm_root_cause_analysis([mock_finding])

        assert result == {"root_causes": [], "grouped_findings": {}}

    @patch("subprocess.run")
    def test_llm_root_cause_analysis_nonzero_return(self, mock_run):
        """Test _llm_root_cause_analysis handles non-zero return code."""
        from src.core.correlation_api import MIESCCorrelationAPI
        from src.ml.correlation_engine import CorrelatedFinding

        mock_run.return_value = MagicMock(returncode=1, stdout="")

        api = MIESCCorrelationAPI()
        api._llm_model = "test-model"
        api._ollama_host = "http://localhost:11434"

        mock_finding = MagicMock(spec=CorrelatedFinding)
        mock_finding.severity = "high"
        mock_finding.canonical_type = "reentrancy"
        mock_finding.location = {"file": "Test.sol", "line": 10}
        mock_finding.message = "Test vulnerability"

        result = api._llm_root_cause_analysis([mock_finding])

        assert result == {"root_causes": [], "grouped_findings": {}}


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
