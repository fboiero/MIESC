"""
Tests for MIESC Plugin System (src/plugins)
============================================

Tests for:
- Plugin Protocol (base classes, metadata, context)
- Plugin Loader (discovery, loading, validation)
- Plugin Registry (registration, queries, persistence)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from src.plugins import (
    AdapterPlugin,
    DetectorPlugin,
    DiscoveryResult,
    LoadedPlugin,
    MIESCPlugin,
    PluginContext,
    PluginEntry,
    # Loader
    PluginLoader,
    PluginMetadata,
    # Registry
    PluginRegistry,
    PluginResult,
    PluginState,
    # Protocol
    PluginType,
    ReporterPlugin,
    TransformerPlugin,
    is_plugin_class,
)

# ============================================================================
# Test Fixtures
# ============================================================================


class SampleDetector(DetectorPlugin):
    """Sample detector plugin for testing."""

    @property
    def name(self) -> str:
        return "sample-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "A sample detector for testing"

    @property
    def author(self) -> str:
        return "Test Author"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def detect(
        self,
        code: str,
        filename: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        findings = []
        if "vulnerable" in code.lower():
            findings.append(
                {
                    "type": "test-vulnerability",
                    "severity": "high",
                    "line": 1,
                    "message": "Test vulnerability found",
                }
            )
        return findings


class SampleAdapter(AdapterPlugin):
    """Sample adapter plugin for testing."""

    @property
    def name(self) -> str:
        return "sample-adapter"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def tool_name(self) -> str:
        return "sample-tool"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def is_available(self) -> bool:
        return True

    def analyze(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        return [{"type": "sample-finding", "severity": "medium"}]


class SampleReporter(ReporterPlugin):
    """Sample reporter plugin for testing."""

    @property
    def name(self) -> str:
        return "sample-reporter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def format_name(self) -> str:
        return "txt"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def generate(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        output_path: str,
    ) -> Path:
        path = Path(output_path)
        path.write_text(f"Report: {len(findings)} findings")
        return path


class SampleTransformer(TransformerPlugin):
    """Sample transformer plugin for testing."""

    @property
    def name(self) -> str:
        return "sample-transformer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def transform(
        self,
        code: str,
        finding: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        return code.replace("vulnerable", "safe")


@pytest.fixture
def plugin_context():
    """Create a test plugin context."""
    return PluginContext(
        miesc_version="4.5.0",
        config={"test": True},
        data_dir=Path("/tmp/miesc/data"),
        cache_dir=Path("/tmp/miesc/cache"),
        log_level="DEBUG",
        debug=True,
    )


@pytest.fixture
def sample_detector():
    """Create a sample detector instance."""
    return SampleDetector()


@pytest.fixture
def sample_adapter():
    """Create a sample adapter instance."""
    return SampleAdapter()


@pytest.fixture
def temp_registry_path(tmp_path):
    """Create a temporary registry path."""
    return tmp_path / "test_registry.json"


# ============================================================================
# Protocol Tests
# ============================================================================


class TestPluginType:
    """Tests for PluginType enum."""

    def test_plugin_types_exist(self):
        """All plugin types should be defined."""
        assert PluginType.DETECTOR.value == "detector"
        assert PluginType.ADAPTER.value == "adapter"
        assert PluginType.REPORTER.value == "reporter"
        assert PluginType.TRANSFORMER.value == "transformer"
        assert PluginType.ANALYZER.value == "analyzer"
        assert PluginType.HOOK.value == "hook"

    def test_plugin_type_from_string(self):
        """Should create PluginType from string."""
        assert PluginType("detector") == PluginType.DETECTOR
        assert PluginType("adapter") == PluginType.ADAPTER

    def test_invalid_plugin_type(self):
        """Should raise ValueError for invalid type."""
        with pytest.raises(ValueError):
            PluginType("invalid")


class TestPluginState:
    """Tests for PluginState enum."""

    def test_plugin_states_exist(self):
        """All plugin states should be defined."""
        assert PluginState.UNLOADED.value == "unloaded"
        assert PluginState.LOADED.value == "loaded"
        assert PluginState.INITIALIZED.value == "initialized"
        assert PluginState.ENABLED.value == "enabled"
        assert PluginState.DISABLED.value == "disabled"
        assert PluginState.ERROR.value == "error"


class TestPluginMetadata:
    """Tests for PluginMetadata dataclass."""

    def test_create_metadata(self):
        """Should create metadata with required fields."""
        meta = PluginMetadata(
            name="test-plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
        )
        assert meta.name == "test-plugin"
        assert meta.version == "1.0.0"
        assert meta.plugin_type == PluginType.DETECTOR

    def test_metadata_defaults(self):
        """Should have sensible defaults."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
        )
        assert meta.description == ""
        assert meta.author == ""
        assert meta.tags == []
        assert meta.dependencies == []
        assert meta.min_miesc_version == "4.0.0"

    def test_metadata_to_dict(self):
        """Should convert to dictionary."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Test plugin",
            author="Test Author",
            tags=["security", "testing"],
        )
        data = meta.to_dict()
        assert data["name"] == "test"
        assert data["version"] == "1.0.0"
        assert data["plugin_type"] == "detector"
        assert data["tags"] == ["security", "testing"]

    def test_metadata_from_dict(self):
        """Should create from dictionary."""
        data = {
            "name": "test",
            "version": "1.0.0",
            "plugin_type": "detector",
            "description": "Test",
        }
        meta = PluginMetadata.from_dict(data)
        assert meta.name == "test"
        assert meta.plugin_type == PluginType.DETECTOR


class TestPluginContext:
    """Tests for PluginContext dataclass."""

    def test_create_context(self, plugin_context):
        """Should create context with all fields."""
        assert plugin_context.miesc_version == "4.5.0"
        assert plugin_context.config["test"] is True
        assert plugin_context.debug is True

    def test_context_get_service(self, plugin_context):
        """Should get service by name."""
        plugin_context.services["test_service"] = "test_value"
        assert plugin_context.get_service("test_service") == "test_value"
        assert plugin_context.get_service("nonexistent") is None

    def test_context_report_finding(self):
        """Should call on_finding callback."""
        callback = MagicMock()
        context = PluginContext(
            miesc_version="4.5.0",
            config={},
            data_dir=Path("/tmp"),
            cache_dir=Path("/tmp"),
            on_finding=callback,
        )
        finding = {"type": "test", "severity": "high"}
        context.report_finding(finding)
        callback.assert_called_once_with(finding)

    def test_context_report_progress(self):
        """Should call on_progress callback."""
        callback = MagicMock()
        context = PluginContext(
            miesc_version="4.5.0",
            config={},
            data_dir=Path("/tmp"),
            cache_dir=Path("/tmp"),
            on_progress=callback,
        )
        context.report_progress(0.5, "Processing...")
        callback.assert_called_once_with(0.5, "Processing...")


class TestPluginResult:
    """Tests for PluginResult dataclass."""

    def test_success_result(self):
        """Should create success result."""
        result = PluginResult(success=True, data={"findings": []})
        assert result.success is True
        assert result.error is None

    def test_error_result(self):
        """Should create error result."""
        result = PluginResult(success=False, error="Something went wrong")
        assert result.success is False
        assert result.error == "Something went wrong"

    def test_result_with_warnings(self):
        """Should include warnings."""
        result = PluginResult(
            success=True,
            data={},
            warnings=["Warning 1", "Warning 2"],
        )
        assert len(result.warnings) == 2


# ============================================================================
# Plugin Base Class Tests
# ============================================================================


class TestDetectorPlugin:
    """Tests for DetectorPlugin base class."""

    def test_detector_plugin_type(self, sample_detector):
        """Detector should have DETECTOR type."""
        assert sample_detector.plugin_type == PluginType.DETECTOR

    def test_detector_properties(self, sample_detector):
        """Should have required properties."""
        assert sample_detector.name == "sample-detector"
        assert sample_detector.version == "1.0.0"
        assert sample_detector.description == "A sample detector for testing"

    def test_detector_initialize(self, sample_detector, plugin_context):
        """Should initialize with context."""
        sample_detector.initialize(plugin_context)
        assert sample_detector._context == plugin_context

    def test_detector_detect(self, sample_detector, plugin_context):
        """Should detect vulnerabilities."""
        sample_detector.initialize(plugin_context)
        findings = sample_detector.detect("This code is vulnerable")
        assert len(findings) == 1
        assert findings[0]["type"] == "test-vulnerability"

    def test_detector_detect_no_findings(self, sample_detector, plugin_context):
        """Should return empty list for safe code."""
        sample_detector.initialize(plugin_context)
        findings = sample_detector.detect("This code is safe")
        assert len(findings) == 0

    def test_detector_execute(self, sample_detector, plugin_context):
        """Should execute and return PluginResult."""
        sample_detector.initialize(plugin_context)
        result = sample_detector.execute(code="vulnerable code")
        assert result.success is True
        assert result.metadata["finding_count"] == 1


class TestAdapterPlugin:
    """Tests for AdapterPlugin base class."""

    def test_adapter_plugin_type(self, sample_adapter):
        """Adapter should have ADAPTER type."""
        assert sample_adapter.plugin_type == PluginType.ADAPTER

    def test_adapter_tool_name(self, sample_adapter):
        """Should have tool name."""
        assert sample_adapter.tool_name == "sample-tool"

    def test_adapter_is_available(self, sample_adapter):
        """Should check availability."""
        assert sample_adapter.is_available() is True

    def test_adapter_analyze(self, sample_adapter, plugin_context):
        """Should analyze target."""
        sample_adapter.initialize(plugin_context)
        findings = sample_adapter.analyze("test.sol")
        assert len(findings) == 1

    def test_adapter_execute(self, sample_adapter, plugin_context):
        """Should execute and return PluginResult."""
        sample_adapter.initialize(plugin_context)
        result = sample_adapter.execute(target="test.sol")
        assert result.success is True
        assert result.metadata["tool"] == "sample-tool"


class TestReporterPlugin:
    """Tests for ReporterPlugin base class."""

    def test_reporter_format_name(self):
        """Should have format name."""
        reporter = SampleReporter()
        assert reporter.format_name == "txt"
        assert reporter.file_extension == "txt"

    def test_reporter_generate(self, plugin_context, tmp_path):
        """Should generate report."""
        reporter = SampleReporter()
        reporter.initialize(plugin_context)
        output = tmp_path / "report.txt"
        result = reporter.generate(
            findings=[{"type": "test"}],
            metadata={},
            output_path=str(output),
        )
        assert result.exists()
        assert "1 findings" in result.read_text()


class TestTransformerPlugin:
    """Tests for TransformerPlugin base class."""

    def test_transformer_transform(self, plugin_context):
        """Should transform code."""
        transformer = SampleTransformer()
        transformer.initialize(plugin_context)
        result = transformer.transform("This is vulnerable code")
        assert "safe" in result
        assert "vulnerable" not in result


# ============================================================================
# Plugin Helpers Tests
# ============================================================================


class TestPluginHelpers:
    """Tests for plugin helper functions."""

    def test_is_plugin_class_valid(self):
        """Should identify valid plugin classes."""
        assert is_plugin_class(SampleDetector) is True
        assert is_plugin_class(SampleAdapter) is True

    def test_is_plugin_class_invalid(self):
        """Should reject invalid classes."""
        assert is_plugin_class(str) is False
        assert is_plugin_class(MIESCPlugin) is False  # Abstract
        assert is_plugin_class("not a class") is False


# ============================================================================
# Loader Tests
# ============================================================================


class TestPluginLoader:
    """Tests for PluginLoader."""

    def test_loader_init(self):
        """Should initialize loader."""
        loader = PluginLoader()
        assert len(loader.plugin_dirs) > 0

    def test_loader_custom_dirs(self, tmp_path):
        """Should accept custom plugin directories."""
        loader = PluginLoader(plugin_dirs=[tmp_path])
        assert tmp_path in loader.plugin_dirs

    def test_discover_from_directory_empty(self, tmp_path):
        """Should handle empty directory."""
        loader = PluginLoader()
        result = loader.discover_from_directory(tmp_path)
        assert len(result.plugins) == 0
        assert str(tmp_path) in result.sources_searched

    def test_discover_from_directory_nonexistent(self, tmp_path):
        """Should handle nonexistent directory."""
        loader = PluginLoader()
        result = loader.discover_from_directory(tmp_path / "nonexistent")
        assert len(result.plugins) == 0
        assert len(result.errors) > 0

    def test_load_plugin_file(self, tmp_path):
        """Should load plugin from file."""
        # Create a plugin file
        plugin_code = """
from src.plugins import DetectorPlugin, PluginContext
from typing import Any, Dict, List, Optional

class TestFileDetector(DetectorPlugin):
    @property
    def name(self) -> str:
        return "test-file-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        pass

    def detect(self, code: str, filename: str = "", options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return []
"""
        plugin_file = tmp_path / "test_plugin.py"
        plugin_file.write_text(plugin_code)

        loader = PluginLoader()
        plugins = loader.load_plugin_file(plugin_file)

        assert len(plugins) == 1
        assert plugins[0].plugin_class.__name__ == "TestFileDetector"

    def test_validate_plugin_valid(self):
        """Should validate valid plugin."""
        loader = PluginLoader()
        errors = loader.validate_plugin(SampleDetector)
        assert len(errors) == 0

    def test_validate_plugin_invalid(self):
        """Should return errors for invalid plugin."""
        loader = PluginLoader()
        errors = loader.validate_plugin(str)
        assert len(errors) > 0

    def test_version_compatible(self):
        """Should check version compatibility."""
        loader = PluginLoader()
        assert loader._version_compatible("4.5.0", "4.0.0") is True
        assert loader._version_compatible("4.5.0", "5.0.0") is False
        assert loader._version_compatible("4.5.0", "4.0.0", "5.0.0") is True
        assert loader._version_compatible("4.5.0", "4.0.0", "4.4.0") is False

    def test_load_and_initialize(self, plugin_context):
        """Should load and initialize plugin."""
        loader = PluginLoader()
        loaded = LoadedPlugin(
            plugin_class=SampleDetector,
            source="test",
        )
        instance = loader.load_and_initialize(loaded, plugin_context)

        assert instance.name == "sample-detector"
        assert instance.state == PluginState.INITIALIZED
        assert loaded.instance is instance


class TestLoadedPlugin:
    """Tests for LoadedPlugin dataclass."""

    def test_loaded_plugin_name(self):
        """Should get name from various sources."""
        # From class name
        loaded = LoadedPlugin(plugin_class=SampleDetector)
        assert loaded.name == "SampleDetector"

        # From instance
        instance = SampleDetector()
        loaded.instance = instance
        assert loaded.name == "sample-detector"

    def test_loaded_plugin_type(self):
        """Should get plugin type."""
        instance = SampleDetector()
        loaded = LoadedPlugin(plugin_class=SampleDetector)
        loaded.instance = instance
        assert loaded.plugin_type == PluginType.DETECTOR


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""

    def test_success_count(self):
        """Should count successful loads."""
        result = DiscoveryResult(
            plugins=[
                LoadedPlugin(plugin_class=SampleDetector),
                LoadedPlugin(plugin_class=SampleAdapter, load_error="Error"),
            ]
        )
        assert result.success_count == 1
        assert result.error_count == 1


# ============================================================================
# Registry Tests
# ============================================================================


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_registry_init(self, temp_registry_path):
        """Should initialize registry."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        assert len(registry) == 0

    def test_register_plugin(self, temp_registry_path, plugin_context):
        """Should register a plugin."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        entry = registry.register(detector)

        assert entry.name == "sample-detector"
        assert entry.version == "1.0.0"
        assert "sample-detector" in registry

    def test_register_loaded_plugin(self, temp_registry_path, plugin_context):
        """Should register LoadedPlugin."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        loaded = LoadedPlugin(
            plugin_class=SampleDetector,
            instance=detector,
            source="test",
        )

        entry = registry.register(loaded)
        assert entry.source == "test"

    def test_unregister_plugin(self, temp_registry_path, plugin_context):
        """Should unregister a plugin."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        registry.register(detector)
        assert "sample-detector" in registry

        result = registry.unregister("sample-detector")
        assert result is True
        assert "sample-detector" not in registry

    def test_get_plugin(self, temp_registry_path, plugin_context):
        """Should get plugin by name."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        registry.register(detector)

        result = registry.get("sample-detector")
        assert result is detector

    def test_get_nonexistent_plugin(self, temp_registry_path):
        """Should return None for nonexistent plugin."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        assert registry.get("nonexistent") is None

    def test_enable_disable(self, temp_registry_path, plugin_context):
        """Should enable and disable plugins."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )
        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        registry.register(detector, enabled=True)

        # Disable
        registry.disable("sample-detector")
        entry = registry.get_entry("sample-detector")
        assert entry.enabled is False
        assert registry.get("sample-detector") is None  # Disabled plugins not returned

        # Enable
        registry.enable("sample-detector")
        entry = registry.get_entry("sample-detector")
        assert entry.enabled is True

    def test_list_plugins(self, temp_registry_path, plugin_context):
        """Should list all plugins."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        for plugin_cls in [SampleDetector, SampleAdapter]:
            plugin = plugin_cls()
            plugin.initialize(plugin_context)
            plugin._set_initialized(plugin_context)
            registry.register(plugin)

        plugins = registry.list_plugins()
        assert len(plugins) == 2

    def test_list_by_type(self, temp_registry_path, plugin_context):
        """Should list plugins by type."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        for plugin_cls in [SampleDetector, SampleAdapter]:
            plugin = plugin_cls()
            plugin.initialize(plugin_context)
            plugin._set_initialized(plugin_context)
            registry.register(plugin)

        detectors = registry.list_by_type(PluginType.DETECTOR)
        assert len(detectors) == 1
        assert detectors[0].name == "sample-detector"

        adapters = registry.list_by_type(PluginType.ADAPTER)
        assert len(adapters) == 1

    def test_list_enabled_disabled(self, temp_registry_path, plugin_context):
        """Should list enabled/disabled plugins."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)

        adapter = SampleAdapter()
        adapter.initialize(plugin_context)
        adapter._set_initialized(plugin_context)

        registry.register(detector, enabled=True)
        registry.register(adapter, enabled=False)

        assert len(registry.list_enabled()) == 1
        assert len(registry.list_disabled()) == 1

    def test_search_plugins(self, temp_registry_path, plugin_context):
        """Should search plugins."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry.register(detector)

        results = registry.search("detector")
        assert len(results) == 1

        results = registry.search("nonexistent")
        assert len(results) == 0

    def test_configure_plugin(self, temp_registry_path, plugin_context):
        """Should configure a plugin."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry.register(detector)

        config = {"option1": "value1"}
        result = registry.configure("sample-detector", config)
        assert result is True

        entry = registry.get_entry("sample-detector")
        assert entry.config == config

    def test_persistence_save_load(self, temp_registry_path, plugin_context):
        """Should save and load registry."""
        # Create and save
        registry1 = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry1.register(detector)
        registry1.save()

        # Load in new registry
        registry2 = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=True,
        )

        assert "sample-detector" in registry2
        entry = registry2.get_entry("sample-detector")
        assert entry.version == "1.0.0"

    def test_hooks(self, temp_registry_path, plugin_context):
        """Should trigger hooks."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        register_callback = MagicMock()
        registry.add_hook("on_register", register_callback)

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry.register(detector)

        register_callback.assert_called_once()

    def test_get_stats(self, temp_registry_path, plugin_context):
        """Should return statistics."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry.register(detector)

        stats = registry.get_stats()
        assert stats["total"] == 1
        assert stats["enabled"] == 1
        assert stats["by_type"]["detector"] == 1

    def test_clear_registry(self, temp_registry_path, plugin_context):
        """Should clear all plugins."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        detector = SampleDetector()
        detector.initialize(plugin_context)
        detector._set_initialized(plugin_context)
        registry.register(detector)

        assert len(registry) == 1
        registry.clear()
        assert len(registry) == 0


class TestPluginEntry:
    """Tests for PluginEntry dataclass."""

    def test_entry_to_dict(self):
        """Should convert to dictionary."""
        entry = PluginEntry(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            enabled=True,
        )
        data = entry.to_dict()
        assert data["name"] == "test"
        assert data["plugin_type"] == "detector"

    def test_entry_from_dict(self):
        """Should create from dictionary."""
        data = {
            "name": "test",
            "version": "1.0.0",
            "plugin_type": "detector",
            "enabled": True,
            "installed_at": datetime.now().isoformat(),
        }
        entry = PluginEntry.from_dict(data)
        assert entry.name == "test"
        assert entry.plugin_type == PluginType.DETECTOR


# ============================================================================
# Integration Tests
# ============================================================================


class TestPluginSystemIntegration:
    """Integration tests for plugin system."""

    def test_full_lifecycle(self, tmp_path, plugin_context):
        """Test complete plugin lifecycle."""
        # 1. Create plugin file
        plugin_code = """
from src.plugins import DetectorPlugin, PluginContext, PluginResult
from typing import Any, Dict, List, Optional

class IntegrationTestDetector(DetectorPlugin):
    @property
    def name(self) -> str:
        return "integration-test-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Integration test detector"

    def initialize(self, context: PluginContext) -> None:
        self._context = context
        self._initialized = True

    def detect(self, code: str, filename: str = "", options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return [{"type": "test", "severity": "low"}] if "test" in code else []
"""
        plugin_file = tmp_path / "integration_plugin.py"
        plugin_file.write_text(plugin_code)

        # 2. Load plugin
        loader = PluginLoader(plugin_dirs=[tmp_path])
        plugins = loader.load_plugin_file(plugin_file)
        assert len(plugins) == 1

        loaded = plugins[0]

        # 3. Initialize
        instance = loader.load_and_initialize(loaded, plugin_context)
        assert instance.state == PluginState.INITIALIZED

        # 4. Register
        registry_path = tmp_path / "registry.json"
        registry = PluginRegistry(registry_path=registry_path, auto_load=False)
        entry = registry.register(loaded)
        assert entry.name == "integration-test-detector"

        # 5. Use plugin
        plugin = registry.get("integration-test-detector")
        result = plugin.execute(code="test code here")
        assert result.success is True
        assert len(result.data) == 1

        # 6. Save registry
        registry.save()
        assert registry_path.exists()

        # 7. Disable and re-enable
        registry.disable("integration-test-detector")
        assert registry.get("integration-test-detector") is None

        registry.enable("integration-test-detector")
        assert registry.get("integration-test-detector") is not None

        # 8. Unregister
        registry.unregister("integration-test-detector")
        assert "integration-test-detector" not in registry

    def test_multiple_plugin_types(self, temp_registry_path, plugin_context):
        """Test registering multiple plugin types."""
        registry = PluginRegistry(
            registry_path=temp_registry_path,
            auto_load=False,
        )

        # Register all sample plugins
        for plugin_cls in [SampleDetector, SampleAdapter, SampleReporter, SampleTransformer]:
            plugin = plugin_cls()
            plugin.initialize(plugin_context)
            plugin._set_initialized(plugin_context)
            registry.register(plugin)

        # Verify
        assert len(registry) == 4
        assert len(registry.list_by_type(PluginType.DETECTOR)) == 1
        assert len(registry.list_by_type(PluginType.ADAPTER)) == 1
        assert len(registry.list_by_type(PluginType.REPORTER)) == 1
        assert len(registry.list_by_type(PluginType.TRANSFORMER)) == 1

        stats = registry.get_stats()
        assert stats["total"] == 4


# ============================================================================
# Template Generator Tests
# ============================================================================


class TestPluginTemplateGenerator:
    """Tests for PluginTemplateGenerator."""

    def test_create_detector_plugin(self, tmp_path):
        """Should create a detector plugin scaffold."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="test-detector",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
            description="Test detector",
            author="Test Author",
        )

        assert plugin_path.exists()
        assert plugin_path.name == "miesc-test-detector"
        assert (plugin_path / "pyproject.toml").exists()
        assert (plugin_path / "test_detector" / "__init__.py").exists()
        assert (plugin_path / "test_detector" / "plugin.py").exists()
        assert (plugin_path / "tests" / "test_test_detector.py").exists()
        assert (plugin_path / "README.md").exists()

    def test_create_adapter_plugin(self, tmp_path):
        """Should create an adapter plugin scaffold."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="custom-tool",
            plugin_type=PluginType.ADAPTER,
            output_dir=tmp_path,
        )

        assert plugin_path.exists()
        plugin_file = plugin_path / "custom_tool" / "plugin.py"
        assert plugin_file.exists()
        content = plugin_file.read_text()
        assert "AdapterPlugin" in content
        assert "is_available" in content
        assert "analyze" in content

    def test_create_reporter_plugin(self, tmp_path):
        """Should create a reporter plugin scaffold."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="custom-report",
            plugin_type=PluginType.REPORTER,
            output_dir=tmp_path,
        )

        plugin_file = plugin_path / "custom_report" / "plugin.py"
        content = plugin_file.read_text()
        assert "ReporterPlugin" in content
        assert "generate" in content
        assert "format_name" in content

    def test_create_transformer_plugin(self, tmp_path):
        """Should create a transformer plugin scaffold."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="auto-fixer",
            plugin_type=PluginType.TRANSFORMER,
            output_dir=tmp_path,
        )

        plugin_file = plugin_path / "auto_fixer" / "plugin.py"
        content = plugin_file.read_text()
        assert "TransformerPlugin" in content
        assert "transform" in content

    def test_normalize_name(self):
        """Should normalize plugin names correctly."""
        from src.plugins import PluginTemplateGenerator

        generator = PluginTemplateGenerator()

        assert generator._normalize_name("My Plugin") == "my-plugin"
        assert generator._normalize_name("miesc-test") == "test"
        assert generator._normalize_name("Test_Plugin") == "test-plugin"
        assert generator._normalize_name("flash--loan") == "flash-loan"

    def test_to_class_name(self):
        """Should convert to PascalCase class name."""
        from src.plugins import PluginTemplateGenerator

        generator = PluginTemplateGenerator()

        assert generator._to_class_name("test-detector") == "TestDetector"
        assert generator._to_class_name("flash-loan") == "FlashLoan"
        assert generator._to_class_name("my_plugin") == "MyPlugin"

    def test_pyproject_toml_content(self, tmp_path):
        """Should create valid pyproject.toml."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="test-plugin",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
            author="Test Author",
            email="test@example.com",
        )

        pyproject = plugin_path / "pyproject.toml"
        content = pyproject.read_text()

        assert 'name = "miesc-test-plugin"' in content
        assert 'version = "0.1.0"' in content
        assert "[project.entry-points" in content
        assert "miesc.plugins" in content

    def test_readme_content(self, tmp_path):
        """Should create README with plugin info."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="my-detector",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
            description="My custom detector",
        )

        readme = plugin_path / "README.md"
        content = readme.read_text()

        assert "miesc-my-detector" in content
        assert "My custom detector" in content
        assert "detector" in content.lower()
        assert "pip install" in content

    def test_test_file_content(self, tmp_path):
        """Should create test file with plugin tests."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="test-detector",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
        )

        test_file = plugin_path / "tests" / "test_test_detector.py"
        content = test_file.read_text()

        assert "pytest" in content
        assert "test_plugin_name" in content
        assert "test_plugin_version" in content
        assert "test_plugin_type" in content

    def test_plugin_with_tags(self, tmp_path):
        """Should include tags in metadata."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="defi-detector",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
            tags=["defi", "flash-loan", "security"],
        )

        pyproject = plugin_path / "pyproject.toml"
        content = pyproject.read_text()

        assert "defi" in content
        assert "flash-loan" in content

    def test_generated_plugin_imports(self, tmp_path):
        """Generated plugin should have correct imports."""
        from src.plugins import PluginTemplateGenerator, PluginType

        generator = PluginTemplateGenerator()
        plugin_path = generator.create_plugin(
            name="import-test",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
        )

        plugin_file = plugin_path / "import_test" / "plugin.py"
        content = plugin_file.read_text()

        # Imports are combined in one line
        assert "DetectorPlugin" in content
        assert "PluginContext" in content
        assert "from src.plugins import" in content
