"""
Tests for src/plugins/loader.py

Comprehensive tests for plugin loading functionality including:
- LoadedPlugin and DiscoveryResult dataclasses
- PluginLoader class methods
- Plugin discovery from directories and entry points
- Plugin validation and initialization
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.plugins.loader import (
    DEFAULT_PLUGIN_DIRS,
    ENTRY_POINT_GROUP,
    DiscoveryResult,
    LoadedPlugin,
    PluginLoader,
)
from src.plugins.protocol import (
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginState,
    PluginType,
)


class MockPlugin(MIESCPlugin):
    """Mock plugin for testing."""

    @property
    def name(self) -> str:
        return "MockPlugin"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.DETECTOR

    def initialize(self, context: PluginContext) -> None:
        pass

    def execute(self, contract_code: str, **kwargs):
        return []


class TestConstants:
    """Tests for module constants."""

    def test_entry_point_group(self):
        """Test entry point group name."""
        assert ENTRY_POINT_GROUP == "miesc.plugins"

    def test_default_plugin_dirs(self):
        """Test default plugin directories."""
        assert len(DEFAULT_PLUGIN_DIRS) == 2
        assert DEFAULT_PLUGIN_DIRS[0] == Path.home() / ".miesc" / "plugins"
        assert DEFAULT_PLUGIN_DIRS[1] == Path("/etc/miesc/plugins")


class TestLoadedPlugin:
    """Tests for LoadedPlugin dataclass."""

    def test_default_values(self):
        """Test default values."""
        loaded = LoadedPlugin(plugin_class=MockPlugin)
        assert loaded.plugin_class == MockPlugin
        assert loaded.instance is None
        assert loaded.source == ""
        assert loaded.metadata is None
        assert loaded.load_error is None

    def test_with_all_values(self):
        """Test with all values set."""
        instance = MockPlugin()
        metadata = PluginMetadata(
            name="TestPlugin",
            version="2.0.0",
            plugin_type=PluginType.ANALYZER,
        )
        loaded = LoadedPlugin(
            plugin_class=MockPlugin,
            instance=instance,
            source="/path/to/plugin.py",
            metadata=metadata,
            load_error=None,
        )
        assert loaded.source == "/path/to/plugin.py"
        assert loaded.metadata.name == "TestPlugin"

    def test_name_from_instance(self):
        """Test name property from instance."""
        instance = MockPlugin()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        assert loaded.name == "MockPlugin"

    def test_name_from_metadata(self):
        """Test name property from metadata when no instance."""
        metadata = PluginMetadata(
            name="FromMetadata",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
        )
        loaded = LoadedPlugin(plugin_class=MockPlugin, metadata=metadata)
        assert loaded.name == "FromMetadata"

    def test_name_from_class(self):
        """Test name property from class when no instance or metadata."""
        loaded = LoadedPlugin(plugin_class=MockPlugin)
        assert loaded.name == "MockPlugin"

    def test_version_from_instance(self):
        """Test version property from instance."""
        instance = MockPlugin()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        assert loaded.version == "1.0.0"

    def test_version_from_metadata(self):
        """Test version property from metadata when no instance."""
        metadata = PluginMetadata(
            name="Test",
            version="2.5.0",
            plugin_type=PluginType.DETECTOR,
        )
        loaded = LoadedPlugin(plugin_class=MockPlugin, metadata=metadata)
        assert loaded.version == "2.5.0"

    def test_version_default(self):
        """Test version property default when no instance or metadata."""
        loaded = LoadedPlugin(plugin_class=MockPlugin)
        assert loaded.version == "0.0.0"

    def test_plugin_type_from_instance(self):
        """Test plugin_type property from instance."""
        instance = MockPlugin()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        assert loaded.plugin_type == PluginType.DETECTOR

    def test_plugin_type_from_metadata(self):
        """Test plugin_type property from metadata."""
        metadata = PluginMetadata(
            name="Test",
            version="1.0.0",
            plugin_type=PluginType.REPORTER,
        )
        loaded = LoadedPlugin(plugin_class=MockPlugin, metadata=metadata)
        assert loaded.plugin_type == PluginType.REPORTER

    def test_plugin_type_none_when_no_data(self):
        """Test plugin_type returns None when no instance or metadata."""
        loaded = LoadedPlugin(plugin_class=MockPlugin)
        assert loaded.plugin_type is None


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""

    def test_default_values(self):
        """Test default values."""
        result = DiscoveryResult()
        assert result.plugins == []
        assert result.errors == []
        assert result.sources_searched == []

    def test_success_count_all_successful(self):
        """Test success_count with all successful plugins."""
        plugins = [
            LoadedPlugin(plugin_class=MockPlugin),
            LoadedPlugin(plugin_class=MockPlugin),
        ]
        result = DiscoveryResult(plugins=plugins)
        assert result.success_count == 2

    def test_success_count_with_errors(self):
        """Test success_count with some errors."""
        plugins = [
            LoadedPlugin(plugin_class=MockPlugin),
            LoadedPlugin(plugin_class=MockPlugin, load_error="Failed to load"),
        ]
        result = DiscoveryResult(plugins=plugins)
        assert result.success_count == 1

    def test_error_count(self):
        """Test error_count property."""
        plugins = [
            LoadedPlugin(plugin_class=MockPlugin),
            LoadedPlugin(plugin_class=MockPlugin, load_error="Error 1"),
            LoadedPlugin(plugin_class=MockPlugin, load_error="Error 2"),
        ]
        result = DiscoveryResult(plugins=plugins)
        assert result.error_count == 2

    def test_error_count_none(self):
        """Test error_count with no errors."""
        plugins = [LoadedPlugin(plugin_class=MockPlugin)]
        result = DiscoveryResult(plugins=plugins)
        assert result.error_count == 0


class TestPluginLoaderInit:
    """Tests for PluginLoader initialization."""

    def test_default_init(self):
        """Test default initialization."""
        loader = PluginLoader()
        assert len(loader.plugin_dirs) == 2
        assert loader._loaded_plugins == {}
        assert loader._discovered_sources == set()

    def test_custom_plugin_dirs(self):
        """Test with custom plugin directories."""
        custom_dirs = [Path("/custom/plugins")]
        loader = PluginLoader(plugin_dirs=custom_dirs)
        assert loader.plugin_dirs == custom_dirs

    def test_auto_discover_false(self):
        """Test auto_discover=False doesn't discover."""
        loader = PluginLoader(auto_discover=False)
        assert loader._loaded_plugins == {}

    @patch.object(PluginLoader, "discover_all")
    def test_auto_discover_true(self, mock_discover):
        """Test auto_discover=True calls discover_all."""
        mock_discover.return_value = DiscoveryResult()
        loader = PluginLoader(auto_discover=True)
        mock_discover.assert_called_once()


class TestDiscoverFromDirectory:
    """Tests for discover_from_directory method."""

    def test_nonexistent_directory(self):
        """Test with non-existent directory."""
        loader = PluginLoader()
        result = loader.discover_from_directory("/nonexistent/path")
        assert len(result.errors) == 1
        assert "Directory not found" in result.errors[0]

    def test_empty_directory(self):
        """Test with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = PluginLoader()
            result = loader.discover_from_directory(tmpdir)
            assert result.plugins == []
            assert str(tmpdir) in result.sources_searched[0]

    def test_skips_underscore_files(self):
        """Test that files starting with _ are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file starting with underscore
            init_file = Path(tmpdir) / "__init__.py"
            init_file.write_text("# init")

            loader = PluginLoader()
            result = loader.discover_from_directory(tmpdir)
            assert result.plugins == []

    def test_recursive_search(self):
        """Test recursive directory search."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create subdirectory with a file
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "test.py").write_text("x = 1")

            loader = PluginLoader()
            result = loader.discover_from_directory(tmpdir, recursive=True)
            # No plugins, but no errors either for non-plugin files
            assert str(tmpdir) in result.sources_searched[0]

    def test_non_recursive_search(self):
        """Test non-recursive directory search."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create subdirectory with a file
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "test.py").write_text("x = 1")

            # Create file in root
            (Path(tmpdir) / "root.py").write_text("y = 2")

            loader = PluginLoader()
            result = loader.discover_from_directory(tmpdir, recursive=False)
            # Should only check root files, not subdirectory
            assert str(tmpdir) in result.sources_searched[0]


class TestDiscoverFromEntryPoints:
    """Tests for discover_from_entry_points method."""

    def test_no_entry_points(self):
        """Test with no entry points registered."""
        loader = PluginLoader()
        with patch("importlib.metadata.entry_points") as mock_eps:
            # Simulate no entry points
            if sys.version_info >= (3, 10):
                mock_eps.return_value = []
            else:
                mock_eps.return_value = {}
            result = loader.discover_from_entry_points()
            assert f"entry_points:{ENTRY_POINT_GROUP}" in result.sources_searched

    @patch("importlib.metadata.entry_points")
    def test_entry_point_load_error(self, mock_eps):
        """Test handling entry point load errors."""
        mock_ep = MagicMock()
        mock_ep.name = "bad_plugin"
        mock_ep.load.side_effect = Exception("Load failed")

        if sys.version_info >= (3, 10):
            mock_eps.return_value = [mock_ep]
        else:
            mock_eps.return_value = {ENTRY_POINT_GROUP: [mock_ep]}

        loader = PluginLoader()
        result = loader.discover_from_entry_points()
        assert len(result.errors) >= 1


class TestLoadPluginFile:
    """Tests for load_plugin_file method."""

    def test_nonexistent_file(self):
        """Test loading non-existent file."""
        loader = PluginLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_plugin_file("/nonexistent/file.py")

    def test_invalid_python_file(self):
        """Test loading invalid Python file."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"this is not valid python !!!")
            f.flush()

            loader = PluginLoader()
            with pytest.raises(ImportError):
                loader.load_plugin_file(f.name)

    def test_file_without_plugins(self):
        """Test loading file with no plugin classes."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1\ny = 2\n")
            f.flush()

            loader = PluginLoader()
            result = loader.load_plugin_file(f.name)
            assert result == []


class TestLoadPluginPackage:
    """Tests for load_plugin_package method."""

    def test_nonexistent_package(self):
        """Test loading non-existent package."""
        loader = PluginLoader()
        with pytest.raises(ImportError):
            loader.load_plugin_package("nonexistent_package_12345")

    def test_package_without_plugins(self):
        """Test loading package with no plugin classes."""
        loader = PluginLoader()
        # json is a standard library module with no plugins
        result = loader.load_plugin_package("json")
        assert result == []


class TestLoadAndInitialize:
    """Tests for load_and_initialize method."""

    @pytest.fixture
    def context(self, tmp_path):
        """Create plugin context with all required fields."""
        return PluginContext(
            miesc_version="5.0.0",
            config={},
            data_dir=tmp_path / "data",
            cache_dir=tmp_path / "cache",
        )

    def test_already_initialized(self, context):
        """Test with already initialized plugin."""
        instance = MockPlugin()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)

        loader = PluginLoader()

        result = loader.load_and_initialize(loaded, context)
        assert result is instance

    def test_initialize_new_plugin(self, context):
        """Test initializing new plugin."""
        loaded = LoadedPlugin(plugin_class=MockPlugin)

        loader = PluginLoader()

        result = loader.load_and_initialize(loaded, context)
        assert isinstance(result, MockPlugin)
        assert loaded.instance is result
        assert loaded.metadata is not None

    def test_initialize_error(self, context):
        """Test handling initialization error."""

        class BadPlugin(MIESCPlugin):
            @property
            def name(self) -> str:
                return "BadPlugin"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def plugin_type(self) -> PluginType:
                return PluginType.DETECTOR

            def initialize(self, context: PluginContext) -> None:
                raise RuntimeError("Init failed")

            def execute(self, contract_code: str, **kwargs):
                return []

        loaded = LoadedPlugin(plugin_class=BadPlugin)
        loader = PluginLoader()

        with pytest.raises(RuntimeError):
            loader.load_and_initialize(loaded, context)

        assert loaded.load_error == "Init failed"


class TestValidatePlugin:
    """Tests for validate_plugin method."""

    def test_valid_plugin(self):
        """Test validating a valid plugin."""
        loader = PluginLoader()
        errors = loader.validate_plugin(MockPlugin)
        assert errors == []

    def test_invalid_plugin_class(self):
        """Test validating non-plugin class."""
        loader = PluginLoader()

        class NotAPlugin:
            pass

        errors = loader.validate_plugin(NotAPlugin)
        assert "Not a valid plugin class" in errors

    def test_plugin_cannot_instantiate(self):
        """Test plugin that cannot be instantiated."""
        loader = PluginLoader()

        class BadConstructor(MIESCPlugin):
            def __init__(self):
                raise RuntimeError("No!")

            @property
            def name(self) -> str:
                return "Bad"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def plugin_type(self) -> PluginType:
                return PluginType.DETECTOR

            def initialize(self, context):
                pass

            def execute(self, contract_code, **kwargs):
                return []

        errors = loader.validate_plugin(BadConstructor)
        assert any("Cannot instantiate" in e for e in errors)

    def test_plugin_invalid_name(self):
        """Test plugin with invalid name."""
        loader = PluginLoader()

        class BadName(MIESCPlugin):
            @property
            def name(self) -> str:
                return ""  # Empty name

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def plugin_type(self) -> PluginType:
                return PluginType.DETECTOR

            def initialize(self, context):
                pass

            def execute(self, contract_code, **kwargs):
                return []

        errors = loader.validate_plugin(BadName)
        assert any("Invalid plugin name" in e for e in errors)

    def test_plugin_invalid_version(self):
        """Test plugin with invalid version."""
        loader = PluginLoader()

        class BadVersion(MIESCPlugin):
            @property
            def name(self) -> str:
                return "BadVersion"

            @property
            def version(self) -> str:
                return ""  # Empty version

            @property
            def plugin_type(self) -> PluginType:
                return PluginType.DETECTOR

            def initialize(self, context):
                pass

            def execute(self, contract_code, **kwargs):
                return []

        errors = loader.validate_plugin(BadVersion)
        assert any("Invalid plugin version" in e for e in errors)


class TestVersionCompatible:
    """Tests for _version_compatible method."""

    @pytest.fixture
    def loader(self):
        return PluginLoader()

    def test_compatible_equal_version(self, loader):
        """Test equal versions are compatible."""
        assert loader._version_compatible("5.0.0", "5.0.0") is True

    def test_compatible_higher_version(self, loader):
        """Test higher version is compatible."""
        assert loader._version_compatible("5.1.0", "5.0.0") is True

    def test_incompatible_lower_version(self, loader):
        """Test lower version is incompatible."""
        assert loader._version_compatible("4.9.0", "5.0.0") is False

    def test_compatible_with_max_version(self, loader):
        """Test compatibility with max version."""
        assert loader._version_compatible("5.5.0", "5.0.0", "6.0.0") is True

    def test_incompatible_above_max(self, loader):
        """Test incompatibility above max version."""
        assert loader._version_compatible("6.1.0", "5.0.0", "6.0.0") is False

    def test_version_padding(self, loader):
        """Test version with fewer parts."""
        assert loader._version_compatible("5", "5.0.0") is True
        assert loader._version_compatible("5.0", "5.0.0") is True

    def test_invalid_version_format(self, loader):
        """Test invalid version format returns True."""
        # Invalid format should assume compatible
        assert loader._version_compatible("invalid", "5.0.0") is True


class TestUnloadPlugin:
    """Tests for unload_plugin method."""

    def test_unload_nonexistent(self):
        """Test unloading non-existent plugin."""
        loader = PluginLoader()
        result = loader.unload_plugin("nonexistent")
        assert result is False

    def test_unload_existing_plugin(self):
        """Test unloading existing plugin."""
        loader = PluginLoader()

        # Add a plugin
        instance = MockPlugin()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        loader._loaded_plugins["MockPlugin"] = loaded

        result = loader.unload_plugin("MockPlugin")
        assert result is True
        assert "MockPlugin" not in loader._loaded_plugins

    def test_unload_calls_cleanup(self):
        """Test that unload calls cleanup on instance."""
        loader = PluginLoader()

        # Create mock instance
        instance = MagicMock()
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        loader._loaded_plugins["test"] = loaded

        loader.unload_plugin("test")
        instance.cleanup.assert_called_once()

    def test_unload_handles_cleanup_error(self):
        """Test unload handles cleanup errors gracefully."""
        loader = PluginLoader()

        # Create mock instance with failing cleanup
        instance = MagicMock()
        instance.cleanup.side_effect = RuntimeError("Cleanup failed")
        loaded = LoadedPlugin(plugin_class=MockPlugin, instance=instance)
        loader._loaded_plugins["test"] = loaded

        # Should not raise
        result = loader.unload_plugin("test")
        assert result is True


class TestGetLoadedPlugins:
    """Tests for get_loaded_plugins method."""

    def test_empty(self):
        """Test with no loaded plugins."""
        loader = PluginLoader()
        result = loader.get_loaded_plugins()
        assert result == {}

    def test_with_plugins(self):
        """Test with loaded plugins."""
        loader = PluginLoader()

        loaded1 = LoadedPlugin(plugin_class=MockPlugin)
        loaded2 = LoadedPlugin(plugin_class=MockPlugin)
        loader._loaded_plugins["plugin1"] = loaded1
        loader._loaded_plugins["plugin2"] = loaded2

        result = loader.get_loaded_plugins()
        assert len(result) == 2
        assert "plugin1" in result
        assert "plugin2" in result

    def test_returns_copy(self):
        """Test that returned dict is a copy."""
        loader = PluginLoader()
        loaded = LoadedPlugin(plugin_class=MockPlugin)
        loader._loaded_plugins["test"] = loaded

        result = loader.get_loaded_plugins()
        result["new"] = LoadedPlugin(plugin_class=MockPlugin)

        # Original should not be modified
        assert "new" not in loader._loaded_plugins


class TestDiscoverAll:
    """Tests for discover_all method."""

    def test_discover_all_empty(self):
        """Test discover_all with no plugins found."""
        loader = PluginLoader(plugin_dirs=[])
        with patch.object(loader, "discover_from_entry_points") as mock_ep:
            mock_ep.return_value = DiscoveryResult()
            result = loader.discover_all()
            assert result.success_count == 0

    def test_discover_all_combines_results(self):
        """Test discover_all combines results from all sources."""
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = PluginLoader(plugin_dirs=[Path(tmpdir)])

            with patch.object(loader, "discover_from_entry_points") as mock_ep:
                mock_ep.return_value = DiscoveryResult(
                    sources_searched=["entry_points:test"]
                )

                result = loader.discover_all()
                assert str(tmpdir) in result.sources_searched[0]
                assert "entry_points:test" in result.sources_searched
