"""
Tests for src/plugins/registry.py

Comprehensive tests for plugin registry including:
- PluginEntry dataclass
- PluginRegistry class
- Global registry functions
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.plugins.protocol import PluginMetadata, PluginState, PluginType
from src.plugins.registry import (
    PluginEntry,
    PluginRegistry,
    get_registry,
    set_registry,
)


class MockPlugin:
    """Mock plugin for testing."""

    def __init__(
        self,
        name: str = "test-plugin",
        version: str = "1.0.0",
        plugin_type: PluginType = PluginType.DETECTOR,
    ):
        self.name = name
        self.version = version
        self.plugin_type = plugin_type
        self.state = PluginState.INITIALIZED
        self._config = {}

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            version=self.version,
            plugin_type=self.plugin_type,
            description="Test plugin",
            author="Test",
            tags=["test", "mock"],
        )

    def configure(self, config: dict) -> None:
        self._config = config

    def enable(self) -> None:
        self.state = PluginState.ENABLED

    def disable(self) -> None:
        self.state = PluginState.DISABLED

    def cleanup(self) -> None:
        self.state = PluginState.UNLOADED


class TestPluginEntry:
    """Tests for PluginEntry dataclass."""

    def test_minimal_construction(self):
        """Test creating PluginEntry with required fields."""
        entry = PluginEntry(
            name="test-plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
        )
        assert entry.name == "test-plugin"
        assert entry.version == "1.0.0"
        assert entry.plugin_type == PluginType.DETECTOR
        assert entry.enabled is True
        assert entry.source == ""
        assert entry.config == {}

    def test_full_construction(self):
        """Test creating PluginEntry with all fields."""
        now = datetime.now()
        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.ADAPTER,
            description="Test",
            author="Author",
        )
        entry = PluginEntry(
            name="test-plugin",
            version="2.0.0",
            plugin_type=PluginType.ADAPTER,
            enabled=False,
            source="/path/to/plugin",
            installed_at=now,
            last_used=now,
            config={"key": "value"},
            metadata=metadata,
        )
        assert entry.version == "2.0.0"
        assert entry.enabled is False
        assert entry.source == "/path/to/plugin"
        assert entry.config["key"] == "value"

    def test_instance_property(self):
        """Test instance property."""
        entry = PluginEntry(
            name="test",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
        )
        assert entry.instance is None

        mock_plugin = MockPlugin()
        entry.instance = mock_plugin
        assert entry.instance == mock_plugin

    def test_to_dict(self):
        """Test to_dict method."""
        entry = PluginEntry(
            name="test-plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            enabled=True,
            config={"option": True},
        )
        d = entry.to_dict()
        assert d["name"] == "test-plugin"
        assert d["version"] == "1.0.0"
        assert d["plugin_type"] == "detector"
        assert d["enabled"] is True
        assert "installed_at" in d
        assert d["config"]["option"] is True

    def test_from_dict(self):
        """Test from_dict class method."""
        data = {
            "name": "restored-plugin",
            "version": "1.2.3",
            "plugin_type": "adapter",
            "enabled": False,
            "source": "/some/path",
            "installed_at": "2024-01-15T10:30:00",
            "config": {"debug": True},
        }
        entry = PluginEntry.from_dict(data)
        assert entry.name == "restored-plugin"
        assert entry.version == "1.2.3"
        assert entry.plugin_type == PluginType.ADAPTER
        assert entry.enabled is False
        assert entry.config["debug"] is True

    def test_from_dict_with_metadata(self):
        """Test from_dict with metadata."""
        data = {
            "name": "plugin",
            "version": "1.0.0",
            "plugin_type": "detector",
            "metadata": {
                "name": "plugin",
                "version": "1.0.0",
                "plugin_type": "detector",
                "description": "A plugin",
                "author": "Author",
                "tags": ["security"],
            },
        }
        entry = PluginEntry.from_dict(data)
        assert entry.metadata is not None
        assert entry.metadata.description == "A plugin"


class TestPluginRegistryInit:
    """Tests for PluginRegistry initialization."""

    def test_default_init(self, tmp_path):
        """Test default initialization."""
        registry = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        assert len(registry) == 0
        assert registry.context is None

    def test_init_with_auto_load(self, tmp_path):
        """Test initialization with auto_load but no file."""
        registry = PluginRegistry(registry_path=tmp_path / "nonexistent.json", auto_load=True)
        assert len(registry) == 0

    def test_init_loads_existing_registry(self, tmp_path):
        """Test initialization loads existing registry file."""
        registry_file = tmp_path / "registry.json"
        data = {
            "version": "1.0",
            "plugins": {
                "existing": {
                    "name": "existing",
                    "version": "1.0.0",
                    "plugin_type": "detector",
                    "enabled": True,
                }
            },
        }
        with open(registry_file, "w") as f:
            json.dump(data, f)

        registry = PluginRegistry(registry_path=registry_file, auto_load=True)
        assert "existing" in registry
        assert len(registry) == 1


class TestPluginRegistryRegister:
    """Tests for PluginRegistry.register method."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry instance."""
        return PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)

    def test_register_plugin(self, registry):
        """Test registering a plugin."""
        plugin = MockPlugin(name="my-detector")
        entry = registry.register(plugin)

        assert entry.name == "my-detector"
        assert entry.version == "1.0.0"
        assert "my-detector" in registry
        assert len(registry) == 1

    def test_register_with_config(self, registry):
        """Test registering with configuration."""
        plugin = MockPlugin()
        config = {"threshold": 0.5}
        entry = registry.register(plugin, config=config)

        assert entry.config["threshold"] == 0.5
        assert plugin._config["threshold"] == 0.5

    def test_register_disabled(self, registry):
        """Test registering disabled plugin."""
        plugin = MockPlugin()
        entry = registry.register(plugin, enabled=False)

        assert entry.enabled is False

    def test_register_duplicate(self, registry):
        """Test registering duplicate plugin."""
        plugin1 = MockPlugin(name="test")
        plugin2 = MockPlugin(name="test")

        entry1 = registry.register(plugin1)
        entry2 = registry.register(plugin2)

        # Should return existing entry
        assert entry1 == entry2
        assert len(registry) == 1

    def test_register_update_version(self, registry):
        """Test registering plugin with new version."""
        plugin1 = MockPlugin(name="test", version="1.0.0")
        plugin2 = MockPlugin(name="test", version="2.0.0")

        registry.register(plugin1)
        entry = registry.register(plugin2)

        assert entry.version == "2.0.0"


class TestPluginRegistryUnregister:
    """Tests for PluginRegistry.unregister method."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with plugin."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        plugin = MockPlugin(name="test-plugin")
        reg.register(plugin)
        return reg

    def test_unregister_existing(self, registry):
        """Test unregistering existing plugin."""
        assert "test-plugin" in registry
        result = registry.unregister("test-plugin")

        assert result is True
        assert "test-plugin" not in registry
        assert len(registry) == 0

    def test_unregister_nonexistent(self, registry):
        """Test unregistering nonexistent plugin."""
        result = registry.unregister("nonexistent")
        assert result is False

    def test_unregister_calls_cleanup(self, registry):
        """Test unregister calls plugin cleanup."""
        entry = registry.get_entry("test-plugin")
        plugin = entry.instance

        registry.unregister("test-plugin")
        assert plugin.state == PluginState.UNLOADED


class TestPluginRegistryGet:
    """Tests for PluginRegistry.get and get_entry methods."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with plugins."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="enabled-plugin"))
        reg.register(MockPlugin(name="disabled-plugin"), enabled=False)
        return reg

    def test_get_enabled_plugin(self, registry):
        """Test getting enabled plugin."""
        plugin = registry.get("enabled-plugin")
        assert plugin is not None
        assert plugin.name == "enabled-plugin"

    def test_get_disabled_plugin(self, registry):
        """Test getting disabled plugin returns None."""
        plugin = registry.get("disabled-plugin")
        assert plugin is None

    def test_get_nonexistent(self, registry):
        """Test getting nonexistent plugin."""
        plugin = registry.get("nonexistent")
        assert plugin is None

    def test_get_entry(self, registry):
        """Test get_entry method."""
        entry = registry.get_entry("enabled-plugin")
        assert entry is not None
        assert entry.name == "enabled-plugin"

    def test_get_entry_disabled(self, registry):
        """Test get_entry works for disabled plugins."""
        entry = registry.get_entry("disabled-plugin")
        assert entry is not None
        assert entry.enabled is False


class TestPluginRegistryEnableDisable:
    """Tests for PluginRegistry enable/disable methods."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with plugin."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="test"), enabled=False)
        return reg

    def test_enable_plugin(self, registry):
        """Test enabling a plugin."""
        assert registry.get_entry("test").enabled is False

        result = registry.enable("test")

        assert result is True
        assert registry.get_entry("test").enabled is True

    def test_enable_already_enabled(self, registry):
        """Test enabling already enabled plugin."""
        registry.enable("test")
        result = registry.enable("test")
        assert result is True

    def test_enable_nonexistent(self, registry):
        """Test enabling nonexistent plugin."""
        result = registry.enable("nonexistent")
        assert result is False

    def test_disable_plugin(self, registry):
        """Test disabling a plugin."""
        registry.enable("test")
        result = registry.disable("test")

        assert result is True
        assert registry.get_entry("test").enabled is False

    def test_disable_already_disabled(self, registry):
        """Test disabling already disabled plugin."""
        result = registry.disable("test")
        assert result is True

    def test_disable_nonexistent(self, registry):
        """Test disabling nonexistent plugin."""
        result = registry.disable("nonexistent")
        assert result is False


class TestPluginRegistryConfigure:
    """Tests for PluginRegistry.configure method."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with plugin."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="test"))
        return reg

    def test_configure_plugin(self, registry):
        """Test configuring a plugin."""
        config = {"option": "value"}
        result = registry.configure("test", config)

        assert result is True
        assert registry.get_entry("test").config["option"] == "value"

    def test_configure_nonexistent(self, registry):
        """Test configuring nonexistent plugin."""
        result = registry.configure("nonexistent", {"key": "val"})
        assert result is False


class TestPluginRegistryList:
    """Tests for PluginRegistry list methods."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with multiple plugins."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="detector1", plugin_type=PluginType.DETECTOR))
        reg.register(MockPlugin(name="detector2", plugin_type=PluginType.DETECTOR))
        reg.register(MockPlugin(name="adapter1", plugin_type=PluginType.ADAPTER))
        reg.register(MockPlugin(name="disabled1", plugin_type=PluginType.REPORTER), enabled=False)
        return reg

    def test_list_plugins(self, registry):
        """Test listing all plugins."""
        plugins = registry.list_plugins()
        assert len(plugins) == 4

    def test_list_by_type(self, registry):
        """Test listing by type."""
        detectors = registry.list_by_type(PluginType.DETECTOR)
        assert len(detectors) == 2
        for entry in detectors:
            assert entry.plugin_type == PluginType.DETECTOR

    def test_list_enabled(self, registry):
        """Test listing enabled plugins."""
        enabled = registry.list_enabled()
        assert len(enabled) == 3
        for entry in enabled:
            assert entry.enabled is True

    def test_list_disabled(self, registry):
        """Test listing disabled plugins."""
        disabled = registry.list_disabled()
        assert len(disabled) == 1
        assert disabled[0].name == "disabled1"


class TestPluginRegistrySearch:
    """Tests for PluginRegistry.search method."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with searchable plugins."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="security-scanner"))
        reg.register(MockPlugin(name="audit-helper"))
        reg.register(MockPlugin(name="disabled-tool"), enabled=False)
        return reg

    def test_search_by_name(self, registry):
        """Test searching by name."""
        results = registry.search("security")
        assert len(results) == 1
        assert results[0].name == "security-scanner"

    def test_search_case_insensitive(self, registry):
        """Test search is case insensitive."""
        results = registry.search("AUDIT")
        assert len(results) == 1
        assert results[0].name == "audit-helper"

    def test_search_enabled_only(self, registry):
        """Test search with enabled_only filter."""
        results = registry.search("tool", enabled_only=True)
        assert len(results) == 0  # disabled-tool should be excluded

    def test_search_with_type_filter(self, registry):
        """Test search with type filter."""
        results = registry.search("", plugin_type=PluginType.DETECTOR)
        assert all(r.plugin_type == PluginType.DETECTOR for r in results)

    def test_search_no_results(self, registry):
        """Test search with no results."""
        results = registry.search("nonexistent-xyz")
        assert len(results) == 0


class TestPluginRegistryDunder:
    """Tests for PluginRegistry dunder methods."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry with plugins."""
        reg = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        reg.register(MockPlugin(name="plugin1"))
        reg.register(MockPlugin(name="plugin2"))
        return reg

    def test_contains(self, registry):
        """Test __contains__."""
        assert "plugin1" in registry
        assert "plugin2" in registry
        assert "nonexistent" not in registry

    def test_len(self, registry):
        """Test __len__."""
        assert len(registry) == 2

    def test_iter(self, registry):
        """Test __iter__."""
        names = [entry.name for entry in registry]
        assert "plugin1" in names
        assert "plugin2" in names


class TestPluginRegistryPersistence:
    """Tests for PluginRegistry save/load methods."""

    def test_save_and_load(self, tmp_path):
        """Test saving and loading registry."""
        registry_path = tmp_path / "registry.json"

        # Create and save
        registry1 = PluginRegistry(registry_path=registry_path, auto_load=False)
        registry1.register(MockPlugin(name="saved-plugin", version="1.0.0"))
        registry1.save()

        assert registry_path.exists()

        # Load in new registry
        registry2 = PluginRegistry(registry_path=registry_path, auto_load=True)
        assert "saved-plugin" in registry2
        entry = registry2.get_entry("saved-plugin")
        assert entry.version == "1.0.0"

    def test_load_nonexistent(self, tmp_path):
        """Test loading nonexistent file doesn't error."""
        registry = PluginRegistry(
            registry_path=tmp_path / "nonexistent.json",
            auto_load=False,
        )
        registry.load()  # Should not raise
        assert len(registry) == 0

    def test_load_invalid_json(self, tmp_path):
        """Test loading invalid JSON doesn't crash."""
        registry_path = tmp_path / "invalid.json"
        with open(registry_path, "w") as f:
            f.write("invalid json {{{")

        registry = PluginRegistry(registry_path=registry_path, auto_load=False)
        registry.load()  # Should not raise
        assert len(registry) == 0

    def test_clear(self, tmp_path):
        """Test clearing registry."""
        registry = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        registry.register(MockPlugin(name="plugin1"))
        registry.register(MockPlugin(name="plugin2"))

        assert len(registry) == 2
        registry.clear()
        assert len(registry) == 0


class TestPluginRegistryHooks:
    """Tests for PluginRegistry hook system."""

    @pytest.fixture
    def registry(self, tmp_path):
        """Create registry instance."""
        return PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)

    def test_add_hook(self, registry):
        """Test adding a hook."""
        callback = MagicMock()
        registry.add_hook("on_register", callback)

        plugin = MockPlugin()
        registry.register(plugin)

        callback.assert_called_once()

    def test_remove_hook(self, registry):
        """Test removing a hook."""
        callback = MagicMock()
        registry.add_hook("on_register", callback)
        registry.remove_hook("on_register", callback)

        registry.register(MockPlugin())
        callback.assert_not_called()

    def test_hook_on_unregister(self, registry):
        """Test on_unregister hook."""
        callback = MagicMock()
        registry.add_hook("on_unregister", callback)

        registry.register(MockPlugin(name="test"))
        registry.unregister("test")

        callback.assert_called_once()

    def test_hook_on_enable(self, registry):
        """Test on_enable hook."""
        callback = MagicMock()
        registry.add_hook("on_enable", callback)

        registry.register(MockPlugin(name="test"), enabled=False)
        registry.enable("test")

        callback.assert_called_once()

    def test_hook_on_disable(self, registry):
        """Test on_disable hook."""
        callback = MagicMock()
        registry.add_hook("on_disable", callback)

        registry.register(MockPlugin(name="test"))
        registry.disable("test")

        callback.assert_called_once()

    def test_hook_error_doesnt_crash(self, registry):
        """Test hook error doesn't crash registry."""

        def bad_callback(entry):
            raise ValueError("Hook error")

        registry.add_hook("on_register", bad_callback)

        # Should not raise
        registry.register(MockPlugin())
        assert len(registry) == 1


class TestPluginRegistryStats:
    """Tests for PluginRegistry.get_stats method."""

    def test_get_stats(self, tmp_path):
        """Test getting statistics."""
        registry = PluginRegistry(registry_path=tmp_path / "registry.json", auto_load=False)
        registry.register(MockPlugin(name="d1", plugin_type=PluginType.DETECTOR))
        registry.register(MockPlugin(name="d2", plugin_type=PluginType.DETECTOR))
        registry.register(MockPlugin(name="a1", plugin_type=PluginType.ADAPTER))
        registry.register(
            MockPlugin(name="disabled", plugin_type=PluginType.REPORTER), enabled=False
        )

        stats = registry.get_stats()

        assert stats["total"] == 4
        assert stats["enabled"] == 3
        assert stats["disabled"] == 1
        assert stats["by_type"]["detector"] == 2
        assert stats["by_type"]["adapter"] == 1


class TestGlobalRegistry:
    """Tests for global registry functions."""

    def test_get_registry(self):
        """Test get_registry creates singleton."""
        # Reset global registry
        set_registry(None)

        reg1 = get_registry()
        reg2 = get_registry()

        assert reg1 is reg2

    def test_set_registry(self, tmp_path):
        """Test set_registry."""
        custom = PluginRegistry(registry_path=tmp_path / "custom.json", auto_load=False)
        set_registry(custom)

        assert get_registry() is custom

        # Reset
        set_registry(None)
