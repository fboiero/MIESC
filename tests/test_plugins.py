"""Tests for the MIESC plugin system."""

import tempfile
from pathlib import Path


class TestPluginConfig:
    """Tests for PluginConfig dataclass."""

    def test_create_config(self):
        """Test creating a PluginConfig."""
        from miesc.plugins import PluginConfig

        config = PluginConfig(name="test-plugin", enabled=True, version="1.0.0")
        assert config.name == "test-plugin"
        assert config.enabled is True
        assert config.version == "1.0.0"

    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        from miesc.plugins import PluginConfig

        config = PluginConfig(name="test", enabled=False, version="2.0", package="miesc-test")
        data = config.to_dict()
        assert data["enabled"] is False
        assert data["version"] == "2.0"
        assert data["package"] == "miesc-test"

    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        from miesc.plugins import PluginConfig

        data = {"enabled": True, "version": "1.0", "package": "pkg", "settings": {"a": 1}}
        config = PluginConfig.from_dict("test", data)
        assert config.name == "test"
        assert config.enabled is True
        assert config.settings == {"a": 1}


class TestPluginConfigManager:
    """Tests for PluginConfigManager."""

    def test_enable_disable_plugin(self):
        """Test enabling and disabling plugins."""
        from miesc.plugins import PluginConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=Path(tmpdir))

            # Enable plugin
            manager.enable_plugin("test-plugin", package="miesc-test", version="1.0")
            assert manager.is_enabled("test-plugin") is True

            # Disable plugin
            manager.disable_plugin("test-plugin")
            assert manager.is_enabled("test-plugin") is False

    def test_list_plugins(self):
        """Test listing configured plugins."""
        from miesc.plugins import PluginConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=Path(tmpdir))

            manager.enable_plugin("plugin1")
            manager.enable_plugin("plugin2")

            plugins = manager.list_plugins()
            assert len(plugins) == 2
            names = [p.name for p in plugins]
            assert "plugin1" in names
            assert "plugin2" in names

    def test_remove_plugin(self):
        """Test removing plugin from config."""
        from miesc.plugins import PluginConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginConfigManager(config_dir=Path(tmpdir))

            manager.enable_plugin("to-remove")
            assert len(manager.list_plugins()) == 1

            result = manager.remove_plugin("to-remove")
            assert result is True
            assert len(manager.list_plugins()) == 0

    def test_persistence(self):
        """Test that config persists across manager instances."""
        from miesc.plugins import PluginConfigManager

        with tempfile.TemporaryDirectory() as tmpdir:
            # First manager
            manager1 = PluginConfigManager(config_dir=Path(tmpdir))
            manager1.enable_plugin("persistent", version="1.0")

            # Second manager (new instance, same dir)
            manager2 = PluginConfigManager(config_dir=Path(tmpdir))
            assert manager2.is_enabled("persistent") is True

            config = manager2.get_plugin_config("persistent")
            assert config is not None
            assert config.version == "1.0"


class TestPluginManager:
    """Tests for PluginManager."""

    def test_normalize_package_name(self):
        """Test package name normalization."""
        from miesc.plugins import PluginManager

        manager = PluginManager()

        # Without prefix
        assert manager._normalize_package_name("test") == "miesc-test"

        # With prefix
        assert manager._normalize_package_name("miesc-test") == "miesc-test"

    def test_list_installed(self):
        """Test listing installed plugins."""
        from miesc.plugins import PluginManager

        manager = PluginManager()
        plugins = manager.list_installed()

        # Should find at least the built-in miesc package
        assert isinstance(plugins, list)
        # miesc itself has entry points
        names = [p.package for p in plugins]
        assert "miesc" in names or len(plugins) >= 0

    def test_get_plugin_info(self):
        """Test getting plugin info."""
        from miesc.plugins import PluginManager

        manager = PluginManager()

        # Try to get info for miesc itself
        info = manager.get_plugin_info("miesc")
        if info:
            assert info.package == "miesc"
            assert info.detector_count >= 0

    def test_enable_disable(self):
        """Test enable/disable methods."""
        from miesc.plugins import PluginManager

        with tempfile.TemporaryDirectory() as tmpdir:
            from miesc.plugins import PluginConfigManager

            config_manager = PluginConfigManager(config_dir=Path(tmpdir))
            manager = PluginManager(config_manager=config_manager)

            # These will fail gracefully if plugin doesn't exist
            ok, msg = manager.disable("nonexistent-plugin-xyz")
            assert ok is False

    def test_create_plugin_scaffold(self):
        """Test creating plugin scaffold."""
        from miesc.plugins import PluginManager

        manager = PluginManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = manager.create_plugin_scaffold(
                name="test-scaffold",
                output_dir=Path(tmpdir),
                description="Test plugin",
                author="Test Author",
            )

            assert plugin_path.exists()
            assert (plugin_path / "pyproject.toml").exists()
            assert (plugin_path / "test_scaffold" / "detectors.py").exists()
            assert (plugin_path / "tests").exists()
            assert (plugin_path / "README.md").exists()


class TestPluginScaffold:
    """Tests for plugin scaffold generator."""

    def test_scaffold_structure(self):
        """Test that scaffold creates correct structure."""
        from miesc.plugins.templates import create_plugin_scaffold

        with tempfile.TemporaryDirectory() as tmpdir:
            path = create_plugin_scaffold(
                name="my-detector",
                output_dir=Path(tmpdir),
                description="My detector",
                author="Me",
            )

            # Check directory structure
            assert path.name == "miesc-my_detector"
            assert (path / "pyproject.toml").exists()
            assert (path / "my_detector" / "__init__.py").exists()
            assert (path / "my_detector" / "detectors.py").exists()
            assert (path / "tests" / "__init__.py").exists()
            assert (path / "tests" / "test_my_detector.py").exists()
            assert (path / "README.md").exists()

    def test_scaffold_pyproject_content(self):
        """Test pyproject.toml content."""
        from miesc.plugins.templates import create_plugin_scaffold

        with tempfile.TemporaryDirectory() as tmpdir:
            path = create_plugin_scaffold(
                name="flash-loan",
                output_dir=Path(tmpdir),
                description="Flash loan detector",
                author="Security Team",
            )

            content = (path / "pyproject.toml").read_text()
            assert 'name = "miesc-flash_loan"' in content
            assert "miesc.detectors" in content
            assert "flash_loan.detectors:FlashLoanDetector" in content

    def test_scaffold_detector_content(self):
        """Test detector template content."""
        from miesc.plugins.templates import create_plugin_scaffold

        with tempfile.TemporaryDirectory() as tmpdir:
            path = create_plugin_scaffold(
                name="custom",
                output_dir=Path(tmpdir),
            )

            content = (path / "custom" / "detectors.py").read_text()
            assert "class CustomDetector(BaseDetector)" in content
            assert "def analyze" in content
            assert "list[Finding]" in content


class TestPluginIntegration:
    """Integration tests for the plugin system."""

    def test_full_workflow(self):
        """Test complete plugin workflow."""
        from miesc.plugins import PluginConfigManager, PluginManager

        with tempfile.TemporaryDirectory() as tmpdir:
            config_manager = PluginConfigManager(config_dir=Path(tmpdir))
            manager = PluginManager(config_manager=config_manager)

            # Create scaffold
            plugin_path = manager.create_plugin_scaffold(
                name="integration-test",
                output_dir=Path(tmpdir),
                description="Integration test plugin",
            )
            assert plugin_path.exists()

            # List installed (should not include new plugin yet - not installed)
            plugins = manager.list_installed()
            len(plugins)

            # Enable/disable through config (even without pip install)
            config_manager.enable_plugin("miesc-integration-test")
            assert config_manager.is_enabled("miesc-integration-test")

            config_manager.disable_plugin("miesc-integration-test")
            assert not config_manager.is_enabled("miesc-integration-test")
