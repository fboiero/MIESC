"""Plugin configuration management.

Handles loading, saving, and managing plugin settings from ~/.miesc/plugins.yaml
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PluginConfig:
    """Configuration for a single plugin."""

    name: str
    enabled: bool = True
    version: str = ""
    package: str = ""
    settings: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {
            "enabled": self.enabled,
            "version": self.version,
            "package": self.package,
            "settings": self.settings,
        }

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "PluginConfig":
        """Create from dictionary."""
        return cls(
            name=name,
            enabled=data.get("enabled", True),
            version=data.get("version", ""),
            package=data.get("package", ""),
            settings=data.get("settings", {}),
        )


class PluginConfigManager:
    """Manages plugin configuration file (~/.miesc/plugins.yaml)."""

    DEFAULT_CONFIG_DIR = Path.home() / ".miesc"
    CONFIG_FILENAME = "plugins.yaml"

    def __init__(self, config_dir: Path | None = None):
        """Initialize config manager.

        Args:
            config_dir: Custom config directory (defaults to ~/.miesc)
        """
        self.config_dir = config_dir or self.DEFAULT_CONFIG_DIR
        self.config_file = self.config_dir / self.CONFIG_FILENAME
        self._plugins: dict[str, PluginConfig] = {}
        self._loaded = False

    def _ensure_config_dir(self) -> None:
        """Create config directory if it doesn't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, PluginConfig]:
        """Load plugins configuration from file.

        Returns:
            Dictionary of plugin name to PluginConfig
        """
        if self._loaded:
            return self._plugins

        self._plugins = {}

        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    data = yaml.safe_load(f) or {}

                plugins_data = data.get("plugins", {})
                for name, plugin_data in plugins_data.items():
                    if isinstance(plugin_data, dict):
                        self._plugins[name] = PluginConfig.from_dict(name, plugin_data)
            except (yaml.YAMLError, OSError) as e:
                # Log error but continue with empty config
                print(f"Warning: Failed to load plugin config: {e}")

        self._loaded = True
        return self._plugins

    def save(self) -> None:
        """Save current configuration to file."""
        self._ensure_config_dir()

        data = {
            "plugins": {
                name: config.to_dict() for name, config in self._plugins.items()
            }
        }

        with open(self.config_file, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=True)

    def get_plugin_config(self, name: str) -> PluginConfig | None:
        """Get configuration for a specific plugin.

        Args:
            name: Plugin name

        Returns:
            PluginConfig or None if not found
        """
        self.load()
        return self._plugins.get(name)

    def set_plugin_config(self, config: PluginConfig) -> None:
        """Set configuration for a plugin.

        Args:
            config: Plugin configuration to save
        """
        self.load()
        self._plugins[config.name] = config
        self.save()

    def is_enabled(self, name: str) -> bool:
        """Check if a plugin is enabled.

        Args:
            name: Plugin name

        Returns:
            True if enabled (default True if not configured)
        """
        self.load()
        config = self._plugins.get(name)
        return config.enabled if config else True

    def enable_plugin(self, name: str, package: str = "", version: str = "") -> None:
        """Enable a plugin.

        Args:
            name: Plugin name
            package: Package name (optional)
            version: Version string (optional)
        """
        self.load()
        if name in self._plugins:
            self._plugins[name].enabled = True
            if package:
                self._plugins[name].package = package
            if version:
                self._plugins[name].version = version
        else:
            self._plugins[name] = PluginConfig(
                name=name, enabled=True, package=package, version=version
            )
        self.save()

    def disable_plugin(self, name: str) -> None:
        """Disable a plugin.

        Args:
            name: Plugin name
        """
        self.load()
        if name in self._plugins:
            self._plugins[name].enabled = False
        else:
            self._plugins[name] = PluginConfig(name=name, enabled=False)
        self.save()

    def remove_plugin(self, name: str) -> bool:
        """Remove a plugin from configuration.

        Args:
            name: Plugin name

        Returns:
            True if removed, False if not found
        """
        self.load()
        if name in self._plugins:
            del self._plugins[name]
            self.save()
            return True
        return False

    def list_plugins(self) -> list[PluginConfig]:
        """List all configured plugins.

        Returns:
            List of PluginConfig objects
        """
        self.load()
        return list(self._plugins.values())
