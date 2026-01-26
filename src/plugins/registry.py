"""
Plugin Registry - Local Plugin Management
==========================================

Manages installed plugins, their metadata, versions, and state.

Features:
- Register/unregister plugins
- Enable/disable plugins
- Query plugins by type, name, or tags
- Persist plugin state to disk
- Version management

Usage:
    registry = PluginRegistry()

    # Register a plugin
    registry.register(my_plugin)

    # Get a plugin
    detector = registry.get("my-detector")

    # List plugins
    detectors = registry.list_by_type(PluginType.DETECTOR)

    # Enable/disable
    registry.disable("my-detector")
    registry.enable("my-detector")

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Union

from .protocol import (
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginState,
    PluginType,
)
from .loader import LoadedPlugin, PluginLoader

logger = logging.getLogger(__name__)


# Default registry storage path
DEFAULT_REGISTRY_PATH = Path.home() / ".miesc" / "plugin_registry.json"


@dataclass
class PluginEntry:
    """Registry entry for a plugin."""
    name: str
    version: str
    plugin_type: PluginType
    enabled: bool = True
    source: str = ""
    installed_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Optional[PluginMetadata] = None

    # Runtime state (not persisted)
    _instance: Optional[MIESCPlugin] = field(default=None, repr=False)
    _loaded_plugin: Optional[LoadedPlugin] = field(default=None, repr=False)

    @property
    def instance(self) -> Optional[MIESCPlugin]:
        """Get plugin instance."""
        return self._instance

    @instance.setter
    def instance(self, value: MIESCPlugin) -> None:
        """Set plugin instance."""
        self._instance = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for persistence."""
        return {
            "name": self.name,
            "version": self.version,
            "plugin_type": self.plugin_type.value,
            "enabled": self.enabled,
            "source": self.source,
            "installed_at": self.installed_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "config": self.config,
            "metadata": self.metadata.to_dict() if self.metadata else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginEntry":
        """Create from dictionary."""
        plugin_type = data.get("plugin_type", "detector")
        if isinstance(plugin_type, str):
            plugin_type = PluginType(plugin_type)

        metadata = None
        if data.get("metadata"):
            metadata = PluginMetadata.from_dict(data["metadata"])

        return cls(
            name=data["name"],
            version=data["version"],
            plugin_type=plugin_type,
            enabled=data.get("enabled", True),
            source=data.get("source", ""),
            installed_at=datetime.fromisoformat(data["installed_at"])
                if data.get("installed_at") else datetime.now(),
            last_used=datetime.fromisoformat(data["last_used"])
                if data.get("last_used") else None,
            config=data.get("config", {}),
            metadata=metadata,
        )


class PluginRegistry:
    """
    Manages registered MIESC plugins.

    Provides:
    - Plugin registration and lookup
    - Enable/disable functionality
    - Persistence to disk
    - Query by type, tags, etc.
    """

    def __init__(
        self,
        registry_path: Optional[Path] = None,
        auto_load: bool = True,
        context: Optional[PluginContext] = None,
    ):
        """
        Initialize the plugin registry.

        Args:
            registry_path: Path to persist registry state
            auto_load: Load existing registry on init
            context: Plugin context for initialization
        """
        self.registry_path = registry_path or DEFAULT_REGISTRY_PATH
        self.context = context
        self._plugins: Dict[str, PluginEntry] = {}
        self._hooks: Dict[str, List[Callable]] = {
            "on_register": [],
            "on_unregister": [],
            "on_enable": [],
            "on_disable": [],
        }

        if auto_load and self.registry_path.exists():
            self.load()

    def register(
        self,
        plugin: Union[MIESCPlugin, LoadedPlugin],
        config: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> PluginEntry:
        """
        Register a plugin.

        Args:
            plugin: Plugin instance or LoadedPlugin
            config: Plugin configuration
            enabled: Whether to enable immediately

        Returns:
            PluginEntry for the registered plugin
        """
        # Handle LoadedPlugin
        if isinstance(plugin, LoadedPlugin):
            if plugin.instance is None:
                raise ValueError("LoadedPlugin has no instance")
            instance = plugin.instance
            source = plugin.source
        else:
            instance = plugin
            source = ""

        name = instance.name

        # Check for duplicates
        if name in self._plugins:
            existing = self._plugins[name]
            if existing.version == instance.version:
                logger.warning(f"Plugin {name} already registered")
                return existing
            else:
                logger.info(f"Updating plugin {name}: {existing.version} -> {instance.version}")

        # Create entry
        entry = PluginEntry(
            name=name,
            version=instance.version,
            plugin_type=instance.plugin_type,
            enabled=enabled,
            source=source,
            metadata=instance.get_metadata(),
            config=config or {},
        )
        entry._instance = instance
        if isinstance(plugin, LoadedPlugin):
            entry._loaded_plugin = plugin

        # Configure if provided
        if config:
            instance.configure(config)

        # Enable if requested
        if enabled and instance.state == PluginState.INITIALIZED:
            instance.enable()

        self._plugins[name] = entry
        self._trigger_hook("on_register", entry)

        logger.info(f"Registered plugin: {name} v{instance.version}")
        return entry

    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin.

        Args:
            name: Plugin name

        Returns:
            True if unregistered successfully
        """
        if name not in self._plugins:
            return False

        entry = self._plugins[name]

        # Cleanup instance
        if entry.instance:
            try:
                entry.instance.cleanup()
            except Exception as e:
                logger.warning(f"Error during plugin cleanup: {e}")

        del self._plugins[name]
        self._trigger_hook("on_unregister", entry)

        logger.info(f"Unregistered plugin: {name}")
        return True

    def get(self, name: str) -> Optional[MIESCPlugin]:
        """
        Get a plugin instance by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        entry = self._plugins.get(name)
        if entry and entry.enabled and entry.instance:
            entry.last_used = datetime.now()
            return entry.instance
        return None

    def get_entry(self, name: str) -> Optional[PluginEntry]:
        """
        Get a plugin entry by name.

        Args:
            name: Plugin name

        Returns:
            PluginEntry or None
        """
        return self._plugins.get(name)

    def enable(self, name: str) -> bool:
        """
        Enable a plugin.

        Args:
            name: Plugin name

        Returns:
            True if enabled successfully
        """
        entry = self._plugins.get(name)
        if not entry:
            return False

        if entry.enabled:
            return True

        entry.enabled = True
        if entry.instance:
            entry.instance.enable()

        self._trigger_hook("on_enable", entry)
        logger.info(f"Enabled plugin: {name}")
        return True

    def disable(self, name: str) -> bool:
        """
        Disable a plugin.

        Args:
            name: Plugin name

        Returns:
            True if disabled successfully
        """
        entry = self._plugins.get(name)
        if not entry:
            return False

        if not entry.enabled:
            return True

        entry.enabled = False
        if entry.instance:
            entry.instance.disable()

        self._trigger_hook("on_disable", entry)
        logger.info(f"Disabled plugin: {name}")
        return True

    def configure(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Configure a plugin.

        Args:
            name: Plugin name
            config: Configuration dictionary

        Returns:
            True if configured successfully
        """
        entry = self._plugins.get(name)
        if not entry:
            return False

        entry.config = config
        if entry.instance:
            entry.instance.configure(config)

        return True

    def list_plugins(self) -> List[PluginEntry]:
        """
        List all registered plugins.

        Returns:
            List of PluginEntry objects
        """
        return list(self._plugins.values())

    def list_by_type(self, plugin_type: PluginType) -> List[PluginEntry]:
        """
        List plugins of a specific type.

        Args:
            plugin_type: Type to filter by

        Returns:
            List of matching PluginEntry objects
        """
        return [
            entry for entry in self._plugins.values()
            if entry.plugin_type == plugin_type
        ]

    def list_enabled(self) -> List[PluginEntry]:
        """List all enabled plugins."""
        return [
            entry for entry in self._plugins.values()
            if entry.enabled
        ]

    def list_disabled(self) -> List[PluginEntry]:
        """List all disabled plugins."""
        return [
            entry for entry in self._plugins.values()
            if not entry.enabled
        ]

    def list_by_tag(self, tag: str) -> List[PluginEntry]:
        """
        List plugins with a specific tag.

        Args:
            tag: Tag to filter by

        Returns:
            List of matching PluginEntry objects
        """
        return [
            entry for entry in self._plugins.values()
            if entry.metadata and tag in entry.metadata.tags
        ]

    def search(
        self,
        query: str,
        plugin_type: Optional[PluginType] = None,
        enabled_only: bool = False,
    ) -> List[PluginEntry]:
        """
        Search plugins by name or description.

        Args:
            query: Search query
            plugin_type: Optional type filter
            enabled_only: Only return enabled plugins

        Returns:
            List of matching PluginEntry objects
        """
        query = query.lower()
        results = []

        for entry in self._plugins.values():
            # Apply filters
            if plugin_type and entry.plugin_type != plugin_type:
                continue
            if enabled_only and not entry.enabled:
                continue

            # Search in name and description
            if query in entry.name.lower():
                results.append(entry)
                continue

            if entry.metadata:
                if query in entry.metadata.description.lower():
                    results.append(entry)
                    continue
                if any(query in tag.lower() for tag in entry.metadata.tags):
                    results.append(entry)
                    continue

        return results

    def __contains__(self, name: str) -> bool:
        """Check if a plugin is registered."""
        return name in self._plugins

    def __len__(self) -> int:
        """Get number of registered plugins."""
        return len(self._plugins)

    def __iter__(self) -> Iterator[PluginEntry]:
        """Iterate over plugin entries."""
        return iter(self._plugins.values())

    # ========================================================================
    # Persistence
    # ========================================================================

    def save(self) -> None:
        """Save registry state to disk."""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "1.0",
            "plugins": {
                name: entry.to_dict()
                for name, entry in self._plugins.items()
            },
            "saved_at": datetime.now().isoformat(),
        }

        with open(self.registry_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.debug(f"Saved registry to {self.registry_path}")

    def load(self) -> None:
        """Load registry state from disk."""
        if not self.registry_path.exists():
            return

        try:
            with open(self.registry_path) as f:
                data = json.load(f)

            for name, entry_data in data.get("plugins", {}).items():
                entry = PluginEntry.from_dict(entry_data)
                self._plugins[name] = entry

            logger.debug(
                f"Loaded {len(self._plugins)} plugins from {self.registry_path}"
            )
        except Exception as e:
            logger.error(f"Error loading registry: {e}")

    def clear(self) -> None:
        """Clear all registered plugins."""
        for entry in list(self._plugins.values()):
            self.unregister(entry.name)

    # ========================================================================
    # Hooks
    # ========================================================================

    def add_hook(self, event: str, callback: Callable) -> None:
        """
        Add a hook callback.

        Args:
            event: Event name (on_register, on_unregister, etc.)
            callback: Callback function
        """
        if event in self._hooks:
            self._hooks[event].append(callback)

    def remove_hook(self, event: str, callback: Callable) -> None:
        """
        Remove a hook callback.

        Args:
            event: Event name
            callback: Callback to remove
        """
        if event in self._hooks and callback in self._hooks[event]:
            self._hooks[event].remove(callback)

    def _trigger_hook(self, event: str, *args: Any) -> None:
        """Trigger hook callbacks."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args)
            except Exception as e:
                logger.warning(f"Hook error ({event}): {e}")

    # ========================================================================
    # Statistics
    # ========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        by_type = {}
        for pt in PluginType:
            by_type[pt.value] = len(self.list_by_type(pt))

        return {
            "total": len(self._plugins),
            "enabled": len(self.list_enabled()),
            "disabled": len(self.list_disabled()),
            "by_type": by_type,
        }


# ============================================================================
# Global Registry Instance
# ============================================================================

_global_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


def set_registry(registry: PluginRegistry) -> None:
    """Set the global plugin registry instance."""
    global _global_registry
    _global_registry = registry


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "PluginRegistry",
    "PluginEntry",
    "DEFAULT_REGISTRY_PATH",
    "get_registry",
    "set_registry",
]
