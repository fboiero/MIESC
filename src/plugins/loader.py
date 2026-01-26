"""
Plugin Loader - Discovery and Loading of MIESC Plugins
=======================================================

Handles plugin discovery from multiple sources:
- Local directories (~/.miesc/plugins)
- Python entry points (miesc.plugins)
- Installed packages

Usage:
    loader = PluginLoader()

    # Discover from directory
    plugins = loader.discover_from_directory("~/.miesc/plugins")

    # Discover from entry points
    plugins = loader.discover_from_entry_points()

    # Load a specific plugin
    plugin = loader.load_plugin("path/to/plugin.py")

    # Load and initialize
    plugin = loader.load_and_initialize(plugin_class, context)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import importlib
import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Union

from .protocol import (
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginState,
    PluginType,
    is_plugin_class,
    get_plugin_classes,
)

logger = logging.getLogger(__name__)


# Entry point group name for MIESC plugins
ENTRY_POINT_GROUP = "miesc.plugins"

# Default plugin directories
DEFAULT_PLUGIN_DIRS = [
    Path.home() / ".miesc" / "plugins",
    Path("/etc/miesc/plugins"),
]


@dataclass
class LoadedPlugin:
    """Container for a loaded plugin."""
    plugin_class: Type[MIESCPlugin]
    instance: Optional[MIESCPlugin] = None
    source: str = ""  # file path, entry point name, or package name
    metadata: Optional[PluginMetadata] = None
    load_error: Optional[str] = None

    @property
    def name(self) -> str:
        """Get plugin name."""
        if self.instance:
            return self.instance.name
        if self.metadata:
            return self.metadata.name
        return self.plugin_class.__name__

    @property
    def version(self) -> str:
        """Get plugin version."""
        if self.instance:
            return self.instance.version
        if self.metadata:
            return self.metadata.version
        return "0.0.0"

    @property
    def plugin_type(self) -> Optional[PluginType]:
        """Get plugin type."""
        if self.instance:
            return self.instance.plugin_type
        if self.metadata:
            return self.metadata.plugin_type
        return None


@dataclass
class DiscoveryResult:
    """Result of plugin discovery."""
    plugins: List[LoadedPlugin] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sources_searched: List[str] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return len([p for p in self.plugins if p.load_error is None])

    @property
    def error_count(self) -> int:
        return len([p for p in self.plugins if p.load_error is not None])


class PluginLoader:
    """
    Discovers and loads MIESC plugins from various sources.

    Supports:
    - Directory-based plugins (Python files)
    - Entry point plugins (setuptools)
    - Package-based plugins (installed packages)
    """

    def __init__(
        self,
        plugin_dirs: Optional[List[Path]] = None,
        auto_discover: bool = False,
    ):
        """
        Initialize the plugin loader.

        Args:
            plugin_dirs: Directories to search for plugins
            auto_discover: Automatically discover plugins on init
        """
        self.plugin_dirs = plugin_dirs or DEFAULT_PLUGIN_DIRS.copy()
        self._loaded_plugins: Dict[str, LoadedPlugin] = {}
        self._discovered_sources: Set[str] = set()

        if auto_discover:
            self.discover_all()

    def discover_all(self) -> DiscoveryResult:
        """
        Discover plugins from all configured sources.

        Returns:
            DiscoveryResult with all discovered plugins
        """
        result = DiscoveryResult()

        # Discover from directories
        for plugin_dir in self.plugin_dirs:
            if plugin_dir.exists():
                dir_result = self.discover_from_directory(plugin_dir)
                result.plugins.extend(dir_result.plugins)
                result.errors.extend(dir_result.errors)
                result.sources_searched.extend(dir_result.sources_searched)

        # Discover from entry points
        ep_result = self.discover_from_entry_points()
        result.plugins.extend(ep_result.plugins)
        result.errors.extend(ep_result.errors)
        result.sources_searched.extend(ep_result.sources_searched)

        logger.info(
            f"Discovered {result.success_count} plugins "
            f"({result.error_count} errors)"
        )

        return result

    def discover_from_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
    ) -> DiscoveryResult:
        """
        Discover plugins from a directory.

        Args:
            directory: Directory to search
            recursive: Search subdirectories

        Returns:
            DiscoveryResult with discovered plugins
        """
        result = DiscoveryResult()
        directory = Path(directory).expanduser()

        if not directory.exists():
            result.errors.append(f"Directory not found: {directory}")
            return result

        result.sources_searched.append(str(directory))
        logger.debug(f"Searching for plugins in {directory}")

        # Find Python files
        pattern = "**/*.py" if recursive else "*.py"
        for py_file in directory.glob(pattern):
            if py_file.name.startswith("_"):
                continue

            try:
                loaded = self.load_plugin_file(py_file)
                if loaded:
                    result.plugins.extend(loaded)
            except Exception as e:
                error_msg = f"Error loading {py_file}: {e}"
                result.errors.append(error_msg)
                logger.warning(error_msg)

        return result

    def discover_from_entry_points(self) -> DiscoveryResult:
        """
        Discover plugins from Python entry points.

        Uses the 'miesc.plugins' entry point group.

        Returns:
            DiscoveryResult with discovered plugins
        """
        result = DiscoveryResult()
        result.sources_searched.append(f"entry_points:{ENTRY_POINT_GROUP}")

        try:
            # Python 3.10+ uses importlib.metadata
            if sys.version_info >= (3, 10):
                from importlib.metadata import entry_points
                eps = entry_points(group=ENTRY_POINT_GROUP)
            else:
                # Python 3.9 compatibility
                from importlib.metadata import entry_points as get_eps
                all_eps = get_eps()
                eps = all_eps.get(ENTRY_POINT_GROUP, [])

            for ep in eps:
                try:
                    plugin_class = ep.load()
                    if is_plugin_class(plugin_class):
                        loaded = LoadedPlugin(
                            plugin_class=plugin_class,
                            source=f"entry_point:{ep.name}",
                        )
                        result.plugins.append(loaded)
                        logger.debug(f"Loaded plugin from entry point: {ep.name}")
                except Exception as e:
                    error_msg = f"Error loading entry point {ep.name}: {e}"
                    result.errors.append(error_msg)
                    logger.warning(error_msg)

        except Exception as e:
            result.errors.append(f"Error reading entry points: {e}")
            logger.warning(f"Could not read entry points: {e}")

        return result

    def load_plugin_file(self, filepath: Union[str, Path]) -> List[LoadedPlugin]:
        """
        Load plugins from a Python file.

        Args:
            filepath: Path to Python file

        Returns:
            List of loaded plugins from the file
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Plugin file not found: {filepath}")

        # Create unique module name
        module_name = f"miesc_plugin_{filepath.stem}_{id(filepath)}"

        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec for {filepath}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            del sys.modules[module_name]
            raise ImportError(f"Error executing module {filepath}: {e}")

        # Find plugin classes
        plugins = []
        for plugin_class in get_plugin_classes(module):
            loaded = LoadedPlugin(
                plugin_class=plugin_class,
                source=str(filepath),
            )
            plugins.append(loaded)
            logger.debug(f"Found plugin class: {plugin_class.__name__}")

        return plugins

    def load_plugin_package(self, package_name: str) -> List[LoadedPlugin]:
        """
        Load plugins from an installed package.

        Args:
            package_name: Name of the package

        Returns:
            List of loaded plugins from the package
        """
        try:
            module = importlib.import_module(package_name)
        except ImportError as e:
            raise ImportError(f"Could not import package {package_name}: {e}")

        plugins = []
        for plugin_class in get_plugin_classes(module):
            loaded = LoadedPlugin(
                plugin_class=plugin_class,
                source=f"package:{package_name}",
            )
            plugins.append(loaded)

        return plugins

    def load_and_initialize(
        self,
        loaded_plugin: LoadedPlugin,
        context: PluginContext,
    ) -> MIESCPlugin:
        """
        Create and initialize a plugin instance.

        Args:
            loaded_plugin: LoadedPlugin container
            context: Plugin context

        Returns:
            Initialized plugin instance
        """
        if loaded_plugin.instance is not None:
            return loaded_plugin.instance

        # Create instance
        instance = loaded_plugin.plugin_class()

        # Initialize
        try:
            instance.initialize(context)
            instance._set_initialized(context)
            loaded_plugin.instance = instance
            loaded_plugin.metadata = instance.get_metadata()

            logger.info(
                f"Initialized plugin: {instance.name} v{instance.version}"
            )
        except Exception as e:
            instance._state = PluginState.ERROR
            loaded_plugin.load_error = str(e)
            logger.error(f"Failed to initialize plugin: {e}")
            raise

        return instance

    def validate_plugin(
        self,
        plugin_class: Type[MIESCPlugin],
        miesc_version: str = "4.0.0",
    ) -> List[str]:
        """
        Validate a plugin class.

        Args:
            plugin_class: Plugin class to validate
            miesc_version: Current MIESC version

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check it's a valid plugin class
        if not is_plugin_class(plugin_class):
            errors.append("Not a valid plugin class")
            return errors

        # Try to instantiate
        try:
            instance = plugin_class()
        except Exception as e:
            errors.append(f"Cannot instantiate: {e}")
            return errors

        # Check required properties
        try:
            name = instance.name
            if not name or not isinstance(name, str):
                errors.append("Invalid plugin name")
        except Exception as e:
            errors.append(f"Error getting name: {e}")

        try:
            version = instance.version
            if not version or not isinstance(version, str):
                errors.append("Invalid plugin version")
        except Exception as e:
            errors.append(f"Error getting version: {e}")

        try:
            plugin_type = instance.plugin_type
            if not isinstance(plugin_type, PluginType):
                errors.append("Invalid plugin type")
        except Exception as e:
            errors.append(f"Error getting plugin_type: {e}")

        # Check version compatibility
        try:
            metadata = instance.get_metadata()
            if metadata.min_miesc_version:
                if not self._version_compatible(
                    miesc_version, metadata.min_miesc_version, metadata.max_miesc_version
                ):
                    errors.append(
                        f"Version incompatible: requires MIESC "
                        f"{metadata.min_miesc_version}"
                        f"{' - ' + metadata.max_miesc_version if metadata.max_miesc_version else '+'}"
                    )
        except Exception:
            pass  # Metadata is optional

        return errors

    def _version_compatible(
        self,
        current: str,
        min_version: str,
        max_version: Optional[str] = None,
    ) -> bool:
        """Check version compatibility."""
        try:
            current_parts = [int(x) for x in current.split(".")[:3]]
            min_parts = [int(x) for x in min_version.split(".")[:3]]

            # Pad to 3 parts
            while len(current_parts) < 3:
                current_parts.append(0)
            while len(min_parts) < 3:
                min_parts.append(0)

            # Check minimum
            if current_parts < min_parts:
                return False

            # Check maximum
            if max_version:
                max_parts = [int(x) for x in max_version.split(".")[:3]]
                while len(max_parts) < 3:
                    max_parts.append(0)
                if current_parts > max_parts:
                    return False

            return True
        except Exception:
            return True  # Assume compatible on parse error

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin.

        Args:
            plugin_name: Name of plugin to unload

        Returns:
            True if unloaded successfully
        """
        if plugin_name not in self._loaded_plugins:
            return False

        loaded = self._loaded_plugins[plugin_name]
        if loaded.instance:
            try:
                loaded.instance.cleanup()
            except Exception as e:
                logger.warning(f"Error during plugin cleanup: {e}")

        del self._loaded_plugins[plugin_name]
        logger.info(f"Unloaded plugin: {plugin_name}")
        return True

    def get_loaded_plugins(self) -> Dict[str, LoadedPlugin]:
        """Get all loaded plugins."""
        return self._loaded_plugins.copy()


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "PluginLoader",
    "LoadedPlugin",
    "DiscoveryResult",
    "ENTRY_POINT_GROUP",
    "DEFAULT_PLUGIN_DIRS",
]
