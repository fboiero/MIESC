"""Plugin Manager for MIESC.

Handles installation, uninstallation, discovery, and loading of
external detector plugins from PyPI or local directories.
"""

import importlib.metadata
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import PluginConfigManager


@dataclass
class PluginInfo:
    """Information about an installed plugin."""

    name: str
    package: str
    version: str
    enabled: bool = True
    detector_count: int = 0
    detectors: list[str] = field(default_factory=list)
    description: str = ""
    author: str = ""
    local: bool = False

    def __str__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"{self.name} ({self.package} v{self.version}) - {status}"


class PluginManager:
    """Manages MIESC plugins (detector packages)."""

    PLUGIN_PREFIX = "miesc-"
    ENTRY_POINT_GROUP = "miesc.detectors"
    LOCAL_PLUGINS_DIR = Path.home() / ".miesc" / "plugins"

    def __init__(self, config_manager: PluginConfigManager | None = None):
        """Initialize plugin manager.

        Args:
            config_manager: Custom config manager (creates default if None)
        """
        self.config_manager = config_manager or PluginConfigManager()
        self._cached_plugins: list[PluginInfo] | None = None

    def _normalize_package_name(self, name: str) -> str:
        """Normalize package name to include miesc- prefix.

        Args:
            name: Package name (with or without prefix)

        Returns:
            Normalized package name with miesc- prefix
        """
        if name.startswith(self.PLUGIN_PREFIX):
            return name
        return f"{self.PLUGIN_PREFIX}{name}"

    def install(self, package_name: str, upgrade: bool = False) -> tuple[bool, str]:
        """Install a plugin package from PyPI.

        Args:
            package_name: Package name (with or without miesc- prefix)
            upgrade: If True, upgrade if already installed

        Returns:
            Tuple of (success, message)
        """
        normalized_name = self._normalize_package_name(package_name)

        cmd = [sys.executable, "-m", "pip", "install", "--quiet"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.append(normalized_name)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300  # 5 min timeout
            )

            if result.returncode == 0:
                # Clear cache and enable plugin
                self._cached_plugins = None

                # Get version from installed package
                try:
                    version = importlib.metadata.version(normalized_name)
                except importlib.metadata.PackageNotFoundError:
                    version = "unknown"

                # Enable in config
                self.config_manager.enable_plugin(
                    normalized_name, package=normalized_name, version=version
                )

                return True, f"Successfully installed {normalized_name}"
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Failed to install {normalized_name}: {error_msg}"

        except subprocess.TimeoutExpired:
            return False, f"Installation timed out for {normalized_name}"
        except Exception as e:
            return False, f"Installation error: {e}"

    def uninstall(self, package_name: str) -> tuple[bool, str]:
        """Uninstall a plugin package.

        Args:
            package_name: Package name (with or without miesc- prefix)

        Returns:
            Tuple of (success, message)
        """
        normalized_name = self._normalize_package_name(package_name)

        cmd = [sys.executable, "-m", "pip", "uninstall", "-y", normalized_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Clear cache and remove from config
                self._cached_plugins = None
                self.config_manager.remove_plugin(normalized_name)
                return True, f"Successfully uninstalled {normalized_name}"
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Failed to uninstall {normalized_name}: {error_msg}"

        except subprocess.TimeoutExpired:
            return False, f"Uninstallation timed out for {normalized_name}"
        except Exception as e:
            return False, f"Uninstallation error: {e}"

    def list_installed(self, include_disabled: bool = True) -> list[PluginInfo]:
        """List all installed MIESC plugins.

        Args:
            include_disabled: Include disabled plugins in list

        Returns:
            List of PluginInfo objects
        """
        if self._cached_plugins is not None:
            plugins = self._cached_plugins
        else:
            plugins = self._discover_plugins()
            self._cached_plugins = plugins

        if include_disabled:
            return plugins
        return [p for p in plugins if p.enabled]

    def _discover_plugins(self) -> list[PluginInfo]:
        """Discover all installed plugins from entry points.

        Returns:
            List of PluginInfo objects
        """
        plugins: dict[str, PluginInfo] = {}

        # Get entry points for miesc.detectors
        try:
            eps = importlib.metadata.entry_points()
            if hasattr(eps, "select"):
                # Python 3.10+
                detector_eps = eps.select(group=self.ENTRY_POINT_GROUP)
            else:
                # Python 3.9
                detector_eps = eps.get(self.ENTRY_POINT_GROUP, [])
        except Exception:
            detector_eps = []

        for ep in detector_eps:
            try:
                dist = ep.dist
                if dist is None:
                    continue

                package_name = dist.name
                version = dist.version

                # Get or create plugin info
                if package_name not in plugins:
                    # Get metadata
                    try:
                        metadata = dist.metadata
                        description = metadata.get("Summary", "")
                        author = metadata.get("Author", "")
                    except Exception:
                        description = ""
                        author = ""

                    enabled = self.config_manager.is_enabled(package_name)

                    plugins[package_name] = PluginInfo(
                        name=package_name,
                        package=package_name,
                        version=version,
                        enabled=enabled,
                        detector_count=0,
                        detectors=[],
                        description=description,
                        author=author,
                    )

                # Add detector to plugin
                plugins[package_name].detectors.append(ep.name)
                plugins[package_name].detector_count += 1

            except Exception:
                continue

        # Also check for local plugins
        local_plugins = self._discover_local_plugins()
        for plugin in local_plugins:
            if plugin.package not in plugins:
                plugins[plugin.package] = plugin

        return list(plugins.values())

    def _discover_local_plugins(self) -> list[PluginInfo]:
        """Discover plugins from local plugins directory.

        Returns:
            List of PluginInfo for local plugins
        """
        plugins = []

        if not self.LOCAL_PLUGINS_DIR.exists():
            return plugins

        for plugin_dir in self.LOCAL_PLUGINS_DIR.iterdir():
            if not plugin_dir.is_dir():
                continue

            # Look for __init__.py or detectors.py
            init_file = plugin_dir / "__init__.py"
            detectors_file = plugin_dir / "detectors.py"

            if init_file.exists() or detectors_file.exists():
                enabled = self.config_manager.is_enabled(plugin_dir.name)
                plugins.append(
                    PluginInfo(
                        name=plugin_dir.name,
                        package=plugin_dir.name,
                        version="local",
                        enabled=enabled,
                        detector_count=0,  # Would need to introspect
                        detectors=[],
                        description=f"Local plugin from {plugin_dir}",
                        local=True,
                    )
                )

        return plugins

    def enable(self, plugin_name: str) -> tuple[bool, str]:
        """Enable a plugin.

        Args:
            plugin_name: Plugin name

        Returns:
            Tuple of (success, message)
        """
        normalized = self._normalize_package_name(plugin_name)

        # Check if plugin exists
        plugins = self.list_installed()
        plugin = next((p for p in plugins if p.package == normalized), None)

        if plugin is None:
            # Try without prefix
            plugin = next((p for p in plugins if p.package == plugin_name), None)

        if plugin is None:
            return False, f"Plugin '{plugin_name}' not found"

        self.config_manager.enable_plugin(plugin.package)
        self._cached_plugins = None
        return True, f"Enabled plugin '{plugin.package}'"

    def disable(self, plugin_name: str) -> tuple[bool, str]:
        """Disable a plugin.

        Args:
            plugin_name: Plugin name

        Returns:
            Tuple of (success, message)
        """
        normalized = self._normalize_package_name(plugin_name)

        # Check if plugin exists
        plugins = self.list_installed()
        plugin = next((p for p in plugins if p.package == normalized), None)

        if plugin is None:
            plugin = next((p for p in plugins if p.package == plugin_name), None)

        if plugin is None:
            return False, f"Plugin '{plugin_name}' not found"

        self.config_manager.disable_plugin(plugin.package)
        self._cached_plugins = None
        return True, f"Disabled plugin '{plugin.package}'"

    def get_plugin_info(self, plugin_name: str) -> PluginInfo | None:
        """Get detailed information about a plugin.

        Args:
            plugin_name: Plugin name

        Returns:
            PluginInfo or None if not found
        """
        normalized = self._normalize_package_name(plugin_name)
        plugins = self.list_installed()

        plugin = next((p for p in plugins if p.package == normalized), None)
        if plugin is None:
            plugin = next((p for p in plugins if p.package == plugin_name), None)

        return plugin

    def get_enabled_detectors(self) -> list[tuple[str, Any]]:
        """Get all detector classes from enabled plugins.

        Returns:
            List of (name, detector_class) tuples
        """
        detectors = []

        try:
            eps = importlib.metadata.entry_points()
            if hasattr(eps, "select"):
                detector_eps = eps.select(group=self.ENTRY_POINT_GROUP)
            else:
                detector_eps = eps.get(self.ENTRY_POINT_GROUP, [])
        except Exception:
            return detectors

        for ep in detector_eps:
            try:
                # Check if plugin is enabled
                dist = ep.dist
                if dist and not self.config_manager.is_enabled(dist.name):
                    continue

                # Load detector class
                detector_class = ep.load()
                detectors.append((ep.name, detector_class))
            except Exception:
                continue

        return detectors

    def search_pypi(self, query: str) -> list[dict[str, str]]:
        """Search PyPI for MIESC plugins.

        Note: PyPI doesn't have a search API, so this uses a simple approach
        of checking if specific packages exist.

        Args:
            query: Search query

        Returns:
            List of package info dicts
        """
        # PyPI search API is deprecated, so we return empty
        # In a real implementation, you could use pypi.org/search
        # or maintain a registry of known plugins
        return []

    def create_plugin_scaffold(
        self, name: str, output_dir: Path, description: str = "", author: str = ""
    ) -> Path:
        """Create a new plugin project scaffold.

        Args:
            name: Plugin name (without miesc- prefix)
            output_dir: Directory to create plugin in
            description: Plugin description
            author: Author name

        Returns:
            Path to created plugin directory
        """
        from .templates import create_plugin_scaffold

        return create_plugin_scaffold(
            name=name, output_dir=output_dir, description=description, author=author
        )
