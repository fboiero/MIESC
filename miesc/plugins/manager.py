"""Plugin Manager for MIESC.

Handles installation, uninstallation, discovery, and loading of
external detector plugins from PyPI or local directories.
"""

import importlib.metadata
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .config import PluginConfigManager


class CompatibilityStatus(Enum):
    """Plugin compatibility status with current MIESC version."""

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"
    WARNING = "warning"  # Compatible but newer version recommended


@dataclass
class VersionConstraint:
    """Represents a version constraint (e.g., >=4.0.0, <5.0.0)."""

    min_version: str | None = None
    max_version: str | None = None
    min_inclusive: bool = True
    max_inclusive: bool = False

    def __str__(self) -> str:
        parts = []
        if self.min_version:
            op = ">=" if self.min_inclusive else ">"
            parts.append(f"{op}{self.min_version}")
        if self.max_version:
            op = "<=" if self.max_inclusive else "<"
            parts.append(f"{op}{self.max_version}")
        return ", ".join(parts) if parts else "any"

    @classmethod
    def from_string(cls, constraint_str: str) -> "VersionConstraint":
        """Parse a version constraint string like '>=4.0.0,<5.0.0' or 'miesc>=4.2.0'."""
        constraint = cls()

        # Remove package name if present (e.g., "miesc>=4.0.0" -> ">=4.0.0")
        constraint_str = re.sub(r"^miesc\s*", "", constraint_str.strip())

        # Parse operators and versions
        patterns = [
            (r">=\s*([\d.]+)", "min_inclusive"),
            (r">\s*([\d.]+)", "min_exclusive"),
            (r"<=\s*([\d.]+)", "max_inclusive"),
            (r"<\s*([\d.]+)", "max_exclusive"),
            (r"==\s*([\d.]+)", "exact"),
            (r"~=\s*([\d.]+)", "compatible"),
        ]

        for pattern, kind in patterns:
            match = re.search(pattern, constraint_str)
            if match:
                version = match.group(1)
                if kind == "min_inclusive":
                    constraint.min_version = version
                    constraint.min_inclusive = True
                elif kind == "min_exclusive":
                    constraint.min_version = version
                    constraint.min_inclusive = False
                elif kind == "max_inclusive":
                    constraint.max_version = version
                    constraint.max_inclusive = True
                elif kind == "max_exclusive":
                    constraint.max_version = version
                    constraint.max_inclusive = False
                elif kind == "exact":
                    constraint.min_version = version
                    constraint.max_version = version
                    constraint.min_inclusive = True
                    constraint.max_inclusive = True
                elif kind == "compatible":
                    # ~=4.2.0 means >=4.2.0, <4.3.0
                    constraint.min_version = version
                    constraint.min_inclusive = True
                    parts = version.split(".")
                    if len(parts) >= 2:
                        parts[-2] = str(int(parts[-2]) + 1)
                        parts[-1] = "0"
                        constraint.max_version = ".".join(parts)
                        constraint.max_inclusive = False

        return constraint


@dataclass
class CompatibilityInfo:
    """Detailed compatibility information for a plugin."""

    status: CompatibilityStatus = CompatibilityStatus.UNKNOWN
    miesc_constraint: VersionConstraint | None = None
    current_miesc_version: str = ""
    message: str = ""
    python_constraint: str | None = None

    def __str__(self) -> str:
        if self.status == CompatibilityStatus.COMPATIBLE:
            return "compatible"
        elif self.status == CompatibilityStatus.INCOMPATIBLE:
            return f"incompatible ({self.message})"
        elif self.status == CompatibilityStatus.WARNING:
            return f"warning ({self.message})"
        return "unknown"


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
    compatibility: CompatibilityInfo | None = None
    requires_miesc: str | None = None  # e.g., ">=4.0.0"
    requires_python: str | None = None

    def __str__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        compat = ""
        if self.compatibility and self.compatibility.status != CompatibilityStatus.COMPATIBLE:
            compat = f" [{self.compatibility.status.value}]"
        return f"{self.name} ({self.package} v{self.version}) - {status}{compat}"


def get_miesc_version() -> str:
    """Get the current MIESC version.

    Returns:
        Version string (e.g., '4.3.3')
    """
    try:
        from miesc import __version__

        return __version__
    except ImportError:
        try:
            return importlib.metadata.version("miesc")
        except importlib.metadata.PackageNotFoundError:
            return "0.0.0"


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """

    def normalize(v: str) -> tuple[int, ...]:
        parts = []
        for part in v.split("."):
            # Handle versions like "4.3.3a1" -> extract numeric part
            numeric = re.match(r"(\d+)", part)
            if numeric:
                parts.append(int(numeric.group(1)))
            else:
                parts.append(0)
        # Pad to at least 3 parts
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)

    n1, n2 = normalize(v1), normalize(v2)

    if n1 < n2:
        return -1
    elif n1 > n2:
        return 1
    return 0


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
        self._miesc_version = get_miesc_version()

    def validate_compatibility(
        self,
        requires_miesc: str | None = None,
        requires_python: str | None = None,
    ) -> CompatibilityInfo:
        """Validate plugin compatibility with current MIESC version.

        Args:
            requires_miesc: MIESC version constraint (e.g., ">=4.0.0,<5.0.0")
            requires_python: Python version constraint (optional)

        Returns:
            CompatibilityInfo with validation results
        """
        info = CompatibilityInfo(
            current_miesc_version=self._miesc_version,
            python_constraint=requires_python,
        )

        # If no constraint specified, assume compatible
        if not requires_miesc:
            info.status = CompatibilityStatus.UNKNOWN
            info.message = "No MIESC version requirement specified"
            return info

        # Parse the constraint
        constraint = VersionConstraint.from_string(requires_miesc)
        info.miesc_constraint = constraint

        # Check minimum version
        if constraint.min_version:
            cmp = compare_versions(self._miesc_version, constraint.min_version)
            if constraint.min_inclusive and cmp < 0:
                info.status = CompatibilityStatus.INCOMPATIBLE
                info.message = f"Requires MIESC {constraint.min_version}+, current is {self._miesc_version}"
                return info
            elif not constraint.min_inclusive and cmp <= 0:
                info.status = CompatibilityStatus.INCOMPATIBLE
                info.message = f"Requires MIESC >{constraint.min_version}, current is {self._miesc_version}"
                return info

        # Check maximum version
        if constraint.max_version:
            cmp = compare_versions(self._miesc_version, constraint.max_version)
            if constraint.max_inclusive and cmp > 0:
                info.status = CompatibilityStatus.INCOMPATIBLE
                info.message = f"Requires MIESC <={constraint.max_version}, current is {self._miesc_version}"
                return info
            elif not constraint.max_inclusive and cmp >= 0:
                info.status = CompatibilityStatus.INCOMPATIBLE
                info.message = f"Requires MIESC <{constraint.max_version}, current is {self._miesc_version}"
                return info

        # Check Python version if specified
        if requires_python:
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
            py_constraint = VersionConstraint.from_string(requires_python)

            if py_constraint.min_version:
                cmp = compare_versions(python_version, py_constraint.min_version)
                if cmp < 0:
                    info.status = CompatibilityStatus.WARNING
                    info.message = f"Recommends Python {py_constraint.min_version}+, using {python_version}"
                    return info

        # All checks passed
        info.status = CompatibilityStatus.COMPATIBLE
        info.message = "Compatible with current MIESC version"
        return info

    def check_pypi_compatibility(
        self, package_name: str, timeout: int = 10
    ) -> tuple[CompatibilityInfo, str | None]:
        """Check compatibility of a PyPI package before installation.

        Args:
            package_name: Package name to check
            timeout: Request timeout in seconds

        Returns:
            Tuple of (CompatibilityInfo, version_string or None)
        """
        import json
        import urllib.error
        import urllib.request

        normalized_name = self._normalize_package_name(package_name)

        try:
            url = f"https://pypi.org/pypi/{normalized_name}/json"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": f"MIESC/{self._miesc_version}"},
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    info = data.get("info", {})
                    version = info.get("version", "unknown")
                    requires_dist = info.get("requires_dist") or []

                    # Find MIESC dependency requirement
                    miesc_constraint = None
                    python_constraint = info.get("requires_python")

                    for req_str in requires_dist:
                        # Look for miesc requirement
                        if req_str.lower().startswith("miesc"):
                            # Extract constraint (e.g., "miesc>=4.0.0" -> ">=4.0.0")
                            miesc_constraint = req_str
                            break

                    # Validate compatibility
                    compat = self.validate_compatibility(
                        requires_miesc=miesc_constraint,
                        requires_python=python_constraint,
                    )

                    return compat, version

        except urllib.error.HTTPError:
            info = CompatibilityInfo(
                status=CompatibilityStatus.UNKNOWN,
                current_miesc_version=self._miesc_version,
                message="Package not found on PyPI",
            )
            return info, None
        except Exception as e:
            info = CompatibilityInfo(
                status=CompatibilityStatus.UNKNOWN,
                current_miesc_version=self._miesc_version,
                message=f"Could not check compatibility: {e}",
            )
            return info, None

        return CompatibilityInfo(status=CompatibilityStatus.UNKNOWN), None

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

    def install(
        self,
        package_name: str,
        upgrade: bool = False,
        check_compatibility: bool = True,
        force: bool = False,
    ) -> tuple[bool, str]:
        """Install a plugin package from PyPI.

        Args:
            package_name: Package name (with or without miesc- prefix)
            upgrade: If True, upgrade if already installed
            check_compatibility: If True, check version compatibility before install
            force: If True, install even if incompatible

        Returns:
            Tuple of (success, message)
        """
        normalized_name = self._normalize_package_name(package_name)

        # Check compatibility before installation
        if check_compatibility:
            compat, pkg_version = self.check_pypi_compatibility(normalized_name)
            if compat.status == CompatibilityStatus.INCOMPATIBLE and not force:
                return (
                    False,
                    f"Plugin {normalized_name} is incompatible: {compat.message}. "
                    f"Use --force to install anyway.",
                )
            elif compat.status == CompatibilityStatus.WARNING:
                # Warn but proceed
                pass  # Will show warning in CLI

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

                # Include compatibility warning if applicable
                if check_compatibility and compat.status == CompatibilityStatus.WARNING:
                    return (
                        True,
                        f"Successfully installed {normalized_name} (warning: {compat.message})",
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
                    description = ""
                    author = ""
                    requires_miesc = None
                    requires_python = None

                    try:
                        metadata = dist.metadata
                        description = metadata.get("Summary", "")
                        author = metadata.get("Author", "")
                        requires_python = metadata.get("Requires-Python", "")

                        # Check requires_dist for miesc dependency
                        requires_dist = metadata.get_all("Requires-Dist") or []
                        for req in requires_dist:
                            if req.lower().startswith("miesc"):
                                requires_miesc = req
                                break
                    except Exception:
                        pass

                    enabled = self.config_manager.is_enabled(package_name)

                    # Validate compatibility
                    compatibility = self.validate_compatibility(
                        requires_miesc=requires_miesc,
                        requires_python=requires_python,
                    )

                    plugins[package_name] = PluginInfo(
                        name=package_name,
                        package=package_name,
                        version=version,
                        enabled=enabled,
                        detector_count=0,
                        detectors=[],
                        description=description,
                        author=author,
                        compatibility=compatibility,
                        requires_miesc=requires_miesc,
                        requires_python=requires_python,
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

        Scans ~/.miesc/plugins/ for valid plugin packages and introspects
        them to find detector classes.

        Returns:
            List of PluginInfo for local plugins
        """
        plugins = []

        if not self.LOCAL_PLUGINS_DIR.exists():
            return plugins

        for plugin_dir in self.LOCAL_PLUGINS_DIR.iterdir():
            if not plugin_dir.is_dir():
                continue

            # Skip hidden directories and __pycache__
            if plugin_dir.name.startswith('.') or plugin_dir.name == '__pycache__':
                continue

            # Try to load plugin info
            plugin_info = self._load_local_plugin_info(plugin_dir)
            if plugin_info:
                plugins.append(plugin_info)

        return plugins

    def _load_local_plugin_info(self, plugin_dir: Path) -> PluginInfo | None:
        """Load plugin info from a local plugin directory.

        Args:
            plugin_dir: Path to the plugin directory

        Returns:
            PluginInfo or None if not a valid plugin
        """
        import importlib.util
        import tomllib
        import inspect

        plugin_name = plugin_dir.name
        version = "local"
        description = ""
        author = ""
        detectors = []

        # Try to read pyproject.toml for metadata
        pyproject_path = plugin_dir / "pyproject.toml"
        if pyproject_path.exists():
            try:
                with open(pyproject_path, "rb") as f:
                    pyproject = tomllib.load(f)
                    project = pyproject.get("project", {})
                    version = project.get("version", "local")
                    description = project.get("description", "")
                    authors = project.get("authors", [])
                    if authors and isinstance(authors, list):
                        author = authors[0].get("name", "") if isinstance(authors[0], dict) else str(authors[0])
            except Exception:
                pass

        # Find detector classes in the plugin
        detector_classes = self._find_detector_classes_in_dir(plugin_dir)
        detectors = [cls.__name__ for cls in detector_classes]

        # Must have at least one detector or a recognizable structure
        has_detectors_file = (plugin_dir / "detectors.py").exists()
        has_init = (plugin_dir / "__init__.py").exists()
        has_subpackage = any(
            (plugin_dir / d / "detectors.py").exists()
            for d in plugin_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
        )

        if not (detectors or has_detectors_file or has_init or has_subpackage):
            return None

        enabled = self.config_manager.is_enabled(plugin_name)

        return PluginInfo(
            name=plugin_name,
            package=plugin_name,
            version=version,
            enabled=enabled,
            detector_count=len(detectors),
            detectors=detectors,
            description=description or f"Local plugin from {plugin_dir}",
            author=author,
            local=True,
        )

    def _find_detector_classes_in_dir(self, plugin_dir: Path) -> list[type]:
        """Find all detector classes in a plugin directory.

        Args:
            plugin_dir: Path to the plugin directory

        Returns:
            List of detector classes found
        """
        import importlib.util
        import inspect
        import sys

        detector_classes = []

        # Import BaseDetector for isinstance checks
        try:
            from miesc.detectors import BaseDetector
        except ImportError:
            try:
                from src.detectors.detector_api import BaseDetector
            except ImportError:
                return detector_classes

        # Files to check for detectors
        files_to_check = []

        # Direct detectors.py
        if (plugin_dir / "detectors.py").exists():
            files_to_check.append(plugin_dir / "detectors.py")

        # Check subpackages (e.g., my_plugin/detectors.py)
        for subdir in plugin_dir.iterdir():
            if subdir.is_dir() and not subdir.name.startswith('.') and subdir.name != '__pycache__':
                if (subdir / "detectors.py").exists():
                    files_to_check.append(subdir / "detectors.py")
                if (subdir / "__init__.py").exists():
                    files_to_check.append(subdir / "__init__.py")

        for file_path in files_to_check:
            try:
                # Create a unique module name
                module_name = f"miesc_local_plugin_{plugin_dir.name}_{file_path.stem}"

                # Load the module
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                if spec is None or spec.loader is None:
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module

                try:
                    spec.loader.exec_module(module)
                except Exception:
                    continue

                # Find detector classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (obj is not BaseDetector and
                        issubclass(obj, BaseDetector) and
                        hasattr(obj, 'name') and
                        hasattr(obj, 'analyze')):
                        detector_classes.append(obj)

            except Exception:
                continue

        return detector_classes

    def ensure_local_plugins_dir(self) -> Path:
        """Ensure the local plugins directory exists.

        Returns:
            Path to the local plugins directory
        """
        self.LOCAL_PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        return self.LOCAL_PLUGINS_DIR

    def get_local_plugin_detectors(self) -> list[tuple[str, type]]:
        """Get all detector classes from enabled local plugins.

        Returns:
            List of (detector_name, detector_class) tuples
        """
        detectors = []

        for plugin in self._discover_local_plugins():
            if not plugin.enabled:
                continue

            plugin_dir = self.LOCAL_PLUGINS_DIR / plugin.name
            if plugin_dir.exists():
                for detector_class in self._find_detector_classes_in_dir(plugin_dir):
                    detector_name = getattr(detector_class, 'name', detector_class.__name__)
                    detectors.append((detector_name, detector_class))

        return detectors

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
        """Get all detector classes from enabled plugins (PyPI and local).

        Returns:
            List of (name, detector_class) tuples
        """
        detectors = []

        # Get detectors from PyPI-installed plugins (entry points)
        try:
            eps = importlib.metadata.entry_points()
            if hasattr(eps, "select"):
                detector_eps = eps.select(group=self.ENTRY_POINT_GROUP)
            else:
                detector_eps = eps.get(self.ENTRY_POINT_GROUP, [])
        except Exception:
            detector_eps = []

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

        # Get detectors from local plugins
        local_detectors = self.get_local_plugin_detectors()
        detectors.extend(local_detectors)

        return detectors

    def search_pypi(self, query: str, timeout: int = 10) -> list[dict[str, str]]:
        """Search PyPI for MIESC plugins.

        Uses multiple strategies:
        1. Check known MIESC plugins registry
        2. Query PyPI JSON API for packages matching miesc-* pattern
        3. Filter results by query string

        Args:
            query: Search query (searches name and description)
            timeout: Request timeout in seconds

        Returns:
            List of package info dicts with keys: name, version, description, url
        """
        import urllib.request
        import urllib.error
        import json

        results = []
        checked_packages = set()

        # Known MIESC plugins registry (expandable)
        known_plugins = [
            "miesc-defi-detectors",
            "miesc-flash-loan",
            "miesc-reentrancy",
            "miesc-access-control",
            "miesc-mev-protection",
            "miesc-upgradeable",
            "miesc-oracle",
            "miesc-nft-security",
            "miesc-token-security",
            "miesc-bridge-security",
        ]

        # Also generate potential package names from query
        query_lower = query.lower().strip()
        potential_packages = [
            f"miesc-{query_lower}",
            f"miesc-{query_lower}-detector",
            f"miesc-{query_lower}-detectors",
            f"miesc-{query_lower.replace(' ', '-')}",
        ]

        # Combine all packages to check
        packages_to_check = known_plugins + potential_packages

        for package_name in packages_to_check:
            if package_name in checked_packages:
                continue
            checked_packages.add(package_name)

            try:
                # Query PyPI JSON API
                url = f"https://pypi.org/pypi/{package_name}/json"
                req = urllib.request.Request(
                    url,
                    headers={"Accept": "application/json", "User-Agent": "MIESC/4.3.3"}
                )

                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode("utf-8"))
                        info = data.get("info", {})

                        name = info.get("name", package_name)
                        version = info.get("version", "unknown")
                        description = info.get("summary", "")
                        project_url = info.get("project_url", f"https://pypi.org/project/{package_name}/")

                        # Filter by query - check if query matches name or description
                        name_lower = name.lower()
                        desc_lower = description.lower()

                        if (query_lower in name_lower or
                            query_lower in desc_lower or
                            any(word in name_lower for word in query_lower.split()) or
                            any(word in desc_lower for word in query_lower.split())):

                            results.append({
                                "name": name,
                                "version": version,
                                "description": description,
                                "url": project_url,
                            })

            except urllib.error.HTTPError:
                # Package doesn't exist, skip
                continue
            except urllib.error.URLError:
                # Network error, skip
                continue
            except Exception:
                # Any other error, skip
                continue

        # Sort by relevance (exact match first, then alphabetically)
        def sort_key(pkg):
            name = pkg["name"].lower()
            if query_lower == name or query_lower == name.replace("miesc-", ""):
                return (0, name)
            if query_lower in name:
                return (1, name)
            return (2, name)

        results.sort(key=sort_key)

        return results

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
