"""MIESC Plugin System.

Provides functionality for installing, managing, and loading
external detector plugins from PyPI or local directories.
"""

from .config import PluginConfig, PluginConfigManager
from .manager import (
    CompatibilityInfo,
    CompatibilityStatus,
    PluginInfo,
    PluginManager,
    VersionConstraint,
    compare_versions,
    get_miesc_version,
)

__all__ = [
    "PluginManager",
    "PluginInfo",
    "PluginConfig",
    "PluginConfigManager",
    "CompatibilityStatus",
    "CompatibilityInfo",
    "VersionConstraint",
    "get_miesc_version",
    "compare_versions",
]
