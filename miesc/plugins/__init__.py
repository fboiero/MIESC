"""MIESC Plugin System.

Provides functionality for installing, managing, and loading
external detector plugins from PyPI or local directories.
"""

from .manager import (
    PluginManager,
    PluginInfo,
    CompatibilityStatus,
    CompatibilityInfo,
    VersionConstraint,
    get_miesc_version,
    compare_versions,
)
from .config import PluginConfig, PluginConfigManager

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
