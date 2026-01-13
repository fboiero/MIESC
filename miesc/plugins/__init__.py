"""MIESC Plugin System.

Provides functionality for installing, managing, and loading
external detector plugins from PyPI or local directories.
"""

from .manager import PluginManager, PluginInfo
from .config import PluginConfig, PluginConfigManager

__all__ = [
    "PluginManager",
    "PluginInfo",
    "PluginConfig",
    "PluginConfigManager",
]
