"""
MIESC Plugins Module
====================

Extensible plugin system for MIESC.

This module provides:
- Plugin protocol (base classes and interfaces)
- Plugin loader (discovery and loading)
- Plugin registry (management and storage)

Usage:
    from src.plugins import PluginLoader, PluginRegistry, MIESCPlugin

    # Load plugins
    loader = PluginLoader()
    plugins = loader.discover("~/.miesc/plugins")

    # Register plugins
    registry = PluginRegistry()
    for plugin in plugins:
        registry.register(plugin)

    # Use plugins
    detector = registry.get("my-detector")
    result = detector.execute(code="...")

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

from .protocol import (
    # Enums
    PluginType,
    PluginState,
    # Data classes
    PluginMetadata,
    PluginContext,
    PluginResult,
    # Base classes
    MIESCPlugin,
    DetectorPlugin,
    AdapterPlugin,
    ReporterPlugin,
    TransformerPlugin,
    # Helpers
    is_plugin_class,
    get_plugin_classes,
)

from .loader import (
    PluginLoader,
    LoadedPlugin,
    DiscoveryResult,
    ENTRY_POINT_GROUP,
    DEFAULT_PLUGIN_DIRS,
)

from .registry import (
    PluginRegistry,
    PluginEntry,
    DEFAULT_REGISTRY_PATH,
    get_registry,
    set_registry,
)

from .templates import (
    PluginTemplateGenerator,
    PluginTemplate,
)

__all__ = [
    # Enums
    "PluginType",
    "PluginState",
    # Data classes
    "PluginMetadata",
    "PluginContext",
    "PluginResult",
    # Base classes
    "MIESCPlugin",
    "DetectorPlugin",
    "AdapterPlugin",
    "ReporterPlugin",
    "TransformerPlugin",
    # Helpers
    "is_plugin_class",
    "get_plugin_classes",
    # Loader
    "PluginLoader",
    "LoadedPlugin",
    "DiscoveryResult",
    "ENTRY_POINT_GROUP",
    "DEFAULT_PLUGIN_DIRS",
    # Registry
    "PluginRegistry",
    "PluginEntry",
    "DEFAULT_REGISTRY_PATH",
    "get_registry",
    "set_registry",
    # Templates
    "PluginTemplateGenerator",
    "PluginTemplate",
]

# Version
__version__ = "1.0.0"
