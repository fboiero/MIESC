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

from .loader import (
    DEFAULT_PLUGIN_DIRS,
    ENTRY_POINT_GROUP,
    DiscoveryResult,
    LoadedPlugin,
    PluginLoader,
)
from .marketplace import (
    DEFAULT_CACHE_PATH,
    DEFAULT_INDEX_URL,
    MarketplaceClient,
    MarketplaceIndex,
    MarketplacePlugin,
    MarketplaceSearchResult,
    VerificationStatus,
)
from .protocol import (
    AdapterPlugin,
    DetectorPlugin,
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginResult,
    PluginState,
    PluginType,
    ReporterPlugin,
    TransformerPlugin,
    get_plugin_classes,
    is_plugin_class,
)
from .registry import (
    DEFAULT_REGISTRY_PATH,
    PluginEntry,
    PluginRegistry,
    get_registry,
    set_registry,
)
from .templates import (
    PluginTemplate,
    PluginTemplateGenerator,
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
    # Marketplace
    "MarketplaceClient",
    "MarketplacePlugin",
    "MarketplaceIndex",
    "MarketplaceSearchResult",
    "VerificationStatus",
    "DEFAULT_INDEX_URL",
    "DEFAULT_CACHE_PATH",
]

# Version
__version__ = "1.0.0"
