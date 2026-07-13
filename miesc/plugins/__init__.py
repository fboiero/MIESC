"""MIESC Plugin System.

Unified plugin package. Provides plugin management (install/config/compatibility
via ``config`` and ``manager``) plus the plugin protocol, loader, registry,
marketplace, and templates (merged from the former ``miesc.plugins`` on the
src/ -> miesc/ package unification).
"""

from .config import PluginConfig, PluginConfigManager
from .conformance import (
    ConformanceIssue,
    ConformanceReport,
    ConformanceSeverity,
    PluginConformanceChecker,
    check_plugin_conformance,
)
from .loader import (
    DEFAULT_PLUGIN_DIRS,
    ENTRY_POINT_GROUP,
    DiscoveryResult,
    LoadedPlugin,
    PluginAPIIncompatibleError,
    PluginLoader,
)
from .manager import (
    CompatibilityInfo,
    CompatibilityStatus,
    PluginInfo,
    PluginManager,
    VersionConstraint,
    compare_versions,
    get_miesc_version,
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
from .template_generator import (
    PluginTemplate,
    PluginTemplateGenerator,
)
from .version import (
    PLUGIN_API_VERSION,
    ApiCompatResult,
    ApiCompatStatus,
    check_api_compatibility,
    parse_api_version,
)

__all__ = [
    # Management (config + manager)
    "PluginManager",
    "PluginInfo",
    "PluginConfig",
    "PluginConfigManager",
    "CompatibilityStatus",
    "CompatibilityInfo",
    "VersionConstraint",
    "get_miesc_version",
    "compare_versions",
    # Protocol
    "PluginType",
    "PluginState",
    "PluginMetadata",
    "PluginContext",
    "PluginResult",
    "MIESCPlugin",
    "DetectorPlugin",
    "AdapterPlugin",
    "ReporterPlugin",
    "TransformerPlugin",
    "is_plugin_class",
    "get_plugin_classes",
    # Loader
    "PluginLoader",
    "LoadedPlugin",
    "DiscoveryResult",
    "PluginAPIIncompatibleError",
    "ENTRY_POINT_GROUP",
    "DEFAULT_PLUGIN_DIRS",
    # API versioning
    "PLUGIN_API_VERSION",
    "ApiCompatStatus",
    "ApiCompatResult",
    "check_api_compatibility",
    "parse_api_version",
    # Conformance
    "PluginConformanceChecker",
    "ConformanceReport",
    "ConformanceIssue",
    "ConformanceSeverity",
    "check_plugin_conformance",
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

__version__ = "1.0.0"
