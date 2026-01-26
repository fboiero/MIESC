"""
Plugin Protocol - Base Interface for MIESC Plugins
===================================================

Defines the plugin interface and types for extending MIESC functionality.

Plugin Types:
- DETECTOR: Custom vulnerability detectors
- ADAPTER: Tool adapters for external security tools
- REPORTER: Custom report format generators
- TRANSFORMER: Code transformers and fixers

Usage:
    from src.plugins.protocol import MIESCPlugin, PluginType

    class MyDetector(MIESCPlugin):
        @property
        def name(self) -> str:
            return "my-detector"

        @property
        def version(self) -> str:
            return "1.0.0"

        @property
        def plugin_type(self) -> PluginType:
            return PluginType.DETECTOR

        def initialize(self, context: PluginContext) -> None:
            self.config = context.config

        def execute(self, *args, **kwargs) -> Any:
            # Detection logic here
            pass

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, Union
from datetime import datetime

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Types of MIESC plugins."""
    DETECTOR = "detector"       # Custom vulnerability detectors
    ADAPTER = "adapter"         # Tool adapters for external tools
    REPORTER = "reporter"       # Custom report format generators
    TRANSFORMER = "transformer" # Code transformers and fixers
    ANALYZER = "analyzer"       # Additional analysis modules
    HOOK = "hook"               # Lifecycle hooks


class PluginState(Enum):
    """Plugin lifecycle states."""
    UNLOADED = "unloaded"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class PluginMetadata:
    """Metadata describing a plugin."""
    name: str
    version: str
    plugin_type: PluginType
    description: str = ""
    author: str = ""
    email: str = ""
    homepage: str = ""
    license: str = ""
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    min_miesc_version: str = "4.0.0"
    max_miesc_version: Optional[str] = None
    entry_point: Optional[str] = None
    config_schema: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "plugin_type": self.plugin_type.value,
            "description": self.description,
            "author": self.author,
            "email": self.email,
            "homepage": self.homepage,
            "license": self.license,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "min_miesc_version": self.min_miesc_version,
            "max_miesc_version": self.max_miesc_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginMetadata":
        """Create from dictionary."""
        plugin_type = data.get("plugin_type", "detector")
        if isinstance(plugin_type, str):
            plugin_type = PluginType(plugin_type)

        return cls(
            name=data["name"],
            version=data["version"],
            plugin_type=plugin_type,
            description=data.get("description", ""),
            author=data.get("author", ""),
            email=data.get("email", ""),
            homepage=data.get("homepage", ""),
            license=data.get("license", ""),
            tags=data.get("tags", []),
            dependencies=data.get("dependencies", []),
            min_miesc_version=data.get("min_miesc_version", "4.0.0"),
            max_miesc_version=data.get("max_miesc_version"),
            entry_point=data.get("entry_point"),
            config_schema=data.get("config_schema"),
        )


@dataclass
class PluginContext:
    """Context provided to plugins during initialization."""
    miesc_version: str
    config: Dict[str, Any]
    data_dir: Path
    cache_dir: Path
    log_level: str = "INFO"
    debug: bool = False

    # Callbacks for plugin communication
    on_finding: Optional[Callable[[Dict[str, Any]], None]] = None
    on_progress: Optional[Callable[[float, str], None]] = None
    on_log: Optional[Callable[[str, str], None]] = None

    # Access to MIESC services
    services: Dict[str, Any] = field(default_factory=dict)

    def get_service(self, name: str) -> Optional[Any]:
        """Get a MIESC service by name."""
        return self.services.get(name)

    def report_finding(self, finding: Dict[str, Any]) -> None:
        """Report a finding to MIESC."""
        if self.on_finding:
            self.on_finding(finding)

    def report_progress(self, progress: float, message: str = "") -> None:
        """Report progress (0.0 to 1.0)."""
        if self.on_progress:
            self.on_progress(progress, message)

    def log(self, level: str, message: str) -> None:
        """Log a message."""
        if self.on_log:
            self.on_log(level, message)


@dataclass
class PluginResult:
    """Result from plugin execution."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    execution_time_ms: float = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class MIESCPlugin(ABC):
    """
    Base class for all MIESC plugins.

    Plugins must implement:
    - name: Unique plugin identifier
    - version: Semantic version string
    - plugin_type: Type of plugin (detector, adapter, etc.)
    - initialize(): Setup with context
    - execute(): Main plugin logic

    Optional:
    - cleanup(): Resource cleanup
    - validate_config(): Config validation
    - get_metadata(): Extended metadata
    """

    _state: PluginState = PluginState.UNLOADED
    _context: Optional[PluginContext] = None
    _config: Dict[str, Any] = field(default_factory=dict)

    def __init__(self):
        """Initialize plugin instance."""
        self._state = PluginState.LOADED
        self._config = {}
        self._context = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name (lowercase, hyphen-separated)."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version (semantic versioning)."""
        ...

    @property
    @abstractmethod
    def plugin_type(self) -> PluginType:
        """Type of plugin."""
        ...

    @property
    def description(self) -> str:
        """Plugin description."""
        return ""

    @property
    def author(self) -> str:
        """Plugin author."""
        return ""

    @property
    def state(self) -> PluginState:
        """Current plugin state."""
        return self._state

    @property
    def config(self) -> Dict[str, Any]:
        """Plugin configuration."""
        return self._config

    @property
    def context(self) -> Optional[PluginContext]:
        """Plugin context."""
        return self._context

    @abstractmethod
    def initialize(self, context: PluginContext) -> None:
        """
        Initialize the plugin with context.

        Called once when plugin is loaded. Use this to:
        - Store context reference
        - Load configuration
        - Initialize resources
        - Connect to services

        Args:
            context: Plugin context with config, paths, and services
        """
        ...

    @abstractmethod
    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """
        Execute the plugin's main functionality.

        Args:
            *args: Positional arguments (varies by plugin type)
            **kwargs: Keyword arguments (varies by plugin type)

        Returns:
            PluginResult with success status and data
        """
        ...

    def cleanup(self) -> None:
        """
        Clean up plugin resources.

        Called when plugin is unloaded. Override to:
        - Close connections
        - Release resources
        - Save state
        """
        pass

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate plugin configuration.

        Args:
            config: Configuration to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        return []

    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.

        Returns:
            PluginMetadata instance
        """
        return PluginMetadata(
            name=self.name,
            version=self.version,
            plugin_type=self.plugin_type,
            description=self.description,
            author=self.author,
        )

    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the plugin.

        Args:
            config: Configuration dictionary
        """
        errors = self.validate_config(config)
        if errors:
            raise ValueError(f"Invalid config: {'; '.join(errors)}")
        self._config = config

    def enable(self) -> None:
        """Enable the plugin."""
        if self._state == PluginState.INITIALIZED:
            self._state = PluginState.ENABLED
            logger.debug(f"Plugin {self.name} enabled")

    def disable(self) -> None:
        """Disable the plugin."""
        if self._state == PluginState.ENABLED:
            self._state = PluginState.DISABLED
            logger.debug(f"Plugin {self.name} disabled")

    def _set_initialized(self, context: PluginContext) -> None:
        """Mark plugin as initialized (called by loader)."""
        self._context = context
        self._state = PluginState.INITIALIZED


# ============================================================================
# Specialized Plugin Base Classes
# ============================================================================


class DetectorPlugin(MIESCPlugin):
    """Base class for vulnerability detector plugins."""

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.DETECTOR

    @abstractmethod
    def detect(
        self,
        code: str,
        filename: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in code.

        Args:
            code: Source code to analyze
            filename: Optional filename for context
            options: Detection options

        Returns:
            List of finding dictionaries
        """
        ...

    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """Execute detection."""
        code = kwargs.get("code", args[0] if args else "")
        filename = kwargs.get("filename", "")
        options = kwargs.get("options", {})

        try:
            findings = self.detect(code, filename, options)
            return PluginResult(
                success=True,
                data=findings,
                metadata={"finding_count": len(findings)},
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e),
            )


class AdapterPlugin(MIESCPlugin):
    """Base class for tool adapter plugins."""

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.ADAPTER

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the external tool."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is available."""
        ...

    @abstractmethod
    def analyze(
        self,
        target: Union[str, Path],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run the tool and return findings.

        Args:
            target: File or directory to analyze
            options: Tool-specific options

        Returns:
            List of normalized findings
        """
        ...

    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """Execute tool analysis."""
        target = kwargs.get("target", args[0] if args else "")
        options = kwargs.get("options", {})

        if not self.is_available():
            return PluginResult(
                success=False,
                error=f"Tool {self.tool_name} is not available",
            )

        try:
            findings = self.analyze(target, options)
            return PluginResult(
                success=True,
                data=findings,
                metadata={
                    "tool": self.tool_name,
                    "finding_count": len(findings),
                },
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e),
            )


class ReporterPlugin(MIESCPlugin):
    """Base class for report generator plugins."""

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.REPORTER

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Report format name (e.g., 'pdf', 'html', 'sarif')."""
        ...

    @property
    def file_extension(self) -> str:
        """File extension for the report."""
        return self.format_name

    @abstractmethod
    def generate(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        output_path: Union[str, Path],
    ) -> Path:
        """
        Generate a report.

        Args:
            findings: List of findings to include
            metadata: Report metadata (title, date, etc.)
            output_path: Output file path

        Returns:
            Path to generated report
        """
        ...

    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """Execute report generation."""
        findings = kwargs.get("findings", [])
        metadata = kwargs.get("metadata", {})
        output_path = kwargs.get("output_path", "")

        try:
            path = self.generate(findings, metadata, output_path)
            return PluginResult(
                success=True,
                data=str(path),
                metadata={"format": self.format_name},
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e),
            )


class TransformerPlugin(MIESCPlugin):
    """Base class for code transformer plugins."""

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.TRANSFORMER

    @abstractmethod
    def transform(
        self,
        code: str,
        finding: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Transform code (e.g., apply fix).

        Args:
            code: Source code to transform
            finding: Optional finding to fix
            options: Transformation options

        Returns:
            Transformed code
        """
        ...

    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """Execute transformation."""
        code = kwargs.get("code", args[0] if args else "")
        finding = kwargs.get("finding")
        options = kwargs.get("options", {})

        try:
            result = self.transform(code, finding, options)
            return PluginResult(
                success=True,
                data=result,
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e),
            )


# ============================================================================
# Plugin Discovery Helpers
# ============================================================================


def is_plugin_class(cls: type) -> bool:
    """Check if a class is a valid MIESC plugin."""
    if not isinstance(cls, type):
        return False
    if cls is MIESCPlugin:
        return False
    if not issubclass(cls, MIESCPlugin):
        return False
    if getattr(cls, "__abstractmethods__", None):
        return False
    return True


def get_plugin_classes(module: Any) -> List[Type[MIESCPlugin]]:
    """Get all plugin classes from a module."""
    plugins = []
    for name in dir(module):
        obj = getattr(module, name)
        if is_plugin_class(obj):
            plugins.append(obj)
    return plugins


# ============================================================================
# Export
# ============================================================================

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
]
