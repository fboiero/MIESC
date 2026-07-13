"""
Plugin Conformance Suite - Verify a Plugin Implements the API Correctly
=======================================================================

A public, self-service harness a community developer runs against their
plugin to confirm it conforms to the MIESC Plugin API before publishing.

The checker validates, without needing MIESC internals:

- the class is a concrete :class:`~miesc.plugins.protocol.MIESCPlugin`
  subclass (no unimplemented abstract methods);
- it can be instantiated;
- required identity properties are present and well-formed
  (``name``, ``version``, ``plugin_type``);
- it declares a valid, host-compatible Plugin API version;
- required methods exist with compatible signatures
  (``initialize``, ``execute`` plus type-specific methods);
- it registers cleanly into a throwaway registry.

Usage:
    from miesc.plugins.conformance import PluginConformanceChecker

    report = PluginConformanceChecker().check(MyDetector)
    if not report.passed:
        for issue in report.failures:
            print(issue.message)

    # Or check a plugin file directly:
    reports = PluginConformanceChecker().check_file("my_plugin.py")

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: July 2026
Version: 1.0.0
"""

from __future__ import annotations

import inspect
import logging
import re
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, Union

from .protocol import (
    MIESCPlugin,
    PluginContext,
    PluginMetadata,
    PluginType,
    is_plugin_class,
)
from .version import (
    PLUGIN_API_VERSION,
    check_api_compatibility,
    parse_api_version,
)

logger = logging.getLogger(__name__)

_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ConformanceSeverity(Enum):
    """Severity of a conformance issue."""

    ERROR = "error"  # Fails conformance.
    WARNING = "warning"  # Recommended, not required.
    INFO = "info"


@dataclass
class ConformanceIssue:
    """A single conformance finding."""

    check: str
    passed: bool
    severity: ConformanceSeverity
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "passed": self.passed,
            "severity": self.severity.value,
            "message": self.message,
        }


@dataclass
class ConformanceReport:
    """Structured pass/fail report for one plugin class."""

    plugin: str
    api_version: str = PLUGIN_API_VERSION
    host_api_version: str = PLUGIN_API_VERSION
    issues: List[ConformanceIssue] = field(default_factory=list)

    def add(
        self,
        check: str,
        passed: bool,
        message: str,
        severity: ConformanceSeverity = ConformanceSeverity.ERROR,
    ) -> ConformanceIssue:
        issue = ConformanceIssue(
            check=check,
            passed=passed,
            severity=severity if not passed else ConformanceSeverity.INFO,
            message=message,
        )
        self.issues.append(issue)
        return issue

    @property
    def failures(self) -> List[ConformanceIssue]:
        """Issues that block conformance (failed ERROR checks)."""
        return [
            i
            for i in self.issues
            if not i.passed and i.severity == ConformanceSeverity.ERROR
        ]

    @property
    def warnings(self) -> List[ConformanceIssue]:
        return [
            i
            for i in self.issues
            if not i.passed and i.severity == ConformanceSeverity.WARNING
        ]

    @property
    def passed(self) -> bool:
        """True when there are no blocking ERROR failures."""
        return len(self.failures) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin": self.plugin,
            "passed": self.passed,
            "api_version": self.api_version,
            "host_api_version": self.host_api_version,
            "failures": len(self.failures),
            "warnings": len(self.warnings),
            "issues": [i.to_dict() for i in self.issues],
        }


# Type-specific method contracts: method name -> (positional sample args,
# keyword sample args) used to verify the signature can accept a canonical
# protocol call via ``inspect.Signature.bind``.
_TYPE_METHODS: Dict[PluginType, List[Tuple[str, tuple, dict]]] = {
    PluginType.DETECTOR: [
        ("detect", ("",), {"filename": "", "options": None}),
    ],
    PluginType.ADAPTER: [
        ("is_available", (), {}),
        ("analyze", ("",), {"options": None}),
    ],
    PluginType.REPORTER: [
        ("generate", ([], {}, "out"), {}),
    ],
    PluginType.TRANSFORMER: [
        ("transform", ("",), {"finding": None, "options": None}),
    ],
}

# Type-specific required (abstract) properties.
_TYPE_PROPERTIES: Dict[PluginType, List[str]] = {
    PluginType.ADAPTER: ["tool_name"],
    PluginType.REPORTER: ["format_name"],
}


class PluginConformanceChecker:
    """Runs the conformance suite against a plugin class, instance, or file."""

    def __init__(self, host_api_version: str = PLUGIN_API_VERSION) -> None:
        self.host_api_version = host_api_version

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def check(
        self,
        target: Union[Type[MIESCPlugin], MIESCPlugin, str, Path],
    ) -> Union[ConformanceReport, List[ConformanceReport]]:
        """Check a plugin class, instance, or file path.

        Returns a single :class:`ConformanceReport` for a class/instance, or a
        list of reports for a file (which may contain several plugin classes).
        """
        if isinstance(target, (str, Path)):
            return self.check_file(target)
        if isinstance(target, MIESCPlugin):
            return self.check_class(type(target))
        return self.check_class(target)

    def check_file(self, filepath: Union[str, Path]) -> List[ConformanceReport]:
        """Load a plugin file and run conformance on every plugin class found."""
        # Local import to avoid a circular import at module load time.
        from .loader import PluginLoader

        loader = PluginLoader()
        loaded = loader.load_plugin_file(filepath)
        if not loaded:
            report = ConformanceReport(plugin=str(filepath))
            report.add(
                "discovery",
                False,
                f"No MIESCPlugin subclasses found in {filepath}. Ensure the "
                "file defines a concrete plugin class.",
            )
            return [report]
        return [self.check_class(lp.plugin_class) for lp in loaded]

    def check_class(self, plugin_class: Type[MIESCPlugin]) -> ConformanceReport:
        """Run the full conformance suite against a single plugin class."""
        name = getattr(plugin_class, "__name__", str(plugin_class))
        report = ConformanceReport(plugin=name, host_api_version=self.host_api_version)

        # 1. Structural: concrete MIESCPlugin subclass.
        if not isinstance(plugin_class, type) or not issubclass(
            plugin_class, MIESCPlugin
        ):
            report.add(
                "subclass",
                False,
                f"{name} is not a subclass of MIESCPlugin. Extend MIESCPlugin "
                "or a specialized base (DetectorPlugin, AdapterPlugin, ...).",
            )
            return report
        report.add("subclass", True, f"{name} subclasses MIESCPlugin.")

        abstract = getattr(plugin_class, "__abstractmethods__", None)
        if abstract:
            report.add(
                "abstract_methods",
                False,
                f"{name} does not implement required abstract members: "
                f"{', '.join(sorted(abstract))}.",
            )
            return report
        report.add("abstract_methods", True, "All abstract members implemented.")

        if not is_plugin_class(plugin_class):
            report.add(
                "plugin_class",
                False,
                f"{name} is not a valid concrete plugin class.",
            )
            return report

        # 2. Instantiation.
        try:
            instance = plugin_class()
        except Exception as e:
            report.add(
                "instantiate",
                False,
                f"{name} cannot be instantiated with no arguments: {e}",
            )
            return report
        report.add("instantiate", True, f"{name} instantiates cleanly.")

        # 3. Identity properties.
        self._check_identity(instance, report)

        # 4. API version + compatibility.
        self._check_api_version(instance, report)

        # 5. Base + type-specific methods.
        self._check_methods(instance, report)

        # 6. Type-specific properties.
        self._check_type_properties(instance, report)

        # 7. Registration smoke test.
        self._check_registration(instance, report)

        return report

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------
    def _check_identity(self, instance: MIESCPlugin, report: ConformanceReport) -> None:
        # name
        try:
            pname = instance.name
            if not pname or not isinstance(pname, str):
                report.add("name", False, "Plugin 'name' must be a non-empty string.")
            else:
                report.add("name", True, f"name = {pname!r}")
                if not _NAME_RE.match(pname):
                    report.add(
                        "name_format",
                        False,
                        f"name {pname!r} should be lowercase, hyphen-separated "
                        "(e.g. 'my-detector').",
                        severity=ConformanceSeverity.WARNING,
                    )
        except Exception as e:
            report.add("name", False, f"Error reading 'name': {e}")

        # version
        try:
            pver = instance.version
            if not pver or not isinstance(pver, str):
                report.add("version", False, "Plugin 'version' must be a non-empty string.")
            elif parse_api_version(pver) is None:
                report.add(
                    "version",
                    False,
                    f"Plugin 'version' {pver!r} is not valid semver "
                    "(MAJOR.MINOR.PATCH).",
                    severity=ConformanceSeverity.WARNING,
                )
            else:
                report.add("version", True, f"version = {pver!r}")
        except Exception as e:
            report.add("version", False, f"Error reading 'version': {e}")

        # plugin_type
        try:
            ptype = instance.plugin_type
            if not isinstance(ptype, PluginType):
                report.add(
                    "plugin_type",
                    False,
                    "Plugin 'plugin_type' must be a PluginType enum member.",
                )
            else:
                report.add("plugin_type", True, f"plugin_type = {ptype.value}")
        except Exception as e:
            report.add("plugin_type", False, f"Error reading 'plugin_type': {e}")

    def _check_api_version(
        self, instance: MIESCPlugin, report: ConformanceReport
    ) -> None:
        try:
            declared = instance.api_version
        except Exception as e:
            report.add("api_version", False, f"Error reading 'api_version': {e}")
            return

        if not declared or not isinstance(declared, str):
            report.add(
                "api_version",
                False,
                "Plugin must declare an 'api_version' (set the API_VERSION "
                "class attribute to the Plugin API version it targets).",
            )
            return

        report.api_version = declared

        if parse_api_version(declared) is None:
            report.add(
                "api_version",
                False,
                f"Declared api_version {declared!r} is not valid semver "
                "(MAJOR.MINOR.PATCH).",
            )
            return
        report.add("api_version", True, f"Declares Plugin API v{declared}.")

        compat = check_api_compatibility(declared, self.host_api_version)
        report.add("api_compatibility", compat.compatible, compat.message)

    def _check_methods(self, instance: MIESCPlugin, report: ConformanceReport) -> None:
        # Base methods every plugin must provide.
        self._check_callable(instance, "initialize", (_DummyContext(),), {}, report)
        self._check_callable(instance, "execute", (), {}, report)

        # Type-specific methods.
        try:
            ptype = instance.plugin_type
        except Exception:
            return
        for method_name, pos, kw in _TYPE_METHODS.get(ptype, []):
            self._check_callable(instance, method_name, pos, kw, report)

    def _check_callable(
        self,
        instance: MIESCPlugin,
        method_name: str,
        sample_pos: tuple,
        sample_kw: dict,
        report: ConformanceReport,
    ) -> None:
        method = getattr(instance, method_name, None)
        if method is None or not callable(method):
            report.add(
                f"method:{method_name}",
                False,
                f"Required method '{method_name}' is missing or not callable.",
            )
            return
        try:
            sig = inspect.signature(method)
            sig.bind(*sample_pos, **sample_kw)
        except TypeError as e:
            report.add(
                f"method:{method_name}",
                False,
                f"Method '{method_name}' has an incompatible signature: {e}. "
                f"Expected to accept ({_describe_args(sample_pos, sample_kw)}).",
            )
            return
        except Exception as e:  # pragma: no cover - defensive
            report.add(
                f"method:{method_name}",
                False,
                f"Could not inspect method '{method_name}': {e}",
            )
            return
        report.add(f"method:{method_name}", True, f"'{method_name}' signature OK.")

    def _check_type_properties(
        self, instance: MIESCPlugin, report: ConformanceReport
    ) -> None:
        try:
            ptype = instance.plugin_type
        except Exception:
            return
        for prop in _TYPE_PROPERTIES.get(ptype, []):
            try:
                value = getattr(instance, prop)
                if not value or not isinstance(value, str):
                    report.add(
                        f"property:{prop}",
                        False,
                        f"Required property '{prop}' must return a non-empty string.",
                    )
                else:
                    report.add(f"property:{prop}", True, f"{prop} = {value!r}")
            except Exception as e:
                report.add(f"property:{prop}", False, f"Error reading '{prop}': {e}")

    def _check_registration(
        self, instance: MIESCPlugin, report: ConformanceReport
    ) -> None:
        # Local import to avoid a circular import at module load time.
        from .registry import PluginRegistry

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ctx = PluginContext(
                miesc_version="0.0.0",
                config={},
                data_dir=tmp_path,
                cache_dir=tmp_path,
            )
            try:
                instance.initialize(ctx)
                instance._set_initialized(ctx)
            except Exception as e:
                report.add(
                    "registration",
                    False,
                    f"Plugin failed to initialize with a context: {e}",
                )
                return

            try:
                metadata = instance.get_metadata()
                if not isinstance(metadata, PluginMetadata):
                    report.add(
                        "metadata",
                        False,
                        "get_metadata() must return a PluginMetadata instance.",
                    )
                else:
                    report.add("metadata", True, "get_metadata() returns PluginMetadata.")
            except Exception as e:
                report.add("metadata", False, f"get_metadata() raised: {e}")

            try:
                registry = PluginRegistry(
                    registry_path=tmp_path / "registry.json", auto_load=False
                )
                registry.register(instance, enabled=True)
                if instance.name not in registry:
                    report.add(
                        "registration",
                        False,
                        "Plugin did not appear in the registry after register().",
                    )
                else:
                    report.add("registration", True, "Plugin registers cleanly.")
            except Exception as e:
                report.add("registration", False, f"Registration failed: {e}")


class _DummyContext(PluginContext):
    """Minimal context for signature-binding checks (never executed)."""

    def __init__(self) -> None:
        super().__init__(
            miesc_version="0.0.0",
            config={},
            data_dir=Path("."),
            cache_dir=Path("."),
        )


def _describe_args(pos: tuple, kw: dict) -> str:
    parts = [f"arg{i}" for i in range(len(pos))]
    parts.extend(f"{k}=..." for k in kw)
    return ", ".join(parts) if parts else "no arguments"


def check_plugin_conformance(
    target: Union[Type[MIESCPlugin], MIESCPlugin, str, Path],
    host_api_version: str = PLUGIN_API_VERSION,
) -> Union[ConformanceReport, List[ConformanceReport]]:
    """Convenience wrapper: run conformance with a default checker."""
    return PluginConformanceChecker(host_api_version=host_api_version).check(target)


__all__ = [
    "ConformanceSeverity",
    "ConformanceIssue",
    "ConformanceReport",
    "PluginConformanceChecker",
    "check_plugin_conformance",
]
