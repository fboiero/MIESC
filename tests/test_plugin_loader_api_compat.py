"""
Loader integration tests for Plugin API compatibility enforcement.

The loader must reject a plugin whose declared Plugin API version is
incompatible with the host, with an actionable error, and must not silently
initialize it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from miesc.plugins import (
    DetectorPlugin,
    LoadedPlugin,
    PluginContext,
    PluginLoader,
    PluginState,
)
from miesc.plugins.loader import PluginAPIIncompatibleError
from miesc.plugins.version import PLUGIN_API_VERSION


def _ctx() -> PluginContext:
    return PluginContext(
        miesc_version="6.0.0",
        config={},
        data_dir=Path("/tmp"),
        cache_dir=Path("/tmp"),
    )


class _CompatDetector(DetectorPlugin):
    API_VERSION = PLUGIN_API_VERSION

    @property
    def name(self) -> str:
        return "compat-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def detect(self, code, filename="", options=None):
        return []


class _IncompatMajorDetector(DetectorPlugin):
    API_VERSION = "99.0.0"

    @property
    def name(self) -> str:
        return "incompat-major"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:  # pragma: no cover
        self._context = context

    def detect(self, code, filename="", options=None):  # pragma: no cover
        return []


class _InvalidApiDetector(DetectorPlugin):
    API_VERSION = "not-a-version"

    @property
    def name(self) -> str:
        return "invalid-api"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:  # pragma: no cover
        self._context = context

    def detect(self, code, filename="", options=None):  # pragma: no cover
        return []


class TestLoaderApiCompat:
    def test_compatible_plugin_loads(self):
        loader = PluginLoader()
        lp = LoadedPlugin(plugin_class=_CompatDetector, source="test")
        instance = loader.load_and_initialize(lp, _ctx())
        assert instance.name == "compat-detector"
        assert lp.load_error is None

    def test_incompatible_major_is_rejected(self):
        loader = PluginLoader()
        lp = LoadedPlugin(plugin_class=_IncompatMajorDetector, source="test")
        with pytest.raises(PluginAPIIncompatibleError) as excinfo:
            loader.load_and_initialize(lp, _ctx())
        # Actionable error carries the diagnostic and the plugin name.
        assert "incompat-major" in str(excinfo.value)
        assert "MAJOR versions differ" in str(excinfo.value)
        assert lp.load_error is not None
        assert lp.instance is None

    def test_invalid_api_version_is_rejected(self):
        loader = PluginLoader()
        lp = LoadedPlugin(plugin_class=_InvalidApiDetector, source="test")
        with pytest.raises(PluginAPIIncompatibleError):
            loader.load_and_initialize(lp, _ctx())
        assert lp.load_error is not None

    def test_validate_plugin_reports_api_error(self):
        loader = PluginLoader()
        errors = loader.validate_plugin(_IncompatMajorDetector)
        assert any("MAJOR versions differ" in e for e in errors)

    def test_validate_plugin_ok_for_compatible(self):
        loader = PluginLoader()
        errors = loader.validate_plugin(_CompatDetector)
        assert errors == []

    def test_resolve_api_version_from_class_and_instance(self):
        assert PluginLoader.resolve_api_version(_CompatDetector) == PLUGIN_API_VERSION
        assert PluginLoader.resolve_api_version(_CompatDetector()) == PLUGIN_API_VERSION


class TestBackwardCompat:
    def test_plugin_without_explicit_api_version_defaults_to_host(self):
        """Legacy plugins that never set API_VERSION default to host and load."""

        class _Legacy(DetectorPlugin):
            @property
            def name(self) -> str:
                return "legacy"

            @property
            def version(self) -> str:
                return "1.0.0"

            def initialize(self, context: PluginContext) -> None:
                self._context = context

            def detect(self, code, filename="", options=None):
                return []

        assert _Legacy().api_version == PLUGIN_API_VERSION
        loader = PluginLoader()
        lp = LoadedPlugin(plugin_class=_Legacy, source="test")
        instance = loader.load_and_initialize(lp, _ctx())
        assert instance.state == PluginState.INITIALIZED
