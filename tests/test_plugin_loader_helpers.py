"""Tests for PluginLoader pure helpers: version compatibility + validation."""

from __future__ import annotations

from miesc.plugins.loader import PluginLoader
from miesc.plugins.protocol import MIESCPlugin, PluginResult, PluginType


class _ValidPlugin(MIESCPlugin):
    @property
    def name(self) -> str:
        return "valid"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.DETECTOR

    def initialize(self, context) -> None:
        pass

    def execute(self, *args, **kwargs) -> PluginResult:
        return PluginResult(success=True, data={})


class TestVersionCompatible:
    def test_min_satisfied(self):
        assert PluginLoader()._version_compatible("5.4.0", "5.0.0") is True

    def test_min_not_satisfied(self):
        assert PluginLoader()._version_compatible("4.0.0", "5.0.0") is False

    def test_equal_min(self):
        assert PluginLoader()._version_compatible("5.4.0", "5.4.0") is True

    def test_within_max_bound(self):
        assert PluginLoader()._version_compatible("4.5.0", "1.0.0", "5.0.0") is True

    def test_exceeds_max_bound(self):
        assert PluginLoader()._version_compatible("5.4.0", "1.0.0", "5.0.0") is False


class TestValidatePlugin:
    def test_valid_plugin_no_errors(self):
        errors = PluginLoader().validate_plugin(_ValidPlugin, "5.4.0")
        assert errors == []

    def test_returns_list(self):
        # Older miesc version still returns a list (possibly with compat warnings)
        assert isinstance(PluginLoader().validate_plugin(_ValidPlugin, "1.0.0"), list)
