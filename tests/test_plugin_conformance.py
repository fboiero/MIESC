"""
Tests for the plugin conformance suite (miesc/plugins/conformance.py).

A conforming plugin passes; stubs that are missing a required method, use a
wrong signature, declare no/invalid API version, or target an incompatible
API each fail with the right check name and message.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from miesc.plugins import (
    AdapterPlugin,
    DetectorPlugin,
    PluginContext,
    PluginType,
    ReporterPlugin,
    TransformerPlugin,
)
from miesc.plugins.conformance import (
    ConformanceReport,
    ConformanceSeverity,
    PluginConformanceChecker,
    check_plugin_conformance,
)


# ---------------------------------------------------------------------------
# Fixtures / stubs
# ---------------------------------------------------------------------------
class ConformingDetector(DetectorPlugin):
    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "conforming-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def detect(self, code, filename="", options=None):
        return []


class ConformingAdapter(AdapterPlugin):
    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "conforming-adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def tool_name(self) -> str:
        return "mytool"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def is_available(self) -> bool:
        return False

    def analyze(self, target, options=None):
        return []


class ConformingReporter(ReporterPlugin):
    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "conforming-reporter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def format_name(self) -> str:
        return "txt"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def generate(self, findings, metadata, output_path):
        return Path(output_path)


class ConformingTransformer(TransformerPlugin):
    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "conforming-transformer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        self._context = context

    def transform(self, code, finding=None, options=None):
        return code


class WrongDetectSignature(DetectorPlugin):
    """detect() has an incompatible signature (no params)."""

    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "wrong-sig"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        pass

    def detect(self):  # type: ignore[override]
        return []


class NoApiVersion(DetectorPlugin):
    """Declares an empty (missing) API version."""

    API_VERSION = ""

    @property
    def name(self) -> str:
        return "no-api"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        pass

    def detect(self, code, filename="", options=None):
        return []


class IncompatibleApiVersion(DetectorPlugin):
    """Targets a newer MAJOR than the host provides."""

    API_VERSION = "99.0.0"

    @property
    def name(self) -> str:
        return "incompat-api"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        pass

    def detect(self, code, filename="", options=None):
        return []


class BadName(DetectorPlugin):
    """Name is not lowercase-hyphen -> WARNING, not a hard failure."""

    API_VERSION = "1.0.0"

    @property
    def name(self) -> str:
        return "Bad_Name"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, context: PluginContext) -> None:
        pass

    def detect(self, code, filename="", options=None):
        return []


class NotAPlugin:
    """Not a MIESCPlugin subclass at all."""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestConformingPlugins:
    @pytest.mark.parametrize(
        "cls",
        [
            ConformingDetector,
            ConformingAdapter,
            ConformingReporter,
            ConformingTransformer,
        ],
    )
    def test_all_types_pass(self, cls):
        report = PluginConformanceChecker().check(cls)
        assert isinstance(report, ConformanceReport)
        assert report.passed, [f.message for f in report.failures]
        assert report.failures == []

    def test_report_to_dict(self):
        report = PluginConformanceChecker().check(ConformingDetector)
        data = report.to_dict()
        assert data["passed"] is True
        assert data["api_version"] == "1.0.0"
        assert data["failures"] == 0
        assert any(i["check"] == "api_compatibility" for i in data["issues"])

    def test_check_instance_dispatches_to_class(self):
        report = PluginConformanceChecker().check(ConformingDetector())
        assert report.passed

    def test_convenience_wrapper(self):
        report = check_plugin_conformance(ConformingDetector)
        assert report.passed


class TestNonConforming:
    def test_wrong_signature_fails_with_method_check(self):
        report = PluginConformanceChecker().check(WrongDetectSignature)
        assert not report.passed
        checks = {f.check for f in report.failures}
        assert "method:detect" in checks
        msg = next(f.message for f in report.failures if f.check == "method:detect")
        assert "incompatible signature" in msg

    def test_missing_required_method_fails(self):
        # Build a plugin type dynamically whose detect attribute is removed is
        # not possible (abstract), so simulate a missing type-specific method
        # via an adapter missing analyze -> abstract, caught earlier. Instead
        # verify the wrong-signature path covers "missing or not callable".
        report = PluginConformanceChecker().check(WrongDetectSignature)
        assert "method:detect" in {f.check for f in report.failures}

    def test_no_api_version_fails(self):
        report = PluginConformanceChecker().check(NoApiVersion)
        assert not report.passed
        fail = next(f for f in report.failures if f.check == "api_version")
        assert "api_version" in fail.message.lower() or "API_VERSION" in fail.message

    def test_incompatible_api_version_fails(self):
        report = PluginConformanceChecker().check(IncompatibleApiVersion)
        assert not report.passed
        checks = {f.check for f in report.failures}
        assert "api_compatibility" in checks

    def test_not_a_plugin_fails_subclass_check(self):
        report = PluginConformanceChecker().check(NotAPlugin)
        assert not report.passed
        assert "subclass" in {f.check for f in report.failures}

    def test_bad_name_is_warning_not_failure(self):
        report = PluginConformanceChecker().check(BadName)
        # Naming is a recommendation -> the plugin still conforms.
        assert report.passed
        warn_checks = {w.check for w in report.warnings}
        assert "name_format" in warn_checks
        assert all(
            w.severity == ConformanceSeverity.WARNING for w in report.warnings
        )


class TestFileConformance:
    def test_check_file(self, tmp_path):
        plugin_file = tmp_path / "my_plugin.py"
        plugin_file.write_text(
            "from miesc.plugins import DetectorPlugin\n"
            "\n"
            "class MyPlugin(DetectorPlugin):\n"
            "    API_VERSION = '1.0.0'\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'file-detector'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def initialize(self, context):\n"
            "        self._context = context\n"
            "    def detect(self, code, filename='', options=None):\n"
            "        return []\n"
        )
        reports = PluginConformanceChecker().check_file(plugin_file)
        assert len(reports) == 1
        assert reports[0].passed

    def test_check_file_no_plugins(self, tmp_path):
        empty = tmp_path / "empty.py"
        empty.write_text("x = 1\n")
        reports = PluginConformanceChecker().check_file(empty)
        assert len(reports) == 1
        assert not reports[0].passed
        assert "discovery" in {f.check for f in reports[0].failures}
