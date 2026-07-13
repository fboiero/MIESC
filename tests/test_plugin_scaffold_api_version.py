"""
Tests that the plugin scaffold declares the current Plugin API version and
that generated plugins pass the conformance suite.
"""

from __future__ import annotations

import pytest

from miesc.plugins import PLUGIN_API_VERSION, PluginType
from miesc.plugins.conformance import PluginConformanceChecker
from miesc.plugins.template_generator import (
    PluginTemplate,
    PluginTemplateGenerator,
)


class TestScaffoldApiVersion:
    def test_template_defaults_to_current_api_version(self):
        template = PluginTemplate(name="x", plugin_type=PluginType.DETECTOR)
        assert template.api_version == PLUGIN_API_VERSION

    @pytest.mark.parametrize(
        "ptype",
        [
            PluginType.DETECTOR,
            PluginType.ADAPTER,
            PluginType.REPORTER,
            PluginType.TRANSFORMER,
        ],
    )
    def test_generated_plugin_declares_api_version(self, tmp_path, ptype):
        gen = PluginTemplateGenerator()
        plugin_dir = gen.create_plugin(
            name="sample",
            plugin_type=ptype,
            output_dir=tmp_path,
            description="Sample plugin",
            author="Tester",
        )
        module_dir = plugin_dir / "sample"
        source = (module_dir / "plugin.py").read_text()
        assert f'API_VERSION = "{PLUGIN_API_VERSION}"' in source

    def test_detector_metadata_carries_api_version(self, tmp_path):
        gen = PluginTemplateGenerator()
        plugin_dir = gen.create_plugin(
            name="metadet",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
        )
        source = (plugin_dir / "metadet" / "plugin.py").read_text()
        assert f'api_version="{PLUGIN_API_VERSION}"' in source

    def test_generated_test_checks_api_version(self, tmp_path):
        gen = PluginTemplateGenerator()
        plugin_dir = gen.create_plugin(
            name="tested",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
        )
        test_source = (plugin_dir / "tests" / "test_tested.py").read_text()
        assert "test_plugin_api_version" in test_source
        assert "PLUGIN_API_VERSION" in test_source

    def test_generated_plugin_is_conformant(self, tmp_path):
        """Load a scaffolded plugin file and confirm it passes conformance."""
        gen = PluginTemplateGenerator()
        plugin_dir = gen.create_plugin(
            name="confdet",
            plugin_type=PluginType.DETECTOR,
            output_dir=tmp_path,
        )
        plugin_file = plugin_dir / "confdet" / "plugin.py"
        reports = PluginConformanceChecker().check_file(plugin_file)
        assert len(reports) == 1
        assert reports[0].passed, [f.message for f in reports[0].failures]
