"""
Tests for the `miesc plugins conformance` CLI command.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from miesc.cli.commands.plugins import plugins

_CONFORMING = (
    "from miesc.plugins import DetectorPlugin\n"
    "\n"
    "class GoodPlugin(DetectorPlugin):\n"
    "    API_VERSION = '1.0.0'\n"
    "    @property\n"
    "    def name(self):\n"
    "        return 'good-detector'\n"
    "    @property\n"
    "    def version(self):\n"
    "        return '1.0.0'\n"
    "    def initialize(self, context):\n"
    "        self._context = context\n"
    "    def detect(self, code, filename='', options=None):\n"
    "        return []\n"
)

_NON_CONFORMING = (
    "from miesc.plugins import DetectorPlugin\n"
    "\n"
    "class BadPlugin(DetectorPlugin):\n"
    "    API_VERSION = '99.0.0'\n"  # incompatible major
    "    @property\n"
    "    def name(self):\n"
    "        return 'bad-detector'\n"
    "    @property\n"
    "    def version(self):\n"
    "        return '1.0.0'\n"
    "    def initialize(self, context):\n"
    "        self._context = context\n"
    "    def detect(self, code, filename='', options=None):\n"
    "        return []\n"
)


class TestConformanceCommand:
    def test_conformance_registered(self):
        runner = CliRunner()
        result = runner.invoke(plugins, ["conformance", "--help"])
        assert result.exit_code == 0
        assert "conform" in result.output.lower()

    def test_conforming_plugin_exits_zero(self, tmp_path):
        pf = tmp_path / "good.py"
        pf.write_text(_CONFORMING)
        runner = CliRunner()
        result = runner.invoke(plugins, ["conformance", str(pf)])
        assert result.exit_code == 0
        assert "CONFORMANT" in result.output

    def test_non_conforming_plugin_exits_nonzero(self, tmp_path):
        pf = tmp_path / "bad.py"
        pf.write_text(_NON_CONFORMING)
        runner = CliRunner()
        result = runner.invoke(plugins, ["conformance", str(pf)])
        assert result.exit_code == 1
        assert "NON-CONFORMANT" in result.output

    def test_json_output(self, tmp_path):
        pf = tmp_path / "good.py"
        pf.write_text(_CONFORMING)
        runner = CliRunner()
        result = runner.invoke(plugins, ["conformance", str(pf), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["passed"] is True
        assert payload["host_api_version"]
        assert len(payload["reports"]) == 1

    def test_json_output_failure_exit_code(self, tmp_path):
        pf = tmp_path / "bad.py"
        pf.write_text(_NON_CONFORMING)
        runner = CliRunner()
        result = runner.invoke(plugins, ["conformance", str(pf), "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["passed"] is False
