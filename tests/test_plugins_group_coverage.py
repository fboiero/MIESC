"""Behavioral coverage for the ``miesc plugins`` command group.

Targets the previously-untested command paths in
``miesc.cli.commands.plugins`` (install, uninstall, create, search, path,
runtime, new). The ``PluginManager`` / registry / template generator
collaborators are mocked so no PyPI request, subprocess, or filesystem
mutation outside ``tmp_path`` happens. Assertions check real exit codes and
emitted messages.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.plugins import plugins
from miesc.plugins import CompatibilityStatus


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _compat(status, message=""):
    return SimpleNamespace(status=status, message=message)


# ===========================================================================
# install
# ===========================================================================


class TestPluginsInstall:
    def test_install_compatible_success(self, runner):
        manager = MagicMock()
        manager.resolve_marketplace_slug.return_value = None
        manager.check_pypi_compatibility.return_value = (
            _compat(CompatibilityStatus.COMPATIBLE),
            "1.0.0",
        )
        manager.install.return_value = (True, "Installed miesc-defi 1.0.0")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["install", "miesc-defi"])
        assert result.exit_code == 0, result.output
        assert "Installed" in result.output
        manager.install.assert_called_once()

    def test_install_incompatible_aborts(self, runner):
        manager = MagicMock()
        manager.resolve_marketplace_slug.return_value = None
        manager.check_pypi_compatibility.return_value = (
            _compat(CompatibilityStatus.INCOMPATIBLE, "needs MIESC 7"),
            "9.9.9",
        )
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["install", "miesc-future"])
        assert result.exit_code == 1
        assert "incompatible" in result.output.lower()
        manager.install.assert_not_called()

    def test_install_resolves_marketplace_slug(self, runner):
        manager = MagicMock()
        manager.resolve_marketplace_slug.return_value = "miesc-defi-detectors"
        manager.check_pypi_compatibility.return_value = (
            _compat(CompatibilityStatus.WARNING, "untested"),
            "1.0.0",
        )
        manager.install.return_value = (True, "ok")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["install", "defi"])
        assert result.exit_code == 0, result.output
        assert "Resolved marketplace" in result.output
        # The resolved name must reach install().
        assert manager.install.call_args[0][0] == "miesc-defi-detectors"

    def test_install_failure_exits_1(self, runner):
        manager = MagicMock()
        manager.resolve_marketplace_slug.return_value = None
        manager.install.return_value = (False, "pip error")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["install", "miesc-x", "--no-check"])
        assert result.exit_code == 1
        assert "pip error" in result.output


# ===========================================================================
# uninstall
# ===========================================================================


class TestPluginsUninstall:
    def test_uninstall_declined_by_prompt(self, runner):
        manager = MagicMock()
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["uninstall", "miesc-x"], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.output
        manager.uninstall.assert_not_called()

    def test_uninstall_confirmed_success(self, runner):
        manager = MagicMock()
        manager.uninstall.return_value = (True, "Uninstalled miesc-x")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["uninstall", "miesc-x", "-y"])
        assert result.exit_code == 0, result.output
        assert "Uninstalled" in result.output

    def test_uninstall_failure_exits_1(self, runner):
        manager = MagicMock()
        manager.uninstall.return_value = (False, "not found")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["uninstall", "miesc-x", "-y"])
        assert result.exit_code == 1
        assert "not found" in result.output


# ===========================================================================
# create
# ===========================================================================


class TestPluginsCreate:
    def test_create_success(self, runner, tmp_path):
        manager = MagicMock()
        manager.create_plugin_scaffold.return_value = tmp_path / "my-detector"
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["create", "my-detector", "-o", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "Created plugin at" in result.output

    def test_create_failure_exits_1(self, runner, tmp_path):
        manager = MagicMock()
        manager.create_plugin_scaffold.side_effect = OSError("disk full")
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["create", "bad", "-o", str(tmp_path)])
        assert result.exit_code == 1
        assert "Failed to create plugin" in result.output


# ===========================================================================
# search
# ===========================================================================


class TestPluginsSearch:
    def test_search_no_results(self, runner):
        manager = MagicMock()
        manager.search_marketplace.return_value = []
        manager.search_pypi.return_value = []
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["search", "nonexistent"])
        assert result.exit_code == 0
        assert "No plugins found" in result.output

    def test_search_with_results(self, runner):
        manager = MagicMock()
        manager.search_marketplace.return_value = [
            {
                "source": "marketplace",
                "pypi_package": "miesc-defi",
                "name": "defi",
                "version": "1.0.0",
                "description": "DeFi detectors",
                "verification_status": "verified",
            }
        ]
        manager.search_pypi.return_value = [
            {"name": "miesc-nft", "version": "0.1.0", "description": "NFT"}
        ]
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["search", "detect"])
        assert result.exit_code == 0, result.output
        assert "miesc-defi" in result.output
        assert "miesc-nft" in result.output

    def test_search_marketplace_only_skips_pypi(self, runner):
        manager = MagicMock()
        manager.search_marketplace.return_value = []
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["search", "x", "--marketplace-only"])
        assert result.exit_code == 0
        manager.search_pypi.assert_not_called()


# ===========================================================================
# path
# ===========================================================================


class TestPluginsPath:
    def test_path_show_existing(self, runner, tmp_path):
        pdir = tmp_path / "plugins"
        (pdir / "some-plugin").mkdir(parents=True)
        manager = MagicMock()
        manager.LOCAL_PLUGINS_DIR = pdir
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["path"])
        assert result.exit_code == 0, result.output
        assert "Directory exists" in result.output
        assert "Contains 1 plugin" in result.output

    def test_path_create_flag(self, runner, tmp_path):
        pdir = tmp_path / "plugins"
        manager = MagicMock()
        manager.LOCAL_PLUGINS_DIR = pdir
        manager.ensure_local_plugins_dir.return_value = pdir
        with patch("miesc.plugins.PluginManager", return_value=manager):
            result = runner.invoke(plugins, ["path", "--create"])
        assert result.exit_code == 0, result.output
        assert "created" in result.output.lower()
        manager.ensure_local_plugins_dir.assert_called_once()


# ===========================================================================
# runtime
# ===========================================================================


class TestPluginsRuntime:
    def test_runtime_empty_registry(self, runner):
        registry = MagicMock()
        registry.list_plugins.return_value = []
        with patch("miesc.plugins.get_registry", return_value=registry):
            result = runner.invoke(plugins, ["runtime"])
        assert result.exit_code == 0
        assert "No plugins loaded" in result.output

    def test_runtime_with_entries(self, runner):
        entry = SimpleNamespace(
            name="my-detector",
            version="1.0.0",
            plugin_type=SimpleNamespace(value="detector"),
            enabled=True,
            source="/path/to/plugin.py",
        )
        registry = MagicMock()
        registry.list_plugins.return_value = [entry]
        registry.get_stats.return_value = {"total": 1, "enabled": 1}
        with patch("miesc.plugins.get_registry", return_value=registry):
            result = runner.invoke(plugins, ["runtime", "-v"])
        assert result.exit_code == 0, result.output
        assert "my-detector" in result.output
        assert "1 plugins loaded" in result.output


# ===========================================================================
# new
# ===========================================================================


class TestPluginsNew:
    def test_new_success(self, runner, tmp_path):
        created = tmp_path / "my-detector"
        (created / "src").mkdir(parents=True)
        (created / "src" / "plugin.py").write_text("# impl", encoding="utf-8")
        (created / "README.md").write_text("# readme", encoding="utf-8")

        generator = MagicMock()
        generator.create_plugin.return_value = created
        with patch("miesc.plugins.PluginTemplateGenerator", return_value=generator):
            result = runner.invoke(
                plugins, ["new", "my-detector", "-t", "detector", "-o", str(tmp_path)]
            )
        assert result.exit_code == 0, result.output
        assert "Plugin created" in result.output

    def test_new_failure_exits_1(self, runner, tmp_path):
        generator = MagicMock()
        generator.create_plugin.side_effect = RuntimeError("template broken")
        with patch("miesc.plugins.PluginTemplateGenerator", return_value=generator):
            result = runner.invoke(plugins, ["new", "bad", "-o", str(tmp_path)])
        assert result.exit_code == 1
        assert "Failed to create plugin" in result.output
