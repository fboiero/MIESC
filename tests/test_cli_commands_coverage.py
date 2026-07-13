"""CLI command coverage tests for the lowest-covered command modules.

These tests exercise real code paths in the click command implementations of
``miesc.cli.commands`` (poc, plugins, tools, detectors, benchmark) using
``CliRunner`` and mocked external collaborators (PoC generator, Foundry runner,
plugin manager, adapter loader, orchestrator). They deliberately avoid any
network / subprocess side effects so they run deterministically in CI.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ===========================================================================
# poc command group
# ===========================================================================
from miesc.cli.commands.poc import poc  # noqa: E402


class TestPocList:
    def test_list_generator_unavailable(self, runner):
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=None):
            result = runner.invoke(poc, ["list"])
        assert result.exit_code == 1
        assert "not available" in result.output.lower()

    def test_list_success(self, runner):
        gen = SimpleNamespace(TEMPLATE_MAP={}, TYPE_ALIASES={})
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            result = runner.invoke(poc, ["list"])
        assert result.exit_code == 0
        # Every real VulnerabilityType should be rendered
        assert "reentrancy" in result.output.lower()

    def test_list_verbose(self, runner):
        gen = SimpleNamespace(TEMPLATE_MAP={}, TYPE_ALIASES={})
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            result = runner.invoke(poc, ["list", "-v"])
        assert result.exit_code == 0


class TestPocGenerate:
    def _fake_template(self):
        tpl = MagicMock()
        tpl.name = "PoC_reentrancy"
        tpl.vulnerability_type = SimpleNamespace(value="reentrancy")
        tpl.save.return_value = "test/exploits/PoC_reentrancy_test.t.sol"
        return tpl

    def test_generate_unavailable(self, runner):
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=None):
            result = runner.invoke(poc, ["generate", "-c", "Token.sol", "-t", "reentrancy"])
        assert result.exit_code == 1

    def test_generate_no_input(self, runner):
        gen = MagicMock()
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            # No finding file, no --json-input, no --type -> error path
            result = runner.invoke(poc, ["generate", "-c", "Token.sol"])
        assert result.exit_code == 1
        assert "provide a finding" in result.output.lower()

    def test_generate_from_type(self, runner):
        gen = MagicMock()
        gen.generate.return_value = self._fake_template()
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            result = runner.invoke(
                poc,
                ["generate", "-c", "Token.sol", "-t", "reentrancy", "-f", "withdraw"],
            )
        assert result.exit_code == 0
        assert "generated" in result.output.lower()
        gen.generate.assert_called_once()

    def test_generate_from_inline_json(self, runner):
        gen = MagicMock()
        gen.generate.return_value = self._fake_template()
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            result = runner.invoke(
                poc,
                ["generate", "-c", "Token.sol", "-j", '{"type": "reentrancy"}'],
            )
        assert result.exit_code == 0

    def test_generate_from_file(self, runner):
        gen = MagicMock()
        gen.generate.return_value = self._fake_template()
        with runner.isolated_filesystem():
            Path("finding.json").write_text(json.dumps({"type": "reentrancy"}))
            with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
                result = runner.invoke(poc, ["generate", "finding.json", "-c", "Token.sol"])
        assert result.exit_code == 0

    def test_generate_exception(self, runner):
        gen = MagicMock()
        gen.generate.side_effect = RuntimeError("boom")
        with patch("miesc.cli.commands.poc.get_poc_generator", return_value=gen):
            result = runner.invoke(poc, ["generate", "-c", "Token.sol", "-t", "reentrancy"])
        assert result.exit_code == 1
        assert "failed" in result.output.lower()


class TestPocRun:
    def _result(self, success=True):
        return SimpleNamespace(
            success=success,
            error=None if success else "revert",
            total_tests=1,
            passed=1 if success else 0,
            failed=0 if success else 1,
            skipped=0,
            total_gas=21000,
            execution_time_ms=12.5,
            tests=[],
        )

    def test_run_foundry_unavailable(self, runner):
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=None):
                result = runner.invoke(poc, ["run", "poc.t.sol"])
        assert result.exit_code == 1
        assert "not available" in result.output.lower()

    def test_run_success(self, runner):
        fr = MagicMock()
        fr.run_test.return_value = self._result(success=True)
        fr.validate_poc.return_value = {"exploit_demonstrated": True, "warnings": []}
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=fr):
                result = runner.invoke(poc, ["run", "poc.t.sol", "-p", "."])
        assert result.exit_code == 0
        assert "successfully" in result.output.lower()

    def test_run_failure_exits_1(self, runner):
        fr = MagicMock()
        fr.run_test.return_value = self._result(success=False)
        fr.validate_poc.return_value = {"exploit_demonstrated": False, "warnings": ["w"]}
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=fr):
                result = runner.invoke(poc, ["run", "poc.t.sol"])
        assert result.exit_code == 1


class TestPocValidate:
    def test_validate_unavailable(self, runner):
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=None):
                result = runner.invoke(poc, ["validate", "poc.t.sol"])
        assert result.exit_code == 1

    def test_validate_pass(self, runner):
        fr = MagicMock()
        fr.validate_poc.return_value = {
            "valid": True,
            "tests_passed": 1,
            "total_gas": 21000,
            "exploit_demonstrated": True,
            "warnings": [],
        }
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=fr):
                result = runner.invoke(poc, ["validate", "poc.t.sol"])
        assert result.exit_code == 0
        assert "passed" in result.output.lower()

    def test_validate_fail_exits_1(self, runner):
        fr = MagicMock()
        fr.validate_poc.return_value = {
            "valid": False,
            "errors": ["no exploit"],
            "warnings": [],
        }
        with runner.isolated_filesystem():
            Path("poc.t.sol").write_text("// poc")
            with patch("miesc.cli.commands.poc.get_foundry_runner", return_value=fr):
                result = runner.invoke(poc, ["validate", "poc.t.sol"])
        assert result.exit_code == 1


# ===========================================================================
# plugins command group
# ===========================================================================
from miesc.cli.commands.plugins import plugins  # noqa: E402
from miesc.plugins.manager import (  # noqa: E402
    CompatibilityInfo,
    CompatibilityStatus,
    PluginInfo,
)


def _plugin(**kw) -> PluginInfo:
    defaults = {
        "name": "demo",
        "package": "miesc-demo",
        "version": "1.0.0",
        "enabled": True,
        "detector_count": 3,
        "detectors": ["det-a", "det-b"],
        "description": "A demo plugin",
        "author": "Tester",
        "local": False,
    }
    defaults.update(kw)
    return PluginInfo(**defaults)


class TestPluginsList:
    def test_list_empty(self, runner):
        mgr = MagicMock()
        mgr.list_installed.return_value = []
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["list"])
        assert result.exit_code == 0
        assert "no plugins installed" in result.output.lower()

    def test_list_with_plugins(self, runner):
        mgr = MagicMock()
        mgr.LOCAL_PLUGINS_DIR = "/tmp/plugins"
        mgr._miesc_version = "6.0.0"
        compat = CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE, message="too old")
        mgr.list_installed.return_value = [
            _plugin(local=True, compatibility=compat),
            _plugin(name="other", package="miesc-other", enabled=False),
        ]
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["list", "--all"])
        assert result.exit_code == 0
        assert "miesc-demo" in result.output


class TestPluginsEnableDisable:
    def test_enable_ok(self, runner):
        mgr = MagicMock()
        mgr.enable.return_value = (True, "enabled demo")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["enable", "miesc-demo"])
        assert result.exit_code == 0
        assert "enabled demo" in result.output

    def test_enable_fail(self, runner):
        mgr = MagicMock()
        mgr.enable.return_value = (False, "not found")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["enable", "nope"])
        assert result.exit_code == 1

    def test_disable_ok(self, runner):
        mgr = MagicMock()
        mgr.disable.return_value = (True, "disabled demo")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["disable", "miesc-demo"])
        assert result.exit_code == 0

    def test_disable_fail(self, runner):
        mgr = MagicMock()
        mgr.disable.return_value = (False, "not found")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["disable", "nope"])
        assert result.exit_code == 1


class TestPluginsInfo:
    def test_info_not_found(self, runner):
        mgr = MagicMock()
        mgr.get_plugin_info.return_value = None
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["info", "ghost"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_info_found(self, runner):
        mgr = MagicMock()
        mgr._miesc_version = "6.0.0"
        compat = CompatibilityInfo(status=CompatibilityStatus.COMPATIBLE, message="ok")
        mgr.get_plugin_info.return_value = _plugin(
            compatibility=compat, requires_miesc=">=5.0.0", requires_python=">=3.10"
        )
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["info", "miesc-demo"])
        assert result.exit_code == 0
        assert "miesc-demo" in result.output


# ===========================================================================
# tools command group
# ===========================================================================
from miesc.cli.commands.tools import tools  # noqa: E402


class TestToolsList:
    def test_list_all(self, runner):
        with patch(
            "miesc.cli.commands.tools.AdapterLoader.check_tool_status",
            return_value={"available": True, "status": "available"},
        ):
            result = runner.invoke(tools, ["list"])
        assert result.exit_code == 0

    def test_list_layer_filter_available_only(self, runner):
        with patch(
            "miesc.cli.commands.tools.AdapterLoader.check_tool_status",
            return_value={"available": False, "status": "not_installed"},
        ):
            result = runner.invoke(tools, ["list", "-l", "1", "-a"])
        assert result.exit_code == 0


class TestToolsInfo:
    def test_info_no_adapter(self, runner):
        with patch("miesc.cli.commands.tools.AdapterLoader.get_adapter", return_value=None):
            result = runner.invoke(tools, ["info", "does-not-exist"])
        assert result.exit_code == 0
        assert "no adapter" in result.output.lower()

    def test_info_found(self, runner):
        adapter = MagicMock()
        meta = SimpleNamespace(
            name="Slither",
            version="0.10.0",
            category=SimpleNamespace(value="static"),
            author="Trail of Bits",
            license="AGPL",
            homepage="h",
            repository="r",
            documentation="d",
            installation_cmd="pip install slither-analyzer",
            capabilities=[
                SimpleNamespace(
                    name="detect", description="find bugs", detection_types=["reentrancy"]
                )
            ],
        )
        adapter.get_metadata.return_value = meta
        adapter.is_available.return_value = SimpleNamespace(value="available")
        with patch("miesc.cli.commands.tools.AdapterLoader.get_adapter", return_value=adapter):
            result = runner.invoke(tools, ["info", "slither"])
        assert result.exit_code == 0
        assert "Slither" in result.output


# ===========================================================================
# detectors command group
# ===========================================================================
from miesc.cli.commands.detectors import detectors  # noqa: E402


class TestDetectorsList:
    def test_list_empty(self, runner):
        with (
            patch("miesc.detectors.list_detectors", return_value=[]),
            patch("miesc.detectors.load_local_plugins", return_value=None),
        ):
            result = runner.invoke(detectors, ["list"])
        assert result.exit_code == 0
        assert "no custom detectors" in result.output.lower()

    def test_list_with_detectors(self, runner):
        det = [
            {
                "name": "flash-loan",
                "category": "defi",
                "severity": "High",
                "description": "detects flash loan abuse",
                "author": "me",
            }
        ]
        with (
            patch("miesc.detectors.list_detectors", return_value=det),
            patch("miesc.detectors.load_local_plugins", return_value=None),
        ):
            result = runner.invoke(detectors, ["list", "-v"])
        assert result.exit_code == 0
        assert "1 detectors registered" in result.output


class TestDetectorsInfo:
    def test_info_not_found(self, runner):
        registry = MagicMock()
        registry.get.return_value = None
        registry.list_detectors.return_value = ["a", "b"]
        with patch("miesc.detectors.detector_api.get_registry", return_value=registry):
            result = runner.invoke(detectors, ["info", "ghost"])
        assert result.exit_code == 0
        assert "not found" in result.output.lower()

    def test_info_found(self, runner):
        det = SimpleNamespace(
            name="flash-loan",
            description="detects flash loan abuse",
            version="1.0.0",
            author="me",
            category=SimpleNamespace(value="defi"),
            default_severity=SimpleNamespace(value="High"),
            enabled=True,
            target_patterns=["flashLoan"],
        )
        registry = MagicMock()
        registry.get.return_value = det
        with patch("miesc.detectors.detector_api.get_registry", return_value=registry):
            result = runner.invoke(detectors, ["info", "flash-loan"])
        assert result.exit_code == 0
        assert "flash-loan" in result.output


class TestDetectorsRun:
    def test_run_no_detectors(self, runner):
        with runner.isolated_filesystem():
            Path("c.sol").write_text("contract C {}")
            with (
                patch("miesc.detectors.get_all_detectors", return_value={}),
                patch("miesc.detectors.load_local_plugins", return_value=None),
            ):
                result = runner.invoke(detectors, ["run", "c.sol"])
        assert result.exit_code == 0
        assert "no custom detectors" in result.output.lower()

    def test_run_unknown_detector_filter(self, runner):
        with runner.isolated_filesystem():
            Path("c.sol").write_text("contract C {}")
            with (
                patch("miesc.detectors.get_all_detectors", return_value={"known": object()}),
                patch("miesc.detectors.load_local_plugins", return_value=None),
            ):
                result = runner.invoke(detectors, ["run", "c.sol", "-d", "missing"])
        assert result.exit_code == 1

    def test_run_with_findings(self, runner):
        finding = SimpleNamespace(
            severity=SimpleNamespace(value="high"),
            detector="known",
            title="Reentrancy",
            location=SimpleNamespace(line=10),
            to_dict=lambda: {"title": "Reentrancy"},
        )
        with runner.isolated_filesystem():
            Path("c.sol").write_text("contract C {}")
            with (
                patch("miesc.detectors.get_all_detectors", return_value={"known": object()}),
                patch("miesc.detectors.load_local_plugins", return_value=None),
                patch("miesc.detectors.run_detector", return_value=[finding]),
            ):
                result = runner.invoke(detectors, ["run", "c.sol", "-o", "out.json", "-s", "high"])
            assert result.exit_code == 0
            assert Path("out.json").exists()
            saved = json.loads(Path("out.json").read_text())
            assert saved["total_findings"] == 1


# ===========================================================================
# benchmark command + helpers
# ===========================================================================
import importlib  # noqa: E402

from miesc.cli.commands.benchmark import benchmark  # noqa: E402

# The command object shadows the submodule in the package namespace, so load the
# module explicitly to reach its private helper functions.
bench_mod = importlib.import_module("miesc.cli.commands.benchmark")


def _write_benchmark(dir_path: Path, project: str, run_id: str, **metrics) -> Path:
    data = {
        "timestamp": "2026-07-12T10:00:00",
        "commit": "abc1234",
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
    }
    data.update(metrics)
    f = dir_path / f"{project}_{run_id}.json"
    f.write_text(json.dumps(data))
    return f


class TestBenchmarkHelpers:
    def test_show_history_empty(self, tmp_path):
        bench_mod._show_benchmark_history(tmp_path, "proj")  # no raise

    def test_show_history_with_data(self, tmp_path):
        _write_benchmark(tmp_path, "proj", "20260712_100000", total=5, high=2)
        bench_mod._show_benchmark_history(tmp_path, "proj")

    def test_compare_no_previous(self, tmp_path):
        current = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        bench_mod._compare_benchmarks(tmp_path, "proj", "last", current)

    def test_compare_last(self, tmp_path):
        _write_benchmark(tmp_path, "proj", "20260101_000000", total=10, high=5)
        current = {"critical": 0, "high": 2, "medium": 0, "low": 0, "total": 4}
        bench_mod._compare_benchmarks(tmp_path, "proj", "last", current)

    def test_compare_missing_named(self, tmp_path):
        current = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        bench_mod._compare_benchmarks(tmp_path, "proj", "nope", current)

    def test_generate_report(self, tmp_path):
        out = tmp_path / "trend.md"
        metrics = {
            "project": "proj",
            "timestamp": "2026-07-12T10:00:00",
            "commit": "abc1234",
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 1,
        }
        bench_mod._generate_benchmark_report(metrics, str(out), "30d")
        assert out.exists()
        assert "Security Posture Report" in out.read_text()


class TestBenchmarkCommand:
    def test_orchestrator_symbol_exists(self):
        """Regression: benchmark imports MIESCOrchestrator, which must be a real
        symbol exposing run_quick_audit (previously imported a non-existent
        SecurityOrchestrator, so the audit path always raised ImportError)."""
        from miesc.core.orchestrator import MIESCOrchestrator

        assert hasattr(MIESCOrchestrator, "run_quick_audit")

    def test_benchmark_history_flag(self, runner, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        contracts = tmp_path / "contracts"
        contracts.mkdir()
        result = runner.invoke(benchmark, [str(contracts), "--history"])
        assert result.exit_code == 0

    def test_benchmark_run_and_save(self, runner, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        contracts = tmp_path / "contracts"
        contracts.mkdir()
        orch = MagicMock()
        orch.run_quick_audit.return_value = {
            "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
            "files_count": 3,
            "tools": ["slither"],
        }
        with patch(
            "miesc.core.orchestrator.MIESCOrchestrator",
            return_value=orch,
        ):
            result = runner.invoke(benchmark, [str(contracts), "--save"])
        assert result.exit_code == 0
        assert "Benchmark saved" in result.output or "saved" in result.output.lower()

    def test_benchmark_audit_failure(self, runner, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        contracts = tmp_path / "contracts"
        contracts.mkdir()
        orch = MagicMock()
        orch.run_quick_audit.side_effect = RuntimeError("boom")
        with patch(
            "miesc.core.orchestrator.MIESCOrchestrator",
            return_value=orch,
        ):
            result = runner.invoke(benchmark, [str(contracts)])
        assert result.exit_code == 1
