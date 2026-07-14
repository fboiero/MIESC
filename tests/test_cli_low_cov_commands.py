"""Real CLI coverage tests for the lowest-covered command modules.

Exercises genuine code paths (success, error, empty input, flag variations and
unavailable-tool branches) in the click implementations of:

  detect, init, testgen, specs, config, server, analyze, export

All external collaborators (framework detector, filesystem writers, formal-spec
generator, chain analyzers, API servers, exporters) are mocked, so the suite is
deterministic and passes with no local tooling installed.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ===========================================================================
# detect command
# ===========================================================================
from miesc.cli.commands.detect import detect  # noqa: E402
from miesc.core.framework_detector import Framework, FrameworkConfig  # noqa: E402


def _fw_config(framework=Framework.FOUNDRY, **kw) -> FrameworkConfig:
    defaults = {
        "framework": framework,
        "root_path": Path("."),
        "config_file": Path("foundry.toml"),
        "solc_version": "0.8.20",
        "evm_version": "paris",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
    }
    defaults.update(kw)
    return FrameworkConfig(**defaults)  # type: ignore[arg-type]


class TestDetect:
    def test_unknown_framework(self, runner):
        cfg = _fw_config(Framework.UNKNOWN, config_file=None, solc_version=None)
        with patch("miesc.core.framework_detector.detect_framework", return_value=cfg):
            result = runner.invoke(detect, ["."])
        assert result.exit_code == 0
        assert "no supported framework" in result.output.lower()

    def test_json_output(self, runner):
        cfg = _fw_config()
        with patch("miesc.core.framework_detector.detect_framework", return_value=cfg):
            result = runner.invoke(detect, [".", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["framework"] == "foundry"
        assert payload["solc_version"] == "0.8.20"

    def test_success_rich(self, runner):
        cfg = _fw_config(
            remappings=[f"lib{i}=src{i}" for i in range(7)],
            lib_paths=[Path("lib/forge-std"), Path("lib/openzeppelin")],
        )
        with patch("miesc.core.framework_detector.detect_framework", return_value=cfg):
            result = runner.invoke(detect, ["."])
        assert result.exit_code == 0
        assert "detected foundry project" in result.output.lower()

    def test_success_plain_no_rich(self, runner):
        cfg = _fw_config(remappings=["a=b", "c=d"])
        with (
            patch("miesc.core.framework_detector.detect_framework", return_value=cfg),
            patch("miesc.cli.commands.detect.RICH_AVAILABLE", False),
        ):
            result = runner.invoke(detect, ["."])
        assert result.exit_code == 0
        assert "Framework Detection" in result.output
        assert "FOUNDRY" in result.output


# ===========================================================================
# init command group
# ===========================================================================
from miesc.cli.commands.init import init  # noqa: E402


class TestInitFoundry:
    def test_missing_foundry_toml(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(init, ["foundry"])
        assert result.exit_code == 1
        assert "foundry.toml not found" in result.output.lower()

    def test_new_profile_inline_hook(self, runner):
        with runner.isolated_filesystem():
            Path("foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
            result = runner.invoke(init, ["foundry", "--fail-on", "critical"])
            assert result.exit_code == 0
            content = Path("foundry.toml").read_text()
            assert "post_build_hook" in content
            assert "--fail-on critical" in content

    def test_existing_profile_insert(self, runner):
        with runner.isolated_filesystem():
            Path("foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\n\n[rpc_endpoints]\nmain = 'x'\n"
            )
            result = runner.invoke(init, ["foundry"])
            assert result.exit_code == 0
            assert "post_build_hook" in Path("foundry.toml").read_text()

    def test_hook_script_flag(self, runner):
        with runner.isolated_filesystem():
            Path("foundry.toml").write_text("[profile.default]\n")
            result = runner.invoke(init, ["foundry", "--hook-script"])
            assert result.exit_code == 0
            hook = Path("scripts/miesc-hook.sh")
            assert hook.exists()
            assert "MIESC Foundry Post-Build Hook" in hook.read_text()
            assert "./scripts/miesc-hook.sh" in Path("foundry.toml").read_text()

    def test_already_configured_abort(self, runner):
        with runner.isolated_filesystem():
            Path("foundry.toml").write_text("[profile.default]\npost_build_hook = 'miesc audit'\n")
            # Answer 'n' to the overwrite confirmation -> early return, no change
            result = runner.invoke(init, ["foundry"], input="n\n")
            assert result.exit_code == 0
            assert "already be configured" in result.output.lower()


class TestInitHardhat:
    def test_missing_config(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(init, ["hardhat"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_creates_task_file(self, runner):
        with runner.isolated_filesystem():
            Path("hardhat.config.js").write_text("module.exports = {};")
            result = runner.invoke(init, ["hardhat", "--fail-on", "medium"])
            assert result.exit_code == 0
            task = Path("tasks/miesc.js")
            assert task.exists()
            assert '"medium"' in task.read_text()


class TestInitGithub:
    def test_creates_workflow(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(init, ["github", "--workflow-name", "audit"])
            assert result.exit_code == 0
            wf = Path(".github/workflows/audit.yml")
            assert wf.exists()
            assert "MIESC Security Audit" in wf.read_text()


# ===========================================================================
# test-gen command + helpers
# ===========================================================================
from miesc.cli.commands.testgen import (  # noqa: E402
    _detect_contract_name,
    _get_call_args,
    _normalize_test_name,
    generate_test,
    testgen,
)


class TestTestgenHelpers:
    def test_normalize_test_name_sanitizes(self):
        name = _normalize_test_name("access-control", "with draw()")
        assert "-" not in name
        assert " " not in name
        assert "(" not in name
        assert name.startswith("access_control")

    def test_detect_contract_name(self):
        assert _detect_contract_name("pragma solidity;\ncontract Vault {}") == "Vault"
        assert _detect_contract_name("// just a comment") == "Target"

    def test_get_call_args(self):
        assert _get_call_args({"type": "suicidal"}) == ""
        assert _get_call_args({"type": "missing owner check"}) == "attacker"
        assert _get_call_args({"type": "reentrancy"}) == ""

    def test_generate_reentrancy_template(self):
        code = generate_test({"type": "reentrancy", "function": "withdraw"}, "Vault.sol", "Vault")
        assert code is not None
        assert "ReentrancyAttacker" in code
        assert "Vault" in code

    def test_generate_access_control_template(self):
        code = generate_test({"type": "access_control", "function": "setOwner"}, "C.sol", "C")
        assert code and "test_exploit_" in code

    def test_generate_selfdestruct_template(self):
        code = generate_test({"type": "suicidal", "function": "kill"}, "C.sol", "C")
        assert code and "code.length" in code

    def test_generate_unchecked_template(self):
        code = generate_test({"type": "unchecked_call", "function": "pay"}, "C.sol", "C")
        assert code and "RevertingReceiver" in code

    def test_generate_default_template_with_steps(self):
        code = generate_test(
            {
                "type": "weird-bug",
                "function": "boom",
                "exploit_scenario": ["step one", "step two"],
                "description": "a weird bug",
            },
            "C.sol",
            "C",
        )
        assert code is not None
        assert "1. step one" in code
        assert "2. step two" in code

    def test_generate_infers_function_from_line(self):
        source = "contract C {\n  function target() public {\n    revert();\n  }\n}"
        code = generate_test({"type": "reentrancy", "line": 3}, "C.sol", "C", source=source)
        assert code is not None
        assert "target" in code


class TestTestgenCommand:
    def test_invalid_json(self, runner):
        with runner.isolated_filesystem():
            Path("bad.json").write_text("{not json")
            Path("C.sol").write_text("contract C {}")
            result = runner.invoke(testgen, ["bad.json", "-c", "C.sol"])
        assert result.exit_code == 1
        assert "cannot read results" in result.output.lower()

    def test_no_exploitable_findings(self, runner):
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps({"findings": [{"type": "reentrancy"}]}))
            Path("C.sol").write_text("contract C {}")
            result = runner.invoke(testgen, ["r.json", "-c", "C.sol"])
        assert result.exit_code == 0
        assert "nothing to generate" in result.output.lower()

    def test_generates_tests(self, runner):
        findings = {
            "findings": [
                {
                    "type": "reentrancy",
                    "function": "withdraw",
                    "exploit_scenario": ["reenter"],
                },
                {
                    "type": "access_control",
                    "function": "setOwner",
                    "fix_code": "onlyOwner",
                },
            ]
        }
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps(findings))
            Path("Vault.sol").write_text("contract Vault {}")
            result = runner.invoke(testgen, ["r.json", "-c", "Vault.sol", "-o", "out"])
            assert result.exit_code == 0
            generated = list(Path("out").glob("Test_*.t.sol"))
            assert len(generated) == 2
        assert "generated 2" in result.output.lower()

    def test_dedup_and_quiet(self, runner):
        findings = {
            "results": [
                {
                    "findings": [
                        {"type": "reentrancy", "function": "w", "exploit_scenario": ["x"]},
                        {"type": "reentrancy", "function": "w", "exploit_scenario": ["x"]},
                    ]
                }
            ]
        }
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps(findings))
            Path("C.sol").write_text("contract C {}")
            result = runner.invoke(testgen, ["r.json", "-c", "C.sol", "-q"])
            assert result.exit_code == 0
            # deduped to a single test file
            assert len(list(Path("test/exploit").glob("*.t.sol"))) == 1


# ===========================================================================
# specs command
# ===========================================================================
from miesc.cli.commands.specs import specs  # noqa: E402


class TestSpecs:
    def test_invalid_json(self, runner):
        with runner.isolated_filesystem():
            Path("r.json").write_text("{broken")
            result = runner.invoke(specs, ["r.json"])
        assert result.exit_code == 1
        assert "failed to load" in result.output.lower()

    def test_no_findings(self, runner):
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps({"findings": []}))
            result = runner.invoke(specs, ["r.json"])
        assert result.exit_code == 0
        assert "nothing to generate" in result.output.lower()

    def test_generation_success(self, runner):
        gen = MagicMock()
        gen.generate_spec_file.return_value = 3
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps({"findings": [{"type": "reentrancy"}]}))
            with (
                patch("miesc.formal.SpecGenerator", return_value=gen),
                patch("miesc.formal.SpecFormat", side_effect=lambda v: v),
            ):
                result = runner.invoke(specs, ["r.json", "-q"])
        assert result.exit_code == 0
        assert "generated 3 cvl" in result.output.lower()
        gen.generate_spec_file.assert_called_once()

    def test_generation_zero_count(self, runner):
        gen = MagicMock()
        gen.generate_spec_file.return_value = 0
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps({"results": [{"findings": [{"type": "x"}]}]}))
            with (
                patch("miesc.formal.SpecGenerator", return_value=gen),
                patch("miesc.formal.SpecFormat", side_effect=lambda v: v),
            ):
                result = runner.invoke(specs, ["r.json", "-f", "scribble"])
        assert result.exit_code == 0
        assert "no specs generated" in result.output.lower()

    def test_generation_exception(self, runner):
        with runner.isolated_filesystem():
            Path("r.json").write_text(json.dumps({"findings": [{"type": "x"}]}))
            with (
                patch("miesc.formal.SpecGenerator", side_effect=RuntimeError("boom")),
                patch("miesc.formal.SpecFormat", side_effect=lambda v: v),
            ):
                result = runner.invoke(specs, ["r.json"])
        assert result.exit_code == 1
        assert "spec generation failed" in result.output.lower()


# ===========================================================================
# config command group
# ===========================================================================
from miesc.cli.commands.config import config  # noqa: E402


class TestConfigShow:
    def test_show_empty(self, runner):
        with patch("miesc.cli.commands.config.load_config", return_value={}):
            result = runner.invoke(config, ["show"])
        assert result.exit_code == 0
        assert "no configuration found" in result.output.lower()

    def test_show_rich_tree(self, runner):
        cfg = {"layers": {"static": ["slither"]}, "adapters": [{"name": "slither"}]}
        with patch("miesc.cli.commands.config.load_config", return_value=cfg):
            result = runner.invoke(config, ["show"])
        assert result.exit_code == 0
        assert "layers" in result.output

    def test_show_plain_json(self, runner):
        cfg = {"layers": {"static": ["slither"]}}
        with (
            patch("miesc.cli.commands.config.load_config", return_value=cfg),
            patch("miesc.cli.commands.config.RICH_AVAILABLE", False),
        ):
            result = runner.invoke(config, ["show"])
        assert result.exit_code == 0
        assert '"layers"' in result.output


class TestConfigValidate:
    def test_missing_file(self, runner, tmp_path):
        with patch("miesc.cli.commands.config.ROOT_DIR", tmp_path):
            result = runner.invoke(config, ["validate"])
        assert result.exit_code == 1
        assert "config file not found" in result.output.lower()

    def test_valid_config(self, runner, tmp_path):
        cfg_dir = tmp_path / "config"
        cfg_dir.mkdir()
        (cfg_dir / "miesc.yaml").write_text("layers: {}\nadapters: {}\n")
        with (
            patch("miesc.cli.commands.config.ROOT_DIR", tmp_path),
            patch(
                "miesc.cli.commands.config.load_config",
                return_value={"layers": {}, "adapters": {}},
            ),
        ):
            result = runner.invoke(config, ["validate"])
        assert result.exit_code == 0
        assert "configuration is valid" in result.output.lower()

    def test_missing_optional_section(self, runner, tmp_path):
        cfg_dir = tmp_path / "config"
        cfg_dir.mkdir()
        (cfg_dir / "miesc.yaml").write_text("layers: {}\n")
        with (
            patch("miesc.cli.commands.config.ROOT_DIR", tmp_path),
            patch("miesc.cli.commands.config.load_config", return_value={"layers": {}}),
        ):
            result = runner.invoke(config, ["validate"])
        assert result.exit_code == 0
        assert "missing (optional)" in result.output.lower()

    def test_load_error(self, runner, tmp_path):
        cfg_dir = tmp_path / "config"
        cfg_dir.mkdir()
        (cfg_dir / "miesc.yaml").write_text("layers: {}\n")
        with (
            patch("miesc.cli.commands.config.ROOT_DIR", tmp_path),
            patch(
                "miesc.cli.commands.config.load_config",
                side_effect=RuntimeError("bad yaml"),
            ),
        ):
            result = runner.invoke(config, ["validate"])
        assert result.exit_code == 1
        assert "config error" in result.output.lower()


# ===========================================================================
# server command group
# ===========================================================================
from miesc.cli.commands.server import server  # noqa: E402


class TestServerRest:
    def test_rest_success(self, runner):
        run = MagicMock()
        with patch("miesc.api.rest.run_server", run):
            result = runner.invoke(server, ["rest", "-p", "9100", "-h", "127.0.0.1"])
        assert result.exit_code == 0
        run.assert_called_once_with("127.0.0.1", 9100, False)

    def test_rest_import_error(self, runner):
        with patch("miesc.api.rest.run_server", side_effect=ImportError("no django")):
            result = runner.invoke(server, ["rest"])
        assert result.exit_code == 1
        assert "not available" in result.output.lower()

    def test_rest_generic_error(self, runner):
        with patch("miesc.api.rest.run_server", side_effect=RuntimeError("boom")):
            result = runner.invoke(server, ["rest", "--debug"])
        assert result.exit_code == 1
        assert "server error" in result.output.lower()


class TestServerMcp:
    def test_mcp_success(self, runner):
        with (
            patch("miesc.mcp_core.websocket_server.run_server", MagicMock()),
            patch("asyncio.run", MagicMock()),
        ):
            result = runner.invoke(server, ["mcp", "-p", "9000", "-h", "0.0.0.0"])
        assert result.exit_code == 0
        assert "mcp websocket server" in result.output.lower()

    def test_mcp_import_error(self, runner):
        with patch(
            "miesc.mcp_core.websocket_server.run_server",
            side_effect=ImportError("no websockets"),
        ):
            result = runner.invoke(server, ["mcp"])
        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    def test_mcp_keyboard_interrupt(self, runner):
        with (
            patch("miesc.mcp_core.websocket_server.run_server", MagicMock()),
            patch("asyncio.run", side_effect=KeyboardInterrupt),
        ):
            result = runner.invoke(server, ["mcp"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_mcp_generic_error(self, runner):
        with (
            patch("miesc.mcp_core.websocket_server.run_server", MagicMock()),
            patch("asyncio.run", side_effect=RuntimeError("boom")),
        ):
            result = runner.invoke(server, ["mcp"])
        assert result.exit_code == 1
        assert "error" in result.output.lower()


# ===========================================================================
# analyze command
# ===========================================================================
from miesc.cli.commands.analyze import analyze, detect_chain  # noqa: E402


def _chain_finding(sev="high"):
    return SimpleNamespace(
        severity=SimpleNamespace(value=sev),
        to_dict=lambda: {
            "severity": sev.upper(),
            "title": "Bug",
            "type": "bug",
            "location": {"line": 7},
        },
    )


class TestAnalyzeDetectChain:
    def test_detect_by_extension(self):
        assert detect_chain("a.sol") == "ethereum"
        assert detect_chain("a.cairo") == "starknet"
        assert detect_chain("a.move") == "move"
        assert detect_chain("a.rs") == "solana"
        assert detect_chain("a.txt") == "unknown"


class TestAnalyzeCommand:
    def test_unknown_chain_exits(self, runner):
        with runner.isolated_filesystem():
            Path("mystery.txt").write_text("data")
            result = runner.invoke(analyze, ["mystery.txt"])
        assert result.exit_code == 1
        assert "cannot determine chain" in result.output.lower()

    def test_ethereum_delegates_to_scan(self, runner):
        @click.command()
        @click.option("--contract")
        @click.option("--output")
        @click.option("--ci", is_flag=True)
        @click.option("--quiet", is_flag=True)
        @click.option("--fp-strictness")
        @click.option("--llm-enhance", is_flag=True)
        def fake_scan(contract, output, ci, quiet, fp_strictness, llm_enhance):
            click.echo(f"scanned {contract}")

        with runner.isolated_filesystem():
            Path("Token.sol").write_text("contract Token {}")
            with patch("miesc.cli.commands.scan.scan", fake_scan):
                result = runner.invoke(analyze, ["Token.sol"])
        assert result.exit_code == 0
        assert "scanned Token.sol" in result.output

    def test_starknet_analysis(self, runner):
        analyzer = MagicMock()
        analyzer.analyze.return_value = {
            "success": True,
            "tool": "cairo",
            "findings": [{"severity": "HIGH", "title": "X", "location": {"line": 3}}],
            "summary": {"High": 1},
        }
        with runner.isolated_filesystem():
            Path("v.cairo").write_text("felt")
            with patch("miesc.adapters.cairo_adapter.CairoAnalyzer", return_value=analyzer):
                result = runner.invoke(analyze, ["v.cairo", "-o", "out.json"])
            assert result.exit_code == 0
            saved = json.loads(Path("out.json").read_text())
            assert saved["chain"] == "starknet"
            assert saved["total_findings"] == 1

    def test_move_analysis(self, runner):
        analyzer = MagicMock()
        analyzer.parse.return_value = object()
        analyzer.detect_vulnerabilities.return_value = [_chain_finding("high")]
        with runner.isolated_filesystem():
            Path("m.move").write_text("module M {}")
            with patch("miesc.adapters.move_adapter.MoveAnalyzer", return_value=analyzer):
                result = runner.invoke(analyze, ["m.move"])
        assert result.exit_code == 0
        assert "move analysis complete" in result.output.lower()

    def test_solana_ci_mode_fails(self, runner):
        analyzer = MagicMock()
        analyzer.parse.return_value = object()
        analyzer.detect_vulnerabilities.return_value = [_chain_finding("critical")]
        with runner.isolated_filesystem():
            Path("p.rs").write_text("fn main() {}")
            with patch("miesc.adapters.solana_adapter.SolanaAnalyzer", return_value=analyzer):
                result = runner.invoke(analyze, ["p.rs", "--chain", "solana", "--ci"])
        # critical finding + --ci -> exit 1
        assert result.exit_code == 1

    def test_analysis_exception(self, runner):
        with runner.isolated_filesystem():
            Path("v.cairo").write_text("felt")
            with patch(
                "miesc.adapters.cairo_adapter.CairoAnalyzer",
                side_effect=RuntimeError("boom"),
            ):
                result = runner.invoke(analyze, ["v.cairo"])
        assert result.exit_code == 1
        assert "analysis failed" in result.output.lower()


# ===========================================================================
# export command
# ===========================================================================
from miesc.cli.commands.export import export  # noqa: E402

_EXPORT_DATA = {
    "contract": "Vault.sol",
    "results": [
        {
            "tool": "slither",
            "findings": [
                {
                    "severity": "HIGH",
                    "title": "Reentrancy",
                    "type": "reentrancy",
                    "description": "external call before state update",
                    "location": {"file": "Vault.sol", "line": 42, "function": "withdraw"},
                    "confidence": 0.9,
                }
            ],
        }
    ],
}


def _write_input(dir_path: Path) -> Path:
    f = dir_path / "results.json"
    f.write_text(json.dumps(_EXPORT_DATA))
    return f


class TestExport:
    @pytest.mark.parametrize(
        "fmt,needle",
        [
            ("sarif", '"version"'),
            ("markdown", "#"),
            ("csv", "Reentrancy"),
            ("html", "<!DOCTYPE html>"),
            ("jsonl", '"severity"'),
        ],
    )
    def test_export_formats_write_file(self, runner, tmp_path, fmt, needle):
        inp = _write_input(tmp_path)
        out = tmp_path / f"report.{fmt}"
        result = runner.invoke(export, [str(inp), "-f", fmt, "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert needle in out.read_text()

    def test_export_default_output_path(self, runner, tmp_path):
        inp = _write_input(tmp_path)
        result = runner.invoke(export, [str(inp), "-f", "markdown"])
        assert result.exit_code == 0
        assert (tmp_path / "results.md").exists()

    def test_export_github_stdout(self, runner, tmp_path):
        inp = _write_input(tmp_path)
        result = runner.invoke(export, [str(inp), "-f", "github"])
        assert result.exit_code == 0
        assert "::" in result.output  # ::error / ::warning annotations

    def test_export_github_with_output_file(self, runner, tmp_path):
        inp = _write_input(tmp_path)
        out = tmp_path / "annotations.txt"
        result = runner.invoke(export, [str(inp), "-f", "github", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_export_github_baseline_filters(self, runner, tmp_path):
        inp = _write_input(tmp_path)
        baseline = tmp_path / "baseline.json"
        baseline.write_text("{}")
        with (
            patch("miesc.core.baseline.load_baseline", return_value=MagicMock()) as lb,
            patch(
                "miesc.core.baseline.diff_against_baseline",
                return_value={"new": []},
            ) as diff,
        ):
            result = runner.invoke(export, [str(inp), "-f", "github", "--baseline", str(baseline)])
        assert result.exit_code == 0
        lb.assert_called_once()
        diff.assert_called_once()

    def test_export_github_baseline_invalid(self, runner, tmp_path):
        inp = _write_input(tmp_path)
        with patch(
            "miesc.core.baseline.load_baseline",
            side_effect=FileNotFoundError("nope"),
        ):
            result = runner.invoke(export, [str(inp), "-f", "github", "--baseline", "missing.json"])
        assert result.exit_code == 0
        assert "invalid or missing baseline" in result.output.lower()

    def test_export_jsonl_empty(self, runner, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text(json.dumps({"contract": "C.sol", "results": []}))
        out = tmp_path / "e.jsonl"
        result = runner.invoke(export, [str(f), "-f", "jsonl", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
