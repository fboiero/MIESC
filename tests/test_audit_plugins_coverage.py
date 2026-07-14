"""Coverage-focused tests for audit / plugins CLI commands and PluginManager.

These exercise real code paths in three of the lowest-covered modules:

* ``miesc.cli.commands.audit``   — audit command group + output converters
* ``miesc.cli.commands.plugins`` — plugin management command group
* ``miesc.plugins.manager``      — PluginManager class (unit-tested directly)

All external collaborators (tool runners, orchestrators, subprocess, network,
entry points, LLM validators, notifiers) are mocked at their lookup site so the
suite is fully deterministic and needs no installed tools or network access.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.audit import (
    _ml_result_to_markdown,
    _rank_report_findings,
    _run_full_audit_basic,
    _run_full_audit_with_correlation,
    _run_full_audit_with_ml,
    _to_markdown,
    _to_sarif,
    audit,
)
from miesc.cli.commands.plugins import plugins
from miesc.plugins.manager import (
    CompatibilityInfo,
    CompatibilityStatus,
    PluginInfo,
    PluginManager,
    VersionConstraint,
    compare_versions,
    get_miesc_version,
)

AUDIT = "miesc.cli.commands.audit"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ===========================================================================
# Helpers
# ===========================================================================


def _finding(severity: str = "HIGH", **kw) -> dict:
    base = {
        "type": "reentrancy",
        "title": "Reentrancy in withdraw",
        "severity": severity,
        "description": "State updated after external call",
        "message": "reentrancy",
        "location": {"file": "Token.sol", "line": 42},
        "confidence": 0.9,
        "recommendation": "Use CEI",
        "swc_id": "SWC-107",
        "references": ["https://swcregistry.io/docs/SWC-107"],
    }
    base.update(kw)
    return base


def _tool_result(tool: str = "slither", status: str = "success", findings=None) -> dict:
    return {
        "tool": tool,
        "status": status,
        "findings": findings if findings is not None else [],
        "execution_time": 1.5,
        "error": None if status == "success" else "boom",
    }


def _fake_ml_result(findings=None):
    findings = findings if findings is not None else [_finding()]
    return SimpleNamespace(
        ml_filtered_findings=list(findings),
        total_raw_findings=len(findings) + 2,
        false_positives_removed=2,
        severity_adjustments=1,
        cluster_count=1,
        clusters=[
            SimpleNamespace(
                to_dict=lambda: {"primary_type": "reentrancy", "count": 2, "max_severity": "high"}
            )
        ],
        cross_validated=1,
        tools_success=["slither"],
        tools_run=["slither", "aderyn"],
        tools_failed=["aderyn"],
        execution_time_ms=1200.0,
        ml_processing_time_ms=300.0,
        timestamp=datetime(2026, 7, 14, 10, 0, 0),
        get_summary=lambda: {
            "risk_level": "HIGH",
            "total_findings": len(findings),
            "critical": 0,
            "high": len(findings),
            "medium": 0,
            "low": 0,
            "reduction_rate": 25.0,
        },
        to_dict=lambda: {"findings": findings, "summary": "ml"},
    )


# ===========================================================================
# audit.py — output converters (pure functions)
# ===========================================================================


class TestOutputConverters:
    def test_to_sarif_structure(self):
        results = [
            {
                "tool": "slither",
                "status": "success",
                "findings": [
                    _finding(severity="CRITICAL"),
                    _finding(severity="MEDIUM", type="overflow"),
                ],
            }
        ]
        sarif = _to_sarif(results)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "MIESC"
        # Two distinct rule ids -> two rules, two results
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2
        # CRITICAL maps to error level
        assert run["results"][0]["level"] == "error"
        assert run["results"][1]["level"] == "warning"

    def test_to_sarif_non_dict_location(self):
        results = [{"tool": "t", "contract": "C.sol", "findings": [_finding(location="somewhere")]}]
        sarif = _to_sarif(results)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "C.sol"

    def test_to_markdown_report(self):
        results = [
            _tool_result("slither", "success", [_finding()]),
            _tool_result("aderyn", "error", []),
        ]
        md = _to_markdown(results, "Token.sol")
        assert "MIESC Security Audit Report" in md
        assert "Token.sol" in md
        assert "SLITHER" in md
        assert "slither" in md  # appendix table
        assert "SWC-107" in md

    def test_ml_result_to_markdown(self):
        md = _ml_result_to_markdown(_fake_ml_result(), "Token.sol")
        assert "ML-Enhanced Security Audit Report" in md
        assert "Reentrancy" in md
        assert "Vulnerability Clusters" in md
        assert "reentrancy" in md


# ===========================================================================
# audit.py — _run_full_audit_* internal helpers
# ===========================================================================


class TestRunFullAuditHelpers:
    def test_basic_no_findings_writes_json(self, tmp_path):
        out = tmp_path / "r.json"
        with (
            patch(f"{AUDIT}.run_layer", return_value=[_tool_result()]),
            patch(f"{AUDIT}.run_plugins", return_value=[]),
        ):
            _run_full_audit_basic("C.sol", str(out), "json", [1], 30)
        data = json.loads(out.read_text())
        assert data["ml_enabled"] is False
        assert data["tools"] == ["slither"]
        assert "timing" in data

    def test_basic_sarif_and_markdown(self, tmp_path):
        with (
            patch(
                f"{AUDIT}.run_layer",
                return_value=[_tool_result("slither", "success", [_finding()])],
            ),
            patch(f"{AUDIT}.run_plugins", return_value=[]),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        ):
            sarif_out = tmp_path / "r.sarif"
            _run_full_audit_basic("C.sol", str(sarif_out), "sarif", [1], 30)
            assert json.loads(sarif_out.read_text())["version"] == "2.1.0"

            md_out = tmp_path / "r.md"
            _run_full_audit_basic("C.sol", str(md_out), "markdown", [1], 30)
            assert "Security Audit Report" in md_out.read_text()

    def test_basic_with_plugins_and_baseline(self, tmp_path):
        gate = MagicMock()
        with (
            patch(f"{AUDIT}.run_layer", return_value=[]),
            patch(f"{AUDIT}.run_plugins", return_value=[_tool_result("plugin-det", "success", [])]),
            patch("miesc.cli.commands.baseline.apply_baseline_gate", gate),
        ):
            _run_full_audit_basic("C.sol", None, "json", [1], 30, baseline_path="base.json")
        gate.assert_called_once()

    def test_ml_helper_writes_json_and_gates(self, tmp_path):
        out = tmp_path / "ml.json"
        orch = MagicMock()
        orch.analyze.return_value = _fake_ml_result()
        gate = MagicMock()
        with patch("miesc.cli.commands.baseline.apply_baseline_gate", gate):
            _run_full_audit_with_ml(
                "C.sol", str(out), "json", [1], 30, orch, baseline_path="base.json"
            )
        assert out.exists()
        orch.analyze.assert_called_once()
        gate.assert_called_once()

    def test_ml_helper_sarif_output(self, tmp_path):
        out = tmp_path / "ml.sarif"
        orch = MagicMock()
        orch.analyze.return_value = _fake_ml_result()
        _run_full_audit_with_ml("C.sol", str(out), "sarif", [1], 30, orch)
        assert json.loads(out.read_text())["version"] == "2.1.0"

    def test_ml_helper_falls_back_to_basic_on_error(self, tmp_path):
        orch = MagicMock()
        orch.analyze.side_effect = RuntimeError("ml exploded")
        with (
            patch(f"{AUDIT}.run_layer", return_value=[]),
            patch(f"{AUDIT}.run_plugins", return_value=[]),
        ):
            # Should not raise: catches and falls back to basic mode
            _run_full_audit_with_ml("C.sol", None, "json", [1], 30, orch)

    def test_correlation_helper(self, tmp_path):
        out = tmp_path / "corr.json"
        api = MagicMock()
        api.analyze.return_value = {
            "summary": {
                "total_correlated": 3,
                "cross_validated": 1,
                "high_confidence_count": 2,
                "deduplication_rate": 0.25,
            },
            "findings": {
                "actionable": [_finding()],
                "likely_false_positives": [_finding(severity="LOW")],
            },
        }
        with patch(
            f"{AUDIT}.run_layer",
            return_value=[_tool_result("slither", "success", [_finding()])],
        ):
            _run_full_audit_with_correlation("C.sol", str(out), "json", [1], 30, api)
        api.add_tool_results.assert_called()
        assert out.exists()

    def test_rank_report_findings_no_model(self):
        ranker = MagicMock()
        ranker.available.return_value = False
        findings = {"actionable": [_finding()]}
        with patch("miesc.ml.triage_ranker.TriageRanker", return_value=ranker):
            _rank_report_findings(findings, contract="C.sol")
        # unchanged (no model)
        assert findings["actionable"]

    def test_rank_report_findings_with_model(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        ranker = MagicMock()
        ranker.available.return_value = True
        ranker.rank.side_effect = lambda lst, code_for: list(reversed(lst))
        findings = {"actionable": [_finding(), _finding(severity="LOW")]}
        with patch("miesc.ml.triage_ranker.TriageRanker", return_value=ranker):
            _rank_report_findings(findings, contract=str(contract))
        ranker.rank.assert_called()


# ===========================================================================
# audit.py — CLI commands
# ===========================================================================


class TestAuditQuick:
    def test_quick_success_json(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "r.json"
        with patch(f"{AUDIT}.run_tool", return_value=_tool_result("slither", "success", [])):
            result = runner.invoke(audit, ["quick", str(contract), "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()

    def test_quick_not_available_and_error_tools(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")

        def fake_run(tool, *a, **k):
            if tool == "slither":
                return _tool_result(tool, "not_available", [])
            return _tool_result(tool, "error", [])

        with patch(f"{AUDIT}.run_tool", side_effect=fake_run):
            result = runner.invoke(audit, ["quick", str(contract)])
        assert result.exit_code == 0

    def test_quick_ci_exit_on_critical(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with (
            patch(
                f"{AUDIT}.run_tool",
                return_value=_tool_result("slither", "success", [_finding(severity="CRITICAL")]),
            ),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        ):
            result = runner.invoke(audit, ["quick", str(contract), "--ci"])
        assert result.exit_code == 1

    def test_quick_verify_fp_and_rank(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with (
            patch(f"{AUDIT}.run_tool", return_value=_tool_result("slither", "success", [])),
            patch("miesc.ml.benign_context_verifier.apply_to_results", return_value=(1, 2)),
            patch("miesc.ml.triage_ranker.rank_results", return_value=3),
        ):
            result = runner.invoke(audit, ["quick", str(contract), "--verify-fp", "--rank"])
        assert result.exit_code == 0
        assert "verify-fp" in result.output

    def test_quick_notify_dispatch(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        dispatch = MagicMock()
        with (
            patch(f"{AUDIT}.run_tool", return_value=_tool_result("slither", "success", [])),
            patch("miesc.core.notifiers.dispatch_notifications", dispatch),
        ):
            result = runner.invoke(
                audit, ["quick", str(contract), "--notify", "https://example.com/hook"]
            )
        assert result.exit_code == 0
        dispatch.assert_called_once()


class TestAuditFull:
    def test_full_ml_path(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        orch = MagicMock()
        orch.analyze.return_value = _fake_ml_result()
        with patch(f"{AUDIT}.get_ml_orchestrator", return_value=orch):
            result = runner.invoke(audit, ["full", str(contract)])
        assert result.exit_code == 0
        orch.analyze.assert_called_once()

    def test_full_correlation_path(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        api = MagicMock()
        api.analyze.return_value = {"summary": {}, "findings": {}}
        with (
            patch(f"{AUDIT}.get_ml_orchestrator", return_value=None),
            patch(f"{AUDIT}.get_correlation_api", return_value=api),
            patch(f"{AUDIT}.run_layer", return_value=[]),
        ):
            result = runner.invoke(audit, ["full", str(contract), "--no-ml"])
        assert result.exit_code == 0

    def test_full_basic_fallback(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with (
            patch(f"{AUDIT}.get_ml_orchestrator", return_value=None),
            patch(f"{AUDIT}.get_correlation_api", return_value=None),
            patch(f"{AUDIT}.run_layer", return_value=[]),
            patch(f"{AUDIT}.run_plugins", return_value=[]),
        ):
            result = runner.invoke(
                audit, ["full", str(contract), "--no-ml", "--no-correlate", "-l", "1,2"]
            )
        assert result.exit_code == 0


class TestAuditLayer:
    def test_layer_invalid(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        result = runner.invoke(audit, ["layer", "99", str(contract)])
        assert result.exit_code == 1
        assert "Invalid layer" in result.output

    def test_layer_valid_with_output(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "layer.json"
        with patch(
            f"{AUDIT}.run_layer",
            return_value=[_tool_result("slither", "success", [_finding()])],
        ):
            result = runner.invoke(audit, ["layer", "1", str(contract), "-o", str(out)])
        assert result.exit_code == 0
        assert json.loads(out.read_text())["layer"] == 1


class TestAuditSmart:
    def test_smart_no_orchestrator_falls_back(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with (
            patch(f"{AUDIT}.get_ml_orchestrator", return_value=None),
            patch(f"{AUDIT}.run_layer", return_value=[]),
            patch(f"{AUDIT}.run_plugins", return_value=[]),
        ):
            result = runner.invoke(audit, ["smart", str(contract)])
        assert result.exit_code == 0
        assert "not available" in result.output.lower()

    def test_smart_with_orchestrator_and_output(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "smart.json"
        orch = MagicMock()
        orch.analyze.return_value = _fake_ml_result()
        with patch(f"{AUDIT}.get_ml_orchestrator", return_value=orch):
            result = runner.invoke(audit, ["smart", str(contract), "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["llm_validated"] is False

    def test_smart_llm_validate(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        orch = MagicMock()
        orch.analyze.return_value = _fake_ml_result()
        validator = MagicMock()

        async def _batch(findings):
            return findings[:0], []  # drops all -> exercises llm_fp_count path

        validator.validate_findings_batch.side_effect = _batch

        async def _close():
            return None

        validator.close.side_effect = _close
        with (
            patch(f"{AUDIT}.get_ml_orchestrator", return_value=orch),
            patch("miesc.llm.finding_validator.LLMFindingValidator", return_value=validator),
            patch("miesc.llm.finding_validator.ValidatorConfig", MagicMock()),
        ):
            result = runner.invoke(audit, ["smart", str(contract), "--llm-validate"])
        assert result.exit_code == 0


class TestAuditProfile:
    def test_profile_list(self, runner):
        with patch(
            f"{AUDIT}.load_profiles",
            return_value={"fast": {"description": "d", "layers": [1], "timeout": 60}},
        ):
            result = runner.invoke(audit, ["profile", "list"])
        assert result.exit_code == 0
        assert "fast" in result.output

    def test_profile_missing_contract(self, runner):
        with patch(f"{AUDIT}.get_profile", return_value={"layers": [1]}):
            result = runner.invoke(audit, ["profile", "fast"])
        assert result.exit_code == 1
        assert "required" in result.output.lower()

    def test_profile_not_found(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with patch(f"{AUDIT}.get_profile", return_value=None):
            result = runner.invoke(audit, ["profile", "ghost", str(contract)])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_profile_tool_loop_with_output(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "p.json"
        profile = {"description": "d", "layers": [1], "timeout": 60, "tools": ["slither"]}
        with (
            patch(f"{AUDIT}.get_profile", return_value=profile),
            patch(f"{AUDIT}.run_tool", return_value=_tool_result("slither", "success", [])),
        ):
            result = runner.invoke(audit, ["profile", "custom", str(contract), "-o", str(out)])
        assert result.exit_code == 0
        assert json.loads(out.read_text())["profile"] == "custom"


class TestAuditSingle:
    def test_single_unknown_tool(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        result = runner.invoke(audit, ["single", "notatool", str(contract)])
        assert result.exit_code == 1
        assert "Unknown tool" in result.output

    def test_single_success_with_output(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "s.json"
        with patch(
            f"{AUDIT}.run_tool",
            return_value=_tool_result("slither", "success", [_finding()]),
        ):
            result = runner.invoke(audit, ["single", "slither", str(contract), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_single_failure(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        with patch(f"{AUDIT}.run_tool", return_value=_tool_result("slither", "error", [])):
            result = runner.invoke(audit, ["single", "slither", str(contract)])
        assert result.exit_code == 0
        assert "Failed" in result.output


class TestAuditBatch:
    def test_batch_no_files(self, runner, tmp_path):
        (tmp_path / "sub").mkdir()
        result = runner.invoke(audit, ["batch", str(tmp_path / "sub")])
        assert result.exit_code == 0
        assert "No" in result.output

    def test_batch_json(self, runner, tmp_path):
        (tmp_path / "A.sol").write_text("contract A {}")
        out = tmp_path / "b.json"
        with patch(
            f"{AUDIT}.run_tool",
            return_value=_tool_result("slither", "success", [_finding()]),
        ):
            result = runner.invoke(audit, ["batch", str(tmp_path), "-o", str(out), "-j", "1"])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["contracts_analyzed"] == 1

    def test_batch_csv(self, runner, tmp_path):
        (tmp_path / "A.sol").write_text("contract A {}")
        out = tmp_path / "b.csv"
        with patch(
            f"{AUDIT}.run_tool",
            return_value=_tool_result("slither", "success", [_finding()]),
        ):
            result = runner.invoke(
                audit, ["batch", str(tmp_path), "-o", str(out), "-f", "csv", "-j", "1"]
            )
        assert result.exit_code == 0
        assert "Contract" in out.read_text()

    def test_batch_fail_on(self, runner, tmp_path):
        (tmp_path / "A.sol").write_text("contract A {}")
        with patch(
            f"{AUDIT}.run_tool",
            return_value=_tool_result("slither", "success", [_finding(severity="CRITICAL")]),
        ):
            result = runner.invoke(
                audit, ["batch", str(tmp_path), "--fail-on", "critical", "-j", "1"]
            )
        assert result.exit_code == 1


class TestAuditDeep:
    def _fake_agent_result(self):
        return {
            "summary": {
                "CRITICAL": 1,
                "HIGH": 0,
                "total": 1,
                "tools_used": ["slither"],
                "iterations": 2,
            },
            "phases": {
                "reconnaissance": {"risk_profile": {"primary": "defi"}},
                "deep_investigation": {"iterations": 2},
            },
            "findings": [_finding(severity="CRITICAL")],
            "narrative": "Executive narrative text",
        }

    def test_deep_json_output(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "d.json"
        result_data = self._fake_agent_result()

        class FakeAgent:
            def __init__(self, config):
                pass

            def analyze(self, path):
                return result_data

        with patch("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent):
            result = runner.invoke(
                audit, ["deep", str(contract), "-o", str(out), "--no-llm", "--no-rag"]
            )
        assert result.exit_code == 0
        assert out.exists()

    def test_deep_markdown_and_ci(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        out = tmp_path / "d.md"
        result_data = self._fake_agent_result()

        class FakeAgent:
            def __init__(self, config):
                pass

            def analyze(self, path):
                return result_data

        with patch("miesc.agents.deep_audit_agent.DeepAuditAgent", FakeAgent):
            result = runner.invoke(
                audit, ["deep", str(contract), "-o", str(out), "-f", "markdown", "--ci", "--no-llm"]
            )
        # CI mode with a CRITICAL finding -> exit 1, but markdown still written first
        assert result.exit_code == 1
        assert out.exists()


# ===========================================================================
# plugins.py — CLI commands
# ===========================================================================


class TestPluginsInstall:
    def test_install_resolves_marketplace_slug(self, runner):
        mgr = MagicMock()
        mgr.resolve_marketplace_slug.return_value = "miesc-defi"
        mgr.check_pypi_compatibility.return_value = (
            CompatibilityInfo(status=CompatibilityStatus.COMPATIBLE),
            "1.0.0",
        )
        mgr.install.return_value = (True, "Successfully installed miesc-defi")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["install", "defi"])
        assert result.exit_code == 0
        mgr.resolve_marketplace_slug.assert_called_once_with("defi")

    def test_install_incompatible_aborts(self, runner):
        mgr = MagicMock()
        mgr.check_pypi_compatibility.return_value = (
            CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE, message="too old"),
            "0.1.0",
        )
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["install", "miesc-old"])
        assert result.exit_code == 1
        assert "incompatible" in result.output.lower()

    def test_install_warning_then_success(self, runner):
        mgr = MagicMock()
        mgr.check_pypi_compatibility.return_value = (
            CompatibilityInfo(status=CompatibilityStatus.WARNING, message="newer recommended"),
            "1.0.0",
        )
        mgr.install.return_value = (True, "Successfully installed miesc-x")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["install", "miesc-x"])
        assert result.exit_code == 0
        assert "warning" in result.output.lower()

    def test_install_no_check_failure(self, runner):
        mgr = MagicMock()
        mgr.install.return_value = (False, "pip failed")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["install", "miesc-x", "--no-check"])
        assert result.exit_code == 1
        mgr.check_pypi_compatibility.assert_not_called()


class TestPluginsUninstall:
    def test_uninstall_declined(self, runner):
        mgr = MagicMock()
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["uninstall", "miesc-x"], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.output
        mgr.uninstall.assert_not_called()

    def test_uninstall_yes_success(self, runner):
        mgr = MagicMock()
        mgr.uninstall.return_value = (True, "Successfully uninstalled miesc-x")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["uninstall", "miesc-x", "-y"])
        assert result.exit_code == 0

    def test_uninstall_fail(self, runner):
        mgr = MagicMock()
        mgr.uninstall.return_value = (False, "not installed")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["uninstall", "miesc-x", "-y"])
        assert result.exit_code == 1


class TestPluginsCreate:
    def test_create_success(self, runner, tmp_path):
        target = tmp_path / "my-plugin"
        target.mkdir()
        mgr = MagicMock()
        mgr.create_plugin_scaffold.return_value = target
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["create", "my-plugin", "-o", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created plugin" in result.output

    def test_create_failure(self, runner):
        mgr = MagicMock()
        mgr.create_plugin_scaffold.side_effect = RuntimeError("disk full")
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["create", "my-plugin"])
        assert result.exit_code == 1
        assert "Failed" in result.output


class TestPluginsSearch:
    def test_search_combined_results(self, runner):
        mgr = MagicMock()
        mgr.search_marketplace.return_value = [
            {
                "name": "DeFi",
                "pypi_package": "miesc-defi",
                "version": "1.0.0",
                "description": "defi detectors",
                "source": "marketplace",
                "verification_status": "verified",
            }
        ]
        mgr.search_pypi.return_value = [
            {"name": "miesc-reentrancy", "version": "2.0.0", "description": "reentrancy"}
        ]
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["search", "defi"])
        assert result.exit_code == 0
        assert "miesc-defi" in result.output

    def test_search_empty(self, runner):
        mgr = MagicMock()
        mgr.search_marketplace.return_value = []
        mgr.search_pypi.return_value = []
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["search", "nothing"])
        assert result.exit_code == 0
        assert "No plugins found" in result.output

    def test_search_pypi_only(self, runner):
        mgr = MagicMock()
        mgr.search_pypi.return_value = [{"name": "miesc-x", "version": "1.0", "description": "x"}]
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["search", "x", "--pypi-only"])
        assert result.exit_code == 0
        mgr.search_marketplace.assert_not_called()


class TestPluginsPath:
    def test_path_create(self, runner, tmp_path):
        mgr = MagicMock()
        created = tmp_path / "plugins"
        created.mkdir()
        mgr.LOCAL_PLUGINS_DIR = created
        mgr.ensure_local_plugins_dir.return_value = created
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["path", "--create"])
        assert result.exit_code == 0
        assert "created" in result.output.lower()

    def test_path_exists_with_count(self, runner, tmp_path):
        d = tmp_path / "plugins"
        d.mkdir()
        (d / "plug1").mkdir()
        mgr = MagicMock()
        mgr.LOCAL_PLUGINS_DIR = d
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["path"])
        assert result.exit_code == 0
        assert "Directory exists" in result.output

    def test_path_missing(self, runner, tmp_path):
        mgr = MagicMock()
        mgr.LOCAL_PLUGINS_DIR = tmp_path / "does-not-exist"
        with patch("miesc.plugins.PluginManager", return_value=mgr):
            result = runner.invoke(plugins, ["path"])
        assert result.exit_code == 0
        assert "does not exist" in result.output.lower()


class TestPluginsNew:
    def test_new_success(self, runner, tmp_path):
        created = tmp_path / "my-detector"
        created.mkdir()
        (created / "plugin.py").write_text("# plugin")
        generator = MagicMock()
        generator.create_plugin.return_value = created
        with patch("miesc.plugins.PluginTemplateGenerator", return_value=generator):
            result = runner.invoke(plugins, ["new", "my-detector", "-o", str(tmp_path)])
        assert result.exit_code == 0
        assert "Plugin created" in result.output

    def test_new_failure(self, runner):
        generator = MagicMock()
        generator.create_plugin.side_effect = RuntimeError("template error")
        with patch("miesc.plugins.PluginTemplateGenerator", return_value=generator):
            result = runner.invoke(plugins, ["new", "my-detector"])
        assert result.exit_code == 1
        assert "Failed" in result.output


class TestPluginsRuntime:
    def test_runtime_empty(self, runner):
        registry = MagicMock()
        registry.list_plugins.return_value = []
        with patch("miesc.plugins.get_registry", return_value=registry):
            result = runner.invoke(plugins, ["runtime"])
        assert result.exit_code == 0
        assert "No plugins loaded" in result.output

    def test_runtime_with_plugins(self, runner):
        entry = SimpleNamespace(
            name="det",
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
        assert result.exit_code == 0
        assert "det" in result.output


class TestPluginsLoad:
    def test_load_no_classes(self, runner, tmp_path):
        pf = tmp_path / "p.py"
        pf.write_text("# nothing")
        loader = MagicMock()
        loader.load_plugin_file.return_value = []
        with (
            patch("miesc.plugins.PluginLoader", return_value=loader),
            patch("miesc.plugins.get_registry", return_value=MagicMock()),
            patch("miesc.plugins.PluginContext", MagicMock()),
        ):
            result = runner.invoke(plugins, ["load", str(pf)])
        assert result.exit_code == 0
        assert "No plugin classes" in result.output

    def test_load_success(self, runner, tmp_path):
        pf = tmp_path / "p.py"
        pf.write_text("# plugin")
        loader = MagicMock()
        loaded = MagicMock()
        loader.load_plugin_file.return_value = [loaded]
        registry = MagicMock()
        registry.register.return_value = SimpleNamespace(
            name="det", version="1.0.0", plugin_type=SimpleNamespace(value="detector")
        )
        with (
            patch("miesc.plugins.PluginLoader", return_value=loader),
            patch("miesc.plugins.get_registry", return_value=registry),
            patch("miesc.plugins.PluginContext", MagicMock()),
        ):
            result = runner.invoke(plugins, ["load", str(pf)])
        assert result.exit_code == 0
        assert "Loaded" in result.output

    def test_load_error(self, runner, tmp_path):
        pf = tmp_path / "p.py"
        pf.write_text("# plugin")
        loader = MagicMock()
        loader.load_plugin_file.side_effect = RuntimeError("bad file")
        with (
            patch("miesc.plugins.PluginLoader", return_value=loader),
            patch("miesc.plugins.get_registry", return_value=MagicMock()),
            patch("miesc.plugins.PluginContext", MagicMock()),
        ):
            result = runner.invoke(plugins, ["load", str(pf)])
        assert result.exit_code == 1


class TestPluginsMarketplace:
    def test_marketplace_empty(self, runner):
        client = MagicMock()
        client.browse.return_value = []
        with patch("miesc.plugins.marketplace.MarketplaceClient", return_value=client):
            result = runner.invoke(plugins, ["marketplace"])
        assert result.exit_code == 0
        assert "No plugins found" in result.output

    def test_marketplace_with_plugins(self, runner):
        from miesc.plugins.marketplace import VerificationStatus

        p = SimpleNamespace(
            name="DeFi",
            version="1.0.0",
            plugin_type="detector",
            verification_status=VerificationStatus.VERIFIED,
            author="me",
            description="defi detectors",
            tags={"defi"},
        )
        client = MagicMock()
        client.browse.return_value = [p]
        with patch("miesc.plugins.marketplace.MarketplaceClient", return_value=client):
            result = runner.invoke(plugins, ["marketplace", "--tag", "defi", "--verified-only"])
        assert result.exit_code == 0
        assert "DeFi" in result.output

    def test_marketplace_error(self, runner):
        client = MagicMock()
        client.browse.side_effect = RuntimeError("network down")
        with patch("miesc.plugins.marketplace.MarketplaceClient", return_value=client):
            result = runner.invoke(plugins, ["marketplace"])
        assert result.exit_code == 1


class TestPluginsSubmit:
    def test_submit_success(self, runner):
        client = MagicMock()
        client.generate_submission.return_value = {"name": "X"}
        client.validate_submission.return_value = []
        with patch("miesc.plugins.marketplace.MarketplaceClient", return_value=client):
            result = runner.invoke(
                plugins,
                [
                    "submit",
                    "--name",
                    "My Detector",
                    "--package",
                    "miesc-my",
                    "--version",
                    "1.0.0",
                    "--type",
                    "detector",
                    "--description",
                    "does things",
                    "--author",
                    "Dev",
                ],
            )
        assert result.exit_code == 0
        assert "generated" in result.output.lower()

    def test_submit_validation_fail(self, runner):
        client = MagicMock()
        client.generate_submission.return_value = {"name": "X"}
        client.validate_submission.return_value = ["missing field"]
        with patch("miesc.plugins.marketplace.MarketplaceClient", return_value=client):
            result = runner.invoke(
                plugins,
                [
                    "submit",
                    "--name",
                    "X",
                    "--package",
                    "miesc-x",
                    "--version",
                    "1.0.0",
                    "--type",
                    "detector",
                    "--description",
                    "d",
                    "--author",
                    "Dev",
                ],
            )
        assert result.exit_code == 1
        assert "validation failed" in result.output.lower()


# ===========================================================================
# manager.py — module-level helpers & dataclasses
# ===========================================================================


class TestVersionHelpers:
    def test_compare_versions(self):
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.2.3", "1.2.3") == 0
        # alphanumeric part normalization ("4.3.3a1")
        assert compare_versions("4.3.3a1", "4.3.3") == 0

    def test_get_miesc_version(self):
        assert isinstance(get_miesc_version(), str)

    def test_version_constraint_from_string_operators(self):
        c = VersionConstraint.from_string("miesc>=4.0.0,<5.0.0")
        assert c.min_version == "4.0.0" and c.min_inclusive is True
        assert c.max_version == "5.0.0" and c.max_inclusive is False
        assert ">=4.0.0" in str(c)

    def test_version_constraint_exact_and_compatible(self):
        exact = VersionConstraint.from_string("==4.2.0")
        assert exact.min_version == exact.max_version == "4.2.0"
        compat = VersionConstraint.from_string("~=4.2.0")
        assert compat.min_version == "4.2.0"
        assert compat.max_version == "4.3.0"

    def test_version_constraint_str_any(self):
        assert str(VersionConstraint()) == "any"

    def test_compatibility_info_str(self):
        assert str(CompatibilityInfo(status=CompatibilityStatus.COMPATIBLE)) == "compatible"
        assert "incompatible" in str(
            CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE, message="x")
        )
        assert "warning" in str(CompatibilityInfo(status=CompatibilityStatus.WARNING, message="y"))
        assert str(CompatibilityInfo(status=CompatibilityStatus.UNKNOWN)) == "unknown"

    def test_plugin_info_str(self):
        p = PluginInfo(name="d", package="miesc-d", version="1.0.0")
        assert "enabled" in str(p)
        p.enabled = False
        assert "disabled" in str(p)
        p.compatibility = CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE)
        assert "incompatible" in str(p)


# ===========================================================================
# manager.py — PluginManager methods (mocked config + filesystem + network)
# ===========================================================================


@pytest.fixture
def manager(tmp_path) -> PluginManager:
    cfg = MagicMock()
    cfg.is_enabled.return_value = True
    mgr = PluginManager(config_manager=cfg)
    # Point local plugin dir at an isolated tmp location per-instance.
    mgr.LOCAL_PLUGINS_DIR = tmp_path / "local_plugins"
    return mgr


class TestPluginManagerValidate:
    def test_validate_no_constraint(self, manager):
        info = manager.validate_compatibility()
        assert info.status == CompatibilityStatus.UNKNOWN

    def test_validate_incompatible_min(self, manager):
        manager._miesc_version = "4.0.0"
        info = manager.validate_compatibility(requires_miesc="miesc>=5.0.0")
        assert info.status == CompatibilityStatus.INCOMPATIBLE

    def test_validate_incompatible_max(self, manager):
        manager._miesc_version = "6.0.0"
        info = manager.validate_compatibility(requires_miesc="miesc<5.0.0")
        assert info.status == CompatibilityStatus.INCOMPATIBLE

    def test_validate_compatible(self, manager):
        manager._miesc_version = "6.0.0"
        info = manager.validate_compatibility(requires_miesc="miesc>=5.0.0,<7.0.0")
        assert info.status == CompatibilityStatus.COMPATIBLE

    def test_validate_python_warning(self, manager):
        manager._miesc_version = "6.0.0"
        info = manager.validate_compatibility(
            requires_miesc="miesc>=5.0.0", requires_python=">=99.0"
        )
        assert info.status == CompatibilityStatus.WARNING

    def test_normalize_package_name(self, manager):
        assert manager._normalize_package_name("foo") == "miesc-foo"
        assert manager._normalize_package_name("miesc-foo") == "miesc-foo"


class _FakeResp:
    def __init__(self, status, payload):
        self.status = status
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestPluginManagerPyPI:
    def test_check_pypi_success(self, manager):
        payload = {
            "info": {
                "version": "2.0.0",
                "requires_dist": ["miesc>=5.0.0"],
                "requires_python": ">=3.10",
            }
        }
        manager._miesc_version = "6.0.0"
        with patch("urllib.request.urlopen", return_value=_FakeResp(200, payload)):
            info, version = manager.check_pypi_compatibility("miesc-x")
        assert version == "2.0.0"
        assert info.status == CompatibilityStatus.COMPATIBLE

    def test_check_pypi_not_found(self, manager):
        err = urllib.error.HTTPError("u", 404, "nf", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            info, version = manager.check_pypi_compatibility("miesc-ghost")
        assert version is None
        assert info.status == CompatibilityStatus.UNKNOWN

    def test_check_pypi_generic_error(self, manager):
        with patch("urllib.request.urlopen", side_effect=OSError("dns")):
            info, version = manager.check_pypi_compatibility("miesc-x")
        assert version is None
        assert "Could not check" in info.message

    def test_search_pypi(self, manager):
        payload = {
            "info": {
                "name": "miesc-reentrancy",
                "version": "1.0.0",
                "summary": "reentrancy detector",
            }
        }
        with patch("urllib.request.urlopen", return_value=_FakeResp(200, payload)):
            results = manager.search_pypi("reentrancy")
        assert results and results[0]["name"]

    def test_search_pypi_http_errors(self, manager):
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError("u", 404, "nf", {}, None),
        ):
            assert manager.search_pypi("ghostplugin") == []


class TestPluginManagerInstallUninstall:
    def test_install_success(self, manager):
        proc = SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch("miesc.plugins.manager.subprocess.run", return_value=proc),
            patch("miesc.plugins.manager.importlib.metadata.version", return_value="1.0.0"),
        ):
            ok, msg = manager.install("foo", check_compatibility=False)
        assert ok is True
        manager.config_manager.enable_plugin.assert_called_once()

    def test_install_incompatible_without_force(self, manager):
        incompat = CompatibilityInfo(status=CompatibilityStatus.INCOMPATIBLE, message="old")
        with patch.object(manager, "check_pypi_compatibility", return_value=(incompat, "0.1")):
            ok, msg = manager.install("foo", check_compatibility=True)
        assert ok is False
        assert "incompatible" in msg.lower()

    def test_install_pip_failure(self, manager):
        proc = SimpleNamespace(returncode=1, stdout="", stderr="pip error")
        with patch("miesc.plugins.manager.subprocess.run", return_value=proc):
            ok, msg = manager.install("foo", check_compatibility=False)
        assert ok is False
        assert "Failed to install" in msg

    def test_install_timeout(self, manager):
        import subprocess as _sp

        with patch(
            "miesc.plugins.manager.subprocess.run",
            side_effect=_sp.TimeoutExpired("pip", 300),
        ):
            ok, msg = manager.install("foo", check_compatibility=False)
        assert ok is False
        assert "timed out" in msg

    def test_uninstall_success(self, manager):
        proc = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("miesc.plugins.manager.subprocess.run", return_value=proc):
            ok, msg = manager.uninstall("foo")
        assert ok is True
        manager.config_manager.remove_plugin.assert_called_once()

    def test_uninstall_failure(self, manager):
        proc = SimpleNamespace(returncode=1, stdout="", stderr="not installed")
        with patch("miesc.plugins.manager.subprocess.run", return_value=proc):
            ok, msg = manager.uninstall("foo")
        assert ok is False


class TestPluginManagerDiscovery:
    def _fake_ep(self, name="det1", pkg="miesc-foo", version="1.0.0"):
        meta = MagicMock()
        meta.get.side_effect = lambda k, d="": {
            "Summary": "a plugin",
            "Author": "me",
            "Requires-Python": ">=3.10",
        }.get(k, d)
        meta.get_all.return_value = ["miesc>=5.0.0"]
        dist = SimpleNamespace(name=pkg, version=version, metadata=meta)
        return SimpleNamespace(name=name, dist=dist)

    def test_discover_plugins_from_entry_points(self, manager):
        manager._miesc_version = "6.0.0"
        with patch(
            "miesc.plugins.manager._entry_points_for_group",
            return_value=[self._fake_ep(), self._fake_ep(name="det2")],
        ):
            plugins_found = manager.list_installed()
        assert len(plugins_found) == 1
        assert plugins_found[0].detector_count == 2

    def test_list_installed_filters_disabled(self, manager):
        manager._cached_plugins = [
            PluginInfo(name="a", package="miesc-a", version="1", enabled=True),
            PluginInfo(name="b", package="miesc-b", version="1", enabled=False),
        ]
        assert len(manager.list_installed(include_disabled=False)) == 1

    def test_discover_local_plugins_missing_dir(self, manager):
        assert manager._discover_local_plugins() == []

    def test_load_local_plugin_info_from_pyproject(self, manager):
        d = manager.LOCAL_PLUGINS_DIR / "my_plugin"
        d.mkdir(parents=True)
        (d / "__init__.py").write_text("")
        (d / "pyproject.toml").write_text(
            '[project]\nname = "my_plugin"\nversion = "2.1.0"\n'
            'description = "local test plugin"\nauthors = [{name = "Dev"}]\n'
        )
        info = manager._load_local_plugin_info(d)
        assert info is not None
        assert info.version == "2.1.0"
        assert info.local is True
        assert info.author == "Dev"

    def test_load_local_plugin_info_rejects_empty(self, manager):
        d = manager.LOCAL_PLUGINS_DIR / "empty"
        d.mkdir(parents=True)
        assert manager._load_local_plugin_info(d) is None

    def test_discover_local_plugins_with_valid(self, manager):
        base = manager.LOCAL_PLUGINS_DIR
        (base / "good").mkdir(parents=True)
        (base / "good" / "__init__.py").write_text("")
        (base / ".hidden").mkdir()
        (base / "afile.txt").write_text("x")
        found = manager._discover_local_plugins()
        assert [p.name for p in found] == ["good"]

    def test_ensure_local_plugins_dir(self, manager):
        created = manager.ensure_local_plugins_dir()
        assert created.exists()


class TestPluginManagerEnableDisableInfo:
    def _installed(self):
        return [PluginInfo(name="foo", package="miesc-foo", version="1.0.0")]

    def test_enable_found(self, manager):
        with patch.object(manager, "list_installed", return_value=self._installed()):
            ok, msg = manager.enable("foo")
        assert ok is True
        manager.config_manager.enable_plugin.assert_called()

    def test_enable_not_found(self, manager):
        with patch.object(manager, "list_installed", return_value=[]):
            ok, msg = manager.enable("ghost")
        assert ok is False
        assert "not found" in msg

    def test_disable_found(self, manager):
        with patch.object(manager, "list_installed", return_value=self._installed()):
            ok, msg = manager.disable("foo")
        assert ok is True
        manager.config_manager.disable_plugin.assert_called()

    def test_disable_not_found(self, manager):
        with patch.object(manager, "list_installed", return_value=[]):
            ok, msg = manager.disable("ghost")
        assert ok is False

    def test_get_plugin_info(self, manager):
        with patch.object(manager, "list_installed", return_value=self._installed()):
            assert manager.get_plugin_info("foo") is not None
            assert manager.get_plugin_info("miesc-foo") is not None
            assert manager.get_plugin_info("ghost") is None


class TestPluginManagerEnabledDetectors:
    def test_get_enabled_detectors(self, manager):
        detector_cls = type("MyDet", (), {"name": "my-det"})
        dist = SimpleNamespace(name="miesc-foo")
        ep = SimpleNamespace(name="my-det", dist=dist, load=lambda: detector_cls)
        with (
            patch("miesc.plugins.manager._entry_points_for_group", return_value=[ep]),
            patch.object(manager, "get_local_plugin_detectors", return_value=[]),
        ):
            detectors = manager.get_enabled_detectors()
        assert detectors == [("my-det", detector_cls)]

    def test_get_enabled_detectors_skips_disabled(self, manager):
        manager.config_manager.is_enabled.return_value = False
        dist = SimpleNamespace(name="miesc-foo")
        ep = SimpleNamespace(name="my-det", dist=dist, load=MagicMock())
        with (
            patch("miesc.plugins.manager._entry_points_for_group", return_value=[ep]),
            patch.object(manager, "get_local_plugin_detectors", return_value=[]),
        ):
            detectors = manager.get_enabled_detectors()
        assert detectors == []
        ep.load.assert_not_called()


class TestPluginManagerMarketplace:
    def test_search_marketplace(self, manager):
        client = MagicMock()
        plugin = SimpleNamespace(
            name="DeFi",
            version="1.0.0",
            description="defi",
            homepage="https://h",
            repository="https://r",
            slug="defi",
            pypi_package="miesc-defi",
            verification_status=SimpleNamespace(value="verified"),
        )
        client.search.return_value = [SimpleNamespace(plugin=plugin)]
        with patch.object(manager, "get_marketplace_client", return_value=client):
            results = manager.search_marketplace("defi")
        assert results[0]["pypi_package"] == "miesc-defi"

    def test_search_marketplace_error(self, manager):
        with patch.object(manager, "get_marketplace_client", side_effect=RuntimeError("x")):
            assert manager.search_marketplace("defi") == []

    def test_resolve_marketplace_slug(self, manager):
        client = MagicMock()
        client.get_plugin.return_value = SimpleNamespace(pypi_package="miesc-defi")
        with patch.object(manager, "get_marketplace_client", return_value=client):
            assert manager.resolve_marketplace_slug("defi") == "miesc-defi"

    def test_resolve_marketplace_slug_error(self, manager):
        with patch.object(manager, "get_marketplace_client", side_effect=RuntimeError("x")):
            assert manager.resolve_marketplace_slug("defi") is None
