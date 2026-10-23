"""One tool-status vocabulary across scan, audit and doctor (plan B.3).

success / skipped / timeout / error, with ``reason`` on skips and
``fallback: True`` on built-in heuristics; doctor and audit print the same
"available" denominator.
"""

import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from miesc.cli import utils
from miesc.cli.commands.audit import audit
from miesc.cli.commands.doctor import doctor
from miesc.cli.commands.scan import scan
from miesc.cli.constants import LAYERS
from miesc.core.ml_orchestrator import MLAnalysisResult, MLOrchestrator, _normalize_status
from miesc.core.tool_protocol import ToolStatus


def _adapter(status=ToolStatus.AVAILABLE, result=None, raise_on_analyze=None):
    a = Mock()
    a.is_available.return_value = status
    if raise_on_analyze:
        a.analyze.side_effect = raise_on_analyze
    else:
        a.analyze.return_value = result or {"status": "success", "findings": []}
    return a


@pytest.fixture(autouse=True)
def _fresh_availability():
    utils.AdapterLoader.reset_availability()
    yield
    utils.AdapterLoader.reset_availability()


class TestNormalize:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("success", "success"),
            ("ok", "success"),
            ("skipped", "skipped"),
            ("not_available", "skipped"),
            ("no_adapter", "skipped"),
            ("timeout", "timeout"),
            ("error", "error"),
            ("failed", "error"),
            ("something-new", "error"),
            (None, "success"),
        ],
    )
    def test_every_label_lands_in_the_vocabulary(self, raw, expected):
        assert utils.normalize_tool_status(raw) == expected
        assert utils.normalize_tool_status(raw) in utils.TOOL_STATUSES

    def test_unknown_label_is_flagged_not_silently_succeeded(self):
        r = utils.normalize_tool_result({"status": "verified", "findings": []})
        assert r["status"] == "error" and r["reason"] == "unknown_status:verified"

    def test_metadata_reason_and_fallback_are_lifted(self):
        r = utils.normalize_tool_result(
            {"status": "skipped", "metadata": {"reason": "unsupported_source"}}
        )
        assert r["reason"] == "unsupported_source"
        r = utils.normalize_tool_result({"status": "success", "metadata": {"fallback": True}})
        assert r["fallback"] is True

    def test_ml_orchestrator_shares_the_mapping(self):
        assert _normalize_status({"status": "not_available"})["status"] == "skipped"
        assert _normalize_status({"status": "failed"})["status"] == "error"


class TestRunTool:
    def test_not_installed_is_skipped_with_reason(self, tmp_path):
        with patch.object(
            utils.AdapterLoader, "get_adapter", return_value=_adapter(ToolStatus.NOT_INSTALLED)
        ):
            r = utils.run_tool("mythril", str(tmp_path / "C.sol"), timeout=5)
        assert r["status"] == "skipped" and r["reason"] == "not_installed"

    def test_configuration_error_is_skipped_with_its_reason(self, tmp_path):
        with patch.object(
            utils.AdapterLoader,
            "get_adapter",
            return_value=_adapter(ToolStatus.CONFIGURATION_ERROR),
        ):
            r = utils.run_tool("iaudit", str(tmp_path / "C.sol"), timeout=5)
        assert (r["status"], r["reason"]) == ("skipped", "configuration_error")

    def test_no_adapter_is_skipped(self, tmp_path):
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=None):
            r = utils.run_tool("ghost", str(tmp_path / "C.sol"), timeout=5)
        assert (r["status"], r["reason"]) == ("skipped", "no_adapter")

    def test_adapter_timeout_and_skip_reasons_pass_through(self, tmp_path):
        timed = _adapter(result={"status": "timeout", "findings": [], "error": "killed"})
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=timed):
            r = utils.run_tool("mythril", str(tmp_path / "C.sol"), timeout=5)
        assert r["status"] == "timeout"
        aderyn_panic = _adapter(
            result={
                "status": "skipped",
                "findings": [],
                "metadata": {"reason": "unsupported_source"},
            }
        )
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=aderyn_panic):
            r = utils.run_tool("aderyn", str(tmp_path / "C.sol"), timeout=5)
        assert (r["status"], r["reason"]) == ("skipped", "unsupported_source")

    def test_fallback_flag_is_kept(self, tmp_path):
        fb = _adapter(result={"status": "success", "findings": [], "fallback": True})
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=fb):
            r = utils.run_tool("dagnn", str(tmp_path / "C.sol"), timeout=5)
        assert r["status"] == "success" and r["fallback"] is True
        assert utils.describe_tool_status(r) == "success (fallback)"

    def test_exception_is_error(self, tmp_path):
        boom = _adapter(raise_on_analyze=RuntimeError("boom"))
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=boom):
            r = utils.run_tool("slither", str(tmp_path / "C.sol"), timeout=5)
        assert r["status"] == "error" and "boom" in r["error"]


class TestSummaries:
    def test_summarize_and_format(self):
        results = [
            {"tool": "slither", "status": "success"},
            {"tool": "dagnn", "status": "success", "fallback": True},
            {"tool": "mythril", "status": "skipped", "reason": "not_installed"},
            {"tool": "wake", "status": "timeout"},
            {"tool": "semgrep", "status": "error"},
            {"status": "success"},  # no tool name: ignored
        ]
        b = utils.summarize_tool_statuses(results)
        assert b == {
            "success": ["slither", "dagnn"],
            "fallback": ["dagnn"],
            "skipped": ["mythril"],
            "timeout": ["wake"],
            "error": ["semgrep"],
        }
        assert utils.format_tool_summary(results) == (
            "ran 2/5 (1 fallback) · skipped 1 · timeout 1 · error 1"
        )

    def test_describe(self):
        assert (
            utils.describe_tool_status({"status": "skipped", "reason": "no_llm"})
            == "skipped (no_llm)"
        )
        assert utils.describe_tool_status({"status": "not_available"}) == "skipped (excluded)"
        assert utils.describe_tool_status({"status": "timeout"}) == "timeout"


class TestMLOrchestrator:
    def test_dataclass_defaults_keep_positional_construction(self):
        r = MLAnalysisResult(
            contract_path="C.sol",
            contract_source="",
            tools_run=["slither"],
            tools_success=["slither"],
            tools_failed=[],
            total_raw_findings=0,
            raw_findings=[],
            ml_filtered_findings=[],
            ml_filtered_out=[],
            false_positives_removed=0,
            severity_adjustments=0,
            clusters=[],
            cluster_count=0,
            remediation_plan=[],
            pattern_matches=[],
            severity_distribution={},
            cross_validated=0,
            execution_time_ms=0.0,
            ml_processing_time_ms=0.0,
            timestamp=datetime.now(),
        )
        d = r.to_dict()
        assert d["tools_skipped"] == [] and d["tools_fallback"] == [] and d["tool_status"] == {}

    def test_run_tool_marks_fallback_and_skips_missing_tools(self, tmp_path):
        orch = MLOrchestrator.__new__(MLOrchestrator)
        orch.cache = None
        orch.config = SimpleNamespace(get_adapter_config=lambda t: SimpleNamespace(timeout=None))
        heuristic = _adapter(
            ToolStatus.NOT_INSTALLED, {"status": "success", "findings": [{"type": "x"}]}
        )
        missing = _adapter(
            ToolStatus.NOT_INSTALLED, {"status": "error", "findings": [], "error": "no slither"}
        )
        real = _adapter(ToolStatus.AVAILABLE, {"status": "success", "findings": []})
        orch.discovery = SimpleNamespace(
            load_adapter=lambda name: {"dagnn": heuristic, "slither": missing, "aderyn": real}[name]
        )
        fb = orch._run_tool("dagnn", str(tmp_path / "C.sol"))
        assert (
            fb["status"] == "success" and fb["fallback"] is True and fb["reason"] == "not_installed"
        )
        sk = orch._run_tool("slither", str(tmp_path / "C.sol"))
        assert sk["status"] == "skipped" and sk["reason"] == "not_installed"
        ok = orch._run_tool("aderyn", str(tmp_path / "C.sol"))
        assert ok["status"] == "success" and "fallback" not in ok


class TestSameDenominator:
    """``miesc doctor`` and ``miesc audit full`` print the same available count."""

    @staticmethod
    def _fake_status(tool):
        if tool in ("mythril", "dagnn", "smartbugs_ml"):
            return {"available": False, "status": "not_installed", "install_cmd": "pip install x"}
        return {"available": True, "status": "available", "install_cmd": ""}

    def test_doctor_and_audit_full_agree(self, tmp_path):
        total = sum(len(layer["tools"]) for layer in LAYERS.values())
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def fake_layer(layer_num, contract_path, timeout, **_):
            out = []
            for tool in LAYERS[layer_num]["tools"]:
                if tool in ("mythril",):
                    out.append(
                        {
                            "tool": tool,
                            "status": "skipped",
                            "reason": "not_installed",
                            "findings": [],
                        }
                    )
                elif tool in ("dagnn", "smartbugs_ml"):
                    out.append(
                        {"tool": tool, "status": "success", "fallback": True, "findings": []}
                    )
                else:
                    out.append({"tool": tool, "status": "success", "findings": []})
            return out

        fake_completed = SimpleNamespace(stdout="v1\n", stderr="")
        with (
            patch("miesc.cli.commands.doctor.print_banner"),
            patch("miesc.cli.commands.doctor.subprocess.run", return_value=fake_completed),
            patch("miesc.cli.commands.doctor._provider_status", return_value=("x", "y")),
            patch("miesc.cli.utils.AdapterLoader.check_tool_status", side_effect=self._fake_status),
        ):
            doc = CliRunner().invoke(doctor)
            with (
                patch("miesc.cli.commands.audit.run_layer", side_effect=fake_layer),
                patch("miesc.cli.commands.audit.run_plugins", return_value=[]),
            ):
                aud = CliRunner().invoke(
                    audit,
                    [
                        "full",
                        str(contract),
                        "--no-ml",
                        "--no-correlate",
                        "-l",
                        ",".join(str(n) for n in LAYERS),
                    ],
                )
        assert doc.exit_code == 0, doc.output
        assert aud.exit_code == 0, aud.output
        expected = f"{total - 3}/{total}"
        assert expected in doc.output
        assert f"available {expected}" in aud.output
        assert "(2 fallback)" in aud.output
        assert "skipped 1" in aud.output and "failed 0" in aud.output


def test_scan_json_separates_skipped_from_failed(tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")
    out = tmp_path / "out.json"

    def fake_run_tool(tool, *a, **k):
        if tool == "aderyn":
            return {"tool": tool, "status": "skipped", "reason": "not_installed", "findings": []}
        if tool == "solhint":
            return {"tool": tool, "status": "timeout", "findings": [], "error": "killed"}
        return {"tool": tool, "status": "success", "findings": []}

    with (
        patch("miesc.cli.commands.scan.run_tool", side_effect=fake_run_tool),
        patch("miesc.cli.commands.scan.run_access_control_semantic", return_value=None),
    ):
        result = CliRunner().invoke(scan, [str(contract), "-q", "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["tools"] == ["slither"]
    assert data["tools_skipped"] == ["aderyn"]
    assert data["tools_failed"] == ["solhint"]
