"""Behavioural coverage for the compatibility ``MIESCOrchestrator`` (miesc/core/orchestrator.py).

The orchestrator shells out to slither/myth via ``subprocess.run``; every test mocks that one
boundary with realistic tool output and asserts the parsed findings, layer routing, availability
handling, and summary — no real tool, no network.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from miesc.core import orchestrator as orch_mod
from miesc.core.orchestrator import IMPLEMENTED_TOOLS, MIESCOrchestrator


def _completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr="")


def _orch(available):
    """An orchestrator with a fixed availability map (bypassing the real tool probe)."""
    with patch.object(orch_mod.subprocess, "run", return_value=_completed(returncode=0)):
        o = MIESCOrchestrator()
    o.available_tools = dict(available)
    return o


@pytest.fixture
def contract(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C {}\n")
    return str(p)


_SLITHER_JSON = json.dumps(
    {
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "description": "reentrancy in withdraw",
                    "elements": [{"type": "function"}],
                }
            ]
        }
    }
)
_MYTH_JSON = json.dumps(
    {
        "issues": [
            {"title": "Integer Overflow", "severity": "High", "description": "x", "swc-id": "101"}
        ]
    }
)


# --- _check_tools -----------------------------------------------------------------------------
def test_check_tools_marks_available_and_unavailable():
    def fake(cmd, **kw):
        return _completed(returncode=0 if cmd[0] == "slither" else 1)

    with patch.object(orch_mod.subprocess, "run", side_effect=fake):
        o = MIESCOrchestrator()
    assert o.available_tools["slither"] is True
    assert o.available_tools["mythril"] is False


def test_check_tools_handles_missing_binary():
    with patch.object(orch_mod.subprocess, "run", side_effect=FileNotFoundError):
        o = MIESCOrchestrator()
    assert o.available_tools == {"slither": False, "mythril": False}


# --- audit / analyze --------------------------------------------------------------------------
def test_audit_missing_contract_raises(contract, tmp_path):
    o = _orch({"slither": False, "mythril": False})
    with pytest.raises(FileNotFoundError):
        o.audit(str(tmp_path / "nope.sol"))


def test_analyze_delegates_to_audit(contract):
    o = _orch({"slither": False, "mythril": False})
    with patch.object(o, "audit", return_value={"ok": True}) as m:
        assert o.analyze(contract, layers=[1], tools=["slither"]) == {"ok": True}
    m.assert_called_once()


def test_run_quick_audit_delegates(contract):
    o = _orch({"slither": False, "mythril": False})
    with patch.object(o, "audit", return_value={"summary": {}}) as m:
        o.run_quick_audit(contract)
    m.assert_called_once()


def test_audit_runs_slither_layer_and_aggregates(contract):
    o = _orch({"slither": True, "mythril": False})
    with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout=_SLITHER_JSON)):
        # layer passed as a string must be coerced to int; an unknown layer is skipped.
        result = o.audit(contract, layers=["1", 999], tools=["slither"])
    assert result["contract"].endswith("C.sol")
    assert sorted(IMPLEMENTED_TOOLS) == result["supported_tools"]
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "reentrancy-eth"
    assert result["findings"][0]["severity"] == "high"
    assert result["summary"]["by_severity"]["high"] == 1
    assert result["summary"]["total_findings"] == 1
    assert "slither" in result["summary"]["tools_used"]
    assert result["execution_time"] >= 0


# --- _run_layer branches ----------------------------------------------------------------------
def test_run_layer_skips_unimplemented_and_unavailable(contract, caplog):
    o = _orch({"slither": False})  # slither unavailable; aderyn not implemented here
    layer_info = o.LAYERS[1]
    res = o._run_layer(1, layer_info, contract, None, 60, verbose=True)
    skipped = {s["tool"]: s["reason"] for s in res["tools_skipped"]}
    assert skipped.get("aderyn") == "not_implemented_in_compatibility_orchestrator"
    assert skipped.get("slither") == "unavailable"
    assert res["tools_run"] == []


def test_run_layer_records_tool_exception(contract):
    o = _orch({"slither": True})
    with patch.object(o, "_run_tool", side_effect=RuntimeError("boom")):
        res = o._run_layer(1, o.LAYERS[1], contract, ["slither"], 60, verbose=False)
    # the exception is logged and swallowed; the tool is not added to tools_run
    assert res["tools_run"] == []
    assert res["findings"] == []


# --- _run_tool dispatch -----------------------------------------------------------------------
def test_run_tool_dispatches_and_ignores_unknown(contract):
    o = _orch({"slither": True, "mythril": True})
    with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout=_SLITHER_JSON)):
        assert o._run_tool("slither", contract, 60)["findings"][0]["tool"] == "slither"
    with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout=_MYTH_JSON)):
        assert o._run_tool("mythril", contract, 60)["findings"][0]["tool"] == "mythril"
    # an unimplemented tool returns the empty default without running anything
    assert o._run_tool("aderyn", contract, 60) == {"tool": "aderyn", "findings": []}


# --- _run_slither -----------------------------------------------------------------------------
class TestRunSlither:
    def test_parses_detectors(self, contract):
        o = _orch({"slither": True})
        with patch.object(
            orch_mod.subprocess, "run", return_value=_completed(stdout=_SLITHER_JSON)
        ):
            out = o._run_slither(contract, 60)
        assert out["findings"][0]["type"] == "reentrancy-eth"
        assert out["findings"][0]["locations"] == [{"type": "function"}]

    def test_malformed_json_yields_no_findings(self, contract):
        o = _orch({"slither": True})
        with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout="{bad")):
            assert o._run_slither(contract, 60)["findings"] == []

    def test_timeout_and_error(self, contract):
        o = _orch({"slither": True})
        with patch.object(
            orch_mod.subprocess, "run", side_effect=subprocess.TimeoutExpired("slither", 1)
        ):
            assert o._run_slither(contract, 60)["error"] == "timeout"
        with patch.object(orch_mod.subprocess, "run", side_effect=OSError("no binary")):
            assert "no binary" in o._run_slither(contract, 60)["error"]


# --- _run_mythril -----------------------------------------------------------------------------
class TestRunMythril:
    def test_parses_issues(self, contract):
        o = _orch({"mythril": True})
        with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout=_MYTH_JSON)):
            out = o._run_mythril(contract, 60)
        assert out["findings"][0]["type"] == "Integer Overflow"
        assert out["findings"][0]["swc_id"] == "101"

    def test_malformed_json(self, contract):
        o = _orch({"mythril": True})
        with patch.object(orch_mod.subprocess, "run", return_value=_completed(stdout="nope")):
            assert o._run_mythril(contract, 60)["findings"] == []

    def test_timeout_and_error(self, contract):
        o = _orch({"mythril": True})
        with patch.object(
            orch_mod.subprocess, "run", side_effect=subprocess.TimeoutExpired("myth", 1)
        ):
            assert o._run_mythril(contract, 60)["error"] == "timeout"
        with patch.object(orch_mod.subprocess, "run", side_effect=RuntimeError("crash")):
            assert "crash" in o._run_mythril(contract, 60)["error"]


# --- _calculate_summary -----------------------------------------------------------------------
def test_calculate_summary_counts_and_dedupes_tools():
    o = _orch({})
    findings = [
        {"severity": "High", "tool": "slither"},
        {"severity": "high", "tool": "slither"},
        {"severity": "unknown-bucket", "tool": "mythril"},  # not a tracked severity
        {"tool": "mythril"},  # defaults to info
    ]
    summary = o._calculate_summary(findings)
    assert summary["total_findings"] == 4
    assert summary["by_severity"]["high"] == 2
    assert summary["by_severity"]["info"] == 1  # the no-severity finding
    assert set(summary["tools_used"]) == {"slither", "mythril"}
