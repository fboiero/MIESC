"""Behavioural coverage for ``miesc.cli.commands.remediate``.

Unit tests for the two path/profile helpers plus ``CliRunner`` drives of the command with the
heavy ``remediate_contract`` call and ``get_profile`` mocked, covering the read-error, profile,
compile/rescan-status and remediation-failure branches.
"""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner

from miesc.cli.commands.remediate import (
    _apply_remediation_profile_config,
    _resolve_output_path,
    remediate,
)

rem = importlib.import_module("miesc.cli.commands.remediate")


# --- _resolve_output_path --------------------------------------------------------------------
def test_resolve_output_default_appends_fixed_sol(tmp_path):
    c = tmp_path / "Token.sol"
    assert _resolve_output_path(c, None) == tmp_path / "Token.fixed.sol"


def test_resolve_output_explicit_sol_file_is_used_verbatim(tmp_path):
    c = tmp_path / "Token.sol"
    out = tmp_path / "patched" / "Out.sol"
    assert _resolve_output_path(c, str(out)) == out  # line 23: a .sol output is returned as-is


def test_resolve_output_directory_gets_fixed_sol_name(tmp_path):
    c = tmp_path / "Token.sol"
    assert (
        _resolve_output_path(c, str(tmp_path / "outdir")) == tmp_path / "outdir" / "Token.fixed.sol"
    )


# --- _apply_remediation_profile_config -------------------------------------------------------
def test_profile_config_passthrough_without_profile():
    assert _apply_remediation_profile_config(
        profile_name=None, compile_check=False, rescan_check=False
    ) == (None, False, False)


def test_profile_config_unknown_profile_raises(monkeypatch):
    monkeypatch.setattr(rem, "get_profile", lambda _n: None)
    with pytest.raises(click.ClickException, match="Unknown profile"):
        _apply_remediation_profile_config(
            profile_name="ghost", compile_check=False, rescan_check=False
        )


def test_profile_config_turns_on_evidence_requirements(monkeypatch):
    monkeypatch.setattr(
        rem,
        "get_profile",
        lambda _n: {
            "remediation_evidence": {
                "require_compile": True,
                "require_no_regression": True,
            }
        },
    )
    profile, compile_check, rescan_check = _apply_remediation_profile_config(
        profile_name="paper2", compile_check=False, rescan_check=False
    )
    assert profile is not None
    assert compile_check is True
    assert rescan_check is True


# --- CLI drives ------------------------------------------------------------------------------
def _fake_evidence(*, status="ok", fixes=2, compiled=True, eliminated=True, no_regression=True):
    return SimpleNamespace(
        status=status,
        fixes_applied=fixes,
        compile=SimpleNamespace(checked=True, compiles=compiled),
        rescan=SimpleNamespace(checked=True, eliminated=eliminated, no_regression=no_regression),
        to_dict=lambda: {"status": status, "fixes_applied": fixes},
    )


def _inputs(tmp_path, results_text='{"findings": []}'):
    results = tmp_path / "results.json"
    results.write_text(results_text)
    contract = tmp_path / "C.sol"
    contract.write_text("pragma solidity ^0.8.0; contract C {}")
    return results, contract


def test_remediate_reports_unreadable_results_file(tmp_path):
    results, contract = _inputs(tmp_path, results_text="{not json")
    res = CliRunner().invoke(remediate, [str(results), "-c", str(contract)])
    assert res.exit_code == 1
    assert "Cannot read results file" in res.output


def test_remediate_happy_path_with_profile_and_status(tmp_path, monkeypatch):
    results, contract = _inputs(tmp_path)
    monkeypatch.setattr(rem, "get_profile", lambda _n: {"description": "Paper 2 evidence"})
    monkeypatch.setattr(rem, "remediate_contract", lambda **kw: _fake_evidence())
    out = tmp_path / "Fixed.sol"
    ev = tmp_path / "ev.json"
    res = CliRunner().invoke(
        remediate,
        [
            str(results),
            "-c",
            str(contract),
            "-o",
            str(out),
            "--evidence-output",
            str(ev),
            "--profile",
            "paper2",
        ],
    )
    assert res.exit_code == 0
    assert "Profile: paper2 (Paper 2 evidence)" in res.output
    assert "Compile check: passed" in res.output
    assert "Re-scan eliminated original high findings: yes" in res.output
    assert "Bounded no-regression: yes" in res.output
    assert "Applied 2 fix(es)" in res.output
    assert ev.exists() and json.loads(ev.read_text())["fixes_applied"] == 2


def test_remediate_handles_remediation_oserror(tmp_path, monkeypatch):
    results, contract = _inputs(tmp_path)

    def _boom(**kw):
        raise OSError("disk gone")

    monkeypatch.setattr(rem, "remediate_contract", _boom)
    res = CliRunner().invoke(remediate, [str(results), "-c", str(contract)])
    assert res.exit_code == 1
    assert "Remediation failed" in res.output


def test_remediate_no_fixable_findings_exits_zero(tmp_path, monkeypatch):
    results, contract = _inputs(tmp_path)
    monkeypatch.setattr(
        rem, "remediate_contract", lambda **kw: _fake_evidence(status="no_fixable_findings")
    )
    res = CliRunner().invoke(remediate, [str(results), "-c", str(contract), "--quiet"])
    assert res.exit_code == 0
    assert "No fixable findings" in res.output
