"""miesc audit batch --checkpoint/--resume. `run_tool` is mocked; no tool runs."""

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.audit import audit
from miesc.cli.constants import QUICK_TOOLS

FINDING = {"severity": "High", "type": "reentrancy"}


def _contracts(tmp_path: Path, names: str) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    for name in names:
        (src / f"{name}.sol").write_text(f"pragma solidity ^0.8.0;\ncontract {name} {{}}\n")
    return src


def _batch(*args: str, fail_on: str = ""):
    """Run `audit batch`; returns (result, contracts each tool ran on)."""
    calls = []

    def run_tool(tool, contract, timeout=0):
        calls.append(Path(contract).stem)
        if Path(contract).stem == fail_on:
            raise RuntimeError("tool crashed")
        return {"tool": tool, "contract": contract, "status": "success", "findings": [FINDING]}

    with patch("miesc.cli.commands.audit.run_tool", side_effect=run_tool):
        result = CliRunner().invoke(audit, ["batch", *args])
    return result, calls


def test_checkpoint_has_the_report_shape_after_every_contract(tmp_path):
    src, ckpt = _contracts(tmp_path, "ABC"), tmp_path / "state.json"

    result, _ = _batch(str(src), "--checkpoint", str(ckpt), "-j", "1")

    assert result.exit_code == 0, result.output
    state = json.loads(ckpt.read_text())
    assert state["tools"] == QUICK_TOOLS
    assert sorted(Path(c["contract"]).stem for c in state["contracts"]) == ["A", "B", "C"]
    assert not (tmp_path / "state.json.tmp").exists()


def test_resume_skips_done_contracts_and_retries_failed_ones(tmp_path, monkeypatch):
    src, ckpt, out = _contracts(tmp_path, "ABC"), tmp_path / "state.json", tmp_path / "r.json"
    _batch(str(src), "--checkpoint", str(ckpt), "-j", "1", fail_on="C")
    assert [f["contract"] for f in json.loads(ckpt.read_text())["failed"]] == [str(src / "C.sol")]

    # The same directory, now given as a relative path: the checkpoint still matches.
    monkeypatch.chdir(tmp_path)
    result, calls = _batch("src", "--checkpoint", str(ckpt), "--resume", "-o", str(out))

    assert result.exit_code == 0, result.output
    assert set(calls) == {"C"}
    report = json.loads(out.read_text())
    assert sorted(Path(c["contract"]).stem for c in report["contracts"]) == ["A", "B", "C"]
    assert report["failed"] == []
    assert report["total_findings"] == 3 * len(QUICK_TOOLS)


def test_resume_without_a_checkpoint_file_starts_from_scratch(tmp_path):
    src, ckpt = _contracts(tmp_path, "A"), tmp_path / "missing.json"

    result, calls = _batch(str(src), "--checkpoint", str(ckpt), "--resume")

    assert result.exit_code == 0, result.output
    assert set(calls) == {"A"} and ckpt.exists()


def test_resume_refuses_a_checkpoint_from_other_tools(tmp_path):
    src, ckpt = _contracts(tmp_path, "A"), tmp_path / "state.json"
    ckpt.write_text(json.dumps({"tools": ["slither"], "contracts": [], "failed": []}))

    result, calls = _batch(str(src), "--checkpoint", str(ckpt), "--resume")

    assert result.exit_code == 1 and calls == []
    assert "--profile" in result.output


def test_resume_needs_a_checkpoint(tmp_path):
    result, calls = _batch(str(_contracts(tmp_path, "A")), "--resume")

    assert result.exit_code == 2 and calls == []
    assert "--resume needs --checkpoint" in result.output
