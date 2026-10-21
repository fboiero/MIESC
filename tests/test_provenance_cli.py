"""Every result JSON written by the CLI carries a non-empty ``provenance`` block.

Covers ``miesc scan``, ``miesc audit quick``, ``miesc evaluate corpus|ablation``,
``miesc fix`` (run report) and the side-by-side table of ``miesc evaluate compare``.
Tool execution is faked; the provenance collectors are kept off the machine.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.cli import utils
from miesc.core import provenance as prov

# ``miesc.cli.commands`` re-exports the click objects under the module names, so
# the modules themselves (the patch targets) are fetched through importlib.
scan_mod = importlib.import_module("miesc.cli.commands.scan")
audit_mod = importlib.import_module("miesc.cli.commands.audit")
ev = importlib.import_module("miesc.cli.commands.evaluate")
fix_mod = importlib.import_module("miesc.cli.commands.fix")

CONTRACT = """pragma solidity ^0.8.0;
contract Victim {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""


@pytest.fixture(autouse=True)
def quiet_provenance(monkeypatch):
    """No subprocesses, no adapter registry: deterministic, fast provenance."""
    prov.reset_tool_versions()
    monkeypatch.setattr(prov, "_adapter_for", lambda _t: None)
    monkeypatch.setattr(prov, "_solc_via_adapter", lambda cs: dict.fromkeys(cs, "0.8.20"))
    monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: f"{cmd[0]} 9.9.9-test")
    monkeypatch.setattr(prov, "git_info", lambda: {"sha": "cafebabe", "dirty": False})
    monkeypatch.setattr(prov, "_llm_tools", lambda: {"smartguard"})
    for name in ("info", "success", "warning"):
        monkeypatch.setattr(utils, name, lambda *_a, **_k: None)
    yield
    prov.reset_tool_versions()


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def contract(tmp_path: Path) -> Path:
    path = tmp_path / "Victim.sol"
    path.write_text(CONTRACT, encoding="utf-8")
    return path


def _fake_run_tool(tool: str, contract: str, timeout: int = 0, **_kw: Any) -> dict:
    if tool == "slither":
        return {
            "tool": "slither",
            "contract": contract,
            "status": "success",
            "findings": [
                {
                    "type": "reentrancy-eth",
                    "severity": "High",
                    "line": 6,
                    "function": "withdraw",
                    "fix_code": "nonReentrant",
                }
            ],
            "metadata": {"solc_version": "0.8.20"},
            "execution_time": 0.1,
        }
    if tool == "aderyn":
        return {"tool": "aderyn", "contract": contract, "status": "not_available", "findings": []}
    return {"tool": tool, "contract": contract, "status": "error", "findings": [], "error": "x"}


def _assert_block(block: dict, command: str) -> None:
    assert block, "provenance block must be non-empty"
    assert block["schema"] == prov.SCHEMA_VERSION
    assert block["command"] == command
    assert block["miesc"]["version"] == prov.VERSION
    assert block["miesc"]["git_sha"] == "cafebabe"
    assert block["python"]["version"]
    assert block["platform"]["system"]
    assert isinstance(block["argv"], list)
    assert "sha256" in block["config"]
    assert "llm_free" in block


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


class TestScan:
    def test_scan_json_carries_provenance(self, runner, contract, tmp_path):
        out = tmp_path / "scan.json"
        with (
            patch.object(scan_mod, "run_tool", side_effect=_fake_run_tool),
            patch.object(scan_mod, "_preflight_syntax_check", lambda *_a, **_k: None),
        ):
            result = runner.invoke(scan_mod.scan, [str(contract), "-o", str(out), "--quiet"])
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        block = data["provenance"]
        _assert_block(block, "scan")
        # slither ran (and only slither: aderyn was not installed, solhint errored out
        # but still executed -> recorded)
        assert block["tools"]["slither"] == "slither 9.9.9-test"
        assert block["tools"]["solhint"] == "solhint 9.9.9-test"
        assert "aderyn" not in block["tools"]
        assert block["solc"]["per_contract"] == {str(contract): "0.8.20"}
        assert block["llm_free"] is True
        # existing top-level keys are untouched
        assert data["version"] == prov.VERSION and "findings" in data and "results" in data

    def test_scan_with_llm_enhance_is_not_llm_free(self, runner, contract, tmp_path):
        out = tmp_path / "scan.json"
        with (
            patch.object(scan_mod, "run_tool", side_effect=_fake_run_tool),
            patch.object(scan_mod, "_preflight_syntax_check", lambda *_a, **_k: None),
        ):
            result = runner.invoke(
                scan_mod.scan, [str(contract), "-o", str(out), "--quiet", "--llm-enhance"]
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["provenance"]["llm_free"] is False


# ---------------------------------------------------------------------------
# audit quick
# ---------------------------------------------------------------------------


class TestAuditQuick:
    def test_audit_quick_json_carries_provenance(self, runner, contract, tmp_path):
        out = tmp_path / "audit.json"
        with patch.object(audit_mod, "run_tool", side_effect=_fake_run_tool):
            result = runner.invoke(audit_mod.audit, ["quick", str(contract), "-o", str(out)])
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        _assert_block(data["provenance"], "audit quick")
        assert data["provenance"]["tools"]["slither"] == "slither 9.9.9-test"
        assert data["version"] == prov.VERSION and "results" in data


# ---------------------------------------------------------------------------
# evaluate corpus / ablation / compare
# ---------------------------------------------------------------------------


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    (root / "reentrancy").mkdir(parents=True)
    (root / "reentrancy" / "dao.sol").write_text(
        "pragma solidity ^0.4.24;\ncontract A { function f() public {} }\n", encoding="utf-8"
    )
    return root


def _fake_layer(layer_num: int, contract: str, timeout: int, **kwargs: Any) -> list[dict]:
    results = [
        {"tool": "slither", "status": "success", "findings": [{"type": "reentrancy-eth"}]},
        {"tool": "aderyn", "status": "not_available", "findings": []},
        {"tool": "fouranalyzer", "status": "error", "findings": [], "error": "crash"},
    ]
    for tool in sorted(kwargs.get("exclude_tools") or ()):
        results.append({"tool": tool, "status": "skipped", "findings": [], "error": "--no-llm"})
    return results


class TestEvaluate:
    def test_corpus_keeps_experiment_card_and_adds_provenance(self, runner, corpus, tmp_path):
        out = tmp_path / "run.json"
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "llm_tools", return_value={"smartguard"}),
        ):
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(corpus),
                    "--layers",
                    "1,6",
                    "--no-llm",
                    "--no-intelligence",
                    "--output",
                    str(out),
                ],
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["experiment_card"]["llm_free"] is True  # untouched
        assert data["reproducibility"]["command"].startswith("miesc evaluate corpus")
        block = data["provenance"]
        _assert_block(block, "evaluate corpus")
        assert block["llm_free"] is True
        # executed = success or error, across all contracts and layers, once each
        assert set(block["tools"]) == {"slither", "fouranalyzer"}
        assert block["solc"]["per_contract"] == {str(corpus / "reentrancy" / "dao.sol"): "0.8.20"}

    def test_corpus_resets_the_version_cache_per_run(self, runner, corpus):
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev, "reset_tool_versions") as reset,
        ):
            result = runner.invoke(
                ev.evaluate, ["corpus", str(corpus), "--layers", "1", "--no-intelligence"]
            )
        assert result.exit_code == 0, result.output
        reset.assert_called_once()

    def test_ablation_carries_provenance(self, runner, corpus, tmp_path):
        out = tmp_path / "ablation.json"
        with patch.object(ev, "run_layer", side_effect=_fake_layer):
            result = runner.invoke(
                ev.evaluate, ["ablation", str(corpus), "--layers", "1", "--output", str(out)]
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "experiment_card" in data and "ablation" in data
        block = data["provenance"]
        _assert_block(block, "evaluate ablation")
        assert set(block["tools"]) == {"slither", "fouranalyzer"}
        assert data["ablation"]["tool_status"]["slither"] == "success"

    def test_compare_prints_both_provenance_blocks(self, runner, corpus, tmp_path):
        new_run = tmp_path / "new.json"
        with patch.object(ev, "run_layer", side_effect=_fake_layer):
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(corpus),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "--output",
                    str(new_run),
                ],
            )
        assert result.exit_code == 0, result.output
        legacy = tmp_path / "paper.json"
        legacy.write_text(
            json.dumps(
                {
                    "version": "5.4.1",
                    "experiment_card": {"python_version": "3.12.0", "platform": "darwin"},
                    "reproducibility": {"command": "miesc evaluate corpus old", "seed": "not_set"},
                    "aggregate": {
                        "precision": 0.2,
                        "recall": 0.9,
                        "f1": 0.3,
                        "hit_rate": 0.9,
                        "total_time_s": 10,
                    },
                    "per_category": {},
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(ev.evaluate, ["compare", str(legacy), str(new_run)])
        assert result.exit_code == 0, result.output
        flat = " ".join(result.output.split())  # Rich wraps cells at the terminal width
        assert "Run Provenance" in flat
        assert "pre-provenance" in flat
        assert "9.9.9-test" in flat
        assert "cafebabe" in flat


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------


class TestFix:
    def _results(self, tmp_path: Path, contract: Path, with_provenance: bool = True) -> Path:
        data: dict[str, Any] = {
            "contract": str(contract),
            "findings": [
                {"type": "reentrancy", "function": "withdraw", "fix_code": "nonReentrant"}
            ],
        }
        if with_provenance:
            data["provenance"] = {"schema": 1, "command": "scan", "tools": {"slither": "0.11.6"}}
        path = tmp_path / "results.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_fix_writes_a_run_report_with_provenance(self, runner, contract, tmp_path):
        results = self._results(tmp_path, contract)
        out = tmp_path / "Victim.fixed.sol"
        result = runner.invoke(
            fix_mod.fix, [str(results), "--contract", str(contract), "--output", str(out)]
        )
        assert result.exit_code == 0, result.output
        report_path = tmp_path / "Victim.fixed.json"
        assert report_path.exists(), "run report is written next to the patched file"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["command"] == "fix"
        assert report["fixes"]["applied"] == 1
        assert report["results_sha256"] == prov.sha256_file(results)
        assert report["output_sha256"] == prov.sha256_file(out)
        assert report["input_provenance"]["tools"] == {"slither": "0.11.6"}
        _assert_block(report["provenance"], "fix")
        assert report["provenance"]["llm_free"] is True

    def test_fix_report_path_can_be_chosen(self, runner, contract, tmp_path):
        results = self._results(tmp_path, contract, with_provenance=False)
        out = tmp_path / "patched.sol"
        report_path = tmp_path / "reports" / "fix.json"
        report_path.parent.mkdir()
        result = runner.invoke(
            fix_mod.fix,
            [str(results), "-c", str(contract), "-o", str(out), "--report", str(report_path)],
        )
        assert result.exit_code == 0, result.output
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["input_provenance"] is None
        assert report["provenance"]["command"] == "fix"
        assert not (tmp_path / "patched.json").exists()

    def test_dry_run_writes_nothing(self, runner, contract, tmp_path):
        results = self._results(tmp_path, contract)
        result = runner.invoke(fix_mod.fix, [str(results), "-c", str(contract), "--dry-run"])
        assert result.exit_code == 0, result.output
        assert not (tmp_path / "Victim.fixed.sol").exists()
        assert not (tmp_path / "Victim.fixed.json").exists()

    def test_code_actions_contract_is_unchanged(self, runner, contract, tmp_path):
        """The LSP CodeAction payload stays a bare JSON array (editor contract)."""
        results = self._results(tmp_path, contract)
        result = runner.invoke(
            fix_mod.fix, [str(results), "-c", str(contract), "-f", "code-actions"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert isinstance(payload, list)
        assert not list(tmp_path.glob("*.json")) == []  # results.json only
        assert not (tmp_path / "Victim.fixed.json").exists()
