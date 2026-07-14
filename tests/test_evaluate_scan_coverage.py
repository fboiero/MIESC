"""Coverage-focused tests for the two largest low-covered CLI modules:

- ``miesc.cli.commands.evaluate`` (research benchmark harness)
- ``miesc.cli.commands.scan`` (quick vulnerability scan)

These exercise real code paths: private helper functions are imported and
called directly (unit style) in addition to end-to-end ``CliRunner`` command
invocations. Every external collaborator (layer/tool runners, orchestrators,
LLM adapters, intelligence engine, FP filter, notifiers, subprocess, dataset
loaders) is mocked so the suite is deterministic and needs no local tools or
network.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from miesc.core.tool_protocol import ToolStatus

# The package namespace shadows these submodules with their click command
# objects, so import the modules explicitly to reach private helpers.
ev = importlib.import_module("miesc.cli.commands.evaluate")
sc = importlib.import_module("miesc.cli.commands.scan")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Corpus builders
# ---------------------------------------------------------------------------

_PRAGMA_SOL = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.19;\ncontract C {}\n"


def _make_corpus(base: Path, layout: dict[str, list[str]]) -> Path:
    """Create a SmartBugs-curated style corpus.

    layout maps ``category`` -> list of contract file names.
    """
    for category, files in layout.items():
        cat_dir = base / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            (cat_dir / name).write_text(_PRAGMA_SOL, encoding="utf-8")
    return base


def _layer_result(findings: list[dict], tool: str = "slither", status: str = "success"):
    """A single run_layer() return payload (list of tool results)."""
    return [{"tool": tool, "status": status, "findings": findings}]


# ===========================================================================
# evaluate.py — pure helper unit tests
# ===========================================================================


class TestNormalizeCategory:
    def test_exact_alias_match(self):
        assert ev._normalize_category("reentrancy-eth") == "reentrancy"
        assert ev._normalize_category("suicidal") == "access_control"
        assert ev._normalize_category("integer-overflow") == "arithmetic"

    def test_substring_match(self):
        # compound type not in alias set but contains a known alias substring
        assert ev._normalize_category("reentrancy_in_withdraw") == "reentrancy"

    def test_keyword_fallback_on_description(self):
        # unknown type but description carries a keyword
        cat = ev._normalize_category(
            "SWC-107", title="Possible reentrancy", description="external call before state update"
        )
        assert cat == "reentrancy"

    def test_keyword_fallback_overflow(self):
        assert (
            ev._normalize_category("custom", description="integer overflow in add") == "arithmetic"
        )

    def test_returns_none_for_unknown(self):
        assert ev._normalize_category("totally-unrelated-thing") is None


class TestComputeMetrics:
    def test_perfect_scores(self):
        m = ev._compute_metrics(tp=10, fp=0, fn=0)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0

    def test_zero_division_guards(self):
        m = ev._compute_metrics(tp=0, fp=0, fn=0)
        assert m["precision"] == 0.0
        assert m["recall"] == 0.0
        assert m["f1"] == 0.0

    def test_mixed(self):
        m = ev._compute_metrics(tp=8, fp=2, fn=2)
        assert m["precision"] == 0.8
        assert m["recall"] == 0.8
        assert m["f1"] == pytest.approx(0.8, abs=1e-4)


class TestLoadGroundTruth:
    def test_loads_categories(self, tmp_path):
        _make_corpus(
            tmp_path,
            {"reentrancy": ["A.sol", "B.sol"], "arithmetic": ["C.sol"]},
        )
        gt = ev._load_ground_truth(tmp_path)
        assert gt["reentrancy/A.sol"] == {"reentrancy"}
        assert gt["arithmetic/C.sol"] == {"arithmetic"}
        assert len(gt) == 3

    def test_ignores_unknown_dirs_and_files(self, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        (tmp_path / "not_a_category").mkdir()
        (tmp_path / "not_a_category" / "X.sol").write_text(_PRAGMA_SOL)
        (tmp_path / "loose.txt").write_text("noise")
        gt = ev._load_ground_truth(tmp_path)
        assert set(gt.keys()) == {"reentrancy/A.sol"}

    def test_empty_corpus(self, tmp_path):
        assert ev._load_ground_truth(tmp_path) == {}


class TestGenerateExperimentCard:
    def test_card_structure(self, tmp_path):
        card = ev._generate_experiment_card(
            tmp_path,
            [1, 5],
            120,
            {"corpus_size": 3, "skip_unavailable": True},
            12.34,
        )
        ec = card["experiment_card"]
        assert ec["tool"] == "MIESC"
        assert ec["layers_evaluated"] == [1, 5]
        assert ec["corpus_size"] == 3
        assert card["reproducibility"]["command"].startswith("miesc evaluate")


class TestEvaluateContract:
    def test_detects_true_positive(self, tmp_path):
        contract = tmp_path / "Foo.sol"
        contract.write_text(_PRAGMA_SOL)
        with patch.object(
            ev,
            "run_layer",
            return_value=_layer_result([{"type": "reentrancy-eth", "severity": "HIGH"}]),
        ):
            res = ev._evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=10,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert res["match"]["hit"] is True
        assert "reentrancy" in res["match"]["tp"]
        assert res["match"]["fn"] == []
        assert res["layers"][1]["findings_count"] == 1

    def test_false_negative_when_nothing_detected(self, tmp_path):
        contract = tmp_path / "Foo.sol"
        contract.write_text(_PRAGMA_SOL)
        with patch.object(ev, "run_layer", return_value=_layer_result([])):
            res = ev._evaluate_contract(
                contract, {"reentrancy"}, [1], 10, True, use_intelligence=False
            )
        assert res["match"]["hit"] is False
        assert res["match"]["fn"] == ["reentrancy"]

    def test_skip_unavailable_tool(self, tmp_path):
        contract = tmp_path / "Foo.sol"
        contract.write_text(_PRAGMA_SOL)
        na = [{"tool": "mythril", "status": "not_available", "findings": []}]
        with patch.object(ev, "run_layer", return_value=na):
            res = ev._evaluate_contract(
                contract, {"reentrancy"}, [1], 10, skip_unavailable=True, use_intelligence=False
            )
        assert res["layers"][1]["findings_count"] == 0

    def test_run_layer_exception_is_captured(self, tmp_path):
        contract = tmp_path / "Foo.sol"
        contract.write_text(_PRAGMA_SOL)
        with patch.object(ev, "run_layer", side_effect=RuntimeError("boom")):
            res = ev._evaluate_contract(
                contract, {"reentrancy"}, [1], 10, True, use_intelligence=False
            )
        # error path produces a layer_error tool result with no findings
        assert res["layers"][1]["findings_count"] == 0

    def test_intelligence_adds_categories(self, tmp_path):
        contract = tmp_path / "Foo.sol"
        contract.write_text(_PRAGMA_SOL)

        def fake_enhance(findings, source_code="", file_path=""):
            return findings + [{"type": "arithmetic", "severity": "HIGH"}]

        with (
            patch.object(ev, "run_layer", return_value=_layer_result([])),
            patch("miesc.core.intelligence.enhance_findings", side_effect=fake_enhance),
        ):
            res = ev._evaluate_contract(
                contract, {"arithmetic"}, [1], 10, True, use_intelligence=True
            )
        assert "arithmetic" in res["match"]["tp"]
        assert "intelligence" in res["layers"]


class TestRunAblation:
    def test_ablation_per_layer_and_combined(self, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        gt = ev._load_ground_truth(tmp_path)
        with (
            patch.object(
                ev,
                "run_layer",
                return_value=_layer_result([{"type": "reentrancy", "severity": "HIGH"}]),
            ),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        ):
            out = ev._run_ablation(tmp_path, gt, [1], 10, True, None)
        assert 1 in out["per_layer"]
        assert out["combined"] is not None
        assert out["layer_contributions"][1]["standalone_recall"] >= 0.0

    def test_ablation_streams_jsonl(self, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        gt = ev._load_ground_truth(tmp_path)
        jsonl = tmp_path / "out.jsonl"
        with (
            patch.object(ev, "run_layer", return_value=_layer_result([])),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        ):
            ev._run_ablation(tmp_path, gt, [1], 10, True, jsonl)
        lines = [json.loads(x) for x in jsonl.read_text().splitlines() if x.strip()]
        assert any(r["type"] == "ablation_single" for r in lines)


# ===========================================================================
# evaluate.py — CliRunner command invocations
# ===========================================================================


class TestEvaluateCorpusCommand:
    def _patches(self, findings):
        return (
            patch.object(ev, "run_layer", return_value=_layer_result(findings)),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        )

    def test_corpus_no_ground_truth_exits_1(self, runner, tmp_path):
        result = runner.invoke(ev.evaluate, ["corpus", str(tmp_path)])
        assert result.exit_code == 1
        assert "No ground truth" in result.output

    def test_corpus_success_reports_metrics(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"], "arithmetic": ["B.sol"]})
        p1, p2 = self._patches([{"type": "reentrancy", "severity": "HIGH"}])
        with p1, p2:
            result = runner.invoke(
                ev.evaluate, ["corpus", str(tmp_path), "--layers", "1", "--no-intelligence"]
            )
        assert result.exit_code == 0
        assert "Evaluation complete" in result.output

    def test_corpus_output_and_jsonl(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        out = tmp_path / "res.json"
        jsonl = tmp_path / "res.jsonl"
        p1, p2 = self._patches([{"type": "reentrancy", "severity": "HIGH"}])
        with p1, p2:
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(tmp_path),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "-o",
                    str(out),
                    "--jsonl",
                    str(jsonl),
                ],
            )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "aggregate" in data and "per_contract" in data
        # jsonl has a per-contract record + a summary record
        records = [json.loads(x) for x in jsonl.read_text().splitlines() if x.strip()]
        assert any(r["type"] == "contract_eval" for r in records)
        assert any(r["type"] == "summary" for r in records)

    def test_corpus_category_filter_and_limit(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol", "B.sol"], "arithmetic": ["C.sol"]})
        p1, p2 = self._patches([{"type": "reentrancy", "severity": "HIGH"}])
        with p1, p2:
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(tmp_path),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "--categories",
                    "reentrancy",
                    "--limit",
                    "1",
                ],
            )
        assert result.exit_code == 0
        assert "Category filter" in result.output
        assert "Limited to 1" in result.output

    def test_corpus_with_config_yaml(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        cfg = tmp_path / "exp.yaml"
        cfg.write_text("layers: [1]\ntimeout: 5\nlimit: 1\nenv:\n  MIESC_SEED: '42'\n")
        p1, p2 = self._patches([{"type": "reentrancy", "severity": "HIGH"}])
        with p1, p2:
            result = runner.invoke(
                ev.evaluate,
                ["corpus", str(tmp_path), "--no-intelligence", "--config", str(cfg)],
            )
        assert result.exit_code == 0
        assert "Loaded experiment config" in result.output

    def test_corpus_with_llm_recovers_missed(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        adapter = MagicMock()
        adapter.analyze.return_value = {"findings": [{"type": "reentrancy", "severity": "HIGH"}]}
        # run_layer detects nothing -> the single contract is a miss (fn > 0)
        with (
            patch.object(ev, "run_layer", return_value=_layer_result([])),
            patch(
                "miesc.adapters.frontier_llm_adapter.FrontierLLMAdapter",
                return_value=adapter,
            ),
        ):
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(tmp_path),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "--with-llm",
                    "claude",
                ],
            )
        assert result.exit_code == 0
        assert "LLM follow-up" in result.output
        adapter.analyze.assert_called()


class TestEvaluateAblationCommand:
    def test_ablation_no_ground_truth_exits_1(self, runner, tmp_path):
        result = runner.invoke(ev.evaluate, ["ablation", str(tmp_path)])
        assert result.exit_code == 1

    def test_ablation_success_with_output(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol"]})
        out = tmp_path / "abl.json"
        with (
            patch.object(
                ev,
                "run_layer",
                return_value=_layer_result([{"type": "reentrancy", "severity": "HIGH"}]),
            ),
            patch("miesc.core.intelligence.enhance_findings", side_effect=lambda f, **k: f),
        ):
            result = runner.invoke(
                ev.evaluate,
                ["ablation", str(tmp_path), "--layers", "1", "--limit", "1", "-o", str(out)],
            )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "ablation" in data


class TestEvaluateInfoCommand:
    def test_info_no_ground_truth_exits_1(self, runner, tmp_path):
        result = runner.invoke(ev.evaluate, ["info", str(tmp_path)])
        assert result.exit_code == 1

    def test_info_reports_distribution(self, runner, tmp_path):
        _make_corpus(tmp_path, {"reentrancy": ["A.sol", "B.sol"], "arithmetic": ["C.sol"]})
        result = runner.invoke(ev.evaluate, ["info", str(tmp_path)])
        assert result.exit_code == 0
        assert "3 contracts" in result.output


class TestEvaluateCompareCommand:
    def _run_file(self, path: Path, recall: float) -> None:
        path.write_text(
            json.dumps(
                {
                    "experiment_card": {"version": "5.2.0"},
                    "aggregate": {
                        "precision": 0.9,
                        "recall": recall,
                        "f1": 0.85,
                        "hit_rate": 0.8,
                        "total_time_s": 100,
                    },
                    "per_category": {"reentrancy": {"recall": recall}},
                }
            )
        )

    def test_compare_two_runs(self, runner, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        self._run_file(a, 0.70)
        self._run_file(b, 0.90)
        result = runner.invoke(ev.evaluate, ["compare", str(a), str(b)])
        assert result.exit_code == 0
        assert "Comparison complete" in result.output


class TestEvaluateDownloadCommand:
    def test_download_already_exists(self, runner, tmp_path):
        target = tmp_path / "ds"
        target.mkdir()
        (target / "placeholder").write_text("x")
        result = runner.invoke(ev.evaluate, ["download", "smartbugs", "-o", str(target)])
        assert result.exit_code == 0
        assert "already exists" in result.output

    def test_download_clone_success(self, runner, tmp_path):
        target = tmp_path / "fresh"
        proc = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=proc):
            result = runner.invoke(ev.evaluate, ["download", "smartbugs", "-o", str(target)])
        assert result.exit_code == 0
        assert "Downloaded" in result.output

    def test_download_clone_failure_exits_1(self, runner, tmp_path):
        target = tmp_path / "fail"
        proc = SimpleNamespace(returncode=1, stdout="", stderr="fatal: nope")
        with patch("subprocess.run", return_value=proc):
            result = runner.invoke(ev.evaluate, ["download", "solidifi", "-o", str(target)])
        assert result.exit_code == 1
        assert "Clone failed" in result.output

    def test_download_git_missing_exits_1(self, runner, tmp_path):
        target = tmp_path / "nogit"
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = runner.invoke(ev.evaluate, ["download", "dvd", "-o", str(target)])
        assert result.exit_code == 1
        assert "git not found" in result.output


# ===========================================================================
# scan.py — profile / helper unit tests
# ===========================================================================


class TestScanProfileHelpers:
    def test_get_scan_profile_none(self):
        assert sc._get_scan_profile(None) is None

    def test_get_scan_profile_missing_raises(self):
        import click

        with patch.object(sc, "get_profile", return_value=None):
            with pytest.raises(click.ClickException):
                sc._get_scan_profile("ghost")

    def test_get_scan_profile_found(self):
        with patch.object(sc, "get_profile", return_value={"tools": ["slither"]}):
            assert sc._get_scan_profile("fast") == {"tools": ["slither"]}

    def test_profile_tools_defaults(self):
        assert sc._profile_tools(None) == ["slither", "aderyn", "solhint"]
        assert sc._profile_tools({}) == ["slither", "aderyn", "solhint"]

    def test_profile_tools_explicit(self):
        assert sc._profile_tools({"tools": ["slither", "wake"]}) == ["slither", "wake"]

    def test_profile_uses_agentic(self):
        assert sc._profile_uses_agentic_path({"agentic_ensemble": {"x": 1}}) is True
        assert sc._profile_uses_agentic_path({"enable_agentic_invariants": True}) is True
        assert sc._profile_uses_agentic_path({"tools": ["slither"]}) is False


class TestScanSingleFileHelper:
    def test_scan_single_file_appends_tagged_results(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        results: list[dict] = []
        with patch.object(
            sc,
            "run_tool",
            return_value={"tool": "slither", "status": "success", "findings": []},
        ):
            sc._scan_single_file(
                str(contract), results, quiet=True, llm_enhance=False, tools=["slither"]
            )
        assert len(results) == 1
        assert results[0]["contract"] == str(contract)

    def test_scan_single_file_captures_tool_exception(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        results: list[dict] = []
        with patch.object(sc, "run_tool", side_effect=RuntimeError("crash")):
            sc._scan_single_file(
                str(contract), results, quiet=True, llm_enhance=False, tools=["slither"]
            )
        assert results[0]["status"] == "error"
        assert "crash" in results[0]["error"]


class TestPreflightSyntaxCheck:
    def test_no_solc_available_is_noop(self, tmp_path, monkeypatch):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        with patch("shutil.which", return_value=None):
            sc._preflight_syntax_check(str(contract), quiet=False)  # no raise

    def test_syntax_error_warns(self, tmp_path, monkeypatch, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract {")
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        proc = SimpleNamespace(returncode=1, stdout="", stderr="ParserError: bad\n")
        with (
            patch("shutil.which", return_value="/usr/bin/solc"),
            patch("subprocess.run", return_value=proc),
        ):
            sc._preflight_syntax_check(str(contract), quiet=False)


class TestApplyVerifyFpAndRank:
    def test_apply_verify_fp_invokes_verifier(self):
        results = [{"tool": "slither", "findings": []}]
        with patch("miesc.ml.benign_context_verifier.apply_to_results", return_value=(2, 1)) as m:
            sc._apply_verify_fp(results, contract="C.sol", model=None, quiet=False)
        m.assert_called_once()

    def test_apply_verify_fp_import_error_swallowed(self):
        results = [{"tool": "slither", "findings": []}]
        # Replace the verifier module with a stub lacking apply_to_results so the
        # `from ... import apply_to_results` guard raises ImportError and is caught.
        import sys
        import types

        stub = types.ModuleType("miesc.ml.benign_context_verifier")
        with patch.dict(sys.modules, {"miesc.ml.benign_context_verifier": stub}):
            sc._apply_verify_fp(results, contract="C.sol", model=None, quiet=False)  # no raise

    def test_apply_triage_rank_no_model(self):
        results = [{"tool": "slither", "findings": []}]
        with patch("miesc.ml.triage_ranker.rank_results", return_value=-1) as m:
            sc._apply_triage_rank(results, contract="C.sol", quiet=False)
        m.assert_called_once()

    def test_apply_triage_rank_ordered(self):
        results = [{"tool": "slither", "findings": []}]
        with patch("miesc.ml.triage_ranker.rank_results", return_value=3):
            sc._apply_triage_rank(results, contract="C.sol", quiet=False)  # no raise


# ===========================================================================
# scan.py — _display_and_save (covers save / verbose / annotate / notify / ci)
# ===========================================================================


def _finding(sev: str, ftype: str = "reentrancy") -> dict:
    return {"severity": sev, "type": ftype, "message": "m", "recommendation": "fix it properly"}


class TestDisplayAndSave:
    def test_saves_json_output(self, tmp_path):
        out = tmp_path / "report.json"
        results = [{"tool": "slither", "status": "success", "findings": [_finding("HIGH")]}]
        sc._display_and_save(
            results, contract="C.sol", output=str(out), quiet=True, verbose=False, ci=False
        )
        data = json.loads(out.read_text())
        assert data["total_findings"] == 1
        assert data["tools"] == ["slither"]
        assert data["findings"][0]["tool"] == "slither"

    def test_verbose_output(self, tmp_path):
        results = [
            {
                "tool": "slither",
                "status": "success",
                "findings": [
                    {
                        "severity": "High",
                        "type": "reentrancy",
                        "confidence": 0.9,
                        "recommendation": "apply CEI pattern to the function",
                        "canonical_category": "reentrancy",
                    }
                ],
            }
        ]
        sc._display_and_save(
            results, contract="C.sol", output=None, quiet=False, verbose=True, ci=False
        )  # no raise

    def test_all_tools_errored_message(self, tmp_path):
        results = [{"tool": "slither", "status": "error", "error": "not installed", "findings": []}]
        sc._display_and_save(
            results, contract="C.sol", output=None, quiet=False, verbose=False, ci=False
        )  # no raise

    def test_ci_exit_on_critical(self):
        results = [{"tool": "slither", "status": "success", "findings": [_finding("CRITICAL")]}]
        with pytest.raises(SystemExit) as exc:
            sc._display_and_save(
                results, contract="C.sol", output=None, quiet=True, verbose=False, ci=True
            )
        assert exc.value.code == 1

    def test_verify_fp_and_rank_invoked(self):
        results = [{"tool": "slither", "status": "success", "findings": []}]
        with (
            patch.object(sc, "_apply_verify_fp") as vfp,
            patch.object(sc, "_apply_triage_rank") as rank,
        ):
            sc._display_and_save(
                results,
                contract="C.sol",
                output=None,
                quiet=True,
                verbose=False,
                ci=False,
                verify_fp=True,
                rank=True,
            )
        vfp.assert_called_once()
        rank.assert_called_once()

    def test_github_annotations(self):
        results = [{"tool": "slither", "status": "success", "findings": [_finding("HIGH")]}]
        exporter = MagicMock()
        exporter.to_github_annotations.return_value = ["::error file=C.sol::reentrancy"]
        with patch("miesc.core.exporters.GitHubAnnotationsExporter", return_value=exporter):
            sc._display_and_save(
                results,
                contract="C.sol",
                output=None,
                quiet=True,
                verbose=False,
                ci=False,
                annotate="github",
            )
        exporter.to_github_annotations.assert_called_once()

    def test_baseline_gate_invoked(self):
        results = [{"tool": "slither", "status": "success", "findings": [_finding("HIGH")]}]
        with patch("miesc.cli.commands.baseline.apply_baseline_gate") as gate:
            sc._display_and_save(
                results,
                contract="C.sol",
                output=None,
                quiet=True,
                verbose=False,
                ci=False,
                baseline_path="base.json",
                fail_on_new=True,
            )
        gate.assert_called_once()

    def test_notifications_dispatched(self):
        results = [{"tool": "slither", "status": "success", "findings": [_finding("HIGH")]}]
        with patch(
            "miesc.core.notifiers.dispatch_notifications",
            return_value={"webhook": True},
        ) as dispatch:
            sc._display_and_save(
                results,
                contract="C.sol",
                output=None,
                quiet=False,
                verbose=False,
                ci=False,
                notify_url="https://example.com/hook",
            )
        dispatch.assert_called_once()


# ===========================================================================
# scan.py — end-to-end single-file command with LLM / ensemble branches
# ===========================================================================


class TestScanCommandBranches:
    def _base_patches(self):
        """Patch tool runner + intelligence engine (passthrough) so the scan
        pipeline is deterministic and has no side effects."""
        return (
            patch.object(
                sc,
                "run_tool",
                return_value={"tool": "slither", "status": "success", "findings": []},
            ),
            patch(
                "miesc.core.intelligence.enhance_findings",
                side_effect=lambda findings, **kw: findings,
            ),
        )

    def test_single_file_basic(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        p1, p2 = self._base_patches()
        with p1, p2, patch.object(sc, "_preflight_syntax_check"):
            result = runner.invoke(sc.scan, [str(contract), "--quiet", "--fp-strictness", "off"])
        assert result.exit_code == 0

    def test_single_file_fp_filter_removes(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)

        class FakeFR:
            is_likely_fp = True

        fake_filter = MagicMock()
        fake_filter.filter_finding.return_value = FakeFR()
        p1, p2 = self._base_patches()
        with (
            patch.object(
                sc,
                "run_tool",
                return_value={
                    "tool": "slither",
                    "status": "success",
                    "findings": [_finding("LOW")],
                },
            ),
            p2,
            patch.object(sc, "_preflight_syntax_check"),
            patch("miesc.ml.fp_filter.FalsePositiveFilter", return_value=fake_filter),
        ):
            result = runner.invoke(sc.scan, [str(contract), "--fp-strictness", "high"])
        assert result.exit_code == 0
        assert "removed 1 likely false positives" in result.output

    def test_single_file_frontier_model(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        adapter = MagicMock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.return_value = {
            "status": "success",
            "findings": [_finding("HIGH", "arithmetic")],
        }
        p1, p2 = self._base_patches()
        with (
            p1,
            p2,
            patch.object(sc, "_preflight_syntax_check"),
            patch(
                "miesc.adapters.frontier_llm_adapter.FrontierLLMAdapter",
                return_value=adapter,
            ),
        ):
            result = runner.invoke(
                sc.scan,
                [str(contract), "--fp-strictness", "off", "--model", "claude"],
            )
        assert result.exit_code == 0
        adapter.analyze.assert_called_once()

    def test_single_file_frontier_not_available(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        adapter = MagicMock()
        adapter.is_available.return_value = ToolStatus.NOT_INSTALLED
        p1, p2 = self._base_patches()
        with (
            p1,
            p2,
            patch.object(sc, "_preflight_syntax_check"),
            patch(
                "miesc.adapters.frontier_llm_adapter.FrontierLLMAdapter",
                return_value=adapter,
            ),
        ):
            result = runner.invoke(
                sc.scan,
                [str(contract), "--fp-strictness", "off", "--model", "gpt"],
            )
        assert result.exit_code == 0
        assert "not available" in result.output.lower()
        adapter.analyze.assert_not_called()

    def test_single_file_ensemble(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        adapter = MagicMock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.return_value = {
            "status": "success",
            "findings": [{"type": "reentrancy", "severity": "HIGH"}],
        }
        p1, p2 = self._base_patches()
        with (
            p1,
            p2,
            patch.object(sc, "_preflight_syntax_check"),
            patch(
                "miesc.adapters.frontier_llm_adapter.FrontierLLMAdapter",
                return_value=adapter,
            ),
        ):
            result = runner.invoke(sc.scan, [str(contract), "--fp-strictness", "off", "--ensemble"])
        assert result.exit_code == 0
        # three providers attempted
        assert adapter.analyze.call_count == 3

    def test_single_file_llm_enhance(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        interp = MagicMock()
        interp.is_available.return_value = True
        interp.interpret_critical_findings.return_value = [
            {"title": "reentrancy", "llm_interpretation": "reentrancy risk explained"}
        ]
        with (
            patch.object(
                sc,
                "run_tool",
                return_value={
                    "tool": "slither",
                    "status": "success",
                    "findings": [_finding("CRITICAL", "reentrancy")],
                },
            ),
            patch(
                "miesc.core.intelligence.enhance_findings",
                side_effect=lambda findings, **kw: findings,
            ),
            patch.object(sc, "_preflight_syntax_check"),
            patch("miesc.reports.llm_interpreter.LLMReportInterpreter", return_value=interp),
        ):
            result = runner.invoke(
                sc.scan, [str(contract), "--fp-strictness", "off", "--llm-enhance"]
            )
        assert result.exit_code == 0
        interp.interpret_critical_findings.assert_called_once()

    def test_single_file_ci_exit_on_high(self, runner, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text(_PRAGMA_SOL)
        with (
            patch.object(
                sc,
                "run_tool",
                return_value={
                    "tool": "slither",
                    "status": "success",
                    "findings": [_finding("HIGH")],
                },
            ),
            patch(
                "miesc.core.intelligence.enhance_findings",
                side_effect=lambda findings, **kw: findings,
            ),
            patch.object(sc, "_preflight_syntax_check"),
        ):
            result = runner.invoke(sc.scan, [str(contract), "--fp-strictness", "off", "--ci"])
        assert result.exit_code == 1
        assert "CI check failed" in result.output


# ===========================================================================
# scan.py — directory mode / diff mode / agentic profile routing
# ===========================================================================


class TestScanDirectoryMode:
    def test_directory_no_sol_files_exits_1(self, runner, tmp_path):
        (tmp_path / "README.md").write_text("noise")
        result = runner.invoke(sc.scan, [str(tmp_path), "--quiet"])
        assert result.exit_code == 1

    def test_directory_with_fp_filter_and_intelligence(self, runner, tmp_path):
        (tmp_path / "A.sol").write_text(_PRAGMA_SOL)
        (tmp_path / "B.sol").write_text(_PRAGMA_SOL)

        class KeepFR:
            is_likely_fp = False

        fake_filter = MagicMock()
        fake_filter.filter_finding.return_value = KeepFR()
        with (
            patch.object(
                sc,
                "run_tool",
                return_value={
                    "tool": "slither",
                    "status": "success",
                    "findings": [_finding("HIGH")],
                },
            ),
            patch(
                "miesc.core.intelligence.enhance_findings",
                side_effect=lambda findings, **kw: findings,
            ),
            patch("miesc.ml.fp_filter.FalsePositiveFilter", return_value=fake_filter),
        ):
            result = runner.invoke(sc.scan, [str(tmp_path), "--fp-strictness", "medium"])
        assert result.exit_code == 0

    def test_directory_with_frontier_model(self, runner, tmp_path):
        (tmp_path / "Vault.sol").write_text(_PRAGMA_SOL)
        (tmp_path / "Token.sol").write_text(_PRAGMA_SOL)
        adapter = MagicMock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.return_value = {
            "status": "success",
            "findings": [_finding("HIGH", "arithmetic")],
        }
        with (
            patch.object(
                sc,
                "run_tool",
                return_value={"tool": "slither", "status": "success", "findings": []},
            ),
            patch(
                "miesc.core.intelligence.enhance_findings",
                side_effect=lambda findings, **kw: findings,
            ),
            patch(
                "miesc.adapters.frontier_llm_adapter.FrontierLLMAdapter",
                return_value=adapter,
            ),
        ):
            result = runner.invoke(
                sc.scan,
                [str(tmp_path), "--fp-strictness", "off", "--model", "claude"],
            )
        assert result.exit_code == 0
        adapter.analyze.assert_called_once()


class TestScanDiffMode:
    def test_diff_scans_changed_sol(self, runner, tmp_path):
        sol = tmp_path / "Changed.sol"
        sol.write_text(_PRAGMA_SOL)

        def fake_run(cmd, **kwargs):
            result = MagicMock()
            result.stderr = ""
            if "diff" in cmd:
                result.stdout = "Changed.sol\n"
            else:  # rev-parse --show-toplevel
                result.stdout = str(tmp_path) + "\n"
            result.returncode = 0
            return result

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch.object(sc, "_scan_single_file") as mock_scan,
            patch.object(sc, "_display_and_save"),
        ):
            result = runner.invoke(sc.scan, [str(tmp_path), "--diff", "HEAD~1", "--quiet"])
        assert result.exit_code == 0
        assert mock_scan.call_count == 1

    def test_diff_no_changes_exits_0(self, runner, tmp_path):
        def fake_run(cmd, **kwargs):
            result = MagicMock()
            result.stderr = ""
            result.stdout = "" if "diff" in cmd else str(tmp_path) + "\n"
            result.returncode = 0
            return result

        with patch("subprocess.run", side_effect=fake_run):
            result = runner.invoke(sc.scan, [str(tmp_path), "--diff", "origin/main"])
        assert result.exit_code == 0
        assert "No Solidity files changed" in result.output


class TestScanAgenticProfile:
    def test_agentic_profile_routes_to_deep_agent(self, runner, tmp_path):
        contract = tmp_path / "Vault.sol"
        contract.write_text(_PRAGMA_SOL)
        agentic_profile = {
            "enable_agentic_invariants": True,
            "description": "agentic",
            "timeout": 600,
        }
        agent = MagicMock()
        agent.analyze.return_value = {
            "findings": [{"type": "invariant", "severity": "HIGH"}],
            "metadata": {"agentic_invariants_count": 1},
        }
        with (
            patch.object(sc, "get_profile", return_value=agentic_profile),
            patch("miesc.agents.deep_audit_agent.DeepAuditAgent", return_value=agent),
            patch(
                "miesc.cli.commands.audit._apply_deep_profile_config",
                side_effect=lambda cfg, name: (cfg, agentic_profile),
            ),
        ):
            result = runner.invoke(sc.scan, [str(contract), "--profile", "agentic-x", "--quiet"])
        assert result.exit_code == 0
        agent.analyze.assert_called_once_with(str(contract))

    def test_agentic_profile_rejects_directory(self, runner, tmp_path):
        (tmp_path / "A.sol").write_text(_PRAGMA_SOL)
        agentic_profile = {"agentic_ensemble": {"provider_contract": "x"}}
        with patch.object(sc, "get_profile", return_value=agentic_profile):
            result = runner.invoke(sc.scan, [str(tmp_path), "--profile", "agentic-x", "--quiet"])
        assert result.exit_code == 1
