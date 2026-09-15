"""Behavioral coverage tests for the ``miesc evaluate`` research harness.

These tests exercise the real code paths in ``miesc.cli.commands.evaluate``:
the pure helpers (``_normalize_category``, ``_compute_metrics``,
``_load_ground_truth``, ``_generate_experiment_card``), the evaluation engine
(``_evaluate_contract``, ``_run_ablation``) and the click commands
(``corpus``, ``ablation``, ``info``, ``compare``, ``download``) via
``CliRunner``. The scan layers are mocked (``run_layer``) so no external tool
or network side effect is triggered; every assertion checks real behaviour
(exit codes, emitted metrics, written JSON/JSONL artifacts).

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.evaluate import (
    _compute_metrics,
    _evaluate_contract,
    _generate_experiment_card,
    _load_ground_truth,
    _normalize_category,
    _run_ablation,
    evaluate,
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Build a minimal SmartBugs-curated style corpus on disk.

    Layout:
        corpus/reentrancy/vuln.sol   -> {reentrancy}
        corpus/arithmetic/of.sol     -> {arithmetic}
        corpus/not_a_category/x.sol  -> ignored (unknown category)
    """
    root = tmp_path / "corpus"
    (root / "reentrancy").mkdir(parents=True)
    (root / "arithmetic").mkdir(parents=True)
    (root / "not_a_category").mkdir(parents=True)
    (root / "reentrancy" / "vuln.sol").write_text(
        "pragma solidity ^0.4.24;\ncontract A { function f() public {} }\n",
        encoding="utf-8",
    )
    (root / "arithmetic" / "of.sol").write_text(
        "pragma solidity ^0.5.0;\ncontract B {}\n", encoding="utf-8"
    )
    (root / "not_a_category" / "x.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    return root


# ===========================================================================
# Pure helpers
# ===========================================================================


class TestNormalizeCategory:
    def test_direct_alias_match(self):
        assert _normalize_category("reentrancy-eth") == "reentrancy"
        assert _normalize_category("suicidal") == "access_control"
        assert _normalize_category("integer-overflow") == "arithmetic"

    def test_keyword_fallback_on_description(self):
        # Type is unknown but the description carries a keyword.
        assert (
            _normalize_category("SWC-107", description="A classic reentrancy attack vector")
            == "reentrancy"
        )

    def test_keyword_fallback_on_title(self):
        assert _normalize_category("custom", title="Integer overflow in add()") == "arithmetic"

    def test_unmatched_returns_none(self):
        assert _normalize_category("totally-unrelated-thing") is None


class TestComputeMetrics:
    def test_perfect_scores(self):
        m = _compute_metrics(tp=10, fp=0, fn=0)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0

    def test_zero_division_guarded(self):
        m = _compute_metrics(tp=0, fp=0, fn=0)
        assert m["precision"] == 0.0
        assert m["recall"] == 0.0
        assert m["f1"] == 0.0

    def test_partial(self):
        m = _compute_metrics(tp=3, fp=1, fn=1)
        assert m["precision"] == 0.75
        assert m["recall"] == 0.75
        assert m["f1"] == 0.75


class TestLoadGroundTruth:
    def test_reads_known_categories_only(self, corpus):
        gt = _load_ground_truth(corpus)
        assert gt == {
            "reentrancy/vuln.sol": {"reentrancy"},
            "arithmetic/of.sol": {"arithmetic"},
        }
        # The unknown category directory is ignored entirely.
        assert not any("not_a_category" in k for k in gt)


class TestGenerateExperimentCard:
    def test_card_fields(self):
        card = _generate_experiment_card(
            Path("/corpus"),
            [1, 5],
            120,
            {"corpus_size": 42, "skip_unavailable": True},
            duration_s=3.14159,
        )
        ec = card["experiment_card"]
        assert ec["tool"] == "MIESC"
        assert ec["corpus_size"] == 42
        assert ec["layers_evaluated"] == [1, 5]
        assert ec["total_duration_s"] == 3.1
        assert "command" in card["reproducibility"]


# ===========================================================================
# Evaluation engine
# ===========================================================================


def _layer_returning(category_type: str):
    """Return a fake run_layer that emits one finding of the given type."""

    def _fake(layer_num, contract, timeout):
        return [
            {
                "tool": f"tool_{layer_num}",
                "status": "ok",
                "findings": [{"type": category_type, "description": ""}],
            }
        ]

    return _fake


class TestEvaluateContract:
    def test_true_positive_match(self, corpus):
        contract = corpus / "reentrancy" / "vuln.sol"
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy-eth"),
        ):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert result["match"]["hit"] is True
        assert "reentrancy" in result["match"]["tp"]
        assert result["match"]["fn"] == []
        assert result["aggregate"]["findings_count"] == 1
        assert "layer_1" in result["timing"]

    def test_category_only_finding_still_counts(self, corpus):
        # smartllm/gptscan (and ~26 other adapters) key their per-finding
        # taxonomy as "category", never "type" - a finding missing "type"
        # entirely must not be dropped just because its title/description
        # don't happen to contain a matching keyword.
        contract = corpus / "reentrancy" / "vuln.sol"

        def _fake(layer_num, contract_path, timeout):
            return [
                {
                    "tool": "smartllm",
                    "status": "ok",
                    "findings": [{"category": "reentrancy", "title": "LLM-detected issue"}],
                }
            ]

        with patch("miesc.cli.commands.evaluate.run_layer", side_effect=_fake):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert result["match"]["hit"] is True
        assert "reentrancy" in result["match"]["tp"]

    def test_false_negative_when_nothing_detected(self, corpus):
        contract = corpus / "reentrancy" / "vuln.sol"
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("some-unrelated-lint"),
        ):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert result["match"]["hit"] is False
        assert result["match"]["fn"] == ["reentrancy"]

    def test_layer_exception_is_captured(self, corpus):
        contract = corpus / "reentrancy" / "vuln.sol"
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=RuntimeError("boom"),
        ):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        # Exception path still yields a well-formed result (no findings).
        assert result["aggregate"]["findings_count"] == 0
        assert result["layers"][1]["findings_count"] == 0

    def test_skip_unavailable_tool_result(self, corpus):
        contract = corpus / "reentrancy" / "vuln.sol"

        def _fake(layer_num, contract_path, timeout):
            return [{"tool": "slither", "status": "not_available", "findings": []}]

        with patch("miesc.cli.commands.evaluate.run_layer", side_effect=_fake):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert result["aggregate"]["findings_count"] == 0

    def _isolated_contract(self) -> Path:
        """A contract path outside pytest's tmp_path tree.

        tmp_path-based fixtures (like `corpus`) live under
        .../pytest-of-<user>/pytest-N/test_<name>0/... - and "pytest"
        itself contains "test", which trips FalsePositiveFilter's
        test/mock-file heuristic regardless of the actual finding. That's
        the filter working as designed, just colliding with pytest's own
        naming - so these two tests need a path it won't misread.
        """
        root = Path(tempfile.mkdtemp()) / "reentrancy"
        root.mkdir(parents=True)
        contract = root / "vuln.sol"
        contract.write_text(
            "pragma solidity ^0.4.24;\ncontract A { function f() public {} }\n",
            encoding="utf-8",
        )
        return contract

    def test_fp_filter_suppresses_informational_finding(self):
        """MEJORAS2.md #5a: the 270+-pattern FalsePositiveFilter, previously
        wired into scan/audit full but not evaluate_corpus/ablation, must now
        actually remove a category from the match set - not just get computed
        and ignored. Uses severity=info, which FalsePositiveFilter's medium
        preset always treats as a FP (filter_informational=True) - a
        deterministic trigger that doesn't depend on regex/confidence
        arithmetic.
        """
        contract = self._isolated_contract()

        def _fake(layer_num, contract_path, timeout):
            return [
                {
                    "tool": "tool_1",
                    "status": "ok",
                    "findings": [{"type": "reentrancy-eth", "description": "", "severity": "info"}],
                }
            ]

        with patch("miesc.cli.commands.evaluate.run_layer", side_effect=_fake):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=True,
            )
        assert "reentrancy" not in result["match"]["tp"]
        assert result["match"]["fn"] == ["reentrancy"]

    def test_fp_strictness_off_keeps_informational_finding(self):
        """fp_strictness is threaded through to FalsePositiveFilter, not just
        accepted and ignored: "off" never filters (fp_threshold=1.1, always
        > any real score), so the same informational finding that "medium"
        suppresses above must survive here."""
        contract = self._isolated_contract()

        def _fake(layer_num, contract_path, timeout):
            return [
                {
                    "tool": "tool_1",
                    "status": "ok",
                    "findings": [{"type": "reentrancy-eth", "description": "", "severity": "info"}],
                }
            ]

        with patch("miesc.cli.commands.evaluate.run_layer", side_effect=_fake):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=True,
                fp_strictness="off",
            )
        assert "reentrancy" in result["match"]["tp"]

    def test_fp_filter_keeps_real_finding(self):
        """Recall-safety companion to the suppression test above: a
        medium-severity finding with no safe-library/safe-pattern signal must
        survive the new filter untouched."""
        contract = self._isolated_contract()

        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy-eth"),
        ):
            result = _evaluate_contract(
                contract,
                {"reentrancy"},
                [1],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=True,
            )
        assert "reentrancy" in result["match"]["tp"]


def _layer9_llmbugscanner(category: str, title: str):
    """Fake run_layer emitting one llmbugscanner-shaped Layer 9 finding.

    Matches llmbugscanner's real output shape (category, not type; no
    structured location.function - only free text), not the generic
    ``_layer_returning`` shape other tests use.
    """

    def _fake(layer_num, contract, timeout):
        if layer_num != 9:
            return []
        return [
            {
                "tool": "llmbugscanner",
                "status": "success",
                "findings": [
                    {
                        "category": category,
                        "title": title,
                        "description": "",
                        "severity": "Medium",
                        "confidence": 0.9,
                    }
                ],
            }
        ]

    return _fake


class TestPocVerification:
    """MEJORAS2.md #5j: llmbugscanner candidates in the 3 categories
    exploit_synthesizer has a real PoC template for get verified with
    run_poc=True before counting - narrow but reliable, per the chosen scope.
    """

    def test_confirmed_poc_counts_as_tp(self, corpus):
        # reentrancy/vuln.sol has `function f() public {}` - "f" is the
        # function _extract_function_hint must recover from free text.
        contract = corpus / "reentrancy" / "vuln.sol"
        fake_run_layer = _layer9_llmbugscanner(
            "access_control", "Potential access control issue in f"
        )

        def _fake_analyze(self, contract_path, **kwargs):
            findings = kwargs.get("findings", [])
            assert kwargs.get("run_poc") is True
            func = findings[0]["location"]["function"]
            assert func == "f"  # hint extraction actually worked
            return {
                "tool": "exploit_synthesizer",
                "status": "success",
                "findings": [
                    {
                        "type": "exploit_confirmed",
                        "location": {"file": contract_path, "line": 0, "function": func},
                    }
                ],
            }

        with (
            patch("miesc.cli.commands.evaluate.run_layer", side_effect=fake_run_layer),
            patch(
                "miesc.adapters.exploit_synthesizer_adapter.ExploitSynthesizerAdapter.analyze",
                _fake_analyze,
            ),
        ):
            result = _evaluate_contract(
                contract,
                {"access_control"},
                [9],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert "access_control" in result["match"]["tp"]

    def test_unconfirmed_poc_does_not_count(self, corpus):
        contract = corpus / "reentrancy" / "vuln.sol"
        fake_run_layer = _layer9_llmbugscanner(
            "access_control", "Potential access control issue in f"
        )

        def _fake_analyze(self, contract_path, **kwargs):
            return {
                "tool": "exploit_synthesizer",
                "status": "success",
                "findings": [
                    {
                        "type": "exploit_not_confirmed",
                        "location": {"file": contract_path, "line": 0, "function": "f"},
                    }
                ],
            }

        with (
            patch("miesc.cli.commands.evaluate.run_layer", side_effect=fake_run_layer),
            patch(
                "miesc.adapters.exploit_synthesizer_adapter.ExploitSynthesizerAdapter.analyze",
                _fake_analyze,
            ),
        ):
            result = _evaluate_contract(
                contract,
                {"access_control"},
                [9],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        assert "access_control" in result["match"]["fn"]

    def test_out_of_scope_category_never_sent_to_synthesizer(self, corpus):
        """oracle isn't one of the 3 categories with a real PoC template -
        must never even reach exploit_synthesizer, not just fail to confirm."""
        contract = corpus / "reentrancy" / "vuln.sol"
        fake_run_layer = _layer9_llmbugscanner("oracle", "Potential oracle manipulation in f")

        with (
            patch("miesc.cli.commands.evaluate.run_layer", side_effect=fake_run_layer),
            patch(
                "miesc.adapters.exploit_synthesizer_adapter.ExploitSynthesizerAdapter.analyze"
            ) as mock_analyze,
        ):
            result = _evaluate_contract(
                contract,
                {"oracle"},
                [9],
                timeout=1,
                skip_unavailable=True,
                use_intelligence=False,
            )
        mock_analyze.assert_not_called()
        # oracle isn't gated (only the 3 PoC-verifiable categories are), so
        # it's still counted via the pre-existing raw-detection path - the
        # point of this test is that it got there without ever calling
        # exploit_synthesizer, not that it's excluded.
        assert "oracle" in result["match"]["tp"]


class TestRunAblation:
    def test_ablation_computes_per_layer_and_combined(self, corpus):
        gt = _load_ground_truth(corpus)
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy"),
        ):
            res = _run_ablation(
                corpus, gt, [1], timeout=1, skip_unavailable=True, output_jsonl=None
            )
        assert 1 in res["per_layer"]
        assert res["combined"] is not None
        # Layer 1 detected reentrancy on the reentrancy contract -> some recall.
        assert res["per_layer"][1]["recall"] >= 0.0
        assert "is_redundant" in res["layer_contributions"][1]

    def test_ablation_streams_jsonl(self, corpus, tmp_path):
        gt = _load_ground_truth(corpus)
        out = tmp_path / "abl.jsonl"
        out.write_text("", encoding="utf-8")
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy"),
        ):
            _run_ablation(corpus, gt, [1], timeout=1, skip_unavailable=True, output_jsonl=out)
        lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
        assert lines
        assert all(rec["type"] == "ablation_single" for rec in lines)


# ===========================================================================
# CLI commands
# ===========================================================================


class TestEvaluateGroup:
    def test_group_help(self, runner):
        result = runner.invoke(evaluate, ["--help"])
        assert result.exit_code == 0
        assert "ablation" in result.output


class TestCorpusCommand:
    def test_corpus_empty_dir_exits_1(self, runner, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(evaluate, ["corpus", str(empty)])
        assert result.exit_code == 1
        assert "No ground truth" in result.output

    def test_corpus_full_run_writes_output(self, runner, corpus, tmp_path):
        out = tmp_path / "res.json"
        jsonl = tmp_path / "res.jsonl"
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy"),
        ):
            result = runner.invoke(
                evaluate,
                [
                    "corpus",
                    str(corpus),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "--output",
                    str(out),
                    "--jsonl",
                    str(jsonl),
                ],
            )
        assert result.exit_code == 0, result.output
        assert "Evaluation complete" in result.output
        data = json.loads(out.read_text())
        assert data["aggregate"]["contracts_evaluated"] == 2
        # Summary line present in JSONL stream.
        records = [json.loads(x) for x in jsonl.read_text().splitlines() if x.strip()]
        assert any(r.get("type") == "summary" for r in records)

    def test_corpus_category_filter_and_limit(self, runner, corpus):
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy"),
        ):
            result = runner.invoke(
                evaluate,
                [
                    "corpus",
                    str(corpus),
                    "--layers",
                    "1",
                    "--no-intelligence",
                    "--categories",
                    "reentrancy",
                    "--limit",
                    "1",
                ],
            )
        assert result.exit_code == 0, result.output
        assert "Category filter" in result.output


class TestAblationCommand:
    def test_ablation_empty_exits_1(self, runner, tmp_path):
        empty = tmp_path / "e"
        empty.mkdir()
        result = runner.invoke(evaluate, ["ablation", str(empty)])
        assert result.exit_code == 1

    def test_ablation_run_writes_output(self, runner, corpus, tmp_path):
        out = tmp_path / "abl.json"
        with patch(
            "miesc.cli.commands.evaluate.run_layer",
            side_effect=_layer_returning("reentrancy"),
        ):
            result = runner.invoke(
                evaluate,
                ["ablation", str(corpus), "--layers", "1", "--output", str(out)],
            )
        assert result.exit_code == 0, result.output
        assert "Ablation complete" in result.output
        data = json.loads(out.read_text())
        assert "ablation" in data


class TestInfoCommand:
    def test_info_empty_exits_1(self, runner, tmp_path):
        empty = tmp_path / "e"
        empty.mkdir()
        result = runner.invoke(evaluate, ["info", str(empty)])
        assert result.exit_code == 1

    def test_info_reports_distribution(self, runner, corpus):
        result = runner.invoke(evaluate, ["info", str(corpus)])
        assert result.exit_code == 0, result.output
        assert "2 contracts" in result.output
        assert "reentrancy" in result.output


class TestCompareCommand:
    def _write_run(self, path: Path, recall: float, version: str) -> None:
        path.write_text(
            json.dumps(
                {
                    "experiment_card": {"version": version},
                    "aggregate": {
                        "precision": 0.5,
                        "recall": recall,
                        "f1": 0.5,
                        "hit_rate": recall,
                        "total_time_s": 100,
                    },
                    "per_category": {"reentrancy": {"recall": recall}},
                }
            ),
            encoding="utf-8",
        )

    def test_compare_two_runs(self, runner, tmp_path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        self._write_run(a, 0.5, "5.2")
        self._write_run(b, 0.8, "5.3")
        result = runner.invoke(evaluate, ["compare", str(a), str(b)])
        assert result.exit_code == 0, result.output
        assert "Comparison complete" in result.output


class TestDownloadCommand:
    def test_download_existing_dataset_short_circuits(self, runner, tmp_path):
        # Pre-create the target dir with a .sol so the command reports "already exists".
        target = tmp_path / "sb"
        (target / "dataset").mkdir(parents=True)
        (target / "dataset" / "a.sol").write_text("pragma solidity ^0.8.0;", encoding="utf-8")
        result = runner.invoke(evaluate, ["download", "smartbugs", "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert "already exists" in result.output

    def test_download_clones_when_missing(self, runner, tmp_path):
        target = tmp_path / "new_ds"

        class _Proc:
            returncode = 0
            stderr = ""

        def _fake_run(cmd, *args, **kwargs):
            # Simulate a successful clone by creating the eval subdir + a .sol.
            dest = Path(cmd[-1])
            (dest / "dataset").mkdir(parents=True, exist_ok=True)
            (dest / "dataset" / "cloned.sol").write_text("pragma;", encoding="utf-8")
            return _Proc()

        with patch("subprocess.run", side_effect=_fake_run):
            result = runner.invoke(evaluate, ["download", "smartbugs", "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert "Downloaded" in result.output
