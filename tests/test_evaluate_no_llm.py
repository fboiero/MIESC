"""LLM-free evaluation profile (``miesc evaluate --no-llm``) and run-level tool probing.

Covers the three behaviours the Paper 1 reproduction depends on:

* ``--no-llm`` skips every adapter that declares ``requires_llm`` (SmartGuard in
  layer 6 is the one that bites: it calls Ollama whenever ``ollama list`` shows a
  model) without probing it, and records ``llm_free`` in the experiment card.
* Tool availability is probed once per run, not once per contract.
* Evaluate results keep ``version``, ``timestamp`` and ``tools_used`` at the top
  level (as the 5.4.1 paper artifacts do) so ``evaluate compare`` can read them.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc import __version__ as VERSION
from miesc.cli import utils
from miesc.cli.commands import evaluate as ev
from miesc.cli.utils import AdapterLoader
from miesc.core.tool_protocol import ToolStatus

REPO = Path(__file__).resolve().parents[1]
PAPER1_ARTIFACT = REPO / "benchmarks" / "results" / "paper1_smartbugs_eval_layers_1_6_7.json"

# Adapters whose analysis calls an LLM backend (local Ollama or a hosted API).
LLM_ADAPTERS = {
    "frontier_llm",
    "gptlens",
    "gptscan",
    "iaudit",
    "llamaaudit",
    "llmbugscanner",
    "llmsmartaudit",
    "propertygpt",
    "smartguard",
    "smartllm",
}


class _FakeAdapter:
    """Minimal adapter: counts availability probes, returns no findings."""

    def __init__(self, status: ToolStatus = ToolStatus.AVAILABLE, requires_llm: bool = False):
        self.status = status
        self.probes = 0
        self.analyses = 0
        self._requires_llm = requires_llm

    def is_available(self) -> ToolStatus:
        self.probes += 1
        return self.status

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        self.analyses += 1
        return {"status": "success", "findings": [], "execution_time": 0.0}

    def get_metadata(self) -> Any:
        class _Meta:
            requires_llm = self._requires_llm

        return _Meta()


@pytest.fixture
def adapter_registry(monkeypatch):
    """Replace the process-wide adapter registry with fakes for one test."""
    saved = (AdapterLoader._adapters, AdapterLoader._loaded, AdapterLoader._availability)

    def install(adapters: Dict[str, Any]) -> None:
        AdapterLoader._adapters = adapters
        AdapterLoader._loaded = True
        AdapterLoader._availability = {}

    for name in ("info", "success", "warning"):
        monkeypatch.setattr(utils, name, lambda *_a, **_k: None)
    yield install
    AdapterLoader._adapters, AdapterLoader._loaded, AdapterLoader._availability = saved


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    (root / "reentrancy").mkdir(parents=True)
    (root / "reentrancy" / "dao.sol").write_text(
        "pragma solidity ^0.4.24;\ncontract A { function f() public {} }\n", encoding="utf-8"
    )
    (root / "arithmetic").mkdir()
    (root / "arithmetic" / "of.sol").write_text("pragma solidity ^0.5.0;\ncontract B {}\n")
    return root


def _fake_layer(layer_num: int, contract: str, timeout: int, **kwargs: Any) -> list[dict]:
    """run_layer stand-in: one static finding, plus whatever ``exclude_tools`` says to skip."""
    results = [
        {"tool": "slither", "status": "success", "findings": [{"type": "reentrancy-eth"}]},
        {"tool": "aderyn", "status": "skipped", "reason": "not_installed", "findings": []},
    ]
    for tool in sorted(kwargs.get("exclude_tools") or ()):
        results.append(
            {
                "tool": tool,
                "status": "skipped",
                "reason": "no_llm",
                "findings": [],
                "error": "--no-llm",
            }
        )
    return results


# ===========================================================================
# Adapter metadata: requires_llm is the single source of truth
# ===========================================================================


class TestRequiresLLMMetadata:
    def test_every_adapter_with_an_llm_backend_declares_it(self):
        """Any adapter importing an LLM backend must flag requires_llm=True.

        Guards the list against rot: a new Ollama-backed adapter that forgets the
        flag would silently run under ``--no-llm``.
        """
        backend_import = re.compile(
            r"from miesc\.core\.(llm_config|ollama_models) import|FrontierLLMAdapter\("
        )
        offenders = []
        for path in sorted((REPO / "miesc" / "adapters").glob("*_adapter.py")):
            text = path.read_text(encoding="utf-8")
            if backend_import.search(text) and "requires_llm=True" not in text:
                offenders.append(path.name)
        assert offenders == [], f"LLM-backed adapters missing requires_llm=True: {offenders}"

    def test_known_llm_adapters_are_flagged_and_static_ones_are_not(self):
        flagged = {
            name[: -len("_adapter.py")]
            for name in (
                p.name
                for p in (REPO / "miesc" / "adapters").glob("*_adapter.py")
                if "requires_llm=True" in p.read_text(encoding="utf-8")
            )
        }
        assert flagged == LLM_ADAPTERS
        # The Paper 1 profile's tools stay LLM-free.
        assert not flagged & {
            "slither",
            "aderyn",
            "solhint",
            "fouranalyzer",
            "smartbugs_ml",
            "smartbugs_detector",
        }

    def test_smartguard_metadata_requires_llm(self):
        from miesc.adapters.smartguard_adapter import SmartGuardAdapter

        with patch("miesc.adapters.smartguard_adapter.select_ollama_model", return_value="m"):
            meta = SmartGuardAdapter().get_metadata()
        assert meta.requires_llm is True

    def test_default_is_false(self):
        from miesc.core.tool_protocol import ToolCategory, ToolMetadata

        meta = ToolMetadata(
            name="x",
            version="1",
            category=ToolCategory.STATIC_ANALYSIS,
            author="",
            license="",
            homepage="",
            repository="",
            documentation="",
            installation_cmd="",
            capabilities=[],
        )
        assert meta.requires_llm is False

    def test_llm_tools_reads_the_registry(self, adapter_registry):
        adapter_registry(
            {
                "slither": _FakeAdapter(),
                "smartguard": _FakeAdapter(requires_llm=True),
                "gptscan": _FakeAdapter(requires_llm=True),
            }
        )
        assert AdapterLoader.llm_tools() == {"smartguard", "gptscan"}


# ===========================================================================
# run_layer(exclude_tools=...): skipped tools are neither probed nor run
# ===========================================================================


class TestRunLayerExclusion:
    def test_smartguard_is_not_probed_under_exclusion(self, adapter_registry, monkeypatch):
        smartguard = _FakeAdapter(requires_llm=True)
        others = {tool: _FakeAdapter() for tool in utils.LAYERS[6]["tools"] if tool != "smartguard"}
        adapter_registry({"smartguard": smartguard, **others})
        monkeypatch.setattr(utils, "get_max_workers", lambda default=4: 1)

        results = utils.run_layer(6, "C.sol", timeout=10, exclude_tools={"smartguard"})

        by_tool = {r["tool"]: r for r in results}
        assert by_tool["smartguard"]["status"] == "skipped"
        assert by_tool["smartguard"]["findings"] == []
        assert smartguard.probes == 0
        assert smartguard.analyses == 0
        # Same shape as a full layer run: every layer tool has a record.
        assert set(by_tool) == set(utils.LAYERS[6]["tools"])
        assert all(a.analyses == 1 for a in others.values())

    def test_without_exclusion_smartguard_runs(self, adapter_registry, monkeypatch):
        smartguard = _FakeAdapter(requires_llm=True)
        others = {tool: _FakeAdapter() for tool in utils.LAYERS[6]["tools"] if tool != "smartguard"}
        adapter_registry({"smartguard": smartguard, **others})
        monkeypatch.setattr(utils, "get_max_workers", lambda default=4: 1)

        results = utils.run_layer(6, "C.sol", timeout=10)

        assert {r["tool"]: r["status"] for r in results}["smartguard"] == "success"
        assert smartguard.probes == 1
        assert smartguard.analyses == 1

    def test_exclusion_preserved_in_parallel_mode(self, adapter_registry, monkeypatch):
        adapters = {tool: _FakeAdapter() for tool in utils.LAYERS[1]["tools"]}
        adapter_registry(adapters)
        monkeypatch.setattr(utils, "get_max_workers", lambda default=4: 4)

        results = utils.run_layer(1, "C.sol", timeout=10, exclude_tools={"semgrep", "wake"})

        statuses = {r["tool"]: r["status"] for r in results}
        assert statuses["semgrep"] == "skipped" and statuses["wake"] == "skipped"
        assert adapters["semgrep"].probes == 0 and adapters["wake"].probes == 0
        assert [r["tool"] for r in results][:4] == ["slither", "aderyn", "solhint", "fouranalyzer"]


# ===========================================================================
# Availability probed once per run
# ===========================================================================


class TestAvailabilityCache:
    def test_run_tool_probes_each_tool_once(self, adapter_registry):
        slither = _FakeAdapter()
        adapter_registry({"slither": slither})

        for contract in ("A.sol", "B.sol", "C.sol"):
            utils.run_tool("slither", contract, timeout=10)

        assert slither.probes == 1
        assert slither.analyses == 3

    def test_not_available_is_cached_too(self, adapter_registry):
        smartguard = _FakeAdapter(status=ToolStatus.CONFIGURATION_ERROR)
        adapter_registry({"smartguard": smartguard})

        statuses = [utils.run_tool("smartguard", c, timeout=10)["status"] for c in ("A", "B")]

        assert statuses == ["skipped", "skipped"]
        assert smartguard.probes == 1
        assert smartguard.analyses == 0

    def test_reset_availability_probes_again(self, adapter_registry):
        slither = _FakeAdapter()
        adapter_registry({"slither": slither})

        utils.run_tool("slither", "A.sol", timeout=10)
        AdapterLoader.reset_availability()
        utils.run_tool("slither", "B.sol", timeout=10)

        assert slither.probes == 2

    def test_evaluate_corpus_resets_the_cache_per_run(self, runner, corpus, tmp_path):
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "reset_availability") as reset,
        ):
            result = runner.invoke(
                ev.evaluate, ["corpus", str(corpus), "--layers", "1", "--no-intelligence"]
            )
        assert result.exit_code == 0, result.output
        reset.assert_called_once()


# ===========================================================================
# CLI: --no-llm flag, experiment card, top-level keys
# ===========================================================================


class TestNoLLMFlag:
    def test_no_llm_skips_llm_tools_and_records_llm_free(self, runner, corpus, tmp_path):
        out = tmp_path / "res.json"
        seen_excludes = []

        def spy(layer_num, contract, timeout, **kwargs):
            seen_excludes.append(set(kwargs.get("exclude_tools") or ()))
            return _fake_layer(layer_num, contract, timeout, **kwargs)

        with (
            patch.object(ev, "run_layer", side_effect=spy),
            patch.object(ev.AdapterLoader, "llm_tools", return_value={"smartguard", "gptscan"}),
        ):
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(corpus),
                    "--layers",
                    "1,6,7",
                    "--no-llm",
                    "--no-intelligence",
                    "--output",
                    str(out),
                ],
            )
        assert result.exit_code == 0, result.output
        assert seen_excludes and all(ex == {"smartguard", "gptscan"} for ex in seen_excludes)

        data = json.loads(out.read_text(encoding="utf-8"))
        card = data["experiment_card"]
        assert card["llm_free"] is True
        # Only the LLM tools that belong to the evaluated layers are reported.
        assert card["skipped_tools"] == ["smartguard"]
        assert data["reproducibility"]["command"].endswith("--layers 1,6,7 --timeout 120 --no-llm")
        assert "corpus" in data["reproducibility"]["command"]

    def test_default_run_is_not_llm_free(self, runner, corpus, tmp_path):
        out = tmp_path / "res.json"
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "llm_tools") as llm_tools,
        ):
            result = runner.invoke(
                ev.evaluate,
                ["corpus", str(corpus), "--layers", "1", "--no-intelligence", "-o", str(out)],
            )
        assert result.exit_code == 0, result.output
        llm_tools.assert_not_called()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["experiment_card"]["llm_free"] is False
        assert data["experiment_card"]["skipped_tools"] == []
        assert "--no-llm" not in data["reproducibility"]["command"]

    def test_no_llm_and_with_llm_are_mutually_exclusive(self, runner, corpus):
        result = runner.invoke(
            ev.evaluate, ["corpus", str(corpus), "--no-llm", "--with-llm", "ollama"]
        )
        assert result.exit_code == 2
        assert "mutually exclusive" in result.output

    def test_top_level_keys_match_the_paper_artifacts(self, runner, corpus, tmp_path):
        out = tmp_path / "res.json"
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "llm_tools", return_value={"smartguard"}),
        ):
            result = runner.invoke(
                ev.evaluate,
                [
                    "corpus",
                    str(corpus),
                    "-l",
                    "1,6",
                    "--no-llm",
                    "--no-intelligence",
                    "-o",
                    str(out),
                ],
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))

        for key in ("version", "timestamp", "tools_used", "experiment_card", "aggregate"):
            assert key in data, key
        assert data["version"] == VERSION
        assert data["timestamp"] == data["experiment_card"]["timestamp"]
        # Only tools that produced a result: not the unavailable or skipped ones.
        assert data["tools_used"] == ["slither"]
        per_layer = data["per_contract"][0]["layers"]["6"]
        # Not-installed and --no-llm tools share the status; the reason tells them apart.
        assert per_layer["tools_skipped"] == ["aderyn", "smartguard"]
        assert per_layer["tool_status"]["smartguard"] == "skipped"
        assert per_layer["tool_reason"] == {"aderyn": "not_installed", "smartguard": "no_llm"}

    def test_ablation_accepts_no_llm(self, runner, corpus, tmp_path):
        out = tmp_path / "abl.json"
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "llm_tools", return_value={"smartguard"}),
        ):
            result = runner.invoke(
                ev.evaluate, ["ablation", str(corpus), "-l", "1,6", "--no-llm", "-o", str(out)]
            )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == VERSION
        assert data["experiment_card"]["llm_free"] is True
        assert data["experiment_card"]["skipped_tools"] == ["smartguard"]
        assert data["reproducibility"]["command"].startswith("miesc evaluate ablation ")
        assert data["reproducibility"]["command"].endswith("--no-llm")
        assert "ablation" in data

    def test_config_no_llm_still_conflicts_with_with_llm(self, runner, corpus, tmp_path):
        pytest.importorskip("yaml")
        cfg = tmp_path / "exp.yaml"
        cfg.write_text("no_llm: true\n", encoding="utf-8")
        result = runner.invoke(
            ev.evaluate, ["corpus", str(corpus), "--config", str(cfg), "--with-llm", "ollama"]
        )
        assert result.exit_code == 2
        assert "mutually exclusive" in result.output

    def test_config_file_can_turn_no_llm_on(self, runner, corpus, tmp_path):
        pytest.importorskip("yaml")
        cfg = tmp_path / "exp.yaml"
        cfg.write_text("layers: [1]\nno_llm: true\n", encoding="utf-8")
        out = tmp_path / "res.json"
        with (
            patch.object(ev, "run_layer", side_effect=_fake_layer),
            patch.object(ev.AdapterLoader, "llm_tools", return_value={"smartguard"}),
        ):
            result = runner.invoke(
                ev.evaluate,
                ["corpus", str(corpus), "--config", str(cfg), "--no-intelligence", "-o", str(out)],
            )
        assert result.exit_code == 0, result.output
        assert json.loads(out.read_text())["experiment_card"]["llm_free"] is True


# ===========================================================================
# Helpers and `evaluate compare`
# ===========================================================================


class TestToolsUsedAndCompare:
    def test_collect_tools_used_keeps_layer_order(self):
        results = [
            {"tools_used": ["solhint", "smartbugs_ml"]},
            {"tools_used": ["slither", "plugin:custom"]},
        ]
        assert ev._collect_tools_used(results, [1, 6]) == [
            "slither",
            "solhint",
            "smartbugs_ml",
            "plugin:custom",
        ]

    def test_run_version_prefers_top_level_then_card(self):
        assert ev._run_version({"version": "5.4.1"}) == "5.4.1"
        assert ev._run_version({"experiment_card": {"version": "6.1.0"}}) == "6.1.0"
        assert ev._run_version({"version": "5.4.1", "experiment_card": {"version": "x"}}) == "5.4.1"
        assert ev._run_version({}) == "?"

    @pytest.mark.skipif(not PAPER1_ARTIFACT.exists(), reason="paper artifact not checked out")
    def test_compare_reads_the_paper_artifact_version(self, runner, tmp_path):
        run_b = tmp_path / "b.json"
        run_b.write_text(
            json.dumps(
                {
                    "experiment_card": {"version": "6.1.0"},
                    "aggregate": {
                        "precision": 0.2,
                        "recall": 1.0,
                        "f1": 0.34,
                        "tp": 1,
                        "fp": 1,
                        "fn": 0,
                    },
                    "per_category": {},
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(ev.evaluate, ["compare", str(PAPER1_ARTIFACT), str(run_b)])
        assert result.exit_code == 0, result.output
        assert "Run A: MIESC 5.4.1" in result.output
        assert "Run B: MIESC 6.1.0" in result.output
        assert "MIESC ?" not in result.output
