"""
Tests for the ``miesc doctor --smoke`` functional probe (P1-5).

The classification matrix is driven with a mocked subprocess so no real tool is
needed; one real subprocess probe of a bogus tool exercises the end-to-end path
deterministically.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from miesc.cli import smoke_probe


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestLayerSelection:
    def test_default_is_fast_layers(self):
        assert smoke_probe.layers_for(False) == smoke_probe.FAST_LAYERS

    def test_smoke_all_adds_slow_layers(self):
        layers = smoke_probe.layers_for(True)
        assert set(layers) == set(smoke_probe.FAST_LAYERS) | set(smoke_probe.SLOW_LAYERS)
        # Fast and slow layers are disjoint and cover 1..9.
        assert set(layers) == set(range(1, 10))

    def test_timeout_longer_for_smoke_all(self):
        assert smoke_probe.timeout_for(True) > smoke_probe.timeout_for(False)


class TestProbeClassification:
    _KW = {"timeout": 5, "llm_tools": set(), "ollama_online": True}

    @pytest.mark.parametrize("status", ["success", "inconclusive"])
    def test_success_and_inconclusive_are_functional(self, status):
        out = _completed(stdout='{"status": "%s", "error": "", "findings": 0}\n' % status)
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, detail = smoke_probe.probe_tool("slither", "/f.sol", **self._KW)
        assert verdict == smoke_probe.FUNCTIONAL
        if status == "inconclusive":
            assert "inconclusive" in detail

    def test_error_status_is_degraded(self):
        out = _completed(stdout='{"status": "error", "error": "boom", "findings": 0}\n')
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, detail = smoke_probe.probe_tool("mythril", "/f.sol", **self._KW)
        assert verdict == smoke_probe.DEGRADED
        assert "boom" in detail

    def test_skipped_unsupported_source_is_not_applicable_not_degraded(self):
        # A .vy / circom analyzer handed a .sol correctly declines it — that is
        # designed behaviour, not a defect, and must not inflate the gap.
        out = _completed(
            stdout='{"status": "skipped", "reason": "unsupported_source", "error": ""}\n'
        )
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, detail = smoke_probe.probe_tool("vyper", "/f.sol", **self._KW)
        assert verdict == smoke_probe.NOT_APPLICABLE
        assert "unsupported_source" in detail

    def test_nonzero_exit_is_degraded(self):
        out = _completed(returncode=1, stderr="Traceback: kaboom")
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, detail = smoke_probe.probe_tool("wake", "/f.sol", **self._KW)
        assert verdict == smoke_probe.DEGRADED
        assert "kaboom" in detail

    def test_unparseable_output_is_degraded(self):
        out = _completed(stdout="not json at all")
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, _ = smoke_probe.probe_tool("semgrep", "/f.sol", **self._KW)
        assert verdict == smoke_probe.DEGRADED

    def test_timeout_is_slow_not_broken(self):
        with patch(
            "miesc.cli.smoke_probe.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5),
        ):
            verdict, _ = smoke_probe.probe_tool("manticore", "/f.sol", **self._KW)
        assert verdict == smoke_probe.SLOW

    def test_llm_tool_offline_is_needs_backend_without_spawning(self):
        with patch("miesc.cli.smoke_probe.subprocess.run") as run:
            verdict, detail = smoke_probe.probe_tool(
                "gptscan", "/f.sol", timeout=5, llm_tools={"gptscan"}, ollama_online=False
            )
        assert verdict == smoke_probe.NEEDS_BACKEND
        run.assert_not_called()  # never probe a tool whose backend is down

    def test_llm_tool_online_is_probed(self):
        out = _completed(stdout='{"status": "success", "error": "", "findings": 1}\n')
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out) as run:
            verdict, _ = smoke_probe.probe_tool(
                "gptscan", "/f.sol", timeout=5, llm_tools={"gptscan"}, ollama_online=True
            )
        assert verdict == smoke_probe.FUNCTIONAL
        run.assert_called_once()

    def test_last_stdout_line_is_parsed(self):
        # Adapters log noise before the JSON; only the last line is the result.
        out = _completed(stdout='INFO loading\nWARN slow\n{"status": "success", "error": ""}\n')
        with patch("miesc.cli.smoke_probe.subprocess.run", return_value=out):
            verdict, _ = smoke_probe.probe_tool("slither", "/f.sol", **self._KW)
        assert verdict == smoke_probe.FUNCTIONAL


class TestEnvAndFixture:
    def test_probe_env_strips_cloud_keys(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-x", "ANTHROPIC_API_KEY": "sk-y"}):
            env = smoke_probe._probe_env()
        assert "OPENAI_API_KEY" not in env
        assert "ANTHROPIC_API_KEY" not in env

    def test_write_fixture_creates_compilable_contract(self, tmp_path):
        path = smoke_probe.write_fixture(tmp_path)
        assert path.exists() and path.suffix == ".sol"
        src = path.read_text()
        assert "pragma solidity" in src and "contract SmokeProbe" in src


class TestSummaryHelpers:
    def test_summarize_counts_all_verdicts(self):
        counts = smoke_probe.summarize(
            [smoke_probe.FUNCTIONAL, smoke_probe.FUNCTIONAL, smoke_probe.SLOW, "junk"]
        )
        assert counts[smoke_probe.FUNCTIONAL] == 2
        assert counts[smoke_probe.SLOW] == 1
        assert counts[smoke_probe.DEGRADED] == 0
        assert "junk" not in counts

    def test_headline_shape(self):
        assert smoke_probe.headline(31, 33, 47, 50) == (
            "functional 31 / applicable 33 / available 47 / total 50"
        )


class TestRealSubprocess:
    """One un-mocked probe to exercise the real child process + run_tool path."""

    def test_bogus_tool_is_not_functional(self, tmp_path):
        fixture = str(smoke_probe.write_fixture(Path(tmp_path)))
        verdict, _ = smoke_probe.probe_tool(
            "definitely_not_a_real_tool",
            fixture,
            timeout=15,
            llm_tools=set(),
            ollama_online=True,
        )
        # run_tool returns skipped/no_adapter for an unknown tool -> not-applicable
        # (never "functional"). This exercises the real child + run_tool path.
        assert verdict == smoke_probe.NOT_APPLICABLE
        assert verdict != smoke_probe.FUNCTIONAL
