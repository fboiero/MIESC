"""Unit tests for ``miesc.core.provenance`` (the ``provenance`` block of result JSON).

The block must (1) record tool versions as the binaries report them, probing each
tool once per run, (2) never let a failing probe break a run, (3) record the config
file hash, the reproducibility env vars that are set, git SHA when running from a
checkout, and (4) flatten for ``miesc evaluate compare`` even for pre-provenance
artifacts.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from miesc import __version__ as VERSION
from miesc.core import provenance as prov


@pytest.fixture(autouse=True)
def _fresh_cache():
    prov.reset_tool_versions()
    yield
    prov.reset_tool_versions()


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


# ---------------------------------------------------------------------------
# probe_version
# ---------------------------------------------------------------------------


class TestProbeVersion:
    def test_returns_the_version_line_as_the_binary_prints_it(self, monkeypatch):
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: "/usr/bin/aderyn")
        with patch.object(prov.subprocess, "run", return_value=_completed("aderyn 0.1.9\n")):
            assert prov.probe_version(["aderyn", "--version"]) == "aderyn 0.1.9"

    def test_skips_banner_lines_without_a_digit(self, monkeypatch):
        """solc prints a banner before ``Version: ...``; the version line is kept."""
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: "/usr/bin/solc")
        out = "solc, the solidity compiler commandline interface\nVersion: 0.8.10+commit.fc41\n"
        with patch.object(prov.subprocess, "run", return_value=_completed(out)):
            assert prov.probe_version(["solc", "--version"]) == "Version: 0.8.10+commit.fc41"

    def test_falls_back_to_stderr(self, monkeypatch):
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: "/usr/bin/x")
        with patch.object(prov.subprocess, "run", return_value=_completed("", "myth v0.24.8")):
            assert prov.probe_version(["myth", "version"]) == "myth v0.24.8"

    def test_not_installed_when_executable_is_missing(self, monkeypatch):
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: None)
        with patch.object(prov.subprocess, "run") as run:
            assert prov.probe_version(["nothere", "--version"]) == "not_installed"
        run.assert_not_called()

    @pytest.mark.parametrize(
        "exc",
        [
            subprocess.TimeoutExpired(cmd="x", timeout=1),
            FileNotFoundError("bad interpreter"),
            PermissionError("denied"),
            RuntimeError("boom"),
        ],
    )
    def test_unknown_on_any_probe_failure(self, monkeypatch, exc):
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: "/usr/bin/x")
        with patch.object(prov.subprocess, "run", side_effect=exc):
            assert prov.probe_version(["x", "--version"]) == "unknown"

    def test_unknown_when_output_is_empty(self, monkeypatch):
        monkeypatch.setattr(prov.shutil, "which", lambda _exe: "/usr/bin/x")
        with patch.object(prov.subprocess, "run", return_value=_completed("", "", 1)):
            assert prov.probe_version(["x", "--version"]) == "unknown"

    def test_empty_command_is_unknown(self):
        assert prov.probe_version([]) == "unknown"


# ---------------------------------------------------------------------------
# tool_version / collect_tool_versions (once per run, adapter-declared command)
# ---------------------------------------------------------------------------


class _Adapter:
    def __init__(self, command=None, install_cmd="pip install something"):
        self._command = command
        self._install_cmd = install_cmd

    def version_command(self):
        return self._command

    def get_metadata(self):
        return SimpleNamespace(installation_cmd=self._install_cmd)


class TestToolVersions:
    def test_uses_the_adapter_declared_command(self, monkeypatch):
        """The recorded version is the binary the adapter resolved, not PATH's."""
        adapter = _Adapter(["/opt/homebrew/bin/slither", "--version"])
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: adapter)
        seen = []

        def fake_probe(cmd, timeout=prov.PROBE_TIMEOUT_S):
            seen.append(list(cmd))
            return "0.11.6"

        monkeypatch.setattr(prov, "probe_version", fake_probe)
        assert prov.tool_version("slither") == "0.11.6"
        assert seen == [["/opt/homebrew/bin/slither", "--version"]]

    def test_falls_back_to_the_known_command_table(self, monkeypatch):
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: _Adapter(None))
        monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: " ".join(cmd))
        assert prov.tool_version("aderyn") == "aderyn --version"

    def test_builtin_adapters_report_the_miesc_version(self, monkeypatch):
        monkeypatch.setattr(
            prov, "_adapter_for", lambda _t: _Adapter(None, "# Built-in, no installation required")
        )
        assert prov.tool_version("gas_analyzer") == f"built-in (miesc {VERSION})"
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: _Adapter(None, "pip install miesc"))
        assert prov.tool_version("l2_validator") == f"built-in (miesc {VERSION})"

    def test_miesc_pseudo_tools_are_builtin_without_an_adapter(self, monkeypatch):
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: None)
        assert prov.tool_version("miesc-intelligence") == f"built-in (miesc {VERSION})"
        assert prov.tool_version("access-control-semantic") == f"built-in (miesc {VERSION})"

    def test_unknown_when_no_version_flag_is_known(self, monkeypatch):
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: _Adapter(None, "npm install -g x"))
        assert prov.tool_version("fouranalyzer") == "unknown"

    def test_probes_each_tool_once_per_run(self, monkeypatch):
        monkeypatch.setattr(prov, "_adapter_for", lambda _t: None)
        calls = []
        monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: calls.append(cmd) or "1")
        prov.collect_tool_versions(["slither", "aderyn"])
        prov.collect_tool_versions(["slither", "aderyn", "slither"])
        assert len(calls) == 2
        prov.reset_tool_versions()
        prov.collect_tool_versions(["slither"])
        assert len(calls) == 3

    def test_adapter_errors_do_not_propagate(self, monkeypatch):
        class Broken:
            def version_command(self):
                raise RuntimeError("no")

            def get_metadata(self):
                raise RuntimeError("no")

        monkeypatch.setattr(prov, "_adapter_for", lambda _t: Broken())
        assert prov.tool_version("weird") == "unknown"


# ---------------------------------------------------------------------------
# executed_tools
# ---------------------------------------------------------------------------


class TestExecutedTools:
    def test_keeps_only_tools_that_ran_in_first_seen_order(self):
        results = [
            {"tool": "slither", "status": "success"},
            {"tool": "aderyn", "status": "not_available"},
            {"tool": "mythril", "status": "error"},
            {"tool": "smartguard", "status": "skipped"},
            {"tool": "slither", "status": "success"},
            {"tool": "echidna", "status": "timeout"},
            "garbage",
            {"status": "success"},
        ]
        assert prov.executed_tools(results) == ["slither", "mythril", "echidna"]


# ---------------------------------------------------------------------------
# config / env / git / solc
# ---------------------------------------------------------------------------


class TestCollectors:
    def test_config_records_path_and_sha256(self, tmp_path, monkeypatch):
        cfg = tmp_path / "miesc.yaml"
        cfg.write_text("version: '1'\n", encoding="utf-8")
        monkeypatch.setenv("MIESC_CONFIG", str(cfg))
        from miesc.core import config_loader

        config_loader.MIESCConfig._instance = None  # force re-resolution of the path
        try:
            info = prov.config_info()
        finally:
            config_loader.MIESCConfig._instance = None
        assert info["path"] == str(cfg)
        assert info["exists"] is True
        assert info["sha256"] == prov.sha256_file(cfg)
        assert len(info["sha256"]) == 64

    def test_sha256_file_none_when_unreadable(self, tmp_path):
        assert prov.sha256_file(tmp_path / "missing") is None
        assert prov.sha256_file(None) is None

    def test_python_packages_lists_only_installed_distributions(self):
        found = prov.python_packages(["pytest", "miesc-definitely-not-a-package"])
        assert list(found) == ["pytest"]
        assert found["pytest"][0].isdigit()

    def test_tracked_env_only_when_set(self, monkeypatch):
        for name in prov.TRACKED_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        assert prov.tracked_env() == {}
        monkeypatch.setenv("MIESC_SEED", "42")
        monkeypatch.setenv("MIESC_LLM_PROVIDER", "")  # empty counts as unset
        assert prov.tracked_env() == {"MIESC_SEED": "42"}

    def test_git_info_none_outside_a_checkout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(prov, "__file__", str(tmp_path / "pkg" / "core" / "provenance.py"))
        assert prov.git_info() == {"sha": None, "dirty": None}

    def test_git_info_reads_sha_and_dirty_flag(self, tmp_path, monkeypatch):
        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(prov, "__file__", str(tmp_path / "miesc" / "core" / "provenance.py"))
        outputs = {"rev-parse": _completed("abc123\n"), "status": _completed(" M x.py\n")}

        def fake_run(cmd, **_kw):
            return outputs["rev-parse" if "rev-parse" in cmd else "status"]

        with patch.object(prov.subprocess, "run", side_effect=fake_run):
            assert prov.git_info() == {"sha": "abc123", "dirty": True}

    def test_git_info_survives_a_missing_git_binary(self, tmp_path, monkeypatch):
        (tmp_path / ".git").write_text("gitdir: elsewhere\n")  # worktree style
        monkeypatch.setattr(prov, "__file__", str(tmp_path / "miesc" / "core" / "provenance.py"))
        with patch.object(prov.subprocess, "run", side_effect=FileNotFoundError("git")):
            assert prov.git_info() == {"sha": None, "dirty": None}

    def test_solc_prefers_the_adapter_recorded_selection(self, monkeypatch, tmp_path):
        monkeypatch.setattr(prov, "_solc_via_adapter", lambda _c: {"should": "not be used"})
        monkeypatch.setattr(prov, "_SOLC_ARTIFACTS", tmp_path / "artifacts")
        monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: "Version: 0.4.26+x")
        results = [
            {
                "tool": "slither",
                "status": "success",
                "contract": "a.sol",
                "metadata": {"solc_version": "0.4.26"},
            },
            {"tool": "aderyn", "status": "success", "contract": "a.sol", "metadata": {}},
        ]
        info = prov.solc_info(results, contracts=["a.sol"])
        assert info["per_contract"] == {"a.sol": "0.4.26"}
        # artifact absent in tmp -> not_installed; PATH solc probed via the patched probe
        assert info["binaries"] == {"0.4.26": "not_installed"}
        assert info["path_default"] == "Version: 0.4.26+x"

    def test_solc_recomputes_missing_contracts_with_the_adapter_logic(self, monkeypatch, tmp_path):
        monkeypatch.setattr(prov, "_SOLC_ARTIFACTS", tmp_path / "artifacts")
        binary = tmp_path / "artifacts" / "solc-0.5.17" / "solc-0.5.17"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\n")
        monkeypatch.setattr(prov, "_solc_via_adapter", lambda cs: dict.fromkeys(cs, "0.5.17"))
        monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: f"probed {cmd[0]}")
        info = prov.solc_info([], contracts=["b.sol"])
        assert info["per_contract"] == {"b.sol": "0.5.17"}
        assert info["binaries"] == {"0.5.17": f"probed {binary}"}


# ---------------------------------------------------------------------------
# build_provenance
# ---------------------------------------------------------------------------


@pytest.fixture
def quiet_collectors(monkeypatch):
    """Keep the builder off the real machine: no subprocesses, no adapters."""
    monkeypatch.setattr(prov, "_adapter_for", lambda _t: None)
    monkeypatch.setattr(prov, "_solc_via_adapter", lambda _c: {})
    monkeypatch.setattr(prov, "probe_version", lambda cmd, timeout=0: f"{cmd[0]} 1.2.3")
    monkeypatch.setattr(prov, "git_info", lambda: {"sha": "deadbeef", "dirty": False})
    monkeypatch.setattr(prov, "_llm_tools", lambda: {"smartguard", "gptscan"})
    for name in prov.TRACKED_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class TestBuildProvenance:
    def test_block_has_every_documented_field(self, quiet_collectors, monkeypatch):
        monkeypatch.setenv("MIESC_SEED", "7")
        results = [
            {
                "tool": "slither",
                "status": "success",
                "contract": "a.sol",
                "metadata": {"solc_version": "0.8.20"},
            },
            {"tool": "aderyn", "status": "not_available"},
        ]
        block = prov.build_provenance(
            results, command="scan", contracts=["a.sol"], argv=["miesc", "scan", "a.sol"]
        )
        assert block["schema"] == prov.SCHEMA_VERSION
        assert block["command"] == "scan"
        assert block["argv"] == ["miesc", "scan", "a.sol"]
        assert block["command_line"] == "miesc scan a.sol"
        assert block["miesc"] == {"version": VERSION, "git_sha": "deadbeef", "git_dirty": False}
        assert block["python"]["version"] and block["platform"]["system"]
        assert block["tools"] == {"slither": "slither 1.2.3"}  # aderyn did not run
        assert block["solc"]["per_contract"] == {"a.sol": "0.8.20"}
        assert block["config"]["sha256"] and block["config"]["exists"] is True
        assert block["env"] == {"MIESC_SEED": "7"}
        assert block["llm_free"] is True
        json.dumps(block)  # serialisable as written

    def test_llm_free_is_false_when_an_llm_tool_ran(self, quiet_collectors):
        results = [{"tool": "smartguard", "status": "success"}]
        assert prov.build_provenance(results, command="audit full")["llm_free"] is False

    def test_llm_free_is_false_when_the_caller_used_an_llm(self, quiet_collectors):
        results = [{"tool": "slither", "status": "success"}]
        block = prov.build_provenance(results, command="scan", llm_used=True)
        assert block["llm_free"] is False

    def test_explicit_llm_free_wins(self, quiet_collectors):
        results = [{"tool": "smartguard", "status": "success"}]
        block = prov.build_provenance(results, command="evaluate corpus", llm_free=True)
        assert block["llm_free"] is True

    def test_unknown_llm_use_is_recorded_as_null(self, quiet_collectors):
        block = prov.build_provenance([], command="scan", llm_used=None)
        assert block["llm_free"] is None

    def test_extra_is_kept_verbatim(self, quiet_collectors):
        block = prov.build_provenance([], command="fix", extra={"profile": "deep"})
        assert block["extra"] == {"profile": "deep"}

    def test_a_failing_collector_never_breaks_the_build(self, quiet_collectors, monkeypatch):
        def boom(*_a, **_k):
            raise RuntimeError("probe exploded")

        monkeypatch.setattr(prov, "collect_tool_versions", boom)
        monkeypatch.setattr(prov, "solc_info", boom)
        monkeypatch.setattr(prov, "config_info", boom)
        monkeypatch.setattr(prov, "git_info", boom)
        block = prov.build_provenance(
            [{"tool": "slither", "status": "success"}], command="scan", argv=["x"]
        )
        assert block["miesc"]["version"] == VERSION
        assert block["tools"] == {}
        assert block["config"]["sha256"] is None
        assert block["llm_free"] is True

    def test_argv_defaults_to_sys_argv(self, quiet_collectors, monkeypatch):
        monkeypatch.setattr(prov.sys, "argv", ["miesc", "audit", "quick", "c.sol"])
        block = prov.build_provenance([], command="audit quick")
        assert block["argv"] == ["miesc", "audit", "quick", "c.sol"]


# ---------------------------------------------------------------------------
# compare support
# ---------------------------------------------------------------------------


class TestCompareSupport:
    def test_pre_provenance_artifact_falls_back_to_the_experiment_card(self):
        legacy = {
            "version": "5.4.1",
            "experiment_card": {
                "python_version": "3.12.0",
                "platform": "darwin",
                "llm_free": False,
            },
            "reproducibility": {
                "command": "miesc evaluate corpus x",
                "seed": "not_set",
                "llm_provider": "ollama",
                "llm_model": "not_set",
            },
            "aggregate": {},
        }
        rows = prov.provenance_summary(legacy)
        assert rows["MIESC version"] == "5.4.1"
        assert rows["Python"] == "3.12.0"
        assert rows["Git SHA"] == "n/a (pre-provenance artifact)"
        assert rows["Tool versions"] == "n/a (pre-provenance artifact)"
        assert rows["MIESC_SEED"] == "not set"
        assert rows["MIESC_LLM_PROVIDER"] == "ollama"
        assert rows["Command"] == "miesc evaluate corpus x"

    def test_rows_cover_both_runs_with_tool_union(self, quiet_collectors):
        run_a = {
            "provenance": prov.build_provenance(
                [{"tool": "slither", "status": "success"}], command="evaluate corpus", argv=["a"]
            )
        }
        run_b = {
            "provenance": prov.build_provenance(
                [{"tool": "slither", "status": "success"}, {"tool": "aderyn", "status": "success"}],
                command="evaluate corpus",
                argv=["b"],
            )
        }
        rows = prov.provenance_rows(run_a, run_b)
        labels = [label for label, _a, _b in rows]
        assert labels[0] == "MIESC version"
        assert "tool: slither" in labels and "tool: aderyn" in labels
        assert labels[-1] == "Command"
        aderyn = next(row for row in rows if row[0] == "tool: aderyn")
        assert aderyn[1] == "—" and aderyn[2] == "aderyn 1.2.3"
        command = next(row for row in rows if row[0] == "Command")
        assert command[1:] == ("a", "b")

    def test_rows_never_raise_on_garbage(self):
        rows = prov.provenance_rows({}, {"provenance": "not a dict"})
        assert rows and all(len(row) == 3 for row in rows)
