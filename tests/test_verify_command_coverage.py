"""
Coverage-focused tests for the ``miesc verify`` CLI command.

These exercise the reachable branches of the command driven through Click's
``CliRunner`` with real temporary inputs, asserting observable behaviour: exit
codes, rendered output, JSON payload contents, argument propagation to the
prover runner, and the import/degradation paths. Genuine externals (the
``SpecRunner`` that shells out to solc/certora/halmos) are replaced with an
in-process fake whose calls are recorded, so we assert on *what the command did
with the results*, never merely that a stub was invoked.

The formal package (``miesc.formal``) is imported dynamically because the command imports it
inside the function body.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from miesc.cli.commands.verify import _find_foundry_root, verify

# The module whose globals we may need to patch (e.g. _find_foundry_root).
VERIFY_MOD = importlib.import_module("miesc.cli.commands.verify")


def _formal_module():
    """Return the importable formal package (``miesc.formal``)."""
    for name in ("miesc.formal",):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    pytest.skip("miesc.formal not importable")


FORMAL_MOD = _formal_module()
VerificationResult = FORMAL_MOD.VerificationResult


def make_result(
    tool: str,
    status: str,
    *,
    rules_passed: int = 0,
    rules_failed: int = 0,
    rules_total: int = 0,
    counterexamples=None,
    elapsed_seconds: float = 0.01,
    spec_file: str = "",
) -> "VerificationResult":
    """Build a real VerificationResult so ``to_dict`` produces the real shape."""
    return VerificationResult(
        tool=tool,
        spec_file=spec_file,
        status=status,
        rules_passed=rules_passed,
        rules_failed=rules_failed,
        rules_total=rules_total,
        counterexamples=list(counterexamples or []),
        elapsed_seconds=elapsed_seconds,
    )


class FakeRunner:
    """In-process stand-in for SpecRunner that records how it was driven."""

    def __init__(self, availability, *, smtchecker=None, certora=None, halmos=None):
        self._availability = availability
        self._smtchecker = smtchecker
        self._certora = certora
        self._halmos = halmos
        self.calls: dict = {}

    def availability_report(self):
        return self._availability

    def run_smtchecker(self, contract_path, timeout=300):
        self.calls["smtchecker"] = {"contract_path": contract_path, "timeout": timeout}
        return self._smtchecker

    def run_certora(self, contract_path, spec, contract_name="MyContract", timeout=300):
        self.calls["certora"] = {
            "contract_path": contract_path,
            "spec": spec,
            "contract_name": contract_name,
            "timeout": timeout,
        }
        return self._certora

    def run_halmos(self, foundry_root, timeout=300):
        self.calls["halmos"] = {"foundry_root": foundry_root, "timeout": timeout}
        return self._halmos


def install_runner(monkeypatch, runner: FakeRunner) -> FakeRunner:
    """Make ``SpecRunner()`` (zero-arg) return ``runner`` inside the command."""
    monkeypatch.setattr(FORMAL_MOD, "SpecRunner", lambda: runner)
    return runner


@pytest.fixture
def contract(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C { uint x; }\n"
    )
    return str(p)


@pytest.fixture
def spec_file(tmp_path):
    p = tmp_path / "rules.spec"
    p.write_text("rule sanity { assert true; }\n")
    return str(p)


# ---------------------------------------------------------------------------
# _find_foundry_root — exercise the real upward walk
# ---------------------------------------------------------------------------


class TestFindFoundryRoot:
    def test_walks_up_from_nested_contract(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        nested = tmp_path / "src" / "token"
        nested.mkdir(parents=True)
        contract = nested / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        assert _find_foundry_root(contract) == tmp_path

    def test_accepts_directory_argument(self, tmp_path):
        # When handed a directory (not a file), the walk starts at the dir itself.
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        subdir = tmp_path / "test"
        subdir.mkdir()
        assert _find_foundry_root(subdir) == tmp_path

    def test_returns_none_in_pristine_tree(self, tmp_path, monkeypatch):
        # Neutralise any foundry.toml that might exist above a real tmp dir by
        # pointing the walk at an isolated chain with a fake filesystem root.
        leaf = tmp_path / "a" / "b" / "c"
        leaf.mkdir(parents=True)
        contract = leaf / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        real_exists = Path.exists

        def no_toml_above(self):
            if self.name == "foundry.toml" and tmp_path in self.parents:
                return False
            if self.name == "foundry.toml":
                # anything outside our tmp tree: pretend it is absent too
                return False
            return real_exists(self)

        monkeypatch.setattr(Path, "exists", no_toml_above)
        assert _find_foundry_root(contract) is None


# ---------------------------------------------------------------------------
# Argument / help plumbing
# ---------------------------------------------------------------------------


class TestInvocationPlumbing:
    def test_missing_contract_arg_errors(self):
        result = CliRunner().invoke(verify, [])
        assert result.exit_code != 0

    def test_nonexistent_contract_path_rejected(self):
        result = CliRunner().invoke(verify, ["/no/such/contract.sol", "--quiet"])
        assert result.exit_code != 0

    def test_import_error_is_reported_and_exits_one(self, monkeypatch, contract):
        # Force ``from <formal> import SpecRunner`` to raise ImportError.
        monkeypatch.delattr(FORMAL_MOD, "SpecRunner", raising=False)
        result = CliRunner().invoke(verify, [contract, "--quiet"])
        assert result.exit_code == 1
        assert "specrunner" in result.output.lower()


# ---------------------------------------------------------------------------
# SMTChecker branch
# ---------------------------------------------------------------------------


class TestSmtChecker:
    def test_runs_and_propagates_timeout(self, monkeypatch, contract):
        runner = install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": False, "halmos": False, "smtchecker": True},
                smtchecker=make_result("smtchecker", "passed", rules_total=2, rules_passed=2),
            ),
        )
        result = CliRunner().invoke(
            verify, [contract, "--tool", "smtchecker", "--quiet", "--timeout", "42"]
        )
        assert result.exit_code == 0
        # Real behaviour: the contract path and timeout were routed through.
        assert runner.calls["smtchecker"]["contract_path"] == contract
        assert runner.calls["smtchecker"]["timeout"] == 42

    def test_mixed_case_tool_is_normalised(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": False, "halmos": False, "smtchecker": True},
                smtchecker=make_result("smtchecker", "passed"),
            ),
        )
        # case_sensitive=False on the Choice + .lower() in the body.
        result = CliRunner().invoke(verify, [contract, "--tool", "SMTChecker", "--quiet"])
        assert result.exit_code == 0

    def test_unavailable_solc_errors(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "smtchecker", "--quiet"])
        assert result.exit_code == 1
        assert "solc" in result.output.lower()


# ---------------------------------------------------------------------------
# Certora branch
# ---------------------------------------------------------------------------


class TestCertora:
    def test_requires_spec_when_selected(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner({"certora": True, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "certora", "--quiet"])
        assert result.exit_code == 1
        assert "spec is required" in result.output.lower()

    def test_unavailable_certora_errors(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "certora", "--quiet"])
        assert result.exit_code == 1
        assert "certorarun" in result.output.lower()

    def test_runs_with_spec_and_contract_name(self, monkeypatch, contract, spec_file):
        runner = install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": True, "halmos": False, "smtchecker": False},
                certora=make_result("certora", "passed", rules_total=1, rules_passed=1),
            ),
        )
        result = CliRunner().invoke(
            verify,
            [
                contract,
                "--tool",
                "certora",
                "--spec",
                spec_file,
                "--contract-name",
                "Foo",
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        assert runner.calls["certora"]["spec"] == spec_file
        assert runner.calls["certora"]["contract_name"] == "Foo"

    def test_all_mode_skips_certora_without_spec(self, monkeypatch, contract):
        # certora available but no spec, nothing else available -> skip + no runs.
        install_runner(
            monkeypatch,
            FakeRunner({"certora": True, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "all"])
        assert result.exit_code == 0
        assert "Skipping Certora" in result.output
        assert "No provers were run" in result.output


# ---------------------------------------------------------------------------
# Halmos branch
# ---------------------------------------------------------------------------


class TestHalmos:
    def test_runs_on_detected_foundry_root(self, monkeypatch, tmp_path):
        # Real foundry.toml at the project root, contract nested beneath it.
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        nested = tmp_path / "src"
        nested.mkdir()
        contract = nested / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        runner = install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": False, "halmos": True, "smtchecker": False},
                halmos=make_result("halmos", "passed", rules_total=3, rules_passed=3),
            ),
        )
        result = CliRunner().invoke(verify, [str(contract), "--tool", "halmos", "--quiet"])
        assert result.exit_code == 0
        # The command walked up and handed run_halmos the project root as str.
        assert runner.calls["halmos"]["foundry_root"] == str(tmp_path)

    def test_selected_halmos_without_foundry_errors(self, monkeypatch, contract):
        monkeypatch.setattr(VERIFY_MOD, "_find_foundry_root", lambda _p: None)
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": True, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "halmos", "--quiet"])
        assert result.exit_code == 1
        assert "foundry.toml" in result.output.lower()

    def test_unavailable_halmos_errors(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "halmos", "--quiet"])
        assert result.exit_code == 1
        assert "halmos" in result.output.lower()

    def test_all_mode_skips_halmos_without_foundry(self, monkeypatch, contract):
        monkeypatch.setattr(VERIFY_MOD, "_find_foundry_root", lambda _p: None)
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": True, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "all"])
        assert result.exit_code == 0
        assert "Skipping Halmos" in result.output
        assert "No provers were run" in result.output


# ---------------------------------------------------------------------------
# Full non-quiet run: banner, availability, summary, JSON, exit code
# ---------------------------------------------------------------------------


class TestFullRunAndReporting:
    def test_all_provers_non_quiet_with_json_output(self, monkeypatch, tmp_path, spec_file):
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;")
        out = tmp_path / "out.json"

        install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": True, "halmos": True, "smtchecker": True},
                smtchecker=make_result("smtchecker", "passed", rules_total=1, rules_passed=1),
                certora=make_result(
                    "certora",
                    "failed",
                    rules_total=1,
                    rules_failed=1,
                    counterexamples=["x = 0"],
                ),
                halmos=make_result("halmos", "no_tests"),
            ),
        )
        result = CliRunner().invoke(
            verify,
            [str(contract), "--tool", "all", "--spec", spec_file, "--output", str(out)],
        )

        # A failed prover drives exit code 1.
        assert result.exit_code == 1
        # Non-quiet rendering: availability block + results summary + counterexamples.
        assert "Prover availability" in result.output
        assert "Verification Results" in result.output
        assert "counterexamples" in result.output
        assert "written to" in result.output

        # Real serialisation: the unified verification report shape.
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["contract"]
        assert {"summary", "provers"} <= set(data)
        provers = data["provers"]
        assert {"smtchecker", "certora", "halmos"} <= set(provers)
        # The failed certora run is serialised with its status and counterexample.
        assert provers["certora"]["status"] in (
            "failed",
            "violated",
        )  # main normalizes failed->violated
        assert any("x = 0" in json.dumps(c) for c in provers["certora"]["counterexamples"])
        assert isinstance(provers["halmos"]["elapsed_seconds"], float)

    def test_timeout_and_error_statuses_render(self, monkeypatch, contract, spec_file):
        # Exercise the status->colour map for 'timeout' and 'error' (no failure).
        install_runner(
            monkeypatch,
            FakeRunner(
                {"certora": True, "halmos": False, "smtchecker": True},
                smtchecker=make_result("smtchecker", "timeout"),
                certora=make_result("certora", "error"),
            ),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "all", "--spec", spec_file])
        # Neither 'timeout' nor 'error' counts as a failure -> exit 0.
        assert result.exit_code == 0
        assert "timeout" in result.output
        assert "error" in result.output

    def test_no_provers_available_in_all_mode(self, monkeypatch, contract):
        install_runner(
            monkeypatch,
            FakeRunner({"certora": False, "halmos": False, "smtchecker": False}),
        )
        result = CliRunner().invoke(verify, [contract, "--tool", "all", "--quiet"])
        assert result.exit_code == 0
        assert "No provers were run" in result.output
