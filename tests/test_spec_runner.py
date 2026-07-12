"""Tests for src.formal.spec_runner — Formal verification runner."""

from unittest.mock import patch

import pytest

from miesc.formal.spec_runner import SpecRunner, VerificationResult, run_all_available

# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_defaults(self):
        r = VerificationResult(tool="halmos", spec_file="foo.t.sol", status="passed")
        assert r.rules_passed == 0
        assert r.rules_failed == 0
        assert r.rules_total == 0
        assert r.counterexamples == []
        assert r.elapsed_seconds == 0.0

    def test_to_dict_roundtrip(self):
        r = VerificationResult(
            tool="certora",
            spec_file="rules.spec",
            status="failed",
            rules_passed=3,
            rules_failed=1,
            rules_total=4,
            counterexamples=["x = 0"],
            elapsed_seconds=12.345,
        )
        d = r.to_dict()
        assert d["tool"] == "certora"
        assert d["status"] == "failed"
        assert d["rules_total"] == 4
        assert d["counterexamples"] == ["x = 0"]
        # Elapsed rounded to 2dp
        assert d["elapsed_seconds"] == 12.35
        # stdout/stderr excluded from dict
        assert "stdout" not in d
        assert "stderr" not in d


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


class TestAvailability:
    def test_availability_report_structure(self):
        runner = SpecRunner()
        report = runner.availability_report()
        assert set(report.keys()) == {"certora", "halmos", "smtchecker"}
        for v in report.values():
            assert isinstance(v, bool)

    def test_is_certora_respects_which(self):
        runner = SpecRunner()
        with patch("miesc.formal.spec_runner.shutil.which", return_value=None):
            assert runner.is_certora_available() is False
        with patch("miesc.formal.spec_runner.shutil.which", return_value="/opt/certoraRun"):
            assert runner.is_certora_available() is True


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class TestCertoraParser:
    def test_counts_verified_and_violated(self):
        stdout = """
        Rule noReentrancy: VERIFIED
        Rule onlyOwnerCanPause: VIOLATED
        Rule monotonicity: VERIFIED
        """
        stderr = ""
        passed, failed = SpecRunner._parse_certora_output(stdout, stderr)
        assert passed == 2
        assert failed == 1

    def test_empty_output(self):
        passed, failed = SpecRunner._parse_certora_output("", "")
        assert passed == 0 and failed == 0


class TestHalmosParser:
    def test_counts_pass_fail(self):
        stdout = """
        [PASS] check_invariant_balance
        [FAIL] check_invariant_supply
        Counterexample: amount = 2**256 - 1
        [PASS] test_symbolic_transfer
        """
        passed, failed, counterexamples = SpecRunner._parse_halmos_output(stdout)
        assert passed == 2
        assert failed == 1
        assert len(counterexamples) == 1
        assert "2**256" in counterexamples[0]

    def test_empty_output(self):
        passed, failed, cex = SpecRunner._parse_halmos_output("")
        assert passed == 0 and failed == 0 and cex == []

    def test_strips_ansi_codes(self):
        # Halmos emits ANSI color codes — parser should ignore them
        stdout = "\x1b[32m[PASS]\x1b[0m check_x\n\x1b[31m[FAIL]\x1b[0m check_y\nCounterexample: v = 1\x1b[0m"
        passed, failed, cex = SpecRunner._parse_halmos_output(stdout)
        assert passed == 1
        assert failed == 1
        # Counterexample should be cleaned of ANSI
        assert cex == ["v = 1"]


class TestSmtcheckerParser:
    def test_extracts_warnings(self):
        stderr = """
Warning: CHC: Overflow at line 10
Warning: CHC: Underflow at line 22
"""
        warnings = SpecRunner._parse_smtchecker_warnings(stderr)
        assert len(warnings) >= 1
        assert any("Overflow" in w for w in warnings)

    def test_no_warnings(self):
        warnings = SpecRunner._parse_smtchecker_warnings("")
        assert warnings == []


# ---------------------------------------------------------------------------
# Graceful degradation when tools not installed
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_certora_not_installed(self):
        runner = SpecRunner()
        with patch.object(runner, "is_certora_available", return_value=False):
            r = runner.run_certora("contract.sol", "rules.spec")
            assert r.status == "error"
            assert "certora" in r.stderr.lower()

    def test_halmos_not_installed(self):
        runner = SpecRunner()
        with patch.object(runner, "is_halmos_available", return_value=False):
            r = runner.run_halmos("/tmp/foundry_project")
            assert r.status == "error"
            assert "halmos" in r.stderr.lower()

    def test_smtchecker_not_installed(self):
        runner = SpecRunner()
        with patch.object(runner, "is_solc_available", return_value=False):
            r = runner.run_smtchecker("contract.sol")
            assert r.status == "error"
            assert "solc" in r.stderr.lower()


# ---------------------------------------------------------------------------
# SMTChecker integration (real solc, if available)
# ---------------------------------------------------------------------------


class TestSMTCheckerIntegration:
    @pytest.fixture
    def contract(self, tmp_path):
        p = tmp_path / "C.sol"
        p.write_text("""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            contract C {
                uint256 public x;
                function inc(uint256 v) external {
                    x += v;
                }
            }
            """)
        return str(p)

    def test_run_smtchecker_returns_result(self, contract):
        runner = SpecRunner()
        if not runner.is_solc_available():
            pytest.skip("solc not installed")
        r = runner.run_smtchecker(contract, timeout=60)
        assert r.tool == "smtchecker"
        assert r.status in ("passed", "failed", "timeout", "error")
        assert r.elapsed_seconds >= 0


# ---------------------------------------------------------------------------
# run_all_available
# ---------------------------------------------------------------------------


class TestRunAllAvailable:
    def test_skips_unavailable_tools(self, tmp_path):
        # When nothing is installed, result is empty
        with (
            patch.object(SpecRunner, "is_certora_available", return_value=False),
            patch.object(SpecRunner, "is_halmos_available", return_value=False),
            patch.object(SpecRunner, "is_solc_available", return_value=False),
        ):
            results = run_all_available("contract.sol", spec_path="rules.spec")
            assert results == {}


# ---------------------------------------------------------------------------
# Status disambiguation (no_tests vs. failed)
# ---------------------------------------------------------------------------


class TestHalmosStatusLogic:
    def test_zero_zero_is_no_tests_not_failed(self, tmp_path):
        """If halmos runs but finds no tests, that's 'no_tests' not 'failed'."""
        runner = SpecRunner()

        class MockProc:
            stdout = ""  # no [PASS]/[FAIL] markers
            stderr = ""
            returncode = 0

        with (
            patch.object(runner, "is_halmos_available", return_value=True),
            patch("miesc.formal.spec_runner.subprocess.run", return_value=MockProc()),
        ):
            r = runner.run_halmos(str(tmp_path))
            assert r.status == "no_tests"
            assert r.rules_total == 0


# =========================================================================== #
# Runner subprocess branches (availability + subprocess mocked) + parse extras.
# =========================================================================== #
import miesc.formal.spec_runner as sr  # noqa: E402


class _Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _runner(monkeypatch, tool, available=True):
    r = SpecRunner()
    monkeypatch.setattr(r, f"is_{tool}_available", lambda: available)
    return r


class TestRunCertora:
    def test_success(self, monkeypatch):
        r = _runner(monkeypatch, "certora")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: _Proc(stdout="Rule x: VERIFIED"))
        res = r.run_certora("C.sol", "C.spec")
        assert res.status == "passed" and res.rules_passed == 1

    def test_timeout(self, monkeypatch):
        r = _runner(monkeypatch, "certora")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(
                                sr.subprocess.TimeoutExpired("certoraRun", 600)))
        assert r.run_certora("C.sol", "C.spec").status == "timeout"

    def test_error(self, monkeypatch):
        r = _runner(monkeypatch, "certora")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        assert r.run_certora("C.sol", "C.spec").status == "error"

    def test_not_available(self, monkeypatch):
        r = _runner(monkeypatch, "certora", available=False)
        assert r.run_certora("C.sol", "C.spec").status == "error"


class TestRunHalmos:
    def test_passed_with_contract_arg(self, monkeypatch):
        r = _runner(monkeypatch, "halmos")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: _Proc(stdout="[PASS] check_inv"))
        res = r.run_halmos("/dir", test_contract="MyTest")
        assert res.status == "passed"

    def test_failed(self, monkeypatch):
        r = _runner(monkeypatch, "halmos")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: _Proc(stdout="[FAIL] check_bad"))
        assert r.run_halmos("/dir").status == "failed"

    def test_no_tests(self, monkeypatch):
        r = _runner(monkeypatch, "halmos")
        monkeypatch.setattr(sr.subprocess, "run", lambda *a, **k: _Proc(stdout="nothing"))
        assert r.run_halmos("/dir").status == "no_tests"

    def test_error(self, monkeypatch):
        r = _runner(monkeypatch, "halmos")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        assert r.run_halmos("/dir").status == "error"


class TestRunSmtchecker:
    def test_runs(self, monkeypatch):
        r = _runner(monkeypatch, "solc")  # smtchecker uses solc
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: _Proc(stderr="Warning: assertion violation"))
        res = r.run_smtchecker("C.sol")
        assert res.tool == "smtchecker"

    def test_error(self, monkeypatch):
        r = _runner(monkeypatch, "solc")
        monkeypatch.setattr(sr.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        assert r.run_smtchecker("C.sol").status == "error"


class TestParseExtras:
    def test_strip_ansi_and_halmos_counterexamples(self):
        out = "\x1b[32m[PASS]\x1b[0m a\n[FAIL] b\nCounterexample: x=1\n"
        passed, failed, ce = SpecRunner._parse_halmos_output(out)
        assert passed == 1 and failed == 1
        assert ce == ["x=1"]

    def test_parse_smtchecker_warnings(self):
        stderr = "Warning: overflow here\nWarning: assertion fails\n"
        w = SpecRunner._parse_smtchecker_warnings(stderr)
        assert len(w) >= 1


def test_run_all_available_runs_each_tool(monkeypatch):
    from miesc.formal.spec_runner import run_all_available, VerificationResult

    monkeypatch.setattr(SpecRunner, "availability_report",
                        lambda self: {"smtchecker": True, "certora": True, "halmos": True})
    monkeypatch.setattr(SpecRunner, "run_smtchecker",
                        lambda self, c, **k: VerificationResult(tool="smtchecker", spec_file=c, status="passed"))
    monkeypatch.setattr(SpecRunner, "run_certora",
                        lambda self, c, s, **k: VerificationResult(tool="certora", spec_file=s, status="passed"))
    monkeypatch.setattr(SpecRunner, "run_halmos",
                        lambda self, d, **k: VerificationResult(tool="halmos", spec_file=d, status="passed"))

    results = run_all_available("/proj/C.sol", spec_path="C.spec")
    assert set(results) == {"smtchecker", "certora", "halmos"}
