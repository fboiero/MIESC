"""
Tests for medusa harness detection + 1.3.x output parsing (P1-3a).

Medusa (1.3.x) needs explicit target contracts and a property-test prefix, and
reports coverage as ``calls`` / ``branches hit`` / ``corpus`` (no percentage).
These tests pin the detection, the config writer, and the parsers against the
REAL output medusa 1.3.1 produces, with ANSI stripping.
"""

import json
from unittest.mock import MagicMock, patch

from miesc.adapters import _medusa_harness as mh
from miesc.adapters.medusa_adapter import MedusaAdapter
from miesc.core.tool_protocol import ToolStatus

# --- Real medusa 1.3.1 output captured on this host (do not synthesize) ------

MEDUSA_SUCCESS = (
    "fuzz: elapsed: 0s, calls: 0 (0/sec), seq/s: 0, branches hit: 10, corpus: 0, failures: 0/0\n"
    "fuzz: elapsed: 3s, calls: 140003 (46667/sec), seq/s: 466, branches hit: 81, "
    "corpus: 2, failures: 0/1399, gas/s: 1495194459\n"
    "[PASSED] Assertion Test: Harness.inc()\n"
    "[PASSED] Property Test: Harness.property_count_reasonable()\n"
    "Test summary: 3 test(s) passed, 0 test(s) failed\n"
)
# Same, with the ANSI colour codes medusa actually emits.
MEDUSA_SUCCESS_ANSI = (
    "\x1b[32m\x1b[0m\x1b[1mfuzz: \x1b[0melapsed: \x1b[1m3s\x1b[0m, calls: \x1b[1m140003\x1b[0m, "
    "branches hit: \x1b[1m81\x1b[0m, corpus: \x1b[1m2\x1b[0m\n"
    "\x1b[32m[PASSED] \x1b[0mProperty Test: Harness.property_count_reasonable()\n"
    "Test summary: \x1b[32m3\x1b[0m test(s) passed, \x1b[31m0\x1b[0m test(s) failed\n"
)
MEDUSA_FAILURE = (
    "fuzz: elapsed: 2s, calls: 50000, branches hit: 40, corpus: 5, failures: 1/200\n"
    "[FAILED] Property Test: Vault.property_solvent()\n"
    "Test summary: 2 test(s) passed, 1 test(s) failed\n"
)
# No-target abort (multi-contract project, no targetContracts).
MEDUSA_NO_TARGET = (
    "Setting up test chain\n"
    "error Failed to initialize the test chain\n"
    "specify target contract(s)\n"
)


class TestDetection:
    def test_detects_property_invariant_echidna_contracts(self, tmp_path):
        (tmp_path / "Harness.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Counter { uint256 public c; }\n"
            "contract Harness {\n"
            "  function property_ok() public pure returns (bool) { return true; }\n"
            "}\n"
            "contract InvH {\n"
            "  function invariant_balance() public pure returns (bool) { return true; }\n"
            "}\n"
        )
        got = mh.detect_harness_contracts(tmp_path)
        assert "Harness" in got and "InvH" in got
        assert "Counter" not in got  # no harness function

    def test_foundry_unit_tests_are_not_harnesses(self, tmp_path):
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "Thing.t.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract ThingTest {\n"
            "  function test_increment() public {}\n"
            "  function testFuzz_add(uint256 x) public {}\n"
            "}\n"
        )
        assert mh.detect_harness_contracts(tmp_path) == []

    def test_lib_dependencies_are_excluded(self, tmp_path):
        lib = tmp_path / "lib" / "dep"
        lib.mkdir(parents=True)
        (lib / "Dep.sol").write_text(
            "contract Dep { function property_x() public pure returns (bool) { return true; } }\n"
        )
        assert mh.detect_harness_contracts(tmp_path) == []

    def test_select_targets_prefers_harness(self, tmp_path):
        (tmp_path / "H.sol").write_text(
            "contract H { function property_ok() public pure returns (bool) { return true; } }\n"
        )
        targets, source = mh.select_targets(str(tmp_path))
        assert targets == ["H"] and source == "harness"

    def test_select_targets_falls_back_to_src(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "Token.sol").write_text("contract Token { function f() public {} }\n")
        targets, source = mh.select_targets(str(tmp_path))
        assert targets == ["Token"] and source == "first-party"

    def test_no_harness_reason(self, tmp_path):
        assert mh.no_harness_reason("contract C { function f() public {} }") is not None
        assert mh.no_harness_reason("function property_x() public {}") is None


class TestConfigWriter:
    def test_writes_valid_config(self, tmp_path):
        path = mh.write_medusa_config(
            tmp_path,
            targets=["Harness", "InvH"],
            compilation_target=".",
            test_limit=500,
            timeout=25,
            workers=2,
        )
        data = json.loads(path.read_text())
        assert data["fuzzing"]["targetContracts"] == ["Harness", "InvH"]
        prefixes = data["fuzzing"]["testing"]["propertyTesting"]["testPrefixes"]
        assert prefixes == ["property_", "invariant_", "echidna_"]
        assert data["compilation"]["platformConfig"]["target"] == "."


class TestCoverageParsing:
    def test_real_success_output(self):
        m = MedusaAdapter()._extract_coverage_metrics(MEDUSA_SUCCESS)
        # Final progress line wins, not the 0-call startup line.
        assert m["calls"] == 140003
        assert m["branches_hit"] == 81
        assert m["corpus_size"] == 2
        assert m["tests_passed"] == 3 and m["tests_failed"] == 0

    def test_ansi_is_stripped(self):
        m = MedusaAdapter()._extract_coverage_metrics(MEDUSA_SUCCESS_ANSI)
        assert m["calls"] == 140003 and m["tests_passed"] == 3

    def test_no_target_abort_reads_zero(self):
        m = MedusaAdapter()._extract_coverage_metrics(MEDUSA_NO_TARGET)
        assert m["calls"] == 0 and m["corpus_size"] == 0 and m["tests_passed"] == 0


class TestFindingsParsing:
    def test_failed_test_becomes_a_finding(self):
        findings = MedusaAdapter().normalize_findings(MEDUSA_FAILURE)
        assert len(findings) == 1
        assert findings[0]["type"] == "property_violation"

    def test_passed_tests_are_not_findings(self):
        assert MedusaAdapter().normalize_findings(MEDUSA_SUCCESS) == []


def _completed(stdout, returncode=0, stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestAdapterAnalyze:
    def _project(self, tmp_path):
        (tmp_path / "H.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract H { function property_ok() public pure returns (bool) { return true; } }\n"
        )
        return str(tmp_path)

    def test_successful_fuzz_is_exercised(self, tmp_path):
        adapter = MedusaAdapter()
        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch("subprocess.run", return_value=_completed(MEDUSA_SUCCESS)),
        ):
            r = adapter.analyze(self._project(tmp_path), test_limit=400, timeout=20)
        assert r["status"] == "success"
        assert r["metadata"]["campaign_exercised"] is True
        assert r["metadata"]["target_contracts"] == ["H"]
        assert r["metadata"]["target_source"] == "harness"

    def test_no_harness_project_is_inconclusive_with_reason(self, tmp_path):
        # A project with first-party src but no harness: medusa aborts on target
        # selection here (mocked) -> not exercised -> inconclusive, reason named.
        src = tmp_path / "src"
        src.mkdir()
        (src / "C.sol").write_text("contract C { function f() public {} }\n")
        adapter = MedusaAdapter()
        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch("subprocess.run", return_value=_completed(MEDUSA_NO_TARGET, returncode=1)),
        ):
            r = adapter.analyze(str(tmp_path), test_limit=400, timeout=20)
        assert r["status"] == "inconclusive"
        assert "harness" in (r.get("warning") or "").lower()
        assert r["metadata"]["target_source"] == "first-party"

    def test_tool_crash_is_error_not_inconclusive(self, tmp_path):
        # A crytic-compile crash (Python traceback) is a real failure the user
        # must see — not a quiet "no coverage" inconclusive.
        crash = (
            "Traceback (most recent call last):\n"
            "  File crytic_compile.py, line 749, in compile_all\n"
            "ValueError: Harness.sol is not a file or directory.\n"
        )
        adapter = MedusaAdapter()
        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch("subprocess.run", return_value=_completed(crash, returncode=1)),
        ):
            r = adapter.analyze(self._project(tmp_path), test_limit=400, timeout=20)
        assert r["status"] == "error"
        assert "ValueError" in (r.get("error") or "")
