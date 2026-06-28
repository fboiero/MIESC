from __future__ import annotations

import json

from src.security.remediation_pipeline import (
    apply_patch_candidates,
    classify_compile_failure,
    count_high_findings,
    diff_high_finding_types,
    remediate_contract,
    select_solc,
    summarize_high_finding_types,
)

SIMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""


def test_classify_compile_failure_matches_paper2_taxonomy():
    assert (
        classify_compile_failure("Source file requires different compiler version")
        == "solidity_version_mismatch"
    )
    assert classify_compile_failure('Source "@openzeppelin/X.sol" not found') == (
        "missing_import_or_dependency"
    )
    assert classify_compile_failure("Undeclared identifier: owner") == "undefined_symbol"
    assert classify_compile_failure("ParserError: Expected ';'") == "parser_or_syntax_error"
    assert classify_compile_failure("TypeError: invalid conversion") == "type_error"
    assert classify_compile_failure("compile timeout") == "compile_timeout"
    assert classify_compile_failure("some unknown compiler failure") == "other_compile_error"


def test_select_solc_uses_exact_version_for_locked_pragma(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    solc_path = artifacts / "solc-0.4.25" / "solc-0.4.25"
    solc_path.parent.mkdir(parents=True)
    solc_path.write_text("")
    contract = tmp_path / "Exact.sol"
    contract.write_text("pragma solidity 0.4.25;\ncontract C {}\n")

    monkeypatch.setattr("src.security.remediation_pipeline.SOLC_DIR", artifacts)
    monkeypatch.setattr("shutil.which", lambda _name: None)

    assert select_solc(contract) == str(solc_path)


def test_select_solc_uses_highest_compatible_patch_for_caret_pragma(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    old_solc = artifacts / "solc-0.4.18" / "solc-0.4.18"
    new_solc = artifacts / "solc-0.4.26" / "solc-0.4.26"
    old_solc.parent.mkdir(parents=True)
    new_solc.parent.mkdir(parents=True)
    old_solc.write_text("")
    new_solc.write_text("")
    contract = tmp_path / "Caret.sol"
    contract.write_text("pragma solidity ^0.4.0;\ncontract C {}\n")

    monkeypatch.setattr("src.security.remediation_pipeline.SOLC_DIR", artifacts)
    monkeypatch.setattr("shutil.which", lambda _name: None)

    assert select_solc(contract) == str(new_solc)


def test_count_high_findings_counts_critical_and_high_only():
    result = {
        "findings": [
            {"severity": "critical"},
            {"severity": "HIGH"},
            {"severity": "medium"},
            {"severity": "info"},
        ]
    }
    assert count_high_findings(result) == 2


def test_summarize_high_finding_types_counts_only_high_and_critical():
    result = {
        "findings": [
            {"severity": "critical", "type": "reentrancy"},
            {"severity": "HIGH", "title": "unchecked-call"},
            {"severity": "HIGH", "type": "reentrancy"},
            {"severity": "medium", "type": "unchecked-call"},
            {"severity": "info", "type": "solc-version"},
        ]
    }

    summary = summarize_high_finding_types(result)

    assert summary == {"reentrancy": 2, "unchecked-call": 1}
    assert diff_high_finding_types(
        {"reentrancy": 1, "unchecked-call": 1},
        summary,
    ) == {"reentrancy": 1}


def test_apply_patch_candidates_uses_existing_fix_logic():
    findings = [
        {
            "type": "reentrancy",
            "function": "withdraw",
            "fix_code": "add nonReentrant",
        }
    ]
    patched, applied, skipped = apply_patch_candidates(SIMPLE_CONTRACT, findings)
    assert applied == 1
    assert skipped == 0
    assert "nonReentrant" in patched
    assert "MiescReentrancyGuard" in patched


def test_remediate_contract_emits_evidence_bundle_without_optional_checks(tmp_path):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    output = tmp_path / "Victim.fixed.sol"
    results = {
        "contract": str(contract),
        "findings": [
            {
                "type": "reentrancy",
                "function": "withdraw",
                "severity": "High",
                "fix_code": "add nonReentrant",
            }
        ],
    }

    evidence = remediate_contract(
        contract_path=contract,
        results=results,
        output_path=output,
    )

    assert evidence.status == "patch_applied"
    assert evidence.fixes_applied == 1
    assert evidence.fixable_findings == 1
    assert evidence.compile.checked is False
    assert evidence.rescan.checked is False
    assert output.exists()
    assert evidence.original_sha256 != evidence.patched_sha256

    payload = evidence.to_dict()
    json.dumps(payload)
    assert payload["patched_path"] == str(output)


def test_remediate_contract_handles_no_fixable_findings(tmp_path):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)

    evidence = remediate_contract(
        contract_path=contract,
        results={"findings": [{"type": "reentrancy"}]},
        output_path=tmp_path / "unused.sol",
    )

    assert evidence.status == "no_fixable_findings"
    assert evidence.patched_path is None
    assert evidence.fixable_findings == 0


def test_remediate_contract_records_rescan_deltas_and_high_type_diff(tmp_path, monkeypatch):
    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    output = tmp_path / "Victim.fixed.sol"
    results = {
        "contract": str(contract),
        "findings": [
            {
                "type": "unchecked-call",
                "function": "withdraw",
                "severity": "High",
                "fix_code": "check call return",
            },
            {
                "type": "naming-convention",
                "severity": "Info",
            },
        ],
    }

    def fake_run_scan(contract_path, output_path):
        return {
            "findings": [
                {"type": "unchecked-call", "severity": "High"},
                {"type": "arbitrary-send-eth", "severity": "High"},
                {"type": "naming-convention", "severity": "Info"},
                {"type": "solc-version", "severity": "Info"},
            ]
        }

    monkeypatch.setattr("src.security.remediation_pipeline.run_scan", fake_run_scan)

    evidence = remediate_contract(
        contract_path=contract,
        results=results,
        output_path=output,
        rescan_check=True,
        no_regression_bound=1,
    )

    assert evidence.rescan.high_before == 1
    assert evidence.rescan.high_after == 2
    assert evidence.rescan.total_before == 2
    assert evidence.rescan.total_after == 4
    assert evidence.rescan.high_delta == 1
    assert evidence.rescan.total_delta == 2
    assert evidence.rescan.high_types_before == {"unchecked-call": 1}
    assert evidence.rescan.high_types_after == {
        "arbitrary-send-eth": 1,
        "unchecked-call": 1,
    }
    assert evidence.rescan.new_high_types == {"arbitrary-send-eth": 1}
    assert evidence.rescan.eliminated is False
    assert evidence.rescan.no_regression is False


# =========================================================================== #
# Extra coverage: classify branches, select_solc fallback, mocked subprocess.
# =========================================================================== #
import src.security.remediation_pipeline as rp  # noqa: E402
from src.security.remediation_pipeline import (  # noqa: E402
    CompileEvidence,
    RescanEvidence,
    compile_contract,
    count_high_findings,
    diff_high_finding_types,
    run_scan,
    select_solc,
    summarize_high_finding_types,
)


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_classify_compile_failure_extra_branches():
    assert rp.classify_compile_failure("requires different compiler version") == "solidity_version_mismatch"
    assert rp.classify_compile_failure("Error: File not found foo.sol") == "missing_import_or_dependency"
    assert rp.classify_compile_failure("X not found or not visible") == "undefined_symbol"
    assert rp.classify_compile_failure("TypeError: bad") == "type_error"
    assert rp.classify_compile_failure("operation timeout") == "compile_timeout"
    assert rp.classify_compile_failure("solc: command not found") == "solc_unavailable"
    assert rp.classify_compile_failure("totally novel error") == "other_compile_error"


def test_select_solc_which_fallback_and_default(tmp_path, monkeypatch):
    sol = tmp_path / "C.sol"
    # exact ancient version with no installed solc dir -> reaches the fallback paths
    sol.write_text("pragma solidity 0.3.1;\ncontract C {}")
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/solc")
    assert select_solc(sol) == "/usr/bin/solc"
    # which returns None -> hardcoded default
    monkeypatch.setattr(rp.shutil, "which", lambda n: None)
    assert "solc-0.4.26" in select_solc(sol)


def test_compile_contract_success_timeout_and_error(tmp_path, monkeypatch):
    sol = tmp_path / "C.sol"
    sol.write_text("pragma solidity ^0.8.20;\ncontract C {}")
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/solc")

    monkeypatch.setattr(rp.subprocess, "run",
                        lambda *a, **k: _Proc(returncode=0, stdout="Binary: 60..."))
    ev = compile_contract(sol)
    assert ev.compiles is True

    def _timeout(*a, **k):
        raise rp.subprocess.TimeoutExpired(cmd="solc", timeout=15)
    monkeypatch.setattr(rp.subprocess, "run", _timeout)
    ev = compile_contract(sol)
    assert ev.failure_class == "compile_timeout"

    def _boom(*a, **k):
        raise OSError("solc missing")
    monkeypatch.setattr(rp.subprocess, "run", _boom)
    ev = compile_contract(sol)
    assert ev.compiles is False


def test_count_and_summarize_empty():
    assert count_high_findings(None) == 0
    assert summarize_high_finding_types(None) == {}
    assert diff_high_finding_types({"reentrancy": 1}, {"reentrancy": 3}) == {"reentrancy": 2}


def test_run_scan_success_and_failure(tmp_path, monkeypatch):
    out = tmp_path / "scan.json"

    def _ok(*a, **k):
        out.write_text('{"findings": []}')
        return _Proc(returncode=0)
    monkeypatch.setattr(rp.subprocess, "run", _ok)
    assert run_scan(tmp_path / "C.sol", out) == {"findings": []}

    def _boom(*a, **k):
        raise OSError("scan failed")
    monkeypatch.setattr(rp.subprocess, "run", _boom)
    assert run_scan(tmp_path / "C.sol", tmp_path / "x.json") is None


def test_evidence_to_dict():
    ce = CompileEvidence(checked=True, compiles=True, solc="solc")
    assert ce.to_dict()["compiles"] is True
    re_ = RescanEvidence(checked=True, high_before=2, high_after=0)
    assert re_.to_dict()["high_before"] == 2


def test_apply_patch_candidates_counts_skips():
    from src.security.remediation_pipeline import apply_patch_candidates
    # an unknown finding type yields no change -> skipped counter increments
    src = "contract C { function f() public {} }"
    patched, applied, skipped = apply_patch_candidates(src, [{"type": "no-such-fix"}])
    assert patched == src
    assert applied == 0 and skipped == 1


def test_run_scan_returns_none_when_no_output(tmp_path, monkeypatch):
    # subprocess succeeds but writes no output file -> final return None
    monkeypatch.setattr(rp.subprocess, "run", lambda *a, **k: _Proc(returncode=0))
    assert run_scan(tmp_path / "C.sol", tmp_path / "absent.json") is None


def test_remediate_contract_compile_checked_status(tmp_path, monkeypatch):
    from src.security.remediation_pipeline import CompileEvidence, remediate_contract

    contract = tmp_path / "Victim.sol"
    contract.write_text(SIMPLE_CONTRACT)
    # compile_check=True, rescan_check=False -> status becomes "compile_checked"
    monkeypatch.setattr("src.security.remediation_pipeline.compile_contract",
                        lambda *a, **k: CompileEvidence(checked=True, compiles=True, solc="solc"))
    evidence = remediate_contract(
        contract_path=contract,
        results={"contract": str(contract), "findings": [
            {"type": "reentrancy", "function": "withdraw", "severity": "High",
             "fix_code": "add nonReentrant"}]},
        output_path=tmp_path / "Victim.fixed.sol",
        compile_check=True,
        rescan_check=False,
    )
    assert evidence.status == "compile_checked"
    assert evidence.compile.checked is True
