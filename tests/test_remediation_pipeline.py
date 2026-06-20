from __future__ import annotations

import json

from src.security.remediation_pipeline import (
    apply_patch_candidates,
    classify_compile_failure,
    count_high_findings,
    remediate_contract,
    select_solc,
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
