"""Tests for the Paper 2 fix_eval benchmark runner controls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import benchmarks.fix_eval as fix_eval


class FakeCompile:
    def to_dict(self):
        return {"compiles": True, "failure_class": None}


class FakeEvidence:
    fixes_applied = 1
    fixes_skipped = 0
    compile = FakeCompile()
    rescan = SimpleNamespace(
        checked=False,
        total_before=None,
        high_after=None,
        total_after=None,
        eliminated=None,
        no_regression=None,
    )

    def to_dict(self):
        return {
            "fixes_applied": self.fixes_applied,
            "fixes_skipped": self.fixes_skipped,
            "compile": self.compile.to_dict(),
        }


class FakeRescanEvidence(FakeEvidence):
    rescan = SimpleNamespace(
        checked=True,
        total_before=2,
        high_after=0,
        total_after=0,
        eliminated=True,
        no_regression=True,
    )


class FakeFailedEvidence(FakeEvidence):
    fixes_applied = 0
    fixes_skipped = 2


def test_fix_eval_limit_progress_and_details_metadata(monkeypatch, tmp_path: Path, capsys):
    dataset = tmp_path / "dataset"
    category = dataset / "unchecked_low_level_calls"
    category.mkdir(parents=True)
    for idx in range(3):
        (category / f"C{idx}.sol").write_text("pragma solidity 0.4.25; contract C {}\n")

    scanned = []
    remediated = []

    def fake_run_scan(sol_path, output_path, timeout):
        scanned.append((Path(sol_path).name, timeout))
        return {
            "findings": [
                {
                    "severity": "HIGH",
                    "type": "unchecked-call",
                    "fix_code": "check return value",
                }
            ]
        }

    def fake_remediate_contract(**kwargs):
        remediated.append(Path(kwargs["contract_path"]).name)
        return FakeEvidence()

    details = tmp_path / "details.json"
    monkeypatch.setattr(fix_eval, "DATASET", dataset)
    monkeypatch.setattr(fix_eval, "run_scan", fake_run_scan)
    monkeypatch.setattr(fix_eval, "remediate_contract", fake_remediate_contract)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fix_eval.py",
            "--category",
            "unchecked_low_level_calls",
            "--limit",
            "2",
            "--scan-timeout",
            "7",
            "--skip-rescan",
            "--details-output",
            str(details),
        ],
    )

    fix_eval.main()

    assert scanned == [("C0.sol", 7), ("C1.sol", 7)]
    assert remediated == ["C0.sol", "C1.sol"]
    output = capsys.readouterr().out
    assert "Limit: 2 contract(s) per category" in output
    assert "[1/2] scan C0.sol" in output
    assert "[2/2] scan C1.sol" in output
    assert "C2.sol" not in output

    payload = json.loads(details.read_text())
    assert payload["limit"] == 2
    assert payload["scan_timeout"] == 7
    assert payload["skip_rescan"] is True
    assert payload["totals"]["contracts"] == 2
    assert payload["totals"]["fix_applied"] == 2
    assert [contract["status"] for contract in payload["contracts"]] == ["applied", "applied"]


def test_fix_eval_details_include_skipped_contract_statuses(monkeypatch, tmp_path: Path):
    dataset = tmp_path / "dataset"
    category = dataset / "denial_of_service"
    category.mkdir(parents=True)
    for name in ("empty.sol", "low.sol", "failed.sol"):
        (category / name).write_text("pragma solidity 0.4.25; contract C {}\n")

    def fake_run_scan(sol_path, output_path, timeout):
        name = Path(sol_path).name
        if name == "empty.sol":
            return {"findings": []}
        if name == "low.sol":
            return {"findings": [{"severity": "LOW", "type": "dos"}]}
        return {"findings": [{"severity": "HIGH", "type": "dos", "fix_code": "fix"}]}

    def fake_remediate_contract(**kwargs):
        return FakeFailedEvidence()

    details = tmp_path / "details.json"
    monkeypatch.setattr(fix_eval, "DATASET", dataset)
    monkeypatch.setattr(fix_eval, "run_scan", fake_run_scan)
    monkeypatch.setattr(fix_eval, "remediate_contract", fake_remediate_contract)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fix_eval.py",
            "--category",
            "denial_of_service",
            "--limit",
            "3",
            "--skip-rescan",
            "--details-output",
            str(details),
            "--no-progress",
        ],
    )

    fix_eval.main()

    payload = json.loads(details.read_text())
    assert payload["totals"]["scan_empty"] == 1
    assert payload["totals"]["no_high"] == 1
    assert payload["totals"]["fix_failed"] == 1
    assert [contract["status"] for contract in payload["contracts"]] == [
        "scan_empty",
        "fix_failed",
        "no_high",
    ]
    assert payload["contracts"][1]["evidence"]["fixes_skipped"] == 2


def test_fix_eval_results_output_avoids_canonical_default(monkeypatch, tmp_path: Path):
    dataset = tmp_path / "dataset"
    category = dataset / "reentrancy"
    category.mkdir(parents=True)
    (category / "C.sol").write_text("pragma solidity 0.4.25; contract C {}\n")

    canonical = tmp_path / "benchmarks" / "results" / "fix_eval_results.json"
    alternate = tmp_path / "benchmarks" / "results" / "fix_eval_dry_codex.json"

    def fake_run_scan(sol_path, output_path, timeout):
        return {
            "findings": [
                {
                    "severity": "HIGH",
                    "type": "reentrancy",
                    "fix_code": "add nonReentrant",
                }
            ]
        }

    def fake_remediate_contract(**kwargs):
        assert kwargs["rescan_check"] is True
        return FakeRescanEvidence()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(fix_eval, "DATASET", dataset)
    monkeypatch.setattr(fix_eval, "run_scan", fake_run_scan)
    monkeypatch.setattr(fix_eval, "remediate_contract", fake_remediate_contract)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fix_eval.py",
            "--category",
            "reentrancy",
            "--results-output",
            str(alternate),
            "--no-progress",
        ],
    )

    fix_eval.main()

    assert not canonical.exists()
    payload = json.loads(alternate.read_text())
    assert payload["totals"]["fix_applied"] == 1
    assert payload["totals"]["vuln_eliminated"] == 1
    assert payload["by_category"]["reentrancy"]["no_regression"] == 1


def test_fix_eval_skip_rescan_can_write_noncanonical_results(monkeypatch, tmp_path: Path):
    dataset = tmp_path / "dataset"
    category = dataset / "access_control"
    category.mkdir(parents=True)
    (category / "C.sol").write_text("pragma solidity 0.4.25; contract C {}\n")

    alternate = tmp_path / "fix_eval_skip_rescan_codex.json"

    def fake_run_scan(sol_path, output_path, timeout):
        return {
            "findings": [
                {
                    "severity": "HIGH",
                    "type": "access-control",
                    "fix_code": "add onlyOwner",
                }
            ]
        }

    def fake_remediate_contract(**kwargs):
        assert kwargs["rescan_check"] is False
        return FakeEvidence()

    monkeypatch.setattr(fix_eval, "DATASET", dataset)
    monkeypatch.setattr(fix_eval, "run_scan", fake_run_scan)
    monkeypatch.setattr(fix_eval, "remediate_contract", fake_remediate_contract)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fix_eval.py",
            "--category",
            "access_control",
            "--skip-rescan",
            "--results-output",
            str(alternate),
            "--no-progress",
        ],
    )

    fix_eval.main()

    payload = json.loads(alternate.read_text())
    assert payload["totals"]["fix_applied"] == 1
    assert payload["totals"]["fix_compiles"] == 1
    assert payload["totals"]["vuln_eliminated"] == 0


def test_fix_eval_external_validator_runs_on_compiling_patches(
    monkeypatch, tmp_path: Path
):
    dataset = tmp_path / "dataset"
    category = dataset / "reentrancy"
    category.mkdir(parents=True)
    (category / "C.sol").write_text("pragma solidity 0.4.25; contract C {}\n")

    details = tmp_path / "details.json"
    validations = []

    def fake_run_scan(sol_path, output_path, timeout):
        return {
            "findings": [
                {
                    "severity": "HIGH",
                    "type": "reentrancy",
                    "fix_code": "add nonReentrant",
                }
            ]
        }

    def fake_remediate_contract(**kwargs):
        return FakeEvidence()

    def fake_external_validation(sol_path, tool, timeout):
        validations.append((Path(sol_path).name, tool, timeout))
        return {
            "checked": True,
            "tool": tool,
            "status": "clean_high",
            "returncode": 0,
            "findings_total": 0,
            "high_findings": 0,
            "stdout": "{}",
            "stderr": "",
        }

    monkeypatch.setattr(fix_eval, "DATASET", dataset)
    monkeypatch.setattr(fix_eval, "run_scan", fake_run_scan)
    monkeypatch.setattr(fix_eval, "remediate_contract", fake_remediate_contract)
    monkeypatch.setattr(fix_eval, "run_external_validation", fake_external_validation)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fix_eval.py",
            "--category",
            "reentrancy",
            "--skip-rescan",
            "--external-validator",
            "slither",
            "--external-timeout",
            "9",
            "--details-output",
            str(details),
            "--no-progress",
        ],
    )

    fix_eval.main()

    assert validations == [("fixed.sol", "slither", 9)]
    payload = json.loads(details.read_text())
    assert payload["external_validator"] == "slither"
    assert payload["external_timeout"] == 9
    assert payload["totals"]["external_checked"] == 1
    assert payload["totals"]["external_clean_high"] == 1
    assert payload["contracts"][0]["external_validation"]["status"] == "clean_high"


def test_external_validation_parses_slither_high_findings(monkeypatch, tmp_path: Path):
    contract = tmp_path / "C.fixed.sol"
    contract.write_text("pragma solidity 0.8.20; contract C {}\n")

    completed = SimpleNamespace(returncode=255, stdout="", stderr="")

    def fake_run(cmd, **kwargs):
        Path(cmd[-1]).write_text(
            json.dumps(
                {
                    "results": {
                        "detectors": [
                            {"impact": "High", "check": "reentrancy-eth"},
                            {"impact": "Low", "check": "naming-convention"},
                        ]
                    }
                }
            )
        )
        return completed

    monkeypatch.setattr(fix_eval.subprocess, "run", fake_run)

    evidence = fix_eval.run_external_validation(contract, tool="slither", timeout=5)

    assert evidence["checked"] is True
    assert evidence["status"] == "findings"
    assert evidence["findings_total"] == 2
    assert evidence["high_findings"] == 1
    assert evidence["high_checks"] == ["reentrancy-eth"]
    assert evidence["detector_summary"] == {
        "high:reentrancy-eth": 1,
        "low:naming-convention": 1,
    }
