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
