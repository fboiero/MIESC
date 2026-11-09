"""
Tests for the reentrancy REVIEW/NOISE triage wired into ``miesc scan``.

The triage partition (miesc/ml/reentrancy_triage.py) annotates every reentrancy-*
finding in place with its tier / signals / reason. This test drives the real scan
finalize path (``_display_and_save``) with a pre-built result set and asserts the
annotation reaches the written JSON report — the deterministic wiring boundary,
exercised without running any external analyzer.

(A real ``miesc scan <contract> -o out.json`` run also carries the annotation into
the JSON end-to-end; under pytest the Rich/CLI capture layer makes the full
CliRunner path's written-report assertion flaky, so we call the finalize step
directly here, as the sibling access-control wiring test does for its boundary.
Recall-safety and the NOISE label are covered by the annotate_results unit test.)

Author: Fernando Boiero
"""

from __future__ import annotations

import json

from miesc.cli.commands.scan import _display_and_save

_SOL = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract V { function redeem(uint256 s) external {} }\n"
)

# A value-moving reentrancy whose description triages to REVIEW.
_REVIEW_FINDING = {
    "tool": "slither",
    "type": "reentrancy-no-eth",
    "severity": "Medium",
    "title": "Reentrancy in V.redeem",
    "description": (
        "Reentrancy in V.redeem(uint256) (src/V.sol#1-9): External calls: "
        "- IK(k()).settle(s) (src/V.sol#5) "
        "State variables written after the call(s): "
        "- totalShares = 0 (src/V.sol#7) "
        "V.totalShares can be used in cross function reentrancies:"
    ),
}


def _triage_annotations(report: dict) -> dict:
    """Map each annotated finding's description -> its reentrancy_triage object.

    Keyed by description so the same finding appearing in both the top-level
    ``findings`` list and the per-tool ``results`` block counts once.
    """
    out: dict[str, dict] = {}

    def walk(node):
        if isinstance(node, dict):
            if "reentrancy_triage" in node:
                out[node.get("description", "")] = node["reentrancy_triage"]
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(report)
    return out


def test_finalize_writes_reentrancy_triage_into_json(tmp_path):
    contract = tmp_path / "V.sol"
    contract.write_text(_SOL, encoding="utf-8")
    out = tmp_path / "report.json"

    all_results = [{"tool": "slither", "status": "success", "findings": [dict(_REVIEW_FINDING)]}]

    try:
        _display_and_save(
            all_results,
            contract=str(contract),
            output=str(out),
            quiet=True,
            verbose=False,
            ci=False,
        )
    except SystemExit:
        pass  # finalize may raise on CI exit codes; the JSON is written regardless.

    assert out.exists(), "finalize did not write the JSON report"
    report = json.loads(out.read_text(encoding="utf-8"))

    annotations = _triage_annotations(report)
    assert annotations, "reentrancy_triage annotation never reached the written JSON"
    triage = annotations[_REVIEW_FINDING["description"]]
    assert triage["tier"] == "review"
    assert "value-function" in triage["signals"]
    assert triage["reason"]
