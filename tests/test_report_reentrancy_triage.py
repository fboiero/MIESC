"""
The reentrancy REVIEW/GUARDED/NOISE triage, surfaced in the generated audit report.

The scan annotates reentrancy findings with ``reentrancy_triage`` (tier / guard);
`miesc report` carries a flattened ``triage_tier`` / ``triage_guard`` through the
finding whitelist and the detailed-finding property table prints a conditional row.
These tests render real templates and assert the row appears only on reentrancy
findings, in the template's language.

Author: Fernando Boiero
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from miesc.cli.commands.report import report

_RESULTS = {
    "contract": "V.sol",
    "findings": [
        {
            "id": "F-001",
            "type": "reentrancy-no-eth",
            "severity": "Medium",
            "title": "Reentrancy in V.redeem",
            "description": "redeem reenters before NAV is updated",
            "location": "V.sol#10",
            "tool": "slither",
            "reentrancy_triage": {
                "tier": "review",
                "guard": "custom-mutex-candidate",
                "signals": ["value-function", "non-access-external-call"],
                "reason": "value-moving op ...",
            },
        },
        {
            "id": "F-002",
            "type": "tx-origin",
            "severity": "Low",
            "title": "tx.origin used for authorization",
            "description": "auth via tx.origin",
            "location": "V.sol#20",
            "tool": "slither",
        },
    ],
}


def _render(template: str, tmp_path: Path) -> str:
    src = tmp_path / "results.json"
    src.write_text(json.dumps(_RESULTS), encoding="utf-8")
    out = tmp_path / "report.md"
    result = CliRunner().invoke(
        report, [str(src), "-t", template, "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    return out.read_text(encoding="utf-8")


def test_english_table_templates_show_tier_and_guard(tmp_path):
    for template in ("profesional", "premium"):
        text = _render(template, tmp_path)
        assert (
            "| **Reentrancy Triage** | REVIEW (guard: custom-mutex-candidate) |" in text
        ), template


def test_default_and_professional_templates_show_tier(tmp_path):
    # 'simple' is the DEFAULT template (bullet list); 'professional' is a table.
    # Both — the formats a user gets without picking a detailed Spanish template —
    # must surface the tier.
    simple = _render("simple", tmp_path)
    assert "- **Reentrancy Triage:** REVIEW (guard: custom-mutex-candidate)" in simple
    professional = _render("professional", tmp_path)
    assert "| Reentrancy Triage | REVIEW (guard: custom-mutex-candidate) |" in professional


def test_spanish_template_shows_localized_row(tmp_path):
    text = _render("profesional-es", tmp_path)
    assert "| **Triaje de reentrancy** | REVIEW (guardia: custom-mutex-candidate) |" in text


def test_row_is_conditional_only_reentrancy_findings_get_it(tmp_path):
    # Exactly one finding carries a triage tier; the tx-origin finding must not
    # grow an (empty) triage row.
    text = _render("profesional", tmp_path)
    assert text.count("Reentrancy Triage") == 1


def test_guard_unknown_is_not_appended(tmp_path):
    # A reentrancy finding whose guard is "unknown" shows the tier but no guard note.
    results = {
        "contract": "V.sol",
        "findings": [
            {
                "id": "F-001",
                "type": "reentrancy-no-eth",
                "severity": "Medium",
                "title": "Reentrancy in V.redeem",
                "description": "x",
                "location": "V.sol#10",
                "tool": "slither",
                "reentrancy_triage": {
                    "tier": "review",
                    "guard": "unknown",
                    "signals": [],
                    "reason": "x",
                },
            }
        ],
    }
    src = tmp_path / "r.json"
    src.write_text(json.dumps(results), encoding="utf-8")
    out = tmp_path / "r.md"
    res = CliRunner().invoke(
        report, [str(src), "-t", "profesional", "-f", "markdown", "-o", str(out)]
    )
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "| **Reentrancy Triage** | REVIEW |" in text
    assert "guard:" not in text
