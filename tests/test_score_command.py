"""Tests for the ``miesc score`` CLI command.

The command turns a scan/audit's findings into a composite security score plus an
optional badge. These tests pin the JSON-input path (the must-have), the badge
emission, the CI ``--fail-under`` gate, and the ``--min-confidence`` pre-filter,
cross-checking each against ``compute_score`` on the same findings so the CLI can
never silently drift from the scoring core.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from miesc.cli.commands.score import score
from miesc.core.scoring import compute_score

# A results JSON with a mix of severities and confidences, in the per-tool shape
# the scan/export commands emit (a list of dicts each with a "findings" list).
_FINDINGS = [
    {"severity": "high", "confidence": 0.9},
    {"severity": "medium", "confidence": 0.8},
    {"severity": "medium", "confidence": 0.7},
    {"severity": "critical", "confidence": 0.2},  # low-confidence noise
]


def _write_report(tmp_path: Path) -> str:
    report = {
        "contract": "Foo.sol",
        "results": [
            {"tool": "slither", "findings": _FINDINGS[:2]},
            {"tool": "mythril", "findings": _FINDINGS[2:]},
        ],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return str(path)


def test_scores_a_results_json(tmp_path):
    expected = compute_score(_FINDINGS)
    runner = CliRunner()
    result = runner.invoke(score, [_write_report(tmp_path)])
    assert result.exit_code == 0, result.output
    assert f"{expected.score}/100" in result.output
    assert f"({expected.grade})" in result.output


def test_json_flag_emits_machine_readable(tmp_path):
    expected = compute_score(_FINDINGS)
    runner = CliRunner()
    result = runner.invoke(score, [_write_report(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["score"] == expected.score
    assert payload["grade"] == expected.grade
    assert payload["total_findings"] == len(_FINDINGS)


def test_badge_svg_written_to_file(tmp_path):
    out = tmp_path / "badge.svg"
    runner = CliRunner()
    result = runner.invoke(score, [_write_report(tmp_path), "--badge", "svg", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert content.startswith("<svg")
    assert content.rstrip().endswith("</svg>")


def test_badge_json_is_shields_endpoint(tmp_path):
    runner = CliRunner()
    result = runner.invoke(score, [_write_report(tmp_path), "--badge", "json"])
    assert result.exit_code == 0, result.output
    endpoint = json.loads(result.output)
    assert endpoint["schemaVersion"] == 1
    assert endpoint["label"] == "MIESC security"


def test_badge_markdown_is_self_contained(tmp_path):
    runner = CliRunner()
    result = runner.invoke(score, [_write_report(tmp_path), "--badge", "markdown"])
    assert result.exit_code == 0, result.output
    assert result.output.strip().startswith("![MIESC security](data:image/svg+xml;base64,")


def test_fail_under_above_score_exits_nonzero(tmp_path):
    expected = compute_score(_FINDINGS)
    runner = CliRunner()
    result = runner.invoke(
        score, [_write_report(tmp_path), "--fail-under", str(expected.score + 1)]
    )
    assert result.exit_code == 1
    assert "below" in result.output.lower()


def test_fail_under_below_score_exits_zero(tmp_path):
    expected = compute_score(_FINDINGS)
    runner = CliRunner()
    result = runner.invoke(
        score, [_write_report(tmp_path), "--fail-under", str(max(expected.score - 1, 0))]
    )
    assert result.exit_code == 0, result.output


def test_min_confidence_filters_low_confidence_findings(tmp_path):
    """Filtering low-confidence noise should raise the score (fewer penalties)."""
    report_path = _write_report(tmp_path)
    runner = CliRunner()

    baseline = runner.invoke(score, [report_path, "--json"])
    filtered = runner.invoke(score, [report_path, "--json", "--min-confidence", "0.5"])
    assert baseline.exit_code == 0, baseline.output
    assert filtered.exit_code == 0, filtered.output

    baseline_score = json.loads(baseline.output)["score"]
    filtered_score = json.loads(filtered.output)["score"]
    assert filtered_score > baseline_score

    # Cross-check: the filtered score matches compute_score over the kept findings
    # (everything with confidence >= 0.5).
    kept = [f for f in _FINDINGS if f["confidence"] >= 0.5]
    assert filtered_score == compute_score(kept).score
