"""
Tests for GitHub Actions inline PR annotations (T1.2).

Covers:
- severity -> annotation level mapping (error / warning / notice)
- annotation format: file / line / title / message layout
- GitHub workflow-command escaping (escapeData for messages,
  escapeProperty for property values: %, CR, LF, ':' and ',')
- the N-cap: most-severe-first ordering, suppressed-count log + notice line
  (no silent truncation)
- baseline composition: with a baseline, only NEW findings are annotated
- flat vs nested-location finding shapes
- CLI wiring: `miesc export -f github` and `miesc scan --annotate github`

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from click.testing import CliRunner

from miesc.core.baseline import generate_baseline
from miesc.core.exporters import Finding, GitHubAnnotationsExporter, ReportExporter

# =============================================================================
# Helpers
# =============================================================================


def _finding(
    rule="reentrancy",
    severity="high",
    file="contracts/Bank.sol",
    line=15,
    message="Reentrancy in withdraw()",
):
    """A dict-shaped finding with a nested location (tool-native shape)."""
    return {
        "type": rule,
        "severity": severity,
        "message": message,
        "location": {"file": file, "line": line},
        "tool": "slither",
    }


def _parse(line: str):
    """Split a '::level props::message' command into (level, props, message)."""
    assert line.startswith("::")
    head, _, message = line[2:].partition("::")
    level, _, prop_str = head.partition(" ")
    props = {}
    if prop_str:
        for pair in prop_str.split(","):
            key, _, val = pair.partition("=")
            props[key] = val
    return level, props, message


# =============================================================================
# Severity -> level mapping
# =============================================================================


class TestSeverityMapping:
    def test_critical_and_high_map_to_error(self):
        exp = GitHubAnnotationsExporter()
        for sev in ("critical", "high", "Critical", "HIGH"):
            level, _, _ = _parse(exp.to_github_annotations([_finding(severity=sev)])[0])
            assert level == "error", sev

    def test_medium_and_low_map_to_warning(self):
        exp = GitHubAnnotationsExporter()
        for sev in ("medium", "low", "Medium", "LOW"):
            level, _, _ = _parse(exp.to_github_annotations([_finding(severity=sev)])[0])
            assert level == "warning", sev

    def test_info_maps_to_notice(self):
        exp = GitHubAnnotationsExporter()
        level, _, _ = _parse(exp.to_github_annotations([_finding(severity="info")])[0])
        assert level == "notice"

    def test_unknown_severity_defaults_to_warning(self):
        exp = GitHubAnnotationsExporter()
        level, _, _ = _parse(exp.to_github_annotations([_finding(severity="weird")])[0])
        assert level == "warning"


# =============================================================================
# Annotation format
# =============================================================================


class TestFormat:
    def test_contains_file_line_title_message(self):
        exp = GitHubAnnotationsExporter()
        line = exp.to_github_annotations(
            [_finding(rule="reentrancy", file="a/B.sol", line=42, message="boom")]
        )[0]
        level, props, message = _parse(line)
        assert level == "error"
        assert props["file"] == "a/B.sol"
        assert props["line"] == "42"
        assert props["title"] == "reentrancy"
        assert message == "boom"

    def test_supports_dataclass_finding(self):
        exp = GitHubAnnotationsExporter()
        f = Finding(
            id="F1",
            type="unchecked_call",
            severity="medium",
            title="t",
            description="unchecked external call",
            file_path="contracts/T.sol",
            line_start=7,
        )
        level, props, message = _parse(exp.to_github_annotations([f])[0])
        assert level == "warning"
        assert props["file"] == "contracts/T.sol"
        assert props["line"] == "7"
        assert props["title"] == "unchecked_call"
        assert message == "unchecked external call"

    def test_flat_location_shape(self):
        exp = GitHubAnnotationsExporter()
        flat = {
            "type": "tx_origin",
            "severity": "high",
            "message": "tx.origin auth",
            "file": "contracts/Flat.sol",
            "line_start": 99,
        }
        _, props, _ = _parse(exp.to_github_annotations([flat])[0])
        assert props["file"] == "contracts/Flat.sol"
        assert props["line"] == "99"

    def test_missing_line_omits_line_property(self):
        exp = GitHubAnnotationsExporter()
        f = {"type": "x", "severity": "low", "message": "m", "location": {"file": "z.sol"}}
        _, props, _ = _parse(exp.to_github_annotations([f])[0])
        assert "line" not in props
        assert props["file"] == "z.sol"

    def test_empty_findings_returns_empty(self):
        assert GitHubAnnotationsExporter().to_github_annotations([]) == []


# =============================================================================
# Escaping (GitHub @actions/core escapeData / escapeProperty)
# =============================================================================


class TestEscaping:
    def test_message_escapes_data_only(self):
        exp = GitHubAnnotationsExporter()
        # escapeData: % \r \n — but NOT ':' or ',' in the message body.
        f = _finding(message="100% off,\nline: two\r")
        _, _, message = _parse(exp.to_github_annotations([f])[0])
        assert message == "100%25 off,%0Aline: two%0D"
        assert "\n" not in message and "\r" not in message

    def test_property_escapes_comma_and_colon(self):
        exp = GitHubAnnotationsExporter()
        # escapeProperty additionally escapes ':' -> %3A and ',' -> %2C so a
        # value can never break out of the comma-delimited property list.
        f = _finding(rule="ns:rule,v2", file="a,b:c.sol", message="m")
        line = exp.to_github_annotations([f])[0]
        _, props, _ = _parse(line)
        assert props["title"] == "ns%3Arule%2Cv2"
        assert props["file"] == "a%2Cb%3Ac.sol"
        # And the raw line must not contain an unescaped comma/colon in props.
        head = line[2:].partition("::")[0]
        assert "ns:rule" not in head and "a,b" not in head

    def test_percent_escaped_first(self):
        exp = GitHubAnnotationsExporter()
        # A literal '%0A' in input must not be mistaken for a newline escape.
        f = _finding(message="raw %0A literal")
        _, _, message = _parse(exp.to_github_annotations([f])[0])
        assert message == "raw %250A literal"


# =============================================================================
# N-cap + suppressed-count log (no silent truncation)
# =============================================================================


class TestCap:
    def test_caps_at_max_and_appends_notice(self):
        exp = GitHubAnnotationsExporter(max_annotations=3)
        findings = [_finding(rule=f"r{i}", severity="high") for i in range(10)]
        lines = exp.to_github_annotations(findings)
        # 3 findings + 1 notice line about the suppression.
        assert len(lines) == 4
        notice = lines[-1]
        level, _, message = _parse(notice)
        assert level == "notice"
        assert "7 additional finding(s)" in message

    def test_no_notice_when_under_cap(self):
        exp = GitHubAnnotationsExporter(max_annotations=10)
        lines = exp.to_github_annotations([_finding(), _finding(rule="b")])
        assert len(lines) == 2
        assert not any(line.startswith("::notice") for line in lines)

    def test_cap_keeps_most_severe_first(self):
        exp = GitHubAnnotationsExporter(max_annotations=2)
        findings = [
            _finding(rule="low1", severity="low"),
            _finding(rule="crit1", severity="critical"),
            _finding(rule="med1", severity="medium"),
        ]
        lines = exp.to_github_annotations(findings)
        titles = [_parse(line)[1].get("title") for line in lines if not line.startswith("::notice")]
        # critical + medium survive; low is dropped.
        assert titles == ["crit1", "med1"]

    def test_suppression_is_logged(self, caplog):
        exp = GitHubAnnotationsExporter(max_annotations=1)
        findings = [_finding(rule=f"r{i}", severity="high") for i in range(5)]
        with caplog.at_level(logging.WARNING, logger="miesc.core.exporters"):
            exp.to_github_annotations(findings)
        assert any("suppressed" in rec.message.lower() for rec in caplog.records)
        assert any("4" in rec.getMessage() for rec in caplog.records)

    def test_negative_cap_disables_truncation(self):
        exp = GitHubAnnotationsExporter()
        findings = [_finding(rule=f"r{i}", severity="high") for i in range(15)]
        lines = exp.to_github_annotations(findings, max_annotations=-1)
        assert len(lines) == 15
        assert not any(line.startswith("::notice") for line in lines)


# =============================================================================
# Baseline composition — annotate only NEW findings
# =============================================================================


class TestBaselineComposition:
    def test_only_new_findings_annotated(self, tmp_path):
        known = _finding(rule="known", message="already accepted")
        new = _finding(rule="brand_new", message="just introduced")
        base = tmp_path / ".miesc-baseline.json"
        generate_baseline([known]).save(base)

        from miesc.core.baseline import diff_against_baseline, load_baseline

        partitioned = diff_against_baseline([known, new], load_baseline(base))
        lines = GitHubAnnotationsExporter().to_github_annotations(partitioned["new"])
        titles = [_parse(line)[1].get("title") for line in lines]
        assert titles == ["brand_new"]


# =============================================================================
# Dispatcher registration
# =============================================================================


class TestDispatcher:
    def test_github_registered(self):
        exp = ReportExporter()
        assert "github" in exp.exporters

    def test_dispatch_export_returns_lines(self):
        exp = ReportExporter()
        out = exp.export([_finding()], "github")
        assert out.startswith("::error ")
        assert out.endswith("\n")

    def test_export_all_still_five_formats(self, tmp_path):
        # github must NOT leak into export_all's fixed format set.
        f = Finding(
            id="F1",
            type="reentrancy",
            severity="high",
            title="t",
            description="d",
            file_path="C.sol",
            line_start=1,
        )
        results = ReportExporter().export_all([f], str(tmp_path))
        assert set(results) == {"sarif", "sonarqube", "checkmarx", "markdown", "json"}


# =============================================================================
# CLI wiring
# =============================================================================


def _write_results(path: Path, findings) -> Path:
    path.write_text(
        json.dumps(
            {
                "contract": "contracts/",
                "findings": findings,
                "results": [{"tool": "slither", "status": "success", "findings": findings}],
            }
        ),
        encoding="utf-8",
    )
    return path


class TestCliWiring:
    def test_export_github_prints_annotations(self, tmp_path):
        from miesc.cli.commands.export import export

        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])
        result = CliRunner().invoke(export, ["-f", "github", str(results)])
        assert result.exit_code == 0, result.output
        annotation_lines = [ln for ln in result.output.splitlines() if ln.startswith("::")]
        assert len(annotation_lines) == 2
        assert all("title=" in ln for ln in annotation_lines)

    def test_export_github_with_baseline_only_new(self, tmp_path):
        from miesc.cli.commands.export import export

        base = tmp_path / ".miesc-baseline.json"
        generate_baseline([_finding(rule="a")]).save(base)
        results = _write_results(tmp_path / "r.json", [_finding(rule="a"), _finding(rule="b")])

        result = CliRunner().invoke(export, ["-f", "github", str(results), "--baseline", str(base)])
        assert result.exit_code == 0, result.output
        annotation_lines = [ln for ln in result.output.splitlines() if ln.startswith("::")]
        assert len(annotation_lines) == 1
        assert "title=b" in annotation_lines[0]

    def test_export_github_writes_file(self, tmp_path):
        from miesc.cli.commands.export import export

        results = _write_results(tmp_path / "r.json", [_finding()])
        out = tmp_path / "ann.txt"
        result = CliRunner().invoke(export, ["-f", "github", str(results), "-o", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.read_text().startswith("::error ")

    def test_scan_help_shows_annotate_option(self):
        from miesc.cli.commands.scan import scan

        result = CliRunner().invoke(scan, ["--help"])
        assert result.exit_code == 0
        assert "--annotate" in result.output
        assert "github" in result.output
