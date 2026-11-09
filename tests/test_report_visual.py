"""Visual-polish guarantees for the premium / profesional / profesional-es reports.

These tests lock in the report-polish pass: the templates now ship deterministic
inline-SVG charts (severity distribution, risk matrix, effort/impact) and a new
"Bug Bounty Submission Readiness" section, and the two stylesheets stay byte-for-byte
identical except for the Spanish running header/footer. None of this is allowed to
change any finding count or the overall risk score, add a banned overclaim word, or
drop an existing disclaimer — the charts only *visualise* numbers that already exist.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from click.testing import CliRunner

import miesc
from miesc.cli.commands.report import report

ROOT = Path(miesc.__file__).parent.parent
SAMPLE = Path(miesc.__file__).parent.parent / "examples" / "contracts" / "results.json"
CSS_DIR = ROOT / "docs" / "templates" / "reports"

# Baseline that must never drift: the bundled sample has 0 critical / 8 high /
# 1 medium / 1 low / 0 info = 10 findings, risk score 85/100.
EXPECTED_SEVERITY_EN = {
    "| **Critical** | 0 |",
    "| **High** | 8 |",
    "| **Medium** | 1 |",
    "| **Low** | 1 |",
    "| **Total** | **10** |",
    "| **Overall Risk Score** | 85/100 |",
}
EXPECTED_SEVERITY_ES = {
    "| **Crítica** | 0 |",
    "| **Alta** | 8 |",
    "| **Media** | 1 |",
    "| **Baja** | 1 |",
    "| **Total** | **10** |",
    "| **Puntaje de Riesgo General** | 85/100 |",
}

BANNED = ("proven", "formally verified", "Manual Review", "Revisión Manual")


def _render(template: str, tmp_path: Path) -> str:
    if not SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    out = tmp_path / f"{template}.md"
    res = CliRunner().invoke(
        report, [str(SAMPLE), "-t", template, "-f", "markdown", "-o", str(out)]
    )
    assert res.exit_code == 0, res.output
    return out.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Inline SVG charts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional", "profesional-es"])
def test_templates_render_inline_svg_charts(template: str, tmp_path: Path) -> None:
    """Severity, risk-matrix and effort/impact charts render as inline SVG."""
    text = _render(template, tmp_path)
    assert "<svg" in text
    assert 'class="chart chart-severity"' in text
    assert 'class="chart chart-matrix"' in text
    assert 'class="chart chart-effort"' in text
    # The severity SVG encodes the real counts: High is 8/10 of the 380px track.
    assert 'width="304.0"' in text
    # No raw Jinja leaked into the SVG markup.
    assert "{{" not in text and "{%" not in text


@pytest.mark.parametrize("template", ["premium", "profesional-es"])
def test_cover_uses_svg_shield_not_emoji(template: str, tmp_path: Path) -> None:
    """The cover mark is an inline SVG shield, not the old emoji."""
    text = _render(template, tmp_path)
    assert "🛡" not in text
    # The shield path lives in the cover <h1>.
    assert "M12 2L4 5v6c0 5 3.4 8.9 8 11" in text


# ---------------------------------------------------------------------------
# Submission readiness section
# ---------------------------------------------------------------------------


def test_submission_readiness_en(tmp_path: Path) -> None:
    """English §6.5 renders the honest intro and a per-finding readiness column."""
    text = _render("premium", tmp_path)
    assert "## 6.5 Bug Bounty Submission Readiness" in text
    assert "automated triage starting point" in text
    assert "not confirmed vulnerabilities" in text
    assert "Immunefi Vulnerability Severity Classification System V2.3" in text
    assert "mandatory Proof of Concept" in text
    # The readiness column is honest for every finding: triage + PoC, never "ready".
    assert "| Finding | Severity | PoC available | Readiness |" in text
    assert "Requires manual triage + PoC" in text
    # The only "ready to submit" mention is the explicit negation.
    assert "nothing here is ready to submit without human verification" in text


def test_submission_readiness_es(tmp_path: Path) -> None:
    """Spanish §6.5 renders the translated honest intro and readiness column."""
    text = _render("profesional-es", tmp_path)
    assert "## 6.5 Preparación para Envío a Bug Bounty" in text
    assert "punto de partida de triaje automatizado" in text
    assert "no son vulnerabilidades confirmadas" in text
    assert "Immunefi Vulnerability Severity Classification System V2.3" in text
    assert "| Hallazgo | Severidad | PoC disponible | Preparación |" in text
    assert "Requiere triaje manual + PoC" in text


def test_readiness_row_per_finding_without_changing_counts(tmp_path: Path) -> None:
    """The readiness table has one row per finding and adds nothing to any count."""
    text = _render("premium", tmp_path)
    readiness_rows = text.count("Requires manual triage + PoC")
    # 10 findings -> 10 rows (plus one quoted mention in the closing paragraph).
    assert readiness_rows == 11
    # Counts and score are still the Phase-1 baseline.
    for line in EXPECTED_SEVERITY_EN:
        assert line in text


# ---------------------------------------------------------------------------
# Honesty invariants survive the polish
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "template,expected",
    [("premium", EXPECTED_SEVERITY_EN), ("profesional-es", EXPECTED_SEVERITY_ES)],
)
def test_counts_and_score_byte_identical(template: str, expected: set[str], tmp_path: Path) -> None:
    text = _render(template, tmp_path)
    for line in expected:
        assert line in text, line


@pytest.mark.parametrize("template", ["premium", "profesional", "profesional-es"])
def test_no_banned_overclaim_words(template: str, tmp_path: Path) -> None:
    text = _render(template, tmp_path)
    for word in BANNED:
        assert word not in text, f"{word!r} must not appear in {template}"


@pytest.mark.parametrize("template", ["premium", "profesional", "profesional-es"])
def test_sha256_attestation_still_matches_input(template: str, tmp_path: Path) -> None:
    text = _render(template, tmp_path)
    expected = hashlib.sha256(SAMPLE.read_bytes()).hexdigest()
    assert expected in text


# ---------------------------------------------------------------------------
# CSS twin discipline: the stylesheets differ only in the Spanish page chrome
# ---------------------------------------------------------------------------


def test_css_twins_differ_only_in_spanish_chrome() -> None:
    """profesional-es.css must equal profesional.css except for the 3 Spanish lines
    (comment banner, @top-center header, @bottom-right page counter)."""
    en = (CSS_DIR / "profesional.css").read_text(encoding="utf-8").splitlines()
    es = (CSS_DIR / "profesional-es.css").read_text(encoding="utf-8").splitlines()
    assert len(en) == len(es), "stylesheets must have the same number of lines"
    differing = [i for i, (a, b) in enumerate(zip(en, es, strict=False)) if a != b]
    assert len(differing) == 3, f"expected exactly 3 differing lines, got {differing}"
    joined_es = "\n".join(es)
    assert "Español" in joined_es
    assert "CONFIDENCIAL" in joined_es
    assert "Página" in joined_es
