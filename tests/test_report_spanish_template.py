"""The `profesional-es` template renders a Spanish-language report.

It is the Spanish sibling of `profesional`: same Jinja variables and the same
premium data path (CVSS, risk matrix), with the static scaffolding — headings,
table labels, methodology, trust/invariant/fuzzing section prose, disclaimers and
glossary — translated to Spanish. Per-finding technical prose that comes from the
analysis engine (impact/recommendation dicts, detector descriptions) is not the
template's responsibility and is not asserted here.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from miesc.cli.commands.report import (
    _get_impact_description,
    _get_recommendation,
    _localized_description,
    report,
)
from miesc.core.finding_taxonomy import CanonicalCategory

SAMPLE = {
    "contract": "VulnerableDeFi.sol",
    "summary": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "results": [
        {
            "tool": "slither",
            "contract": "VulnerableDeFi.sol",
            "status": "success",
            "findings": [
                {
                    "title": "suicidal",
                    "type": "suicidal",
                    "severity": "High",
                    "description": "Unprotected selfdestruct.",
                    "location": {"file": "VulnerableDeFi.sol", "line": 10},
                    "tool": "slither",
                }
            ],
            "metadata": {},
        }
    ],
}


@pytest.fixture
def results_file(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(json.dumps(SAMPLE), encoding="utf-8")
    return p


def _render(results_file, tmp_path):
    out = tmp_path / "report_es.md"
    res = CliRunner().invoke(
        report, [str(results_file), "-t", "profesional-es", "-f", "markdown", "-o", str(out)]
    )
    assert res.exit_code == 0, res.output
    return out.read_text(encoding="utf-8")


def test_profesional_es_renders_spanish_scaffolding(results_file, tmp_path):
    text = _render(results_file, tmp_path)
    # Section headings are Spanish.
    for heading in (
        "# 1. Resumen Ejecutivo",
        "# 2. Alcance y Metodología",
        "# 3. Evaluación de Riesgo",
        "# 4. Panorama de Hallazgos",
        "# 5. Hallazgos Detallados",
        "## 4.5 Modelo de Confianza y Roles Privilegiados",
        "## 4.6 Pruebas Dinámicas y Fuzzing",
        "# Descargo de Responsabilidad",
    ):
        assert heading in text, heading
    # The legally-important disclaimer is Spanish.
    assert 'Este informe de auditoría se provee "TAL CUAL"' in text
    # The premium data path still runs: the severity table is present and the one
    # finding is counted — the Spanish template must not change finding counts.
    assert "| **Alta** | 1 |" in text
    assert "| **Total** | **1** |" in text


def test_profesional_es_is_registered_and_distinct_from_english(results_file, tmp_path):
    es = _render(results_file, tmp_path)
    out_en = tmp_path / "report_en.md"
    res = CliRunner().invoke(
        report, [str(results_file), "-t", "profesional", "-f", "markdown", "-o", str(out_en)]
    )
    assert res.exit_code == 0, res.output
    en = out_en.read_text(encoding="utf-8")
    # English sibling keeps English headings; Spanish one does not.
    assert "# 1. Executive Summary" in en and "# 1. Resumen Ejecutivo" not in en
    assert "# 1. Resumen Ejecutivo" in es and "# 1. Executive Summary" not in es


def test_impact_and_recommendation_localize_by_lang():
    """The impact/recommendation prose is Spanish for lang='es' and English for 'en',
    selected per-category; English output is unchanged (separate code path)."""
    # Canonical category path.
    es_impact = _get_impact_description(
        "high", canonical=CanonicalCategory.PROXY_UPGRADE, lang="es"
    )
    en_impact = _get_impact_description(
        "high", canonical=CanonicalCategory.PROXY_UPGRADE, lang="en"
    )
    assert "delegatecall sin verificar" in es_impact
    assert "unchecked delegatecall" in en_impact
    es_rec = _get_recommendation("", canonical=CanonicalCategory.CENTRALIZATION, lang="es")
    en_rec = _get_recommendation("", canonical=CanonicalCategory.CENTRALIZATION, lang="en")
    assert "multisig" in es_rec and "Reduzca la confianza" in es_rec
    assert "Reduce single-key trust" in en_rec
    # Keyword-table path (reentrancy) + severity fallback.
    assert "patrón Checks-Effects-Interactions" in _get_recommendation("reentrancy", lang="es")
    assert "Pérdida total de fondos" in _get_impact_description("critical", lang="es")
    # Default stays English.
    assert "Complete loss of funds" in _get_impact_description("critical")


def test_rendered_report_impact_is_spanish_for_es_english_for_en(results_file, tmp_path):
    """End-to-end: the per-finding impact prose follows the template's language."""
    es = _render(results_file, tmp_path)
    out_en = tmp_path / "en.md"
    assert (
        CliRunner()
        .invoke(
            report, [str(results_file), "-t", "profesional", "-f", "markdown", "-o", str(out_en)]
        )
        .exit_code
        == 0
    )
    en = out_en.read_text(encoding="utf-8")
    # The one finding is 'suicidal' -> access_control; its impact localizes.
    assert "usuarios no autorizados" in es
    assert "unauthorized users" in en


def test_localized_description_curated_fallback_and_english():
    """ES uses the curated Spanish description keyed by check id; an unknown check
    keeps the English detector text plus a visible note; English is unchanged."""
    known = {"type": "suicidal", "description": "allows anyone to destruct the contract"}
    assert _localized_description(known, "en") == "allows anyone to destruct the contract"
    es = _localized_description(known, "es")
    assert "selfdestruct desprotegido" in es
    assert "allows anyone to destruct" not in es  # curated, not the raw detector text
    # Unknown check: English kept + visible honest note, never a silent mix.
    unknown = {"type": "some-unknown-check", "description": "Raw detector text."}
    out = _localized_description(unknown, "es")
    assert "Raw detector text." in out
    assert "sin traducción curada para `some-unknown-check`" in out


def test_rendered_es_descriptions_are_curated_with_no_silent_english(results_file, tmp_path):
    """On a sample of recognized checks, every §5 description is curated Spanish and
    carries no 'sin traducción curada' note; the English report keeps the raw text."""
    es = _render(results_file, tmp_path)
    # 'suicidal' is recognized -> curated Spanish, and no fallback note for it.
    assert "selfdestruct desprotegido" in es
    assert "sin traducción curada" not in es
