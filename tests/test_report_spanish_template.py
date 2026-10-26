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

from miesc.cli.commands.report import report

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
