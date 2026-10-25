"""Honesty guarantees for the premium/profesional audit reports.

These tests lock in the "stop overclaiming" fixes so the automated report never
again (a) describes manual/human review it does not perform, (b) ships a
fabricated PoC for a vulnerability class it has no template for, or (c) prints a
default CVSS score for a finding whose category it could not classify.
"""

from pathlib import Path

import pytest

import miesc
from miesc.poc.poc_generator import PoCGenerator, VulnerabilityType
from miesc.reports.risk_calculator import RiskCalculator, calculate_premium_risk_data

TEMPLATES_DIR = Path(miesc.__file__).parent / "data" / "templates" / "reports"


# ---------------------------------------------------------------------------
# Edit 1 & 2 — methodology and disclaimer honesty (templates)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium.md", "profesional.md"])
def test_methodology_has_no_manual_or_human_review(template):
    """The automated pipeline does not do manual review or human reproduction."""
    text = (TEMPLATES_DIR / template).read_text(encoding="utf-8")
    assert "Manual Review" not in text
    assert "Reproduce and validate" not in text


@pytest.mark.parametrize("template", ["premium.md", "profesional.md"])
def test_disclaimer_declares_automated_output(template):
    """The disclaimer must state the report is automated, not a manual audit."""
    text = (TEMPLATES_DIR / template).read_text(encoding="utf-8")
    assert "output of automated security tooling" in text
    assert "not a manual professional audit" in text


# ---------------------------------------------------------------------------
# Edit 3 — PoC generator never fabricates a reentrancy exploit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vuln", ["weak-prng", "suicidal", "unchecked-return"])
def test_generate_returns_none_for_unknown_type(vuln):
    """Unknown types yield no PoC rather than a mislabelled reentrancy exploit."""
    gen = PoCGenerator()
    finding = {"type": vuln, "severity": "high", "location": {"function": "f"}}
    assert gen.generate(finding, "Contract.sol") is None


def test_generate_still_works_for_known_type():
    """Known types keep producing a PoC."""
    gen = PoCGenerator()
    finding = {"type": "reentrancy", "severity": "high", "location": {"function": "withdraw"}}
    poc = gen.generate(finding, "Bank.sol")
    assert poc is not None
    assert poc.vulnerability_type == VulnerabilityType.REENTRANCY


def test_generate_batch_drops_unresolved_findings():
    """Batch generation keeps only findings with a real template."""
    gen = PoCGenerator()
    findings = [
        {"type": "reentrancy", "location": {"function": "withdraw"}},
        {"type": "weak-prng", "location": {"function": "lottery"}},
        {"type": "suicidal", "location": {"function": "kill"}},
    ]
    pocs = gen.generate_batch(findings, "Contract.sol")
    assert len(pocs) == 1
    assert pocs[0].vulnerability_type == VulnerabilityType.REENTRANCY


# ---------------------------------------------------------------------------
# Edit 4 — CVSS "not scored" instead of a fabricated default
# ---------------------------------------------------------------------------


def test_get_vector_for_category_none_when_unmatched():
    calc = RiskCalculator()
    assert calc.get_vector_for_category("weak-prng") is None
    assert calc.get_vector_for_category("") is None


def test_uncategorized_finding_rendered_not_scored():
    """An unclassifiable finding is flagged and shown as 'not scored'."""
    data = calculate_premium_risk_data(
        [{"id": "F-001", "type": "weak-prng", "severity": "high", "category": "weak-prng"}]
    )
    row = data["cvss_scores"][0]
    assert row["uncategorized"] is True
    assert row["base_score"] == "not scored (uncategorized)"
    assert row["vector"] == "not scored (uncategorized)"


def test_matched_category_keeps_numeric_score():
    """A classified finding still receives a real numeric CVSS base score."""
    data = calculate_premium_risk_data(
        [{"id": "F-001", "type": "reentrancy", "severity": "high", "category": "reentrancy"}]
    )
    row = data["cvss_scores"][0]
    assert row["uncategorized"] is False
    assert isinstance(row["base_score"], float)
    assert row["base_score"] > 0
