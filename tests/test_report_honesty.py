"""Honesty guarantees for the premium/profesional audit reports.

These tests lock in the "stop overclaiming" fixes so the automated report never
again (a) describes manual/human review it does not perform, (b) ships a
fabricated PoC for a vulnerability class it has no template for, or (c) prints a
default CVSS score for a finding whose category it could not classify.
"""

import json
from pathlib import Path

import pytest

import miesc
from miesc.core.finding_taxonomy import CanonicalCategory
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


# Types with no exploit template (OTHER canonical, or categories like
# BAD_RANDOMNESS/INITIALIZATION that have no .t.sol) must still yield NO PoC,
# rather than a mislabelled exploit — the honesty invariant survives Phase 1.
@pytest.mark.parametrize(
    "vuln",
    ["weak-prng", "weak-randomness", "uninitialized-state", "naming-convention", "dead-code"],
)
def test_generate_returns_none_for_templateless_type(vuln):
    """Template-less / uncategorized types yield no PoC (never a reentrancy exploit)."""
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


def test_poc_resolves_via_canonical_not_mislabelled():
    """Phase 1: a raw detector name resolves to the RIGHT template via taxonomy.

    aderyn's ``unchecked-return`` (SWC-104) has no exact alias but normalizes to
    UNCHECKED_CALL — it must get the unchecked_call template, never reentrancy.
    """
    gen = PoCGenerator()
    finding = {
        "type": "unchecked-return",
        "swc_id": "SWC-104",
        "severity": "high",
        "location": {"function": "approveSpender"},
    }
    poc = gen.generate(finding, "Contract.sol")
    assert poc is not None
    assert poc.vulnerability_type == VulnerabilityType.UNCHECKED_CALL


def test_generate_batch_drops_unresolved_findings():
    """Batch generation keeps only findings with a real template."""
    gen = PoCGenerator()
    findings = [
        {"type": "reentrancy", "location": {"function": "withdraw"}},
        {"type": "weak-prng", "location": {"function": "lottery"}},
        {"type": "naming-convention", "location": {"function": "x"}},
    ]
    pocs = gen.generate_batch(findings, "Contract.sol")
    assert len(pocs) == 1
    assert pocs[0].vulnerability_type == VulnerabilityType.REENTRANCY


# ---------------------------------------------------------------------------
# Edit 4 — CVSS "not scored" instead of a fabricated default
# ---------------------------------------------------------------------------


def test_get_vector_for_category_none_when_unmatched():
    """A name with no canonical category and no hygiene match is not scored."""
    calc = RiskCalculator()
    assert calc.get_vector_for_category("naming-convention") is None
    assert calc.get_vector_for_category("dead-code") is None
    assert calc.get_vector_for_category("") is None


def test_uncategorized_finding_rendered_not_scored():
    """A genuinely unclassifiable finding is flagged and shown as 'not scored'."""
    data = calculate_premium_risk_data(
        [
            {
                "id": "F-001",
                "type": "naming-convention",
                "severity": "low",
                "category": "naming-convention",
            }
        ]
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


# ---------------------------------------------------------------------------
# Phase 1 — correct data binding fills PR-0's honest blanks (without regressing)
# ---------------------------------------------------------------------------


def test_normalization_gives_real_vector_for_slither_check():
    """A raw slither check (weak-prng) now scores via its canonical category."""
    calc = RiskCalculator()
    score = calc.calculate_finding_score({"id": "F-001", "type": "weak-prng", "severity": "high"})
    assert score.uncategorized is False
    assert isinstance(score.base_score, float)
    assert score.base_score > 0
    # BAD_RANDOMNESS high -> high integrity impact, directionally consistent.
    assert "I:H" in score.vector


def test_other_category_stays_not_scored():
    """A finding that maps only to OTHER keeps PR-0's honest 'not scored' blank."""
    calc = RiskCalculator()
    score = calc.calculate_finding_score(
        {"id": "F-001", "type": "naming-convention", "severity": "high"}
    )
    assert score.uncategorized is True
    assert score.vector == "not scored (uncategorized)"


def test_low_finding_never_gets_high_score():
    """Directional-consistency guard: a LOW reported finding never shows 9.x.

    ``reentrancy-benign`` normalizes to REENTRANCY (whose raw vector is ~9.x),
    but reported LOW: the symmetric nudge keeps the score low and the guard
    withholds anything more than one band away.
    """
    calc = RiskCalculator()
    score = calc.calculate_finding_score(
        {"id": "F-001", "type": "reentrancy-benign", "severity": "low"}
    )
    # reentrancy-benign LOW is scored (not withheld) and relaxed well below High.
    assert score.uncategorized is False
    assert isinstance(score.base_score, float)
    assert score.base_score < 7.0  # never High/Critical for a LOW finding
    assert calc.get_severity_from_score(score.base_score) in ("Info", "Low", "Medium")


def test_inconsistent_severity_is_withheld_not_misreported():
    """The directional guard fires when the computed band is >1 from reported.

    A CENTRALIZATION finding reported CRITICAL computes to ~Low (band distance
    3): rather than print a contradictory number, the score is withheld as
    'not scored (inconsistent with reported severity)'.
    """
    calc = RiskCalculator()
    score = calc.calculate_finding_score(
        {"id": "F-001", "type": "centralization-risk", "severity": "critical"}
    )
    assert score.uncategorized is True
    assert "inconsistent" in score.vector


def test_shared_vector_not_mutated_across_findings():
    """get_vector_for_category returns a copy; scoring one finding must not alter
    the shared class template or a sibling finding of the same category."""
    calc = RiskCalculator()
    before = calc.CATEGORY_VECTORS[CanonicalCategory.REENTRANCY]
    before_integrity = before.integrity_impact
    before_ac = before.attack_complexity

    calc.calculate_finding_score({"id": "A", "type": "reentrancy", "severity": "critical"})
    calc.calculate_finding_score({"id": "B", "type": "reentrancy", "severity": "low"})

    after = calc.CATEGORY_VECTORS[CanonicalCategory.REENTRANCY]
    assert after.integrity_impact == before_integrity
    assert after.attack_complexity == before_ac

    # Two fresh lookups are independent objects.
    v1 = calc.get_vector_for_category("reentrancy")
    v2 = calc.get_vector_for_category("reentrancy")
    assert v1 is not v2


def test_vulnerable_code_snippet_embeds_when_source_present(tmp_path):
    """§5 Vulnerable Code embeds the real source when it is locatable.

    Runs the full ``report`` command on the bundled sample, whose source
    (``VulnerableDeFi.sol``) sits next to the results JSON. The rendered report
    must contain an actual code snippet (the ``lottery`` function), not the
    honest "source not available" fallback.
    """
    from click.testing import CliRunner

    from miesc.cli.commands.report import report

    sample = Path(miesc.__file__).parent.parent / "examples" / "contracts" / "results.json"
    if not sample.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")

    out = tmp_path / "report.md"
    result = CliRunner().invoke(
        report, [str(sample), "-t", "premium", "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "function lottery()" in text  # real source embedded in §5
    assert ">>" in text  # the line marker from _extract_source_code


def test_finding_ids_consistent_across_sections_with_triage_reorder(tmp_path):
    """F-xxx ids agree across §3.2, §4.1 and §5 even when triage reorders findings.

    The CVSS table (§3.2), summary table (§4.1) and detailed findings (§5) are
    all bound by finding position; they must reference the same F-xxx for the
    same finding. A ``triage_score`` reorder before dedup must not desync them.
    """
    import re

    from click.testing import CliRunner

    from miesc.cli.commands.report import report

    results = {
        "contract": "T.sol",
        "summary": {"HIGH": 2},
        "findings": [
            {
                "id": "a",
                "type": "reentrancy-eth",
                "severity": "high",
                "triage_score": 0.2,
                "location": {"file": "T.sol", "line": 1},
            },
            {
                "id": "b",
                "type": "controlled-delegatecall",
                "severity": "high",
                "triage_score": 0.9,
                "location": {"file": "T.sol", "line": 2},
            },
        ],
    }
    src = tmp_path / "results.json"
    src.write_text(json.dumps(results), encoding="utf-8")
    out = tmp_path / "r.md"
    result = CliRunner().invoke(
        report, [str(src), "-t", "premium", "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")

    # In §3.2 the higher triage_score finding (controlled-delegatecall) sorts
    # first as F-001; §5 must give that same title the same id.
    cvss_section = text.split("## 3.2")[1].split("## 3.3")[0]
    m = re.search(r"\|\s*(F-\d{3})\s*\|\s*controlled-delegatecall\s*\|", cvss_section)
    assert m, cvss_section
    fid = m.group(1)
    assert f"## {fid}. controlled-delegatecall" in text
