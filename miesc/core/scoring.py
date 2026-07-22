"""Composite security score + badge for a set of findings.

Turns a scan/audit's findings into a single 0-100 score (and an A-F grade) by
penalizing each finding by its severity weight scaled by its calibrated
confidence — so a confident critical hurts far more than an uncertain
informational note, and low-confidence noise barely moves the number. A clean
contract scores 100 (A); the penalty saturates the score at 0.

The score is deliberately simple and interpretable (a transparent weighted
penalty, not a black box) so a project can reason about why it got the grade it
did. Confidence weighting reuses the calibrated ``confidence`` already attached to
findings; findings without one are treated as fully confident (weight 1.0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

# Points off a perfect 100 per finding, before confidence scaling. Tuned so a
# single high-confidence critical fails the grade while low/info barely register.
SEVERITY_PENALTY: Dict[str, float] = {
    "critical": 40.0,
    "high": 15.0,
    "medium": 5.0,
    "low": 1.5,
    "info": 0.3,
    "informational": 0.3,
    "optimization": 0.1,
    "note": 0.3,
}
_DEFAULT_PENALTY = 5.0  # unknown severity ~ medium

# score >= threshold -> grade (checked high to low)
_GRADES: List[Tuple[int, str]] = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

# grade -> badge colour (GitHub-ish palette)
GRADE_COLORS: Dict[str, str] = {
    "A": "#2ea043",
    "B": "#7cb342",
    "C": "#c9b458",
    "D": "#e08e0b",
    "F": "#d73a49",
}


@dataclass
class SecurityScore:
    """A composite security score for one analysis."""

    score: int  # 0-100, higher is safer
    grade: str  # A-F
    total_findings: int
    severity_counts: Dict[str, int] = field(default_factory=dict)
    penalty: float = 0.0  # total penalty subtracted from 100
    weighted_by_confidence: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "penalty": self.penalty,
            "weighted_by_confidence": self.weighted_by_confidence,
        }


def _grade(score: int) -> str:
    for threshold, g in _GRADES:
        if score >= threshold:
            return g
    return "F"


def _confidence_weight(finding: Dict[str, Any]) -> Tuple[float, bool]:
    conf = finding.get("confidence")
    if conf is None:
        return 1.0, False
    try:
        return max(0.0, min(1.0, float(conf))), True
    except (TypeError, ValueError):
        return 1.0, False


def compute_score(findings: Sequence[Dict[str, Any]]) -> SecurityScore:
    """Compute the composite score from findings (each a dict with ``severity``
    and optionally ``confidence``)."""
    penalty = 0.0
    counts: Dict[str, int] = {}
    weighted = False
    for f in findings:
        sev = str(f.get("severity", "info")).strip().lower()
        counts[sev] = counts.get(sev, 0) + 1
        base = SEVERITY_PENALTY.get(sev, _DEFAULT_PENALTY)
        weight, was_weighted = _confidence_weight(f)
        weighted = weighted or was_weighted
        penalty += base * weight
    score = max(0, min(100, round(100 - penalty)))
    return SecurityScore(
        score=score,
        grade=_grade(score),
        total_findings=len(findings),
        severity_counts=counts,
        penalty=round(penalty, 1),
        weighted_by_confidence=weighted,
    )


def extract_findings(results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten a results structure (list of per-tool dicts each with ``findings``)
    into a single findings list."""
    findings: List[Dict[str, Any]] = []
    for result in results:
        findings.extend(result.get("findings", []) or [])
    return findings


def badge_endpoint(score: SecurityScore) -> Dict[str, Any]:
    """shields.io endpoint schema, so a project can render the badge remotely."""
    return {
        "schemaVersion": 1,
        "label": "MIESC security",
        "message": f"{score.score} {score.grade}",
        "color": GRADE_COLORS.get(score.grade, "#9f9f9f"),
    }


def badge_svg(score: SecurityScore) -> str:
    """A self-contained shields.io-style SVG (no external requests), so it can be
    committed and embedded directly: ``[ MIESC security | 82 A ]``."""
    label = "MIESC security"
    message = f"{score.score} {score.grade}"
    color = GRADE_COLORS.get(score.grade, "#9f9f9f")
    # ~6.5px per char + 10px padding each side; good enough without font metrics.
    lw = int(len(label) * 6.5) + 20
    mw = int(len(message) * 6.5) + 20
    total = lw + mw
    lx = lw * 10 // 2
    mx = (lw + mw // 2) * 10
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {message}">'
        f"<title>{label}: {message}</title>"
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110">'
        f'<text x="{lx}" y="150" fill="#010101" fill-opacity=".3" '
        f'transform="scale(.1)" textLength="{(lw - 20) * 10}">{label}</text>'
        f'<text x="{lx}" y="140" transform="scale(.1)" '
        f'textLength="{(lw - 20) * 10}">{label}</text>'
        f'<text x="{mx}" y="150" fill="#010101" fill-opacity=".3" '
        f'transform="scale(.1)" textLength="{(mw - 20) * 10}">{message}</text>'
        f'<text x="{mx}" y="140" transform="scale(.1)" '
        f'textLength="{(mw - 20) * 10}">{message}</text>'
        f"</g></svg>"
    )
