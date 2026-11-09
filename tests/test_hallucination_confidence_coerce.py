"""Regression tests: hallucination detector must tolerate non-numeric confidence.

LLM findings routinely carry a textual confidence ("high") or a numeric string
("0.8") rather than a float. A bare ``float("high")`` raises ``ValueError`` and
crashes the whole validation run — a fail-hard on ordinary model output.
"""

import pytest

from miesc.security.hallucination_detector import (
    HallucinationDetector,
    _coerce_confidence,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        (0.8, 0.8),
        (1, 1.0),
        (5, 1.0),  # clamped to [0, 1]
        (-2, 0.0),  # clamped
        ("0.8", 0.8),
        ("high", 0.85),
        ("HIGH", 0.85),
        ("Medium", 0.6),
        ("low", 0.35),
        ("informational", 0.2),
        (True, 0.75),  # bool is not a real confidence -> default
        (None, 0.75),  # missing/None -> default
        ("nonsense", 0.75),  # unknown label -> default
        ([0.9], 0.75),  # wrong type -> default
    ],
)
def test_coerce_confidence(value, expected):
    assert _coerce_confidence(value, 0.75) == expected


def test_validate_findings_survives_textual_confidence():
    """A finding with confidence='high' must not crash validate_findings."""
    detector = HallucinationDetector()
    findings = [
        {"type": "reentrancy", "confidence": "high", "description": "x"},
        {"type": "overflow", "confidence": "0.9", "description": "y"},
        {"type": "access_control", "confidence": "bogus", "description": "z"},
    ]

    # Must return a validated finding per input, never raise ValueError.
    results = detector.validate_findings(
        findings, static_findings=[], contract_code="contract C {}"
    )
    assert len(results) == 3
    for r in results:
        # original_confidence must have been coerced to a real float in [0, 1].
        assert isinstance(r.validation.original_confidence, float)
        assert 0.0 <= r.validation.original_confidence <= 1.0
