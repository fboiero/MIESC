"""Regression tests for MythrilAdapter.validate_finding SWC-id handling.

Mythril legitimately emits issues without an ``swc-id`` for several detectors.
``normalize_findings`` stores that as ``swc_id: None`` (not ``""``), so a
``.get("swc_id", "")`` on a present-but-None key still yields ``None``. Calling
``.replace(...)`` on that value used to raise ``AttributeError`` and crash the
whole cross-validation run (fail-hard on hostile/atypical tool output).
"""

from unittest.mock import MagicMock

from miesc.adapters.mythril_adapter import MythrilAdapter


def _adapter_returning(findings):
    """Build a MythrilAdapter whose analyze() yields the given findings."""
    adapter = MythrilAdapter()
    adapter.analyze = MagicMock(return_value={"status": "success", "findings": findings})
    return adapter


def test_validate_finding_survives_none_swc_id():
    """A Mythril finding with swc_id=None must not crash validate_finding."""
    adapter = _adapter_returning([{"swc_id": None, "title": "Some issue"}])

    # Must return a (bool, finding_or_None) tuple, never raise AttributeError.
    confirmed, match = adapter.validate_finding(
        source_code="contract C {}",
        finding_type="reentrancy",
        finding_line=1,
    )
    assert confirmed is False
    assert match is None


def test_validate_finding_matches_normal_swc_id():
    """The normal path (swc_id present) still confirms a matching finding."""
    adapter = _adapter_returning([{"swc_id": "SWC-107", "title": "Reentrancy"}])

    confirmed, match = adapter.validate_finding(
        source_code="contract C {}",
        finding_type="reentrancy",
        finding_line=1,
    )
    assert confirmed is True
    assert match is not None


def test_validate_finding_mixed_none_and_real_swc():
    """A None swc_id ahead of a real match must not short-circuit the loop."""
    adapter = _adapter_returning(
        [
            {"swc_id": None, "title": "Unclassified"},
            {"swc_id": "SWC-107", "title": "Reentrancy"},
        ]
    )

    confirmed, match = adapter.validate_finding(
        source_code="contract C {}",
        finding_type="reentrancy",
        finding_line=1,
    )
    assert confirmed is True
    assert match["swc_id"] == "SWC-107"
