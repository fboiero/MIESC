"""Tests for benchmarks/run_benchmark.py find_matching_findings.

Guards the honest category matcher: a finding must be credited to a category by
its SWC id or detector `type`, not only by substring keywords — otherwise an
access-control finding reported as ``controlled-delegatecall`` is scored a miss.
"""

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "run_benchmark",
    Path(__file__).parent.parent / "benchmarks" / "run_benchmark.py",
)
rb = importlib.util.module_from_spec(_SPEC)
try:
    _SPEC.loader.exec_module(rb)
except Exception as exc:  # pragma: no cover - import guard
    pytest.skip(f"run_benchmark not importable: {exc}", allow_module_level=True)


def test_detector_type_matches_access_control():
    # No access_control keyword in the text, but the detector type maps to it.
    findings = [{"type": "controlled-delegatecall", "message": "delegatecall to input"}]
    assert len(rb.find_matching_findings(findings, "access_control")) == 1


def test_swc_id_matches_arithmetic():
    findings = [{"type": "something", "swc_id": "SWC-101", "message": "big multiply"}]
    assert len(rb.find_matching_findings(findings, "arithmetic")) == 1


def test_keyword_still_matches():
    findings = [{"title": "Reentrancy in withdraw", "description": "external call first"}]
    assert len(rb.find_matching_findings(findings, "reentrancy")) == 1


def test_no_false_match_across_categories():
    # A reentrancy finding must not be credited to access_control.
    findings = [{"type": "reentrancy-eth", "swc_id": "SWC-107", "message": "reentrancy"}]
    assert rb.find_matching_findings(findings, "access_control") == []
