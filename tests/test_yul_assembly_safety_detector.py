"""
Unit + fixture tests for the Yul/inline-assembly memory-safety detector (Phase 1).

Every hazard has a safe/unsafe pair so the negative checks are exercised, and a plain
assembly block must stay silent (advisory, not noisy).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from miesc.detectors.yul_assembly_safety_detector import (
    YulAssemblySafetyDetector,
    detect_yul_assembly_safety,
)


def _hazards(source: str) -> set:
    return {f.metadata.get("hazard") for f in detect_yul_assembly_safety(source)}


def _wrap(body: str, sig: str = "f() public") -> str:
    return f"contract C {{\n  function {sig} {{\n    {body}\n  }}\n}}\n"


# --------------------------------------------------------------------------- #
# H1 — memory-safe annotation violation
# --------------------------------------------------------------------------- #
class TestMemorySafeViolation:
    def test_unsafe_writes_beyond_scratch_without_managing_pointer(self):
        src = _wrap('assembly ("memory-safe") { mstore(0x80, 0x1) }')
        assert "yul-memory-safe-violation" in _hazards(src)

    def test_safe_when_free_pointer_managed(self):
        src = _wrap(
            'assembly ("memory-safe") { let p := mload(0x40) '
            "mstore(p, 0x1) mstore(0x40, add(p, 0x20)) }"
        )
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_safe_when_only_scratch_space(self):
        src = _wrap('assembly ("memory-safe") { mstore(0x0, 0x1) mstore(0x20, 0x2) }')
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_not_flagged_without_annotation(self):
        # non-annotated assembly is not an H1 finding (H1 is about the broken promise)
        src = _wrap("assembly { mstore(0x80, 0x1) }")
        assert "yul-memory-safe-violation" not in _hazards(src)


# --------------------------------------------------------------------------- #
# H2 — unbounded returndatacopy
# --------------------------------------------------------------------------- #
class TestUnboundedReturndatacopy:
    def test_unsafe_full_copy_to_fixed_offset(self):
        src = _wrap("assembly { returndatacopy(0, 0, returndatasize()) }")
        assert "yul-unbounded-returndatacopy" in _hazards(src)

    def test_safe_when_allocated_against_free_pointer(self):
        src = _wrap(
            "assembly { let p := mload(0x40) returndatacopy(p, 0, returndatasize()) "
            "mstore(0x40, add(p, returndatasize())) }"
        )
        assert "yul-unbounded-returndatacopy" not in _hazards(src)


# --------------------------------------------------------------------------- #
# H3 — arbitrary sstore with attacker-influenced slot
# --------------------------------------------------------------------------- #
class TestArbitrarySstore:
    def test_unsafe_slot_from_parameter(self):
        src = _wrap(
            "assembly { sstore(slot, val) }", sig="setSlot(uint256 slot, uint256 val) external"
        )
        assert "yul-arbitrary-sstore" in _hazards(src)

    def test_unsafe_slot_from_calldataload(self):
        src = _wrap("assembly { let s := calldataload(0) sstore(s, 1) }")
        assert "yul-arbitrary-sstore" in _hazards(src)

    def test_safe_constant_slot(self):
        src = _wrap("assembly { sstore(0x0, 1) }")
        assert "yul-arbitrary-sstore" not in _hazards(src)

    def test_safe_keccak_derived_slot(self):
        src = _wrap("assembly { sstore(keccak256(0x0, 0x20), 1) }")
        assert "yul-arbitrary-sstore" not in _hazards(src)


# --------------------------------------------------------------------------- #
# Extraction / anchoring / advisory behavior
# --------------------------------------------------------------------------- #
class TestExtractionAndAdvisory:
    def test_plain_assembly_block_is_silent(self):
        src = _wrap("assembly { let x := add(1, 2) }")
        assert detect_yul_assembly_safety(src) == []

    def test_no_assembly_returns_empty(self):
        assert detect_yul_assembly_safety("contract C { function f() public {} }") == []

    def test_findings_carry_anchor_and_function(self):
        src = _wrap("assembly { sstore(slot, 1) }", sig="writeAt(uint256 slot) external")
        findings = detect_yul_assembly_safety(src)
        assert findings, "expected a finding"
        f = findings[0]
        assert f.location is not None and f.location.line_start >= 1
        assert f.metadata.get("function") == "writeAt"
        assert f.confidence in {"low", "medium"}  # advisory, never high on heuristic alone
        assert f.detector == "yul-assembly-safety-detector"

    def test_comment_mentioning_assembly_does_not_trigger(self):
        src = "contract C {\n  // uses assembly { sstore(x, y) } somewhere\n  function f() public {}\n}"
        assert detect_yul_assembly_safety(src) == []

    def test_detector_name_and_severity_cap(self):
        det = YulAssemblySafetyDetector()
        assert det.name == "yul-assembly-safety-detector"
        src = _wrap("assembly { returndatacopy(0, 0, returndatasize()) }")
        for f in det.analyze(src):
            # advisory: heuristic findings never escalate past MEDIUM
            assert f.severity.value in {"low", "medium"}


# --------------------------------------------------------------------------- #
# Zero-FP regression guard: the detector must stay silent on the SmartBugs-curated
# corpus (solc 0.4.x, essentially no inline assembly). Any emission there is almost
# certainly a false positive and would hurt the precision line. Skips if the dataset
# is not bundled in the checkout (e.g. a trimmed CI image).
# --------------------------------------------------------------------------- #
def test_zero_false_positives_on_smartbugs_corpus():
    root = Path(__file__).resolve().parents[1]
    dataset = root / "benchmarks" / "datasets" / "smartbugs-curated" / "dataset"
    if not dataset.is_dir():
        pytest.skip("SmartBugs-curated dataset not present in this checkout")
    contracts = sorted(dataset.rglob("*.sol"))
    if not contracts:
        pytest.skip("SmartBugs-curated dataset empty")
    offenders = []
    for path in contracts:
        try:
            src = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = detect_yul_assembly_safety(src)
        if hits:
            offenders.append((path.name, [f.metadata.get("hazard") for f in hits]))
    assert offenders == [], f"expected 0 findings on SmartBugs-143, got: {offenders}"
