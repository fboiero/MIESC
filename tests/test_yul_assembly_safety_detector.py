"""
Unit + fixture tests for the Yul/inline-assembly memory-safety detector (Phase 1).

Every hazard has a safe/unsafe pair so the negative checks are exercised, a plain assembly
block must stay silent (advisory, not noisy), and a dedicated class pins the real-library
idioms (OpenZeppelin / Solady) the detector must NOT flag — the memory-safe writes above the
free pointer, clobber-then-restore, proxy return-forwarding, and internal storage helpers
that an earlier model reported in the hundreds.
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
# H1 — a memory-safe block that STRUCTURALLY corrupts the memory model.
# A regex cannot know the runtime free pointer, so only two violations fire:
# freeing 0x40 below 0x80 and left broken, or a non-zero zero-slot (0x60) write
# left unrestored. Temporary use above the pointer and scratch writes are safe.
# --------------------------------------------------------------------------- #
class TestMemorySafeViolation:
    def test_unsafe_frees_pointer_below_0x80(self):
        src = _wrap('assembly ("memory-safe") { mstore(0x40, 0x20) }')
        assert "yul-memory-safe-violation" in _hazards(src)

    def test_unsafe_nonzero_zero_slot_not_restored(self):
        src = _wrap('assembly ("memory-safe") { mstore(0x60, 0x1) }')
        assert "yul-memory-safe-violation" in _hazards(src)

    def test_safe_temporary_use_above_free_pointer(self):
        # writing at/above 0x80 without touching 0x40 is temporary use -> memory-safe
        src = _wrap('assembly ("memory-safe") { mstore(0x80, 0x1) }')
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_safe_scratch_space(self):
        src = _wrap('assembly ("memory-safe") { mstore(0x0, 0x1) mstore(0x20, 0x2) }')
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_safe_clobber_then_restore_pointer(self):
        # the Solady idiom: clobber 0x40 as scratch, then restore it
        src = _wrap(
            'assembly ("memory-safe") { let m := mload(0x40) '
            "mstore(0x40, 0x20) mstore(0x40, m) }"
        )
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_safe_clobber_then_return(self):
        # clobber 0x40 then return -> memory is moot, not a violation
        src = _wrap('assembly ("memory-safe") { mstore(0x40, 1) return(0x40, 0x20) }')
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_safe_when_free_pointer_managed(self):
        src = _wrap(
            'assembly ("memory-safe") { let p := mload(0x40) '
            "mstore(p, 0x1) mstore(0x40, add(p, 0x20)) }"
        )
        assert "yul-memory-safe-violation" not in _hazards(src)

    def test_not_flagged_without_annotation(self):
        # H1 is about the broken `memory-safe` promise; a raw block is not an H1 finding
        src = _wrap("assembly { mstore(0x40, 0x20) }")
        assert "yul-memory-safe-violation" not in _hazards(src)


# --------------------------------------------------------------------------- #
# H2 — unbounded returndatacopy
# --------------------------------------------------------------------------- #
class TestUnboundedReturndatacopy:
    def test_unsafe_full_copy_to_fixed_offset(self):
        src = _wrap("assembly { returndatacopy(0, 0, returndatasize()) sstore(0, 1) }")
        assert "yul-unbounded-returndatacopy" in _hazards(src)

    def test_safe_when_allocated_against_free_pointer(self):
        src = _wrap(
            "assembly { let p := mload(0x40) returndatacopy(p, 0, returndatasize()) "
            "mstore(0x40, add(p, returndatasize())) }"
        )
        assert "yul-unbounded-returndatacopy" not in _hazards(src)

    def test_safe_when_terminates_after_copy(self):
        # the proxy return-forwarding idiom: copy then revert/return over the region
        src = _wrap(
            "assembly { returndatacopy(0, 0, returndatasize()) "
            "switch result case 0 { revert(0, returndatasize()) } "
            "default { return(0, returndatasize()) } }"
        )
        assert "yul-unbounded-returndatacopy" not in _hazards(src)

    def test_unsafe_when_terminator_forwards_a_different_region(self):
        # a return/revert over a *different* offset does not clear the copy into 0
        src = _wrap(
            "assembly { returndatacopy(0, 0, returndatasize()) "
            "if iszero(x) { revert(0x40, 0x20) } sstore(0, mload(0)) }"
        )
        assert "yul-unbounded-returndatacopy" in _hazards(src)


# --------------------------------------------------------------------------- #
# H3 — arbitrary sstore with attacker-influenced slot
# --------------------------------------------------------------------------- #
class TestArbitrarySstore:
    def test_unsafe_slot_from_external_parameter(self):
        src = _wrap(
            "assembly { sstore(slot, val) }", sig="setSlot(uint256 slot, uint256 val) external"
        )
        assert "yul-arbitrary-sstore" in _hazards(src)

    def test_unsafe_slot_from_calldataload(self):
        src = _wrap("assembly { let s := calldataload(0) sstore(s, 1) }")
        assert "yul-arbitrary-sstore" in _hazards(src)

    def test_safe_internal_helper_param_slot(self):
        # an internal/library helper chooses its own slot -> the contract, not an attacker
        src = _wrap(
            "assembly { sstore(slot, val) }",
            sig="_set(bytes32 slot, bytes32 val) internal",
        )
        assert "yul-arbitrary-sstore" not in _hazards(src)

    def test_safe_constant_slot(self):
        src = _wrap("assembly { sstore(0x0, 1) }")
        assert "yul-arbitrary-sstore" not in _hazards(src)

    def test_safe_keccak_derived_slot(self):
        src = _wrap("assembly { sstore(keccak256(0x0, 0x20), 1) }")
        assert "yul-arbitrary-sstore" not in _hazards(src)


# --------------------------------------------------------------------------- #
# Real-library idioms that must stay silent — the negative control the review
# asked for, distilled from OpenZeppelin `contracts/` and Solady `src/`.
# --------------------------------------------------------------------------- #
class TestRealLibraryIdiomsAreSilent:
    def test_solady_scratch_build_and_restore(self):
        # ERC4337.withdrawDepositTo style: scratch writes then restore + revert-forward
        src = _wrap(
            'assembly ("memory-safe") {\n'
            "  mstore(0x14, to) mstore(0x34, amount) mstore(0x00, 0x205c2878)\n"
            "  if iszero(call(gas(), ep, 0, 0x10, 0x44, codesize(), 0x00)) {\n"
            "    returndatacopy(mload(0x40), 0x00, returndatasize())\n"
            "    revert(mload(0x40), returndatasize())\n"
            "  }\n"
            "  mstore(0x34, 0)\n"
            "}",
            sig="withdrawDepositTo(address ep, address to, uint256 amount) public",
        )
        assert detect_yul_assembly_safety(src) == []

    def test_oz_proxy_delegate(self):
        src = _wrap(
            "assembly {\n"
            "  calldatacopy(0, 0, calldatasize())\n"
            "  let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)\n"
            "  returndatacopy(0, 0, returndatasize())\n"
            "  switch result\n"
            "  case 0 { revert(0, returndatasize()) }\n"
            "  default { return(0, returndatasize()) }\n"
            "}",
            sig="_delegate(address impl) internal",
        )
        assert detect_yul_assembly_safety(src) == []

    def test_clones_temporary_use_above_pointer(self):
        # OZ Clones.clone: builds the creation code at a computed pointer, memory-safe
        src = _wrap(
            'assembly ("memory-safe") {\n'
            "  let ptr := mload(0x40)\n"
            "  mstore(ptr, 0x3d602d80600a3d3981f3)\n"
            "  mstore(add(ptr, 0x14), impl)\n"
            "  instance := create(0, add(ptr, 0x0b), 0x37)\n"
            "}",
            sig="clone(address impl) internal",
        )
        assert detect_yul_assembly_safety(src) == []

    def test_storage_lib_internal_set(self):
        src = _wrap(
            "assembly { sstore(slot, value) }",
            sig="_setSlot(bytes32 slot, bytes32 value) internal",
        )
        assert detect_yul_assembly_safety(src) == []


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
        src = _wrap("assembly { returndatacopy(0, 0, returndatasize()) sstore(0, 1) }")
        for f in det.analyze(src):
            # advisory: heuristic findings never escalate past MEDIUM
            assert f.severity.value in {"low", "medium"}


# --------------------------------------------------------------------------- #
# Zero-FP regression guard: the detector must stay silent on the SmartBugs-curated
# corpus (solc 0.4.x, essentially no inline assembly). Skips if the dataset is not
# bundled in the checkout. NOTE: SmartBugs has almost no assembly, so this guard is
# necessary but not sufficient — the real negative control is TestRealLibraryIdioms
# plus the documented OpenZeppelin/Solady full-tree run in the PR body.
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
