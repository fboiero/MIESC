"""
Unit tests for the deterministic Yul/inline-assembly advisory effect-summary plan (SDD later phase).

The miner builds a structured ``assembly_summary`` per inline-assembly block (what it reads/writes
across memory, storage, calldata, returndata, plus external effects and bindings) and fills
``hazards`` by calling the shipped ``YulAssemblySafetyDetector`` — it never writes a second
classifier. Advisory only: a plan is an inventory, never a Finding. Covers the opcode→effect
tokenizer, memory-region and slot-provenance classification, the enclosing-context fix for
fallback/constructor, the detector-backed hazards, and the parser round-trip.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.yul_assembly_memory_safety import (
    _DEFERRED_CATEGORIES,
    _EVALUATED_CATEGORIES,
    AssemblySummary,
    YulHazard,
    mine_yul_assembly_safety,
    parse_yul_assembly_safety_plans,
)

PROXY = """
contract Proxy {
  address impl;
  fallback() external payable {
    assembly {
      calldatacopy(0, 0, calldatasize())
      let result := delegatecall(gas(), sload(impl.slot), 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch result
      case 0 { revert(0, returndatasize()) }
      default { return(0, returndatasize()) }
    }
  }
}
"""


def _summary(src, path="c.sol"):
    plans = mine_yul_assembly_safety(src, Path(path))
    return {p.enclosing_function: p.to_dict()["assembly_summary"] for p in plans}


def _cats(src, path="c.sol"):
    return [
        h["category"]
        for p in mine_yul_assembly_safety(src, Path(path))
        for h in p.to_dict()["hazards"]
    ]


class TestProxyFidelity:
    def test_proxy_fallback_full_effect_summary(self):
        s = _summary(PROXY, "Proxy.sol")["fallback"]
        assert "calldatacopy" in s["calldata_reads"] and "calldatasize" in s["calldata_reads"]
        assert (
            "returndatacopy" in s["returndata_reads"] and "returndatasize" in s["returndata_reads"]
        )
        assert s["external_effects"] == ["delegatecall"]
        assert "delegatecall" in s["memory_reads"]
        # Both copies start at 0 with a dynamic length, so they run over the free pointer (0x40) —
        # classified by the whole range, not just the start offset (which would say "scratch").
        assert "calldatacopy(free_memory_pointer_unbounded)" in s["memory_writes"]
        assert "returndatacopy(free_memory_pointer_unbounded)" in s["memory_writes"]
        # impl.slot read is storage with slot-binding provenance.
        assert s["storage_reads"] == ["sload(slot_binding)"]

    def test_interface_above_proxy_does_not_shadow_the_fallback(self):
        # #207's span finder has no bodiless-declaration guard; the body-aware matcher must still
        # attribute the block to the fallback, not the interface method declared above it.
        src = "interface I { function impl() external view returns (address); }\n" + PROXY
        plans = mine_yul_assembly_safety(src, Path("Proxy.sol"))
        assert plans[0].enclosing_function == "fallback"

    def test_unnamed_legacy_fallback_is_recognised(self):
        src = "contract C { function () payable { assembly { sstore(0, 1) } } }"
        [plan] = mine_yul_assembly_safety(src, Path("c.sol"))
        assert plan.enclosing_function == "fallback"

    def test_extent_crossing_into_the_pointer_is_not_scratch(self):
        # mstore(0x24, _) writes [0x24, 0x44) — a 32-byte write that spills over the free pointer.
        src = "contract C { function f() external { assembly { mstore(0x24, 1) } } }"
        assert _summary(src)["f"]["memory_writes"] == ["mstore(free_memory_pointer)"]

    def test_enclosing_context_recovers_fallback(self):
        # #207's extractor returns "unknown" for a fallback; this phase recovers the name.
        plans = mine_yul_assembly_safety(PROXY, Path("Proxy.sol"))
        assert plans[0].enclosing_function == "fallback"

    def test_safe_proxy_idiom_has_no_hazard(self):
        # returndatacopy forwarded by return(0, ...) is the safe idiom — detector suppresses it.
        assert _cats(PROXY, "Proxy.sol") == []


class TestMemoryRegionClassification:
    def test_regions(self):
        src = """
        contract C { function f() external { assembly {
          mstore(0x20, 1)      // scratch
          mstore(0x40, 0x80)   // free_memory_pointer
          mstore(0x60, 0)      // zero_slot
          mstore(0x80, 2)      // fixed
          mstore(add(x, 1), 3) // computed
        } } }
        """
        writes = _summary(src)["f"]["memory_writes"]
        assert "mstore(scratch)" in writes
        assert "mstore(free_memory_pointer)" in writes
        assert "mstore(zero_slot)" in writes
        assert "mstore(fixed)" in writes
        assert "mstore(computed)" in writes

    def test_slot_is_a_word_not_a_byte(self):
        # The free-pointer slot is [0x40, 0x60) and the zero slot [0x60, 0x80): a write anywhere
        # inside the word corrupts it, not only one landing on 0x40 / 0x60.
        hi = (
            "contract C { function f() external { assembly { mstore8(0x5f, 1) } } }"  # pointer tail
        )
        assert _summary(hi)["f"]["memory_writes"] == ["mstore8(free_memory_pointer)"]
        # mstore(0x50, _) writes [0x50, 0x70): spans the pointer slot tail and the zero slot — the
        # pointer corruption is reported first.
        span = "contract C { function f() external { assembly { mstore(0x50, 1) } } }"
        assert _summary(span)["f"]["memory_writes"] == ["mstore(free_memory_pointer)"]


class TestMemoryWritersBeyondMstore:
    def test_copy_opcodes_are_memory_writes(self):
        # extcodecopy's destination is its 2nd arg, not the 1st.
        src = """
        contract C { function f() external { assembly {
          codecopy(0x80, 0, 32)
          extcodecopy(addr, 0x100, 0, 32)
          mcopy(0x120, 0, 32)
        } } }
        """
        writes = _summary(src)["f"]["memory_writes"]
        assert "codecopy(fixed)" in writes
        assert "extcodecopy(fixed)" in writes  # 0x100 (2nd arg), not addr
        assert "mcopy(fixed)" in writes


class TestStorageProvenance:
    def test_literal_slot(self):
        src = "contract C { function f() external { assembly { sstore(0, 1) } } }"
        assert _summary(src)["f"]["storage_writes"] == ["sstore(literal)"]

    def test_keccak_slot(self):
        src = "contract C { function f() external { assembly { sstore(keccak256(0, 64), 1) } } }"
        assert _summary(src)["f"]["storage_writes"] == ["sstore(keccak)"]

    def test_bare_identifier_slot_resolves_one_let_level(self):
        # sstore(s, _) where `let s := keccak256(...)` is classified by the binding, not "computed".
        src = """
        contract C { function f() external { assembly {
          let s := keccak256(0, 64)
          sstore(s, 1)
        } } }
        """
        assert _summary(src)["f"]["storage_writes"] == ["sstore(keccak)"]

    def test_external_param_slot_is_tainted(self):
        src = "contract C { function f(uint k) external { assembly { sstore(k, 1) } } }"
        assert _summary(src)["f"]["storage_writes"] == ["sstore(tainted_param)"]

    def test_internal_param_slot_is_not_tainted(self):
        # An internal function's parameter is chosen by the contract, not an attacker.
        src = "contract C { function f(uint k) internal { assembly { sstore(k, 1) } } }"
        assert _summary(src)["f"]["storage_writes"] == ["sstore(computed)"]

    def test_transient_storage_kept_out_of_storage_fields(self):
        src = "contract C { function f() external { assembly { tstore(0, 1) let v := tload(0) } } }"
        s = _summary(src)["f"]
        assert s["storage_writes"] == [] and s["storage_reads"] == []
        assert "tstore" in s["instructions"] and "tload" in s["instructions"]


class TestEnclosingContext:
    def test_constructor_and_modifier(self):
        src = """
        contract C {
          constructor() { assembly { sstore(0, 1) } }
          modifier m() { assembly { pop(gas()) } _; }
          receive() external payable { assembly { sstore(1, 2) } }
        }
        """
        names = {p.enclosing_function for p in mine_yul_assembly_safety(src, Path("c.sol"))}
        assert {"constructor", "m", "receive"} <= names


class TestDetectorBackedHazards:
    def test_arbitrary_sstore_maps_to_sdd_category(self):
        src = (
            "contract C { function f(uint slot) external { assembly { sstore(slot, caller()) } } }"
        )
        assert "arbitrary_storage_write" in _cats(src)

    def test_memory_safe_violation_maps(self):
        src = """
        contract C { function f() external view {
          assembly ("memory-safe") { mstore(0x40, 0x20) }
        } }
        """
        assert "unsafe_memory_safe_annotation" in _cats(src)

    def test_every_hazard_carries_a_negative_check(self):
        src = "contract C { function f(uint slot) external { assembly { sstore(slot, 1) } } }"
        plans = mine_yul_assembly_safety(src, Path("c.sol"))
        hz = [h for p in plans for h in p.hazards]
        assert hz and all(h.negative_checks for h in hz)

    def test_evaluated_categories_recorded_even_when_no_hazard(self):
        # A benign block must still report WHICH categories were checked, so empty != "all clean".
        src = "contract C { function f() external { assembly { let x := mload(0x40) } } }"
        [plan] = mine_yul_assembly_safety(src, Path("c.sol"))
        d = plan.to_dict()
        assert d["hazards"] == []
        assert d["metadata"]["evaluated_hazard_categories"] == list(_EVALUATED_CATEGORIES)
        assert d["metadata"]["deferred_hazard_categories"] == list(_DEFERRED_CATEGORIES)


class TestAdvisoryContractAndParser:
    def test_no_assembly_returns_empty(self):
        assert mine_yul_assembly_safety("contract C { function f() external {} }") == []
        assert mine_yul_assembly_safety("") == []

    def test_promotion_state_stays_hypothesis_never_a_finding(self):
        [plan] = mine_yul_assembly_safety(
            "contract C { function f() external { assembly { sstore(0,1) } } }", Path("c.sol")
        )
        d = plan.to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        assert "severity" not in d  # advisory plan, not a Finding

    def test_parser_round_trip(self):
        plans = mine_yul_assembly_safety(PROXY, Path("Proxy.sol"))
        data = {"yul_assembly_safety_plans": [p.to_dict() for p in plans]}
        reparsed = parse_yul_assembly_safety_plans(data)
        assert len(reparsed) == len(plans)
        s = reparsed[0].summary
        assert s is not None and "delegatecall" in s.external_effects

    def test_parser_drops_unknown_hazard_category(self):
        data = {
            "plans": [
                {
                    "objective": "o",
                    "assembly_summary": {"dialect": "evm"},
                    "hazards": [
                        {"category": "made_up", "negative_checks": ["x"]},
                        {"category": "arbitrary_storage_write", "negative_checks": ["y"]},
                    ],
                }
            ]
        }
        [plan] = parse_yul_assembly_safety_plans(data)
        assert [h.category for h in plan.hazards] == ["arbitrary_storage_write"]

    def test_unknown_category_normalizes_in_to_dict(self):
        assert YulHazard(category="nope").to_dict()["category"] == "unclassified"

    def test_source_anchor_survives_to_dict_and_parser(self):
        plans = mine_yul_assembly_safety(PROXY, Path("Proxy.sol"))
        anchor = plans[0].to_dict()["source_anchor"]
        assert anchor.startswith("Proxy.sol:") and anchor.split(":")[1].isdigit()
        data = {"yul_assembly_safety_plans": [p.to_dict() for p in plans]}
        assert parse_yul_assembly_safety_plans(data)[0].source_anchor == anchor

    def test_parsed_plan_does_not_claim_evaluated_categories(self):
        # Only the miner (which ran the detector) stamps evaluated_hazard_categories; a plan rebuilt
        # from provider output must not claim the detector checked anything.
        [plan] = parse_yul_assembly_safety_plans({"plans": [{"objective": "o"}]})
        assert "evaluated_hazard_categories" not in plan.to_dict()["metadata"]

    def test_miner_plan_does_claim_evaluated_categories(self):
        [plan] = mine_yul_assembly_safety(
            "contract C { function f() external { assembly { sstore(0,1) } } }", Path("c.sol")
        )
        assert plan.to_dict()["metadata"]["evaluated_hazard_categories"] == list(
            _EVALUATED_CATEGORIES
        )

    def test_parser_drops_hazard_without_negative_check(self):
        data = {
            "plans": [
                {
                    "objective": "o",
                    "assembly_summary": {"dialect": "evm"},
                    "hazards": [{"category": "arbitrary_storage_write"}],
                }
            ]
        }
        [plan] = parse_yul_assembly_safety_plans(data)
        assert plan.hazards == []

    def test_summary_dialect_normalizes(self):
        assert AssemblySummary(dialect="weird").to_dict()["dialect"] == "unknown"
