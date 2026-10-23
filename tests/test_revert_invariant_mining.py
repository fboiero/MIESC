"""
Unit tests for the deterministic revert-invariant guard miner (SDD Phase 1).

Covers guard extraction per kind, defensive-category normalization, source anchoring, the
provider-neutral parser round-trip, and the advisory contract (plans, never Findings).
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.revert_invariant_mining import (
    GuardInventoryItem,
    RevertInvariantOraclePlan,
    mine_revert_invariants,
    parse_revert_invariant_plans,
)


def _wrap(body: str, sig: str = "f() public") -> str:
    return f"contract C {{\n  function {sig} {{\n    {body}\n  }}\n}}\n"


def _guards(src: str) -> list:
    plans = mine_revert_invariants(src)
    return plans[0].guard_inventory if plans else []


def _kinds(src: str) -> set:
    return {g.guard_kind for g in _guards(src)}


def _categories(src: str) -> set:
    return {g.defensive_category for g in _guards(src)}


class TestGuardKinds:
    def test_require_and_assert(self):
        src = _wrap("require(x > 0, 'bad'); assert(y == 1);")
        assert _kinds(src) == {"require", "assert"}

    def test_custom_error_revert(self):
        src = _wrap("if (x == 0) revert ZeroAmount();")
        # the `if (...) revert` form and the custom-error form both fire here
        assert "custom_error" in _kinds(src) or "if_revert" in _kinds(src)

    def test_if_revert_and_throw(self):
        assert "if_revert" in _kinds(_wrap("if (msg.sender != owner) revert();"))
        assert "if_revert" in _kinds(_wrap("if (x == 0) throw;"))

    def test_no_guards_returns_empty(self):
        assert mine_revert_invariants(_wrap("uint256 z = x + 1;")) == []

    def test_empty_source(self):
        assert mine_revert_invariants("") == []
        assert mine_revert_invariants("   ") == []


class TestCategoryNormalization:
    def test_access_control(self):
        assert "access_control" in _categories(_wrap("require(msg.sender == owner);"))

    def test_signature_verification(self):
        src = _wrap("require(ecrecover(h, v, r, s) == signer);")
        assert "signature_verification" in _categories(src)

    def test_replay_prevention(self):
        assert "replay_prevention" in _categories(_wrap("require(!used[hash]);"))

    def test_bounds_check(self):
        assert "bounds_check" in _categories(_wrap("require(index < arr.length);"))

    def test_unclassified_fallback(self):
        # a predicate with no category keyword and no comparison operator
        cats = _categories(_wrap("require(initialized);"))
        assert "unclassified" in cats


class TestAnchoringAndContract:
    def test_anchor_has_file_and_line_and_function(self):
        src = _wrap("require(msg.sender == owner);", sig="adminOnly() external")
        guards = _guards(src)
        assert guards, "expected a guard"
        g = guards[0]
        assert g.source_anchor.startswith("<memory>:")
        assert int(g.source_anchor.split(":")[1]) >= 1
        assert g.function == "adminOnly"

    def test_file_name_used_as_anchor(self):
        src = _wrap("require(x > 0);")
        plans = mine_revert_invariants(src, Path("/tmp/Token.sol"))
        assert plans[0].guard_inventory[0].source_anchor.startswith("Token.sol:")

    def test_returns_plans_not_findings(self):
        plans = mine_revert_invariants(_wrap("require(msg.sender == owner);"))
        assert plans and isinstance(plans[0], RevertInvariantOraclePlan)
        # advisory: a plan is not a Finding (no severity), and promotion starts as hypothesis
        assert not hasattr(plans[0], "severity")
        assert plans[0].to_dict()["promotion"]["state"] == "hypothesis"
        assert plans[0].to_dict()["metadata"]["capability"] == "revert_invariant_mining"


class TestParserRoundTrip:
    def test_to_dict_parse_round_trip(self):
        src = _wrap("require(msg.sender == owner); require(amount <= cap);")
        plan = mine_revert_invariants(src)[0]
        parsed = parse_revert_invariant_plans({"revert_invariant_plans": [plan.to_dict()]})
        assert len(parsed) == 1
        assert len(parsed[0].guard_inventory) == len(plan.guard_inventory)
        assert {g.defensive_category for g in parsed[0].guard_inventory} == {
            g.defensive_category for g in plan.guard_inventory
        }

    def test_parser_rejects_garbage(self):
        assert parse_revert_invariant_plans("not json") == []
        assert parse_revert_invariant_plans(42) == []
        assert parse_revert_invariant_plans({"revert_invariant_plans": "nope"}) == []

    def test_parser_bounded_and_skips_empty_objective(self):
        item = GuardInventoryItem(
            source_anchor="x:1", function="f", guard_kind="require", predicate="x > 0"
        )
        plan = RevertInvariantOraclePlan(id="p", objective="o", guard_inventory=[item])
        parsed = parse_revert_invariant_plans({"plans": [plan.to_dict(), {"objective": ""}]})
        assert len(parsed) == 1  # the empty-objective entry is dropped
