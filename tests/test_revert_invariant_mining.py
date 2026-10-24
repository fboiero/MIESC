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


class TestReviewFixes:
    def test_predicate_not_truncated_on_inner_comma(self):
        # require(f(a, b), "msg") -> predicate keeps the full call, message is the string
        g = _guards(_wrap('require(hasRole(ROLE, msg.sender), "bad");'))[0]
        assert g.predicate == "hasRole(ROLE, msg.sender)"
        assert g.error_signal == "bad"

    def test_guard_inside_modifier_anchors_to_modifier(self):
        src = (
            "contract C {\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function f() public onlyOwner {}\n"
            "}\n"
        )
        g = _guards(src)
        assert g and g[0].function == "onlyOwner"  # not 'unknown'

    def test_if_revert_custom_counted_once(self):
        g = _guards(_wrap("if (msg.sender != owner) revert NotOwner(msg.sender);"))
        assert len(g) == 1
        assert g[0].guard_kind == "if_revert"  # kept over the duplicate custom_error

    def test_standalone_custom_error_still_counts(self):
        g = _guards(_wrap("revert NotAllowed();"))
        assert len(g) == 1 and g[0].guard_kind == "custom_error"

    def test_not_paused_is_pause_toggle_not_replay(self):
        cats = {
            g.defensive_category for g in _guards(_wrap('require(!paused, "Pausable: paused");'))
        }
        assert "pause_toggle" in cats and "replay_prevention" not in cats

    def test_capacity_is_not_accounting_cap(self):
        cats = {g.defensive_category for g in _guards(_wrap("require(capacity > 0);"))}
        assert "accounting_cap" not in cats


class TestSpanCollection:
    def test_bodiless_declaration_does_not_produce_a_span(self):
        from miesc.llm.revert_invariant_mining import _collect_spans

        src = (
            "contract Abi { function execute(address to) external; }\n"
            "contract W { function f() public { require(msg.sender == owner); } }\n"
        )
        names = [name for _, _, name in _collect_spans(src)]
        assert names == ["f"]


class TestPhase2GapHypotheses:
    def _gaps(self, src: str):
        plans = mine_revert_invariants(src)
        return plans[0].to_dict()["gap_hypotheses"] if plans else []

    def test_within_family_inconsistency_flags_unguarded_sibling(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner, 'no'); }\n"
            "  function setTreasury(address t) external { treasury = t; }\n"
            "}\n"
        )
        gaps = self._gaps(src)
        assert len(gaps) == 1
        assert gaps[0]["affected_functions"] == ["setTreasury"]
        assert gaps[0]["category"] == "access_control"
        assert gaps[0]["observed_gap"] == "inconsistent"
        assert gaps[0]["negative_checks"]

    def test_modifier_guarded_sibling_is_not_a_gap(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function setFee(uint x) external { require(msg.sender == owner, 'no'); }\n"
            "  function setTreasury(address t) external onlyOwner { treasury = t; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_different_family_is_not_a_gap(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function deposit() external payable { bal += msg.value; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_family_with_no_guarded_member_is_not_a_gap(self):
        src = (
            "contract C {\n"
            "  function setFee(uint x) external { fee = x; }\n"
            "  function setTreasury(address t) external { treasury = t; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_internal_sibling_is_skipped(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function _setTreasury(address t) internal { treasury = t; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_view_sibling_is_skipped(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setView() external view returns (uint) { return fee; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_gap_hypotheses_round_trip_through_parser(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setTreasury(address t) external { treasury = t; }\n"
            "}\n"
        )
        plan = mine_revert_invariants(src)[0]
        parsed = parse_revert_invariant_plans({"revert_invariant_plans": [plan.to_dict()]})
        assert len(parsed) == 1
        assert len(parsed[0].gap_hypotheses) == 1
        assert parsed[0].gap_hypotheses[0].affected_functions == ["setTreasury"]

    def test_gap_plan_is_advisory_never_a_finding(self):
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setTreasury(address t) external { treasury = t; }\n"
            "}\n"
        )
        plan = mine_revert_invariants(src)[0]
        assert not hasattr(plan, "severity")
        assert plan.to_dict()["promotion"]["state"] == "hypothesis"

    def test_opaque_modifier_excludes_sibling_not_flags_it(self):
        # onlyRole delegates to an internal check: its body has no anchored guard, so the sibling
        # is opaque, not unguarded -> no hypothesis (SDD FP control: a modifier may enforce it).
        src = (
            "contract C {\n"
            "  modifier onlyRole(bytes32 r) { _checkRole(r); _; }\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setTreasury(address t) external onlyRole(ADMIN) { treasury = t; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_inherited_modifier_is_opaque(self):
        # onlyOwner is not defined in this file (inherited) -> opaque -> excluded.
        src = (
            "contract C {\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setTreasury(address t) external onlyOwner { treasury = t; }\n"
            "}\n"
        )
        assert self._gaps(src) == []

    def test_interface_declaration_does_not_contaminate_functions(self):
        src = (
            "interface I { function setFee(uint) external; }\n"
            "contract C {\n"
            "  function setFee(uint x) external { require(msg.sender == owner); }\n"
            "  function setTreasury(address t) external { treasury = t; }\n"
            "}\n"
        )
        gaps = self._gaps(src)
        assert len(gaps) == 1 and gaps[0]["affected_functions"] == ["setTreasury"]


class TestPhase2PauseGaps:
    def _cats(self, src):
        p = mine_revert_invariants(src)
        return [
            (g["category"], g["affected_functions"])
            for g in (p[0].to_dict()["gap_hypotheses"] if p else [])
        ]

    def test_pause_gap_on_user_mutator_same_file_modifier(self):
        src = (
            "contract C {\n"
            "  bool paused;\n"
            "  modifier whenNotPaused() { require(!paused); _; }\n"
            "  function deposit() external whenNotPaused { bal += 1; }\n"
            "  function withdraw() external { bal -= 1; }\n"
            "}\n"
        )
        assert ("pause_toggle", ["withdraw"]) in self._cats(src)

    def test_privileged_functions_excluded_from_pause_family(self):
        # pause()/setFee are privileged; only deposit is a user mutator -> no pause family of >=2
        src = (
            "contract C {\n"
            "  bool paused; address owner;\n"
            "  modifier whenNotPaused() { require(!paused); _; }\n"
            "  function deposit() external whenNotPaused { bal += 1; }\n"
            "  function pause() external { require(msg.sender == owner); paused = true; }\n"
            "  function setFee(uint x) external { require(msg.sender == owner); fee = x; }\n"
            "}\n"
        )
        assert all(c != "pause_toggle" for c, _ in self._cats(src))

    def test_inherited_pausable_is_opaque_so_silent(self):
        src = (
            "contract C is Pausable {\n"
            "  function deposit() external whenNotPaused { bal += 1; }\n"
            "  function withdraw() external { bal -= 1; }\n"
            "}\n"
        )
        assert self._cats(src) == []


class TestPhase2FreshnessGaps:
    def _cats(self, src):
        p = mine_revert_invariants(src)
        return [
            (g["category"], g["affected_functions"])
            for g in (p[0].to_dict()["gap_hypotheses"] if p else [])
        ]

    def test_freshness_gap_on_unreferenced_deadline_sibling(self):
        # `a` enforces the deadline; `b` takes one and never references it -> gap on `b`.
        src = (
            "contract C {\n"
            "  function a(uint256 deadline, uint256 x) external {\n"
            '    require(block.timestamp <= deadline, "expired"); _do(x);\n'
            "  }\n"
            "  function b(uint256 deadline, uint256 y) external { _do(y); }\n"
            "}\n"
        )
        assert ("freshness_check", ["b"]) in self._cats(src)

    def test_same_file_ensure_modifier_is_guarded_so_silent(self):
        # The DEX-router shape: every deadline function carries one `ensure(deadline)` modifier.
        src = (
            "contract R {\n"
            "  modifier ensure(uint256 deadline) {\n"
            '    require(deadline >= block.timestamp, "EXPIRED"); _;\n'
            "  }\n"
            "  function swapA(uint256 deadline, uint256 x) external ensure(deadline) { _do(x); }\n"
            "  function swapB(uint256 deadline, uint256 y) external ensure(deadline) { _do(y); }\n"
            "}\n"
        )
        assert self._cats(src) == []

    def test_forwarded_deadline_is_opaque_so_silent(self):
        # `b` forwards the deadline into an inner call -> delegated, opaque, not a gap.
        src = (
            "contract C {\n"
            "  function a(uint256 deadline, uint256 x) external {\n"
            '    require(block.timestamp <= deadline, "e"); _do(x);\n'
            "  }\n"
            "  function b(uint256 deadline, uint256 y) external { _settle(y, deadline); }\n"
            "}\n"
        )
        assert self._cats(src) == []

    def test_stored_deadline_is_opaque_so_silent(self):
        # Storing the value references it -> opaque; a checked sibling does not force a gap.
        src = (
            "contract C {\n"
            "  mapping(uint256 => uint256) end;\n"
            "  function a(uint256 deadline, uint256 x) external {\n"
            '    require(block.timestamp <= deadline, "e"); _do(x);\n'
            "  }\n"
            "  function createOrder(uint256 id, uint256 expiry) external { end[id] = expiry; }\n"
            "}\n"
        )
        assert self._cats(src) == []

    def test_group_of_one_is_silent(self):
        # A single deadline function has no sibling to be inconsistent with.
        src = (
            "contract C {\n"
            "  function a(uint256 deadline, uint256 x) external { _do(x); }\n"
            "  function other(uint256 y) external { _do(y); }\n"
            "}\n"
        )
        assert self._cats(src) == []

    def test_gap_is_advisory_hypothesis_never_a_finding(self):
        src = (
            "contract C {\n"
            "  function a(uint256 deadline, uint256 x) external {\n"
            '    require(block.timestamp <= deadline, "e"); _do(x);\n'
            "  }\n"
            "  function b(uint256 deadline, uint256 y) external { _do(y); }\n"
            "}\n"
        )
        plan = mine_revert_invariants(src)[0].to_dict()
        gap = next(g for g in plan["gap_hypotheses"] if g["category"] == "freshness_check")
        assert plan["promotion"]["state"] == "hypothesis"
        assert "finding" not in plan
        assert any("interface/ABI" in nc for nc in gap["negative_checks"])
