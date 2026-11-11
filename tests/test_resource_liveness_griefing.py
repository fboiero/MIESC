"""
Unit tests for the deterministic resource/liveness-griefing progress-surface miner (SDD Phase 1).

A surface is a growable resource that a progress-named function *traverses with a loop* (not an
O(1) per-user access). Growth is `.push(`, `+=`, or a non-clearing assignment — never `==`, `-=`,
`= 0` or `delete`. Covers detection, the growth/traversal distinction, token (not substring)
matching, source anchoring, the parser round-trip, and the advisory contract.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.resource_liveness_griefing import (
    _HYPOTHESIS_CATEGORIES,
    GrowableSurface,
    LivenessHypothesis,
    ResourceLivenessGriefingPlan,
    _is_progress_name,
    _tokenize,
    mine_resource_liveness_griefing,
    parse_resource_liveness_plans,
)

PAYOUTS = """
contract Payouts {
    address[] public depositors;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingRefunds;

    function deposit() external payable {
        if (balances[msg.sender] == 0) { depositors.push(msg.sender); }
        balances[msg.sender] += msg.value;
    }
    function payoutAll() external {
        for (uint256 i = 0; i < depositors.length; i++) {
            payable(depositors[i]).transfer(balances[depositors[i]]);
        }
    }
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
    function refundOf(address a) external view returns (uint256) { return pendingRefunds[a]; }
}
"""


def _surfaces(src, path=None):
    return {p.surface.resource: p.surface for p in mine_resource_liveness_griefing(src, path)}


class TestTraversalGate:
    def test_array_traversed_by_loop_is_a_surface(self):
        s = _surfaces(PAYOUTS)
        assert "depositors" in s
        assert "payoutAll" in s["depositors"].progress_functions  # for over depositors.length
        assert s["depositors"].resource_kind == "array"

    def test_mapping_traversed_in_loop_is_a_surface(self):
        # balances is read as balances[depositors[i]] inside payoutAll's loop
        s = _surfaces(PAYOUTS)
        assert "balances" in s
        assert "payoutAll" in s["balances"].progress_functions

    def test_o1_mapping_access_is_not_a_surface(self):
        # pendingRefunds is only read O(1) in refundOf (no loop) -> not a griefing surface
        assert "pendingRefunds" not in _surfaces(PAYOUTS)

    def test_growth_only_without_traversal_is_dropped(self):
        src = """
        contract C {
            mapping(address => uint256) bal;
            function credit(address a) external { bal[a] += 1; }
            function readOne(address a) external view returns (uint256) { return bal[a]; }
        }
        """
        assert mine_resource_liveness_griefing(src) == []


class TestGrowthRegex:
    def test_compound_assign_counts_as_growth(self):
        # deposit grows balances via `+=`
        assert "deposit" in _surfaces(PAYOUTS)["balances"].growth_sources

    def test_comparison_and_clear_are_not_growth(self):
        # withdraw only does `balances[k] == ...` (comparison) and `balances[k] = 0` (clear)
        assert "withdraw" not in _surfaces(PAYOUTS)["balances"].growth_sources

    def test_push_counts_as_growth(self):
        assert "deposit" in _surfaces(PAYOUTS)["depositors"].growth_sources


class TestTokenMatching:
    def test_tokenize(self):
        assert _tokenize("payoutAll") == ["payout", "all"]
        assert _tokenize("withdrawal_queue") == ["withdrawal", "queue"]

    def test_progress_name_by_token_not_substring(self):
        assert _is_progress_name("payoutAll")
        assert _is_progress_name("liquidatePosition")
        assert _is_progress_name("emergencyWithdraw")
        assert not _is_progress_name("preprocess")  # 'process' only as a substring
        assert not _is_progress_name("setOwner")

    def test_kind_substring_does_not_misfire(self):
        # a queue-named array traversed in a loop keeps its kind; 'task' mid-word does not
        src = """
        contract Q {
            uint256[] withdrawalQueue;
            function flush() external { for (uint256 i; i < withdrawalQueue.length; i++) { delete withdrawalQueue[i]; } }
        }
        """
        s = _surfaces(src)
        assert s and s["withdrawalQueue"].resource_kind == "withdrawal_queue"


class TestContractAndAdvisory:
    def test_no_resources_returns_empty(self):
        assert mine_resource_liveness_griefing("contract C { function f() public {} }") == []

    def test_empty_source(self):
        assert mine_resource_liveness_griefing("") == []

    def test_returns_plans_not_findings(self):
        plans = mine_resource_liveness_griefing(PAYOUTS)
        assert plans and isinstance(plans[0], ResourceLivenessGriefingPlan)
        assert not hasattr(plans[0], "severity")
        d = plans[0].to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        assert d["metadata"]["capability"] == "resource_liveness_griefing_hardening"

    def test_anchors_use_file_name(self):
        plans = mine_resource_liveness_griefing(PAYOUTS, Path("/x/Payouts.sol"))
        assert plans[0].surface.source_anchors[0].startswith("Payouts.sol:")


class TestParserRoundTrip:
    def test_round_trip(self):
        plan = next(
            p
            for p in mine_resource_liveness_griefing(PAYOUTS)
            if p.surface.resource == "depositors"
        )
        parsed = parse_resource_liveness_plans(
            {"resource_liveness_griefing_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert parsed[0].surface.resource == "depositors"
        assert parsed[0].surface.progress_functions == plan.surface.progress_functions

    def test_parser_rejects_garbage(self):
        assert parse_resource_liveness_plans("nope") == []
        assert parse_resource_liveness_plans(9) == []
        assert parse_resource_liveness_plans({"plans": "x"}) == []

    def test_parser_skips_empty_objective(self):
        good = ResourceLivenessGriefingPlan(
            id="p", objective="o", surface=GrowableSurface(resource="q", resource_kind="queue")
        )
        parsed = parse_resource_liveness_plans({"plans": [good.to_dict(), {"objective": ""}]})
        assert len(parsed) == 1


ABSTRACT_THEN_WALLET = """
contract WalletAbi {
    function execute(address to, uint value, bytes data) external returns (bytes32);
    function revoke(bytes32 op) external;
}
contract Wallet {
    uint[] public m_pendingIndex;
    mapping(uint => uint) public m_pending;
    function confirm(bytes32 op) external { m_pendingIndex.push(1); m_pending[1] = 2; }
    function clearPending() internal {
        for (uint i = 0; i < m_pendingIndex.length; ++i) { delete m_pending[m_pendingIndex[i]]; }
    }
}
"""

STRING_FOR = """
contract Channels {
    mapping(bytes32 => uint256) public channels;
    function settleVC(bytes32 id) external {
        require(channels[id] > 0, "Incorrect balances for bonded amount");
        channels[id] = 0;
    }
}
"""

LOOP_ELSEWHERE = """
contract Split {
    address[] public owners;
    mapping(address => uint256) public balances;
    function withdrawAll() external {
        uint256 amt = balances[msg.sender];
        for (uint256 i = 0; i < owners.length; i++) { emit Ping(owners[i]); }
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""


class TestLoopDetectionArtifacts:
    def test_bodiless_declaration_does_not_own_the_next_contract(self):
        plans = mine_resource_liveness_griefing(ABSTRACT_THEN_WALLET, Path("w.sol"))
        progress = {p.surface.resource: p.surface.progress_functions for p in plans if p.surface}
        # `execute` has no body: it must not appear as the function that traverses anything
        assert all("execute" not in fns for fns in progress.values())
        # `clearPending` is not a progress name either, so nothing qualifies here
        assert progress == {}

    def test_for_inside_a_string_literal_is_not_a_loop(self):
        assert mine_resource_liveness_griefing(STRING_FOR, Path("c.sol")) == []

    def test_loop_must_reference_the_resource_inside_its_body(self):
        plans = mine_resource_liveness_griefing(LOOP_ELSEWHERE, Path("s.sol"))
        resources = {p.surface.resource for p in plans if p.surface}
        assert "owners" in resources  # traversed by the for loop
        assert "balances" not in resources  # read O(1) outside the loop

    def test_while_loop_with_resource_in_condition_is_a_traversal(self):
        src = """
        contract Q { address[] public queue; uint256 public head;
          function enqueue() external { queue.push(msg.sender); }
          function processAll() external { while (head < queue.length) { head++; } } }
        """
        plans = mine_resource_liveness_griefing(src, Path("q.sol"))
        assert [p.surface.progress_functions for p in plans] == [["processAll"]]


# ======================================================================================
# Phase 2 — advisory guard-gap liveness hypotheses
# ======================================================================================
def _cats(src, path="c.sol"):
    """{resource: [hypothesis categories]} for a source."""
    return {
        p.surface.resource: [h.category for h in p.liveness_hypotheses]
        for p in mine_resource_liveness_griefing(src, Path(path))
        if p.surface
    }


# A resource grown by an unguarded, uncapped entrypoint, traversed by a progress loop with a push.
UNBOUNDED_PUSH = """
contract C {
  address[] public users;
  function join() external { users.push(msg.sender); }
  function withdrawAll() external {
    for (uint i = 0; i < users.length; i++) { payable(users[i]).transfer(1); }
  }
}
"""


class TestUnboundedLoop:
    def test_attacker_growable_unbounded_loop_fires(self):
        assert "unbounded_loop" in _cats(UNBOUNDED_PUSH)["users"]

    def test_caller_owned_slice_suppresses(self):
        # for (i = start; i < end; ) with end a parameter — a caller-owned slice (SDD l.125).
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function claimRange(uint s, uint e) external {
            require(e <= u.length);
            for (uint i = s; i < e; i++) { payable(u[i]).transfer(1); } } }
        """
        assert "unbounded_loop" not in _cats(src)["u"]

    def test_admin_grown_list_suppresses(self):
        # strategies is only grown behind onlyOwner: not attacker-controlled (SDD l.129).
        src = """
        contract C { address[] public strategies;
          function addStrategy(address s) external onlyOwner { strategies.push(s); }
          function distribute() external {
            for (uint i = 0; i < strategies.length; i++) { payable(strategies[i]).transfer(1); } } }
        """
        assert "unbounded_loop" not in _cats(src)["strategies"]

    def test_length_capped_growth_suppresses(self):
        src = """
        contract C { address[] public u;
          function join() external { require(u.length < 100); u.push(msg.sender); }
          function withdrawAll() external {
            for (uint i = 0; i < u.length; i++) { payable(u[i]).transfer(1); } } }
        """
        assert "unbounded_loop" not in _cats(src)["u"]

    def test_clamped_bound_suppresses(self):
        # end = min(start+n, u.length) via a ternary clamp — not driven by the raw length.
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function claimClamped(uint s, uint n) external {
            uint e = s + n < u.length ? s + n : u.length;
            for (uint i = s; i < e; i++) { payable(u[i]).transfer(1); } } }
        """
        assert "unbounded_loop" not in _cats(src)["u"]

    def test_cached_length_solely_equal_fires(self):
        # uint len = u.length; for (i < len) — the dominant unsafe cached-length form.
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function redeemAll() external {
            uint len = u.length;
            for (uint i = 0; i < len; i++) { payable(u[i]).transfer(1); } } }
        """
        assert "unbounded_loop" in _cats(src)["u"]

    def test_mapping_resource_does_not_seed_unbounded_loop(self):
        # A mapping has no .length to drive a loop; the array driving the loop owns the hypothesis.
        src = """
        contract C { address[] public u; mapping(address => uint) public bal;
          function join() external { u.push(msg.sender); bal[msg.sender] = 1; }
          function withdrawAll() external {
            for (uint i = 0; i < u.length; i++) { payable(u[i]).transfer(bal[u[i]]); } } }
        """
        cats = _cats(src)
        assert "unbounded_loop" in cats["u"]
        assert "unbounded_loop" not in cats.get("bal", [])


class TestPushPaymentBlocking:
    def test_unisolated_push_fires(self):
        assert "push_payment_blocking" in _cats(UNBOUNDED_PUSH)["users"]

    def test_call_value_idiom_is_covered(self):
        # The DoS detector's .transfer/.send patterns miss .call{value:}; this phase catches it.
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) { (bool ok,) = u[i].call{value:1}(""); require(ok); } } }
        """
        assert "push_payment_blocking" in _cats(src)["u"]

    def test_try_catch_isolation_suppresses(self):
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) { try IR(u[i]).p{value:1}() {} catch {} } } }
        """
        assert "push_payment_blocking" not in _cats(src)["u"]

    def test_credit_on_failure_suppresses(self):
        # Nested-key credit write failed[u[i]] = true isolates the failure for a later pull.
        src = """
        contract C { address[] public u; mapping(address=>bool) failed;
          function join() external { u.push(msg.sender); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) {
              (bool ok,) = u[i].call{value:1}(""); if (!ok) { failed[u[i]] = true; } } } }
        """
        assert "push_payment_blocking" not in _cats(src)["u"]

    def test_separate_pull_payment_path_suppresses(self):
        src = """
        contract C { address[] public u; mapping(address => uint) public pendingRefunds;
          function join() external { u.push(msg.sender); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) { payable(u[i]).transfer(1); } }
          function claimRefund() external {
            uint a = pendingRefunds[msg.sender]; payable(msg.sender).transfer(a); } }
        """
        assert "push_payment_blocking" not in _cats(src)["u"]

    def test_recipient_must_index_the_resource(self):
        # IERC20(rewardTokens[i]).safeTransfer(msg.sender, amt): the resource element is the TOKEN,
        # the caller is the payee — not a push-to-each-recipient, so push must NOT fire.
        src = """
        contract C { address[] public rewardTokens;
          function addToken(address t) external onlyOwner { rewardTokens.push(t); }
          function claimAll() external {
            for (uint i = 0; i < rewardTokens.length; i++) {
              IERC20(rewardTokens[i]).safeTransfer(msg.sender, 1); } } }
        """
        assert "push_payment_blocking" not in _cats(src).get("rewardTokens", [])

    def test_onlyowner_sweep_is_not_a_pull_path(self):
        # An onlyOwner function paying msg.sender (the owner) is not a user self-service pull path,
        # so it does not suppress push over the distributed list.
        src = """
        contract C { address[] public u; mapping(address => uint) bal;
          function join() external { u.push(msg.sender); }
          function ownerWithdraw() external onlyOwner {
            payable(msg.sender).transfer(bal[msg.sender]); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) { payable(u[i]).transfer(1); } } }
        """
        assert "push_payment_blocking" in _cats(src)["u"]


class TestPushIsolationEdges:
    def test_plain_indexed_write_does_not_isolate_a_hard_transfer(self):
        # paid[i] = true before a .transfer() is tracking, not isolation: .transfer reverts the
        # whole frame, so the credit never runs. Push must still fire.
        src = """
        contract C { address[] public u; mapping(uint=>bool) paid;
          function join() external { u.push(msg.sender); }
          function distribute() external {
            for (uint i = 0; i < u.length; i++) { paid[i] = true; payable(u[i]).transfer(1); } } }
        """
        assert "push_payment_blocking" in _cats(src)["u"]

    def test_paginated_bound_also_suppresses_push(self):
        # A caller-chosen (start, end) lets the caller skip a reverting index, so push is suppressed.
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function claimRange(uint s, uint e) external {
            require(e <= u.length);
            for (uint i = s; i < e; i++) { payable(u[i]).transfer(1); } } }
        """
        assert _cats(src)["u"] == []


class TestRealFixtures:
    """Positives on the feature's own canonical fixture and a real SmartBugs DoS sample."""

    PAYOUTS = """
    contract Payouts { address[] public depositors;
      mapping(address => uint256) public balances;
      function deposit() external payable {
        if (balances[msg.sender] == 0) { depositors.push(msg.sender); }
        balances[msg.sender] += msg.value; }
      function payoutAll() external {
        for (uint256 i = 0; i < depositors.length; i++) {
          payable(depositors[i]).transfer(balances[depositors[i]]); } }
      function withdraw() external {
        uint256 a = balances[msg.sender]; balances[msg.sender] = 0;
        payable(msg.sender).transfer(a); } }
    """

    def test_payouts_fires_unbounded_but_pull_path_suppresses_push(self):
        # deposit() is open growth (the if(balances[msg.sender]==0) dedup is not access control);
        # withdraw() is a self-service pull path, so push is suppressed, unbounded is not.
        assert _cats(self.PAYOUTS, "P.sol")["depositors"] == ["unbounded_loop"]

    def test_send_loop_style_require_send_in_loop_fires_push(self):
        # SmartBugs send_loop.sol: require(list[x].send(...)) over a constructor-filled list. The
        # constructor push is not an entrypoint, so the list is not attacker-growable (no
        # unbounded_loop); but a single reverting recipient blocks all refunds, and `refunds` is only
        # a lookup, not a pull path — so exactly push_payment_blocking fires.
        src = """
        contract Refunder { address[] private refundAddresses;
          mapping (address => uint) public refunds;
          constructor() { refundAddresses.push(msg.sender); }
          function refundAll() public {
            for (uint x; x < refundAddresses.length; x++) {
              require(refundAddresses[x].send(refunds[refundAddresses[x]])); } } }
        """
        assert _cats(src)["refundAddresses"] == ["push_payment_blocking"]


class TestEntrypointGate:
    def test_internal_and_view_functions_do_not_seed(self):
        # The only loop lives in an internal helper and a view — neither is attack surface.
        src = """
        contract C { address[] public u;
          function join() external { u.push(msg.sender); }
          function _withdrawAll() internal {
            for (uint i = 0; i < u.length; i++) { payable(u[i]).transfer(1); } }
          function claimView() external view returns (uint) {
            uint t; for (uint i = 0; i < u.length; i++) { t += 1; } return t; } }
        """
        # `u` is still a Phase 1 surface (claimView traverses it), but no entrypoint seeds a loop.
        assert _cats(src).get("u", []) == []


class TestRealProtocolNoFalsePositive:
    def test_compound_style_admin_grown_markets_yield_no_hypotheses(self):
        # allMarkets grows only behind onlyAdmin; claimComp is public with no push — zero hypotheses.
        src = """
        contract Comptroller { CToken[] public allMarkets;
          function _supportMarket(CToken c) external onlyAdmin { allMarkets.push(c); }
          function claimComp(address holder) public {
            for (uint i = 0; i < allMarkets.length; i++) { distribute(allMarkets[i], holder); } } }
        """
        assert _cats(src)["allMarkets"] == []


class TestLivenessHypothesisParser:
    def test_round_trip_preserves_categories(self):
        plans = mine_resource_liveness_griefing(UNBOUNDED_PUSH, Path("c.sol"))
        data = {"resource_liveness_griefing_plans": [p.to_dict() for p in plans]}
        reparsed = parse_resource_liveness_plans(data)
        cats = {h.category for p in reparsed for h in p.liveness_hypotheses}
        assert {"unbounded_loop", "push_payment_blocking"} <= cats

    def test_singular_sdd_key_is_accepted(self):
        data = {
            "plans": [
                {
                    "objective": "o",
                    "surface": {"resource": "q"},
                    "liveness_hypothesis": {
                        "category": "keeper_blocking",
                        "attacker_action": "keeper withholds",
                        "negative_checks": ["any keeper can act"],
                    },
                }
            ]
        }
        [plan] = parse_resource_liveness_plans(data)
        assert [h.category for h in plan.liveness_hypotheses] == ["keeper_blocking"]

    def test_unknown_category_dropped(self):
        data = {
            "plans": [
                {
                    "objective": "o",
                    "surface": {"resource": "q"},
                    "liveness_hypotheses": [
                        {"category": "made_up", "negative_checks": ["x"]},
                        {"category": "unbounded_loop", "negative_checks": ["y"]},
                    ],
                }
            ]
        }
        [plan] = parse_resource_liveness_plans(data)
        assert [h.category for h in plan.liveness_hypotheses] == ["unbounded_loop"]

    def test_hypothesis_without_negative_check_dropped(self):
        data = {
            "plans": [
                {
                    "objective": "o",
                    "surface": {"resource": "q"},
                    "liveness_hypotheses": [{"category": "unbounded_loop"}],
                }
            ]
        }
        [plan] = parse_resource_liveness_plans(data)
        assert plan.liveness_hypotheses == []


class TestAdvisoryContract:
    def test_every_hypothesis_carries_a_negative_check(self):
        plans = mine_resource_liveness_griefing(UNBOUNDED_PUSH, Path("c.sol"))
        hyps = [h for p in plans for h in p.liveness_hypotheses]
        assert hyps and all(h.negative_checks for h in hyps)

    def test_promotion_state_stays_hypothesis(self):
        [plan] = mine_resource_liveness_griefing(UNBOUNDED_PUSH, Path("c.sol"))
        assert plan.to_dict()["promotion"]["state"] == "hypothesis"

    def test_all_emitted_categories_are_in_the_schema(self):
        plans = mine_resource_liveness_griefing(UNBOUNDED_PUSH, Path("c.sol"))
        for p in plans:
            for h in p.liveness_hypotheses:
                assert h.category in _HYPOTHESIS_CATEGORIES

    def test_unknown_category_normalizes_to_unclassified_in_to_dict(self):
        h = LivenessHypothesis(category="nope", negative_checks=["x"])
        assert h.to_dict()["category"] == "unclassified"
