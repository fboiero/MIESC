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
    GrowableSurface,
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
