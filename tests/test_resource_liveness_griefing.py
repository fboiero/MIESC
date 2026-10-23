"""
Unit tests for the deterministic resource/liveness-griefing progress-surface miner (SDD Phase 1).

Covers growable-resource detection (array/mapping/queue), growth sources, progress-function
linking, source anchoring, the provider-neutral parser round-trip, and the advisory contract.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.resource_liveness_griefing import (
    GrowableSurface,
    ResourceLivenessGriefingPlan,
    mine_resource_liveness_griefing,
    parse_resource_liveness_plans,
)

CONTRACT = """
contract Payouts {
    address[] public recipients;
    mapping(address => uint256) public pendingWithdrawals;
    uint256[] internal withdrawalQueue;

    function enroll(address a) external { recipients.push(a); }
    function credit(address a, uint256 v) external { pendingWithdrawals[a] = v; }
    function distribute() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1);
        }
    }
    function withdraw() external {
        uint256 amt = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
    function queueWithdrawal(uint256 id) external { withdrawalQueue.push(id); }
    function processQueue() external {
        for (uint256 i = 0; i < withdrawalQueue.length; i++) { delete withdrawalQueue[i]; }
    }
    function noop() external view returns (uint256) { return 1; }
}
"""


def _plans(src):
    return mine_resource_liveness_griefing(src)


def _by_resource(src):
    return {p.surface.resource: p.surface for p in _plans(src)}


class TestResourceDetection:
    def test_array_and_mapping_and_queue_detected(self):
        res = _by_resource(CONTRACT)
        assert "recipients" in res  # dynamic array
        assert "pendingWithdrawals" in res  # mapping
        assert "withdrawalQueue" in res  # array, queue-named

    def test_resource_kind_inference(self):
        res = _by_resource(CONTRACT)
        assert res["withdrawalQueue"].resource_kind == "withdrawal_queue"
        assert res["pendingWithdrawals"].resource_kind == "pending_payment"
        assert res["recipients"].resource_kind == "array"

    def test_growth_sources(self):
        res = _by_resource(CONTRACT)
        assert "enroll" in res["recipients"].growth_sources  # .push(
        assert "credit" in res["pendingWithdrawals"].growth_sources  # [k] =

    def test_progress_functions_linked(self):
        res = _by_resource(CONTRACT)
        assert "distribute" in res["recipients"].progress_functions  # iterates recipients
        assert "withdraw" in res["pendingWithdrawals"].progress_functions

    def test_static_or_untraversed_resource_skipped(self):
        # an array nobody grows or traverses is not a progress surface
        src = "contract C { uint256[] private cache; function f() public {} }"
        assert mine_resource_liveness_griefing(src) == []


class TestContractAndAdvisory:
    def test_no_resources_returns_empty(self):
        assert mine_resource_liveness_griefing("contract C { function f() public {} }") == []

    def test_empty_source(self):
        assert mine_resource_liveness_griefing("") == []

    def test_returns_plans_not_findings(self):
        plans = _plans(CONTRACT)
        assert plans and isinstance(plans[0], ResourceLivenessGriefingPlan)
        assert not hasattr(plans[0], "severity")
        d = plans[0].to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        assert d["metadata"]["capability"] == "resource_liveness_griefing_hardening"
        assert "surface" in d

    def test_anchors_present(self):
        plans = mine_resource_liveness_griefing(CONTRACT, Path("/x/Payouts.sol"))
        assert plans[0].surface.source_anchors[0].startswith("Payouts.sol:")


class TestParserRoundTrip:
    def test_round_trip(self):
        plan = next(p for p in _plans(CONTRACT) if p.surface.resource == "recipients")
        parsed = parse_resource_liveness_plans(
            {"resource_liveness_griefing_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert parsed[0].surface.resource == "recipients"
        assert parsed[0].surface.growth_sources == plan.surface.growth_sources

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
