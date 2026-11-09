"""Tests for the advisory gap-hypothesis -> sequence-oracle bridge."""

from __future__ import annotations

from miesc.llm.agentic_contracts import parse_sequence_oracle_plans
from miesc.llm.revert_invariant_bridge import bridge_revert_invariant_plans
from miesc.llm.revert_invariant_mining import mine_revert_invariants

# Synthetic contracts that each produce exactly one gap hypothesis (mirroring the TestPhase2*
# fixtures in test_revert_invariant_mining.py), so the bridge has a non-dead input.
_ACCESS_CONTROL = (
    "contract C {\n"
    "  address owner;\n"
    "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
    "  function setFee(uint x) external onlyOwner { fee = x; }\n"
    "  function setTreasury(address a) external { treasury = a; }\n"
    "}\n"
)
_PAUSE = (
    "contract C {\n"
    "  bool paused;\n"
    "  modifier whenNotPaused() { require(!paused); _; }\n"
    "  function deposit() external whenNotPaused { bal += 1; }\n"
    "  function withdraw() external { bal -= 1; }\n"
    "}\n"
)
_FRESHNESS = (
    "contract C {\n"
    "  function a(uint256 deadline, uint256 x) external {\n"
    '    require(block.timestamp <= deadline, "expired"); _do(x);\n'
    "  }\n"
    "  function b(uint256 deadline, uint256 y) external { _do(y); }\n"
    "}\n"
)


def _bridged(src: str):
    return bridge_revert_invariant_plans(mine_revert_invariants(src))


class TestBridgeRoundTrip:
    """The real negative control: bridged plans must survive parse_sequence_oracle_plans,
    or the rest of MIESC silently discards them."""

    def test_access_control_round_trips(self):
        bridged = _bridged(_ACCESS_CONTROL)
        assert len(bridged) >= 1
        reparsed = parse_sequence_oracle_plans({"plans": [p.to_dict() for p in bridged]})
        assert len(reparsed) == len(bridged)

    def test_pause_round_trips(self):
        bridged = _bridged(_PAUSE)
        assert len(bridged) >= 1
        reparsed = parse_sequence_oracle_plans({"plans": [p.to_dict() for p in bridged]})
        assert len(reparsed) == len(bridged)

    def test_freshness_round_trips(self):
        bridged = _bridged(_FRESHNESS)
        assert len(bridged) >= 1
        reparsed = parse_sequence_oracle_plans({"plans": [p.to_dict() for p in bridged]})
        assert len(reparsed) == len(bridged)


class TestBridgeFidelity:
    def test_affected_functions_become_steps(self):
        bridged = _bridged(_PAUSE)
        plan = bridged[0].to_dict()
        functions = {s["function"] for s in plan["sequence"]}
        assert "withdraw" in functions
        assert all(s["expected_effect"] for s in plan["sequence"])

    def test_negative_checks_travel_into_evidence(self):
        # A reviewer reading only the fuzz plan must still see the benign explanation.
        plan = _bridged(_ACCESS_CONTROL)[0].to_dict()
        joined = " ".join(plan["evidence"])
        assert "inherited from a base contract" in joined

    def test_confidence_is_low_and_fixed(self):
        for src in (_ACCESS_CONTROL, _PAUSE, _FRESHNESS):
            for p in _bridged(src):
                assert p.to_dict()["confidence"] == 0.2

    def test_category_maps_to_vulnerability_types(self):
        plan = _bridged(_FRESHNESS)[0].to_dict()
        assert "missing-deadline-check" in plan["vulnerability_types"]
        assert plan["metadata"]["source_gap_category"] == "freshness_check"
        assert plan["metadata"]["advisory"] == "true"

    def test_ids_are_distinct_per_gap(self):
        # A contract with two privileged verb families -> two access-control gaps -> two plans
        # with distinct ids (no collision).
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function setFee(uint x) external onlyOwner { fee = x; }\n"
            "  function setTreasury(address a) external { treasury = a; }\n"
            "  function upgradeTo(address a) external onlyOwner { impl = a; }\n"
            "  function upgradeAndCall(address a) external { impl = a; }\n"
            "}\n"
        )
        bridged = _bridged(src)
        ids = [p.to_dict()["id"] for p in bridged]
        assert len(ids) == len(set(ids))


class TestBridgeBounds:
    def test_many_affected_functions_still_valid(self):
        # One guarded privileged sibling + 150 unguarded ones -> one gap with 150 functions.
        guarded = (
            "  address owner;\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function setA0(uint x) external onlyOwner { v = x; }\n"
        )
        siblings = "".join(
            f"  function setA{i}(uint x) external {{ v = x; }}\n" for i in range(1, 151)
        )
        src = "contract C {\n" + guarded + siblings + "}\n"
        bridged = _bridged(src)
        assert len(bridged) == 1
        d = bridged[0].to_dict()
        # bounded downstream; still a valid plan with at least one step.
        assert 1 <= len(d["sequence"]) <= 100
        reparsed = parse_sequence_oracle_plans({"plans": [d]})
        assert len(reparsed) == 1


class TestBridgeSilence:
    def test_no_gaps_yields_no_plans(self):
        # A single guarded function -> no gap hypothesis -> no bridged plans.
        src = (
            "contract C {\n"
            "  address owner;\n"
            "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
            "  function setFee(uint x) external onlyOwner { fee = x; }\n"
            "}\n"
        )
        assert _bridged(src) == []

    def test_empty_input_yields_no_plans(self):
        assert bridge_revert_invariant_plans([]) == []
        assert _bridged("") == []
