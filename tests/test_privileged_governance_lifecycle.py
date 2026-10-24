"""
Unit tests for the deterministic privileged-governance authority miner (SDD Phase 1).

Covers actor detection per kind, AccessControl role + grant/revoke extraction, edges, source
anchoring, the provider-neutral parser round-trip, and the advisory contract (plans, not Findings).
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.privileged_governance_lifecycle import (
    GovernanceActor,
    PrivilegedGovernanceLifecyclePlan,
    mine_privileged_governance_lifecycle,
    parse_privileged_governance_plans,
)

CONTRACT = """
contract Gov {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER");
    address owner;
    function setFee() external onlyOwner { fee = 1; }
    function pause() external onlyPauser { paused = true; }
    function emergency() external onlyGuardian { selfdestruct(payable(owner)); }
    function authorizeUpgrade() external onlyUpgrader { }
    function mint(address to) external onlyRole(MINTER_ROLE) { _mint(to); }
    function grant(address a) external onlyOwner { grantRole(MINTER_ROLE, a); }
    function take(address a) external onlyOwner { revokeRole(MINTER_ROLE, a); }
}
"""


def _plan(src):
    plans = mine_privileged_governance_lifecycle(src)
    return plans[0] if plans else None


def _kinds(src) -> set:
    p = _plan(src)
    return {a.kind for a in p.actors} if p else set()


def _relations(src) -> set:
    p = _plan(src)
    return {e.relation for e in p.edges} if p else set()


class TestActorDetection:
    def test_modifier_actors(self):
        kinds = _kinds(CONTRACT)
        assert {"owner", "pauser", "guardian", "upgrader"} <= kinds

    def test_onlyrole_is_a_role_not_an_actor(self):
        # onlyRole(MINTER_ROLE) must not produce an "unknown" actor; it is a role edge
        p = _plan(CONTRACT)
        assert "MINTER_ROLE" in {r.name for r in p.roles}

    def test_ownable_base_implies_owner(self):
        src = "contract T is ERC20, Ownable { function f() public { _mint(msg.sender, 1); } }"
        assert "owner" in _kinds(src)

    def test_unknown_modifier_kind(self):
        assert "unknown" in _kinds("contract C { function f() external onlyWizard {} }")


class TestRolesAndEdges:
    def test_role_grant_and_revoke_functions(self):
        p = _plan(CONTRACT)
        role = next(r for r in p.roles if r.name == "MINTER_ROLE")
        assert "grant" in role.grant_functions
        assert "take" in role.revoke_functions

    def test_edge_relations(self):
        rels = _relations(CONTRACT)
        assert {"guards", "grants", "revokes"} <= rels

    def test_guard_edge_targets_function(self):
        p = _plan(CONTRACT)
        guards = [(e.source, e.target) for e in p.edges if e.relation == "guards"]
        assert ("owner", "setFee") in guards
        assert ("MINTER_ROLE", "mint") in guards


class TestContractAndAdvisory:
    def test_no_privilege_returns_empty(self):
        assert mine_privileged_governance_lifecycle("contract C { function f() public {} }") == []

    def test_empty_source(self):
        assert mine_privileged_governance_lifecycle("") == []

    def test_returns_plans_not_findings(self):
        p = _plan(CONTRACT)
        assert isinstance(p, PrivilegedGovernanceLifecyclePlan)
        assert not hasattr(p, "severity")
        d = p.to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        assert d["metadata"]["capability"] == "privileged_governance_lifecycle_hardening"
        assert "authority_graph" in d

    def test_anchors_present(self):
        p = mine_privileged_governance_lifecycle(CONTRACT, Path("/x/Gov.sol"))[0]
        owner = next(a for a in p.actors if a.kind == "owner")
        assert owner.source_anchors and owner.source_anchors[0].startswith("Gov.sol:")


class TestParserRoundTrip:
    def test_round_trip(self):
        plan = _plan(CONTRACT)
        parsed = parse_privileged_governance_plans(
            {"privileged_governance_lifecycle_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert {a.kind for a in parsed[0].actors} == {a.kind for a in plan.actors}
        assert {r.name for r in parsed[0].roles} == {r.name for r in plan.roles}

    def test_parser_rejects_garbage(self):
        assert parse_privileged_governance_plans("nope") == []
        assert parse_privileged_governance_plans(7) == []
        assert parse_privileged_governance_plans({"plans": "x"}) == []

    def test_parser_skips_empty_objective(self):
        good = PrivilegedGovernanceLifecyclePlan(
            id="p", objective="o", actors=[GovernanceActor(id="owner", kind="owner")]
        )
        parsed = parse_privileged_governance_plans({"plans": [good.to_dict(), {"objective": ""}]})
        assert len(parsed) == 1
