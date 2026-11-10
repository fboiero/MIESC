"""
Unit tests for the deterministic privileged-governance authority miner (SDD Phases 1 & 2).

Phase 1 covers actor detection per kind, AccessControl role + grant/revoke extraction, edges,
source anchoring, the provider-neutral parser round-trip, and the advisory contract (plans, not
Findings). Phase 2 covers the three deterministic lifecycle guard-gap hypotheses
(unprotected_initializer, unsafe_upgrade_authority, pause_recovery_gap): safe/unsafe fixture pairs
(the safe variant emits nothing — the precision delta over the regex detectors), the regex-trap
regressions, the gate change, and the hypothesis parser round-trip.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.privileged_governance_lifecycle import (
    _HYPOTHESIS_CATEGORIES,
    GovernanceActor,
    LifecycleHypothesis,
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


# ======================================================================================
# Phase 2 — lifecycle guard-gap hypotheses
# ======================================================================================
def _cats(src) -> list:
    plans = mine_privileged_governance_lifecycle(src)
    return sorted(h.category for h in plans[0].lifecycle_hypotheses) if plans else []


class TestUnprotectedInitializer:
    # SDD fixture 44: unprotected initializer grants owner.
    def test_unguarded_initializer_fires(self):
        src = "contract C { function initialize() external { owner = msg.sender; } }"
        assert _cats(src) == ["unprotected_initializer"]

    # SDD fixture 45: safe initializer guard rejects second call -> nothing.
    def test_initializer_modifier_suppresses(self):
        src = "contract C { function initialize() external initializer { owner = msg.sender; } }"
        assert "unprotected_initializer" not in _cats(src)

    def test_reinitializer_and_disable_suppress(self):
        a = "contract C { function initialize() public reinitializer(2) { x = 1; } }"
        b = "contract C { function initialize() public { require(!initialized); initialized = true; } }"
        assert "unprotected_initializer" not in _cats(a)
        assert "unprotected_initializer" not in _cats(b)

    def test_bare_assignment_is_not_a_guard(self):
        # `initialized = true` with no require/if check does not stop re-initialization.
        src = "contract C { function initialize() external { initialized = true; owner = msg.sender; } }"
        assert _cats(src) == ["unprotected_initializer"]

    def test_init_name_trap(self):
        # initiateWithdrawal / initialDeposit are not initializers.
        assert _cats("contract C { function initiateWithdrawal() external { x = 1; } }") == []
        assert _cats("contract C { function initialDeposit() external { x = 1; } }") == []

    def test_internal_initializer_not_entrypoint(self):
        src = "contract C { function initialize() internal { owner = msg.sender; } }"
        assert "unprotected_initializer" not in _cats(src)


class TestUnsafeUpgradeAuthority:
    def test_empty_authorize_upgrade_fires(self):
        src = "contract C is UUPSUpgradeable { function _authorizeUpgrade(address) internal override {} }"
        assert _cats(src) == ["unsafe_upgrade_authority"]

    def test_authorize_upgrade_onlyowner_suppressed(self):
        # The existing regex detector false-positives here; Phase 2 reads the guard and stays silent.
        src = (
            "contract C is UUPSUpgradeable "
            "{ function _authorizeUpgrade(address) internal override onlyOwner {} }"
        )
        assert "unsafe_upgrade_authority" not in _cats(src)

    def test_public_upgrade_without_guard_fires(self):
        src = "contract C { function upgradeTo(address impl) external { _impl = impl; } }"
        assert _cats(src) == ["unsafe_upgrade_authority"]

    def test_public_upgrade_delegating_to_hook_suppressed(self):
        src = (
            "contract C is UUPSUpgradeable {"
            " function upgradeTo(address i) external { _authorizeUpgrade(i); _impl = i; }"
            " function _authorizeUpgrade(address) internal onlyOwner {} }"
        )
        assert "unsafe_upgrade_authority" not in _cats(src)

    def test_onlyproxy_is_not_an_access_guard(self):
        # onlyProxy / onlyDelegateCall gate on call context, not on the caller's identity.
        src = "contract C { function _authorizeUpgrade(address) internal onlyProxy {} }"
        assert _cats(src) == ["unsafe_upgrade_authority"]

    def test_inline_sender_check_suppresses(self):
        src = (
            "contract C { address admin;"
            " function upgradeTo(address i) external { require(msg.sender == admin); _impl = i; } }"
        )
        assert "unsafe_upgrade_authority" not in _cats(src)


class TestPauseRecoveryGap:
    # SDD fixture 48: pause without recovery bricks withdrawal.
    def test_pause_without_recovery_fires(self):
        src = "contract C { function pause() external onlyOwner { _pause(); } }"
        assert _cats(src) == ["pause_recovery_gap"]

    # SDD fixture 49: safe guardian pause with governor unpause -> nothing.
    def test_pause_with_unpause_suppressed(self):
        src = (
            "contract C {"
            " function pause() external onlyGuardian { _pause(); }"
            " function unpause() external onlyGovernor { _unpause(); } }"
        )
        assert "pause_recovery_gap" not in _cats(src)

    def test_boolean_toggle_is_its_own_recovery(self):
        src = (
            "contract C { bool paused; function pause(bool v) external onlyOwner { paused = v; } }"
        )
        assert "pause_recovery_gap" not in _cats(src)

    def test_unpause_alone_does_not_count_as_pause(self):
        # `unpause` contains the substring `pause` but is not a pause entrypoint.
        src = "contract C { function unpause() external onlyOwner { _unpause(); } }"
        assert _cats(src) == []

    def test_scoped_per_contract(self):
        # A paused contract and a separate recovery contract in one file must not cancel out.
        src = (
            "contract Frozen { function pause() external onlyOwner { _pause(); } }\n"
            "contract Other { function unpause() external onlyOwner { _unpause(); } }"
        )
        assert _cats(src) == ["pause_recovery_gap"]


class TestGateChange:
    def test_unguarded_upgrade_only_still_emits_plan(self):
        # No actor/role, but an unguarded _authorizeUpgrade is exactly the case worth surfacing.
        src = "contract C { function _authorizeUpgrade(address) internal override {} }"
        plans = mine_privileged_governance_lifecycle(src)
        assert len(plans) == 1
        assert plans[0].actors == [] and plans[0].roles == []
        assert [h.category for h in plans[0].lifecycle_hypotheses] == ["unsafe_upgrade_authority"]

    def test_clean_contract_still_empty(self):
        assert mine_privileged_governance_lifecycle("contract C { function f() public {} }") == []


class TestHypothesisAdvisoryAndParser:
    SRC = (
        "contract C {"
        " function initialize() external { owner = msg.sender; }"
        " function pause() external onlyOwner { _pause(); } }"
    )

    def test_every_hypothesis_has_a_negative_check(self):
        plan = mine_privileged_governance_lifecycle(self.SRC)[0]
        assert plan.lifecycle_hypotheses
        for h in plan.lifecycle_hypotheses:
            assert h.negative_checks, f"{h.category} has no negative check"

    def test_hypotheses_are_advisory_not_findings(self):
        d = mine_privileged_governance_lifecycle(self.SRC)[0].to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        for h in d["lifecycle_hypotheses"]:
            assert "severity" not in h
            assert h["category"] in _HYPOTHESIS_CATEGORIES

    def test_round_trip_preserves_hypotheses(self):
        plan = mine_privileged_governance_lifecycle(self.SRC)[0]
        parsed = parse_privileged_governance_plans(
            {"privileged_governance_lifecycle_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert {h.category for h in parsed[0].lifecycle_hypotheses} == {
            h.category for h in plan.lifecycle_hypotheses
        }

    def test_parser_accepts_sdd_singular_key(self):
        raw = {
            "plans": [
                {
                    "objective": "o",
                    "lifecycle_hypothesis": {
                        "category": "pause_recovery_gap",
                        "negative_checks": ["an unpause entrypoint exists"],
                    },
                }
            ]
        }
        parsed = parse_privileged_governance_plans(raw)
        assert len(parsed) == 1
        assert [h.category for h in parsed[0].lifecycle_hypotheses] == ["pause_recovery_gap"]

    def test_parser_drops_unknown_category_and_empty_checks(self):
        raw = {
            "plans": [
                {
                    "objective": "o",
                    "lifecycle_hypotheses": [
                        {"category": "made_up", "negative_checks": ["x"]},
                        {"category": "pause_recovery_gap", "negative_checks": []},
                    ],
                }
            ]
        }
        parsed = parse_privileged_governance_plans(raw)
        assert parsed[0].lifecycle_hypotheses == []

    def test_to_dict_normalizes_unknown_category(self):
        h = LifecycleHypothesis(category="not_a_category", negative_checks=["x"])
        assert h.to_dict()["category"] == "unclassified"
