"""
Privileged governance lifecycle hardening — Phase 1 (deterministic authority graph).

Phase 1 of ``docs/sdd/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md``. The SDD's
insight: the gap is not another ``onlyOwner`` matcher (MIESC already emits governance findings in
``advanced_detectors``), but a provider-neutral *model of privileged authority* — who holds power,
over which surfaces, and how it is granted/revoked. This module builds that model deterministically
(no provider, no LLM): it inventories privileged actors, roles and the edges between them and the
functions they guard, into the :class:`PrivilegedGovernanceLifecyclePlan` contract.

It is **advisory**: a plan is an authority inventory, never a ``Finding`` and never a
"missing timelock" accusation. Later SDD phases (lifecycle hypotheses, governance oracles,
execution plans, the LLM reasoning agent) build on this graph; here ``promotion.state`` stays
``"hypothesis"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from miesc.llm._solidity_text import (
    _body_brace,
    _line_of,
    _mask_strings,
    _match_brace,
    _strip_comments,
)
from miesc.llm.agentic_contracts import (
    MAX_AGENT_ITEMS,
    MAX_AGENT_TEXT_CHARS,
    _json_safe_mapping,
    _safe_label,
    _safe_text,
    _safe_text_list,
)

ACTOR_KINDS = {
    "owner",
    "admin",
    "guardian",
    "governor",
    "proposer",
    "executor",
    "pauser",
    "upgrader",
    "timelock",
    "multisig",
    "keeper",
    "unknown",
}
EDGE_RELATIONS = {
    "guards",
    "grants",
    "revokes",
    "queues",
    "executes",
    "cancels",
    "upgrades",
    "pauses",
    "recovers",
    "delegates",
}


# --------------------------------------------------------------------------------------
# Provider-neutral data contract (mirrors the oracle-plan contracts in agentic_contracts).
# --------------------------------------------------------------------------------------
@dataclass
class GovernanceActor:
    id: str
    kind: str = "unknown"
    source: str = "unknown"
    source_anchors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "kind": self.kind if self.kind in ACTOR_KINDS else "unknown",
            "source": _safe_label(self.source) or "unknown",
            "source_anchors": _safe_text_list(self.source_anchors),
        }


@dataclass
class GovernanceRole:
    name: str
    admin_role: str = ""
    grant_functions: List[str] = field(default_factory=list)
    revoke_functions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": _safe_label(self.name) or "",
            "admin_role": _safe_label(self.admin_role) or "",
            "grant_functions": _safe_text_list(self.grant_functions),
            "revoke_functions": _safe_text_list(self.revoke_functions),
        }


@dataclass
class GovernanceEdge:
    source: str
    target: str
    relation: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": _safe_label(self.source) or "",
            "target": _safe_label(self.target) or "",
            "relation": self.relation if self.relation in EDGE_RELATIONS else "guards",
            "evidence": _safe_text_list(self.evidence),
        }


# The twelve lifecycle-hypothesis categories named in the SDD (l.118). A category outside this set
# is dropped (in ``to_dict`` and the parser): a provider may name one, but the schema is fixed.
# Phase 2's deterministic miner emits only the subset with a defensible guard-gap test (see
# ``_derive_lifecycle_hypotheses``): ``unprotected_initializer``, ``unsafe_upgrade_authority`` and
# ``pause_recovery_gap``. The other nine wait for the LLM reasoning agent or a plan that already
# owns them — ``missing_timelock`` / ``timelock_bypass`` (GovernanceDetector's timelock patterns,
# and no deterministic delay model here), ``unbounded_emergency_power`` and ``guardian_takeover``
# (no intra-file bound to test), ``role_admin_self_grant`` (the SDD means a *guarded* admin granting
# *without delay* — a timelock model this phase does not have), ``cross_domain_governance_replay``
# (the cross-chain plan), ``parameter_rug`` / ``treasury_drain_path`` (an economic consequence the
# financial-math / lending plans own), and ``renounce_brick`` (``advanced_detectors`` already reasons
# about renounced ownership from the opposite direction).
_HYPOTHESIS_CATEGORIES = frozenset(
    {
        "unprotected_initializer",
        "role_admin_self_grant",
        "missing_timelock",
        "timelock_bypass",
        "unbounded_emergency_power",
        "pause_recovery_gap",
        "unsafe_upgrade_authority",
        "cross_domain_governance_replay",
        "guardian_takeover",
        "renounce_brick",
        "parameter_rug",
        "treasury_drain_path",
    }
)


@dataclass
class LifecycleHypothesis:
    """A deterministic, advisory hypothesis that a privileged-authority guard may be missing.

    Never a Finding and never a confirmed state: a lifecycle gap is a hypothesis until replay,
    fuzzing, symbolic execution or human review promotes it, which Phase 2 does not do. Each
    ``negative_checks`` entry names a condition that would *reject* the hypothesis — a guard that may
    live out of view (an inherited base, a modifier defined elsewhere, a timelock or multisig as the
    owner, a proxy admin). It is advisory on top of, not a replacement for, the regex findings in
    ``advanced_detectors`` (``ProxyUpgradeDetector``): where they overlap this phase is the more
    precise view, because it recognises the guard shapes those regexes miss and so suppresses their
    false positives rather than re-raising them.
    """

    category: str
    id: str = ""
    attacker_or_fault_model: str = ""
    unsafe_transition: str = ""
    critical_surface: str = ""
    preconditions: List[str] = field(default_factory=list)
    negative_checks: List[str] = field(default_factory=list)
    source_anchors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "category": (
                _safe_label(self.category)
                if self.category in _HYPOTHESIS_CATEGORIES
                else "unclassified"
            ),
            "attacker_or_fault_model": _safe_text(
                self.attacker_or_fault_model, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "unsafe_transition": _safe_text(
                self.unsafe_transition, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "critical_surface": _safe_label(self.critical_surface) or "",
            "preconditions": _safe_text_list(self.preconditions),
            "negative_checks": _safe_text_list(self.negative_checks),
            "source_anchors": _safe_text_list(self.source_anchors),
        }


@dataclass
class PrivilegedGovernanceLifecyclePlan:
    id: str
    objective: str
    actors: List[GovernanceActor] = field(default_factory=list)
    roles: List[GovernanceRole] = field(default_factory=list)
    edges: List[GovernanceEdge] = field(default_factory=list)
    lifecycle_hypotheses: List[LifecycleHypothesis] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "authority_graph": {
                "actors": [a.to_dict() for a in self.actors[:MAX_AGENT_ITEMS]],
                "roles": [r.to_dict() for r in self.roles[:MAX_AGENT_ITEMS]],
                "edges": [e.to_dict() for e in self.edges[:MAX_AGENT_ITEMS]],
            },
            # Phase 2. The SDD's schema shows one ``lifecycle_hypothesis``; a contract can warrant
            # several, so they ride as a bounded list. The parser also accepts the SDD's singular
            # key so provider-conformant output is not dropped.
            "lifecycle_hypotheses": [
                h.to_dict() for h in self.lifecycle_hypotheses[:MAX_AGENT_ITEMS]
            ],
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "privileged_governance_lifecycle_hardening",
                    "schema_version": "1",
                }
            ),
        }


def _hypotheses_from_raw(raw: Mapping[str, Any]) -> List[LifecycleHypothesis]:
    """Parse ``lifecycle_hypotheses`` (list) or the SDD's singular ``lifecycle_hypothesis`` (dict).

    Drops any entry whose category is outside the twelve or that carries no negative check: a
    hypothesis without the condition that would reject it is not a usable obligation.
    """
    raw_list = raw.get("lifecycle_hypotheses")
    if not isinstance(raw_list, list):
        singular = raw.get("lifecycle_hypothesis")
        raw_list = [singular] if isinstance(singular, Mapping) else []

    out: List[LifecycleHypothesis] = []
    for rh in raw_list[:MAX_AGENT_ITEMS]:
        if not isinstance(rh, Mapping):
            continue
        category = _safe_label(rh.get("category")) or ""
        if category not in _HYPOTHESIS_CATEGORIES:
            continue
        negative_checks = _safe_text_list(rh.get("negative_checks"))
        if not negative_checks:
            continue
        out.append(
            LifecycleHypothesis(
                category=category,
                id=_safe_label(rh.get("id")) or "",
                attacker_or_fault_model=_safe_text(
                    rh.get("attacker_or_fault_model"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                unsafe_transition=_safe_text(
                    rh.get("unsafe_transition"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                critical_surface=_safe_label(rh.get("critical_surface")) or "",
                preconditions=_safe_text_list(rh.get("preconditions")),
                negative_checks=negative_checks,
                source_anchors=_safe_text_list(rh.get("source_anchors")),
            )
        )
    return out


def parse_privileged_governance_plans(data: Any) -> List[PrivilegedGovernanceLifecyclePlan]:
    """Parse provider/output data into bounded governance lifecycle plans (provider-neutral)."""
    import json

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, Mapping):
        return []
    raw_items = data.get("privileged_governance_lifecycle_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[PrivilegedGovernanceLifecyclePlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue
        graph = (
            raw.get("authority_graph") if isinstance(raw.get("authority_graph"), Mapping) else {}
        )
        actors: List[GovernanceActor] = []
        for ra in (graph.get("actors") or [])[:MAX_AGENT_ITEMS]:
            if isinstance(ra, Mapping) and ra.get("id"):
                actors.append(
                    GovernanceActor(
                        id=_safe_label(ra.get("id")) or "",
                        kind=str(ra.get("kind") or "unknown"),
                        source=str(ra.get("source") or "unknown"),
                        source_anchors=_safe_text_list(ra.get("source_anchors")),
                    )
                )
        roles: List[GovernanceRole] = []
        for rr in (graph.get("roles") or [])[:MAX_AGENT_ITEMS]:
            if isinstance(rr, Mapping) and rr.get("name"):
                roles.append(
                    GovernanceRole(
                        name=_safe_label(rr.get("name")) or "",
                        admin_role=_safe_label(rr.get("admin_role")) or "",
                        grant_functions=_safe_text_list(rr.get("grant_functions")),
                        revoke_functions=_safe_text_list(rr.get("revoke_functions")),
                    )
                )
        edges: List[GovernanceEdge] = []
        for re_ in (graph.get("edges") or [])[:MAX_AGENT_ITEMS]:
            if isinstance(re_, Mapping) and re_.get("source") and re_.get("target"):
                edges.append(
                    GovernanceEdge(
                        source=_safe_label(re_.get("source")) or "",
                        target=_safe_label(re_.get("target")) or "",
                        relation=str(re_.get("relation") or "guards"),
                        evidence=_safe_text_list(re_.get("evidence")),
                    )
                )
        plans.append(
            PrivilegedGovernanceLifecyclePlan(
                id=_safe_label(raw.get("id")) or "gov",
                objective=objective,
                actors=actors,
                roles=roles,
                edges=edges,
                lifecycle_hypotheses=_hypotheses_from_raw(raw),
            )
        )
    return plans


# --------------------------------------------------------------------------------------
# Deterministic local miner (no provider, no LLM).
# --------------------------------------------------------------------------------------
_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(")
_ONLY_MODIFIER_RE = re.compile(r"\bonly([A-Za-z_]\w*)")
_ONLY_ROLE_RE = re.compile(r"\bonlyRole\s*\(\s*([A-Za-z_]\w*)\s*\)")
_ROLE_CONST_RE = re.compile(r"\b([A-Za-z_]\w*_ROLE)\b\s*=")
_ROLE_USE_RE = re.compile(r"\b([A-Za-z_]\w*_ROLE)\b")
_GRANT_RE = re.compile(r"\b_?(grantRole|setupRole|_setupRole)\s*\(\s*([A-Za-z_]\w*)")
_REVOKE_RE = re.compile(r"\b_?(revokeRole|renounceRole)\s*\(\s*([A-Za-z_]\w*)")

# modifier suffix (lowercased) -> actor kind
_KIND_BY_MODIFIER = {
    "owner": "owner",
    "governor": "governor",
    "governance": "governor",
    "guardian": "guardian",
    "proposer": "proposer",
    "executor": "executor",
    "pauser": "pauser",
    "upgrader": "upgrader",
    "admin": "admin",
    "keeper": "keeper",
    "timelock": "timelock",
    "multisig": "multisig",
}


def _kind_for(modifier_suffix: str) -> str:
    low = modifier_suffix.lower()
    for key, kind in _KIND_BY_MODIFIER.items():
        if key in low:
            return kind
    return "unknown"


# --------------------------------------------------------------------------------------
# Phase 2: deterministic, advisory lifecycle guard-gap hypotheses.
# --------------------------------------------------------------------------------------
# ``only<X>`` reads as an access guard UNLESS it is one of these, which gate on call context, not on
# who the caller is.
_NON_ACCESS_ONLY = {"onlyproxy", "onlydelegatecall", "onlyinitializing"}
# Inherited access modifiers not written ``only<Role>`` (Solmate/DS-Auth and common hand-rolled
# guards); matched by name because their body lives in a base, not in this file.
_INHERITED_ACCESS_MODIFIERS = {"auth", "requiresauth", "authorized", "restricted", "ifadmin"}

_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\{")
# A guard-shaped body: a caller check (order-agnostic, so ``pendingOwner() == msg.sender`` and
# ``msg.sender == owner`` both count), a role check, or an OZ/custom ``_check*`` helper.
_GUARD_BODY_RE = re.compile(
    r"(?i)(_check(?:owner|role|admin|authoriz)[a-z]*\s*\(|\bhasrole\s*\(|"
    r"(?:msg\.sender|_msgsender\s*\(\s*\))\s*[=!]=|[=!]=\s*(?:msg\.sender|_msgsender\s*\(\s*\))|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgsender|hasrole)|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgsender|hasrole)[^;{}]*\)\s*(?:revert|\{))"
)
# Init guard: the initializer family of modifiers, ``_disableInitializers``, or a *check* on an
# initialized flag. ``initialized = true`` is an assignment, not a guard, so a lone ``=`` is excluded.
_INIT_GUARD_RE = re.compile(
    r"(?i)(\binitializer\b|\breinitializer\s*\(|\bonlyinitializing\b|_disableinitializers\s*\(|"
    r"\brequire\s*\(\s*!\s*[a-z_]*initializ|"
    r"\bif\s*\(\s*!?\s*[a-z_]*initializ[a-z_]*\s*\)\s*(?:revert|\{)|"
    r"[a-z_]*initializ[a-z_]*\s*[=!]=\s*(?:true|false))"
)
# Initializer function name: initialize / reinitialize (+ optional version) or exactly init.
# Anchored so initiateWithdrawal / initialDeposit do not match.
_INIT_FN_RE = re.compile(r"(?i)^_{0,2}(?:initialize|reinitialize)(?:[A-Z0-9_]\w*)?$|^_{0,2}init$")
# UUPS upgrade-authorization hook (internal by design, so judged regardless of visibility).
_AUTHORIZE_UPGRADE_FN_RE = re.compile(r"(?i)^_?authorizeupgrade$")
# Public upgrade entrypoints (UUPS upgradeTo*, transparent-proxy upgrade*).
_PUBLIC_UPGRADE_FN_RE = re.compile(
    r"(?i)^(?:upgradeto|upgradetoandcall|upgrade|upgradeandcall|upgradeimplementation)$"
)
_AUTHORIZE_UPGRADE_CALL_RE = re.compile(r"(?i)_authorizeupgrade\s*\(")
# Pause / recovery names, anchored so unpause / paused / whenNotPaused do not read as a pause fn.
_PAUSE_FN_RE = re.compile(r"(?i)^_?pause$")
_UNPAUSE_FN_RE = re.compile(r"(?i)^_?(?:unpause|resume|unfreeze|liftpause)$|^_?recover\w*$")
_PAUSE_CALL_RE = re.compile(r"\b_pause\s*\(")
_UNPAUSE_CALL_RE = re.compile(r"\b_unpause\s*\(")
_CONTRACT_BLOCK_RE = re.compile(r"\b(?:abstract\s+)?(?:contract|library)\s+(?P<name>[A-Za-z_]\w*)")


def _access_modifier_names(masked: str) -> Set[str]:
    """Lowercased names of in-file modifiers whose body checks the caller, plus inherited guards."""
    names = set(_INHERITED_ACCESS_MODIFIERS)
    for m in _MODIFIER_DEF_RE.finditer(masked):
        brace = masked.find("{", m.end() - 1)
        if brace == -1:
            continue
        body = masked[brace : _match_brace(masked, brace) + 1]
        if _GUARD_BODY_RE.search(body):
            names.add(m.group("name").lower())
    return names


def _header_has_access_modifier(header: str, access_names: Set[str]) -> bool:
    """True when the function header carries an access-control modifier."""
    for mm in _ONLY_MODIFIER_RE.finditer(header):
        if mm.group(0).lower() not in _NON_ACCESS_ONLY:
            return True
    tokens = {t.lower() for t in re.findall(r"[A-Za-z_]\w*", header)}
    return bool(tokens & access_names)


def _function_bodies(masked: str) -> List[Tuple[str, str, str, int, bool]]:
    """Return ``(name, header, body, header_offset, is_entrypoint)`` for every function with a body.

    ``header`` is the text between ``(`` and the opening brace (params + visibility + modifiers);
    ``body`` includes the braces. ``is_entrypoint`` is True only for a state-changing external/public
    function: internal/private helpers and view/pure getters are not privileged attack surface, so
    they never seed a hypothesis — except the UUPS ``_authorizeUpgrade`` hook, which the upgrade rule
    inspects directly regardless of this flag because it is internal by design.
    """
    out: List[Tuple[str, str, str, int, bool]] = []
    for m in _FUNCTION_RE.finditer(masked):
        brace = _body_brace(masked, m.end())
        if brace == -1:
            continue
        close = _match_brace(masked, brace)
        header = masked[m.end() : brace]
        is_helper = re.search(r"\b(internal|private)\b", header) is not None
        is_readonly = re.search(r"\b(view|pure)\b", header) is not None
        out.append(
            (
                m.group("name"),
                header,
                masked[brace : close + 1],
                m.start(),
                not is_helper and not is_readonly,
            )
        )
    return out


def _anchor_lines(source: str, anchor: str, offsets: List[int]) -> List[str]:
    """``file:line`` anchors for the given header offsets, bounded and de-duplicated in order."""
    seen: Dict[str, None] = {}
    for off in offsets:
        seen.setdefault(f"{anchor}:{_line_of(source, off)}", None)
    return list(seen)[:MAX_AGENT_ITEMS]


def _contract_blocks(masked: str) -> List[Tuple[str, int, int]]:
    """``(name, start, end)`` offsets of each contract/library body (interfaces excluded).

    Pause/recovery is a per-contract property: a file with a paused contract and a separate
    recovery contract must not cancel out (the #321/#323 cross-contract scoping bug).
    """
    blocks: List[Tuple[str, int, int]] = []
    for m in _CONTRACT_BLOCK_RE.finditer(masked):
        brace = masked.find("{", m.end())
        if brace == -1:
            continue
        blocks.append((m.group("name"), m.start(), _match_brace(masked, brace) + 1))
    return blocks


def _derive_lifecycle_hypotheses(
    source: str,
    anchor: str,
    masked_src: str,
    bodies: List[Tuple[str, str, str, int, bool]],
) -> List[LifecycleHypothesis]:
    """Build advisory guard-gap hypotheses for the three deterministic categories."""
    access_names = _access_modifier_names(masked_src)
    hyps: List[LifecycleHypothesis] = []

    def _guarded(header: str, body: str) -> bool:
        return _header_has_access_modifier(header, access_names) or bool(
            _GUARD_BODY_RE.search(body)
        )

    # 1. unprotected_initializer — an external/public initializer with no visible init guard.
    #    advanced_detectors' ProxyUpgradeDetector flags this but false-positives on the modifier form
    #    (it recognises only ``initialized = true``); this phase suppresses that by reading the guard.
    init_offs = [
        off
        for name, header, body, off, ep in bodies
        if ep and _INIT_FN_RE.match(name) and not _INIT_GUARD_RE.search(header + body)
    ]
    if init_offs:
        hyps.append(
            LifecycleHypothesis(
                category="unprotected_initializer",
                id=f"unprotected_initializer-{anchor}",
                attacker_or_fault_model="Anyone front-runs initialization (or calls it again) to "
                "seize owner/admin/role before the legitimate deployer.",
                unsafe_transition="An external initializer sets privileged authority with no visible "
                "initializer guard, so the uninitialized-to-initialized transition is open to any "
                "caller.",
                critical_surface="initializer",
                preconditions=["external initializer with no visible init guard in this file"],
                negative_checks=[
                    "the initializer carries an initializer/reinitializer/onlyInitializing modifier "
                    "or reverts on an already-initialized flag",
                    "the guard may be inherited from a base initializer not visible here, or the "
                    "proxy calls initialize atomically in the same deploy transaction",
                ],
                source_anchors=_anchor_lines(source, anchor, init_offs),
            )
        )

    # 2. unsafe_upgrade_authority — the UUPS _authorizeUpgrade hook (internal by design) or a public
    #    upgrade entrypoint with no visible access guard. A public upgradeTo that delegates to
    #    _authorizeUpgrade is not a gap (the guard lives in the hook), so it is suppressed there.
    #    advanced_detectors' empty-_authorizeUpgrade regex false-positives on ``onlyOwner {}``; this
    #    phase suppresses it by reading the header guard.
    upgrade_offs = [
        off
        for name, header, body, off, ep in bodies
        if _AUTHORIZE_UPGRADE_FN_RE.match(name) and not _guarded(header, body)
    ]
    upgrade_offs += [
        off
        for name, header, body, off, ep in bodies
        if ep
        and _PUBLIC_UPGRADE_FN_RE.match(name)
        and not _AUTHORIZE_UPGRADE_CALL_RE.search(body)
        and not _guarded(header, body)
    ]
    if upgrade_offs:
        hyps.append(
            LifecycleHypothesis(
                category="unsafe_upgrade_authority",
                id=f"unsafe_upgrade_authority-{anchor}",
                attacker_or_fault_model="Any caller upgrades the implementation and takes over all "
                "contract logic and storage.",
                unsafe_transition="An upgrade authorization path (the UUPS _authorizeUpgrade hook or "
                "a public upgrade entrypoint) runs without a visible access check on the caller.",
                critical_surface="upgrade",
                preconditions=["an upgrade authorization path with no visible access guard here"],
                negative_checks=[
                    "the upgrade path restricts the caller to an owner/admin/upgrader role or a "
                    "proxy admin",
                    "authorization may be enforced in an inherited _authorizeUpgrade override or a "
                    "ProxyAdmin/timelock not visible in this file",
                ],
                source_anchors=_anchor_lines(source, anchor, sorted(set(upgrade_offs))),
            )
        )

    # 3. pause_recovery_gap — a contract that can pause but exposes no recovery (unpause/resume/
    #    recover, or a boolean-toggle pause). Evaluated per contract block so a paused contract and a
    #    separate recovery contract in the same file do not cancel out. No existing detector covers
    #    this: the centralization detector only flags that an owner *can* pause.
    pause_offs: List[int] = []
    for _cname, cstart, cend in _contract_blocks(masked_src):
        block = masked_src[cstart:cend]
        block_fns = [
            (name, header, body, off, ep)
            for name, header, body, off, ep in bodies
            if cstart <= off < cend
        ]
        pause_here = [
            off
            for name, header, body, off, ep in block_fns
            if ep and (_PAUSE_FN_RE.match(name) or _PAUSE_CALL_RE.search(body))
        ]
        if not pause_here:
            continue
        has_recovery = any(
            _UNPAUSE_FN_RE.match(name)
            or _UNPAUSE_CALL_RE.search(body)
            or (_PAUSE_FN_RE.match(name) and "bool" in header)
            for name, header, body, off, ep in block_fns
        ) or bool(re.search(r"(?i)\bpaused\s*=\s*!", block))
        if not has_recovery:
            pause_offs.extend(pause_here)
    if pause_offs:
        hyps.append(
            LifecycleHypothesis(
                category="pause_recovery_gap",
                id=f"pause_recovery_gap-{anchor}",
                attacker_or_fault_model="A pause (by a guardian, or via a compromised pauser key) "
                "freezes the contract with no path back to operation.",
                unsafe_transition="A contract exposes a pause entrypoint but no unpause/resume/"
                "recovery entrypoint, so the paused state has no exit.",
                critical_surface="pause",
                preconditions=[
                    "a pause entrypoint with no recovery entrypoint in the same contract"
                ],
                negative_checks=[
                    "the contract exposes an unpause/resume/recover entrypoint, or pause is a boolean "
                    "toggle",
                    "recovery may be inherited from a base (OpenZeppelin Pausable exposes _unpause) a "
                    "derived contract is expected to wire to a public unpause",
                ],
                source_anchors=_anchor_lines(source, anchor, pause_offs),
            )
        )

    return hyps[:MAX_AGENT_ITEMS]


def mine_privileged_governance_lifecycle(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[PrivilegedGovernanceLifecyclePlan]:
    """Deterministically build the authority graph (actors / roles / edges) from Solidity.

    Returns a single plan when the contract exposes any privileged authority, else an empty
    list. Never raises on malformed input and never emits a Finding — advisory inventory only.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    masked = _strip_comments(source_code)
    anchor = Path(file_path).name if file_path else "<memory>"

    actors: Dict[str, GovernanceActor] = {}
    roles: Dict[str, GovernanceRole] = {}
    edges: List[GovernanceEdge] = []

    def _add_actor(kind: str, where: int, source: str = "role") -> str:
        actor_id = kind
        a = actors.get(actor_id)
        line_anchor = f"{anchor}:{_line_of(source_code, where)}"
        if a is None:
            actors[actor_id] = GovernanceActor(
                id=actor_id, kind=kind, source=source, source_anchors=[line_anchor]
            )
        elif line_anchor not in a.source_anchors and len(a.source_anchors) < 10:
            a.source_anchors.append(line_anchor)
        return actor_id

    # Role constants (AccessControl): bytes32 ... X_ROLE = keccak256(...)
    for m in _ROLE_CONST_RE.finditer(masked):
        roles.setdefault(m.group(1), GovernanceRole(name=m.group(1)))

    # Per-function: modifiers guard the function.
    for fm in _FUNCTION_RE.finditer(masked):
        name = fm.group("name")
        brace = masked.find("{", fm.end())
        semi = masked.find(";", fm.end())
        if brace == -1 or (semi != -1 and semi < brace):
            header = masked[fm.start() : (semi if semi != -1 else fm.end())]
            body = ""
        else:
            header = masked[fm.start() : brace]
            body = masked[brace : _match_brace(masked, brace) + 1]

        # onlyRole(ROLE) -> the role guards this function
        for rm in _ONLY_ROLE_RE.finditer(header):
            role = rm.group(1)
            roles.setdefault(role, GovernanceRole(name=role))
            edges.append(
                GovernanceEdge(
                    source=role, target=name, relation="guards", evidence=[f"onlyRole({role})"]
                )
            )
        # other only* modifiers -> an actor guards this function
        for mm in _ONLY_MODIFIER_RE.finditer(header):
            if mm.group(0) == "onlyRole":
                continue
            kind = _kind_for(mm.group(1))
            actor_id = _add_actor(kind, fm.start(), source="modifier")
            edges.append(
                GovernanceEdge(
                    source=actor_id, target=name, relation="guards", evidence=[mm.group(0)]
                )
            )

        # grantRole / revokeRole inside the body -> grant/revoke edges + role functions
        for gm in _GRANT_RE.finditer(body):
            role = gm.group(2)
            roles.setdefault(role, GovernanceRole(name=role)).grant_functions.append(name)
            edges.append(
                GovernanceEdge(source=name, target=role, relation="grants", evidence=[gm.group(1)])
            )
        for vm in _REVOKE_RE.finditer(body):
            role = vm.group(2)
            roles.setdefault(role, GovernanceRole(name=role)).revoke_functions.append(name)
            edges.append(
                GovernanceEdge(source=name, target=role, relation="revokes", evidence=[vm.group(1)])
            )

    # Ownable base / owner usage implies an owner actor even without an explicit modifier here.
    if "onlyowner" not in masked.lower() and re.search(r"\bis\s+[^{]*\bOwnable\b", masked):
        owner_at = re.search(r"\bOwnable\b", masked)
        if owner_at:
            _add_actor("owner", owner_at.start(), source="external_contract")

    # Phase 2: advisory guard-gap hypotheses. Guards are searched on string-masked text so a guard
    # keyword inside a revert message is not mistaken for a real guard; Phase 1's extraction above
    # keeps using the comment-stripped-only text.
    guard_masked = _mask_strings(masked)
    bodies = _function_bodies(guard_masked)
    hypotheses = _derive_lifecycle_hypotheses(source_code, anchor, guard_masked, bodies)

    # Gate: emit a plan when the contract exposes any authority OR carries a lifecycle hypothesis. A
    # contract whose only signal is an unguarded _authorizeUpgrade has no actor/role, yet that is
    # exactly the case worth surfacing, so hypotheses alone keep the plan.
    if not actors and not roles and not hypotheses:
        return []

    # de-dup role function lists
    for role in roles.values():
        role.grant_functions = sorted(set(role.grant_functions))[:MAX_AGENT_ITEMS]
        role.revoke_functions = sorted(set(role.revoke_functions))[:MAX_AGENT_ITEMS]

    n = len(actors) + len(roles)
    return [
        PrivilegedGovernanceLifecyclePlan(
            id=f"gov-{anchor}",
            objective=f"Authority graph for {anchor} ({n} privileged actors/roles, "
            f"{len(hypotheses)} lifecycle hypotheses)",
            actors=sorted(actors.values(), key=lambda a: a.kind),
            roles=sorted(roles.values(), key=lambda r: r.name),
            edges=edges[:MAX_AGENT_ITEMS],
            lifecycle_hypotheses=hypotheses,
        )
    ]


__all__ = [
    "GovernanceActor",
    "GovernanceRole",
    "GovernanceEdge",
    "LifecycleHypothesis",
    "PrivilegedGovernanceLifecyclePlan",
    "parse_privileged_governance_plans",
    "mine_privileged_governance_lifecycle",
]
