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
from typing import Any, Dict, List, Mapping, Optional

from miesc.llm._solidity_text import _line_of, _match_brace, _strip_comments
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


@dataclass
class PrivilegedGovernanceLifecyclePlan:
    id: str
    objective: str
    actors: List[GovernanceActor] = field(default_factory=list)
    roles: List[GovernanceRole] = field(default_factory=list)
    edges: List[GovernanceEdge] = field(default_factory=list)
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
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "privileged_governance_lifecycle_hardening",
                    "schema_version": "1",
                }
            ),
        }


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

    if not actors and not roles:
        return []

    # de-dup role function lists
    for role in roles.values():
        role.grant_functions = sorted(set(role.grant_functions))[:MAX_AGENT_ITEMS]
        role.revoke_functions = sorted(set(role.revoke_functions))[:MAX_AGENT_ITEMS]

    n = len(actors) + len(roles)
    return [
        PrivilegedGovernanceLifecyclePlan(
            id=f"gov-{anchor}",
            objective=f"Authority graph for {anchor} ({n} privileged actors/roles)",
            actors=sorted(actors.values(), key=lambda a: a.kind),
            roles=sorted(roles.values(), key=lambda r: r.name),
            edges=edges[:MAX_AGENT_ITEMS],
        )
    ]


__all__ = [
    "GovernanceActor",
    "GovernanceRole",
    "GovernanceEdge",
    "PrivilegedGovernanceLifecyclePlan",
    "parse_privileged_governance_plans",
    "mine_privileged_governance_lifecycle",
]
