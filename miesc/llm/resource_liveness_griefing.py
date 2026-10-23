"""
Resource/Liveness griefing hardening — Phase 1 (deterministic progress surface).

Phase 1 of ``docs/sdd/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md``. The SDD's insight:
the gap is not another ``for (...)`` regex (MIESC already emits DoS/unbounded-loop findings) but a
provider-neutral model of **progress** — which resources can be grown by an attacker, which
functions must make progress over them (withdraw, claim, settle, liquidate, …), and how they link.

This module builds that *progress surface* deterministically (no provider, no LLM): for each
externally growable resource it records its kind, the functions that grow it, the progress-critical
functions that traverse it, and source anchors, into a :class:`ResourceLivenessGriefingPlan` (one
plan per resource). It is **advisory**: a surface is an inventory, never a ``Finding`` and never an
"unbounded loop" accusation. Later SDD phases (liveness hypotheses, progress oracles, execution
plans, the LLM agent) build on it; ``promotion.state`` stays ``"hypothesis"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from miesc.llm.agentic_contracts import (
    MAX_AGENT_ITEMS,
    MAX_AGENT_TEXT_CHARS,
    _json_safe_mapping,
    _safe_label,
    _safe_text,
    _safe_text_list,
)

RESOURCE_KINDS = {
    "array",
    "queue",
    "mapping_index",
    "pending_payment",
    "keeper_task",
    "withdrawal_queue",
    "proposal_queue",
    "external_callback",
    "unknown",
}


# --------------------------------------------------------------------------------------
# Provider-neutral data contract (mirrors the oracle-plan contracts in agentic_contracts).
# --------------------------------------------------------------------------------------
@dataclass
class GrowableSurface:
    resource: str
    resource_kind: str = "unknown"
    growth_sources: List[str] = field(default_factory=list)
    progress_functions: List[str] = field(default_factory=list)
    source_anchors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource": _safe_label(self.resource) or "",
            "resource_kind": (
                self.resource_kind if self.resource_kind in RESOURCE_KINDS else "unknown"
            ),
            "growth_sources": _safe_text_list(self.growth_sources),
            "progress_functions": _safe_text_list(self.progress_functions),
            "source_anchors": _safe_text_list(self.source_anchors),
        }


@dataclass
class ResourceLivenessGriefingPlan:
    id: str
    objective: str
    surface: Optional[GrowableSurface] = None
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surface": (self.surface or GrowableSurface(resource="")).to_dict(),
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "resource_liveness_griefing_hardening",
                    "schema_version": "1",
                }
            ),
        }


def parse_resource_liveness_plans(data: Any) -> List[ResourceLivenessGriefingPlan]:
    """Parse provider/output data into bounded resource-liveness plans (provider-neutral)."""
    import json

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, Mapping):
        return []
    raw_items = data.get("resource_liveness_griefing_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[ResourceLivenessGriefingPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue
        rs = raw.get("surface") if isinstance(raw.get("surface"), Mapping) else {}
        resource = _safe_label(rs.get("resource")) or ""
        surface = GrowableSurface(
            resource=resource,
            resource_kind=str(rs.get("resource_kind") or "unknown"),
            growth_sources=_safe_text_list(rs.get("growth_sources")),
            progress_functions=_safe_text_list(rs.get("progress_functions")),
            source_anchors=_safe_text_list(rs.get("source_anchors")),
        )
        plans.append(
            ResourceLivenessGriefingPlan(
                id=_safe_label(raw.get("id")) or "rliv", objective=objective, surface=surface
            )
        )
    return plans


# --------------------------------------------------------------------------------------
# Deterministic local miner (no provider, no LLM).
# --------------------------------------------------------------------------------------
_ARRAY_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\[\s*\]\s+"
    r"(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+)*([A-Za-z_]\w*)\s*[;=]"
)
_MAPPING_DECL_RE = re.compile(
    r"\bmapping\s*\([^;]*?\)\s+(?:public\s+|private\s+|internal\s+)*([A-Za-z_]\w*)\s*[;=]"
)
_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(")
_PROGRESS_RE = re.compile(
    r"(?i)(withdraw|claim|refund|settle|execute|liquidat|process|finaliz|redeem|"
    r"payout|distribut|relay|upkeep|recover|dequeue|flush)"
)

_KIND_BY_NAME = [
    # *_queue kinds require an explicit "queue" token so pull-payment maps like
    # ``pendingWithdrawals`` are not mislabeled as a queue.
    ("withdrawal_queue", ("withdrawqueue", "withdrawalqueue")),
    ("proposal_queue", ("proposalqueue", "proposal", "proposals")),
    ("keeper_task", ("keeper", "upkeep", "jobs", "task")),
    ("pending_payment", ("pending", "owed", "credit", "refund", "payment", "payout", "payable")),
    ("queue", ("queue", "fifo")),
]


def _resource_kind(name: str, is_mapping: bool) -> str:
    low = name.lower()
    for kind, keys in _KIND_BY_NAME:
        if any(k in low for k in keys):
            return kind
    return "mapping_index" if is_mapping else "array"


def _strip_comments(source: str) -> str:
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        c, nxt = source[i], source[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _match_brace(source: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(source)):
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(source)


def _line_of(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


@dataclass(frozen=True)
class _Func:
    name: str
    start: int
    body: str
    is_progress: bool


def _functions(masked: str) -> List[_Func]:
    funcs: List[_Func] = []
    for m in _FUNCTION_RE.finditer(masked):
        brace = masked.find("{", m.end())
        if brace == -1:
            continue
        end = _match_brace(masked, brace)
        funcs.append(
            _Func(
                name=m.group("name"),
                start=m.start(),
                body=masked[brace : end + 1],
                is_progress=bool(_PROGRESS_RE.search(m.group("name"))),
            )
        )
    return funcs


def mine_resource_liveness_griefing(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[ResourceLivenessGriefingPlan]:
    """Deterministically build the progress surface (growable resources × progress functions).

    Returns one plan per growable resource that is either grown or traversed by a progress
    function; empty list when none. Never raises and never emits a Finding — advisory only.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    masked = _strip_comments(source_code)
    anchor = Path(file_path).name if file_path else "<memory>"
    funcs = _functions(masked)

    # Collect candidate resources: dynamic arrays and mappings (declaration site -> name, kind).
    resources: Dict[str, Dict[str, Any]] = {}
    for m in _ARRAY_DECL_RE.finditer(masked):
        name = m.group(2)
        resources.setdefault(
            name,
            {
                "kind": _resource_kind(name, False),
                "anchor": f"{anchor}:{_line_of(source_code, m.start())}",
            },
        )
    for m in _MAPPING_DECL_RE.finditer(masked):
        name = m.group(1)
        resources.setdefault(
            name,
            {
                "kind": _resource_kind(name, True),
                "anchor": f"{anchor}:{_line_of(source_code, m.start())}",
            },
        )

    plans: List[ResourceLivenessGriefingPlan] = []
    for name, meta in resources.items():
        word = re.compile(r"\b" + re.escape(name) + r"\b")
        push = re.compile(r"\b" + re.escape(name) + r"\s*\.\s*push\s*\(")
        assign = re.compile(r"\b" + re.escape(name) + r"\s*\[[^\]]*\]\s*=")
        growth = sorted({f.name for f in funcs if push.search(f.body) or assign.search(f.body)})
        progress = sorted({f.name for f in funcs if f.is_progress and word.search(f.body)})
        if not growth and not progress:
            continue  # a resource nobody grows or traverses is not a progress surface
        surface = GrowableSurface(
            resource=name,
            resource_kind=meta["kind"],
            growth_sources=growth[:MAX_AGENT_ITEMS],
            progress_functions=progress[:MAX_AGENT_ITEMS],
            source_anchors=[meta["anchor"]],
        )
        plans.append(
            ResourceLivenessGriefingPlan(
                id=f"rliv-{anchor}-{name}",
                objective=f"Progress surface for '{name}' in {anchor}",
                surface=surface,
            )
        )
    return plans[:MAX_AGENT_ITEMS]


__all__ = [
    "GrowableSurface",
    "ResourceLivenessGriefingPlan",
    "parse_resource_liveness_plans",
    "mine_resource_liveness_griefing",
]
