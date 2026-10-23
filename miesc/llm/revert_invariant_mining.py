"""
Revert-invariant mining — Phase 1 (deterministic guard inventory).

Phase 1 of ``docs/SDD_REVERT_INVARIANT_MINING_20260810.md``. The SDD's insight is to treat
*successful defenses* as signal: inventory the guards a contract already has
(``require`` / ``assert`` / custom-error ``revert`` / ``if (...) revert|throw``), anchor each to
its source line and enclosing function, and normalize it into a stable defensive category. Later
phases (gap hypotheses, oracle/execution plans, the LLM reasoning agent) build on this inventory.

This module is the SDD's required *deterministic local fallback*: no provider, no LLM. It emits
provider-neutral :class:`RevertInvariantOraclePlan` objects whose ``guard_inventory`` is filled;
the ``gap_hypothesis`` / ``oracle`` / ``execution_plan`` fields stay minimal (``promotion.state =
"hypothesis"``) until a later phase validates them. It is **advisory** and never produces a
``Finding`` — a guard inventory is not an accusation of a missing guard.
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

# --------------------------------------------------------------------------------------
# Provider-neutral data contract (mirrors SequenceOraclePlan in agentic_contracts).
# --------------------------------------------------------------------------------------
GUARD_KINDS = {"require", "assert", "if_revert", "custom_error"}


@dataclass
class GuardInventoryItem:
    """One defensive guard observed in the source, anchored and categorized."""

    source_anchor: str
    function: str
    guard_kind: str
    predicate: str
    error_signal: str = ""
    normalized_terms: List[str] = field(default_factory=list)
    defensive_category: str = "unclassified"
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_anchor": _safe_text(self.source_anchor, MAX_AGENT_TEXT_CHARS) or "",
            "function": _safe_label(self.function) or "",
            "guard_kind": self.guard_kind if self.guard_kind in GUARD_KINDS else "require",
            "predicate": _safe_text(self.predicate, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "error_signal": _safe_text(self.error_signal, MAX_AGENT_TEXT_CHARS) or "",
            "normalized_terms": _safe_text_list(self.normalized_terms),
            "defensive_category": _safe_label(self.defensive_category) or "unclassified",
            "confidence": (
                self.confidence if self.confidence in {"low", "medium", "high"} else "low"
            ),
        }


@dataclass
class RevertInvariantOraclePlan:
    """Provider-neutral plan built from a contract's guard inventory (Phase 1: inventory only)."""

    id: str
    objective: str
    contract_role: str = ""
    guard_inventory: List[GuardInventoryItem] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "contract_role": _safe_text(self.contract_role, MAX_AGENT_TEXT_CHARS) or "",
            "guard_inventory": [g.to_dict() for g in self.guard_inventory[:MAX_AGENT_ITEMS]],
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {**self.metadata, "capability": "revert_invariant_mining", "schema_version": "1"}
            ),
        }


def parse_revert_invariant_plans(data: Any) -> List[RevertInvariantOraclePlan]:
    """Parse provider/output data into bounded revert-invariant oracle plans (provider-neutral)."""
    import json

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, Mapping):
        return []
    raw_items = data.get("revert_invariant_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[RevertInvariantOraclePlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue
        guards: List[GuardInventoryItem] = []
        raw_guards = raw.get("guard_inventory", [])
        if isinstance(raw_guards, list):
            for rg in raw_guards[:MAX_AGENT_ITEMS]:
                if not isinstance(rg, Mapping):
                    continue
                predicate = _safe_text(
                    rg.get("predicate"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                if not predicate:
                    continue
                guards.append(
                    GuardInventoryItem(
                        source_anchor=_safe_text(rg.get("source_anchor"), MAX_AGENT_TEXT_CHARS)
                        or "",
                        function=_safe_label(rg.get("function")) or "",
                        guard_kind=str(rg.get("guard_kind") or "require"),
                        predicate=predicate,
                        error_signal=_safe_text(rg.get("error_signal"), MAX_AGENT_TEXT_CHARS) or "",
                        normalized_terms=_safe_text_list(rg.get("normalized_terms")),
                        defensive_category=_safe_label(rg.get("defensive_category"))
                        or "unclassified",
                    )
                )
        plans.append(
            RevertInvariantOraclePlan(
                id=_safe_label(raw.get("id")) or "revinv",
                objective=objective,
                contract_role=_safe_text(raw.get("contract_role"), MAX_AGENT_TEXT_CHARS) or "",
                guard_inventory=guards,
            )
        )
    return plans


# --------------------------------------------------------------------------------------
# Deterministic local miner (no provider, no LLM).
# --------------------------------------------------------------------------------------
_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(|\bconstructor\s*\(")
_REQUIRE_RE = re.compile(r"\b(?P<kind>require|assert)\s*\(")
_REVERT_CUSTOM_RE = re.compile(r"\brevert\s+(?P<err>[A-Za-z_]\w*)\s*\(")
_IF_REVERT_RE = re.compile(
    r"\bif\s*\((?P<cond>(?:[^(){}]|\([^()]*\))*)\)\s*(?:\{[^{}]*)?(?:revert|throw)\b"
)

# defensive_category -> keyword set (checked in this order; first match wins).
_CATEGORY_RULES = [
    (
        "access_control",
        (
            "msg.sender",
            "owner",
            "admin",
            "onlyowner",
            "authorized",
            "hasrole",
            "role",
            "_msgsender",
        ),
    ),
    ("signature_verification", ("ecrecover", "signature", "signer", "isvalidsignature", "verify")),
    ("replay_prevention", ("nonce", "used", "executed", "processed", "replay", "consumed")),
    ("freshness_check", ("deadline", "expiry", "expired", "block.timestamp", "timestamp", "stale")),
    ("pause_toggle", ("paused", "whennotpaused", "halted", "enabled", "active")),
    ("allow_ban_list", ("whitelist", "blacklist", "allowlist", "denylist", "banned", "allowed")),
    (
        "slippage_threshold",
        ("minout", "amountoutmin", "slippage", "minamount", "minreturn", "mintokens"),
    ),
    ("accounting_cap", ("cap", "maxsupply", "maxmint", "limit", "totalsupply", "maxamount")),
    ("bounds_check", ("length", ".length", "index", "outofbounds", "<=", ">=", "<", ">")),
]


def _normalize_category(predicate: str, error_signal: str) -> tuple:
    """Return ``(category, normalized_terms)`` from the predicate + error label."""
    blob = f"{predicate} {error_signal}".lower()
    terms = sorted({t for t in re.findall(r"[a-z_][a-z0-9_.]*", blob) if len(t) > 2})[:12]
    for category, keywords in _CATEGORY_RULES:
        if any(kw in blob for kw in keywords):
            return category, terms
    return "unclassified", terms


def _strip_comments(source: str) -> str:
    """Blank // and /* */ comments while preserving indexes (string bodies are kept)."""
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


def _balanced_arg(source: str, open_paren: int) -> tuple:
    """Return ``(arg_text, end_index)`` for the parenthesized group opening at ``open_paren``."""
    depth = 0
    for idx in range(open_paren, len(source)):
        if source[idx] == "(":
            depth += 1
        elif source[idx] == ")":
            depth -= 1
            if depth == 0:
                return source[open_paren + 1 : idx], idx
    return source[open_paren + 1 :], len(source)


def _function_at(source: str, pos: int) -> tuple:
    """Return ``(name, start)`` of the innermost function definition containing ``pos``."""
    best = ("unknown", -1)
    for m in _FUNCTION_RE.finditer(source):
        if m.start() > pos:
            break
        brace = source.find("{", m.end())
        if brace == -1:
            continue
        depth, end = 0, brace
        while end < len(source):
            if source[end] == "{":
                depth += 1
            elif source[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if m.start() <= pos <= end and m.start() > best[1]:
            best = (m.groupdict().get("name") or "constructor", m.start())
    return best[0], best[1]


def _line_of(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def mine_revert_invariants(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[RevertInvariantOraclePlan]:
    """Deterministically mine the guard inventory from Solidity source.

    Returns a single :class:`RevertInvariantOraclePlan` (its ``guard_inventory`` populated) when
    the contract has any guard, or an empty list when it has none. Never raises on malformed
    input and never emits a Finding — this is advisory inventory only.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    masked = _strip_comments(source_code)
    anchor = Path(file_path).name if file_path else "<memory>"
    guards: List[GuardInventoryItem] = []

    def _anchor(idx: int) -> tuple:
        name, _ = _function_at(masked, idx)
        return f"{anchor}:{_line_of(source_code, idx)}", name

    # require(...) / assert(...)
    for m in _REQUIRE_RE.finditer(masked):
        arg, _ = _balanced_arg(masked, m.end() - 1)
        cond, _, msg = arg.partition(",")
        predicate = cond.strip()
        if not predicate:
            continue
        src_anchor, func = _anchor(m.start())
        category, terms = _normalize_category(predicate, msg)
        guards.append(
            GuardInventoryItem(
                source_anchor=src_anchor,
                function=func,
                guard_kind="require" if m.group("kind") == "require" else "assert",
                predicate=predicate,
                error_signal=msg.strip().strip("\"'"),
                normalized_terms=terms,
                defensive_category=category,
            )
        )

    # revert CustomError(...)
    for m in _REVERT_CUSTOM_RE.finditer(masked):
        err = m.group("err")
        src_anchor, func = _anchor(m.start())
        category, terms = _normalize_category(err, err)
        guards.append(
            GuardInventoryItem(
                source_anchor=src_anchor,
                function=func,
                guard_kind="custom_error",
                predicate=f"revert {err}(...)",
                error_signal=err,
                normalized_terms=terms,
                defensive_category=category,
            )
        )

    # if (cond) revert / if (cond) throw
    for m in _IF_REVERT_RE.finditer(masked):
        predicate = (m.group("cond") or "").strip()
        if not predicate:
            continue
        src_anchor, func = _anchor(m.start())
        category, terms = _normalize_category(predicate, "")
        guards.append(
            GuardInventoryItem(
                source_anchor=src_anchor,
                function=func,
                guard_kind="if_revert",
                predicate=predicate,
                normalized_terms=terms,
                defensive_category=category,
            )
        )

    if not guards:
        return []
    guards.sort(key=lambda g: (g.function, g.source_anchor))
    return [
        RevertInvariantOraclePlan(
            id=f"revinv-{anchor}",
            objective=f"Guard inventory for {anchor} ({len(guards)} guards)",
            guard_inventory=guards,
        )
    ]


__all__ = [
    "GuardInventoryItem",
    "RevertInvariantOraclePlan",
    "parse_revert_invariant_plans",
    "mine_revert_invariants",
]
