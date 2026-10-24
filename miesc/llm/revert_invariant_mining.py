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

from miesc.llm._solidity_text import _line_of, _strip_comments
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
_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\("
    r"|\bmodifier\s+(?P<mod>[A-Za-z_]\w*)\b"
    r"|\bconstructor\s*\("
)
_REQUIRE_RE = re.compile(r"\b(?P<kind>require|assert)\s*\(")
_REVERT_CUSTOM_RE = re.compile(r"\brevert\s+(?P<err>[A-Za-z_]\w*)\s*\(")
_IF_REVERT_RE = re.compile(
    r"\bif\s*\((?P<cond>(?:[^(){}]|\([^()]*\))*)\)\s*(?:\{[^{}]*)?(?:revert|throw)\b"
)

# defensive_category -> keyword set. Keywords match whole *tokens* of the predicate/error (not
# raw substrings), and ``pause_toggle`` is checked before ``replay_prevention`` so ``paused`` is
# not mis-read as ``used`` (replay). First category with a token match wins.
_CATEGORY_RULES = [
    (
        "access_control",
        (
            "msg.sender",
            "sender",
            "owner",
            "admin",
            "onlyowner",
            "authorized",
            "hasrole",
            "role",
            "governor",
            "guardian",
        ),
    ),
    ("signature_verification", ("ecrecover", "signature", "signer", "isvalidsignature", "verify")),
    ("pause_toggle", ("paused", "pause", "whennotpaused", "halted", "frozen")),
    ("replay_prevention", ("nonce", "used", "executed", "processed", "replay", "consumed")),
    ("freshness_check", ("deadline", "expiry", "expired", "timestamp", "stale")),
    ("allow_ban_list", ("whitelist", "blacklist", "allowlist", "denylist", "banned", "allowed")),
    (
        "slippage_threshold",
        ("minout", "amountoutmin", "slippage", "minamount", "minreturn", "mintokens"),
    ),
    ("accounting_cap", ("cap", "maxsupply", "maxmint", "limit", "totalsupply", "maxamount")),
    ("bounds_check", ("length", "index", "bound")),
]


def _normalize_category(predicate: str, error_signal: str) -> tuple:
    """Return ``(category, normalized_terms)`` from the predicate + error label.

    Tokens come from the identifiers in the predicate/error, expanded over ``.`` so
    ``msg.sender`` yields ``msg``/``sender`` and ``arr.length`` yields ``length``. Categories
    match a whole token, so ``capacity`` does not hit ``cap`` and ``!inactive`` does not hit
    ``active``.
    """
    blob = f"{predicate} {error_signal}".lower()
    raw = re.findall(r"[a-z_][a-z0-9_.]*", blob)
    tokens = set(raw) | {sub for t in raw for sub in t.split(".") if sub}
    terms = sorted(t for t in tokens if len(t) > 2)[:12]
    for category, keywords in _CATEGORY_RULES:
        if any(kw in tokens for kw in keywords):
            return category, terms
    return "unclassified", terms


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


def _split_top_comma(arg: str) -> tuple:
    """Split ``arg`` at the first depth-zero comma into ``(condition, message)``.

    Respects parentheses/brackets so ``check(a, b), "msg"`` splits into ``check(a, b)`` and
    ``"msg"`` instead of truncating the predicate at the inner comma.
    """
    depth = 0
    for i, ch in enumerate(arg):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return arg[:i], arg[i + 1 :]
    return arg, ""


def _collect_spans(source: str) -> List[tuple]:
    """Precompute ``(start, end, name)`` for every function/modifier/constructor body.

    Computed once per contract so guard anchoring is a lookup rather than a full re-scan per
    guard (the ``_function_at`` hot path the review flagged).
    """
    spans: List[tuple] = []
    for m in _FUNCTION_RE.finditer(source):
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
        gd = m.groupdict()
        name = gd.get("name") or gd.get("mod") or "constructor"
        spans.append((m.start(), end, name))
    return spans


def _enclosing(spans: List[tuple], pos: int) -> str:
    """Innermost span name containing ``pos`` (modifiers included), or ``unknown``."""
    best_name, best_start = "unknown", -1
    for start, end, name in spans:
        if start <= pos <= end and start > best_start:
            best_name, best_start = name, start
    return best_name


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
    spans = _collect_spans(masked)
    guards: List[GuardInventoryItem] = []

    def _anchor(idx: int) -> tuple:
        return f"{anchor}:{_line_of(source_code, idx)}", _enclosing(spans, idx)

    # require(...) / assert(...)
    for m in _REQUIRE_RE.finditer(masked):
        arg, _ = _balanced_arg(masked, m.end() - 1)
        cond, msg = _split_top_comma(arg)
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
    # `if (cond) revert Custom(...)` matches both the if_revert and custom_error rules at the
    # same line; keep the if_revert (it carries the real predicate) and drop the duplicate.
    if_anchors = {g.source_anchor for g in guards if g.guard_kind == "if_revert"}
    guards = [
        g for g in guards if not (g.guard_kind == "custom_error" and g.source_anchor in if_anchors)
    ]
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
