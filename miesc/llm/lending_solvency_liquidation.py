"""
Lending solvency & liquidation hardening — Phase 1 (deterministic market model).

Phase 1 of ``docs/sdd/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md``. The SDD's gap is a
unified provider-neutral model of *protocol solvency*: a lending market can pass individual oracle
checks and still be unsafe if collateral, debt, liquidation thresholds, close factors, interest
indexes and reserves do not compose. MIESC already has `defi_detectors` and the `VAULT_SOLVENCY`
invariant template, but no structured solvency model.

This module builds that model deterministically (no provider, no LLM): for a contract that looks
like a lending protocol it records the market parameters, accounting fields, solvency-critical
functions and price dependencies into a :class:`LendingSolvencyLiquidationPlan`. It is **advisory**:
a market model is an inventory, never a ``Finding`` and never an "insolvent" accusation. Later SDD
phases (solvency hypotheses, liquidation oracles, execution plans, the LLM agent) build on it.
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
# Provider-neutral data contract (mirrors the oracle-plan contracts in agentic_contracts).
# --------------------------------------------------------------------------------------
@dataclass
class LendingMarket:
    id: str
    price_source: str = ""
    collateral_factor: str = ""
    liquidation_threshold: str = ""
    close_factor: str = ""
    liquidation_bonus: str = ""
    interest_index: str = ""
    reserve_account: str = ""
    source_anchors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "price_source": _safe_label(self.price_source) or "",
            "collateral_factor": _safe_label(self.collateral_factor) or "",
            "liquidation_threshold": _safe_label(self.liquidation_threshold) or "",
            "close_factor": _safe_label(self.close_factor) or "",
            "liquidation_bonus": _safe_label(self.liquidation_bonus) or "",
            "interest_index": _safe_label(self.interest_index) or "",
            "reserve_account": _safe_label(self.reserve_account) or "",
            "source_anchors": _safe_text_list(self.source_anchors),
        }


@dataclass
class LendingSolvencyLiquidationPlan:
    id: str
    objective: str
    markets: List[LendingMarket] = field(default_factory=list)
    accounting_fields: List[str] = field(default_factory=list)
    solvency_functions: List[str] = field(default_factory=list)
    price_dependencies: List[str] = field(default_factory=list)
    configuration_actors: List[str] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "market_model": {
                "markets": [m.to_dict() for m in self.markets[:MAX_AGENT_ITEMS]],
                "accounting_fields": _safe_text_list(self.accounting_fields),
                "solvency_functions": _safe_text_list(self.solvency_functions),
                "price_dependencies": _safe_text_list(self.price_dependencies),
                "configuration_actors": _safe_text_list(self.configuration_actors),
            },
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "lending_solvency_liquidation_hardening",
                    "schema_version": "1",
                }
            ),
        }


def parse_lending_solvency_plans(data: Any) -> List[LendingSolvencyLiquidationPlan]:
    """Parse provider/output data into bounded lending solvency plans (provider-neutral)."""
    import json

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []
    if not isinstance(data, Mapping):
        return []
    raw_items = data.get("lending_solvency_liquidation_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[LendingSolvencyLiquidationPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue
        model = raw.get("market_model") if isinstance(raw.get("market_model"), Mapping) else {}
        markets: List[LendingMarket] = []
        for rm in (model.get("markets") or [])[:MAX_AGENT_ITEMS]:
            if isinstance(rm, Mapping) and rm.get("id"):
                markets.append(
                    LendingMarket(
                        id=_safe_label(rm.get("id")) or "",
                        price_source=_safe_label(rm.get("price_source")) or "",
                        collateral_factor=_safe_label(rm.get("collateral_factor")) or "",
                        liquidation_threshold=_safe_label(rm.get("liquidation_threshold")) or "",
                        close_factor=_safe_label(rm.get("close_factor")) or "",
                        liquidation_bonus=_safe_label(rm.get("liquidation_bonus")) or "",
                        interest_index=_safe_label(rm.get("interest_index")) or "",
                        reserve_account=_safe_label(rm.get("reserve_account")) or "",
                        source_anchors=_safe_text_list(rm.get("source_anchors")),
                    )
                )
        plans.append(
            LendingSolvencyLiquidationPlan(
                id=_safe_label(raw.get("id")) or "lend",
                objective=objective,
                markets=markets,
                accounting_fields=_safe_text_list(model.get("accounting_fields")),
                solvency_functions=_safe_text_list(model.get("solvency_functions")),
                price_dependencies=_safe_text_list(model.get("price_dependencies")),
                configuration_actors=_safe_text_list(model.get("configuration_actors")),
            )
        )
    return plans


# --------------------------------------------------------------------------------------
# Deterministic local miner (no provider, no LLM).
# --------------------------------------------------------------------------------------
_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(")
_SOLVENCY_FN_RE = re.compile(
    r"(?i)(deposit|supply|withdraw|redeem|borrow|repay|accrue|liquidat|seize|absorb|"
    r"rebalance|configuremarket|configure|updateoracle|setoracle)"
)
_ONLY_MODIFIER_RE = re.compile(r"\bonly([A-Za-z_]\w*)")

# accounting category -> keywords (whole-word, case-insensitive, scanned on the source)
_ACCOUNTING = [
    ("bad_debt", ("baddebt", "bad_debt", "deficit", "shortfall")),
    ("collateral", ("collateral",)),
    ("debt", ("debt", "borrowed", "totalborrow", "totalborrows", "borrowbalance")),
    ("reserves", ("reserve", "reserves", "reservefactor")),
    ("indexes", ("borrowindex", "supplyindex", "exchangerate", "accumulator", "liquidityindex")),
    ("shares", ("shares", "ctoken", "atoken", "sharesof")),
]
# market parameter -> (field name, keywords)
_PARAMS = [
    ("collateral_factor", ("collateralfactor", "ltv", "loantovalue")),
    ("liquidation_threshold", ("liquidationthreshold", "liqthreshold")),
    ("close_factor", ("closefactor",)),
    ("liquidation_bonus", ("liquidationbonus", "liquidationincentive", "liquidationpenalty")),
    ("interest_index", ("borrowindex", "liquidityindex", "interestindex")),
    ("reserve_account", ("reservefactor", "totalreserves")),
]
_PRICE_KEYWORDS = (
    "oracle",
    "pricefeed",
    "getprice",
    "latestanswer",
    "latestrounddata",
    "getunderlyingprice",
)
_ACTOR_KINDS = ("owner", "admin", "governor", "guardian", "governance", "timelock")


def _first_token(lowsrc: str, src: str, keyword: str) -> str:
    """Return the identifier containing ``keyword`` (as written in source), or ''."""
    m = re.search(
        r"\b([A-Za-z_]\w*"
        + re.escape(keyword)
        + r"[A-Za-z_]*|[A-Za-z_]*"
        + re.escape(keyword)
        + r"[A-Za-z_]*)\b",
        src,
        re.IGNORECASE,
    )
    return m.group(1) if m else keyword


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


def _line_of(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def mine_lending_solvency_liquidation(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[LendingSolvencyLiquidationPlan]:
    """Deterministically build a lending market model when the contract looks like a lending protocol.

    Gate: a plan is emitted only when the contract has at least one solvency-critical function AND at
    least one accounting field — otherwise an empty list. Never raises and never emits a Finding.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    masked = _strip_comments(source_code)
    low = masked.lower()
    anchor = Path(file_path).name if file_path else "<memory>"

    solvency_functions = sorted(
        {
            m.group("name")
            for m in _FUNCTION_RE.finditer(masked)
            if _SOLVENCY_FN_RE.search(m.group("name"))
        }
    )
    accounting_fields = [cat for cat, kws in _ACCOUNTING if any(k in low for k in kws)]

    # Precision gate: must look like a lending protocol.
    if not solvency_functions or not accounting_fields:
        return []

    market = LendingMarket(id=anchor)
    for attr, kws in _PARAMS:
        for kw in kws:
            if kw in low:
                setattr(market, attr, _first_token(low, masked, kw))
                break
    price_deps = sorted({kw for kw in _PRICE_KEYWORDS if kw in low})
    if price_deps:
        market.price_source = _first_token(low, masked, price_deps[0])
    first = re.search(r"(?i)collateral|borrow|debt", masked)
    market.source_anchors = [f"{anchor}:{_line_of(source_code, first.start() if first else 0)}"]

    config_actors = sorted(
        {
            kind
            for mm in _ONLY_MODIFIER_RE.finditer(masked)
            for kind in _ACTOR_KINDS
            if kind in mm.group(1).lower()
        }
    )

    return [
        LendingSolvencyLiquidationPlan(
            id=f"lend-{anchor}",
            objective=f"Lending market model for {anchor} "
            f"({len(solvency_functions)} solvency functions, {len(accounting_fields)} field groups)",
            markets=[market],
            accounting_fields=accounting_fields,
            solvency_functions=solvency_functions[:MAX_AGENT_ITEMS],
            price_dependencies=price_deps,
            configuration_actors=config_actors,
        )
    ]


__all__ = [
    "LendingMarket",
    "LendingSolvencyLiquidationPlan",
    "parse_lending_solvency_plans",
    "mine_lending_solvency_liquidation",
]
