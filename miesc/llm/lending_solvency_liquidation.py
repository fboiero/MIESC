"""
Lending solvency & liquidation hardening — Phases 1-2 (deterministic market model + hypotheses).

Phases 1-2 of ``docs/sdd/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md``. The SDD's gap is
a unified provider-neutral model of *protocol solvency*: a lending market can pass individual oracle
checks and still be unsafe if collateral, debt, liquidation thresholds, close factors, interest
indexes and reserves do not compose. MIESC already has `defi_detectors` and the `VAULT_SOLVENCY`
invariant template, but no structured solvency model.

**Phase 1** builds that model deterministically (no provider, no LLM): for a contract that looks
like a lending protocol it records the market parameters, accounting fields, solvency-critical
functions and price dependencies into a :class:`LendingSolvencyLiquidationPlan`.

**Phase 2** adds ``solvency_hypotheses``: deterministic, advisory :class:`SolvencyHypothesis`
records. A hypothesis is emitted only when a solvency-critical function is present *and* the guard
that would disprove it is **not visible in that function's body** (a guard-gap, mirroring
``GuardGapHypothesis`` in ``revert_invariant_mining``). Delegated checks (``*Allowed`` / ``check*``
/ ``isSolvent``, which real protocols route to a controller contract) count as guards and suppress
the hypothesis. Every hypothesis carries at least one ``negative_check`` — the condition that would
reject it — as the SDD requires.

The whole module is **advisory**: a market model is an inventory and a hypothesis is an obligation,
never a ``Finding`` and never an "insolvent" accusation. ``promotion.state`` stays ``hypothesis``;
only replay, fuzzing, symbolic execution or human review promotes it. Later SDD phases (solvency
oracles, execution plans, the LLM agent, and the remaining hypothesis categories) build on this.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

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


# The twelve solvency-hypothesis categories named in the SDD. A category outside this set is
# dropped (in ``to_dict`` and in the parser): a provider is free to name one, but the schema is
# fixed. Phase 2's deterministic miner emits only the subset with a defensible guard-gap test
# (see ``_derive_solvency_hypotheses``); the rest wait for the LLM reasoning agent.
_HYPOTHESIS_CATEGORIES = frozenset(
    {
        "insolvent_borrow",
        "unsafe_withdraw",
        "liquidation_bypass",
        "liquidation_over_seizure",
        "liquidation_under_seizure",
        "interest_accrual_gap",
        "oracle_decimal_shift",
        "stale_price_solvency",
        "bad_debt_double_count",
        "reserve_drift",
        "paused_market_recovery_gap",
        "rounding_threshold_flip",
    }
)


@dataclass
class SolvencyHypothesis:
    """A deterministic, advisory hypothesis that a solvency guard may be missing.

    Never a Finding and never a confirmed state: a solvency gap is a hypothesis until replay,
    fuzzing, symbolic execution or human review promotes it, which Phase 2 does not do. The
    ``negative_checks`` list the conditions that would reject the hypothesis (the guard that would
    make the path safe) so a reader weighs it rather than treating it as a defect. ``id`` lets a
    later phase (solvency-oracle or execution-plan generation) key off a single hypothesis.
    """

    category: str
    id: str = ""
    attacker_or_market_condition: str = ""
    unsafe_state_transition: str = ""
    affected_market: str = ""
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
            "attacker_or_market_condition": _safe_text(
                self.attacker_or_market_condition, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "unsafe_state_transition": _safe_text(
                self.unsafe_state_transition, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "affected_market": _safe_label(self.affected_market) or "",
            "preconditions": _safe_text_list(self.preconditions),
            "negative_checks": _safe_text_list(self.negative_checks),
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
    solvency_hypotheses: List[SolvencyHypothesis] = field(default_factory=list)
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
            # Phase 2. The SDD's schema shows the shape of a single ``solvency_hypothesis``; a
            # market can warrant several, so they ride as a bounded list. The parser below also
            # accepts the SDD's singular key so provider-conformant output is not dropped.
            "solvency_hypotheses": [
                h.to_dict() for h in self.solvency_hypotheses[:MAX_AGENT_ITEMS]
            ],
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "lending_solvency_liquidation_hardening",
                    "schema_version": "1",
                }
            ),
        }


def _hypotheses_from_raw(raw: Mapping[str, Any]) -> List[SolvencyHypothesis]:
    """Parse ``solvency_hypotheses`` (list) or the SDD's singular ``solvency_hypothesis`` (dict).

    Drops any entry whose category is outside the twelve or that carries no negative check: a
    hypothesis without the condition that would reject it is not a usable obligation.
    """
    raw_list = raw.get("solvency_hypotheses")
    if not isinstance(raw_list, list):
        singular = raw.get("solvency_hypothesis")
        raw_list = [singular] if isinstance(singular, Mapping) else []

    out: List[SolvencyHypothesis] = []
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
            SolvencyHypothesis(
                category=category,
                id=_safe_label(rh.get("id")) or "",
                attacker_or_market_condition=_safe_text(
                    rh.get("attacker_or_market_condition"),
                    MAX_AGENT_TEXT_CHARS,
                    allow_multiline=True,
                )
                or "",
                unsafe_state_transition=_safe_text(
                    rh.get("unsafe_state_transition"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                affected_market=_safe_label(rh.get("affected_market")) or "",
                preconditions=_safe_text_list(rh.get("preconditions")),
                negative_checks=negative_checks,
                source_anchors=_safe_text_list(rh.get("source_anchors")),
            )
        )
    return out


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
        raw_model = raw.get("market_model")
        model: Mapping[str, Any] = raw_model if isinstance(raw_model, Mapping) else {}
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
                solvency_hypotheses=_hypotheses_from_raw(raw),
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
# The debt side of a lending market: without one of these the contract is a vault, a
# staking pool, a pair or a token, however many `deposit`/`withdraw`/`totalSupply` it has.
_DEBT_FN_RE = re.compile(r"(?i)(borrow|repay|liquidat|seize|absorb)")
_IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_TYPE_DECL_RE = re.compile(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)")

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

# ---- Phase 2 guard signals (scanned inside a function body, which is already string-masked) ----
# A solvency check: a collateral/health/threshold read, a liquidatability check, a delegated check
# routed to a controller (``*Allowed`` / ``check<solvency-noun>`` / ``isSolvent`` / ``isLiquidatable``
# / ``*Collateralized`` / ``validate*``), or delegation of the whole operation to a ``*Logic``
# library — all of which real lending protocols (Compound's Comptroller + internal helpers, Aave's
# ``BorrowLogic``) keep out of the entrypoint. Breadth is deliberate (a missed guard name is a false
# positive, and each hypothesis has a negative check that cedes to a delegated owner), but the
# ``check`` verb is anchored to solvency nouns so it does not swallow ``unchecked {}`` or
# ``checkpoint``.
_SOLVENCY_GUARD_RE = re.compile(
    r"(?i)(collateralfactor|collateral_factor|liquidationthreshold|liquidation_threshold|"
    r"healthfactor|health_factor|accountliquidity|hypothetical|shortfall|undercollateral|"
    r"collateraliz[a-z]*|liquidatable|\bltv\b|loantovalue|collateralvalue|getcollateral|"
    r"\w*allowed\b|\bissolvent\b|"
    r"\bcheck(?:collateral|health|solvenc|liquidity|account|borrow|position|safe)[a-z]*|"
    r"\bvalidate[a-z_]*|[a-z_]+logic\b|_solvency|solvencycheck)"
)
# A bound on how much collateral a liquidation may seize.
_SEIZE_BOUND_RE = re.compile(
    r"(?i)(closefactor|close_factor|maxclose|maxrepay|seizetokens|"
    r"calculateseizetokens|liquidationincentive|\bmin\b)"
)
# An interest-accrual call. Note: scanned in the body only, so accrual enforced by a *modifier*
# (e.g. ``function borrow(...) accrues { ... }``) or named ``updateState()`` is not recognised and
# would leave interest_accrual_gap firing; this is a known limit of the intra-body heuristic.
_ACCRUE_CALL_RE = re.compile(r"(?i)accrue")
# A price read that returns a *price value*. ``getprice`` must be an immediate call so that
# ``getPriceOracle()`` (which returns the oracle *address*, as Aave's Pool passes to its logic
# libraries) is not mistaken for a price read.
_PRICE_READ_RE = re.compile(
    r"(?i)(getprice\s*\(|latestanswer|latestrounddata|getunderlyingprice|getassetprice|"
    r"\.price\s*\()"
)
# A freshness / round check on that price read.
_FRESHNESS_RE = re.compile(
    r"(?i)(updatedat|updated_at|roundid|round_id|answeredinround|staleness|\bstale\b|"
    r"heartbeat|freshness|block\.timestamp)"
)


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


def _function_bodies(masked: str) -> List[Tuple[str, str, int, bool]]:
    """Return ``(name, body_text, header_offset, is_entrypoint)`` for every function with a body.

    ``body_text`` includes the braces and is taken from the already string/comment-masked
    source, so a guard keyword inside a revert string is not mistaken for a real guard.
    ``header_offset`` anchors the function to a source line. ``is_entrypoint`` is True only for a
    state-changing external/public function: it is False when the header declares ``internal`` /
    ``private`` (a helper is not attack surface, and its guard usually lives in the public wrapper
    that calls it — Compound's ``borrowInternal`` / ``withdrawCollateral``) and False when it
    declares ``view`` / ``pure`` (a getter changes no state, so it is never an unsafe transition —
    Aave's ``MAX_STABLE_RATE_BORROW_SIZE_PERCENT``, Compound's ``isBorrowCollateralized``). Phase 2
    hypothesizes only over state-changing entrypoints.
    """
    out: List[Tuple[str, str, int, bool]] = []
    for m in _FUNCTION_RE.finditer(masked):
        brace = _body_brace(masked, m.end())
        if brace == -1:  # bodiless declaration (interface / abstract)
            continue
        close = _match_brace(masked, brace)
        header = masked[m.end() : brace]  # params + visibility/modifiers, before the body
        is_helper = re.search(r"\b(internal|private)\b", header) is not None
        is_readonly = re.search(r"\b(view|pure)\b", header) is not None
        out.append(
            (
                m.group("name"),
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


# Phase-2 hypothesis templates: provider-neutral, conditional prose. Each is emitted only when
# its triggering function is present AND the suppression guard is absent from that function's
# body. The second negative check always cedes to the plan/contract that may already own the
# guard (a delegated controller, or the oracle-feed plan), an SDD false-positive control.
def _derive_solvency_hypotheses(
    source: str,
    anchor: str,
    bodies: List[Tuple[str, str, int, bool]],
    accounting_fields: List[str],
    market: LendingMarket,
) -> List[SolvencyHypothesis]:
    """Build advisory guard-gap hypotheses from solvency-critical functions missing their guard."""
    acc = set(accounting_fields)
    hyps: List[SolvencyHypothesis] = []

    def _unguarded(fn_match: "re.Pattern[str]", guard: "re.Pattern[str]") -> List[int]:
        """Header offsets of entrypoints matching ``fn_match`` whose body lacks ``guard``."""
        return [
            off
            for name, body, off, ep in bodies
            if ep and fn_match.search(name) and not guard.search(body)
        ]

    borrow_fn = re.compile(r"(?i)borrow")
    withdraw_fn = re.compile(r"(?i)(withdraw|redeem)")
    liquidate_fn = re.compile(r"(?i)(liquidat|seize|absorb)")
    balance_fn = re.compile(r"(?i)(borrow|repay|withdraw|redeem|liquidat|seize)")

    # 1. insolvent_borrow — a borrow that does not check the resulting position against the
    #    collateral factor / liquidation threshold. Needs both sides of a market.
    if {"collateral", "debt"} <= acc:
        offs = _unguarded(borrow_fn, _SOLVENCY_GUARD_RE)
        if offs:
            hyps.append(
                SolvencyHypothesis(
                    category="insolvent_borrow",
                    id=f"insolvent_borrow-{anchor}",
                    attacker_or_market_condition="A borrower increases debt until the position "
                    "sits at or above the value its collateral can back.",
                    unsafe_state_transition="A borrow entrypoint increases debt without a visible "
                    "check that the resulting position stays within the collateral factor or "
                    "liquidation threshold.",
                    affected_market=anchor,
                    preconditions=["borrow functions with no visible solvency check in this file"],
                    negative_checks=[
                        "the borrow reverts when the resulting health factor is below 1 using a "
                        "fresh, bounded, normalized price",
                        "the solvency check may live in a delegated comptroller/controller "
                        "contract that is not visible in this file",
                    ],
                    source_anchors=_anchor_lines(source, anchor, offs),
                )
            )

    # 2. unsafe_withdraw — a collateral withdrawal that does not re-check account health.
    offs = _unguarded(withdraw_fn, _SOLVENCY_GUARD_RE)
    if offs and {"collateral", "debt"} <= acc:
        hyps.append(
            SolvencyHypothesis(
                category="unsafe_withdraw",
                id=f"unsafe_withdraw-{anchor}",
                attacker_or_market_condition="An account withdraws collateral while it still "
                "backs outstanding debt.",
                unsafe_state_transition="A withdraw/redeem entrypoint reduces collateral without "
                "a visible re-check of account health after interest and price updates.",
                affected_market=anchor,
                preconditions=[
                    "withdraw/redeem functions with no visible health check in this file"
                ],
                negative_checks=[
                    "the withdrawal re-checks account health after accrual and a price update "
                    "before transferring collateral",
                    "the health check may be enforced in a delegated controller not visible here",
                ],
                source_anchors=_anchor_lines(source, anchor, offs),
            )
        )

    # 3. liquidation_bypass — a liquidation that does not verify the target is actually underwater.
    offs = _unguarded(liquidate_fn, _SOLVENCY_GUARD_RE)
    if offs:
        hyps.append(
            SolvencyHypothesis(
                category="liquidation_bypass",
                id=f"liquidation_bypass-{anchor}",
                attacker_or_market_condition="A healthy account is liquidated, or an underwater "
                "account cannot be.",
                unsafe_state_transition="A liquidate/seize entrypoint runs without a visible check "
                "that the target account is below its liquidation threshold (in shortfall).",
                affected_market=anchor,
                preconditions=["liquidation functions with no visible liquidatability check here"],
                negative_checks=[
                    "liquidation verifies the account is below its liquidation threshold before "
                    "seizing collateral",
                    "the liquidatability check may live in a delegated controller not visible here",
                ],
                source_anchors=_anchor_lines(source, anchor, offs),
            )
        )

    # 4. liquidation_over_seizure — seize math with no visible close-factor / repay bound. Only
    #    when the market actually carries a liquidation bonus to over-apply.
    if market.liquidation_bonus:
        offs = _unguarded(liquidate_fn, _SEIZE_BOUND_RE)
        if offs:
            hyps.append(
                SolvencyHypothesis(
                    category="liquidation_over_seizure",
                    id=f"liquidation_over_seizure-{anchor}",
                    attacker_or_market_condition="A liquidator seizes more collateral than the "
                    "repaid debt plus the allowed liquidation bonus.",
                    unsafe_state_transition="Seize math runs without a visible close-factor or "
                    "max-repay bound, so the seized amount may exceed debt repaid times (1 + bonus).",
                    affected_market=anchor,
                    preconditions=[
                        "a liquidation bonus exists and seize math has no visible bound"
                    ],
                    negative_checks=[
                        "the seized collateral is bounded by the close factor and the liquidation "
                        "bonus",
                        "the bound may be computed in a delegated controller not visible here",
                    ],
                    source_anchors=_anchor_lines(source, anchor, offs),
                )
            )

    # 5. interest_accrual_gap — a balance-changing entrypoint that reads balances without a
    #    visible accrue call first. Only meaningful when the market tracks an interest index.
    if "indexes" in acc or any(_ACCRUE_CALL_RE.search(n) for n, _, _, _ in bodies):
        offs = _unguarded(balance_fn, _ACCRUE_CALL_RE)
        if offs:
            hyps.append(
                SolvencyHypothesis(
                    category="interest_accrual_gap",
                    id=f"interest_accrual_gap-{anchor}",
                    attacker_or_market_condition="Interest is read from a stale index because "
                    "accrual did not run first.",
                    unsafe_state_transition="A balance-changing entrypoint reads debt or collateral "
                    "before accrueInterest() updates the index, evaluating the position against a "
                    "stale index.",
                    affected_market=anchor,
                    preconditions=["balance-changing functions with no visible accrue call here"],
                    negative_checks=[
                        "every state-changing entrypoint calls accrueInterest() before reading "
                        "balances",
                        "accrual may be enforced by a modifier or a delegated controller not "
                        "visible here",
                    ],
                    source_anchors=_anchor_lines(source, anchor, offs),
                )
            )

    # 6. stale_price_solvency — a price read inside a solvency-critical function with no visible
    #    freshness check. Gated tightly (SDD: stale price is otherwise owned by the oracle plan):
    #    only when the read sits inside borrow/withdraw/liquidate itself.
    price_offs = [
        off
        for name, body, off, ep in bodies
        if ep
        and balance_fn.search(name)
        and _PRICE_READ_RE.search(body)
        and not _FRESHNESS_RE.search(body)
    ]
    if price_offs:
        hyps.append(
            SolvencyHypothesis(
                category="stale_price_solvency",
                id=f"stale_price_solvency-{anchor}",
                attacker_or_market_condition="Solvency math consumes a stale or unbounded oracle "
                "price.",
                unsafe_state_transition="A price read inside a solvency-critical function feeds "
                "collateral/debt valuation without a visible freshness or round check.",
                affected_market=anchor,
                preconditions=[
                    "a price read inside borrow/withdraw/liquidate with no freshness check"
                ],
                negative_checks=[
                    "the price read checks updatedAt / roundId / staleness before use in solvency "
                    "math",
                    "freshness may be enforced inside the oracle contract and owned by the "
                    "oracle-feed hardening plan",
                ],
                source_anchors=_anchor_lines(source, anchor, price_offs),
            )
        )

    return hyps[:MAX_AGENT_ITEMS]


def mine_lending_solvency_liquidation(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[LendingSolvencyLiquidationPlan]:
    """Deterministically build a lending market model when the contract looks like a lending protocol.

    Gate: a plan is emitted only when the contract has a debt-side function (borrow / repay /
    liquidate / seize / absorb) AND a collateral or debt accounting identifier — otherwise an
    empty list. Phase 2 then adds advisory solvency hypotheses for solvency-critical functions
    whose disproving guard is not visible in their body. Never raises and never emits a Finding.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    # Comments and string contents masked: "reserve too low" in a revert message is not a
    # reserve account. Keywords are then matched inside identifiers only.
    masked = _mask_strings(_strip_comments(source_code))
    low = masked.lower()
    anchor = Path(file_path).name if file_path else "<memory>"

    fn_names = {m.group("name") for m in _FUNCTION_RE.finditer(masked)}
    solvency_functions = sorted(n for n in fn_names if _SOLVENCY_FN_RE.search(n))
    identifiers = {t.lower() for t in _IDENT_RE.findall(masked)}
    accounting_fields = [
        cat for cat, kws in _ACCOUNTING if any(k in ident for k in kws for ident in identifiers)
    ]

    # Precision gate: a lending market has a debt side. Require a borrow/repay/liquidate/
    # seize/absorb function AND a collateral or debt identifier; `deposit`/`withdraw`/
    # `totalSupply` plus `shares`/`reserve` describe every vault, pool, pair and token too.
    # Measured 2026-10-24 before this gate: ERC-4626 vaults (OpenZeppelin ×6, Solady), Lido
    # stETH and two SmartBugs tokens passed; Aave v3 and Compound v3 pass either way.
    has_debt_fn = any(_DEBT_FN_RE.search(n) for n in fn_names)
    if not has_debt_fn or not ({"collateral", "debt"} & set(accounting_fields)):
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
    # Anchor at the first accounting identifier in the source (a state variable or parameter
    # declaration in practice), not at the first loose occurrence of a word or line 1.
    # Contract / interface / library names are not accounting fields (a `CToken` contract
    # name matches the `ctoken` share keyword), so they are skipped when anchoring.
    type_names = {m.group(1) for m in _TYPE_DECL_RE.finditer(masked)}
    matched_kws = [k for cat, kws in _ACCOUNTING if cat in accounting_fields for k in kws]
    first_at = min(
        (
            m.start()
            for m in _IDENT_RE.finditer(masked)
            if m.group(0) not in type_names and any(k in m.group(0).lower() for k in matched_kws)
        ),
        default=0,
    )
    market.source_anchors = [f"{anchor}:{_line_of(source_code, first_at)}"]

    config_actors = sorted(
        {
            kind
            for mm in _ONLY_MODIFIER_RE.finditer(masked)
            for kind in _ACTOR_KINDS
            if kind in mm.group(1).lower()
        }
    )

    # Phase 2: advisory guard-gap hypotheses over the solvency-critical function bodies.
    bodies = _function_bodies(masked)
    hypotheses = _derive_solvency_hypotheses(source_code, anchor, bodies, accounting_fields, market)

    return [
        LendingSolvencyLiquidationPlan(
            id=f"lend-{anchor}",
            objective=f"Lending market model for {anchor} "
            f"({len(solvency_functions)} solvency functions, {len(accounting_fields)} field groups, "
            f"{len(hypotheses)} solvency hypotheses)",
            markets=[market],
            accounting_fields=accounting_fields,
            solvency_functions=solvency_functions[:MAX_AGENT_ITEMS],
            price_dependencies=price_deps,
            configuration_actors=config_actors,
            solvency_hypotheses=hypotheses,
        )
    ]


__all__ = [
    "LendingMarket",
    "SolvencyHypothesis",
    "LendingSolvencyLiquidationPlan",
    "parse_lending_solvency_plans",
    "mine_lending_solvency_liquidation",
]
