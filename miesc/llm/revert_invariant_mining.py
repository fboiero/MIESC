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
from typing import Any, Collection, Dict, List, Mapping, Optional

from miesc.llm._solidity_text import (
    _body_brace,
    _line_of,
    _match_brace,
    _strip_comments,
    split_identifier,
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
class GuardGapHypothesis:
    """A deterministic, advisory hypothesis that a guard is inconsistent within a verb family.

    Never a Finding and never a confirmed state: a category gap is a hypothesis until execution
    evidence (a counterexample) promotes it, which Phase 2 does not do. ``negative_checks`` list
    the reasons the gap may be benign so a reader weighs it rather than treats it as a defect.
    """

    category: str
    expected_guard: str
    observed_gap: str = "inconsistent"
    affected_functions: List[str] = field(default_factory=list)
    semantic_preconditions: List[str] = field(default_factory=list)
    negative_checks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": _safe_label(self.category) or "unclassified",
            "expected_guard": _safe_text(self.expected_guard, MAX_AGENT_TEXT_CHARS) or "",
            "observed_gap": (
                self.observed_gap
                if self.observed_gap
                in {"missing", "weaker", "inconsistent", "unreachable", "dead_guard"}
                else "inconsistent"
            ),
            "affected_functions": _safe_text_list(self.affected_functions),
            "semantic_preconditions": _safe_text_list(self.semantic_preconditions),
            "negative_checks": _safe_text_list(self.negative_checks),
        }


@dataclass
class RevertInvariantOraclePlan:
    """Provider-neutral plan from a contract's guards (Phase 1 inventory + Phase 2 gap hypotheses).

    Phase 2 adds ``gap_hypotheses``: deterministic, advisory within-family guard inconsistencies.
    The plan is still never a Finding and ``promotion.state`` stays ``hypothesis``.
    """

    id: str
    objective: str
    contract_role: str = ""
    guard_inventory: List[GuardInventoryItem] = field(default_factory=list)
    gap_hypotheses: List[GuardGapHypothesis] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "contract_role": _safe_text(self.contract_role, MAX_AGENT_TEXT_CHARS) or "",
            "guard_inventory": [g.to_dict() for g in self.guard_inventory[:MAX_AGENT_ITEMS]],
            "gap_hypotheses": [h.to_dict() for h in self.gap_hypotheses[:MAX_AGENT_ITEMS]],
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
        hypotheses: List[GuardGapHypothesis] = []
        raw_gaps = raw.get("gap_hypotheses", [])
        if isinstance(raw_gaps, list):
            for rh in raw_gaps[:MAX_AGENT_ITEMS]:
                if not isinstance(rh, Mapping):
                    continue
                expected = _safe_text(rh.get("expected_guard"), MAX_AGENT_TEXT_CHARS)
                if not expected:
                    continue
                hypotheses.append(
                    GuardGapHypothesis(
                        category=_safe_label(rh.get("category")) or "unclassified",
                        expected_guard=expected,
                        observed_gap=str(rh.get("observed_gap") or "inconsistent"),
                        affected_functions=_safe_text_list(rh.get("affected_functions")),
                        semantic_preconditions=_safe_text_list(rh.get("semantic_preconditions")),
                        negative_checks=_safe_text_list(rh.get("negative_checks")),
                    )
                )
        plans.append(
            RevertInvariantOraclePlan(
                id=_safe_label(raw.get("id")) or "revinv",
                objective=objective,
                contract_role=_safe_text(raw.get("contract_role"), MAX_AGENT_TEXT_CHARS) or "",
                guard_inventory=guards,
                gap_hypotheses=hypotheses,
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
        brace = _body_brace(source, m.end())
        if brace == -1:
            continue  # interface / abstract declaration: no span of its own
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


# --------------------------------------------------------------------------------------
# Phase 2: within-family access-control gap hypotheses (deterministic, advisory).
# --------------------------------------------------------------------------------------
# Verb prefixes that mark a function as privileged. A family is compared only when at least
# one member is guarded, so a broad verb (``add``) never fires on its own.
# Admin-only verbs (the access-control comparison population). Verbs that are ambiguous between
# admin and user intent (``withdraw``, ``mint``, ``burn``, ``add``, ``remove``, ``emergency``) are
# deliberately left out so a plain user ``withdraw()`` is not mistaken for a privileged action.
_PRIVILEGED_VERBS = frozenset(
    {
        "set",
        "update",
        "configure",
        "config",
        "rescue",
        "sweep",
        "pause",
        "unpause",
        "upgrade",
        "grant",
        "revoke",
        "admin",
        "change",
        "enable",
        "disable",
        "initialize",
        "migrate",
        "seize",
        "whitelist",
        "blacklist",
    }
)
# User-facing entry-point verbs (the pause-gating comparison population). Disjoint from the
# privileged set; a verb that is in neither has role ``None`` and joins no comparison.
_USER_VERBS = frozenset(
    {
        "deposit",
        "withdraw",
        "transfer",
        "send",
        "swap",
        "stake",
        "unstake",
        "claim",
        "redeem",
        "borrow",
        "repay",
        "buy",
        "sell",
        "wrap",
        "unwrap",
        "exchange",
        "mint",
        "burn",
        "bid",
        "lock",
        "unlock",
    }
)
_VIS_RE = re.compile(r"\b(external|public|internal|private)\b")
_VIEW_RE = re.compile(r"\b(?:view|pure|constant)\b")
# Bare words in a signature tail that are keywords, not applied modifiers.
_TAIL_KEYWORDS = frozenset(
    {
        "external",
        "public",
        "internal",
        "private",
        "view",
        "pure",
        "payable",
        "nonpayable",
        "virtual",
        "override",
        "returns",
        "constant",
        "memory",
        "storage",
        "calldata",
    }
)
_FUNCTION_DECL_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\(")


@dataclass
class _FuncSig:
    name: str
    visibility: str
    mutates: bool
    modifiers: List[str]
    params: str = ""
    body: str = ""


def _collect_functions(masked: str) -> List["_FuncSig"]:
    """Enumerate named functions with visibility, state-mutability, applied modifiers, the raw
    parameter-list text, and the body text (all already balanced here, so no second parse)."""
    out: List[_FuncSig] = []
    for m in _FUNCTION_DECL_RE.finditer(masked):
        popen = m.end() - 1
        params, pclose = _balanced_arg(masked, popen)
        brace = _body_brace(masked, pclose)
        if brace == -1:
            continue  # abstract/interface declaration: no body of its own
        tail = masked[pclose + 1 : brace]
        vis = _VIS_RE.search(tail)
        # strip modifier args and the returns clause, then bare identifiers are the modifiers
        cleaned = re.sub(r"\([^()]*\)", " ", tail)
        modifiers = [t for t in re.findall(r"[A-Za-z_]\w*", cleaned) if t not in _TAIL_KEYWORDS]
        out.append(
            _FuncSig(
                name=m.group("name"),
                visibility=vis.group(1) if vis else "",
                mutates=not _VIEW_RE.search(tail),
                modifiers=modifiers,
                params=params,
                body=masked[brace : _match_brace(masked, brace)],
            )
        )
    return out


# Parameter-name fragments that mark a function as time-bounded. Substrings (not whole tokens):
# ``expir`` covers expiry/expiration/expired/expires, and the ``valid*`` forms are distinctive
# enough that a substring match carries no realistic collision.
_DEADLINE_HINTS = ("deadline", "expir", "validuntil", "validafter", "validbefore")


def _deadline_params(f: "_FuncSig") -> List[str]:
    """The parameter identifiers naming a deadline/expiry-like argument (names, not types)."""
    out: List[str] = []
    for ident in re.findall(r"[A-Za-z_]\w*", f.params):
        if any(hint in ident.lower() for hint in _DEADLINE_HINTS) and ident not in out:
            out.append(ident)
    return out


def _categories_by_owner(guards: List[GuardInventoryItem]) -> Dict[str, set]:
    """Map each guard-bearing function/modifier name to the set of categories it carries."""
    owner: Dict[str, set] = {}
    for g in guards:
        owner.setdefault(g.function, set()).add(g.defensive_category)
    return owner


def _verb_role(name: str) -> Optional[str]:
    """``privileged`` (admin verb), ``user`` (user-facing entry-point verb), or ``None``.

    The two sets are disjoint and curated: a verb in neither (``execute``, ``flashLoan``, …) is
    left unclassified rather than forced into a comparison it does not belong to.
    """
    toks = split_identifier(name)
    if not toks:
        return None
    if toks[0] in _PRIVILEGED_VERBS:
        return "privileged"
    if toks[0] in _USER_VERBS:
        return "user"
    return None


def _classify_for(f: "_FuncSig", category: str, owner: Dict[str, set]) -> str:
    """``guarded`` (``category`` visible on the function or a resolvable modifier), ``opaque``
    (applies a modifier whose effect we cannot see — delegated or inherited), or ``unguarded``.
    Opaque members are excluded from a comparison: the SDD says a modifier may enforce the
    property, so we never assume it does not."""
    cats = set(owner.get(f.name, ()))
    opaque = False
    for mod in f.modifiers:
        if mod in owner:
            cats |= owner[mod]  # modifier with an anchored guard: categories are known
        else:
            opaque = True  # delegates to an internal check, or inherited from a base
    if category in cats:
        return "guarded"
    if opaque:
        return "opaque"
    return "unguarded"


def _family_gap(
    members: List["_FuncSig"],
    category: str,
    owner: Dict[str, set],
    expected: str,
    precondition: str,
    opaque_names: "Collection[str]" = (),
) -> Optional[GuardGapHypothesis]:
    """Emit one ``inconsistent`` hypothesis when a group has a guarded and an unguarded member
    for ``category`` (opaque members excluded). ``None`` when the group is consistent.

    ``opaque_names`` promotes a would-be-unguarded member to opaque (excluded): the caller knows
    the property is delegated somewhere this parser cannot follow — the same epistemic state as an
    unresolved modifier, so it is treated the same way rather than asserted as a gap."""
    if len(members) < 2:
        return None

    def _cls(f: "_FuncSig") -> str:
        c = _classify_for(f, category, owner)
        if c == "unguarded" and f.name in opaque_names:
            return "opaque"
        return c

    cls = {f.name: _cls(f) for f in members}
    guarded = sorted(f.name for f in members if cls[f.name] == "guarded")
    unguarded = sorted(f.name for f in members if cls[f.name] == "unguarded")
    if not guarded or not unguarded:
        return None
    return GuardGapHypothesis(
        category=category,
        expected_guard=f"{expected} consistent with `{guarded[0]}`",
        observed_gap="inconsistent",
        affected_functions=unguarded,
        semantic_preconditions=[f"{precondition}; `{guarded[0]}` carries {category}"],
        negative_checks=[
            "a guard may be applied by a modifier not parsed here",
            "a guard may be inherited from a base contract",
            "the function may be intentionally exempt from this guard",
            "the property may be enforced upstream or by a protocol invariant",
        ],
    )


def _gap_hypotheses(
    guards: List[GuardInventoryItem], functions: List["_FuncSig"]
) -> List[GuardGapHypothesis]:
    """Deterministic, advisory within-group guard inconsistencies. Three categories, each over the
    population it actually belongs to:

    - ``access_control`` over each *privileged* verb family (set/withdraw/upgrade/…): a privileged
      sibling being guarded is a strong prior that the others should be too.
    - ``pause_toggle`` over *user-facing* external/public mutators (verbs NOT in the privileged
      set): a pause check is a protocol-state property of user entry points, not of admin ones
      (admins must act while paused), so privileged functions are deliberately not in this group.
    - ``freshness_check`` over functions that *accept a deadline/expiry parameter*: the parameter
      is direct evidence of time-bounded intent, so this group is keyed on the signature rather
      than the verb. Modifier-enforced deadlines resolve to guarded/opaque and drop out.

    Guards resolve through modifiers; an opaque modifier (delegated or inherited, e.g. OZ's
    inherited ``whenNotPaused``) excludes the function, so inherited-pause protocols read silent
    rather than noisy. Never a Finding; ``promotion.state`` stays ``hypothesis``.
    """
    owner = _categories_by_owner(guards)
    cands = [f for f in functions if f.visibility in ("external", "public") and f.mutates]

    out: List[GuardGapHypothesis] = []

    priv_families: Dict[str, List[_FuncSig]] = {}
    for f in cands:
        if _verb_role(f.name) == "privileged":
            priv_families.setdefault(split_identifier(f.name)[0], []).append(f)
    for verb, members in sorted(priv_families.items()):
        gap = _family_gap(
            members,
            "access_control",
            owner,
            "access control",
            f"`{verb}`-family privileged external/public state-changing functions",
        )
        if gap:
            out.append(gap)

    user_mutators = [f for f in cands if _verb_role(f.name) == "user"]
    gap = _family_gap(
        user_mutators,
        "pause_toggle",
        owner,
        "pause gating",
        "user-facing external/public state-changing functions",
    )
    if gap:
        out.append(gap)

    # freshness_check over functions that *accept* a deadline/expiry parameter: the parameter is
    # direct evidence the call is meant to be time-bounded, so a sibling in that population that
    # never checks it is an inconsistency. Modifier-enforced deadlines (DEX routers' ``ensure``/
    # ``checkDeadline``) resolve to guarded or opaque and drop out. A function that *forwards* the
    # parameter into its body (passing it to ``permit``, to an internal ``removeLiquidity``, …)
    # delegates the check somewhere this parser cannot follow, so it is opaque, not a gap — only a
    # function that accepts the parameter and never references it reads as unguarded.
    deadline_fns: List[_FuncSig] = []
    forwarded: set = set()
    for f in cands:
        names = _deadline_params(f)
        if not names:
            continue
        deadline_fns.append(f)
        body_idents = set(re.findall(r"[A-Za-z_]\w*", f.body))
        if any(n in body_idents for n in names):
            forwarded.add(f.name)
    gap = _family_gap(
        deadline_fns,
        "freshness_check",
        owner,
        "freshness/deadline enforcement",
        "external/public state-changing functions that accept a deadline/expiry parameter",
        opaque_names=forwarded,
    )
    if gap:
        # A forwarded or stored deadline is already opaque, so what reaches here is a function that
        # accepts the parameter and never references it at all; the benign reading is that the name
        # is only there to satisfy an interface/ABI signature and is intentionally unused.
        gap.negative_checks = [
            "the deadline/expiry parameter may exist only to satisfy an interface/ABI signature and"
            " be intentionally unused in this implementation",
            *gap.negative_checks,
        ]
        out.append(gap)
    return out


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
    gaps = _gap_hypotheses(guards, _collect_functions(masked))
    objective = f"Guard inventory for {anchor} ({len(guards)} guards"
    objective += f", {len(gaps)} gap hypotheses)" if gaps else ")"
    return [
        RevertInvariantOraclePlan(
            id=f"revinv-{anchor}",
            objective=objective,
            guard_inventory=guards,
            gap_hypotheses=gaps,
        )
    ]


__all__ = [
    "GuardInventoryItem",
    "GuardGapHypothesis",
    "RevertInvariantOraclePlan",
    "parse_revert_invariant_plans",
    "mine_revert_invariants",
]
