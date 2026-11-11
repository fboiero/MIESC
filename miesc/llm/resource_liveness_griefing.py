"""
Resource/Liveness griefing hardening — Phases 1-2 (progress surface + advisory hypotheses).

Phases 1-2 of ``docs/sdd/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md``. The SDD's insight:
the gap is not another ``for (...)`` regex (MIESC already emits DoS/unbounded-loop findings) but a
provider-neutral model of **progress** — which resources can be grown by an attacker, which
functions must make progress over them (withdraw, claim, settle, liquidate, …), and how they link.

**Phase 1** builds that *progress surface* deterministically (no provider, no LLM): for each
externally growable resource it records its kind, the functions that grow it, the progress-critical
functions that traverse it, and source anchors, into a :class:`ResourceLivenessGriefingPlan` (one
plan per resource).

**Phase 2** adds ``liveness_hypotheses``: deterministic, advisory :class:`LivenessHypothesis`
records keyed on the resource that *drives the loop header*. A hypothesis is emitted only when the
*progress control* that would disprove it is **not visible** — a guard-gap over the progress surface,
not another loop regex. Two categories ship:

- ``unbounded_loop`` — a state-changing entrypoint iterates a resource (by ``.length`` directly or a
  cached local) whose growth is attacker-controlled (a growth entrypoint with no access guard and no
  length cap), with no pagination, caller-owned slice, or clamped bound. This is the precise advisory
  view over ``smartbugs_detectors``'s ``DenialOfServiceDetector`` and ``examples``'s
  ``UnboundedLoopDetector``, which false-positive on paginated loops, admin-grown lists and clamped
  bounds this phase suppresses (measured 2026-11-11).
- ``push_payment_blocking`` — a push transfer to each element inside such a loop with no visible
  failure isolation (try/catch, or a low-level send/call whose failure is credited) and no
  self-service pull-payment path in the same contract. Also covers the ``.call{value:}`` idiom the
  DoS detector's ``.transfer``/``.send`` patterns miss (the SmartBugs ``send_loop.sol`` case).

``keeper_blocking`` and the other seven SDD categories are deferred to the LLM reasoning agent.
Known limit: growth is read from entrypoint bodies only, so a resource grown through an internal
helper, a constructor or the fallback is not seen as attacker-controlled and ``unbounded_loop`` stays
silent there (a false negative the LLM agent is expected to cover).

The whole module is **advisory**: a surface is an inventory and a hypothesis is an obligation, never
a ``Finding`` and never an "unbounded loop" accusation. Every hypothesis carries at least one
``negative_check`` — the condition that would reject it. ``promotion.state`` stays ``"hypothesis"``;
only replay, fuzzing, symbolic execution or human review promotes it. Later SDD phases (progress
oracles, execution plans, the LLM agent, and the deferred categories) build on this.
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

# Phase 2 reuses the governance access-modifier helpers rather than keeping a third copy: an
# access-control modifier (``only<Role>`` or an in-file/inherited caller-checking modifier) is
# exactly what decides whether a growth entrypoint is behind access control. (Growth uses its own
# narrower body guard below — the governance ``_GUARD_BODY_RE`` also treats an ``if (… msg.sender …)``
# dedup branch as a guard, which a growth entrypoint like ``deposit`` is not.)
from miesc.llm.privileged_governance_lifecycle import (
    _access_modifier_names,
    _contract_blocks,
    _header_has_access_modifier,
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

# The ten liveness-hypothesis categories named in the SDD. A category outside this set is dropped
# (in ``to_dict`` and in the parser): a provider may name one, but the schema is fixed. Phase 2's
# deterministic miner emits only the three with a defensible guard-gap test and a reproduced delta
# (see ``_derive_liveness_hypotheses``); the rest wait for the LLM reasoning agent.
_HYPOTHESIS_CATEGORIES = frozenset(
    {
        "unbounded_loop",
        "state_bloat",
        "push_payment_blocking",
        "withdrawal_queue_blocking",
        "keeper_blocking",
        "revert_griefing",
        "insufficient_gas_griefing",
        "batch_progress_failure",
        "rate_limit_gap",
        "fallback_absence",
    }
)


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
class LivenessHypothesis:
    """A deterministic, advisory hypothesis that a progress control may be missing.

    Never a Finding and never a confirmed state: a liveness gap is a hypothesis until replay,
    fuzzing, symbolic execution or human review demonstrates blocked progress, which Phase 2 does
    not do. The ``negative_checks`` list the conditions that would reject the hypothesis (the
    control that would make progress safe) so a reader weighs it rather than treating it as a defect.
    ``id`` lets a later phase (progress-oracle or execution-plan generation) key off one hypothesis.
    """

    category: str
    id: str = ""
    attacker_action: str = ""
    honest_user_goal: str = ""
    blocked_progress: str = ""
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
            "attacker_action": _safe_text(
                self.attacker_action, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "honest_user_goal": _safe_text(
                self.honest_user_goal, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "blocked_progress": _safe_text(
                self.blocked_progress, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "preconditions": _safe_text_list(self.preconditions),
            "negative_checks": _safe_text_list(self.negative_checks),
            "source_anchors": _safe_text_list(self.source_anchors),
        }


@dataclass
class ResourceLivenessGriefingPlan:
    id: str
    objective: str
    surface: Optional[GrowableSurface] = None
    liveness_hypotheses: List[LivenessHypothesis] = field(default_factory=list)
    promotion_state: str = "hypothesis"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surface": (self.surface or GrowableSurface(resource="")).to_dict(),
            # Phase 2. The SDD's schema shows the shape of a single ``liveness_hypothesis``; a
            # resource can warrant several, so they ride as a bounded list. The parser below also
            # accepts the SDD's singular key so provider-conformant output is not dropped.
            "liveness_hypotheses": [
                h.to_dict() for h in self.liveness_hypotheses[:MAX_AGENT_ITEMS]
            ],
            "promotion": {"state": self.promotion_state, "evidence": [], "blockers": []},
            "metadata": _json_safe_mapping(
                {
                    **self.metadata,
                    "capability": "resource_liveness_griefing_hardening",
                    "schema_version": "1",
                }
            ),
        }


def _hypotheses_from_raw(raw: Mapping[str, Any]) -> List[LivenessHypothesis]:
    """Parse ``liveness_hypotheses`` (list) or the SDD's singular ``liveness_hypothesis`` (dict).

    Drops any entry whose category is outside the ten or that carries no negative check: a
    hypothesis without the condition that would reject it is not a usable obligation.
    """
    raw_list = raw.get("liveness_hypotheses")
    if not isinstance(raw_list, list):
        singular = raw.get("liveness_hypothesis")
        raw_list = [singular] if isinstance(singular, Mapping) else []

    out: List[LivenessHypothesis] = []
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
            LivenessHypothesis(
                category=category,
                id=_safe_label(rh.get("id")) or "",
                attacker_action=_safe_text(
                    rh.get("attacker_action"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                honest_user_goal=_safe_text(
                    rh.get("honest_user_goal"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                blocked_progress=_safe_text(
                    rh.get("blocked_progress"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                preconditions=_safe_text_list(rh.get("preconditions")),
                negative_checks=negative_checks,
                source_anchors=_safe_text_list(rh.get("source_anchors")),
            )
        )
    return out


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
        raw_surface = raw.get("surface")
        rs: Mapping[str, Any] = raw_surface if isinstance(raw_surface, Mapping) else {}
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
                id=_safe_label(raw.get("id")) or "rliv",
                objective=objective,
                surface=surface,
                liveness_hypotheses=_hypotheses_from_raw(raw),
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

# Progress-critical stems, matched against camelCase / snake_case *tokens* (not as raw
# substrings) so ``emergencyWithdraw`` matches but ``preprocess`` does not falsely hit
# ``process`` mid-word.
_PROGRESS_STEMS = (
    "withdraw",
    "claim",
    "refund",
    "settle",
    "execute",
    "liquidat",
    "process",
    "finaliz",
    "redeem",
    "payout",
    "distribut",
    "relay",
    "upkeep",
    "recover",
    "dequeue",
    "flush",
)


def _tokenize(name: str) -> List[str]:
    """Split a camelCase / snake_case identifier into lowercase tokens."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name).replace("_", " ")
    return [p.lower() for p in spaced.split()]


def _is_progress_name(name: str) -> bool:
    return any(t.startswith(s) for t in _tokenize(name) for s in _PROGRESS_STEMS)


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
    # Match a kind keyword as a whole token, or (for long, unambiguous compound keys like
    # ``withdrawalqueue``) as a substring of the de-spaced name — so short keys like ``task``
    # or ``credit`` no longer hit mid-word (``taskmaster``).
    tokens = _tokenize(name)
    joined = "".join(tokens)
    for kind, keys in _KIND_BY_NAME:
        for k in keys:
            if any(t == k for t in tokens) or (len(k) >= 7 and k in joined):
                return kind
    return "mapping_index" if is_mapping else "array"


@dataclass(frozen=True)
class _Func:
    name: str
    start: int
    body: str
    is_progress: bool


_LOOP_HEAD_RE = re.compile(r"\b(?:for|while)\s*\(")


def _loop_texts(body: str) -> List[str]:
    """Text of every `for (...)`/`while (...)` loop in ``body``: header plus its block.

    Strings are already masked, so the keyword is only matched as code. A loop without braces
    runs to the next ``;``.
    """
    loops: List[str] = []
    for m in _LOOP_HEAD_RE.finditer(body):
        close = _match_paren(body, m.end() - 1)
        brace = body.find("{", close)
        semi = body.find(";", close)
        if brace != -1 and (semi == -1 or brace < semi):
            end = _match_brace(body, brace)
        else:
            end = semi if semi != -1 else len(body)
        loops.append(body[m.start() : end + 1])
    return loops


def _match_paren(source: str, open_paren: int) -> int:
    depth = 0
    for idx in range(open_paren, len(source)):
        if source[idx] == "(":
            depth += 1
        elif source[idx] == ")":
            depth -= 1
            if depth == 0:
                return idx
    return len(source)


def _functions(masked: str) -> List[_Func]:
    funcs: List[_Func] = []
    for m in _FUNCTION_RE.finditer(masked):
        brace = _body_brace(masked, m.end())
        if brace == -1:
            continue  # interface / abstract declaration: no body of its own
        end = _match_brace(masked, brace)
        funcs.append(
            _Func(
                name=m.group("name"),
                start=m.start(),
                body=masked[brace : end + 1],
                is_progress=_is_progress_name(m.group("name")),
            )
        )
    return funcs


# --------------------------------------------------------------------------------------
# Phase 2 — deterministic guard-gap liveness hypotheses over the progress surface.
# --------------------------------------------------------------------------------------
# A loop's bound is read from the first ``<`` / ``<=`` in its condition. The RHS is either
# ``<array>.length`` directly or a local variable we resolve below.
_BOUND_RE = re.compile(r"<\s*=?\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)")
# A bound definition that makes the loop caller-bounded rather than attacker-bounded: a clamp
# (``min``), a gas-metered loop (``gasleft``), or a ternary cap. ``start + n`` alone is not enough —
# the parameter check below catches a param-derived bound.
_CLAMP_RE = re.compile(r"(?i)\bmin\b|\bclamp\b|gasleft\s*\(|\?")
# A value push to each loop element: 0.8 ``.transfer``/``.send``/``.call{value:}``, the 0.4
# ``.call.value()()`` idiom, and the OZ ``sendValue``/``safeTransfer`` wrappers — the SmartBugs DoS
# gap the SDD names. (``DenialOfServiceDetector`` matches only ``.transfer``/``.send``.)
_LOOP_TRANSFER_RE = re.compile(
    r"(?i)(\.\s*transfer\s*\(|\.\s*send\s*\(|\.\s*call\s*\{[^}]*value|"
    r"\.\s*call\s*\.\s*value\s*\(|\bsendvalue\s*\(|\bsafetransfer\w*\s*\()"
)
# Failure isolation inside the loop body. A hard-reverting ``.transfer`` cannot be isolated by a
# later credit (the whole call frame reverts), so credit only isolates a *low-level* call: a
# ``.send``/``.call`` returns a bool, and a following indexed write (``owed[user] += amt`` /
# ``failed[recipient] = true``) records the failure for a later pull. The credit regex matches the
# closing ``]`` of any index expression (nested keys like ``failed[users[i]]`` included) before an
# assignment; ``==`` / ``<=`` are excluded.
_TRY_RE = re.compile(r"(?i)\btry\b")
_LOW_LEVEL_CALL_RE = re.compile(r"(?i)\.\s*send\s*\(|\.\s*call\s*[({]")
_CREDIT_WRITE_RE = re.compile(r"\]\s*(?:\+=|-=|=(?!=))")
# A separate pull-payment path: an entrypoint that reads an owed/pending balance keyed by the caller
# and pays the caller, so a blocked push is non-fatal. Name alone is not enough (a ``refunds`` map
# that is only a lookup, as in SmartBugs ``send_loop.sol``, is not a pull path) — the contract block
# must actually route ``[msg.sender]`` to a payment to ``msg.sender``.
_PAYS_SENDER_RE = re.compile(
    r"(?i)(payable\s*\(\s*msg\.sender|msg\.sender\s*\.\s*(?:transfer|send|call))"
)
_READS_SENDER_KEY_RE = re.compile(r"\[\s*msg\.sender\s*\]")
# A caller-bounded or gas-metered loop condition (in addition to the local-bound clamp): a compound
# condition or a gas check caps iteration regardless of the resource length.
_COND_CLAMP_RE = re.compile(r"(?i)&&|gasleft\s*\(")


def _entry_bodies(masked: str) -> List[Tuple[str, str, str, int, bool]]:
    """``(name, header, body, header_offset, is_entrypoint)`` for every function with a body.

    ``is_entrypoint`` is True only for a state-changing external/public function: internal/private
    helpers and ``view``/``pure``/``constant`` (0.4) getters are not attack surface, so they never
    seed a hypothesis. Phase 2 gates on this, not on Phase 1's ``progress_functions`` list (which
    keeps ``claimable``/``withdrawable`` views), so Phase 1 output stays byte-stable.
    """
    out: List[Tuple[str, str, str, int, bool]] = []
    for m in _FUNCTION_RE.finditer(masked):
        brace = _body_brace(masked, m.end())
        if brace == -1:
            continue
        close = _match_brace(masked, brace)
        header = masked[m.end() : brace]
        is_helper = re.search(r"\b(internal|private)\b", header) is not None
        is_readonly = re.search(r"\b(view|pure|constant)\b", header) is not None
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


def _loop_spans(body: str) -> List[Tuple[str, str]]:
    """``(condition_text, block_text)`` for every for/while loop in ``body`` (strings masked)."""
    spans: List[Tuple[str, str]] = []
    for m in _LOOP_HEAD_RE.finditer(body):
        open_paren = m.end() - 1
        close_paren = _match_paren(body, open_paren)
        cond = body[open_paren + 1 : close_paren]
        brace = body.find("{", close_paren)
        semi = body.find(";", close_paren)
        if brace != -1 and (semi == -1 or brace < semi):
            block = body[brace : _match_brace(body, brace) + 1]
        else:
            end = semi if semi != -1 else len(body)
            block = body[close_paren + 1 : end + 1]
        spans.append((cond, block))
    return spans


def _param_names(header: str) -> Set[str]:
    """Lowercased parameter names from a function header (text after ``(``, up to the first ``)``)."""
    close = header.find(")")
    params_text = header[:close] if close != -1 else ""
    names: Set[str] = set()
    for part in params_text.split(","):
        toks = re.findall(r"[A-Za-z_]\w*", part)
        if toks:
            names.add(toks[-1].lower())  # the last token of "type [location] name" is the name
    return names


def _local_def(body: str, var: str) -> Optional[str]:
    """Right-hand side of ``<type?> var = RHS;`` in ``body`` (the first assignment), or None."""
    m = re.search(r"\b" + re.escape(var) + r"\s*=\s*([^;]+);", body)
    return m.group(1).strip() if m else None


def _drives_unbounded(cond: str, resource: str, body: str, params: Set[str]) -> bool:
    """True when ``resource.length`` drives the loop bound with no caller-owned or clamped cap.

    Resolves the dominant ``uint len = arr.length; for (i < len)`` form. A bound that is a parameter,
    keyed by the caller, or clamped (``min`` / ternary / ``gasleft``) is a caller-owned slice (SDD
    l.125) and returns False; an unresolvable local also returns False (do not emit on a guess).
    """
    if _COND_CLAMP_RE.search(cond):  # `i < arr.length && gasleft() > x` is gas/compound-bounded
        return False
    m = _BOUND_RE.search(cond)
    if not m:
        return False
    bound = re.sub(r"\s+", "", m.group(1))
    rlen = resource.lower() + ".length"
    if bound.lower() == rlen:
        return True
    if "." in bound:  # some other <array>.length drives this loop, not this resource
        return False
    if bound.lower() in params:  # caller-owned bound
        return False
    rhs = _local_def(body, bound)
    if rhs is None:  # unresolved local — do not emit
        return False
    rlow = re.sub(r"\s+", "", rhs).lower()
    if _CLAMP_RE.search(rhs) or any(p in re.findall(r"[a-z_]\w*", rlow) for p in params):
        return False  # clamped or parameter-derived
    return rlow == rlen  # the local is solely resource.length


# An access guard *inside a growth entrypoint body*: a caller equality (``msg.sender == owner``), a
# role check, or an OZ ``_check*`` helper. Deliberately narrower than governance's ``_GUARD_BODY_RE``:
# it omits the ``if (… msg.sender …) { … }`` / ``require(… msg.sender …)`` branches, because a
# ``deposit`` that does ``if (balances[msg.sender] == 0) { list.push(msg.sender); }`` is open to
# everyone — that dedup check is not access control.
_GROWTH_GUARD_RE = re.compile(
    r"(?i)(_check(?:owner|role|admin|authoriz)[a-z]*\s*\(|\bhasrole\s*\(|"
    r"(?:msg\.sender|_msgsender\s*\(\s*\))\s*[=!]=|[=!]=\s*(?:msg\.sender|_msgsender\s*\(\s*\)))"
)


def _attacker_growable(
    resource: str,
    growth_sources: Set[str],
    bodies: List[Tuple[str, str, str, int, bool]],
    access_names: Set[str],
) -> bool:
    """True when some growth source lengthens ``resource`` from an unguarded, uncapped entrypoint.

    An admin-curated list (``addStrategy`` behind ``onlyOwner``) or a size-capped array is not
    attacker-growable, so the unbounded-loop hypothesis is suppressed (SDD l.129) — the measurable
    delta over the DoS detectors, which flag admin-grown arrays.
    """
    push_re = re.compile(r"\b" + re.escape(resource) + r"\s*\.\s*push\s*\(")
    cap_re = re.compile(
        r"(?i)require\s*\([^;{}]*\b" + re.escape(resource) + r"\s*\.\s*length\s*<=?"
    )
    for name, header, body, _off, ep in bodies:
        if name not in growth_sources or not ep:
            continue
        if _header_has_access_modifier(header, access_names) or _GROWTH_GUARD_RE.search(body):
            continue
        if not push_re.search(body):  # a mapping/compound write does not lengthen the array
            continue
        if cap_re.search(body):  # an explicit length cap bounds the growth
            continue
        return True
    return False


def _push_isolated(block: str) -> bool:
    """True when a reverting recipient is isolated: a try/catch, or a low-level send/call whose
    failure is credited (``.send``/``.call`` plus an indexed write). A hard ``.transfer`` is never
    isolated — the whole frame reverts before any credit runs.
    """
    if _TRY_RE.search(block):
        return True
    return bool(_LOW_LEVEL_CALL_RE.search(block) and _CREDIT_WRITE_RE.search(block))


def _pays_resource_element(block: str, resource: str) -> bool:
    """True when the transfer's *recipient* is an element of ``resource`` (``resource[i]``), not just
    any transfer in the loop. Distinguishes ``payable(users[i]).transfer(amt)`` (users is the payee)
    from ``IERC20(rewardTokens[i]).safeTransfer(msg.sender, amt)`` (rewardTokens is the token, the
    caller is the payee) — only the former is a push-to-each-recipient that one bad element blocks.
    """
    esc = re.escape(resource)
    # resource[...] as the call receiver: resource[i].transfer / payable(resource[i]).send / .call{…}
    receiver = re.compile(r"(?i)" + esc + r"\s*\[[^\]]*\]\s*\)?\s*\.\s*(?:transfer|send|call)")
    # or resource[...] as the first argument of safeTransfer / sendValue (the recipient slot)
    first_arg = re.compile(
        r"(?i)(?:safetransfer\w*|sendvalue)\s*\(\s*(?:payable\s*\(\s*)?" + esc + r"\s*\["
    )
    return bool(receiver.search(block) or first_arg.search(block))


def _block_bounds(
    off: int, blocks: List[Tuple[str, int, int]], end_default: int
) -> Tuple[int, int]:
    """``(start, end)`` offsets of the contract block containing ``off`` (whole file if none)."""
    for _name, start, end in blocks:
        if start <= off < end:
            return start, end
    return 0, end_default


def _has_pull_path(
    bodies: List[Tuple[str, str, str, int, bool]], lo: int, hi: int, access_names: Set[str]
) -> bool:
    """True when some *unrestricted* entrypoint within ``[lo, hi)`` reads an owed balance keyed by the
    caller and pays the caller in the *same* body — a self-service pull path. Both signals must
    co-occur in one function (a deposit writing ``bal[msg.sender]`` plus an unrelated sweep paying
    ``msg.sender`` is not one), and the function must not be access-restricted (an ``onlyOwner`` sweep
    that pays the owner is not a user pull path)."""
    for _name, header, body, off, ep in bodies:
        if not ep or not (lo <= off < hi):
            continue
        if _header_has_access_modifier(header, access_names):
            continue
        if _READS_SENDER_KEY_RE.search(body) and _PAYS_SENDER_RE.search(body):
            return True
    return False


def _anchor_lines(source: str, anchor: str, offsets: List[int]) -> List[str]:
    """``file:line`` anchors for the given header offsets, bounded and de-duplicated in order."""
    seen: Dict[str, None] = {}
    for off in offsets:
        seen.setdefault(f"{anchor}:{_line_of(source, off)}", None)
    return list(seen)[:MAX_AGENT_ITEMS]


def _derive_liveness_hypotheses(
    source: str,
    anchor: str,
    masked: str,
    plans: List[ResourceLivenessGriefingPlan],
) -> None:
    """Attach advisory guard-gap hypotheses to each resource plan (mutates ``plan`` in place).

    Each hypothesis keys on the resource that *drives the loop header* — the array whose ``.length``
    (directly or via a cached local) bounds the loop — not every resource the body touches. So a
    single loop over ``depositors`` that reads ``balances[depositors[i]]`` yields one hypothesis on
    ``depositors``, never a duplicate on ``balances``. Two categories ship (``unbounded_loop``,
    ``push_payment_blocking``); ``keeper_blocking`` and the other seven are deferred.
    """
    access_names = _access_modifier_names(masked)
    bodies = _entry_bodies(masked)
    blocks = _contract_blocks(masked)

    for plan in plans:
        surf = plan.surface
        if surf is None or not surf.resource:
            continue
        resource = surf.resource
        growth = set(surf.growth_sources)

        unbounded_offs: List[int] = []
        push_offs: List[int] = []

        for _name, header, body, off, ep in bodies:
            if not ep:
                continue
            params = _param_names(header)
            unbounded_here = False
            push_here = False
            for cond, block in _loop_spans(body):
                # Only the resource that drives the loop header owns the hypothesis. A parameter or
                # clamped bound returns False here, so a paginated / caller-owned loop seeds nothing.
                if not _drives_unbounded(cond, resource, body, params):
                    continue
                unbounded_here = True
                if (
                    _LOOP_TRANSFER_RE.search(block)
                    and _pays_resource_element(block, resource)
                    and not _push_isolated(block)
                ):
                    push_here = True
            if unbounded_here:
                unbounded_offs.append(off)
            if push_here:
                push_offs.append(off)

        hyps: List[LivenessHypothesis] = []

        # 1. unbounded_loop — a progress loop over an attacker-growable resource with no cap.
        if unbounded_offs and _attacker_growable(resource, growth, bodies, access_names):
            hyps.append(
                LivenessHypothesis(
                    category="unbounded_loop",
                    id=f"unbounded_loop-{anchor}-{resource}",
                    attacker_action=f"An attacker inflates '{resource}' through an unguarded growth "
                    "entrypoint until a progress loop over it exceeds the block gas limit.",
                    honest_user_goal=f"Reach the progress function that iterates all of '{resource}' "
                    "(a withdraw/claim/settle path).",
                    blocked_progress=f"The loop over '{resource}' no longer fits in a block, so the "
                    "progress function reverts for every caller — funds or settlement are stuck.",
                    preconditions=[
                        f"'{resource}' grows through a state-changing entrypoint with no access "
                        "guard and no length cap",
                        f"a progress entrypoint iterates all of '{resource}' with no pagination or "
                        "caller-owned bound",
                    ],
                    negative_checks=[
                        f"the loop is bounded by pagination, a caller-owned slice, or a constant cap "
                        f"on '{resource}'.length",
                        f"growth of '{resource}' is access-controlled or length-capped, so an "
                        "attacker cannot inflate it",
                    ],
                    source_anchors=_anchor_lines(source, anchor, unbounded_offs),
                )
            )

        # 2. push_payment_blocking — a push transfer per element with no isolation or pull path.
        lo, hi = _block_bounds(push_offs[0], blocks, len(masked)) if push_offs else (0, 0)
        if push_offs and not _has_pull_path(bodies, lo, hi, access_names):
            hyps.append(
                LivenessHypothesis(
                    category="push_payment_blocking",
                    id=f"push_payment_blocking-{anchor}-{resource}",
                    attacker_action=f"An attacker enters '{resource}' as a recipient whose fallback "
                    "always reverts.",
                    honest_user_goal=f"Let the push payment distributed by iterating '{resource}' "
                    "reach every recipient.",
                    blocked_progress=f"A single reverting recipient makes the whole push loop over "
                    f"'{resource}' revert, blocking the payout for everyone.",
                    preconditions=[
                        f"a progress entrypoint pushes value to each element of '{resource}' inside "
                        "a loop",
                        "no visible failure isolation (try/catch or credited retry) around the "
                        "transfer, and no separate pull-payment path in this contract",
                    ],
                    negative_checks=[
                        "each recipient failure is isolated by a try/catch or credited to a pending "
                        "balance for later pull",
                        "a separate pull-payment path lets each recipient withdraw independently, "
                        "not matched in this file",
                    ],
                    source_anchors=_anchor_lines(source, anchor, push_offs),
                )
            )

        plan.liveness_hypotheses = hyps[:MAX_AGENT_ITEMS]


def mine_resource_liveness_griefing(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[ResourceLivenessGriefingPlan]:
    """Deterministically build the progress surface (growable resources × progress functions).

    Returns one plan per growable resource that a progress-named function traverses with a
    loop (an O(1) per-user access is not a surface); empty list when none. Phase 2 then attaches
    advisory guard-gap liveness hypotheses to each plan. Never raises and never emits a Finding.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return []
    # Comments first, then string contents: a "for" inside an error message is not a loop.
    masked = _mask_strings(_strip_comments(source_code))
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
        esc = re.escape(name)
        push = re.compile(r"\b" + esc + r"\s*\.\s*push\s*\(")
        # Growth = push, compound-add (`+=`), or a non-clearing assignment. Deliberately NOT
        # `==` (a comparison), `-=` (a reduction), `= 0` / `= false` (a clear), or `delete`.
        grow_add = re.compile(r"\b" + esc + r"\s*\[[^\]]*\]\s*\+=")
        # `\s*` lives INSIDE the negative lookahead so backtracking can't bypass the
        # not-a-clear check (a bare `\s*` before it would match zero width and pass on ` 0`).
        grow_set = re.compile(
            r"\b" + esc + r"\s*\[[^\]]*\]\s*=(?!=)(?!\s*(?:0\b|false\b|0x0+\b|delete\b))"
        )
        # Traversal = a `for`/`while` loop whose header or body reads the resource (by index,
        # by `.length`, or by name). The reference has to be *inside the loop*: a loop over
        # another array elsewhere in the function plus an O(1) read of this one is not it.
        refs_re = re.compile(r"\b" + esc + r"\b")

        traversal = sorted(
            {
                f.name
                for f in funcs
                if f.is_progress and any(refs_re.search(loop) for loop in _loop_texts(f.body))
            }
        )
        # The SDD gap is *progress over* a growable resource. An O(1) access (e.g. a per-user
        # `withdraw` reading `balances[msg.sender]`) is not a griefing surface, and a resource
        # nobody traverses with a loop is not one either — so require a traversal.
        if not traversal:
            continue
        growth = sorted(
            {
                f.name
                for f in funcs
                if push.search(f.body) or grow_add.search(f.body) or grow_set.search(f.body)
            }
        )
        surface = GrowableSurface(
            resource=name,
            resource_kind=meta["kind"],
            growth_sources=growth[:MAX_AGENT_ITEMS],
            progress_functions=traversal[:MAX_AGENT_ITEMS],
            source_anchors=[meta["anchor"]],
        )
        plans.append(
            ResourceLivenessGriefingPlan(
                id=f"rliv-{anchor}-{name}",
                objective=f"Progress surface for '{name}' in {anchor}",
                surface=surface,
            )
        )

    # Phase 2: attach advisory guard-gap liveness hypotheses to each resource plan.
    _derive_liveness_hypotheses(source_code, anchor, masked, plans)
    return plans[:MAX_AGENT_ITEMS]


__all__ = [
    "GrowableSurface",
    "LivenessHypothesis",
    "ResourceLivenessGriefingPlan",
    "parse_resource_liveness_plans",
    "mine_resource_liveness_griefing",
]
