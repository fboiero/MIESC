"""
Reentrancy triage — partition Slither reentrancy findings into REVIEW vs NOISE.
=============================================================================

Dogfooding nine real audited codebases produced one consistent shape: the static
scanner *locates* the subsystem a real reentrancy lives in, but it cannot
*adjudicate* which of its many ``reentrancy-*`` findings is worth a human's time.
Royco Dawn is the canonical case — the real ERC-777 redemption reentrancy sits
behind one of nineteen ``reentrancy-no-eth`` findings, most of which are admin
setters and access-gated no-ops.

This module is the first adjudication layer: a deterministic, source-free
partition of reentrancy findings into two tiers, each finding carrying the named
signals that placed it there. It does NOT claim exploitability — proving that
needs the token-hook precondition (not statically visible) and a protocol NAV /
accounting invariant (semantic). It narrows *where to look*: on the nine-target
corpus it keeps the value-moving redemption / liquidation / deposit entrypoints
in REVIEW and drops admin/config setters and access-only no-ops to NOISE.

Honesty / scope
---------------
- Signals are parsed from Slither's structured ``reentrancy-*`` description
  (``External calls:`` / ``State variables written after the call(s):`` /
  ``can be used in cross function reentrancies``); no source is read, so the
  partition is a pure function of the findings.
- It deliberately does NOT model ``nonReentrant`` mutexes, CEI ordering, or
  token-hook preconditions. A guarded value-op therefore stays in REVIEW — that
  remains the reviewer's call. Modelling guards (with source access, and the
  cross-function nuance that every writer of the shared slot must be guarded) is
  a separate follow-up.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

# Function-name roles (matched against the ENCLOSING function name only, never the
# whole description — a `transferFrom` inside a callee list must not inflate the
# enclosing function's role).
# Generic verbs like `add` / `remove` / `update` are deliberately excluded: they
# front value-moving ops (`addLiquidity`, `removeCollateral`, `updatePosition`) far
# more often than they front pure admin, so the value/state checks adjudicate them.
_ADMIN_FN_RE = re.compile(
    r"^(set|pause|unpause|init|initialize|configure|config|deploy|grant|revoke|"
    r"register|whitelist|blacklist|renounce|transferOwnership|authorize|upgrade|"
    r"migrate|rescue|sweep|recover)",
    re.IGNORECASE,
)
_VALUE_FN_RE = re.compile(
    r"(redeem|withdraw|deposit|mint|burn|borrow|repay|claim|liquidat|swap|settle|"
    r"unstake|stake|flash|collect|harvest|redemption|send|payout|distribute)",
    re.IGNORECASE,
)

# External-call callees that are pure access/authorization checks — an external
# call list containing ONLY these is not a real reentrancy source.
_ACCESS_CALL_RE = re.compile(
    r"\b(restricted|consumeScheduledOp|authority|hasRole|checkRole|_checkRole|"
    r"onlyRole|_authorizeUpgrade|_checkOwner|owner|paused|_requireNotPaused)\b",
    re.IGNORECASE,
)

# Value-bearing state written after the external call(s) — the accounting a stale
# re-entrant read could exploit.
_VALUE_STATE_RE = re.compile(
    r"nav|supply|shares?|balance|total|asset|accounting|debt|collateral|reserve|"
    r"principal|liquidit|deposit|price|rate|fee|reward|stake",
    re.IGNORECASE,
)

_REENTRANCY_TYPE_RE = re.compile(r"^reentrancy-", re.IGNORECASE)


@dataclass
class TriagedReentrancy:
    """A reentrancy finding with its triage tier and the signals behind it."""

    finding: Dict[str, Any]
    function: str
    tier: str  # "review" | "noise"
    signals: List[str] = field(default_factory=list)
    reason: str = ""


def _enclosing_function(description: str) -> str:
    """The `Contract.fn(params)` Slither names after `Reentrancy in `, or ''."""
    m = re.search(r"Reentrancy in\s+([^()]+\([^)]*\))", description)
    return m.group(1).strip() if m else ""


def _function_name(signature: str) -> str:
    """Bare function name from `Contract.fn(params)` (the part after the last dot)."""
    head = signature.split("(", 1)[0]
    return head.rsplit(".", 1)[-1] if "." in head else head


def _section(description: str, header: str, *stops: str) -> str:
    """Text of a labelled section of the description up to the next known header."""
    stop_alt = "|".join(re.escape(s) for s in stops) or r"\Z"
    m = re.search(re.escape(header) + r"(.*?)(?:" + stop_alt + r"|\Z)", description, re.S)
    return m.group(1) if m else ""


def _external_calls(description: str) -> str:
    return _section(
        description,
        "External calls:",
        "State variables written after the call(s):",
        "can be used in cross function reentrancies",
    )


def _state_writes(description: str) -> str:
    return _section(
        description,
        "State variables written after the call(s):",
        "can be used in cross function reentrancies",
    )


def _has_nonaccess_external_call(external_calls: str) -> bool:
    """True if some external call is more than a pure access/authorization check.

    Each `- <call> (file#line)` bullet is inspected; a call that is only an access
    guard (`restricted()`, `consumeScheduledOp`, role/owner/paused checks) does not
    make a function a meaningful reentrancy source on its own.
    """
    bullets = re.split(r"\n\s*-\s+|\s-\s+", external_calls)
    for b in bullets:
        b = b.strip()
        if not b or "(" not in b:
            continue
        if not _ACCESS_CALL_RE.search(b):
            return True
    return False


def triage_reentrancy(findings: List[Dict[str, Any]]) -> List[TriagedReentrancy]:
    """Partition Slither reentrancy findings into REVIEW vs NOISE tiers.

    Args:
        findings: MIESC/Slither finding dicts (``type``, ``description`` …). Only
            those whose ``type`` starts with ``reentrancy-`` are considered; the
            rest are ignored (returned list covers reentrancy findings only).

    Returns:
        One TriagedReentrancy per reentrancy finding, each with ``tier`` set to
        ``"review"`` or ``"noise"`` and the named ``signals`` that decided it.
        REVIEW requires a value-moving function (not an admin setter), a non-access
        external call, and a value-bearing state write after it.
    """
    triaged: List[TriagedReentrancy] = []
    for finding in findings:
        ftype = str(finding.get("type") or "")
        if not _REENTRANCY_TYPE_RE.match(ftype):
            continue
        desc = str(finding.get("description") or "")
        sig = _enclosing_function(desc)
        fname = _function_name(sig)

        signals: List[str] = []
        is_admin = bool(_ADMIN_FN_RE.match(fname))
        is_value = bool(_VALUE_FN_RE.search(fname))
        nonaccess = _has_nonaccess_external_call(_external_calls(desc))
        value_state = bool(_VALUE_STATE_RE.search(_state_writes(desc)))
        cross_fn = "cross function reentrancies" in desc

        if is_admin:
            signals.append("admin-function")
        if is_value:
            signals.append("value-function")
        if nonaccess:
            signals.append("non-access-external-call")
        else:
            signals.append("access-only-calls")
        if value_state:
            signals.append("value-state-after")
        if cross_fn:
            signals.append("cross-fn-reach")

        review = is_value and not is_admin and nonaccess and value_state
        if review:
            tier, reason = (
                "review",
                "value-moving op with a non-access external call and value-state written after it",
            )
        elif is_admin:
            tier, reason = "noise", "admin / configuration function"
        elif not nonaccess:
            tier, reason = "noise", "external calls are access/authorization checks only"
        elif not value_state:
            tier, reason = "noise", "no value-bearing state written after the call"
        else:
            tier, reason = "noise", "not a value-moving entrypoint"

        triaged.append(
            TriagedReentrancy(
                finding=finding,
                function=sig or fname,
                tier=tier,
                signals=signals,
                reason=reason,
            )
        )
    return triaged


def review_tier(findings: List[Dict[str, Any]]) -> List[TriagedReentrancy]:
    """Just the REVIEW-tier reentrancy findings (the shortlist to adjudicate)."""
    return [t for t in triage_reentrancy(findings) if t.tier == "review"]


def triage_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """{'reentrancy_total': N, 'review': r, 'noise': n} over the given findings."""
    triaged = triage_reentrancy(findings)
    review = sum(1 for t in triaged if t.tier == "review")
    return {
        "reentrancy_total": len(triaged),
        "review": review,
        "noise": len(triaged) - review,
    }


def annotate_results(all_results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Annotate reentrancy findings across scan results, in place, recall-safe.

    Each reentrancy finding gains ``finding["reentrancy_triage"] = {tier, signals,
    reason}``; nothing is dropped or reordered. ``all_results`` is the scan's list
    of per-tool result dicts (each with a ``findings`` list). Returns the aggregate
    ``{'reentrancy_total', 'review', 'noise'}`` so the caller can print a summary.
    """
    total = 0
    review = 0
    for result in all_results:
        for t in triage_reentrancy(result.get("findings") or []):
            t.finding["reentrancy_triage"] = {
                "tier": t.tier,
                "signals": list(t.signals),
                "reason": t.reason,
            }
            total += 1
            if t.tier == "review":
                review += 1
    return {"reentrancy_total": total, "review": review, "noise": total - review}


__all__ = [
    "TriagedReentrancy",
    "triage_reentrancy",
    "review_tier",
    "triage_summary",
    "annotate_results",
]
