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
from typing import Any, Callable, Dict, List, Optional, Tuple

# A source reader maps a finding's file path (as Slither reports it, relative to the
# scanned repo root) to that file's text, or None when it cannot be read. Passing one
# to the triage turns on the source-read guard evidence; without it the triage stays
# a pure function of the findings (unchanged #307 behaviour).
SourceReader = Callable[[str], Optional[str]]

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

# ---------------------------------------------------------------------------
# Guard evidence (source-read, opt-in)
# ---------------------------------------------------------------------------
#
# A recognized OpenZeppelin `nonReentrant` modifier ON THE REPORTED FUNCTION, when
# the finding has no cross-function reach, is the one case where a guard fully
# covers the finding and it can be safely demoted out of REVIEW (to "guarded").
# Everything else is surfaced, never demoted: custom mutexes (a state-var lock,
# e.g. v4lend's `transformedTokenId` / a `revert Reentrancy()`) and CEI ordering
# are real but not statically provable to cover the path, so they stay REVIEW with
# a "verify this guard" note. A guard on a *caller* (Slither often reports the
# internal `_withdraw`) does not show on the reported function, so it reads as
# `none` — narrow beats wrong.
_OZ_GUARD_RE = re.compile(r"\bnonReentrant(?:ReadOnly)?\b")
# A mutex-shaped reverting check: a reentrancy-named revert, or a guard clause on a
# lock-looking state variable. Heuristic — only ever used to annotate, never demote.
_MUTEX_REVERT_RE = re.compile(
    r"\brevert\s+(?:\w*Reentran\w*|\w*Lock\w*|AlreadyEntered)\b",
    re.IGNORECASE,
)
_MUTEX_LOCK_VAR_RE = re.compile(
    r"\b(?:if\s*\(|require\s*\()\s*!?\s*"
    r"([A-Za-z_]\w*(?:[Ll]ock|[Ee]ntered|_status|[Mm]utex|[Gg]uard|TokenId|[Ll]ocked))\b",
)
# Location of the reported function. Robust to both description formats: raw
# Slither (`... (src/File.sol#318-352):`) and the MIESC-processed markdown form
# (`[C.fn(...)](src/File.sol#L27-L37):`). The function's own location is the first
# `<file>#<lines>` in the description (external-call locations come after it).
_LOCATION_RE = re.compile(r"([\w./-]+\.(?:sol|vy))#L?(\d+)(?:[-–]L?(\d+))?")


@dataclass
class TriagedReentrancy:
    """A reentrancy finding with its triage tier and the signals behind it."""

    finding: Dict[str, Any]
    function: str
    tier: str  # "review" | "guarded" | "noise"
    signals: List[str] = field(default_factory=list)
    reason: str = ""
    # Source-read guard evidence, when a source reader was supplied:
    # "oz-nonreentrant" | "custom-mutex-candidate" | "none" | "unknown".
    guard: str = "unknown"


def _parse_location(description: str) -> Optional[Tuple[str, int, int]]:
    """(file, start_line, end_line) of the reported function, or None."""
    m = _LOCATION_RE.search(description)
    if not m:
        return None
    start = int(m.group(2))
    end = int(m.group(3)) if m.group(3) else start
    return m.group(1).strip(), start, end


def _function_source(description: str, source_reader: SourceReader) -> Optional[str]:
    """Text of the reported function's own lines, or None when unreadable."""
    loc = _parse_location(description)
    if loc is None:
        return None
    file, start, end = loc
    try:
        text = source_reader(file)
    except Exception:
        return None
    if not text:
        return None
    lines = text.splitlines()
    # Slither lines are 1-based; clamp defensively.
    lo = max(start - 1, 0)
    hi = min(end, len(lines))
    if lo >= hi:
        return None
    return "\n".join(lines[lo:hi])


def _function_header(function_source: str) -> str:
    """The signature/modifier portion before the function body's first `{`."""
    brace = function_source.find("{")
    return function_source if brace < 0 else function_source[:brace]


def _classify_guard(function_source: Optional[str]) -> str:
    """Classify the reentrancy guard present on the reported function's own source."""
    if function_source is None:
        return "unknown"
    if _OZ_GUARD_RE.search(_function_header(function_source)):
        return "oz-nonreentrant"
    if _MUTEX_REVERT_RE.search(function_source) or _MUTEX_LOCK_VAR_RE.search(function_source):
        return "custom-mutex-candidate"
    return "none"


def _enclosing_function(description: str) -> str:
    """The `Contract.fn(params)` Slither names after `Reentrancy in `, or ''.

    Handles both the raw (`Reentrancy in C.fn(x) (...)`) and the MIESC-processed
    markdown form (`Reentrancy in [C.fn(x)](...)`) by tolerating a leading ``[``.
    """
    m = re.search(r"Reentrancy in\s+\[?([^()\[\]]+\([^)]*\))", description)
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


def triage_reentrancy(
    findings: List[Dict[str, Any]],
    source_reader: Optional[SourceReader] = None,
) -> List[TriagedReentrancy]:
    """Partition Slither reentrancy findings into REVIEW / GUARDED / NOISE tiers.

    Args:
        findings: MIESC/Slither finding dicts (``type``, ``description`` …). Only
            those whose ``type`` starts with ``reentrancy-`` are considered; the
            rest are ignored (returned list covers reentrancy findings only).
        source_reader: optional file-path -> source-text reader. When supplied, each
            REVIEW finding gains source-read guard evidence (``guard`` + a
            ``guard:<class>`` signal). A recognized ``nonReentrant`` on the reported
            function with no cross-function reach is demoted to the ``"guarded"``
            tier; custom mutexes and anything uncertain are annotated but never
            demoted. Without a reader the triage is a pure function of the findings.

    Returns:
        One TriagedReentrancy per reentrancy finding, with ``tier`` in
        {``"review"``, ``"guarded"``, ``"noise"``}, the named ``signals``, and
        ``guard`` ("unknown" when no reader was supplied).
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

        # Source-read guard evidence (opt-in). Only REVIEW findings are inspected —
        # a guard never rescues a NOISE classification, only refines REVIEW.
        guard = "unknown"
        if source_reader is not None and tier == "review":
            guard = _classify_guard(_function_source(desc, source_reader))
            signals.append(f"guard:{guard}")
            if guard == "oz-nonreentrant" and not cross_fn:
                tier = "guarded"
                reason = (
                    "recognized nonReentrant guard on the function with no "
                    "cross-function reach — reentrancy is covered"
                )
            elif guard == "oz-nonreentrant":
                reason += " (nonReentrant present, but cross-function reach remains — verify all writers of the slot are guarded)"
            elif guard == "custom-mutex-candidate":
                reason += " (a mutex-shaped guard is present — verify it covers this path)"

        triaged.append(
            TriagedReentrancy(
                finding=finding,
                function=sig or fname,
                tier=tier,
                signals=signals,
                reason=reason,
                guard=guard,
            )
        )
    return triaged


def review_tier(findings: List[Dict[str, Any]]) -> List[TriagedReentrancy]:
    """Just the REVIEW-tier reentrancy findings (the shortlist to adjudicate)."""
    return [t for t in triage_reentrancy(findings) if t.tier == "review"]


def triage_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """{'reentrancy_total': N, 'review': r, 'guarded': g, 'noise': n}."""
    triaged = triage_reentrancy(findings)
    review = sum(1 for t in triaged if t.tier == "review")
    guarded = sum(1 for t in triaged if t.tier == "guarded")
    return {
        "reentrancy_total": len(triaged),
        "review": review,
        "guarded": guarded,
        "noise": len(triaged) - review - guarded,
    }


def _repo_source_reader(source_root: str) -> SourceReader:
    """A source reader that resolves a Slither file path under ``source_root``.

    Tries the path as given, under the root, and by basename anywhere below the
    root; returns None (never raises) when the file cannot be found or read, so a
    missing source degrades the guard to "unknown" rather than breaking the scan.
    """
    from pathlib import Path

    root = Path(source_root)
    base = root if root.is_dir() else root.parent
    cache: Dict[str, Optional[str]] = {}

    def read(file: str) -> Optional[str]:
        if file in cache:
            return cache[file]
        text: Optional[str] = None
        candidates = [Path(file), base / file]
        for cand in candidates:
            try:
                if cand.is_file():
                    text = cand.read_text(encoding="utf-8")
                    break
            except Exception:
                continue
        if text is None:
            try:
                # Only trust a basename search when it is UNAMBIGUOUS: several files
                # with the same name (a lib/ copy, a build artifact) could slice the
                # wrong lines and manufacture a false guard. Narrow beats wrong.
                hits = [p for p in base.rglob(Path(file).name) if p.is_file()]
                if len(hits) == 1:
                    text = hits[0].read_text(encoding="utf-8")
            except Exception:
                text = None
        cache[file] = text
        return text

    return read


def annotate_results(
    all_results: List[Dict[str, Any]], source_root: Optional[str] = None
) -> Dict[str, int]:
    """Annotate reentrancy findings across scan results, in place, recall-safe.

    Each reentrancy finding gains ``finding["reentrancy_triage"] = {tier, signals,
    reason, guard}``; nothing is dropped or reordered. When ``source_root`` is given
    the guard evidence is source-read (and the narrow ``guarded`` demotion applies);
    otherwise ``guard`` is "unknown". Returns the aggregate
    ``{'reentrancy_total', 'review', 'guarded', 'noise'}`` for the caller's summary.
    """
    reader = _repo_source_reader(source_root) if source_root else None
    total = review = guarded = 0
    for result in all_results:
        for t in triage_reentrancy(result.get("findings") or [], source_reader=reader):
            t.finding["reentrancy_triage"] = {
                "tier": t.tier,
                "signals": list(t.signals),
                "reason": t.reason,
                "guard": t.guard,
            }
            total += 1
            if t.tier == "review":
                review += 1
            elif t.tier == "guarded":
                guarded += 1
    return {
        "reentrancy_total": total,
        "review": review,
        "guarded": guarded,
        "noise": total - review - guarded,
    }


__all__ = [
    "TriagedReentrancy",
    "triage_reentrancy",
    "review_tier",
    "triage_summary",
    "annotate_results",
]
