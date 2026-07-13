"""
MIESC Hypothesis Ledger - Explicit Agentic Memory

The ledger is the memory that makes agentic audit passes *compound* instead of
*repeat*. Every suspected bug is recorded as a :class:`Hypothesis` with a stable
id and a status (``open`` / ``ruled_out`` / ``confirmed``). Once an id has been
seen it can never be re-added or re-opened, so the LLM never re-checks a claim it
already decided on. :meth:`HypothesisLedger.summary_for_prompt` renders a compact
digest of what has already been checked, injected each round to give the loop a
real convergence criterion.

Design: docs/design/agentic_auditor_phase1_20260707.md (§4, D4).

Author: Fernando Boiero
License: AGPL-3.0
"""

import hashlib
import re
from dataclasses import dataclass, field

# Recognized vulnerability classes (informational; not enforced).
VULN_CLASSES = (
    "arithmetic",
    "access_control",
    "reentrancy",
    "accounting",
    "state_consistency",
    "other",
)

_STATUS_OPEN = "open"
_STATUS_RULED_OUT = "ruled_out"
_STATUS_CONFIRMED = "confirmed"


def _normalize_claim(claim: str) -> str:
    """Normalize a claim for stable hashing: lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", claim.strip().lower())


def hypothesis_id(contract: str, function: str, claim: str) -> str:
    """Compute the stable id for a hypothesis.

    The id is a hash of ``(contract, function, normalized_claim)`` so the same
    suspected bug maps to the same id regardless of whitespace/casing in the
    claim. This is the dedup key the ledger relies on.
    """
    key = f"{contract}\x00{function}\x00{_normalize_claim(claim)}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class Hypothesis:
    """A single suspected vulnerability tracked across the agentic loop."""

    id: str  # stable hash of (contract, function, normalized_claim)
    contract: str
    function: str
    vuln_class: (
        str  # arithmetic | access_control | reentrancy | accounting | state_consistency | other
    )
    claim: str  # one-sentence suspected bug
    status: str = _STATUS_OPEN  # open | ruled_out | confirmed
    evidence: list[str] = field(default_factory=list)
    severity: str | None = None

    @classmethod
    def make(cls, contract: str, function: str, vuln_class: str, claim: str) -> "Hypothesis":
        """Build a Hypothesis with a correctly-computed stable id."""
        return cls(
            id=hypothesis_id(contract, function, claim),
            contract=contract,
            function=function,
            vuln_class=vuln_class,
            claim=claim,
        )


class HypothesisLedger:
    """Explicit memory of every hypothesis, keyed by stable id.

    Dedup guarantee: once an id has been seen (in any status), a later
    :meth:`add` of that id returns ``False`` and does not reopen it. This is
    what makes passes compound instead of repeat.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, Hypothesis] = {}

    def add(self, h: Hypothesis) -> bool:
        """Register a hypothesis. Returns ``False`` if its id was already seen.

        A duplicate id is never re-added or reopened, regardless of whether the
        existing entry is open, ruled_out, or confirmed.
        """
        if h.id in self._by_id:
            return False
        self._by_id[h.id] = h
        return True

    def rule_out(self, hid: str, reason: str) -> None:
        """Mark an open hypothesis as ruled out, recording the reason."""
        h = self._by_id.get(hid)
        if h is None:
            return
        h.status = _STATUS_RULED_OUT
        h.evidence.append(f"ruled_out: {reason}")

    def confirm(self, hid: str, evidence: str, severity: str) -> None:
        """Mark a hypothesis as confirmed, recording evidence and severity."""
        h = self._by_id.get(hid)
        if h is None:
            return
        h.status = _STATUS_CONFIRMED
        h.severity = severity
        h.evidence.append(f"confirmed: {evidence}")

    def open_ids(self) -> list[str]:
        """Ids of hypotheses still awaiting a verdict."""
        return [hid for hid, h in self._by_id.items() if h.status == _STATUS_OPEN]

    def confirmed(self) -> list[Hypothesis]:
        """All confirmed hypotheses (the audit's findings)."""
        return [h for h in self._by_id.values() if h.status == _STATUS_CONFIRMED]

    def surviving(self) -> list[Hypothesis]:
        """Confirmed OR still-open hypotheses — everything not ruled out. These are
        the audit's findings: enumeration reliably surfaces real candidates, so
        verification's job is to DROP clear false positives, not to gate."""
        return [h for h in self._by_id.values() if h.status != _STATUS_RULED_OUT]

    def ruled_out(self) -> list[Hypothesis]:
        """All ruled-out hypotheses."""
        return [h for h in self._by_id.values() if h.status == _STATUS_RULED_OUT]

    def all(self) -> list[Hypothesis]:
        """Every hypothesis in insertion order."""
        return list(self._by_id.values())

    def summary_for_prompt(self) -> str:
        """Compact digest of open + ruled-out claims for injection into a prompt.

        Confirmed items are deliberately omitted here (they are surfaced as
        findings); this digest exists so the model never re-checks something it
        already opened or ruled out.
        """
        open_items = [h for h in self._by_id.values() if h.status == _STATUS_OPEN]
        ruled_items = self.ruled_out()

        if not open_items and not ruled_items:
            return "No hypotheses recorded yet."

        lines: list[str] = []

        lines.append("OPEN (still to verify):")
        if open_items:
            for h in open_items:
                lines.append(f"  - [{h.vuln_class}] {h.contract}.{h.function}: {h.claim}")
        else:
            lines.append("  (none)")

        lines.append("RULED OUT (do NOT re-check):")
        if ruled_items:
            for h in ruled_items:
                reason = ""
                for ev in reversed(h.evidence):
                    if ev.startswith("ruled_out:"):
                        reason = ev[len("ruled_out:") :].strip()
                        break
                suffix = f" ({reason})" if reason else ""
                lines.append(f"  - [{h.vuln_class}] {h.contract}.{h.function}: {h.claim}{suffix}")
        else:
            lines.append("  (none)")

        return "\n".join(lines)
