"""
Provider-neutral contracts for acceptance-pattern intelligence.

An *acceptance-pattern* provider answers a single question about a finding:
"historically, how often do human judges in competitive audits (Sherlock,
Code4rena, ...) ACCEPT a finding of this class as valid?" The answer is a
probability in ``[0, 1]`` used purely as an ORDERING / prioritization signal.

Why this module exists (ports & adapters):

The MIESC public core must not be coupled to any external, paid, or proprietary
service. A third party may offer "bug bounty intelligence" as a paid API, but
coupling the core to it would break DPGA platform-independence and privacy
guarantees. So instead we define a *port* (this file) and ship two adapters of
different nature (``acceptance_providers``): a real, offline, always-available
local default, and an opt-in external adapter. Two implementations of different
nature prove the abstraction is genuine.

This mirrors the replaceable-provider shape already used for agentic reasoning
(:mod:`miesc.llm.agentic_contracts`): a ``typing.Protocol`` interface plus a
local-first, remote-off-by-default policy dataclass
(:class:`AcceptancePolicy`, analogous to ``DPGAgentConfig``).

RECALL-SAFETY (locked design decision): an acceptance probability may only
influence ORDERING. It MUST NOT feed any confidence blend or drop/filter path.
A low-acceptance finding drops in rank but stays fully visible — recall stays
1.0. See :mod:`miesc.ml.triage_ranker` for the reorder-only integration.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type


@dataclass(frozen=True)
class AcceptancePolicy:
    """Policy knobs that keep acceptance intelligence local-first and replaceable.

    Mirrors ``miesc.llm.agentic_contracts.DPGAgentConfig``: the core defaults to
    a local provider and never reaches out to a remote service unless the
    operator explicitly opts in.
    """

    local_first: bool = True
    allow_remote: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local_first": bool(self.local_first),
            "allow_remote": bool(self.allow_remote),
        }


@dataclass(frozen=True)
class AcceptanceSignal:
    """A provider-neutral acceptance-probability observation for a vuln class."""

    vuln_class: str
    acceptance_prob: float
    provider: str = "unspecified"
    swc_id: str = ""
    sample_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_class": str(self.vuln_class),
            "acceptance_prob": _clamp_probability(self.acceptance_prob),
            "provider": str(self.provider) or "unspecified",
            "swc_id": str(self.swc_id),
            "sample_note": str(self.sample_note),
        }


@runtime_checkable
class AcceptancePatternProvider(Protocol):
    """Interface implemented by local, external, mock, or future providers.

    Implementations MUST be graceful: an unavailable provider returns ``False``
    from :meth:`is_available` and ``None`` from :meth:`acceptance_probability`
    rather than raising, so callers can no-op and leave ordering unchanged.
    """

    name: str

    def is_available(self) -> bool:
        """Return True when this provider can answer queries (opt-in aware)."""

    def list_vulnerability_patterns(self) -> Dict[str, float]:
        """Return a cheap map of vuln class -> acceptance probability in [0, 1]."""

    def acceptance_probability(
        self,
        finding: Dict[str, Any],
        protocol_type: Optional[str] = None,
    ) -> Optional[float]:
        """Return the acceptance probability for ``finding`` in ``[0, 1]``.

        Returns ``None`` when the class is unknown — the caller must then leave
        the finding's rank unchanged (never guess, never drop).
        """


def finding_to_vuln_class(finding: Any) -> Optional[str]:
    """Map a finding (or raw type string) to a canonical vuln-class key.

    Delegates to :func:`miesc.core.finding_taxonomy.normalize_finding_type` so
    providers share MIESC's single source of truth for the taxonomy instead of
    reinventing it. Returns the canonical string value, or ``None`` if unknown.
    """
    category: Optional[CanonicalCategory] = normalize_finding_type(finding)
    if category is None:
        return None
    return category.value


def _clamp_probability(value: Any) -> float:
    """Clamp ``value`` into ``[0.0, 1.0]``; non-numeric -> ``0.0``."""
    try:
        prob = float(value)
    except (TypeError, ValueError):
        return 0.0
    if prob != prob:  # NaN
        return 0.0
    return max(0.0, min(1.0, prob))


__all__ = [
    "AcceptancePolicy",
    "AcceptanceSignal",
    "AcceptancePatternProvider",
    "finding_to_vuln_class",
]
