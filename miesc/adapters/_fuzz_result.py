"""
Fuzzing campaign result classification — shared adapter helper.
=================================================================

Coverage-guided fuzzers (medusa, echidna, dogefuzz) only tell us something
when the campaign actually *exercises* the contract: achieves coverage,
executes test transactions, or evaluates at least one property/assertion.

A campaign that ends with zero coverage, zero transactions and zero findings
did **not** fuzz anything — the cause may be a missing invariant/property
harness, a CLI/compilation failure, or nothing deployable to drive. Reporting
that as a clean ``success`` is a false negative: the absence of findings is
*inconclusive*, not evidence of safety.

This helper gives every fuzzing adapter one honest verdict. The adapter owns
the tool-specific parsing and decides whether the campaign was ``exercised``;
the helper maps that into the status string the pipeline consumes downstream
(``success`` is counted as a clean pass; anything else surfaces as a warning
and drops out of the successful-tools set).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from typing import Any, Dict, List, Optional, Tuple

#: Pipeline status for a campaign that genuinely exercised the contract.
FUZZ_SUCCESS = "success"
#: Pipeline status for a campaign that never exercised the contract. It is not
#: an execution ``error`` (the process may have exited cleanly) and not a clean
#: ``success`` — it is simply uninformative.
FUZZ_INCONCLUSIVE = "inconclusive"

#: Max chars of tool diagnostic folded into the warning message.
_DIAGNOSTIC_CHARS = 400


def _tail(text: Optional[str], limit: int = _DIAGNOSTIC_CHARS) -> str:
    """Return the last ``limit`` chars of ``text`` (stripped), or ""."""
    if not text:
        return ""
    cleaned = text.strip()
    if len(cleaned) <= limit:
        return cleaned
    return "…" + cleaned[-limit:]


def classify_fuzz_campaign(
    *,
    tool: str,
    findings: List[Any],
    exercised: bool,
    diagnostic: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """Classify a fuzzing campaign honestly.

    Args:
        tool: Adapter/tool name, used in the warning message.
        findings: Normalized findings the campaign produced.
        exercised: ``True`` iff the adapter observed a positive signal that the
            campaign actually drove the contract (coverage > 0, transactions
            executed, or ≥1 property/assertion evaluated). The adapter computes
            this from its own tool's output — the helper never guesses it.
        diagnostic: Optional raw tool output (stderr/stdout tail) explaining why
            nothing ran; folded, truncated, into the warning message.

    Returns:
        ``(status, warning)``. ``status`` is :data:`FUZZ_SUCCESS` when the
        campaign found something or was exercised, else :data:`FUZZ_INCONCLUSIVE`.
        ``warning`` is ``None`` on success, otherwise a human-readable message
        the caller should expose (e.g. as ``error``/``warning`` on the result).
    """
    if findings or exercised:
        return FUZZ_SUCCESS, None

    message = (
        f"{tool} campaign did not exercise the contract "
        f"(no coverage, no transactions, no findings) — absence of findings is "
        f"inconclusive, not a clean pass; no invariant/property harness was run."
    )
    tail = _tail(diagnostic)
    if tail:
        message = f"{message} Diagnostic: {tail}"
    return FUZZ_INCONCLUSIVE, message


def apply_fuzz_verdict(
    result: Dict[str, Any],
    *,
    tool: str,
    exercised: bool,
    diagnostic: Optional[str] = None,
) -> Dict[str, Any]:
    """Stamp a fuzzing ``result`` dict with an honest status in place.

    Convenience wrapper used by adapters: reads ``result["findings"]``, calls
    :func:`classify_fuzz_campaign`, and — when the verdict is inconclusive —
    sets ``status``/``error``/``warning`` plus ``metadata.campaign_exercised``
    and ``metadata.campaign_diagnostic`` so the reason is never silent. A
    successful verdict leaves any existing ``status`` untouched but still
    records ``metadata.campaign_exercised`` for transparency.

    Returns the same ``result`` object (mutated) for chaining.
    """
    findings = result.get("findings") or []
    status, warning = classify_fuzz_campaign(
        tool=tool, findings=findings, exercised=exercised, diagnostic=diagnostic
    )

    metadata = result.setdefault("metadata", {})
    if not isinstance(metadata, dict):  # defensive: never crash on odd shapes
        metadata = {}
        result["metadata"] = metadata
    metadata["campaign_exercised"] = bool(exercised)

    if status == FUZZ_INCONCLUSIVE:
        result["status"] = FUZZ_INCONCLUSIVE
        result["warning"] = warning
        # Downstream renderers key off `error` for the non-success branch.
        result.setdefault("error", warning)
        metadata["campaign_diagnostic"] = _tail(diagnostic)
    return result


__all__ = [
    "FUZZ_SUCCESS",
    "FUZZ_INCONCLUSIVE",
    "classify_fuzz_campaign",
    "apply_fuzz_verdict",
]
