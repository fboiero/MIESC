"""Calibrated per-finding confidence scoring.

Blends three signals that already flow through the analysis pipeline into a
single ``[0, 1]`` confidence score, so findings can be ranked and filtered by how
much we trust them:

- **detector reliability prior** — per-tool trust, reused from the correlation
  engine's ``TOOL_WEIGHTS`` so there is a single source of truth for how much
  each tool is believed;
- **cross-tool agreement** — independent tools reporting the *same* finding raise
  confidence;
- **false-positive signal** — the benign-context FP filter's probability that the
  finding is noise pulls confidence down.

The correlation engine already computed a richer version of this, but it is
dormant on the default ``scan``/``audit`` path. This module surfaces the same
idea, reusing the engine's calibrated priors, onto that default path without
running the full (heavier) correlation pass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from miesc.ml.correlation_engine import SmartCorrelationEngine

logger = logging.getLogger(__name__)

# Reuse the correlation engine's calibrated priors so tool trust lives in ONE
# place. If the engine grows/retunes a tool weight, confidence follows.
_TOOL_WEIGHTS = SmartCorrelationEngine.TOOL_WEIGHTS
_CROSS_VALIDATION_REQUIRED = SmartCorrelationEngine.CROSS_VALIDATION_REQUIRED
_SINGLE_TOOL_MAX_CONFIDENCE = SmartCorrelationEngine.SINGLE_TOOL_MAX_CONFIDENCE
_DEFAULT_TOOL_WEIGHT = 0.50  # unknown tool: neutral prior

HIGH_THRESHOLD = 0.70
MEDIUM_THRESHOLD = 0.40


@dataclass
class ConfidenceResult:
    """Outcome of calibrating one finding."""

    score: float  # calibrated confidence in [0, 1]
    level: str  # "high" | "medium" | "low"
    tool_count: int  # number of distinct tools that reported the finding
    contributing_tools: List[str] = field(default_factory=list)


def confidence_level(score: float) -> str:
    """Bucket a raw score into a human-facing level."""
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def _detector_prior(tools: Sequence[str]) -> float:
    """Best per-tool reliability prior among the reporting tools."""
    weights = [_TOOL_WEIGHTS.get((t or "").lower(), _DEFAULT_TOOL_WEIGHT) for t in tools]
    return max(weights) if weights else _DEFAULT_TOOL_WEIGHT


def _requires_cross_validation(vuln_type: str) -> bool:
    v = (vuln_type or "").lower()
    return any(pattern in v for pattern in _CROSS_VALIDATION_REQUIRED)


class ConfidenceCalibrator:
    """Stateless calibrator combining detector prior, agreement and FP signal.

    ``calibrate`` never raises on odd input: missing tools fall back to the neutral
    prior, and ``fp_probability=None`` simply skips the FP penalty.
    """

    AGREEMENT_BONUS = 0.05  # added per additional confirming tool
    MAX_AGREEMENT_TOOLS = 3  # bonus saturates after this many extra tools
    CAP = 0.99  # never claim certainty

    def calibrate(
        self,
        tools: Sequence[str],
        vuln_type: str = "",
        fp_probability: Optional[float] = None,
    ) -> ConfidenceResult:
        # Distinct tools, order preserved; drop empties.
        distinct = list(dict.fromkeys(t for t in tools if t))
        tool_count = max(len(distinct), 1)

        # 1) start from the most reliable reporting tool
        score = _detector_prior(distinct)

        # 2) cross-tool agreement raises confidence
        extra = min(tool_count - 1, self.MAX_AGREEMENT_TOOLS)
        score += self.AGREEMENT_BONUS * extra

        # 3) the false-positive signal pulls it down
        if fp_probability is not None:
            score *= 1.0 - max(0.0, min(1.0, fp_probability))

        # 4) a single tool on a cross-validation-required pattern is capped:
        #    these types have a high single-tool FP rate, so one tool is not enough
        #    to be confident regardless of that tool's prior.
        if tool_count < 2 and _requires_cross_validation(vuln_type):
            score = min(score, _SINGLE_TOOL_MAX_CONFIDENCE)

        score = round(max(0.0, min(self.CAP, score)), 2)
        return ConfidenceResult(
            score=score,
            level=confidence_level(score),
            tool_count=tool_count,
            contributing_tools=distinct,
        )


def annotate_confidence(
    findings: Sequence[Dict[str, Any]],
    contract_source: str = "",
    contract_path: str = "",
) -> None:
    """Attach a calibrated ``confidence`` (0-1) and ``confidence_level`` to each
    finding, in place.

    Blends the detector reliability prior, cross-tool agreement (the ``tools``
    provenance list) and the benign-context FP probability. Best-effort: a failure
    never breaks the caller, it just leaves confidence unset. This is the single
    source of truth shared by the ML orchestrator (default ``analyze`` path) and the
    ``scan`` CLI, so both annotate findings identically.
    """
    try:
        from miesc.ml.fp_filter import FalsePositiveFilter

        calibrator = ConfidenceCalibrator()
        fp_scorer = FalsePositiveFilter(strictness="high", use_rag=False)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("Confidence calibration unavailable: %s", e)
        return

    for finding in findings:
        try:
            tools = finding.get("tools") or ([finding["tool"]] if finding.get("tool") else [])
            vuln_type = finding.get("type") or finding.get("check") or finding.get("swc") or ""
            try:
                fp_probability = fp_scorer.filter_finding(
                    finding, code_context=contract_source, file_path=contract_path
                ).fp_probability
            except Exception:
                fp_probability = None
            result = calibrator.calibrate(tools, vuln_type, fp_probability)
            finding["confidence"] = result.score
            finding["confidence_level"] = result.level
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("Confidence calibration skipped for a finding: %s", e)


def filter_by_min_confidence(
    findings: Sequence[Dict[str, Any]],
    min_confidence: float,
) -> "tuple[List[Dict[str, Any]], int]":
    """Drop findings whose calibrated ``confidence`` is below ``min_confidence``.

    Findings without a ``confidence`` key default to ``1.0`` so that unannotated
    findings are never silently dropped. A non-positive threshold is a no-op.
    Returns ``(kept, dropped_count)``.
    """
    if not min_confidence or min_confidence <= 0.0:
        return list(findings), 0
    kept: List[Dict[str, Any]] = []
    dropped = 0
    for f in findings:
        try:
            score = float(f.get("confidence", 1.0))
        except (TypeError, ValueError):
            score = 1.0
        if score >= min_confidence:
            kept.append(f)
        else:
            dropped += 1
    return kept, dropped
