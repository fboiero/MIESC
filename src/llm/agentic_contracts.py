"""
Provider-agnostic contracts for agentic security reasoning.

These types keep MIESC's agentic workflow tied to capabilities instead of
specific model names or API vendors. Concrete local or remote backends can
implement ``ReasoningProvider`` without changing the product contract.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Protocol

MAX_AGENT_SOURCE_CHARS = 120_000
MAX_AGENT_PROMPT_CHARS = 140_000
MAX_AGENT_ITEMS = 100
MAX_AGENT_TEXT_CHARS = 4_000
MAX_AGENT_LABEL_CHARS = 120
MAX_AGENT_METADATA_KEYS = 50


class AgentCapability(Enum):
    """Stable capability names for replaceable agent implementations."""

    INVARIANT_EXTRACTION = "invariant_extraction"
    PROPERTY_SYNTHESIS = "property_synthesis"
    COUNTEREXAMPLE_VALIDATION = "counterexample_validation"
    FINDING_JUDGMENT = "finding_judgment"
    REMEDIATION_CRITIQUE = "remediation_critique"


class InvariantCategory(Enum):
    """Common invariant families for smart-contract business logic."""

    ACCOUNTING = "accounting"
    CAP_BOUNDARY = "cap_boundary"
    DEADLINE = "deadline"
    STATE_SYNC = "state_sync"
    REPLAY_DOMAIN = "replay_domain"
    WITHDRAWABILITY = "withdrawability"
    ACCESS_CONTROL = "access_control"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DPGAgentConfig:
    """Policy knobs that keep agentic reasoning local-first and replaceable."""

    local_first: bool = True
    allow_remote: bool = False
    require_replaceable_provider: bool = True
    max_source_chars: int = MAX_AGENT_SOURCE_CHARS

    def to_dict(self) -> Dict[str, Any]:
        max_source_chars = _bounded_positive_int(self.max_source_chars, MAX_AGENT_SOURCE_CHARS)
        return {
            "local_first": self.local_first,
            "allow_remote": self.allow_remote,
            "require_replaceable_provider": self.require_replaceable_provider,
            "max_source_chars": max_source_chars,
        }


@dataclass(frozen=True)
class ReasoningTask:
    """A provider-neutral unit of agentic reasoning work."""

    capability: AgentCapability
    objective: str
    prompt: str
    inputs: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    policy: DPGAgentConfig = field(default_factory=DPGAgentConfig)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability.value,
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS) or "",
            "prompt": _safe_text(self.prompt, MAX_AGENT_PROMPT_CHARS, allow_multiline=True) or "",
            "inputs": _json_safe_mapping(self.inputs),
            "output_schema": _json_safe_mapping(self.output_schema),
            "policy": self.policy.to_dict(),
        }


@dataclass(frozen=True)
class ReasoningResult:
    """Structured output returned by any replaceable reasoning provider."""

    data: Dict[str, Any]
    provider_kind: str = "unspecified"
    implementation_label: str = "unspecified"
    local: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "data": _json_safe_mapping(self.data),
            "provider_kind": _safe_label(self.provider_kind) or "unspecified",
            "implementation_label": _safe_label(self.implementation_label) or "unspecified",
            "local": bool(self.local),
            "metadata": _json_safe_mapping(self.metadata),
        }


class ReasoningProvider(Protocol):
    """Interface implemented by local, cloud, mock, or future providers."""

    def complete_json(self, task: ReasoningTask) -> ReasoningResult:
        """Return JSON-compatible data for ``task``."""


@dataclass(frozen=True)
class InvariantCandidate:
    """A candidate invariant extracted from code or findings."""

    id: str
    statement: str
    category: InvariantCategory = InvariantCategory.UNKNOWN
    affected_functions: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)
    assertion_hint: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.statement),
            "statement": _safe_text(self.statement, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "category": self.category.value,
            "affected_functions": _safe_text_list(self.affected_functions),
            "state_variables": _safe_text_list(self.state_variables),
            "assertion_hint": _safe_text(self.assertion_hint, MAX_AGENT_TEXT_CHARS) or "",
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class CounterexampleEvidence:
    """Evidence produced by a property or PoC validation agent."""

    invariant_id: str
    status: str
    tool: str
    compiled: bool = False
    counterexample_found: bool = False
    test_name: str = ""
    artifact_path: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_id": _safe_label(self.invariant_id) or "unknown",
            "status": _safe_label(self.status) or "unknown",
            "tool": _safe_label(self.tool) or "unknown",
            "compiled": self.compiled,
            "counterexample_found": self.counterexample_found,
            "test_name": _safe_text(self.test_name, MAX_AGENT_TEXT_CHARS) or "",
            "artifact_path": _safe_text(self.artifact_path, MAX_AGENT_TEXT_CHARS) or "",
            "details": _json_safe_mapping(self.details),
        }


class InvariantExtractionAgent:
    """Extracts invariant candidates through a replaceable reasoning provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        prompt = _invariant_extraction_prompt(safe_source, safe_findings)
        return ReasoningTask(
            capability=AgentCapability.INVARIANT_EXTRACTION,
            objective=(
                "Extract replaceable-provider invariant candidates for smart-contract "
                "business-logic validation."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
            },
            output_schema={
                "invariants": [
                    {
                        "id": "short_stable_identifier",
                        "statement": "property that should always hold",
                        "category": "accounting|cap_boundary|deadline|state_sync|replay_domain|withdrawability|access_control|unknown",
                        "affected_functions": ["functionName"],
                        "state_variables": ["stateVariable"],
                        "assertion_hint": "Foundry/Halmos assertion hint",
                        "confidence": 0.0,
                        "evidence": ["code signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def extract(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
    ) -> List[InvariantCandidate]:
        task = self.build_task(source_code, contract_path=contract_path, findings=findings)
        result = self.provider.complete_json(task)
        return parse_invariant_candidates(result.data)


def parse_invariant_candidates(data: Any) -> List[InvariantCandidate]:
    """Parse provider output into bounded invariant candidates."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get("invariants", [])
    if not isinstance(raw_items, list):
        return []

    candidates: List[InvariantCandidate] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue

        statement = _safe_text(raw.get("statement"), MAX_AGENT_TEXT_CHARS)
        if not statement:
            continue

        raw_id = _safe_label(raw.get("id")) or _derive_invariant_id(statement)
        category = _category_from_text(raw.get("category"))
        candidates.append(
            InvariantCandidate(
                id=raw_id,
                statement=statement,
                category=category,
                affected_functions=_safe_text_list(raw.get("affected_functions")),
                state_variables=_safe_text_list(raw.get("state_variables")),
                assertion_hint=_safe_text(raw.get("assertion_hint"), MAX_AGENT_TEXT_CHARS) or "",
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )

    return candidates


def _invariant_extraction_prompt(source_code: str, findings: List[Any]) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Extract candidate invariants for defensive smart-contract validation.
Focus on business-logic properties that can later become Foundry, Halmos,
Echidna, Medusa, SMTChecker, or Certora checks.

Do not depend on a specific model, vendor, or external API. Return only JSON.

Return this shape:
{{
  "invariants": [
    {{
      "id": "short_stable_identifier",
      "statement": "property that should always hold",
      "category": "accounting|cap_boundary|deadline|state_sync|replay_domain|withdrawability|access_control|unknown",
      "affected_functions": ["functionName"],
      "state_variables": ["stateVariable"],
      "assertion_hint": "assertion or property-test hint",
      "confidence": 0.0,
      "evidence": ["specific code signal"]
    }}
  ]
}}

Prioritize high-impact properties:
- accounting conservation and share/asset math
- caps, limits, deadlines, and exact boundary behavior
- state synchronization across arrays, mappings, and structs
- replay-domain separation and nonce/deadline use
- withdrawability and stuck-funds conditions
- privileged-state transitions

Existing findings, if any:
{findings_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _bounded_source(source_code: Any, max_chars: int) -> str:
    text = _safe_text(source_code, max(max_chars, 0), allow_multiline=True)
    return text or ""


def _safe_label(value: Any) -> Optional[str]:
    text = _safe_text(value, MAX_AGENT_LABEL_CHARS, allow_multiline=True)
    if not text:
        return None
    normalized = re.sub(r"[^A-Za-z0-9_.:-]+", "_", text).strip("_")
    return normalized[:MAX_AGENT_LABEL_CHARS] or None


def _safe_text(value: Any, limit: int, *, allow_multiline: bool = False) -> Optional[str]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return None
    text = value if allow_multiline else value.strip()
    if not text:
        return None
    for char in text:
        ordinal = ord(char)
        if ordinal == 127 or ordinal in {0x2028, 0x2029}:
            return None
        if ordinal < 32 and (not allow_multiline or char not in "\n\r\t"):
            return None
    return text[: max(limit, 0)]


def _safe_text_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    result: List[str] = []
    for item in value[:MAX_AGENT_ITEMS]:
        text = _safe_text(item, MAX_AGENT_TEXT_CHARS)
        if text:
            result.append(text)
    return result


def _json_safe_mapping(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    safe: Dict[str, Any] = {}
    for key, item in value.items():
        if len(safe) >= MAX_AGENT_METADATA_KEYS:
            break
        safe_key = _safe_label(key)
        if safe_key:
            safe[safe_key] = _json_safe_value(item)
    return safe


def _json_safe_list(value: Any, *, max_items: int = MAX_AGENT_ITEMS) -> List[Any]:
    if not isinstance(value, list):
        return []
    return [_json_safe_value(item) for item in value[:max_items]]


def _json_safe_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _safe_text(value, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
    if isinstance(value, Mapping):
        return _json_safe_mapping(value)
    if isinstance(value, list):
        return _json_safe_list(value)
    return f"<{type(value).__name__}>"


def _bounded_confidence(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return max(0.0, min(float(value), 1.0))
    if isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError:
            return 0.0
        return max(0.0, min(parsed, 1.0))
    return 0.0


def _bounded_positive_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return max(0, min(value, default))
    return default


def _category_from_text(value: Any) -> InvariantCategory:
    text = _safe_text(value, MAX_AGENT_LABEL_CHARS)
    if not text:
        return InvariantCategory.UNKNOWN
    normalized = text.lower().replace("-", "_").replace(" ", "_")
    try:
        return InvariantCategory(normalized)
    except ValueError:
        return InvariantCategory.UNKNOWN


def _derive_invariant_id(statement: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", statement.lower())[:6]
    return "_".join(words)[:MAX_AGENT_LABEL_CHARS] or "invariant"


__all__ = [
    "AgentCapability",
    "CounterexampleEvidence",
    "DPGAgentConfig",
    "InvariantCandidate",
    "InvariantCategory",
    "InvariantExtractionAgent",
    "ReasoningProvider",
    "ReasoningResult",
    "ReasoningTask",
    "parse_invariant_candidates",
]
