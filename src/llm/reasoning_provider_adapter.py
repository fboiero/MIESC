"""
Replaceable reasoning providers for agentic security workflows.

This module bridges the provider-neutral contracts in ``agentic_contracts`` to
concrete local or configured LLM execution without making a model/vendor part of
the agent contract.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .agentic_contracts import (
    AgentCapability,
    ReasoningProvider,
    ReasoningResult,
    ReasoningTask,
)
from .llm_orchestrator import LLMOrchestrator, LLMResponse

_LOCAL_PROVIDER_PREFIXES = ("local", "ollama")
_MAX_JSON_TEXT_CHARS = 200_000


@dataclass(frozen=True)
class ReasoningProviderRoute:
    """Opaque routing hint for a configured reasoning backend."""

    backend_key: Optional[str] = None
    provider_kind: str = "auto"
    implementation_label: str = "configured-reasoning-provider"
    local: bool = False


class LocalHeuristicReasoningProvider(ReasoningProvider):
    """Deterministic local fallback for lightweight agentic reasoning."""

    def complete_json(self, task: ReasoningTask) -> ReasoningResult:
        if task.capability != AgentCapability.INVARIANT_EXTRACTION:
            return ReasoningResult(
                data={},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"unsupported_capability": task.capability.value},
            )

        source = _source_from_task(task)
        invariants = _extract_heuristic_invariants(source)
        return ReasoningResult(
            data={"invariants": invariants},
            provider_kind="local",
            implementation_label="local-heuristic",
            local=True,
            metadata={"strategy": "regex_signals", "count": len(invariants)},
        )


class LLMOrchestratorReasoningProvider(ReasoningProvider):
    """ReasoningProvider implementation backed by an LLMOrchestrator."""

    def __init__(
        self,
        orchestrator: Optional[LLMOrchestrator] = None,
        *,
        route: Optional[ReasoningProviderRoute] = None,
    ):
        self.orchestrator = orchestrator or LLMOrchestrator()
        self.route = route or ReasoningProviderRoute()

    def complete_json(self, task: ReasoningTask) -> ReasoningResult:
        if task.policy.require_replaceable_provider is False:
            raise ValueError("Agentic reasoning requires a replaceable provider contract")
        if task.policy.allow_remote is False and not _route_is_local(self.route):
            raise ValueError("Remote reasoning is disabled by the task DPG policy")

        response = _run_async(self._complete(task))
        data = _parse_json_response(response.content)
        return ReasoningResult(
            data=data,
            provider_kind=self.route.provider_kind,
            implementation_label=self.route.implementation_label,
            local=self.route.local,
            metadata={
                "backend_key": self.route.backend_key or "",
                "response_provider_kind": response.provider,
                "response_model_label": response.model,
                "tokens_used": response.tokens_used,
                "latency_ms": response.latency_ms,
                "cached": response.cached,
            },
        )

    async def _complete(self, task: ReasoningTask) -> LLMResponse:
        context = {
            "capability": task.capability.value,
            "objective": task.objective,
            "inputs": task.inputs,
            "output_schema": task.output_schema,
            "policy": task.policy.to_dict(),
        }
        return await self.orchestrator.query(
            task.prompt,
            context=context,
            provider=self.route.backend_key,
        )


def auto_reasoning_provider(
    orchestrator: Optional[LLMOrchestrator] = None,
    *,
    prefer_local_fallback: bool = True,
) -> ReasoningProvider:
    """Return a replaceable provider suitable for DPG local-first workflows."""

    if orchestrator is None and prefer_local_fallback:
        return LocalHeuristicReasoningProvider()

    orch = orchestrator or LLMOrchestrator()
    route = _route_from_orchestrator(orch)
    return LLMOrchestratorReasoningProvider(orch, route=route)


def _route_from_orchestrator(orchestrator: LLMOrchestrator) -> ReasoningProviderRoute:
    backend_key = orchestrator.primary_provider
    provider_kind = "auto"
    implementation_label = "configured-reasoning-provider"
    local = False

    if isinstance(backend_key, str) and ":" in backend_key:
        provider_kind, implementation_label = backend_key.split(":", 1)
        local = _provider_kind_is_local(provider_kind)
    elif isinstance(backend_key, str) and _provider_kind_is_local(backend_key):
        provider_kind = backend_key
        implementation_label = backend_key
        local = True

    return ReasoningProviderRoute(
        backend_key=backend_key,
        provider_kind=provider_kind,
        implementation_label=implementation_label,
        local=local,
    )


def _run_async(awaitable: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()
    raise RuntimeError("Synchronous reasoning provider cannot run inside an active event loop")


def _parse_json_response(content: str) -> Dict[str, Any]:
    if not isinstance(content, str):
        return {}
    text = content.strip()[:_MAX_JSON_TEXT_CHARS]
    if not text:
        return {}

    for fenced in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL):
        parsed = _parse_json_text(fenced.group(1).strip())
        normalized = _normalize_json(parsed)
        if normalized is not None:
            return normalized

    parsed = _parse_json_text(text)
    normalized = _normalize_json(parsed)
    if normalized is not None:
        return normalized

    parsed = _parse_embedded_json(text)
    normalized = _normalize_json(parsed)
    return normalized or {}


def _parse_json_text(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _normalize_json(parsed: Any) -> Optional[Dict[str, Any]]:
    if isinstance(parsed, Mapping):
        return dict(parsed)
    if isinstance(parsed, list):
        return {"items": parsed}
    return None


def _parse_embedded_json(text: str) -> Any:
    starts = [idx for idx, char in enumerate(text) if char in "{["]
    for start in starts:
        end_char = "}" if text[start] == "{" else "]"
        end = text.rfind(end_char)
        if end <= start:
            continue
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            continue
    return {}


def _route_is_local(route: ReasoningProviderRoute) -> bool:
    if _provider_kind_is_local(route.provider_kind):
        return True
    if isinstance(route.backend_key, str):
        backend_kind = route.backend_key.split(":", 1)[0]
        return _provider_kind_is_local(backend_kind)
    if route.provider_kind.strip().lower() not in {"", "auto", "unspecified"}:
        return False
    return bool(route.local)


def _provider_kind_is_local(provider_kind: str) -> bool:
    provider = provider_kind.lower().strip()
    return provider in _LOCAL_PROVIDER_PREFIXES


def _source_from_task(task: ReasoningTask) -> str:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    match = re.search(r"<contract_source>\s*(.*?)\s*</contract_source>", prompt, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"```solidity\s*(.*?)\s*```", prompt, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)
    return prompt


def _extract_heuristic_invariants(source_code: str) -> list[Dict[str, Any]]:
    source_lower = source_code.lower()
    invariants: list[Dict[str, Any]] = []

    if "totalsupply" in source_lower and (
        "totalassets" in source_lower or "balanceof" in source_lower
    ):
        invariants.append(
            {
                "id": "asset_accounting_conservation",
                "statement": "aggregate assets should remain consistent with issued supply",
                "category": "accounting",
                "affected_functions": _public_state_functions(source_code),
                "state_variables": _state_variables(source_code, {"totalSupply", "totalAssets"}),
                "assertion_hint": "assertGe(totalAssets(), totalSupply())",
                "confidence": 0.55,
                "evidence": ["totalSupply appears with asset/balance accounting signals"],
            }
        )

    if any(token in source_lower for token in ("cap", "maxsupply", "limit")) and any(
        token in source_lower for token in ("mint", "deposit")
    ):
        invariants.append(
            {
                "id": "cap_boundary",
                "statement": "minted or deposited amount should not exceed configured caps",
                "category": "cap_boundary",
                "affected_functions": _public_state_functions(source_code),
                "state_variables": _state_variables(source_code, {"cap", "maxSupply", "limit"}),
                "assertion_hint": "assertLe(totalSupply(), cap())",
                "confidence": 0.5,
                "evidence": ["cap-like identifier appears with mint/deposit flow"],
            }
        )

    if any(token in source_lower for token in ("owner", "admin", "role")) and any(
        token in source_lower for token in ("onlyowner", "onlyrole", "require(")
    ):
        invariants.append(
            {
                "id": "privileged_access_control",
                "statement": "privileged state changes should require authorized callers",
                "category": "access_control",
                "affected_functions": _public_state_functions(source_code),
                "state_variables": _state_variables(source_code, {"owner", "admin"}),
                "assertion_hint": "vm.prank(attacker); vm.expectRevert(); privilegedCall();",
                "confidence": 0.45,
                "evidence": ["privileged identifiers and authorization checks are present"],
            }
        )

    return invariants[:10]


def _public_state_functions(source_code: str) -> list[str]:
    names = []
    for match in re.finditer(
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:external|public)(?![^{;]*\bview\b)(?![^{;]*\bpure\b)",
        source_code,
    ):
        name = match.group(1)
        if name not in names:
            names.append(name)
    return names[:12]


def _state_variables(source_code: str, candidates: set[str]) -> list[str]:
    found = []
    for candidate in candidates:
        if re.search(rf"\b{re.escape(candidate)}\b", source_code):
            found.append(candidate)
    return sorted(found)[:12]


__all__ = [
    "LLMOrchestratorReasoningProvider",
    "LocalHeuristicReasoningProvider",
    "ReasoningProviderRoute",
    "auto_reasoning_provider",
]
