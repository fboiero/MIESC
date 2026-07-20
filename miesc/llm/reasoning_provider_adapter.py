"""
Replaceable reasoning providers for agentic security workflows.

This module bridges the provider-neutral contracts in ``agentic_contracts`` to
concrete local or configured LLM execution without making a model/vendor part of
the agent contract.
"""

from __future__ import annotations

import asyncio
import json
import math
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
_MAX_ROUTE_TEXT_CHARS = 200
_MAX_METADATA_TEXT_CHARS = 500
_MAX_RESPONSE_METADATA_KEYS = 20


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
        source = _source_from_task(task)
        if task.capability == AgentCapability.INVARIANT_EXTRACTION:
            invariants = _extract_heuristic_invariants(source)
            return ReasoningResult(
                data={"invariants": invariants},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_signals", "count": len(invariants)},
            )

        if task.capability == AgentCapability.SEQUENCE_ORACLE_SYNTHESIS:
            plans = _extract_heuristic_sequence_oracle_plans(task, source)
            return ReasoningResult(
                data={"sequence_oracle_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_sequence_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.SEMANTIC_GRAPH_GATING:
            gates = _extract_heuristic_semantic_graph_gates(task, source)
            return ReasoningResult(
                data={"semantic_graph_gates": gates},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_semantic_graph_signals", "count": len(gates)},
            )

        if task.capability == AgentCapability.SNAPSHOT_FUZZING_GUIDANCE:
            plans = _extract_heuristic_snapshot_fuzzing_plans(task, source)
            return ReasoningResult(
                data={"snapshot_fuzzing_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_snapshot_fuzzing_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.ECONOMIC_ATTACK_SIMULATION:
            plans = _extract_heuristic_economic_attack_plans(task, source)
            return ReasoningResult(
                data={"economic_attack_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_economic_attack_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.METAMORPHIC_DIFF_TESTING:
            plans = _extract_heuristic_differential_test_plans(task, source)
            return ReasoningResult(
                data={"differential_test_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_metamorphic_diff_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.UPGRADE_EVOLUTION_ANALYSIS:
            plans = _extract_heuristic_upgrade_evolution_plans(task, source)
            return ReasoningResult(
                data={"upgrade_evolution_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_upgrade_evolution_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING:
            plans = _extract_heuristic_cross_chain_message_hardening_plans(task, source)
            return ReasoningResult(
                data={"cross_chain_message_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_cross_chain_message_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.DELEGATECALL_STORAGE_ALIASING:
            plans = _extract_heuristic_delegatecall_storage_aliasing_plans(task, source)
            return ReasoningResult(
                data={"delegatecall_storage_aliasing_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_delegatecall_storage_aliasing_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.ORACLE_FEED_HARDENING:
            plans = _extract_heuristic_oracle_feed_hardening_plans(task, source)
            return ReasoningResult(
                data={"oracle_feed_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={"strategy": "regex_oracle_feed_hardening_signals", "count": len(plans)},
            )

        if task.capability == AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING:
            plans = _extract_heuristic_adversarial_ordering_plans(task, source)
            return ReasoningResult(
                data={"adversarial_transaction_ordering_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_adversarial_transaction_ordering_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.ERC4626_VAULT_INFLATION_HARDENING:
            plans = _extract_heuristic_erc4626_vault_inflation_plans(task, source)
            return ReasoningResult(
                data={"erc4626_vault_inflation_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_erc4626_vault_inflation_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.CREATE2_DEPLOYMENT_HARDENING:
            plans = _extract_heuristic_create2_deployment_hardening_plans(task, source)
            return ReasoningResult(
                data={"create2_deployment_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_create2_deployment_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.ABI_PACKED_HASH_COLLISION_HARDENING:
            plans = _extract_heuristic_abi_packed_hash_collision_plans(task, source)
            return ReasoningResult(
                data={"abi_packed_hash_collision_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_abi_packed_hash_collision_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.ERC20_TOKEN_COMPATIBILITY_HARDENING:
            plans = _extract_heuristic_erc20_token_compatibility_plans(task, source)
            return ReasoningResult(
                data={"erc20_token_compatibility_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_erc20_token_compatibility_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.ACCOUNT_ABSTRACTION_USEROP_HARDENING:
            plans = _extract_heuristic_account_abstraction_userop_plans(task, source)
            return ReasoningResult(
                data={"account_abstraction_userop_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_account_abstraction_userop_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.EXTERNAL_CALL_RETURNDATA_HARDENING:
            plans = _extract_heuristic_external_call_returndata_plans(task, source)
            return ReasoningResult(
                data={"external_call_returndata_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_external_call_returndata_signals",
                    "count": len(plans),
                },
            )

        if task.capability == AgentCapability.FINANCIAL_MATH_PRECISION_HARDENING:
            plans = _extract_heuristic_financial_math_precision_plans(task, source)
            return ReasoningResult(
                data={"financial_math_precision_hardening_plans": plans},
                provider_kind="local",
                implementation_label="local-heuristic",
                local=True,
                metadata={
                    "strategy": "regex_financial_math_precision_signals",
                    "count": len(plans),
                },
            )

        return ReasoningResult(
            data={},
            provider_kind="local",
            implementation_label="local-heuristic",
            local=True,
            metadata={"unsupported_capability": task.capability.value},
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
        effective_local = _route_is_local(self.route)
        if task.policy.allow_remote is False and not effective_local:
            raise ValueError("Remote reasoning is disabled by the task DPG policy")

        response = _run_async(self._complete(task))
        data = _parse_json_response(_safe_getattr(response, "content", ""))
        metadata = {
            "backend_key": _safe_route_text(self.route.backend_key, ""),
            "response_provider_kind": _safe_metadata_text(_safe_getattr(response, "provider", "")),
            "response_model_label": _safe_metadata_text(_safe_getattr(response, "model", "")),
            "tokens_used": _safe_nonnegative_int(_safe_getattr(response, "tokens_used", 0)),
            "latency_ms": _safe_nonnegative_float(_safe_getattr(response, "latency_ms", 0.0)),
            "cached": _safe_bool(_safe_getattr(response, "cached", False)),
        }
        response_metadata = _safe_metadata_mapping(_safe_getattr(response, "metadata", {}))
        if response_metadata:
            metadata["response_metadata"] = response_metadata
        return ReasoningResult(
            data=data,
            provider_kind=_safe_route_text(self.route.provider_kind, "auto"),
            implementation_label=_safe_route_text(
                self.route.implementation_label,
                "configured-reasoning-provider",
            ),
            local=effective_local,
            metadata=metadata,
        )

    async def _complete(self, task: ReasoningTask) -> LLMResponse:
        context = {
            "capability": task.capability.value,
            "objective": task.objective,
            "inputs": task.inputs,
            "output_schema": task.output_schema,
            "policy": task.policy.to_dict(),
        }
        backend_key = _safe_route_text(self.route.backend_key, "")
        return await self.orchestrator.query(
            task.prompt,
            context=context,
            provider=backend_key or None,
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
    backend_key = _safe_route_text(_safe_getattr(orchestrator, "primary_provider", None), "")
    provider_kind = "auto"
    implementation_label = "configured-reasoning-provider"
    local = False

    if backend_key and ":" in backend_key:
        provider_kind, implementation_label = backend_key.split(":", 1)
        local = _provider_kind_is_local(provider_kind)
    elif backend_key and _provider_kind_is_local(backend_key):
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
    decoder = json.JSONDecoder()
    starts = [idx for idx, char in enumerate(text) if char in "{["]
    for start in starts:
        try:
            parsed, _end = decoder.raw_decode(text[start:])
            return parsed
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return {}


def _route_is_local(route: ReasoningProviderRoute) -> bool:
    if _provider_kind_is_local(route.provider_kind):
        return True
    backend_key = _safe_route_text(route.backend_key, "")
    if backend_key:
        backend_kind = backend_key.split(":", 1)[0]
        return _provider_kind_is_local(backend_kind)
    provider_kind = _safe_route_text(route.provider_kind, "auto").lower()
    if provider_kind not in {"", "auto", "unspecified"}:
        return False
    return bool(route.local)


def _provider_kind_is_local(provider_kind: Any) -> bool:
    provider = _safe_route_text(provider_kind, "").lower()
    return provider in _LOCAL_PROVIDER_PREFIXES


def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        return default


def _safe_route_text(value: Any, default: str) -> str:
    text = _safe_text(value, limit=_MAX_ROUTE_TEXT_CHARS)
    return text if text is not None else default


def _safe_metadata_text(value: Any) -> str:
    return _safe_text(value, limit=_MAX_METADATA_TEXT_CHARS) or ""


def _safe_text(value: Any, *, limit: int) -> Optional[str]:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return None
    if not isinstance(value, str):
        return None
    try:
        text = value.strip()
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        return None
    if not text or any(ord(ch) < 32 or ord(ch) == 127 or ch in "\u2028\u2029" for ch in text):
        return None
    return text[:limit]


def _safe_nonnegative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(value, 0)


def _safe_nonnegative_float(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    if not math.isfinite(float(value)) or value < 0:
        return 0.0
    return float(value)


def _safe_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def _safe_metadata_mapping(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: Dict[str, Any] = {}
    try:
        items = value.items()
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        return {}
    for raw_key, raw_value in items:
        key = _safe_metadata_text(raw_key)
        if not key:
            continue
        result[key] = _safe_metadata_value(raw_value)
        if len(result) >= _MAX_RESPONSE_METADATA_KEYS:
            break
    return result


def _safe_metadata_value(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    text = _safe_metadata_text(value)
    if text:
        return text
    return f"<{type(value).__name__}>"


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


def _extract_heuristic_sequence_oracle_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    source_lower = source_code.lower()
    functions = _public_state_functions(source_code)
    max_steps = _max_sequence_steps(task)
    tools = ["foundry", "echidna", "halmos"]
    plans: list[Dict[str, Any]] = []

    if _has_any(source_lower, ("totalassets", "totalsupply", "converttoshares", "previewdeposit")):
        donate = _pick_function(functions, ("donate", "skim", "sync", "transfer"))
        deposit = _pick_function(functions, ("deposit", "mint"))
        if donate and deposit:
            plans.append(
                {
                    "id": "share_price_inflation_sequence",
                    "objective": "Validate that asset donation or share-price changes cannot distort depositor share accounting.",
                    "vulnerability_types": ["share_price_inflation"],
                    "sequence": _limit_sequence(
                        [
                            _sequence_step(
                                donate,
                                "attacker",
                                ["asset_amount"],
                                expected="Increase vault assets without proportional share minting.",
                            ),
                            _sequence_step(
                                deposit,
                                "victim",
                                ["deposit_amount"],
                                expected="Mint shares at the post-donation exchange rate.",
                            ),
                        ],
                        max_steps,
                    ),
                    "oracle": "victim shares and totalAssets/totalSupply exchange rate remain proportional after the sequence",
                    "recommended_tools": tools,
                    "confidence": 0.58,
                    "evidence": [
                        "asset/share accounting signals and donation/deposit entry points are present"
                    ],
                }
            )

    if _has_any(source_lower, ("oracle", "price", "getreserves", "twap")) and _has_any(
        source_lower, ("swap", "borrow", "liquidate")
    ):
        manipulate = _pick_function(functions, ("swap", "updatePrice", "sync", "poke"))
        consume = _pick_function(functions, ("borrow", "liquidate", "withdraw"))
        if manipulate and consume:
            plans.append(
                {
                    "id": "oracle_manipulation_sequence",
                    "objective": "Validate that spot price or reserve manipulation cannot unlock unsafe borrowing, swaps, or liquidation.",
                    "vulnerability_types": ["oracle_manipulation"],
                    "sequence": _limit_sequence(
                        [
                            _sequence_step(
                                manipulate,
                                "attacker",
                                ["manipulation_amount"],
                                expected="Move spot price or reserves before the sensitive action.",
                            ),
                            _sequence_step(
                                consume,
                                "attacker",
                                ["target_amount"],
                                expected="Consume the manipulated price in protocol accounting.",
                            ),
                        ],
                        max_steps,
                    ),
                    "oracle": "borrow, liquidation, or swap output remains bounded by non-manipulated collateral/price assumptions",
                    "recommended_tools": tools,
                    "confidence": 0.56,
                    "evidence": [
                        "oracle/price signals appear with swap, borrow, or liquidation flow"
                    ],
                }
            )

    if _has_any(source_lower, ("borrow", "collateral", "health", "liquidate")):
        borrow = _pick_function(functions, ("borrow", "openPosition", "depositCollateral"))
        liquidate = _pick_function(functions, ("liquidate", "seize"))
        if borrow and liquidate:
            plans.append(
                {
                    "id": "liquidation_edge_sequence",
                    "objective": "Validate liquidation boundary behavior across borrow, collateral drift, and liquidation execution.",
                    "vulnerability_types": ["liquidation_edge_case"],
                    "sequence": _limit_sequence(
                        [
                            _sequence_step(
                                borrow,
                                "victim",
                                ["debt_amount"],
                                expected="Create a position near the collateral boundary.",
                            ),
                            _sequence_step(
                                liquidate,
                                "liquidator",
                                ["victim", "repay_amount"],
                                precondition="Position is at or near liquidation threshold.",
                                expected="Apply liquidation without over-seizing collateral.",
                            ),
                        ],
                        max_steps,
                    ),
                    "oracle": "liquidation must not over-seize collateral or leave debt/accounting inconsistent",
                    "recommended_tools": tools,
                    "confidence": 0.5,
                    "evidence": ["borrow/collateral/health/liquidation signals are present"],
                }
            )

    return [plan for plan in plans if plan["sequence"]][:10]


def _extract_heuristic_semantic_graph_gates(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    source_lower = source_code.lower()
    functions = _public_state_functions(source_code)
    max_nodes = _max_semantic_graph_nodes(task)
    tools = ["slither", "mythril", "halmos", "foundry"]
    gates: list[Dict[str, Any]] = []

    if _has_any(source_lower, ("owner", "admin", "role")) and functions:
        function = _pick_function(
            functions,
            ("withdraw", "setOwner", "setAdmin", "upgradeTo", "pause", "mint", "transferOwnership"),
        )
        state_var = _pick_state_variable(source_code, ("owner", "admin", "role"))
        fn_node = _semantic_node(_semantic_function_node_id(function), "function", function)
        state_node = _semantic_node(
            _semantic_state_node_id(state_var or "authority"),
            "state_var",
            state_var or "authority",
        )
        gates.append(
            {
                "id": "access_control_graph_gate",
                "objective": "Focus privileged state-changing paths for access-control review.",
                "target_vulnerability_types": ["access_control"],
                "focal_nodes": [fn_node["id"]],
                "nodes": _limit_nodes([fn_node, state_node], max_nodes),
                "edges": [
                    _semantic_edge(
                        fn_node["id"],
                        state_node["id"],
                        "guards",
                        0.55,
                        "privileged identifier appears with public or external state-changing functions",
                    )
                ],
                "graph_queries": [
                    "find privileged state-changing functions without owner or role guards"
                ],
                "recommended_tools": tools,
                "confidence": 0.55,
                "rationale": "owner, admin, or role signals make privileged paths high-value graph gates.",
                "metadata": {"strategy": "regex_semantic_graph_signals"},
            }
        )

    if _has_any(source_lower, (".call", ".delegatecall", ".staticcall", ".transfer", ".send")):
        function = _pick_function(functions, ("withdraw", "execute", "claim", "transfer", "send"))
        if function:
            fn_node = _semantic_node(_semantic_function_node_id(function), "function", function)
            call_node = _semantic_node(
                "external_call", "external_call", "external value/control transfer"
            )
            target_types = ["reentrancy", "unchecked_call"]
            if ".delegatecall" in source_lower:
                target_types.append("delegatecall")
            gates.append(
                {
                    "id": "external_call_graph_gate",
                    "objective": "Focus external value or control transfer paths for call-safety review.",
                    "target_vulnerability_types": target_types,
                    "focal_nodes": [fn_node["id"]],
                    "nodes": _limit_nodes([fn_node, call_node], max_nodes),
                    "edges": [
                        _semantic_edge(
                            fn_node["id"],
                            call_node["id"],
                            "calls",
                            0.57,
                            "external call primitive appears in a public or external function context",
                        )
                    ],
                    "graph_queries": [
                        "find state writes or balance changes reachable before and after external calls"
                    ],
                    "recommended_tools": tools,
                    "confidence": 0.57,
                    "rationale": "external call edges are a compact focal graph for reentrancy and unchecked-call review.",
                    "metadata": {"strategy": "regex_semantic_graph_signals"},
                }
            )

    if _has_any(source_lower, ("oracle", "price", "getreserves", "twap")) and _has_any(
        source_lower,
        ("swap", "borrow", "liquidate"),
    ):
        function = _pick_function(functions, ("swap", "borrow", "liquidate", "withdraw"))
        if function:
            fn_node = _semantic_node(_semantic_function_node_id(function), "function", function)
            price_node = _semantic_node("oracle_price", "oracle", "oracle price")
            gates.append(
                {
                    "id": "oracle_dataflow_graph_gate",
                    "objective": "Focus price-dependent paths for oracle manipulation review.",
                    "target_vulnerability_types": ["oracle_manipulation"],
                    "focal_nodes": [fn_node["id"]],
                    "nodes": _limit_nodes([fn_node, price_node], max_nodes),
                    "edges": [
                        _semantic_edge(
                            fn_node["id"],
                            price_node["id"],
                            "reads",
                            0.56,
                            "oracle or price signals appear with swap, borrow, or liquidation flows",
                        )
                    ],
                    "graph_queries": [
                        "find protocol actions whose accounting reads spot price or reserve data"
                    ],
                    "recommended_tools": tools,
                    "confidence": 0.56,
                    "rationale": "price-read edges expose compact attacker paths for oracle/dataflow testing.",
                    "metadata": {"strategy": "regex_semantic_graph_signals"},
                }
            )

    return gates[:10]


def _extract_heuristic_snapshot_fuzzing_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    source_lower = source_code.lower()
    functions = _public_state_functions(source_code)
    max_snapshots = _max_snapshot_count(task)
    tools = ["foundry", "echidna", "medusa", "ityfuzz"]
    plans: list[Dict[str, Any]] = []

    if _has_any(source_lower, ("totalassets", "totalsupply", "converttoshares", "previewdeposit")):
        donate = _pick_function(functions, ("donate", "skim", "sync", "transfer"))
        deposit = _pick_function(functions, ("deposit", "mint"))
        if donate and deposit:
            plans.append(
                {
                    "id": "share_price_snapshot_campaign",
                    "objective": "Reuse initialized liquidity state to fuzz share-price drift.",
                    "target_vulnerability_types": ["share_price_inflation"],
                    "seeds": _limit_snapshots(
                        [
                            _snapshot_seed(
                                "seed_after_initial_liquidity",
                                [
                                    _sequence_step(
                                        deposit,
                                        "victim",
                                        ["initial_assets"],
                                        expected="Vault has nonzero assets and shares.",
                                    )
                                ],
                                "vault initialized with nonzero totalAssets and totalSupply",
                                0.75,
                                "asset/share accounting signals and deposit entry point are present",
                            )
                        ],
                        max_snapshots,
                    ),
                    "waypoints": [
                        _fuzzing_waypoint(
                            "waypoint_share_price_delta",
                            "dataflow",
                            "totalAssets / totalSupply",
                            "maximize accounting drift before depositor action",
                            "increase assets without proportional share minting",
                            "totalAssets, totalSupply, or share conversion signals are present",
                        )
                    ],
                    "priority_transactions": [
                        _sequence_step(
                            donate,
                            "attacker",
                            ["asset_amount"],
                            precondition="vault has initial liquidity",
                            expected="Assets increase without proportional share minting.",
                        )
                    ],
                    "oracle": "share price, shares minted, and asset accounting remain proportional across snapshot replay",
                    "recommended_tools": tools,
                    "budget_hint": "use bounded snapshot replay around seeded states before a full fuzzing campaign",
                    "confidence": 0.58,
                    "metadata": {"strategy": "regex_snapshot_fuzzing_signals"},
                }
            )

    if _has_any(source_lower, ("oracle", "price", "getreserves", "twap")) and _has_any(
        source_lower,
        ("swap", "borrow", "liquidate"),
    ):
        manipulate = _pick_function(functions, ("swap", "updatePrice", "sync", "poke"))
        consume = _pick_function(functions, ("borrow", "liquidate", "withdraw"))
        if manipulate and consume:
            plans.append(
                {
                    "id": "oracle_snapshot_campaign",
                    "objective": "Reuse manipulated price states to fuzz price-dependent protocol actions.",
                    "target_vulnerability_types": ["oracle_manipulation"],
                    "seeds": _limit_snapshots(
                        [
                            _snapshot_seed(
                                "seed_after_price_move",
                                [
                                    _sequence_step(
                                        manipulate,
                                        "attacker",
                                        ["manipulation_amount"],
                                        expected="Move spot price or reserves before the sensitive action.",
                                    )
                                ],
                                "price or reserve state moved away from baseline",
                                0.7,
                                "oracle or price signals appear with swap, borrow, or liquidation flow",
                            )
                        ],
                        max_snapshots,
                    ),
                    "waypoints": [
                        _fuzzing_waypoint(
                            "waypoint_oracle_price_delta",
                            "oracle",
                            "price or reserves consumed by sensitive action",
                            "maximize price movement before borrow or liquidation",
                            "branch distance from manipulated price to unsafe accounting path",
                            "oracle/price signals appear with a consumer transaction",
                        )
                    ],
                    "priority_transactions": [
                        _sequence_step(
                            consume,
                            "attacker",
                            ["target_amount"],
                            precondition="price state has moved from baseline",
                            expected="Consume the manipulated price in protocol accounting.",
                        )
                    ],
                    "oracle": "borrow, liquidation, or swap output remains bounded by non-manipulated collateral and price assumptions",
                    "recommended_tools": tools,
                    "budget_hint": "replay price-move snapshots before widening transaction depth",
                    "confidence": 0.56,
                    "metadata": {"strategy": "regex_snapshot_fuzzing_signals"},
                }
            )

    if _has_any(source_lower, ("borrow", "collateral", "health", "liquidate")):
        borrow = _pick_function(functions, ("borrow", "openPosition", "depositCollateral"))
        liquidate = _pick_function(functions, ("liquidate", "seize"))
        if borrow and liquidate:
            plans.append(
                {
                    "id": "liquidation_frontier_snapshot_campaign",
                    "objective": "Reuse near-threshold positions to fuzz liquidation boundary behavior.",
                    "target_vulnerability_types": ["liquidation_edge_case"],
                    "seeds": _limit_snapshots(
                        [
                            _snapshot_seed(
                                "seed_near_liquidation_threshold",
                                [
                                    _sequence_step(
                                        borrow,
                                        "victim",
                                        ["debt_amount"],
                                        expected="Create a position near the collateral boundary.",
                                    )
                                ],
                                "borrower position is near the health or collateral threshold",
                                0.66,
                                "borrow/collateral/health/liquidation signals are present",
                            )
                        ],
                        max_snapshots,
                    ),
                    "waypoints": [
                        _fuzzing_waypoint(
                            "waypoint_health_factor_boundary",
                            "branch",
                            "health factor or collateral threshold",
                            "minimize distance to liquidation eligibility boundary",
                            "health factor approaches the threshold from both sides",
                            "liquidation and health/collateral signals are present",
                        )
                    ],
                    "priority_transactions": [
                        _sequence_step(
                            liquidate,
                            "liquidator",
                            ["victim", "repay_amount"],
                            precondition="position is at or near liquidation threshold",
                            expected="Apply liquidation without over-seizing collateral.",
                        )
                    ],
                    "oracle": "liquidation must not over-seize collateral or leave debt/accounting inconsistent",
                    "recommended_tools": tools,
                    "budget_hint": "focus snapshot fuzzing around near-threshold borrower states",
                    "confidence": 0.52,
                    "metadata": {"strategy": "regex_snapshot_fuzzing_signals"},
                }
            )

    return [
        plan
        for plan in plans
        if plan["seeds"] or plan["waypoints"] or plan["priority_transactions"]
    ][:10]


def _extract_heuristic_economic_attack_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    source_lower = source_code.lower()
    tools = ["foundry", "anvil", "fork-simulation"]
    functions = _public_state_functions(source_code)
    sequence_ids = _input_plan_ids(task, "sequence_plans")
    snapshot_ids = _input_plan_ids(task, "snapshot_plans")
    graph_gate_ids = _input_plan_ids(task, "graph_gates")
    plans: list[Dict[str, Any]] = []

    if _has_any(source_lower, ("oracle", "price", "getreserves", "twap")) and _has_any(
        source_lower,
        ("swap", "borrow", "liquidate"),
    ):
        manipulate = _pick_function(functions, ("swap", "updatePrice", "sync", "poke"))
        consume = _pick_function(functions, ("borrow", "liquidate", "withdraw"))
        if manipulate and consume:
            plans.append(
                {
                    "id": "oracle_profit_plan",
                    "objective": "Validate whether price manipulation is profitable after costs.",
                    "target_vulnerability_types": ["oracle_manipulation"],
                    "base_sequence_plan_ids": sequence_ids,
                    "base_snapshot_plan_ids": snapshot_ids,
                    "base_graph_gate_ids": graph_gate_ids,
                    "capital_requirements": [
                        _capital_requirement(
                            "USDC",
                            "flash loan sized to move pool price",
                            "flash_loan",
                            "fund swap manipulation leg",
                        )
                    ],
                    "asset_flows": [
                        _asset_flow(
                            "USDC",
                            "flash_pool",
                            "attacker",
                            "principal",
                            "borrow_flash",
                            "temporary capital for price movement",
                        ),
                        _asset_flow(
                            "TOKEN",
                            "protocol",
                            "attacker",
                            "borrowed_or_liquidated_value",
                            consume,
                            "extract value after manipulated price is consumed",
                        ),
                    ],
                    "profit_formula": "borrowed_value - principal - premium - swap_fees - gas",
                    "cost_model": "flash-loan premium, pool fees, gas, slippage",
                    "liquidity_assumptions": ["pool depth allows bounded slippage"],
                    "oracle_price_assumptions": ["spot reserve price is consumed without TWAP"],
                    "break_even_threshold": "manipulated value exceeds principal, premium, fees, slippage, and gas",
                    "expected_profit_range": "positive only if price impact exceeds all explicit costs",
                    "risk_factors": [
                        "TWAP, liquidity caps, or conservative collateral factors may invalidate the plan"
                    ],
                    "recommended_tools": tools,
                    "confidence": 0.58,
                    "evidence": [
                        "oracle/price signals appear with swap and borrow/liquidation flow"
                    ],
                    "metadata": {"strategy": "regex_economic_attack_signals"},
                }
            )

    if _has_any(source_lower, ("totalassets", "totalsupply", "converttoshares", "previewdeposit")):
        donate = _pick_function(functions, ("donate", "skim", "sync", "transfer"))
        deposit = _pick_function(functions, ("deposit", "mint"))
        if donate and deposit:
            plans.append(
                {
                    "id": "share_inflation_profit_plan",
                    "objective": "Validate whether share-price inflation can repay capital and leave profit.",
                    "target_vulnerability_types": ["share_price_inflation"],
                    "base_sequence_plan_ids": sequence_ids,
                    "base_snapshot_plan_ids": snapshot_ids,
                    "base_graph_gate_ids": graph_gate_ids,
                    "capital_requirements": [
                        _capital_requirement(
                            "ASSET",
                            "attacker assets for donation and victim-sized deposit comparison",
                            "attacker_capital",
                            "fund donation leg and compare extracted share value",
                        )
                    ],
                    "asset_flows": [
                        _asset_flow(
                            "ASSET",
                            "attacker",
                            "vault",
                            "donation_amount",
                            donate,
                            "increase assets without proportional share minting",
                        ),
                        _asset_flow(
                            "SHARE",
                            "vault",
                            "attacker",
                            "inflated_share_claim",
                            deposit,
                            "measure whether resulting share value exceeds donated assets and fees",
                        ),
                    ],
                    "profit_formula": "redeemable_assets - donation_amount - deposit_amount - gas",
                    "cost_model": "donated assets, deposit capital, gas, redemption slippage",
                    "liquidity_assumptions": [
                        "vault has enough redeemable liquidity after inflation"
                    ],
                    "oracle_price_assumptions": [],
                    "break_even_threshold": "redeemable assets exceed donation, deposit capital at risk, and gas",
                    "expected_profit_range": "positive only if exchange-rate drift dominates donated assets",
                    "risk_factors": [
                        "minimum liquidity, virtual shares, or donation guards may invalidate the plan"
                    ],
                    "recommended_tools": tools,
                    "confidence": 0.55,
                    "evidence": [
                        "asset/share accounting signals and donation/deposit entry points are present"
                    ],
                    "metadata": {"strategy": "regex_economic_attack_signals"},
                }
            )

    if _has_any(source_lower, ("borrow", "collateral", "health", "liquidate")):
        borrow = _pick_function(functions, ("borrow", "openPosition", "depositCollateral"))
        liquidate = _pick_function(functions, ("liquidate", "seize"))
        if borrow and liquidate:
            plans.append(
                {
                    "id": "liquidation_profit_plan",
                    "objective": "Validate whether liquidation bonus exceeds repay, capital, and execution costs.",
                    "target_vulnerability_types": ["liquidation_edge_case"],
                    "base_sequence_plan_ids": sequence_ids,
                    "base_snapshot_plan_ids": snapshot_ids,
                    "base_graph_gate_ids": graph_gate_ids,
                    "capital_requirements": [
                        _capital_requirement(
                            "DEBT",
                            "repay amount near liquidation boundary",
                            "attacker_capital_or_flash_loan",
                            "fund liquidation repay leg",
                        )
                    ],
                    "asset_flows": [
                        _asset_flow(
                            "DEBT",
                            "liquidator",
                            "protocol",
                            "repay_amount",
                            liquidate,
                            "repay borrower debt to trigger collateral seizure",
                        ),
                        _asset_flow(
                            "COLLATERAL",
                            "protocol",
                            "liquidator",
                            "seized_collateral",
                            "seize_collateral",
                            "measure liquidation bonus after repay and costs",
                        ),
                    ],
                    "profit_formula": "seized_collateral_value - repay_amount - premium - gas",
                    "cost_model": "repay capital, optional flash-loan premium, gas, liquidation slippage",
                    "liquidity_assumptions": [
                        "collateral market can absorb seized collateral without excessive slippage"
                    ],
                    "oracle_price_assumptions": [
                        "health factor price is current enough for liquidation boundary"
                    ],
                    "break_even_threshold": "liquidation bonus exceeds repay funding cost and gas",
                    "expected_profit_range": "positive only near eligible positions with sufficient liquidation bonus",
                    "risk_factors": [
                        "close factor, stale oracle checks, or collateral slippage may make path unprofitable"
                    ],
                    "recommended_tools": tools,
                    "confidence": 0.52,
                    "evidence": ["borrow/collateral/health/liquidation signals are present"],
                    "metadata": {"strategy": "regex_economic_attack_signals"},
                }
            )

    return [
        plan
        for plan in plans
        if plan["profit_formula"]
        and (plan["capital_requirements"] or plan["asset_flows"] or plan["liquidity_assumptions"])
    ][:10]


def _extract_heuristic_differential_test_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    del task
    source_lower = source_code.lower()
    functions = _public_state_functions(source_code)
    tools = ["foundry", "echidna", "halmos"]
    plans: list[Dict[str, Any]] = []

    if _has_any(source_lower, ("totalassets", "totalsupply", "converttoshares", "previewdeposit")):
        deposit = _pick_function(functions, ("deposit", "mint"))
        withdraw = _pick_function(functions, ("withdraw", "redeem"))
        if deposit:
            plans.append(
                {
                    "id": "split_merge_deposit_plan",
                    "objective": "Compare split and merged deposits for share or asset drift.",
                    "target_vulnerability_types": ["share_price_inflation", "accounting_drift"],
                    "relations": [
                        _metamorphic_relation(
                            "split_merge_deposit",
                            "split_merge",
                            [_sequence_step(deposit, "user", ["100 ether"])],
                            [
                                _sequence_step(deposit, "user", ["50 ether"]),
                                _sequence_step(deposit, "user", ["50 ether"]),
                            ],
                            "final shares, totalSupply, and totalAssets match within rounding tolerance",
                            "at most one wei of rounding drift",
                            "deposit uses asset/share conversion signals",
                        )
                    ],
                    "state_observables": ["balanceOf(user)", "totalSupply()", "totalAssets()"],
                    "oracle": "split and merged deposit executions diverge beyond rounding tolerance",
                    "recommended_tools": tools,
                    "confidence": 0.6,
                    "evidence": ["asset/share accounting and deposit entry point are present"],
                    "metadata": {"strategy": "regex_metamorphic_diff_signals"},
                }
            )
        if deposit and withdraw:
            plans.append(
                {
                    "id": "deposit_withdraw_round_trip_plan",
                    "objective": "Compare deposit/withdraw round trips against initial accounting state.",
                    "target_vulnerability_types": ["accounting_drift", "rounding_leakage"],
                    "relations": [
                        _metamorphic_relation(
                            "deposit_withdraw_round_trip",
                            "round_trip",
                            [
                                _sequence_step(
                                    deposit,
                                    "user",
                                    ["0 assets"],
                                    expected="Baseline accounting remains unchanged.",
                                )
                            ],
                            [
                                _sequence_step(deposit, "user", ["assets"]),
                                _sequence_step(withdraw, "user", ["assets"]),
                            ],
                            "user balance, totalSupply, and totalAssets return to baseline within tolerance",
                            "at most one wei of rounding drift",
                            "deposit and withdraw/redeem entry points are present",
                        )
                    ],
                    "state_observables": ["balanceOf(user)", "totalSupply()", "totalAssets()"],
                    "oracle": "round-trip execution leaves persistent asset or share drift",
                    "recommended_tools": tools,
                    "confidence": 0.56,
                    "evidence": ["paired deposit and withdraw/redeem functions are present"],
                    "metadata": {"strategy": "regex_metamorphic_diff_signals"},
                }
            )

    if _has_any(source_lower, ("borrow", "repay", "debt", "collateral", "health")):
        borrow = _pick_function(functions, ("borrow", "openPosition"))
        repay = _pick_function(functions, ("repay", "closePosition"))
        if borrow and repay:
            plans.append(
                {
                    "id": "borrow_repay_round_trip_plan",
                    "objective": "Compare borrow/repay round trips against debt and collateral baselines.",
                    "target_vulnerability_types": [
                        "debt_accounting_drift",
                        "liquidation_edge_case",
                    ],
                    "relations": [
                        _metamorphic_relation(
                            "borrow_repay_round_trip",
                            "round_trip",
                            [
                                _sequence_step(
                                    borrow,
                                    "user",
                                    ["0 debt"],
                                    expected="Baseline debt remains unchanged.",
                                )
                            ],
                            [
                                _sequence_step(borrow, "user", ["debt_amount"]),
                                _sequence_step(repay, "user", ["debt_amount"]),
                            ],
                            "debt, collateral, and health observables return to baseline",
                            "zero debt dust unless protocol explicitly rounds debt",
                            "borrow and repay/debt signals are present",
                        )
                    ],
                    "state_observables": ["debtOf(user)", "collateralOf(user)", "health(user)"],
                    "oracle": "borrow/repay round trip leaves unexpected debt or collateral drift",
                    "recommended_tools": tools,
                    "confidence": 0.54,
                    "evidence": ["borrow/repay and debt/collateral signals are present"],
                    "metadata": {"strategy": "regex_metamorphic_diff_signals"},
                }
            )

    if _has_any(source_lower, ("transfer", "balanceof")):
        transfer = _pick_function(functions, ("transfer", "transferFrom"))
        if transfer:
            plans.append(
                {
                    "id": "independent_transfer_commutativity_plan",
                    "objective": "Compare independent transfer orderings for balance conservation.",
                    "target_vulnerability_types": ["accounting_drift"],
                    "relations": [
                        _metamorphic_relation(
                            "independent_transfer_commutativity",
                            "commutative",
                            [
                                _sequence_step(transfer, "alice", ["bob", "amount_a"]),
                                _sequence_step(transfer, "carol", ["dave", "amount_b"]),
                            ],
                            [
                                _sequence_step(transfer, "carol", ["dave", "amount_b"]),
                                _sequence_step(transfer, "alice", ["bob", "amount_a"]),
                            ],
                            "final balances and aggregate supply match for independent transfers",
                            "exact equality expected for ERC20-like transfers",
                            "transfer and balanceOf signals are present",
                        )
                    ],
                    "state_observables": [
                        "balanceOf(alice)",
                        "balanceOf(bob)",
                        "balanceOf(carol)",
                        "balanceOf(dave)",
                        "totalSupply()",
                    ],
                    "oracle": "independent transfer order changes balances or aggregate supply",
                    "recommended_tools": tools,
                    "confidence": 0.5,
                    "evidence": ["transfer and balanceOf signals are present"],
                    "metadata": {"strategy": "regex_metamorphic_diff_signals"},
                }
            )

    return [plan for plan in plans if plan["oracle"] and plan["relations"]][:10]


def _extract_heuristic_upgrade_evolution_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    tools = ["openzeppelin-upgrades", "slither", "foundry"]
    storage_changes = _heuristic_storage_layout_changes(task)
    risks: list[Dict[str, Any]] = []
    migration_checks: list[str] = []

    if storage_changes:
        risks.append(
            _upgrade_risk(
                "storage_layout_drift",
                "storage_layout",
                "implementation storage layout",
                "high",
                "storage layout changes can corrupt proxy state during upgrade",
                "storage layout before/after inputs differ",
                "dry-run upgrade and assert owner, balances, allowances, and accounting slots are preserved",
            )
        )
        migration_checks.append("dry-run upgrade preserves critical proxy storage slots")

    initializer = _pick_upgrade_component(
        combined,
        ("initializeV2", "reinitialize", "initializer", "initialize"),
    )
    if _has_any(combined_lower, ("initializev2", "reinitialize", "initializer")):
        risks.append(
            _upgrade_risk(
                "initializer_drift",
                "initializer",
                initializer or "initializer",
                "medium",
                "new or changed initializer flow may be replayable or may reset privileged state",
                "initializer or reinitializer signal appears in the upgrade prompt",
                "assert initializer cannot be replayed and preserves owner/admin/accounting state",
            )
        )
        migration_checks.append("replay initializer calls and expect revert after upgrade")

    upgrade_component = _pick_upgrade_component(
        combined,
        ("_authorizeUpgrade", "upgradeToAndCall", "upgradeTo", "changeAdmin"),
    )
    if _has_any(combined_lower, ("upgradeto", "_authorizeupgrade", "changeadmin", "proxyadmin")):
        risks.append(
            _upgrade_risk(
                "upgrade_authorization_review",
                "admin",
                upgrade_component or "upgradeTo",
                "high",
                "upgrade entry points require explicit authorization and migration tests",
                "upgrade/admin signal appears in the upgrade prompt",
                "assert only authorized admin or role can change implementation",
            )
        )
        migration_checks.append("unauthorized caller cannot upgrade implementation")

    proxy_pattern = _infer_proxy_pattern(combined_lower)
    if proxy_pattern != "unknown" or ".delegatecall" in combined_lower:
        migration_checks.append("proxy implementation slot remains valid after upgrade")

    if not storage_changes and not risks and not migration_checks:
        return []

    return [
        {
            "id": "upgrade_evolution_local_plan",
            "objective": "Validate upgrade transition risks before treating implementation versions as safe.",
            "proxy_pattern": proxy_pattern,
            "old_implementation": "old implementation",
            "new_implementation": "new implementation",
            "storage_changes": storage_changes,
            "risks": risks,
            "migration_checks": _dedupe_text(migration_checks),
            "recommended_tools": tools,
            "confidence": 0.58 if storage_changes or risks else 0.45,
            "evidence": _upgrade_evidence(storage_changes, risks, proxy_pattern),
            "metadata": {"strategy": "regex_upgrade_evolution_signals"},
        }
    ]


def _heuristic_storage_layout_changes(task: ReasoningTask) -> list[Dict[str, Any]]:
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    before = _layout_mapping(inputs.get("storage_layout_before"))
    after = _layout_mapping(inputs.get("storage_layout_after"))
    changes: list[Dict[str, Any]] = []
    for slot in sorted(set(before) | set(after), key=_slot_sort_key):
        before_value = before.get(slot, "")
        after_value = after.get(slot, "")
        if before_value == after_value:
            continue
        if before_value and after_value:
            change_type = "type_change"
            risk = "slot meaning changed across implementations"
        elif before_value:
            change_type = "delete"
            risk = "slot disappeared from the new implementation layout"
        else:
            change_type = "insert_before_existing"
            risk = "new slot appears in the upgraded implementation layout"
        changes.append(
            {
                "slot": slot,
                "before": before_value,
                "after": after_value,
                "change_type": change_type,
                "risk": risk,
                "evidence": [f"layout slot {slot} differs before and after upgrade"],
            }
        )
        if len(changes) >= 10:
            break
    return changes


def _layout_mapping(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: Dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = _safe_metadata_text(raw_key)
        if not key:
            continue
        if isinstance(raw_value, Mapping):
            text = " ".join(
                part
                for part in (
                    _safe_metadata_text(raw_value.get("type")),
                    _safe_metadata_text(raw_value.get("label")),
                    _safe_metadata_text(raw_value.get("contract")),
                )
                if part
            )
        else:
            text = _safe_metadata_text(raw_value)
        if text:
            result[key] = text
    return result


def _slot_sort_key(value: str) -> tuple[int, str]:
    try:
        return (int(value, 0), value)
    except ValueError:
        return (10**9, value)


def _upgrade_risk(
    risk_id: str,
    category: str,
    affected_component: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_component": affected_component,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _pick_upgrade_component(source_code: str, preferred: tuple[str, ...]) -> str:
    for candidate in preferred:
        if re.search(rf"\b{re.escape(candidate)}\b", source_code):
            return candidate
    return ""


def _infer_proxy_pattern(source_lower: str) -> str:
    if "proxiableuuid" in source_lower or "_authorizeupgrade" in source_lower:
        return "uups"
    if "proxyadmin" in source_lower or "transparent" in source_lower:
        return "transparent"
    if "beacon" in source_lower:
        return "beacon"
    if ".delegatecall" in source_lower or "implementation" in source_lower:
        return "custom"
    return "unknown"


def _upgrade_evidence(
    storage_changes: list[Dict[str, Any]],
    risks: list[Dict[str, Any]],
    proxy_pattern: str,
) -> list[str]:
    evidence: list[str] = []
    if storage_changes:
        evidence.append("storage layout before/after inputs differ")
    if risks:
        evidence.append("upgrade initializer/admin signals are present")
    if proxy_pattern != "unknown":
        evidence.append(f"{proxy_pattern} proxy pattern signal is present")
    return evidence or ["upgrade transition signal is present"]


def _extract_heuristic_cross_chain_message_hardening_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    bridge_summary = _safe_metadata_mapping(
        task.inputs.get("bridge_summary") if isinstance(task.inputs, Mapping) else {}
    )
    handler = _pick_cross_chain_handler(combined)
    has_message_signal = bool(handler) or _has_any(
        combined_lower,
        (
            "bridge",
            "messenger",
            "inbox",
            "outbox",
            "endpoint",
            "lzreceive",
            "ccipreceive",
            "relaymessage",
            "executemessage",
            "receivemessage",
            "finalizewithdrawal",
            "sourcechain",
            "source_chain",
            "destinationchain",
        ),
    )
    has_summary_signal = bool(bridge_summary)
    if not has_message_signal and not has_summary_signal:
        return []

    flow_id = _cross_chain_flow_id(handler)
    message_flows = [
        {
            "id": flow_id,
            "handler_function": handler or "crossChainMessageHandler",
            "source_domain": _cross_chain_domain_hint(source_code, "source"),
            "destination_domain": _cross_chain_domain_hint(source_code, "destination"),
            "trusted_sender_source": _cross_chain_trusted_sender(
                source_code,
                _cross_chain_domain_hint(source_code, "source"),
            ),
            "message_id_source": _cross_chain_message_id_source(source_code),
            "replay_guard": _cross_chain_replay_guard(source_code),
            "finality_assumption": _cross_chain_finality_assumption(source_code),
            "payload_scope": _cross_chain_payload_scope(source_code),
            "evidence": _cross_chain_flow_evidence(combined_lower, handler, has_summary_signal),
        }
    ]
    risks = _cross_chain_message_risks(combined_lower, flow_id)
    validation_tests = _cross_chain_validation_tests(risks, message_flows[0])

    return [
        {
            "id": "cross_chain_message_local_plan",
            "objective": "Validate cross-chain message envelope checks before treating bridge handlers as safe.",
            "message_flows": message_flows,
            "risks": risks,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "bridgefuzz", "slither"],
            "confidence": 0.62 if risks else 0.48,
            "evidence": _dedupe_text(
                message_flows[0]["evidence"] + [risk["description"] for risk in risks]
            ),
            "metadata": {"strategy": "regex_cross_chain_message_signals"},
        }
    ]


def _pick_cross_chain_handler(source_code: str) -> str:
    preferred = (
        "receiveMessage",
        "executeMessage",
        "ccipReceive",
        "relayMessage",
        "finalizeWithdrawal",
        "lzReceive",
        "onMessageReceived",
        "processMessage",
        "handleMessage",
    )
    for candidate in preferred:
        if re.search(rf"\bfunction\s+{re.escape(candidate)}\b", source_code):
            return candidate
    match = re.search(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*(?:message|payload|proof|nonce|chain)",
        source_code,
        re.IGNORECASE | re.DOTALL,
    )
    return match.group(1) if match else ""


def _cross_chain_flow_id(handler: str) -> str:
    if not handler:
        return "cross_chain_message_flow"
    return re.sub(r"[^a-z0-9]+", "_", handler.lower()).strip("_") or "cross_chain_message_flow"


def _cross_chain_domain_hint(source_code: str, kind: str) -> str:
    patterns = {
        "source": (
            r"\b(sourceChainId|srcChainId|sourceDomain|srcDomain|originChainId)\b",
            r"\b(chainId|domain)\b",
        ),
        "destination": (
            r"\b(destinationChainId|dstChainId|destinationDomain|dstDomain|targetChainId)\b",
            r"\b(block\.chainid)\b",
        ),
    }
    for pattern in patterns[kind]:
        match = re.search(pattern, source_code)
        if match:
            return match.group(1)
    return ""


def _cross_chain_trusted_sender(source_code: str, source_domain: str) -> str:
    if re.search(r"\btrustedRemote\b", source_code):
        return f"trustedRemote[{source_domain}]" if source_domain else "trustedRemote"
    if re.search(r"\btrustedSender\b", source_code):
        return f"trustedSender[{source_domain}]" if source_domain else "trustedSender"
    if re.search(r"\bremoteSender\b", source_code):
        return f"remoteSender[{source_domain}]" if source_domain else "remoteSender"
    for pattern in (
        r"\b(trustedRemote\[[^\]]+\])",
        r"\b(trustedSender\[[^\]]+\])",
        r"\b(remoteSender\[[^\]]+\])",
        r"\b(canonicalMessenger)\b",
        r"\b(messenger)\b",
        r"\b(endpoint)\b",
    ):
        match = re.search(pattern, source_code)
        if match:
            return match.group(1)
    return ""


def _cross_chain_message_id_source(source_code: str) -> str:
    for pattern in (
        r"\b(messageId)\b",
        r"\b(messageHash)\b",
        r"\b(msgHash)\b",
        r"\b(payloadHash)\b",
        r"\b(packetId)\b",
        r"\b(nonce)\b",
        r"\bkeccak256\s*\([^;]+?\)",
    ):
        match = re.search(pattern, source_code, re.DOTALL)
        if match:
            return _safe_metadata_text(match.group(1) if match.lastindex else match.group(0))
    return ""


def _cross_chain_replay_guard(source_code: str) -> str:
    for pattern in (
        r"\b(processedMessages\[[^\]]+\])",
        r"\b(consumedMessages\[[^\]]+\])",
        r"\b(spentMessages\[[^\]]+\])",
        r"\b(executedMessages\[[^\]]+\])",
        r"\b(processed\[[^\]]+\])",
    ):
        match = re.search(pattern, source_code)
        if match:
            return match.group(1)
    return ""


def _cross_chain_finality_assumption(source_code: str) -> str:
    source_lower = source_code.lower()
    if _has_any(source_lower, ("merkleproof", "proof", "stateroot", "withdrawal delay")):
        return "proof or root finality check"
    if _has_any(source_lower, ("finalized", "finality", "challengeperiod")):
        return "finality or challenge period check"
    return ""


def _cross_chain_payload_scope(source_code: str) -> list[str]:
    scope: list[str] = []
    for token in ("token", "amount", "recipient", "target", "value", "calldata", "payload"):
        if re.search(rf"\b{token}\b", source_code, re.IGNORECASE) and token not in scope:
            scope.append(token)
    return scope[:8]


def _cross_chain_flow_evidence(
    source_lower: str,
    handler: str,
    has_summary_signal: bool,
) -> list[str]:
    evidence: list[str] = []
    if handler:
        evidence.append(f"{handler} handler signal is present")
    if has_summary_signal:
        evidence.append("bridge summary input is present")
    if _has_any(source_lower, ("bridge", "messenger", "endpoint", "inbox", "outbox")):
        evidence.append("bridge or messenger naming signal is present")
    if _has_any(source_lower, ("sourcechain", "source_chain", "srcchain", "sourcedomain")):
        evidence.append("source domain signal is present")
    return evidence or ["cross-chain message signal is present"]


def _cross_chain_message_risks(
    source_lower: str,
    flow_id: str,
) -> list[Dict[str, Any]]:
    risks: list[Dict[str, Any]] = []
    if not _has_any(
        source_lower, ("trustedremote", "trustedsender", "remotesender", "xdomainsender")
    ):
        risks.append(
            _cross_chain_risk(
                "trusted_sender_review",
                "trusted_sender",
                flow_id,
                "high",
                "cross-chain handler needs an explicit trusted remote sender check",
                "no trusted remote sender signal is present",
                "spoof source sender or messenger and expect revert",
            )
        )
    if not _has_any(
        source_lower, ("processedmessages", "consumedmessages", "spentmessages", "executedmessages")
    ):
        risks.append(
            _cross_chain_risk(
                "replay_guard_review",
                "replay_guard",
                flow_id,
                "high",
                "cross-chain message execution needs consumed-message tracking",
                "no consumed message mapping signal is present",
                "execute same message id twice and expect second call to revert",
            )
        )
    if not _has_any(
        source_lower, ("messageid", "messagehash", "msghash", "payloadhash", "nonce", "packetid")
    ):
        risks.append(
            _cross_chain_risk(
                "message_id_review",
                "message_id",
                flow_id,
                "medium",
                "message uniqueness should bind chain, nonce, sender, and payload",
                "no stable message id or nonce signal is present",
                "mutate source domain or payload and assert message ids differ",
            )
        )
    if not _has_any(
        source_lower, ("proof", "merkleproof", "finalized", "finality", "challengedelay")
    ):
        risks.append(
            _cross_chain_risk(
                "finality_review",
                "finality",
                flow_id,
                "medium",
                "message execution should document proof or finality assumptions",
                "no proof or finality signal is present",
                "attempt execution before proof/finality condition and expect revert",
            )
        )
    return risks[:8]


def _cross_chain_risk(
    risk_id: str,
    category: str,
    flow_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_flow_id": flow_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _cross_chain_validation_tests(
    risks: list[Dict[str, Any]],
    flow: Dict[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if flow.get("replay_guard"):
        tests.append("replay consumed message id must revert")
    if flow.get("trusted_sender_source"):
        tests.append("spoofed remote sender must revert")
    if flow.get("payload_scope"):
        tests.append("mutated payload scope must not execute privileged effect")
    return _dedupe_text(tests)


def _extract_heuristic_erc20_token_compatibility_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_token_summary = inputs.get("token_summary")
    token_summary = raw_token_summary if isinstance(raw_token_summary, Mapping) else {}
    has_token_signal = _has_any(
        combined_lower,
        (
            "ierc20",
            "safeerc20",
            "safetransfer",
            "safetransferfrom",
            "transferfrom",
            ".transfer(",
            "balanceof",
            "fee_on_transfer",
            "fee-on-transfer",
            "rebasing",
            "blacklist",
            "paused",
        ),
    )
    if not has_token_signal and not token_summary:
        return []

    surface = _erc20_token_flow_surface(source_code, combined_lower, token_summary)
    risks = _erc20_token_compatibility_risks(combined_lower, surface, token_summary)
    if not risks and not token_summary:
        return []
    return [
        {
            "id": "erc20_token_compatibility_local_plan",
            "objective": "Validate ERC20 token integration against actual-received accounting and non-standard token semantics.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": _erc20_token_compatibility_mitigations(combined_lower, risks),
            "validation_tests": _erc20_token_compatibility_validation_tests(risks, surface),
            "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
            "confidence": 0.66 if risks else 0.45,
            "evidence": _dedupe_text(surface["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_erc20_token_compatibility_signals"},
        }
    ]


def _erc20_token_flow_surface(
    source_code: str,
    source_lower: str,
    token_summary: Mapping[str, Any],
) -> Dict[str, Any]:
    token_call = _erc20_token_call(source_code)
    requested = _erc20_requested_amount_source(token_call, source_code)
    before = _erc20_balance_source(source_code, ("balanceBefore", "beforeBalance", "preBalance"))
    after = _erc20_balance_source(source_code, ("balanceAfter", "afterBalance", "postBalance"))
    credited = _erc20_credited_amount_source(source_code, requested)
    traits = _erc20_token_traits(source_lower, token_summary)
    return {
        "id": "erc20_token_flow_surface",
        "entrypoint": _first_declared_function(source_code) or "tokenFlow",
        "token_call": token_call,
        "requested_amount_source": requested,
        "balance_before_source": before,
        "balance_after_source": after,
        "credited_amount_source": credited,
        "token_traits": traits,
        "accounting_fields": _erc20_accounting_fields(source_code),
        "guard": _erc20_guard_summary(source_lower, before, after),
        "evidence": _erc20_surface_evidence(source_lower, token_call, traits, before, after),
    }


def _erc20_token_call(source_code: str) -> str:
    match = re.search(
        r"([A-Za-z_][A-Za-z0-9_]*(?:\([^;]*\))?\.(?:safeTransferFrom|transferFrom|safeTransfer|transfer)\s*\([^;]*\))\s*;",
        source_code,
        re.DOTALL,
    )
    return re.sub(r"\s+", " ", match.group(1).strip()) if match else ""


def _erc20_requested_amount_source(token_call: str, source_code: str) -> str:
    args_text = ""
    match = re.search(r"\((.*)\)", token_call)
    if match:
        args_text = match.group(1)
    args = _split_call_arguments(args_text) if args_text else []
    if args:
        return args[-1].strip()
    match = re.search(r"\b(uint(?:256)?\s+(amount|assets|value|tokens))\b", source_code)
    return match.group(2) if match else ""


def _erc20_balance_source(source_code: str, names: tuple[str, ...]) -> str:
    for name in names:
        if re.search(rf"\b{re.escape(name)}\b", source_code):
            return name
    return ""


def _erc20_credited_amount_source(source_code: str, requested: str) -> str:
    if requested and re.search(rf"\+=\s*{re.escape(requested)}\b", source_code):
        return requested
    for pattern in (
        r"\b(actualReceived)\b",
        r"\b(received)\b",
        r"\b(balanceAfter\s*-\s*balanceBefore)\b",
        r"\b(afterBalance\s*-\s*beforeBalance)\b",
    ):
        match = re.search(pattern, source_code)
        if match:
            return match.group(1)
    return requested


def _erc20_token_traits(source_lower: str, token_summary: Mapping[str, Any]) -> list[str]:
    traits: list[str] = []
    raw_traits = token_summary.get("traits")
    if isinstance(raw_traits, list):
        traits.extend(_safe_metadata_text(item) for item in raw_traits if _safe_metadata_text(item))
    trait_signals = {
        "fee_on_transfer": ("fee_on_transfer", "fee-on-transfer", "tax", "transfer fee"),
        "rebasing": ("rebasing", "rebase"),
        "missing_return": ("missing_return", "nonstandard return", "missing return"),
        "blacklist_or_pause": ("blacklist", "paused", "pausable"),
        "allowance_quirk": ("approve(", "allowance", "permit"),
    }
    for trait, signals in trait_signals.items():
        if _has_any(source_lower, signals):
            traits.append(trait)
    return _dedupe_text(traits)[:8]


def _erc20_accounting_fields(source_code: str) -> list[str]:
    fields: list[str] = []
    for name in ("balances", "shares", "deposits", "totalDeposits", "totalAssets", "accounting"):
        if re.search(rf"\b{re.escape(name)}\b", source_code):
            fields.append(name)
    return _dedupe_text(fields)[:8]


def _erc20_guard_summary(source_lower: str, before: str, after: str) -> str:
    guards: list[str] = []
    if "safeerc20" in source_lower or "safetransfer" in source_lower:
        guards.append("SafeERC20")
    if before and after:
        guards.append("balance-delta accounting")
    if _has_any(source_lower, ("nonreentrant", "whennotpaused", "onlyowner")):
        guards.append("execution guard")
    return ", ".join(guards)


def _erc20_surface_evidence(
    source_lower: str,
    token_call: str,
    traits: list[str],
    before: str,
    after: str,
) -> list[str]:
    evidence: list[str] = []
    if token_call:
        evidence.append("ERC20 transfer call is present")
    if "safeerc20" in source_lower:
        evidence.append("SafeERC20 wrapper signal is present")
    if traits:
        evidence.append("token compatibility trait signal is present")
    if before and after:
        evidence.append("balance-before/balance-after accounting signal is present")
    return evidence or ["ERC20 integration signal is present"]


def _erc20_token_compatibility_risks(
    source_lower: str,
    surface: Mapping[str, Any],
    token_summary: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "erc20_token_flow_surface"
    risks: list[Dict[str, Any]] = []
    traits = set(
        surface.get("token_traits") if isinstance(surface.get("token_traits"), list) else []
    )
    credited = _safe_metadata_text(surface.get("credited_amount_source"))
    requested = _safe_metadata_text(surface.get("requested_amount_source"))
    has_delta = bool(surface.get("balance_before_source") and surface.get("balance_after_source"))
    if requested and credited == requested and not has_delta:
        risks.append(
            _erc20_token_risk(
                "requested_amount_credit",
                "fee_on_transfer_misaccounting",
                surface_id,
                "high",
                "crediting the requested ERC20 amount can over-credit fee-on-transfer or deflationary tokens",
                "requested amount is credited without a balance-delta signal",
                "fee-on-transfer token credits only actual received amount",
            )
        )
    if "rebasing" in traits or "rebasing" in source_lower:
        risks.append(
            _erc20_token_risk(
                "rebasing_balance_drift",
                "rebasing_balance_drift",
                surface_id,
                "medium",
                "rebasing tokens can drift from protocol internal accounting if balances are assumed stable",
                "rebasing token trait signal is present",
                "positive and negative rebase keep internal accounting solvent",
            )
        )
    if "safeerc20" not in source_lower and _has_any(source_lower, ("transferfrom", ".transfer(")):
        risks.append(
            _erc20_token_risk(
                "nonstandard_return_review",
                "nonstandard_return",
                surface_id,
                "medium",
                "raw ERC20 calls may mishandle missing or false return values",
                "raw transfer or transferFrom call is present",
                "missing-return and false-return token variants are handled",
            )
        )
    if "blacklist_or_pause" in traits:
        risks.append(
            _erc20_token_risk(
                "blacklist_pause_review",
                "blacklist_pause_incompatibility",
                surface_id,
                "medium",
                "blacklisted or paused tokens can make accounting flows unexpectedly revert or lock funds",
                "blacklist or pause token trait signal is present",
                "paused or blacklisted token path fails without partial accounting",
            )
        )
    if token_summary and not risks:
        risks.append(
            _erc20_token_risk(
                "token_summary_review",
                "fee_on_transfer_misaccounting",
                surface_id,
                "medium",
                "token summary requests ERC20 compatibility validation for actual received accounting",
                "token compatibility summary input is present",
                "non-standard token variants preserve accounting invariants",
            )
        )
    return risks[:8]


def _erc20_token_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _erc20_token_compatibility_mitigations(
    source_lower: str,
    risks: list[Dict[str, Any]],
) -> list[str]:
    mitigations = ["use SafeERC20"]
    if any(risk["category"] == "fee_on_transfer_misaccounting" for risk in risks):
        mitigations.append("credit balance delta")
    if any(risk["category"] == "rebasing_balance_drift" for risk in risks):
        mitigations.append("support rebasing-safe internal accounting")
    if "safeerc20" not in source_lower:
        mitigations.append("wrap raw ERC20 calls")
    return _dedupe_text(mitigations)


def _erc20_token_compatibility_validation_tests(
    risks: list[Dict[str, Any]],
    surface: Mapping[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if surface.get("requested_amount_source"):
        tests.append("fee-on-transfer deposit credits actual received")
    if surface.get("balance_before_source") and surface.get("balance_after_source"):
        tests.append("balance delta equals credited amount for transfer variants")
    return _dedupe_text(tests)


def _extract_heuristic_account_abstraction_userop_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    source_lower = source_code.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_account_summary = inputs.get("account_summary")
    account_summary = raw_account_summary if isinstance(raw_account_summary, Mapping) else {}
    has_userop_signal = _has_any(
        combined_lower,
        (
            "validateuserop",
            "packeduseroperation",
            "useroperation",
            "userophash",
            "entrypoint",
            "missingaccountfunds",
            "validatepaymasteruserop",
            "postop",
            "paymasteranddata",
            "validationdata",
            "initcode",
        ),
    )
    if not has_userop_signal and not account_summary:
        return []

    surface = _account_abstraction_userop_surface(
        source_code,
        source_lower,
        account_summary,
    )
    risks = _account_abstraction_userop_risks(source_lower, surface, account_summary)
    if not risks and not account_summary:
        return []
    return [
        {
            "id": "account_abstraction_userop_local_plan",
            "objective": "Validate ERC-4337 UserOperation handling across EntryPoint gating, replay scope, prefund accounting, and paymaster charging.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": _account_abstraction_userop_mitigations(source_lower, risks),
            "validation_tests": _account_abstraction_userop_validation_tests(risks, surface),
            "recommended_tools": ["foundry", "erc4337 simulation", "stateful fuzzing"],
            "confidence": 0.67 if risks else 0.45,
            "evidence": _dedupe_text(surface["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_account_abstraction_userop_signals"},
        }
    ]


def _account_abstraction_userop_surface(
    source_code: str,
    source_lower: str,
    account_summary: Mapping[str, Any],
) -> Dict[str, Any]:
    function_name = _account_abstraction_entrypoint_function(source_code, source_lower)
    guard = _account_abstraction_entrypoint_guard(source_lower)
    fields = _account_abstraction_userop_fields(source_code, source_lower)
    return {
        "id": f"{_safe_delegatecall_label(function_name)}_userop_surface",
        "component": _account_abstraction_component(source_lower, account_summary),
        "entrypoint_function": function_name,
        "entrypoint_guard": guard,
        "userop_fields": fields,
        "signature_scheme": _account_abstraction_signature_scheme(source_lower),
        "nonce_source": _account_abstraction_nonce_source(source_code, source_lower),
        "prefund_source": _account_abstraction_prefund_source(source_code, source_lower),
        "paymaster_context": _account_abstraction_paymaster_context(source_lower),
        "post_op_path": _account_abstraction_post_op_path(source_lower),
        "validation_data_source": _account_abstraction_validation_data_source(source_lower),
        "evidence": _account_abstraction_surface_evidence(
            source_lower,
            function_name,
            guard,
            fields,
        ),
    }


def _account_abstraction_entrypoint_function(source_code: str, source_lower: str) -> str:
    for name in ("validateUserOp", "validatePaymasterUserOp", "postOp", "createAccount"):
        if name.lower() in source_lower:
            return name
    return _first_declared_function(source_code) or "handleUserOperation"


def _account_abstraction_entrypoint_guard(source_lower: str) -> str:
    guards: list[str] = []
    if _has_any(
        source_lower,
        (
            "onlyentrypoint",
            "only entrypoint",
            "msg.sender == address(entrypoint)",
            "msg.sender == entrypoint",
            "msg.sender != address(entrypoint)",
            "msg.sender != entrypoint",
            "ientrypoint(msg.sender)",
        ),
    ):
        guards.append("trusted EntryPoint caller gate")
    if _has_any(source_lower, ("onlyowner", "onlyrole", "_checkrole")):
        guards.append("administrative access control")
    return ", ".join(guards)


def _account_abstraction_userop_fields(source_code: str, source_lower: str) -> list[str]:
    fields: list[str] = []
    for field in (
        "sender",
        "nonce",
        "initCode",
        "callData",
        "callGasLimit",
        "verificationGasLimit",
        "preVerificationGas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "paymasterAndData",
        "signature",
    ):
        if (
            re.search(rf"\buserOp\.{re.escape(field)}\b", source_code)
            or field.lower() in source_lower
        ):
            fields.append(field)
    return _dedupe_text(fields)[:12]


def _account_abstraction_component(
    source_lower: str,
    account_summary: Mapping[str, Any],
) -> str:
    raw_components = account_summary.get("components")
    if isinstance(raw_components, list):
        for item in raw_components:
            component = _safe_metadata_text(item)
            if component:
                return component
    if "validatepaymasteruserop" in source_lower or "paymasteranddata" in source_lower:
        return "paymaster"
    if "aggregator" in source_lower:
        return "aggregator"
    if "initcode" in source_lower or "createaccount" in source_lower:
        return "factory"
    if "entrypoint" in source_lower and "handleops" in source_lower:
        return "entrypoint"
    return "account"


def _account_abstraction_signature_scheme(source_lower: str) -> str:
    if "userophash" not in source_lower:
        return ""
    bindings: list[str] = ["userOpHash"]
    if _has_any(source_lower, ("chainid", "block.chainid")):
        bindings.append("chain")
    if "entrypoint" in source_lower:
        bindings.append("EntryPoint")
    if "signature" in source_lower:
        bindings.append("signature")
    return " bound to ".join(bindings)


def _account_abstraction_nonce_source(source_code: str, source_lower: str) -> str:
    match = re.search(
        r"\b(userOp\.nonce|nonce\[[^\]]+\]|nonces\[[^\]]+\]|_useNonce\([^;]*\))", source_code
    )
    if match:
        return re.sub(r"\s+", " ", match.group(1).strip())
    return "nonce field referenced" if "nonce" in source_lower else ""


def _account_abstraction_prefund_source(source_code: str, source_lower: str) -> str:
    if "missingaccountfunds" in source_lower:
        match = re.search(r"\bmissingAccountFunds\b[^;]*", source_code)
        return re.sub(r"\s+", " ", match.group(0).strip()) if match else "missingAccountFunds"
    if "depositto" in source_lower or "paymaster" in source_lower:
        return "EntryPoint deposit or paymaster stake"
    return ""


def _account_abstraction_paymaster_context(source_lower: str) -> str:
    if "validatepaymasteruserop" in source_lower and "context" in source_lower:
        return "context returned by validatePaymasterUserOp"
    if "paymasteranddata" in source_lower:
        return "paymasterAndData sponsor context"
    return ""


def _account_abstraction_post_op_path(source_lower: str) -> str:
    if "postop" in source_lower:
        return "postOp charges or settles sponsored operation"
    return ""


def _account_abstraction_validation_data_source(source_lower: str) -> str:
    parts: list[str] = []
    if "validationdata" in source_lower:
        parts.append("validationData")
    if _has_any(source_lower, ("validuntil", "validafter")):
        parts.append("validUntil/validAfter")
    if "aggregator" in source_lower:
        parts.append("aggregator")
    return ", ".join(parts)


def _account_abstraction_surface_evidence(
    source_lower: str,
    function_name: str,
    guard: str,
    fields: list[str],
) -> list[str]:
    evidence: list[str] = []
    if function_name:
        evidence.append(f"{function_name} signal is present")
    if "userop" in source_lower:
        evidence.append("UserOperation signal is present")
    if guard:
        evidence.append("EntryPoint guard signal is present")
    if fields:
        evidence.append("UserOperation field access signal is present")
    if "paymaster" in source_lower:
        evidence.append("paymaster signal is present")
    return evidence or ["account abstraction signal is present"]


def _account_abstraction_userop_risks(
    source_lower: str,
    surface: Mapping[str, Any],
    account_summary: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "validate_userop_surface"
    risks: list[Dict[str, Any]] = []
    guard = _safe_metadata_text(surface.get("entrypoint_guard"))
    fields = set(
        surface.get("userop_fields") if isinstance(surface.get("userop_fields"), list) else []
    )
    signature_scheme = _safe_metadata_text(surface.get("signature_scheme"))
    nonce_source = _safe_metadata_text(surface.get("nonce_source"))
    prefund_source = _safe_metadata_text(surface.get("prefund_source"))
    if (
        _has_any(source_lower, ("validateuserop", "validatepaymasteruserop", "postop"))
        and not guard
    ):
        risks.append(
            _account_abstraction_userop_risk(
                "missing_entrypoint_guard",
                "entrypoint_guard",
                surface_id,
                "high",
                "UserOperation validation can be called outside the trusted EntryPoint",
                "validation entrypoint has no EntryPoint caller gate signal",
                "direct validation call from non-EntryPoint reverts",
            )
        )
    if "userophash" in source_lower and (
        "chain" not in signature_scheme or "EntryPoint" not in signature_scheme
    ):
        risks.append(
            _account_abstraction_userop_risk(
                "weak_userop_signature_scope",
                "signature_scope",
                surface_id,
                "high",
                "UserOperation signatures may replay if userOpHash is not bound to chain and EntryPoint scope",
                "userOpHash appears without full domain-binding signals",
                "signature replay across chain or EntryPoint domain fails",
            )
        )
    if "nonce" not in fields and not nonce_source and "userop" in source_lower:
        risks.append(
            _account_abstraction_userop_risk(
                "missing_nonce_scope",
                "nonce_scope",
                surface_id,
                "high",
                "UserOperations can replay when validation omits sender-scoped nonce consumption",
                "UserOperation signal is present without nonce source",
                "same UserOperation cannot execute twice",
            )
        )
    if prefund_source and not guard:
        risks.append(
            _account_abstraction_userop_risk(
                "unguarded_prefund_refund",
                "prefund_accounting",
                surface_id,
                "medium",
                "missingAccountFunds handling can refund or pull funds through an untrusted caller path",
                "prefund source is present without EntryPoint guard",
                "prefund transfer only occurs through trusted EntryPoint validation",
            )
        )
    if _has_any(source_lower, ("validatepaymasteruserop", "paymasteranddata")):
        risks.append(
            _account_abstraction_userop_risk(
                "paymaster_sponsor_scope",
                "paymaster_drain",
                surface_id,
                "high",
                "paymaster sponsorship can be drained if sponsor scope, deposit, and maxCost are not bounded",
                "paymaster validation or paymasterAndData signal is present",
                "invalid sponsor data cannot spend paymaster deposit",
            )
        )
    if "postop" in source_lower:
        risks.append(
            _account_abstraction_userop_risk(
                "postop_revert_accounting",
                "postop_revert",
                surface_id,
                "medium",
                "postOp revert or undercharge paths can leave sponsored operations unsettled",
                "postOp settlement signal is present",
                "postOp revert path cannot drain paymaster deposit",
            )
        )
    if "validationdata" in source_lower and not _has_any(
        source_lower, ("validuntil", "validafter", "aggregator")
    ):
        risks.append(
            _account_abstraction_userop_risk(
                "validation_data_bounds",
                "validation_data_bounds",
                surface_id,
                "medium",
                "validationData can silently accept invalid time ranges or aggregators when bounds are not decoded",
                "validationData signal is present without bounds decoding",
                "expired or not-yet-valid UserOperation validation fails",
            )
        )
    if "aggregator" in source_lower:
        risks.append(
            _account_abstraction_userop_risk(
                "aggregator_trust_boundary",
                "aggregator_trust",
                surface_id,
                "medium",
                "aggregated signatures require an explicit trusted aggregator boundary",
                "aggregator signal is present",
                "untrusted aggregator signature path is rejected",
            )
        )
    if "initcode" in source_lower or "createaccount" in source_lower:
        risks.append(
            _account_abstraction_userop_risk(
                "initcode_factory_scope",
                "initcode_factory",
                surface_id,
                "medium",
                "initCode account creation can bypass expected factory, sender, or salt constraints",
                "initCode or createAccount signal is present",
                "unexpected factory initCode cannot create privileged sender",
            )
        )
    if account_summary and not risks:
        risks.append(
            _account_abstraction_userop_risk(
                "account_summary_review",
                "userop_replay",
                surface_id,
                "medium",
                "account summary requests ERC-4337 validation review for replay and EntryPoint scope",
                "account abstraction summary input is present",
                "same UserOperation authorization cannot be accepted twice",
            )
        )
    return risks[:10]


def _account_abstraction_userop_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _account_abstraction_userop_mitigations(
    source_lower: str,
    risks: list[Dict[str, Any]],
) -> list[str]:
    categories = {risk["category"] for risk in risks}
    mitigations: list[str] = []
    if "entrypoint_guard" in categories or _has_any(source_lower, ("validateuserop", "postop")):
        mitigations.append("gate validation and execution to the trusted EntryPoint")
    if "signature_scope" in categories or "userophash" in source_lower:
        mitigations.append(
            "bind signatures to userOpHash, chain, EntryPoint, sender, nonce, and calldata"
        )
    if "nonce_scope" in categories:
        mitigations.append("consume sender-scoped nonces during validation")
    if categories.intersection({"prefund_accounting", "paymaster_drain", "postop_revert"}):
        mitigations.append("make paymaster postOp charging non-bypassable and bounded")
    if "validation_data_bounds" in categories:
        mitigations.append("decode and enforce validationData time bounds and aggregator")
    if "initcode_factory" in categories:
        mitigations.append("bind initCode factory, salt, and sender derivation")
    return _dedupe_text(mitigations)


def _account_abstraction_userop_validation_tests(
    risks: list[Dict[str, Any]],
    surface: Mapping[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if surface.get("entrypoint_guard"):
        tests.append("non-EntryPoint validateUserOp call reverts")
    if "nonce" in set(
        surface.get("userop_fields") if isinstance(surface.get("userop_fields"), list) else []
    ):
        tests.append("same UserOperation cannot execute twice")
    if surface.get("prefund_source"):
        tests.append("missingAccountFunds transfer only follows successful validation")
    return _dedupe_text(tests)


def _extract_heuristic_external_call_returndata_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    source_lower = source_code.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_call_summary = inputs.get("call_summary")
    call_summary = raw_call_summary if isinstance(raw_call_summary, Mapping) else {}
    has_call_signal = _has_any(
        combined_lower,
        (
            ".call(",
            ".staticcall(",
            "abi.decode",
            "returndata",
            "return data",
            "bytes memory data",
            "success",
            "revert(",
            "returndatacopy",
        ),
    )
    if not has_call_signal and not call_summary:
        return []

    surface = _external_call_returndata_surface(source_code, source_lower, call_summary)
    risks = _external_call_returndata_risks(source_lower, surface, call_summary)
    if not risks and not call_summary:
        return []
    return [
        {
            "id": "external_call_returndata_local_plan",
            "objective": "Validate low-level external call success, returndata shape, and decode/bubbling paths before trusting returned bytes.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": _external_call_returndata_mitigations(source_lower, risks),
            "validation_tests": _external_call_returndata_validation_tests(risks, surface),
            "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
            "confidence": 0.66 if risks else 0.45,
            "evidence": _dedupe_text(surface["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_external_call_returndata_signals"},
        }
    ]


def _external_call_returndata_surface(
    source_code: str,
    source_lower: str,
    call_summary: Mapping[str, Any],
) -> Dict[str, Any]:
    call_expr = _external_call_expression(source_code)
    call_kind = _external_call_kind(source_lower, call_summary)
    decode_site = _external_call_decode_site(source_code, call_summary)
    size_bound = _external_call_returndata_size_bound(source_code, source_lower)
    success_guard = _external_call_success_guard(source_code, source_lower)
    return {
        "id": f"{_safe_delegatecall_label(_first_declared_function(source_code) or 'call')}_{call_kind or 'call'}_returndata",
        "entrypoint": _first_declared_function(source_code) or "externalCall",
        "target_source": _external_call_target_source(call_expr, source_code),
        "call_kind": call_kind,
        "calldata_source": _external_call_calldata_source(call_expr, source_code),
        "returndata_source": _external_call_returndata_source(source_code),
        "decode_site": decode_site,
        "returndata_size_bound": size_bound,
        "success_guard": success_guard,
        "trust_boundary": _external_call_trust_boundary(source_lower),
        "value_forwarding": _external_call_value_forwarding(source_lower),
        "evidence": _external_call_returndata_evidence(
            source_lower,
            call_kind,
            decode_site,
            size_bound,
            success_guard,
        ),
    }


def _external_call_expression(source_code: str) -> str:
    match = re.search(
        r"([A-Za-z_][A-Za-z0-9_]*(?:\([^;]*\))?\.(?:staticcall|call|delegatecall)\s*(?:\{[^;]*?\})?\s*\([^;]*\))\s*;",
        source_code,
        re.DOTALL,
    )
    return re.sub(r"\s+", " ", match.group(1).strip()) if match else ""


def _external_call_kind(source_lower: str, call_summary: Mapping[str, Any]) -> str:
    raw_kinds = call_summary.get("call_kinds")
    if isinstance(raw_kinds, list):
        for item in raw_kinds:
            kind = _safe_metadata_text(item)
            if kind:
                return kind
    if ".staticcall" in source_lower:
        return "staticcall"
    if ".delegatecall" in source_lower:
        return "delegatecall"
    if ".call" in source_lower:
        return "call"
    return ""


def _external_call_target_source(call_expr: str, source_code: str) -> str:
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*(?:\([^;]*\))?)\.", call_expr)
    if match:
        return match.group(1)
    for name in ("oracleAdapter", "adapter", "target", "callee", "implementation"):
        if re.search(rf"\b{re.escape(name)}\b", source_code):
            return name
    return ""


def _external_call_calldata_source(call_expr: str, source_code: str) -> str:
    for pattern in (
        r"\b(abi\.encodeWithSelector\([^;]*?\))",
        r"\b(abi\.encodeWithSignature\([^;]*?\))",
        r"\b(callData|calldata|data)\b",
    ):
        match = re.search(pattern, call_expr or source_code, re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1).strip())
    return ""


def _external_call_returndata_source(source_code: str) -> str:
    for pattern in (
        r"\b(bytes\s+memory\s+([A-Za-z_][A-Za-z0-9_]*))\b",
        r"\b(bytes\s+([A-Za-z_][A-Za-z0-9_]*))\b",
    ):
        match = re.search(pattern, source_code)
        if match:
            return match.group(2)
    return "returndata" if "returndata" in source_code.lower() else ""


def _external_call_decode_site(
    source_code: str,
    call_summary: Mapping[str, Any],
) -> str:
    match = re.search(r"\babi\.decode\s*\([^;]*\)", source_code, re.DOTALL)
    if match:
        return re.sub(r"\s+", " ", match.group(0).strip())
    raw_decode_sites = call_summary.get("decode_sites")
    if isinstance(raw_decode_sites, list):
        for item in raw_decode_sites:
            decode_site = _safe_metadata_text(item)
            if decode_site:
                return decode_site
    return ""


def _external_call_returndata_size_bound(source_code: str, source_lower: str) -> str:
    for pattern in (
        r"\b([A-Za-z_][A-Za-z0-9_]*\.length\s*(?:==|>=|>|<=|<)\s*\d+)\b",
        r"\b(require\s*\([^;]*?\.length[^;]*?\))",
    ):
        match = re.search(pattern, source_code, re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1).strip())
    if _has_any(source_lower, ("returndatasize", "returndatacopy")):
        return "manual returndatasize guard"
    return ""


def _external_call_success_guard(source_code: str, source_lower: str) -> str:
    for pattern in (
        r"\brequire\s*\(\s*success\b[^;]*?\)",
        r"\bif\s*\(\s*!success\s*\)[^;{]*(?:\{[^}]*\}|;)",
        r"\bif\s*\(\s*success\s*\)",
    ):
        match = re.search(pattern, source_code, re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(0).strip())
    return "success referenced" if "success" in source_lower else ""


def _external_call_trust_boundary(source_lower: str) -> str:
    if _has_any(source_lower, ("registry", "adapter", "oracle", "target", "callee")):
        return "untrusted or registry-controlled target"
    if _has_any(source_lower, ("onlyowner", "allowlist", "whitelist")):
        return "administratively configured target"
    return "external target"


def _external_call_value_forwarding(source_lower: str) -> str:
    if _has_any(source_lower, (".call{value:", "value:", "msg.value")):
        return "value forwarded"
    return "none"


def _external_call_returndata_evidence(
    source_lower: str,
    call_kind: str,
    decode_site: str,
    size_bound: str,
    success_guard: str,
) -> list[str]:
    evidence: list[str] = []
    if call_kind:
        evidence.append(f"{call_kind} low-level call signal is present")
    if decode_site:
        evidence.append("abi.decode returndata consumption signal is present")
    if size_bound:
        evidence.append("returndata length guard signal is present")
    if success_guard:
        evidence.append("success guard signal is present")
    if "revert(" in source_lower or "returndatacopy" in source_lower:
        evidence.append("revert-data bubbling signal is present")
    return evidence or ["external-call returndata signal is present"]


def _external_call_returndata_risks(
    source_lower: str,
    surface: Mapping[str, Any],
    call_summary: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "external_call_returndata_surface"
    risks: list[Dict[str, Any]] = []
    call_kind = _safe_metadata_text(surface.get("call_kind"))
    decode_site = _safe_metadata_text(surface.get("decode_site"))
    size_bound = _safe_metadata_text(surface.get("returndata_size_bound"))
    success_guard = _safe_metadata_text(surface.get("success_guard"))
    returndata_source = _safe_metadata_text(surface.get("returndata_source"))
    if call_kind and not success_guard:
        risks.append(
            _external_call_returndata_risk(
                "unchecked_low_level_success",
                "unchecked_success",
                surface_id,
                "high",
                "low-level call success can be ignored before consuming returned bytes",
                "low-level call has no success guard signal",
                "failed target call does not update state or decode returndata",
            )
        )
    if decode_site and not size_bound:
        risks.append(
            _external_call_returndata_risk(
                "unsafe_returndata_decode",
                "unsafe_abi_decode",
                surface_id,
                "high",
                "abi.decode consumes untrusted returndata without an explicit length or shape bound",
                "abi.decode site is present without returndata length guard",
                "31 byte and oversized returndata are rejected before state update",
            )
        )
        risks.append(
            _external_call_returndata_risk(
                "malformed_returndata_decode",
                "malformed_returndata_dos",
                surface_id,
                "medium",
                "malformed returndata can revert caller logic or leave downstream state assumptions stale",
                "decode path lacks malformed returndata handling",
                "malformed returndata does not update cached state",
            )
        )
    if call_kind and not decode_site and returndata_source:
        risks.append(
            _external_call_returndata_risk(
                "returndata_ignored",
                "returndata_ignored",
                surface_id,
                "medium",
                "returned bytes are captured but not validated before downstream assumptions",
                "returndata variable is present without decode or validation site",
                "unexpected return bytes cannot drive privileged assumptions",
            )
        )
    if (
        _has_any(source_lower, ("returndatacopy", "return(add(", "revert(add(", "assembly"))
        and not size_bound
    ):
        risks.append(
            _external_call_returndata_risk(
                "unbounded_returndata_copy",
                "unbounded_returndata_copy",
                surface_id,
                "medium",
                "assembly returndata copy or bubbling can copy unbounded attacker-controlled bytes",
                "manual returndata copy or bubbling signal has no size bound",
                "oversized returndata target is bounded",
            )
        )
    if _has_any(source_lower, ("revert(", "error ", "returndata")) and call_kind and not size_bound:
        risks.append(
            _external_call_returndata_risk(
                "untrusted_revert_data",
                "revert_data_bubbling_dos",
                surface_id,
                "medium",
                "bubbled revert data from an untrusted target can grief memory or mislead callers",
                "revert-data path is present for untrusted external target",
                "huge revert data cannot DoS caller",
            )
        )
    if call_kind == "staticcall" and decode_site and not size_bound:
        risks.append(
            _external_call_returndata_risk(
                "untrusted_staticcall_decode",
                "untrusted_staticcall_decode",
                surface_id,
                "medium",
                "staticcall return bytes from an external adapter are decoded as trusted data",
                "staticcall decode path lacks return shape validation",
                "malicious staticcall adapter cannot return malformed quote",
            )
        )
    if call_kind and "code.length" not in source_lower and "extcodesize" not in source_lower:
        risks.append(
            _external_call_returndata_risk(
                "success_without_code_check",
                "success_without_code_check",
                surface_id,
                "low",
                "low-level calls can report success against accounts without expected code",
                "target code existence check is absent",
                "EOA or destroyed target cannot be treated as valid callee",
            )
        )
    if call_summary and not risks:
        risks.append(
            _external_call_returndata_risk(
                "call_summary_review",
                "malformed_returndata_dos",
                surface_id,
                "medium",
                "call summary requests returndata hardening review for low-level external call results",
                "external call summary input is present",
                "malicious target returns malformed or huge returndata",
            )
        )
    return risks[:10]


def _external_call_returndata_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _external_call_returndata_mitigations(
    source_lower: str,
    risks: list[Dict[str, Any]],
) -> list[str]:
    categories = {risk["category"] for risk in risks}
    mitigations: list[str] = []
    if "unchecked_success" in categories or _has_any(source_lower, (".call(", ".staticcall(")):
        mitigations.append("check success before decoding returndata")
    if categories.intersection(
        {"unsafe_abi_decode", "malformed_returndata_dos", "untrusted_staticcall_decode"}
    ):
        mitigations.append("bound returndata length before abi.decode")
    if "unbounded_returndata_copy" in categories:
        mitigations.append("cap returndata copy length")
    if "revert_data_bubbling_dos" in categories:
        mitigations.append("avoid trusting bubbled revert data from untrusted targets")
    if "success_without_code_check" in categories:
        mitigations.append("check target code before trusting low-level call success")
    return _dedupe_text(mitigations)


def _external_call_returndata_validation_tests(
    risks: list[Dict[str, Any]],
    surface: Mapping[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if surface.get("decode_site"):
        tests.append("malformed returndata is rejected before decode")
    if surface.get("success_guard"):
        tests.append("failed low-level call cannot update state")
    if surface.get("value_forwarding") == "value forwarded":
        tests.append("value-forwarding target cannot force unsafe decode path")
    return _dedupe_text(tests)


def _extract_heuristic_financial_math_precision_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    source_lower = source_code.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_math_summary = inputs.get("math_summary")
    math_summary = raw_math_summary if isinstance(raw_math_summary, Mapping) else {}
    has_math_signal = _has_any(
        combined_lower,
        (
            "muldiv",
            "1e18",
            "wad",
            "ray",
            "basis",
            "bps",
            "percent",
            "percentage",
            "reward",
            "accrue",
            "accumulator",
            "per share",
            "interest",
            "fee",
            "rate",
            "rounding",
            "unchecked",
        ),
    ) or bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+/[^\n;]+\*", combined))
    if not has_math_signal and not math_summary:
        return []

    surface = _financial_math_precision_surface(source_code, source_lower, math_summary)
    risks = _financial_math_precision_risks(source_lower, surface, math_summary)
    if not risks and not math_summary:
        return []
    return [
        {
            "id": "financial_math_precision_local_plan",
            "objective": "Validate financial formulas preserve precision, unit scale, and rounding assumptions across boundary values.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": _financial_math_precision_mitigations(source_lower, risks),
            "validation_tests": _financial_math_precision_validation_tests(risks, surface),
            "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
            "confidence": 0.67 if risks else 0.45,
            "evidence": _dedupe_text(surface["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_financial_math_precision_signals"},
        }
    ]


def _financial_math_precision_surface(
    source_code: str,
    source_lower: str,
    math_summary: Mapping[str, Any],
) -> Dict[str, Any]:
    entrypoint = _first_declared_function(source_code) or "financialMath"
    formula = _financial_math_formula(source_code)
    operation_order = _financial_math_operation_order(formula, source_lower)
    return {
        "id": f"{_safe_delegatecall_label(entrypoint)}_financial_math",
        "entrypoint": entrypoint,
        "formula": formula,
        "value_flow": _financial_math_value_flow(source_lower, math_summary),
        "unit_sources": _financial_math_unit_sources(source_code, source_lower, math_summary),
        "scale_factor": _financial_math_scale_factor(source_lower, math_summary),
        "rounding_direction": _financial_math_rounding_direction(source_lower),
        "operation_order": operation_order,
        "library_or_helper": _financial_math_library_or_helper(source_lower),
        "unchecked_context": _financial_math_unchecked_context(source_code, source_lower),
        "state_fields": _financial_math_state_fields(source_code),
        "evidence": _financial_math_surface_evidence(
            source_lower,
            formula,
            operation_order,
            math_summary,
        ),
    }


def _financial_math_formula(source_code: str) -> str:
    muldiv_helper = r"mulDiv(?:Down|Up|RoundingUp)?"
    fixed_point_helper = (
        r"(?:mulWad(?:Down|Up)?|divWad(?:Down|Up)?|mulRay(?:Down|Up)?|divRay(?:Down|Up)?)"
    )
    for pattern in (
        rf"\b(?:uint(?:256)?|int(?:256)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*\b{muldiv_helper}\s*\([^;]*);",
        rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*([+\-*/])=\s*([^;]*\b{muldiv_helper}\s*\([^;]*);",
        rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*\b{muldiv_helper}\s*\([^;]*);",
        rf"\breturn\s+([^;]*\b{muldiv_helper}\s*\([^;]*);",
        rf"\b(?:uint(?:256)?|int(?:256)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*\b{fixed_point_helper}\s*\([^;]*);",
        rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*([+\-*/])=\s*([^;]*\b{fixed_point_helper}\s*\([^;]*);",
        rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*\b{fixed_point_helper}\s*\([^;]*);",
        rf"\breturn\s+([^;]*\b{fixed_point_helper}\s*\([^;]*);",
        r"\b(?:uint(?:256)?|int(?:256)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*(?:/|\*)[^;]*);",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*([+\-*/])=\s*([^;]*(?:/|\*)[^;]*);",
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]*(?:/|\*)[^;]*);",
        r"\breturn\s+([^;]*(?:/|\*)[^;]*);",
    ):
        match = re.search(pattern, source_code, re.DOTALL)
        if match:
            if len(match.groups()) == 3:
                formula = f"{match.group(1)} {match.group(2)}= {match.group(3)}"
            elif len(match.groups()) == 2:
                formula = f"{match.group(1)} = {match.group(2)}"
            else:
                formula = f"return {match.group(1)}"
            return re.sub(r"\s+", " ", formula.strip())
    return ""


def _financial_math_operation_order(formula: str, source_lower: str) -> str:
    compact = formula.replace(" ", "")
    if re.search(r"/[A-Za-z0-9_().]+\*", compact):
        return "division_before_multiplication"
    if "muldiv" in source_lower:
        return "full_precision_muldiv"
    if _has_any(source_lower, ("mulwad", "divwad", "mulray", "divray")):
        return "fixed_point_helper"
    if "/" in compact and "*" in compact:
        return "mixed_multiply_divide"
    if "/" in compact:
        return "division"
    if "*" in compact:
        return "multiplication"
    return ""


def _financial_math_value_flow(
    source_lower: str,
    math_summary: Mapping[str, Any],
) -> str:
    raw_surfaces = math_summary.get("surfaces")
    if isinstance(raw_surfaces, list):
        for item in raw_surfaces:
            surface = _safe_metadata_text(item)
            if surface:
                return surface
    for token, label in (
        ("reward", "reward distribution"),
        ("accrue", "interest or reward accrual"),
        ("interest", "interest accrual"),
        ("fee", "fee accounting"),
        ("share", "share accounting"),
        ("debt", "debt accounting"),
        ("liquidat", "liquidation math"),
        ("swap", "AMM quote or swap math"),
    ):
        if token in source_lower:
            return label
    return "financial value flow"


def _financial_math_unit_sources(
    source_code: str,
    source_lower: str,
    math_summary: Mapping[str, Any],
) -> list[str]:
    raw_units = math_summary.get("units")
    units: list[str] = []
    if isinstance(raw_units, list):
        for item in raw_units:
            unit = _safe_metadata_text(item)
            if unit:
                units.append(unit)
                marker = _financial_math_summary_unit_marker(unit)
                if marker:
                    units.append(f"scale:{marker}")
    for name, label in (
        ("amount", "amount:asset"),
        ("totalShares", "totalShares:shares"),
        ("totalSupply", "totalSupply:shares"),
        ("rewardRate", "rewardRate:scaled"),
        ("price", "price:oracle_or_quote"),
        ("rate", "rate:scaled"),
        ("fee", "fee:scaled"),
    ):
        if re.search(rf"\b{re.escape(name)}\b", source_code):
            units.append(label)
    if "1e18" in source_lower:
        units.append("scale:1e18")
    if "1e6" in source_lower:
        units.append("scale:1e6")
    if (
        "decimals()" in source_lower
        or ".decimals(" in source_lower
        or re.search(r"\b10\s*\*\*\s*[a-z_][a-z0-9_]*decimals?\b", source_lower)
    ):
        units.append("scale:decimals()")
    if "10000" in source_lower or "basis" in source_lower or "bps" in source_lower:
        units.append("scale:basis_points")
    if _financial_math_has_percent_scale(source_lower):
        units.append("scale:percent")
    return _dedupe_text([unit for unit in units if unit])


def _financial_math_scale_factor(
    source_lower: str,
    math_summary: Mapping[str, Any],
) -> str:
    raw_units = math_summary.get("units")
    if _financial_math_has_mixed_scales(source_lower, math_summary):
        return "mixed scales"
    if isinstance(raw_units, list):
        for item in raw_units:
            unit = _safe_metadata_text(item)
            marker = _financial_math_summary_unit_marker(unit)
            if marker == "ray":
                return "1e27"
            if marker == "bps":
                return "10000 bps"
            if marker in {"1e18", "1e27", "1e6", "wad", "ray"}:
                return marker
            if marker == "basis_points":
                return "10000 bps"
            if marker == "percent":
                return "100 percent"
            if marker == "decimals()":
                return "decimals()"
    if "1e27" in source_lower or "ray" in source_lower:
        return "1e27"
    if "1e18" in source_lower or "wad" in source_lower:
        return "1e18"
    if "1e6" in source_lower:
        return "1e6"
    if "10000" in source_lower or "basis" in source_lower or "bps" in source_lower:
        return "10000 bps"
    if _financial_math_has_percent_scale(source_lower):
        return "100 percent"
    return ""


def _financial_math_scale_markers(
    source_lower: str,
    math_summary: Mapping[str, Any] | None = None,
) -> list[str]:
    markers: list[str] = []
    raw_units = math_summary.get("units") if isinstance(math_summary, Mapping) else None
    if isinstance(raw_units, list):
        for item in raw_units:
            unit = _safe_metadata_text(item)
            marker = _financial_math_summary_unit_marker(unit)
            if marker:
                markers.append(marker)
    for token, label in (
        ("1e27", "1e27"),
        ("ray", "ray"),
        ("1e18", "1e18"),
        ("wad", "wad"),
        ("1e6", "1e6"),
        ("decimals()", "decimals()"),
        (".decimals(", "decimals()"),
        ("10000", "basis_points"),
        ("bps", "basis_points"),
        ("basis", "basis_points"),
        ("percent", "percent"),
        ("percentage", "percent"),
    ):
        if token in source_lower:
            markers.append(label)
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:pct|percent|percentage)\b", source_lower):
        markers.append("percent")
    if re.search(r"/\s*100\b", source_lower) and _has_any(
        source_lower, ("fee", "rate", "percent", "pct")
    ):
        markers.append("percent")
    if re.search(r"\b10\s*\*\*\s*[a-z_][a-z0-9_]*decimals?\b", source_lower):
        markers.append("decimals()")
    return _dedupe_text(markers)


def _financial_math_summary_unit_marker(unit: str) -> str:
    unit_lower = unit.lower()
    if unit_lower in {"wad", "ray", "bps"}:
        return unit_lower
    if _has_any(unit_lower, ("1e27", "ray", "27 decimals", ":27")):
        return "1e27"
    if _has_any(unit_lower, ("1e18", "wad", "18 decimals", ":18")):
        return "1e18"
    if _has_any(unit_lower, ("1e6", "6 decimals", ":6")):
        return "1e6"
    if _has_any(unit_lower, ("10000", "basis_points", "basis", "bps")):
        return "basis_points"
    if _has_any(unit_lower, ("percent", "percentage", "pct", "1%")):
        return "percent"
    if _has_any(unit_lower, ("decimals()", ".decimals", "dynamic decimals", "token decimals")):
        return "decimals()"
    return ""


def _financial_math_has_percent_scale(source_lower: str) -> bool:
    return bool(
        "percent" in source_lower
        or "percentage" in source_lower
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:pct|percent|percentage)\b", source_lower)
        or (
            re.search(r"/\s*100\b", source_lower)
            and _has_any(source_lower, ("fee", "rate", "percent", "pct"))
        )
    )


def _financial_math_has_mixed_scales(
    source_lower: str,
    math_summary: Mapping[str, Any] | None = None,
) -> bool:
    markers = {
        _financial_math_equivalent_scale_marker(marker)
        for marker in _financial_math_scale_markers(source_lower, math_summary)
    }
    return len(markers) > 1


def _financial_math_equivalent_scale_marker(marker: str) -> str:
    if marker == "wad":
        return "1e18"
    if marker == "ray":
        return "1e27"
    if marker == "bps":
        return "basis_points"
    return marker


def _financial_math_rounding_direction(source_lower: str) -> str:
    if (
        "ceil" in source_lower
        or "rounding.up" in source_lower
        or "roundingup" in source_lower
        or "roundup" in source_lower
        or "muldivup" in source_lower
        or "wadup" in source_lower
        or "rayup" in source_lower
    ):
        return "up"
    if (
        "floor" in source_lower
        or "rounding.down" in source_lower
        or "muldivdown" in source_lower
        or "waddown" in source_lower
        or "raydown" in source_lower
        or "/" in source_lower
    ):
        return "down"
    return ""


def _financial_math_library_or_helper(source_lower: str) -> str:
    if "muldiv" in source_lower:
        return "mulDiv"
    if _has_any(source_lower, ("mulwad", "divwad", "mulray", "divray")):
        return "FixedPointMathLib"
    if "fullmath" in source_lower:
        return "FullMath"
    if "fixedpointmathlib" in source_lower:
        return "FixedPointMathLib"
    if "safecast" in source_lower:
        return "SafeCast"
    return ""


def _financial_math_unchecked_context(source_code: str, source_lower: str) -> str:
    if "unchecked" not in source_lower:
        return ""
    match = re.search(r"\bunchecked\s*\{([^}]*)\}", source_code, re.DOTALL)
    if match:
        return re.sub(r"\s+", " ", match.group(0).strip())[:_MAX_METADATA_TEXT_CHARS]
    return "unchecked arithmetic block"


def _financial_math_state_fields(source_code: str) -> list[str]:
    candidates = {
        "accRewardPerShare",
        "rewardPerShare",
        "totalShares",
        "totalSupply",
        "totalDebt",
        "debtIndex",
        "liquidityIndex",
        "feeGrowthGlobal",
        "lastAccrual",
    }
    return _state_variables(source_code, candidates)


def _financial_math_surface_evidence(
    source_lower: str,
    formula: str,
    operation_order: str,
    math_summary: Mapping[str, Any],
) -> list[str]:
    evidence: list[str] = []
    if formula:
        evidence.append("financial formula with multiplication or division is present")
    if operation_order:
        evidence.append(f"{operation_order} operation order signal is present")
    if _has_any(source_lower, ("1e18", "1e27", "wad", "ray", "1e6", "10000", "bps")):
        evidence.append("fixed-point or basis-point scale signal is present")
    if _financial_math_has_mixed_scales(source_lower, math_summary):
        evidence.append("mixed scale signal is present")
    if "unchecked" in source_lower:
        evidence.append("unchecked arithmetic context signal is present")
    if math_summary:
        evidence.append("math summary input is present")
    return evidence or ["financial math precision signal is present"]


def _financial_math_precision_risks(
    source_lower: str,
    surface: Mapping[str, Any],
    math_summary: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "financial_math_precision_surface"
    risks: list[Dict[str, Any]] = []
    operation_order = _safe_metadata_text(surface.get("operation_order"))
    scale_factor = _safe_metadata_text(surface.get("scale_factor"))
    rounding_direction = _safe_metadata_text(surface.get("rounding_direction"))
    helper = _safe_metadata_text(surface.get("library_or_helper"))

    if operation_order == "division_before_multiplication":
        risks.append(
            _financial_math_precision_risk(
                "division_before_multiplication",
                "division_before_multiplication",
                surface_id,
                "high",
                "division can truncate value before fixed-point scaling or reward multiplication",
                "division appears before multiplication in a financial formula",
                "tiny and large operands preserve expected scaled output",
            )
        )
    if "/" in _safe_metadata_text(surface.get("formula")) and rounding_direction == "down":
        risks.append(
            _financial_math_precision_risk(
                "rounding_to_zero",
                "rounding_to_zero",
                surface_id,
                "medium",
                "integer division can round small user values to zero",
                "division-based formula rounds down by default",
                "minimum nonzero amounts cannot lose all credited value",
            )
        )
    if rounding_direction in {"up", "down"} and helper:
        risks.append(
            _financial_math_precision_risk(
                f"explicit_rounding_{rounding_direction}",
                "rounding_direction_bias",
                surface_id,
                "low",
                "explicit financial rounding direction should be validated against protocol and user value-flow expectations",
                f"{helper} formula declares {rounding_direction} rounding semantics",
                "boundary values use the intended rounding direction",
            )
        )
    if (
        scale_factor
        and not helper
        and _has_any(source_lower, ("reward", "rate", "interest", "fee"))
    ):
        risks.append(
            _financial_math_precision_risk(
                "missing_full_precision_muldiv",
                "muldiv_precision",
                surface_id,
                "medium",
                "scaled financial formula lacks an explicit full-precision multiplication/division helper",
                "scale factor is present without mulDiv helper signal",
                "large operands do not overflow intermediate multiplication",
            )
        )
    if _financial_math_has_mixed_scales(source_lower, math_summary):
        risks.append(
            _financial_math_precision_risk(
                "mixed_scale_formula",
                "scale_mismatch",
                surface_id,
                "medium",
                "financial formula combines multiple scale systems that need explicit normalization",
                "mixed scale markers are present in the formula context",
                "operands with 6-decimal and 18-decimal units normalize before arithmetic",
            )
        )
    if scale_factor == "10000 bps":
        risks.append(
            _financial_math_precision_risk(
                "basis_point_denominator_review",
                "basis_point_denominator",
                surface_id,
                "medium",
                "basis-point fee or rate math depends on the expected denominator",
                "basis-point scale signal is present",
                "100 percent and one basis point rates produce expected values",
            )
        )
    if "percent" in set(_financial_math_scale_markers(source_lower, math_summary)):
        risks.append(
            _financial_math_precision_risk(
                "percentage_denominator_review",
                "percentage_denominator",
                surface_id,
                "medium",
                "percentage fee or rate math depends on a 100 denominator rather than basis points or fixed-point scale",
                "percentage scale signal is present",
                "0 percent, 100 percent, and fractional-rate boundaries produce expected values",
            )
        )
    if "unchecked" in source_lower:
        risks.append(
            _financial_math_precision_risk(
                "unchecked_financial_arithmetic",
                "unchecked_financial_arithmetic",
                surface_id,
                "medium",
                "unchecked arithmetic around financial values can hide intermediate overflow or underflow assumptions",
                "unchecked block is present near financial math signals",
                "boundary values cannot overflow unchecked financial state updates",
            )
        )
    if _has_any(
        source_lower, ("accrewardpershare", "rewardpershare", "debtindex", "liquidityindex")
    ):
        risks.append(
            _financial_math_precision_risk(
                "accumulator_precision_drift",
                "accumulator_drift",
                surface_id,
                "medium",
                "accumulator updates can drift over repeated rounding operations",
                "reward or index accumulator state field is present",
                "repeated accrual preserves aggregate value within explicit tolerance",
            )
        )
    if math_summary and not risks:
        risks.append(
            _financial_math_precision_risk(
                "math_summary_precision_review",
                "unit_conversion_loss",
                surface_id,
                "medium",
                "math summary requests precision review for financial formula units and scale",
                "math summary input is present",
                "formula units and scale factors are consistent across operands",
            )
        )
    return risks[:10]


def _financial_math_precision_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _financial_math_precision_mitigations(
    source_lower: str,
    risks: list[Dict[str, Any]],
) -> list[str]:
    categories = {risk["category"] for risk in risks}
    mitigations: list[str] = []
    if categories.intersection(
        {"division_before_multiplication", "muldiv_precision", "overflow_in_intermediate"}
    ):
        mitigations.append("use full-precision mulDiv")
    if categories.intersection({"rounding_to_zero", "rounding_direction_bias"}):
        mitigations.append("make rounding direction explicit")
    if categories.intersection(
        {
            "scale_mismatch",
            "unit_conversion_loss",
            "basis_point_denominator",
            "percentage_denominator",
        }
    ):
        mitigations.append("normalize units and denominators before arithmetic")
    if "unchecked_financial_arithmetic" in categories:
        mitigations.append("bound unchecked financial arithmetic inputs")
    if "accumulator_drift" in categories or _has_any(source_lower, ("acc", "index")):
        mitigations.append("test accumulator drift across repeated accruals")
    return _dedupe_text(mitigations)


def _financial_math_precision_validation_tests(
    risks: list[Dict[str, Any]],
    surface: Mapping[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if surface.get("scale_factor"):
        tests.append("small and large values preserve expected fixed-point precision")
    if surface.get("rounding_direction"):
        tests.append("rounding direction is explicit at boundary values")
    if surface.get("unchecked_context"):
        tests.append("unchecked arithmetic remains bounded for max-value operands")
    return _dedupe_text(tests)


def _extract_heuristic_delegatecall_storage_aliasing_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_layout_summary = inputs.get("layout_summary")
    raw_callee_summary = inputs.get("callee_summary")
    layout_summary = raw_layout_summary if isinstance(raw_layout_summary, Mapping) else {}
    callee_summary = raw_callee_summary if isinstance(raw_callee_summary, Mapping) else {}
    has_delegatecall = ".delegatecall" in source_code.lower() or ".delegatecall" in combined_lower
    has_summary_signal = bool(layout_summary or callee_summary)
    if not has_delegatecall and not has_summary_signal:
        return []

    surface = _delegatecall_surface(source_code, combined_lower)
    alias_paths = _delegatecall_alias_paths(surface["id"], layout_summary, callee_summary)
    risks = _delegatecall_alias_risks(combined_lower, surface, alias_paths)
    validation_tests = _delegatecall_validation_tests(risks, alias_paths)

    return [
        {
            "id": "delegatecall_aliasing_local_plan",
            "objective": "Validate delegatecall target and storage aliasing paths before treating delegated execution as safe.",
            "delegatecall_surfaces": [surface],
            "storage_alias_paths": alias_paths,
            "risks": risks,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "slither", "symbolic execution"],
            "confidence": 0.64 if risks or alias_paths else 0.48,
            "evidence": _dedupe_text(surface["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_delegatecall_storage_aliasing_signals"},
        }
    ]


def _delegatecall_surface(source_code: str, source_lower: str) -> Dict[str, Any]:
    caller_function = _delegatecall_caller_function(source_code)
    target_source = _delegatecall_target_source(source_code)
    selector_source = "msg.data selector forwarded to callee" if "msg.data" in source_lower else ""
    guard_summary = _delegatecall_guard_summary(source_lower)
    value_forwarding = (
        "delegatecall preserves caller msg.value context" if "msg.value" in source_lower else ""
    )
    trust_boundary = _delegatecall_target_trust_boundary(source_lower, target_source, guard_summary)
    evidence = ["delegatecall opcode signal is present"]
    if target_source:
        evidence.append(f"{target_source} target signal is present")
    if selector_source:
        evidence.append("msg.data selector forwarding signal is present")
    return {
        "id": f"{_safe_delegatecall_label(caller_function)}_delegatecall",
        "caller_function": caller_function,
        "target_source": target_source,
        "selector_source": selector_source,
        "target_trust_boundary": trust_boundary,
        "guard_summary": guard_summary,
        "value_forwarding": value_forwarding,
        "evidence": evidence,
    }


def _delegatecall_caller_function(source_code: str) -> str:
    delegate_pos = source_code.find(".delegatecall")
    prefix = source_code[: delegate_pos if delegate_pos >= 0 else len(source_code)]
    matches = list(
        re.finditer(
            r"\b(function\s+([A-Za-z_][A-Za-z0-9_]*)|fallback|receive)\s*\(",
            prefix,
            re.IGNORECASE,
        )
    )
    if not matches:
        return "fallback"
    match = matches[-1]
    if match.group(2):
        return match.group(2)
    text = match.group(1).lower()
    return "receive" if text == "receive" else "fallback"


def _delegatecall_target_source(source_code: str) -> str:
    for pattern in (
        r"\b(address\s+)?(implementation)\b",
        r"\b(address\s+)?(target)\b",
        r"\b(address\s+)?(module)\b",
        r"\b(address\s+)?(plugin)\b",
        r"\b(address\s+)?(facet)\b",
    ):
        match = re.search(pattern, source_code, re.IGNORECASE)
        if match:
            return match.group(2)
    return ""


def _delegatecall_guard_summary(source_lower: str) -> str:
    guards: list[str] = []
    if _has_any(source_lower, ("onlyowner", "onlyrole", "require(msg.sender", "_checkrole")):
        guards.append("caller access control")
    if _has_any(source_lower, ("whitelist", "allowlist", "approved", "isallowed")):
        guards.append("target allowlist")
    if _has_any(source_lower, ("codehash", "extcodehash")):
        guards.append("target codehash check")
    if _has_any(source_lower, ("address(0)", "code.length")):
        guards.append("basic target existence check")
    return ", ".join(guards)


def _delegatecall_target_trust_boundary(
    source_lower: str,
    target_source: str,
    guard_summary: str,
) -> str:
    if _has_any(source_lower, ("calldata target", "address target", "target) external")):
        return "user-controlled"
    if target_source in {"module", "plugin", "facet"}:
        return "registry or module controlled"
    if guard_summary:
        return "guarded target"
    if target_source:
        return "mutable storage target"
    return ""


def _delegatecall_alias_paths(
    surface_id: str,
    layout_summary: Mapping[str, Any],
    callee_summary: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    caller = _layout_mapping(layout_summary.get("caller_slots"))
    callee = _layout_mapping(callee_summary.get("callee_slots"))
    paths: list[Dict[str, Any]] = []
    for slot in sorted(set(caller) & set(callee), key=_slot_sort_key):
        caller_semantics = caller.get(slot, "")
        callee_semantics = callee.get(slot, "")
        if not caller_semantics or not callee_semantics:
            continue
        paths.append(
            {
                "id": f"slot_{_safe_delegatecall_label(slot)}_alias",
                "delegatecall_surface_id": surface_id,
                "caller_slot": f"slot {slot}",
                "callee_slot": f"slot {slot}",
                "caller_semantics": caller_semantics,
                "callee_semantics": callee_semantics,
                "write_source": "callee delegatecall writes caller storage slot",
                "path_condition": "delegatecall executes callee code in caller storage context",
                "evidence": [f"caller and callee both define slot {slot}"],
            }
        )
        if len(paths) >= 10:
            break
    return paths


def _delegatecall_alias_risks(
    source_lower: str,
    surface: Dict[str, Any],
    alias_paths: list[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    surface_id = surface["id"]
    risks: list[Dict[str, Any]] = []
    if surface.get("target_trust_boundary") in {"user-controlled", "mutable storage target"}:
        risks.append(
            _delegatecall_risk(
                "delegate_target_control_review",
                "target_control",
                surface_id,
                "high",
                "delegatecall target requires explicit trust or allowlist validation",
                "delegatecall target appears mutable or externally supplied",
                "attempt delegatecall to malicious callee and expect rejection",
            )
        )
    if not surface.get("guard_summary"):
        risks.append(
            _delegatecall_risk(
                "delegate_guard_review",
                "access_context",
                surface_id,
                "high",
                "delegatecall surface has no obvious caller or target guard signal",
                "no access-control, allowlist, or codehash signal is present",
                "unauthorized caller cannot select or execute delegated code",
            )
        )
    if alias_paths:
        risks.append(
            _delegatecall_risk(
                "storage_alias_review",
                "storage_collision",
                surface_id,
                "high",
                "callee storage writes may reinterpret caller storage slots",
                "caller and callee layout summaries share slot indexes",
                "malicious or mismatched callee cannot overwrite owner/admin/accounting slot",
            )
        )
    if _has_any(source_lower, ("selfdestruct", "delegatecall(msg.data)", "msg.data")):
        risks.append(
            _delegatecall_risk(
                "selector_context_review",
                "selector_control",
                surface_id,
                "medium",
                "forwarded selectors can reach callee code paths in caller context",
                "msg.data or broad selector forwarding signal is present",
                "unexpected selector must not mutate caller privileged storage",
            )
        )
    return risks[:8]


def _delegatecall_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _delegatecall_validation_tests(
    risks: list[Dict[str, Any]],
    alias_paths: list[Dict[str, Any]],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if alias_paths:
        tests.append(
            "deploy malicious callee that writes caller slot 0 and assert owner/admin unchanged"
        )
    return _dedupe_text(tests)


def _safe_delegatecall_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "delegatecall"


def _extract_heuristic_oracle_feed_hardening_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_oracle_summary = inputs.get("oracle_summary")
    oracle_summary = raw_oracle_summary if isinstance(raw_oracle_summary, Mapping) else {}
    has_oracle_signal = _has_any(
        combined_lower,
        (
            "oracle",
            "pricefeed",
            "latestrounddata",
            "aggregatorv3interface",
            "chainlink",
            "twap",
            "getreserves",
            "sequencer",
            "updatedat",
            "answeredinaround",
            "decimals()",
        ),
    )
    if not has_oracle_signal and not oracle_summary:
        return []

    feed = _oracle_feed_source(source_code, combined_lower, oracle_summary)
    risks = _oracle_feed_risks(combined_lower, feed)
    validation_tests = _oracle_feed_validation_tests(risks, feed)
    return [
        {
            "id": "oracle_feed_local_plan",
            "objective": "Validate oracle feed freshness, normalization, and failure-mode checks before trusting price-dependent logic.",
            "feeds": [feed],
            "risks": risks,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "slither", "symbolic execution"],
            "confidence": 0.64 if risks else 0.48,
            "evidence": _dedupe_text(feed["evidence"] + [risk["description"] for risk in risks]),
            "metadata": {"strategy": "regex_oracle_feed_hardening_signals"},
        }
    ]


def _oracle_feed_source(
    source_code: str,
    source_lower: str,
    oracle_summary: Mapping[str, Any],
) -> Dict[str, Any]:
    consumer_function = _oracle_consumer_function(source_code)
    read_method = _oracle_read_method(source_lower)
    feed_kind = _oracle_feed_kind(source_lower, oracle_summary)
    evidence = ["oracle or price feed signal is present"]
    if read_method:
        evidence.append(f"{read_method} read signal is present")
    if oracle_summary:
        evidence.append("oracle summary input is present")
    return {
        "id": _oracle_feed_id(oracle_summary, feed_kind),
        "consumer_function": consumer_function,
        "feed_kind": feed_kind,
        "source_contract": _oracle_source_contract(source_code),
        "read_method": read_method,
        "freshness_source": "updatedAt" if "updatedat" in source_lower else "",
        "staleness_threshold": _oracle_staleness_threshold(source_code),
        "decimals_source": "decimals()" if "decimals()" in source_lower else "",
        "normalization": _oracle_normalization(source_lower),
        "fallback_source": _oracle_fallback_source(source_lower),
        "sequencer_guard": _oracle_sequencer_guard(source_lower),
        "bounds_check": _oracle_bounds_check(source_lower),
        "evidence": evidence,
    }


def _oracle_consumer_function(source_code: str) -> str:
    for name in ("getPrice", "price", "getLatestPrice", "latestPrice", "quote", "consult"):
        if re.search(rf"\bfunction\s+{name}\b", source_code):
            return name
    match = re.search(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\).*?(latestRoundData|getReserves|consult)",
        source_code,
        re.IGNORECASE | re.DOTALL,
    )
    return match.group(1) if match else "oracleConsumer"


def _oracle_read_method(source_lower: str) -> str:
    if "latestrounddata" in source_lower:
        return "latestRoundData"
    if "latestanswer" in source_lower:
        return "latestAnswer"
    if "getreserves" in source_lower:
        return "getReserves"
    if "consult(" in source_lower:
        return "consult"
    return ""


def _oracle_feed_kind(source_lower: str, oracle_summary: Mapping[str, Any]) -> str:
    summary_text = " ".join(_safe_metadata_text(value).lower() for value in oracle_summary.values())
    combined = f"{source_lower} {summary_text}"
    if (
        "chainlink" in combined
        or "aggregatorv3interface" in combined
        or "latestrounddata" in combined
    ):
        return "chainlink"
    if "twap" in combined or "consult(" in combined:
        return "twap"
    if "getreserves" in combined:
        return "twap"
    if "manual" in combined or "setprice" in combined:
        return "manual"
    if "fallback" in combined:
        return "fallback"
    return "unknown"


def _oracle_feed_id(oracle_summary: Mapping[str, Any], feed_kind: str) -> str:
    feeds = oracle_summary.get("feeds")
    if isinstance(feeds, list) and feeds:
        label = _safe_metadata_text(feeds[0])
        if label:
            return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_") or "oracle_feed"
    return f"{feed_kind}_oracle_feed" if feed_kind and feed_kind != "unknown" else "oracle_feed"


def _oracle_source_contract(source_code: str) -> str:
    for pattern in (
        r"\b(AggregatorV3Interface\s+public\s+([A-Za-z_][A-Za-z0-9_]*))",
        r"\b(IPriceFeed\s+public\s+([A-Za-z_][A-Za-z0-9_]*))",
        r"\b(priceFeed)\b",
        r"\b(oracle)\b",
    ):
        match = re.search(pattern, source_code, re.IGNORECASE)
        if match:
            return match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
    return ""


def _oracle_staleness_threshold(source_code: str) -> str:
    match = re.search(r"\b(maxDelay|heartbeat|maxStaleness|stalePeriod)\b", source_code)
    return match.group(1) if match else ""


def _oracle_normalization(source_lower: str) -> str:
    if _has_any(source_lower, ("1e18", "10 ** 18", "10**18")):
        return "scale to 1e18"
    if "decimals()" in source_lower:
        return "uses feed decimals"
    return ""


def _oracle_fallback_source(source_lower: str) -> str:
    if "fallback" in source_lower or "secondary" in source_lower:
        return "fallback or secondary feed"
    return ""


def _oracle_sequencer_guard(source_lower: str) -> str:
    if "sequencer" in source_lower and _has_any(
        source_lower, ("uptime", "graceperiod", "grace_period")
    ):
        return "sequencer uptime feed plus grace period"
    if "sequencer" in source_lower:
        return "sequencer uptime feed"
    return ""


def _oracle_bounds_check(source_lower: str) -> str:
    checks: list[str] = []
    if _has_any(source_lower, ("answer > 0", "price > 0", "> 0")):
        checks.append("price > 0")
    if _has_any(source_lower, ("maxdeviation", "deviation", "minprice", "maxprice")):
        checks.append("deviation or min/max bounds")
    return ", ".join(checks)


def _oracle_feed_risks(source_lower: str, feed: Dict[str, Any]) -> list[Dict[str, Any]]:
    feed_id = feed["id"]
    risks: list[Dict[str, Any]] = []
    if feed.get("read_method") == "latestRoundData" and not feed.get("freshness_source"):
        risks.append(
            _oracle_risk(
                "missing_updated_at_review",
                "stale_round",
                feed_id,
                "high",
                "Chainlink latestRoundData usage should inspect updatedAt freshness",
                "latestRoundData signal is present without updatedAt",
                "stale updatedAt must revert",
            )
        )
    if feed.get("freshness_source") and not feed.get("staleness_threshold"):
        risks.append(
            _oracle_risk(
                "missing_staleness_threshold",
                "stale_round",
                feed_id,
                "high",
                "updatedAt is present but no heartbeat or max staleness threshold is obvious",
                "updatedAt signal is present without maxDelay or heartbeat",
                "updatedAt older than threshold must revert",
            )
        )
    if "answeredinaround" not in source_lower and feed.get("read_method") == "latestRoundData":
        risks.append(
            _oracle_risk(
                "incomplete_round_review",
                "incomplete_round",
                feed_id,
                "medium",
                "latestRoundData consumers should reject incomplete oracle rounds",
                "answeredInRound signal is not present",
                "answeredInRound lower than roundId must revert",
            )
        )
    if not feed.get("bounds_check"):
        risks.append(
            _oracle_risk(
                "missing_price_bounds",
                "zero_negative_price",
                feed_id,
                "high",
                "oracle answer should reject zero, negative, or out-of-range prices",
                "no positive price or bounds check signal is present",
                "zero or negative price answer must revert",
            )
        )
    if feed.get("decimals_source") and not feed.get("normalization"):
        risks.append(
            _oracle_risk(
                "decimals_normalization_review",
                "decimals_mismatch",
                feed_id,
                "medium",
                "feed decimals should be normalized before accounting or collateral math",
                "decimals() signal is present without clear scaling",
                "different feed decimals produce same normalized value",
            )
        )
    if "sequencer" in source_lower and not feed.get("sequencer_guard"):
        risks.append(
            _oracle_risk(
                "sequencer_guard_review",
                "sequencer_down",
                feed_id,
                "high",
                "L2 oracle consumers should reject prices while sequencer is down or grace period active",
                "sequencer signal is present without uptime grace guard",
                "sequencer-down answer must revert until grace period elapses",
            )
        )
    return risks[:8]


def _oracle_risk(
    risk_id: str,
    category: str,
    feed_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_feed_id": feed_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _oracle_feed_validation_tests(
    risks: list[Dict[str, Any]],
    feed: Dict[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if feed.get("freshness_source"):
        tests.append("stale updatedAt must revert")
    if feed.get("bounds_check"):
        tests.append("zero or negative answer must revert")
    return _dedupe_text(tests)


def _extract_heuristic_adversarial_ordering_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_market_summary = inputs.get("market_summary")
    market_summary = raw_market_summary if isinstance(raw_market_summary, Mapping) else {}
    has_ordering_signal = _has_any(
        combined_lower,
        (
            "swap",
            "minout",
            "amountoutmin",
            "deadline",
            "reserve",
            "liquidat",
            "auction",
            "commit",
            "reveal",
            "permit",
            "nonce",
            "front-run",
            "frontrun",
            "sandwich",
            "mev",
        ),
    )
    if not has_ordering_signal and not market_summary:
        return []

    source_lower = source_code.lower()
    pattern = _ordering_pattern(combined_lower, market_summary)
    transactions = _ordering_transactions(source_code, source_lower, pattern)
    risks = _ordering_risks(source_lower, transactions, pattern)
    oracle = _ordering_oracle(pattern)
    validation_tests = _ordering_validation_tests(risks, pattern)
    return [
        {
            "id": "adversarial_ordering_local_plan",
            "objective": "Validate adversarial transaction ordering before treating public state-dependent execution as safe.",
            "ordering_pattern": pattern,
            "transactions": transactions,
            "risks": risks,
            "oracle": oracle,
            "mitigations": _ordering_mitigations(combined_lower, pattern),
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "mev simulation", "sequence oracle"],
            "confidence": 0.62 if risks else 0.46,
            "evidence": _dedupe_text(
                [f"{pattern} ordering signal is present"] + [risk["description"] for risk in risks]
            ),
            "metadata": {"strategy": "regex_adversarial_transaction_ordering_signals"},
        }
    ]


def _ordering_pattern(source_lower: str, market_summary: Mapping[str, Any]) -> str:
    summary_text = " ".join(_safe_metadata_text(value).lower() for value in market_summary.values())
    combined = f"{source_lower} {summary_text}"
    if _has_any(combined, ("sandwich", "swap", "reserve", "amountoutmin", "minout")):
        return "sandwich"
    if "liquidat" in combined:
        return "liquidation_race"
    if _has_any(combined, ("commit", "reveal", "sealed")):
        return "commit_reveal"
    if _has_any(combined, ("auction", "bid")):
        return "auction_reorder"
    if _has_any(combined, ("permit", "nonce")):
        return "permit_nonce_dos"
    if _has_any(combined, ("front-run", "frontrun")):
        return "front_run"
    return "unknown"


def _ordering_transactions(
    source_code: str,
    source_lower: str,
    pattern: str,
) -> list[Dict[str, Any]]:
    victim_function = _ordering_function(source_code, pattern)
    state_dependency = _ordering_state_dependency(source_lower, pattern)
    slippage = _ordering_slippage_or_limit(source_code, source_lower)
    txs = [
        {
            "id": "attacker_front",
            "role": "attacker_front",
            "function": victim_function,
            "actor": "searcher",
            "position": "before_victim",
            "value_hint": "front-run amount",
            "state_dependency": state_dependency,
            "slippage_or_limit": "none",
            "evidence": ["public state-dependent transaction can be ordered first"],
        },
        {
            "id": "victim_transaction",
            "role": "victim",
            "function": victim_function,
            "actor": "user",
            "position": "victim",
            "value_hint": _ordering_value_hint(source_lower, pattern),
            "state_dependency": state_dependency,
            "slippage_or_limit": slippage,
            "evidence": ["victim transaction consumes state changed by earlier transactions"],
        },
    ]
    if pattern in {"sandwich", "back_run"}:
        txs.append(
            {
                "id": "attacker_back",
                "role": "attacker_back",
                "function": victim_function,
                "actor": "searcher",
                "position": "after_victim",
                "value_hint": "back-run amount",
                "state_dependency": state_dependency,
                "slippage_or_limit": "none",
                "evidence": ["attacker can close ordering-dependent position after victim"],
            }
        )
    return txs


def _ordering_function(source_code: str, pattern: str) -> str:
    preferred = ("swap", "swapExactTokensForTokens", "liquidate", "bid", "reveal", "permit")
    for name in preferred:
        if re.search(rf"\bfunction\s+{re.escape(name)}\b", source_code, re.IGNORECASE):
            return name
    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", source_code)
    if match:
        return match.group(1)
    return "liquidate" if pattern == "liquidation_race" else "transaction"


def _ordering_state_dependency(source_lower: str, pattern: str) -> str:
    if _has_any(source_lower, ("reserve", "getreserves")):
        return "pool reserves"
    if _has_any(source_lower, ("price", "oracle")):
        return "oracle price"
    if pattern == "liquidation_race":
        return "collateral and debt state"
    if pattern == "auction_reorder":
        return "current highest bid"
    return "shared contract state"


def _ordering_slippage_or_limit(source_code: str, source_lower: str) -> str:
    for name in ("amountOutMin", "minOut", "deadline", "maxPrice", "minShares"):
        if re.search(rf"\b{name}\b", source_code):
            return name
    if "deadline" in source_lower:
        return "deadline"
    return "none"


def _ordering_value_hint(source_lower: str, pattern: str) -> str:
    if "amountin" in source_lower:
        return "amountIn"
    if pattern == "liquidation_race":
        return "debt amount"
    if pattern == "auction_reorder":
        return "bid amount"
    return "transaction amount"


def _ordering_risks(
    source_lower: str,
    transactions: list[Dict[str, Any]],
    pattern: str,
) -> list[Dict[str, Any]]:
    victim_id = transactions[1]["id"] if len(transactions) > 1 else "victim_transaction"
    risks: list[Dict[str, Any]] = []
    if pattern in {"sandwich", "front_run"}:
        risks.append(
            _ordering_risk(
                "front_run_state_change",
                "front_run",
                victim_id,
                "high",
                "attacker can change shared state before the victim transaction executes",
                "swap/reserve or front-run ordering signal is present",
                "front-run reserve change must not worsen victim execution beyond limit",
            )
        )
    if _has_any(source_lower, ("swap", "reserve")) and not _has_any(
        source_lower, ("amountoutmin", "minout")
    ):
        risks.append(
            _ordering_risk(
                "missing_min_out",
                "slippage_gap",
                victim_id,
                "high",
                "victim swap appears to lack an explicit minimum output limit",
                "swap signal is present without minOut or amountOutMin",
                "front-run before victim must respect a minimum output",
            )
        )
    if "deadline" not in source_lower and pattern in {"sandwich", "front_run"}:
        risks.append(
            _ordering_risk(
                "missing_deadline",
                "deadline_gap",
                victim_id,
                "medium",
                "public ordering-sensitive transaction has no obvious deadline limit",
                "deadline signal is not present",
                "stale transaction after deadline must revert",
            )
        )
    if pattern == "liquidation_race":
        risks.append(
            _ordering_risk(
                "liquidation_race",
                "liquidation_race",
                victim_id,
                "high",
                "liquidation outcome may depend on same-block state or oracle ordering",
                "liquidation signal is present",
                "competing liquidation order must not over-seize collateral",
            )
        )
    if pattern == "permit_nonce_dos":
        risks.append(
            _ordering_risk(
                "permit_nonce_ordering",
                "permit_nonce_dos",
                victim_id,
                "medium",
                "permit nonce usage can be consumed or reordered before intended action",
                "permit and nonce signals are present",
                "front-run permit nonce consumption must not break intended action",
            )
        )
    return risks[:8]


def _ordering_risk(
    risk_id: str,
    category: str,
    tx_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_transaction_id": tx_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _ordering_oracle(pattern: str) -> str:
    if pattern == "sandwich":
        return "victim receives at least the configured minimum output under adversarial ordering"
    if pattern == "liquidation_race":
        return "liquidation ordering does not over-seize collateral or leave debt inconsistent"
    if pattern == "permit_nonce_dos":
        return "permit nonce ordering cannot break the intended authorized action"
    return "victim outcome remains bounded under adversarial transaction ordering"


def _ordering_mitigations(source_lower: str, pattern: str) -> list[str]:
    mitigations: list[str] = []
    if _has_any(source_lower, ("amountoutmin", "minout")):
        mitigations.append("minOut")
    else:
        mitigations.append("add minOut or equivalent limit")
    if "deadline" in source_lower:
        mitigations.append("deadline")
    elif pattern in {"sandwich", "front_run"}:
        mitigations.append("add deadline")
    if pattern == "commit_reveal":
        mitigations.append("commit-reveal salt binding")
    if pattern == "sandwich":
        mitigations.append("private routing")
    return _dedupe_text(mitigations)


def _ordering_validation_tests(
    risks: list[Dict[str, Any]],
    pattern: str,
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if pattern == "sandwich":
        tests.append("attacker front-run before victim and back-run after victim")
    return _dedupe_text(tests)


def _extract_heuristic_erc4626_vault_inflation_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_vault_summary = inputs.get("vault_summary")
    vault_summary = raw_vault_summary if isinstance(raw_vault_summary, Mapping) else {}
    has_vault_signal = _has_any(
        combined_lower,
        (
            "erc4626",
            "converttoshares",
            "converttoassets",
            "previewdeposit",
            "previewmint",
            "totalassets",
            "totalsupply",
            "deposit(",
            "mint(",
            "share",
            "vault",
        ),
    )
    if not has_vault_signal and not vault_summary:
        return []

    source_lower = source_code.lower()
    surface = _erc4626_vault_surface(source_code, source_lower)
    risks = _erc4626_vault_risks(source_lower, surface)
    mitigations = _erc4626_vault_mitigations(source_lower)
    validation_tests = _erc4626_vault_validation_tests(risks, source_lower)
    return [
        {
            "id": "erc4626_vault_inflation_local_plan",
            "objective": "Validate ERC4626 share math against first-depositor donation and zero-share inflation paths.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": mitigations,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "echidna", "symbolic execution"],
            "confidence": 0.66 if risks else 0.42,
            "evidence": _dedupe_text(
                ["ERC4626 or vault share-accounting signal is present"]
                + surface.get("evidence", [])
                + [risk["description"] for risk in risks]
            ),
            "metadata": {"strategy": "regex_erc4626_vault_inflation_signals"},
        }
    ]


def _erc4626_vault_surface(source_code: str, source_lower: str) -> Dict[str, Any]:
    functions = _public_state_functions(source_code)
    vault_function = _pick_function(functions, ("deposit", "mint", "withdraw", "redeem"))
    if not vault_function:
        vault_function = _first_declared_function(source_code) or "deposit"
    share_function = _erc4626_share_function(source_lower)
    total_assets_source = _erc4626_total_assets_source(source_lower)
    return {
        "id": "vault_share_math",
        "vault_function": vault_function,
        "asset_function": "totalAssets" if "totalassets" in source_lower else "",
        "share_function": share_function,
        "total_assets_source": total_assets_source,
        "total_supply_source": "totalSupply" if "totalsupply" in source_lower else "",
        "conversion_formula": _erc4626_conversion_formula(source_lower),
        "rounding_direction": _erc4626_rounding_direction(source_lower),
        "empty_vault_behavior": _erc4626_empty_vault_behavior(source_lower),
        "donation_exposure": _erc4626_donation_exposure(source_lower),
        "mitigation": ", ".join(_erc4626_vault_mitigations(source_lower)),
        "evidence": _erc4626_surface_evidence(source_lower),
    }


def _first_declared_function(source_code: str) -> str:
    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", source_code)
    return match.group(1) if match else ""


def _erc4626_share_function(source_lower: str) -> str:
    if "converttoshares" in source_lower:
        return "convertToShares"
    if "previewdeposit" in source_lower:
        return "previewDeposit"
    if "previewmint" in source_lower:
        return "previewMint"
    return ""


def _erc4626_total_assets_source(source_lower: str) -> str:
    if _has_any(source_lower, ("balanceof(address(this))", "balanceof(address( this ))")):
        return "asset.balanceOf(address(this))"
    if "totalmanagedassets" in source_lower:
        return "internal totalManagedAssets"
    if "totalassets" in source_lower:
        return "totalAssets()"
    return ""


def _erc4626_conversion_formula(source_lower: str) -> str:
    if _has_any(source_lower, ("assets * totalsupply", "assets*totalsupply")):
        return "assets * totalSupply / totalAssets"
    if _has_any(source_lower, ("shares * totalassets", "shares*totalassets")):
        return "shares * totalAssets / totalSupply"
    if "muldiv" in source_lower:
        return "mulDiv-based conversion"
    return ""


def _erc4626_rounding_direction(source_lower: str) -> str:
    if _has_any(source_lower, ("rounding.up", "ceildiv", "round up")):
        return "up"
    if _has_any(source_lower, ("/ totalassets", "/totalassets", "rounding.down", "floor")):
        return "down"
    return "unknown"


def _erc4626_empty_vault_behavior(source_lower: str) -> str:
    if _has_any(source_lower, ("totalsupply == 0", "totalsupply() == 0", "supply == 0")):
        return "explicit zero-supply branch"
    if _has_any(source_lower, ("virtual", "offset", "deadshares", "dead shares")):
        return "seeded or virtualized first deposit"
    return ""


def _erc4626_donation_exposure(source_lower: str) -> str:
    if _has_any(source_lower, ("balanceof(address(this))", "balanceof(address( this ))")):
        return "direct transfer changes raw asset balance"
    if "totalmanagedassets" in source_lower:
        return "internal accounting limits direct donation exposure"
    return ""


def _erc4626_surface_evidence(source_lower: str) -> list[str]:
    evidence: list[str] = []
    if "erc4626" in source_lower:
        evidence.append("ERC4626 symbol is present")
    if "converttoshares" in source_lower:
        evidence.append("convertToShares share conversion is present")
    if "previewdeposit" in source_lower:
        evidence.append("previewDeposit surface is present")
    if "balanceof(address(this))" in source_lower:
        evidence.append("totalAssets reads raw asset balance")
    if "totalsupply" in source_lower:
        evidence.append("totalSupply participates in share math")
    return _dedupe_text(evidence)


def _erc4626_vault_risks(
    source_lower: str,
    surface: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "vault_share_math"
    risks: list[Dict[str, Any]] = []
    if _has_any(source_lower, ("balanceof(address(this))", "balanceof(address( this ))")):
        risks.append(
            _erc4626_vault_risk(
                "direct_donation_inflation",
                "direct_donation",
                surface_id,
                "high",
                "raw asset balance can be changed by direct donations before victim deposits",
                "totalAssets reads asset.balanceOf(address(this))",
                "attacker donation before victim deposit must not reduce victim shares below minimum",
            )
        )
    if "converttoshares" in source_lower and not _has_any(
        source_lower, ("minshares", "minsharesout", "minimum shares")
    ):
        risks.append(
            _erc4626_vault_risk(
                "missing_minimum_shares",
                "missing_min_shares",
                surface_id,
                "medium",
                "deposit path does not expose an obvious minimum-share guard",
                "minShares or minSharesOut signal is not present",
                "victim deposit must revert when computed shares are below minimum",
            )
        )
    if "totalsupply" in source_lower and not _has_any(
        source_lower, ("virtual", "offset", "deadshares", "dead shares")
    ):
        risks.append(
            _erc4626_vault_risk(
                "missing_virtual_offset",
                "missing_virtual_offset",
                surface_id,
                "medium",
                "low-supply share math has no obvious virtual offset or dead-share seeding",
                "virtual shares/assets or dead shares are not present",
                "first-depositor donation cannot force zero or near-zero victim shares",
            )
        )
    if _has_any(source_lower, ("/ totalassets", "/totalassets")):
        risks.append(
            _erc4626_vault_risk(
                "rounding_loss",
                "rounding_loss",
                surface_id,
                "medium",
                "integer division in share conversion can round victim shares down",
                "share conversion divides by totalAssets",
                "small victim deposit after donation must not round to zero shares",
            )
        )
    if "previewdeposit" in source_lower and "deposit" in source_lower:
        risks.append(
            _erc4626_vault_risk(
                "preview_execution_mismatch",
                "preview_mismatch",
                surface_id,
                "low",
                "previewDeposit and deposit paths should agree under donated or low-supply state",
                "previewDeposit and deposit surfaces are both present",
                "previewDeposit must match deposit share minting under donated state",
            )
        )
    return risks[:8]


def _erc4626_vault_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _erc4626_vault_mitigations(source_lower: str) -> list[str]:
    mitigations: list[str] = []
    if "virtual" in source_lower or "offset" in source_lower:
        mitigations.append("virtual shares/assets")
    else:
        mitigations.append("add virtual shares/assets")
    if _has_any(source_lower, ("deadshares", "dead shares")):
        mitigations.append("dead shares")
    else:
        mitigations.append("seed dead shares or minimum liquidity")
    if _has_any(source_lower, ("minshares", "minsharesout")):
        mitigations.append("minimum-share guard")
    else:
        mitigations.append("add minimum-share guard")
    if "totalmanagedassets" in source_lower:
        mitigations.append("internal totalAssets accounting")
    elif "balanceof(address(this))" in source_lower:
        mitigations.append("consider internal totalAssets accounting")
    return _dedupe_text(mitigations)


def _erc4626_vault_validation_tests(
    risks: list[Dict[str, Any]],
    source_lower: str,
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if _has_any(source_lower, ("balanceof(address(this))", "converttoshares")):
        tests.append("first depositor donation cannot force zero victim shares")
    return _dedupe_text(tests)


def _extract_heuristic_create2_deployment_hardening_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_deployment_summary = inputs.get("deployment_summary")
    deployment_summary = (
        raw_deployment_summary if isinstance(raw_deployment_summary, Mapping) else {}
    )
    has_create2_signal = _has_any(
        combined_lower,
        (
            "create2",
            "createsalted",
            "deterministic",
            "salt",
            "init_code",
            "initcode",
            "creationcode",
            "computeaddress",
            "predict",
            "factory",
        ),
    )
    if not has_create2_signal and not deployment_summary:
        return []

    source_lower = source_code.lower()
    surface = _create2_deployment_surface(source_code, source_lower)
    risks = _create2_deployment_risks(source_lower, surface)
    mitigations = _create2_deployment_mitigations(source_lower)
    validation_tests = _create2_deployment_validation_tests(risks, source_lower)
    return [
        {
            "id": "create2_deployment_local_plan",
            "objective": "Validate deterministic CREATE2 deployment against salt squatting, init-code mismatch, and address trust gaps.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": mitigations,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "slither", "fork simulation"],
            "confidence": 0.66 if risks else 0.42,
            "evidence": _dedupe_text(
                ["CREATE2 or deterministic deployment signal is present"]
                + surface.get("evidence", [])
                + [risk["description"] for risk in risks]
            ),
            "metadata": {"strategy": "regex_create2_deployment_signals"},
        }
    ]


def _create2_deployment_surface(source_code: str, source_lower: str) -> Dict[str, Any]:
    functions = _public_state_functions(source_code)
    deploy_function = _pick_function(
        functions,
        ("deploy", "deployWallet", "createWallet", "cloneDeterministic", "createAccount"),
    )
    if not deploy_function:
        deploy_function = _first_declared_function(source_code) or "deploy"
    return {
        "id": "create2_deployment_surface",
        "deploy_function": deploy_function,
        "factory_contract": _create2_factory_contract(source_code),
        "salt_source": _create2_salt_source(source_lower),
        "init_code_source": _create2_init_code_source(source_lower),
        "address_formula": _create2_address_formula(source_lower),
        "authorization_guard": _create2_authorization_guard(source_lower),
        "collision_check": _create2_collision_check(source_lower),
        "post_deploy_check": _create2_post_deploy_check(source_lower),
        "redeploy_assumption": _create2_redeploy_assumption(source_lower),
        "evidence": _create2_surface_evidence(source_lower),
    }


def _create2_factory_contract(source_code: str) -> str:
    match = re.search(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", source_code)
    return match.group(1) if match else ""


def _create2_salt_source(source_lower: str) -> str:
    if _has_any(source_lower, ("msg.sender", "owner", "receiver")) and "salt" in source_lower:
        return "salt bound to caller or owner"
    if "salt" in source_lower:
        return "user supplied salt"
    return ""


def _create2_init_code_source(source_lower: str) -> str:
    if "creationcode" in source_lower and "abi.encodepacked" in source_lower:
        return "abi.encodePacked(type(...).creationCode, constructor args)"
    if "creationcode" in source_lower:
        return "type(...).creationCode"
    if _has_any(source_lower, ("init_code", "initcode")):
        return "provided init code"
    return ""


def _create2_address_formula(source_lower: str) -> str:
    if _has_any(source_lower, ("0xff", "computeaddress", "predict")):
        return "keccak256(0xff, factory, salt, init_code_hash)"
    if "create2" in source_lower:
        return "CREATE2(factory, salt, init code hash)"
    return ""


def _create2_authorization_guard(source_lower: str) -> str:
    if _has_any(source_lower, ("onlyowner", "onlyrole", "require(msg.sender")):
        return "caller authorization guard"
    if "owner" in source_lower and "salt" in source_lower:
        return "salt includes owner"
    if "msg.sender" in source_lower and "salt" in source_lower:
        return "salt includes msg.sender"
    return ""


def _create2_collision_check(source_lower: str) -> str:
    if _has_any(source_lower, (".code.length == 0", "code.length==0", "extcodesize")):
        return "predicted address has no code before deploy"
    if _has_any(source_lower, ("deployed[address]", "isdeployed", "already deployed")):
        return "deployment registry collision check"
    return ""


def _create2_post_deploy_check(source_lower: str) -> str:
    if _has_any(source_lower, ("codehash", "extcodehash")):
        return "deployed codehash verified"
    if _has_any(
        source_lower, ("wallet != address(0)", "addr != address(0)", "deployed != address(0)")
    ):
        return "nonzero deployed address checked"
    return ""


def _create2_redeploy_assumption(source_lower: str) -> str:
    if "selfdestruct" in source_lower:
        return "selfdestruct or metamorphic redeploy path is present"
    if "create2" in source_lower:
        return "no selfdestruct/redeploy trust documented"
    return ""


def _create2_surface_evidence(source_lower: str) -> list[str]:
    evidence: list[str] = []
    if "create2" in source_lower:
        evidence.append("CREATE2 opcode or helper is present")
    if "salt" in source_lower:
        evidence.append("salt controls deterministic address")
    if "creationcode" in source_lower:
        evidence.append("creation code participates in init-code hash")
    if _has_any(source_lower, ("0xff", "computeaddress", "predict")):
        evidence.append("deterministic address prediction is present")
    if "selfdestruct" in source_lower:
        evidence.append("selfdestruct redeploy signal is present")
    return _dedupe_text(evidence)


def _create2_deployment_risks(
    source_lower: str,
    surface: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "create2_deployment_surface"
    risks: list[Dict[str, Any]] = []
    if "salt" in source_lower and not _has_any(source_lower, ("msg.sender", "owner", "chainid")):
        risks.append(
            _create2_deployment_risk(
                "predictable_salt",
                "predictable_salt",
                surface_id,
                "high",
                "public salt can let an attacker precompute and race the expected deployment address",
                "salt is present without caller, owner, or chain binding",
                "attacker using same salt cannot capture expected deterministic address",
            )
        )
    if "create2" in source_lower and not _has_any(
        source_lower,
        (".code.length == 0", "code.length==0", "extcodesize", "isdeployed"),
    ):
        risks.append(
            _create2_deployment_risk(
                "missing_collision_check",
                "salt_squatting",
                surface_id,
                "high",
                "deployment path has no obvious pre-deploy collision or already-deployed check",
                "CREATE2 signal is present without code-length or registry collision check",
                "predeployed address or repeated salt must revert before trust is assigned",
            )
        )
    if _has_any(source_lower, ("creationcode", "init_code", "initcode")) and not _has_any(
        source_lower,
        ("codehash", "initcodehash", "keccak256(code", "keccak256(init"),
    ):
        risks.append(
            _create2_deployment_risk(
                "missing_init_code_binding",
                "init_code_mismatch",
                surface_id,
                "medium",
                "deterministic address trust has no obvious init-code hash binding or verification",
                "init code participates in deployment without codehash verification signal",
                "predicted address must include and verify init-code hash",
            )
        )
    if "selfdestruct" in source_lower:
        risks.append(
            _create2_deployment_risk(
                "metamorphic_redeploy",
                "metamorphic_redeploy",
                surface_id,
                "high",
                "selfdestruct can change deterministic address trust assumptions after deployment",
                "selfdestruct signal is present near deterministic deployment logic",
                "redeploy after selfdestruct must not preserve stale trust",
            )
        )
    if "chainid" not in source_lower and _has_any(source_lower, ("salt", "owner", "factory")):
        risks.append(
            _create2_deployment_risk(
                "cross_chain_salt_replay",
                "cross_chain_replay",
                surface_id,
                "low",
                "salt domain does not show an explicit chain id binding",
                "block.chainid signal is not present",
                "same salt on another chain must not inherit unintended trust",
            )
        )
    return risks[:8]


def _create2_deployment_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _create2_deployment_mitigations(source_lower: str) -> list[str]:
    mitigations: list[str] = []
    if _has_any(source_lower, ("msg.sender", "owner", "chainid")):
        mitigations.append("salt domain binding")
    else:
        mitigations.append("bind salt to caller, owner, and chain id")
    if _has_any(source_lower, ("codehash", "initcodehash", "keccak256(code", "keccak256(init")):
        mitigations.append("verify init code hash")
    else:
        mitigations.append("verify init code hash")
    if _has_any(source_lower, (".code.length == 0", "code.length==0", "extcodesize", "isdeployed")):
        mitigations.append("collision check")
    else:
        mitigations.append("add collision check before deploy")
    if _has_any(source_lower, ("codehash", "extcodehash")):
        mitigations.append("post-deploy codehash check")
    else:
        mitigations.append("check deployed codehash")
    return _dedupe_text(mitigations)


def _create2_deployment_validation_tests(
    risks: list[Dict[str, Any]],
    source_lower: str,
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    if "create2" in source_lower:
        tests.append("front-run with same salt cannot capture expected address")
    if _has_any(source_lower, ("codehash", "creationcode", "init_code", "initcode")):
        tests.append("changed init code changes predicted address or fails verification")
    return _dedupe_text(tests)


def _extract_heuristic_abi_packed_hash_collision_plans(
    task: ReasoningTask,
    source_code: str,
) -> list[Dict[str, Any]]:
    prompt = task.prompt if isinstance(task.prompt, str) else ""
    combined = f"{prompt}\n{source_code}"
    combined_lower = combined.lower()
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_hash_summary = inputs.get("hash_summary")
    hash_summary = raw_hash_summary if isinstance(raw_hash_summary, Mapping) else {}
    packed_calls = _abi_packed_hash_calls(source_code)
    has_packed_signal = bool(packed_calls) or bool(hash_summary)
    has_relevant_text_signal = _has_any(
        combined_lower,
        (
            "abi.encodepacked",
            "packed_hash",
            "packed hash",
            "hash collision",
            "multiple dynamic",
        ),
    )
    if not has_packed_signal and not has_relevant_text_signal:
        return []

    surface = _abi_packed_hash_surface(source_code, combined_lower, packed_calls)
    dynamic_count = _safe_nonnegative_int_text(surface.get("dynamic_argument_count"))
    if dynamic_count < 2 and not hash_summary:
        return []

    risks = _abi_packed_hash_risks(combined_lower, surface)
    if not risks and dynamic_count < 2:
        return []

    mitigations = _abi_packed_hash_mitigations(combined_lower)
    validation_tests = _abi_packed_hash_validation_tests(risks, surface)
    return [
        {
            "id": "abi_packed_hash_collision_local_plan",
            "objective": "Validate packed ABI hash usage against ambiguous dynamic argument collisions.",
            "surfaces": [surface],
            "risks": risks,
            "mitigations": mitigations,
            "validation_tests": validation_tests,
            "recommended_tools": ["foundry", "slither", "property testing"],
            "confidence": 0.68 if risks else 0.43,
            "evidence": _dedupe_text(
                ["abi.encodePacked hash signal is present"]
                + surface.get("evidence", [])
                + [risk["description"] for risk in risks]
            ),
            "metadata": {"strategy": "regex_abi_packed_hash_collision_signals"},
        }
    ]


def _abi_packed_hash_calls(source_code: str) -> list[Dict[str, Any]]:
    calls: list[Dict[str, Any]] = []
    pattern = re.compile(
        r"keccak256\s*\(\s*abi\.encodePacked\s*\((?P<args>[^;]*?)\)\s*\)",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(source_code):
        expression = re.sub(r"\s+", " ", match.group(0).strip())
        args = _split_call_arguments(match.group("args"))
        calls.append({"expression": expression, "arguments": args})
        if len(calls) >= 5:
            break
    return calls


def _split_call_arguments(arguments_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in arguments_text:
        if char == "," and depth == 0:
            arg = "".join(current).strip()
            if arg:
                args.append(arg)
            current = []
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        current.append(char)
    arg = "".join(current).strip()
    if arg:
        args.append(arg)
    return args[:10]


def _abi_packed_hash_surface(
    source_code: str,
    combined_lower: str,
    packed_calls: list[Dict[str, Any]],
) -> Dict[str, Any]:
    call = packed_calls[0] if packed_calls else {"expression": "", "arguments": []}
    args = call.get("arguments") if isinstance(call.get("arguments"), list) else []
    typed_args = [_abi_packed_argument_type(source_code, arg) for arg in args]
    dynamic_count = sum(1 for arg_type in typed_args if _abi_type_is_dynamic(arg_type))
    hash_function = _abi_hash_function_for_expression(source_code, call.get("expression", ""))
    return {
        "id": "abi_packed_hash_surface",
        "hash_function": hash_function,
        "packed_expression": call.get("expression", ""),
        "argument_types": typed_args,
        "dynamic_argument_count": str(dynamic_count),
        "user_controlled_arguments": _abi_packed_user_controlled_args(source_code, args),
        "hash_usage": _abi_packed_hash_usage(combined_lower),
        "domain_separator": _abi_packed_domain_separator(combined_lower),
        "delimiter_or_length_guard": _abi_packed_delimiter_guard(combined_lower),
        "safer_encoding": _abi_packed_safer_encoding(args),
        "evidence": _abi_packed_surface_evidence(combined_lower, dynamic_count),
    }


def _abi_hash_function_for_expression(source_code: str, expression: Any) -> str:
    expr = expression if isinstance(expression, str) else ""
    if expr:
        idx = source_code.find(expr)
        if idx >= 0:
            prefix = source_code[:idx]
            matches = list(
                re.finditer(
                    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                    prefix,
                    re.IGNORECASE,
                )
            )
            if matches:
                return matches[-1].group(1)
    return _first_declared_function(source_code) or "hash"


def _abi_packed_argument_type(source_code: str, argument: str) -> str:
    arg_name = re.sub(r"[^A-Za-z0-9_].*$", "", argument.strip())
    if not arg_name:
        return "unknown"
    declaration = re.search(
        rf"\b(string|bytes(?:\d+)?|uint(?:\d+)?|int(?:\d+)?|address|bool)\s+(?:(?:calldata|memory|storage)\s+)?{re.escape(arg_name)}\b",
        source_code,
        re.IGNORECASE,
    )
    if declaration:
        return declaration.group(1)
    if re.search(rf"\b{re.escape(arg_name)}\s*\[\s*\]", source_code):
        return "array"
    if arg_name.lower() in {"msg", "sender", "block", "tx"}:
        return "context"
    return "unknown"


def _abi_type_is_dynamic(arg_type: str) -> bool:
    lowered = arg_type.lower()
    return lowered in {"string", "bytes", "array", "unknown"} or lowered.endswith("[]")


def _abi_packed_user_controlled_args(source_code: str, args: list[str]) -> list[str]:
    controlled: list[str] = []
    for arg in args:
        arg_name = re.sub(r"[^A-Za-z0-9_].*$", "", arg.strip())
        if not arg_name:
            continue
        if re.search(
            rf"\b(?:string|bytes(?:\d+)?|uint(?:\d+)?|int(?:\d+)?|address|bool)\s+(?:(?:calldata|memory|storage)\s+)?{re.escape(arg_name)}\b",
            source_code,
            re.IGNORECASE,
        ):
            controlled.append(arg_name)
    return _dedupe_text(controlled)


def _abi_packed_hash_usage(combined_lower: str) -> str:
    if _has_any(combined_lower, ("mapping(bytes32", "used[", "consumed[", "claimed[")):
        return "mapping_key"
    if _has_any(combined_lower, ("ecrecover", "signature", "signer", "permit", "sig")):
        return "signature_or_authorization"
    if _has_any(combined_lower, ("commit", "reveal", "nullifier", "leaf", "merkle")):
        return "commitment_or_identifier"
    if _has_any(combined_lower, ("require(", "authorized", "allow", "access")):
        return "authorization"
    return "hash_identifier"


def _abi_packed_domain_separator(combined_lower: str) -> str:
    domains: list[str] = []
    if "block.chainid" in combined_lower or "chainid()" in combined_lower:
        domains.append("chain id")
    if "address(this)" in combined_lower:
        domains.append("contract address")
    if "msg.sender" in combined_lower:
        domains.append("caller")
    return ", ".join(domains)


def _abi_packed_delimiter_guard(combined_lower: str) -> str:
    if _has_any(combined_lower, ("length", ".length", "bytes.concat", "delimiter", "separator")):
        return "explicit length or delimiter signal"
    return "none"


def _abi_packed_safer_encoding(args: list[str]) -> str:
    if args:
        return f"abi.encode({', '.join(args)})"
    return "abi.encode(...)"


def _abi_packed_surface_evidence(combined_lower: str, dynamic_count: int) -> list[str]:
    evidence = ["keccak256(abi.encodePacked(...)) is present"]
    if dynamic_count >= 2:
        evidence.append("two or more dynamic packed arguments inferred")
    if _has_any(combined_lower, ("mapping(bytes32", "used[", "consumed[")):
        evidence.append("packed hash is consumed as a bytes32 mapping key")
    if _has_any(combined_lower, ("ecrecover", "signature", "sig")):
        evidence.append("packed hash is adjacent to signature or authorization flow")
    return _dedupe_text(evidence)


def _abi_packed_hash_risks(
    combined_lower: str,
    surface: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    surface_id = _safe_metadata_text(surface.get("id")) or "abi_packed_hash_surface"
    dynamic_count = _safe_nonnegative_int_text(surface.get("dynamic_argument_count"))
    risks: list[Dict[str, Any]] = []
    if dynamic_count >= 2:
        risks.append(
            _abi_packed_hash_risk(
                "multiple_dynamic_args",
                "multiple_dynamic_args",
                surface_id,
                "high",
                "multiple dynamic arguments in abi.encodePacked can share the same packed bytes across different semantic tuples",
                "dynamic packed argument count is at least two",
                "crafted shifted dynamic boundaries must not hash to the same value",
            )
        )
    if surface.get("user_controlled_arguments"):
        risks.append(
            _abi_packed_hash_risk(
                "user_controlled_packed_args",
                "user_controlled_packed_args",
                surface_id,
                "high",
                "user-controlled packed arguments can be chosen to collide when boundaries are ambiguous",
                "function parameters feed the packed hash",
                "attacker-controlled tuple variants must not bypass uniqueness or authorization",
            )
        )
    if surface.get("hash_usage") == "mapping_key":
        risks.append(
            _abi_packed_hash_risk(
                "mapping_key_collision",
                "mapping_key_collision",
                surface_id,
                "high",
                "a colliding packed digest can reuse or block a bytes32 mapping key",
                "packed digest is used as a mapping key",
                "distinct logical claims must produce distinct mapping keys",
            )
        )
    if surface.get("hash_usage") == "signature_or_authorization" or _has_any(
        combined_lower, ("ecrecover", "signature", "sig")
    ):
        risks.append(
            _abi_packed_hash_risk(
                "signature_collision",
                "signature_collision",
                surface_id,
                "high",
                "ambiguous packed digest can authorize a different tuple than the signer intended",
                "packed digest is adjacent to signature or authorization flow",
                "signature over one tuple must not validate a shifted tuple",
            )
        )
    if _abi_packed_delimiter_guard(combined_lower) == "none":
        risks.append(
            _abi_packed_hash_risk(
                "length_prefix_absent",
                "length_prefix_absent",
                surface_id,
                "medium",
                "packed dynamic values have no visible length prefix or unambiguous delimiter",
                "no delimiter or length guard signal is present",
                "encoded tuple boundaries must be explicit",
            )
        )
    return risks[:8]


def _abi_packed_hash_risk(
    risk_id: str,
    category: str,
    surface_id: str,
    severity_hint: str,
    description: str,
    evidence: str,
    recommended_check: str,
) -> Dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "affected_surface_id": surface_id,
        "severity_hint": severity_hint,
        "description": description,
        "evidence": [evidence],
        "recommended_check": recommended_check,
    }


def _abi_packed_hash_mitigations(combined_lower: str) -> list[str]:
    mitigations = ["use abi.encode for typed tuple hashing"]
    if _abi_packed_delimiter_guard(combined_lower) == "none":
        mitigations.append("add explicit length prefixes or unambiguous delimiters")
    if not _abi_packed_domain_separator(combined_lower):
        mitigations.append("bind hash domain to contract and chain where relevant")
    mitigations.append("limit abi.encodePacked to at most one dynamic argument")
    return _dedupe_text(mitigations)


def _abi_packed_hash_validation_tests(
    risks: list[Dict[str, Any]],
    surface: Mapping[str, Any],
) -> list[str]:
    tests = [risk["recommended_check"] for risk in risks if risk.get("recommended_check")]
    args = surface.get("user_controlled_arguments")
    if isinstance(args, list) and len(args) >= 2:
        tests.append("shifted dynamic boundaries such as ('a','bc') and ('ab','c') do not collide")
    tests.append("abi.encode replacement changes digest for ambiguous dynamic tuples")
    return _dedupe_text(tests)


def _safe_nonnegative_int_text(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(value, 0)
    if not isinstance(value, str):
        return 0
    try:
        return max(int(value.strip()), 0)
    except ValueError:
        return 0


def _dedupe_text(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result[:10]


def _metamorphic_relation(
    relation_id: str,
    relation_type: str,
    baseline_sequence: list[Dict[str, Any]],
    variant_sequence: list[Dict[str, Any]],
    expected_relation: str,
    tolerance_hint: str,
    evidence: str,
) -> Dict[str, Any]:
    return {
        "id": relation_id,
        "relation_type": relation_type,
        "baseline_sequence": baseline_sequence,
        "variant_sequence": variant_sequence,
        "expected_relation": expected_relation,
        "tolerance_hint": tolerance_hint,
        "evidence": [evidence],
    }


def _input_plan_ids(task: ReasoningTask, key: str) -> list[str]:
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_items = inputs.get(key, [])
    if not isinstance(raw_items, list):
        return []
    plan_ids = []
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        plan_id = _safe_metadata_text(raw.get("id"))
        if plan_id and plan_id not in plan_ids:
            plan_ids.append(plan_id)
        if len(plan_ids) >= 10:
            break
    return plan_ids


def _capital_requirement(
    asset: str,
    amount_hint: str,
    source: str,
    purpose: str,
) -> Dict[str, Any]:
    return {
        "asset": asset,
        "amount_hint": amount_hint,
        "source": source,
        "purpose": purpose,
    }


def _asset_flow(
    asset: str,
    from_actor: str,
    to_actor: str,
    amount_hint: str,
    step_id: str,
    rationale: str,
) -> Dict[str, Any]:
    return {
        "asset": asset,
        "from_actor": from_actor,
        "to_actor": to_actor,
        "amount_hint": amount_hint,
        "step_id": step_id,
        "rationale": rationale,
    }


def _max_snapshot_count(task: ReasoningTask) -> int:
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_value = inputs.get("max_snapshots", 8)
    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        return 8
    return max(1, min(raw_value, 50))


def _snapshot_seed(
    seed_id: str,
    setup_sequence: list[Dict[str, Any]],
    target_state: str,
    priority: float,
    evidence: str,
) -> Dict[str, Any]:
    return {
        "id": seed_id,
        "setup_sequence": setup_sequence,
        "target_state": target_state,
        "priority": priority,
        "evidence": [evidence],
    }


def _fuzzing_waypoint(
    waypoint_id: str,
    kind: str,
    target: str,
    objective: str,
    distance_hint: str,
    evidence: str,
) -> Dict[str, Any]:
    return {
        "id": waypoint_id,
        "kind": kind,
        "target": target,
        "objective": objective,
        "distance_hint": distance_hint,
        "evidence": [evidence],
    }


def _limit_snapshots(seeds: list[Dict[str, Any]], max_snapshots: int) -> list[Dict[str, Any]]:
    return seeds[:max_snapshots]


def _max_semantic_graph_nodes(task: ReasoningTask) -> int:
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_value = inputs.get("max_nodes", 25)
    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        return 25
    return max(1, min(raw_value, 50))


def _pick_state_variable(source_code: str, preferred: tuple[str, ...]) -> str:
    found = _state_variables(source_code, set(preferred))
    lowered = {name.lower(): name for name in found}
    for candidate in preferred:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    return found[0] if found else ""


def _semantic_node(node_id: str, kind: str, label: str) -> Dict[str, Any]:
    node: Dict[str, Any] = {"id": node_id, "kind": kind, "label": label}
    if kind == "function":
        node["function"] = label
    return node


def _semantic_edge(
    source: str,
    target: str,
    relation: str,
    confidence: float,
    evidence: str,
) -> Dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "relation": relation,
        "confidence": confidence,
        "evidence": [evidence],
    }


def _semantic_function_node_id(function: str) -> str:
    return f"fn_{function}"


def _semantic_state_node_id(state_var: str) -> str:
    return f"state_{state_var}"


def _limit_nodes(nodes: list[Dict[str, Any]], max_nodes: int) -> list[Dict[str, Any]]:
    return nodes[:max_nodes]


def _max_sequence_steps(task: ReasoningTask) -> int:
    inputs = task.inputs if isinstance(task.inputs, Mapping) else {}
    raw_value = inputs.get("max_sequence_length", 5)
    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        return 5
    return max(1, min(raw_value, 8))


def _has_any(source_lower: str, tokens: tuple[str, ...]) -> bool:
    return any(token.lower() in source_lower for token in tokens)


def _pick_function(functions: list[str], preferred: tuple[str, ...]) -> str:
    lowered = {name.lower(): name for name in functions}
    for candidate in preferred:
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
    return functions[0] if functions else ""


def _sequence_step(
    function: str,
    actor: str,
    arguments: list[str],
    *,
    precondition: str = "",
    expected: str = "",
) -> Dict[str, Any]:
    return {
        "function": function,
        "actor": actor,
        "arguments": arguments,
        "precondition": precondition,
        "expected_effect": expected,
    }


def _limit_sequence(sequence: list[Dict[str, Any]], max_steps: int) -> list[Dict[str, Any]]:
    return sequence[:max_steps]


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
