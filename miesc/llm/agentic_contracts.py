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
    SEQUENCE_ORACLE_SYNTHESIS = "sequence_oracle_synthesis"
    SEMANTIC_GRAPH_GATING = "semantic_graph_gating"
    SNAPSHOT_FUZZING_GUIDANCE = "snapshot_fuzzing_guidance"
    ECONOMIC_ATTACK_SIMULATION = "economic_attack_simulation"
    METAMORPHIC_DIFF_TESTING = "metamorphic_diff_testing"
    UPGRADE_EVOLUTION_ANALYSIS = "upgrade_evolution_analysis"
    SIGNATURE_DOMAIN_HARDENING = "signature_domain_hardening"
    CROSS_CHAIN_MESSAGE_HARDENING = "cross_chain_message_hardening"
    DELEGATECALL_STORAGE_ALIASING = "delegatecall_storage_aliasing"
    ORACLE_FEED_HARDENING = "oracle_feed_hardening"
    ADVERSARIAL_TRANSACTION_ORDERING = "adversarial_transaction_ordering"
    RANDOMNESS_ENTROPY_HARDENING = "randomness_entropy_hardening"
    ERC4626_VAULT_INFLATION_HARDENING = "erc4626_vault_inflation_hardening"
    CREATE2_DEPLOYMENT_HARDENING = "create2_deployment_hardening"
    ABI_PACKED_HASH_COLLISION_HARDENING = "abi_packed_hash_collision_hardening"
    TOKEN_HOOK_REENTRANCY_HARDENING = "token_hook_reentrancy_hardening"
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
            "statement": _safe_text(self.statement, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
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


@dataclass(frozen=True)
class SequenceStep:
    """One transaction or setup action in a sequence-aware oracle plan."""

    function: str
    actor: str = ""
    arguments: List[str] = field(default_factory=list)
    value_hint: str = ""
    precondition: str = ""
    expected_effect: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function": _safe_label(self.function) or "unknown",
            "actor": _safe_label(self.actor) or "",
            "arguments": _safe_text_list(self.arguments),
            "value_hint": _safe_text(self.value_hint, MAX_AGENT_TEXT_CHARS) or "",
            "precondition": _safe_text(self.precondition, MAX_AGENT_TEXT_CHARS) or "",
            "expected_effect": _safe_text(self.expected_effect, MAX_AGENT_TEXT_CHARS) or "",
        }


@dataclass(frozen=True)
class SequenceOraclePlan:
    """Provider-neutral plan for validating bugs that need transaction sequences."""

    id: str
    objective: str
    invariant_id: str = ""
    vulnerability_types: List[str] = field(default_factory=list)
    sequence: List[SequenceStep] = field(default_factory=list)
    oracle: str = ""
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "invariant_id": _safe_label(self.invariant_id) or "",
            "vulnerability_types": _safe_text_list(self.vulnerability_types),
            "sequence": [step.to_dict() for step in self.sequence[:MAX_AGENT_ITEMS]],
            "oracle": _safe_text(self.oracle, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class SemanticGraphNode:
    """A bounded node in a semantic contract graph."""

    id: str
    kind: str
    label: str = ""
    contract: str = ""
    function: str = ""
    line: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "unknown",
            "kind": _safe_label(self.kind) or "unknown",
            "label": _safe_text(self.label, MAX_AGENT_TEXT_CHARS) or "",
            "contract": _safe_label(self.contract) or "",
            "function": _safe_label(self.function) or "",
            "line": _bounded_nonnegative_int(self.line, 1_000_000),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class SemanticGraphEdge:
    """A bounded relation between semantic graph nodes."""

    source: str
    target: str
    relation: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": _safe_label(self.source) or "unknown",
            "target": _safe_label(self.target) or "unknown",
            "relation": _safe_label(self.relation) or "related",
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class SemanticGraphGate:
    """Provider-neutral routing plan from semantic graph evidence."""

    id: str
    objective: str
    target_vulnerability_types: List[str] = field(default_factory=list)
    focal_nodes: List[str] = field(default_factory=list)
    nodes: List[SemanticGraphNode] = field(default_factory=list)
    edges: List[SemanticGraphEdge] = field(default_factory=list)
    graph_queries: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    rationale: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "target_vulnerability_types": _safe_text_list(self.target_vulnerability_types),
            "focal_nodes": _safe_text_list(self.focal_nodes),
            "nodes": [node.to_dict() for node in self.nodes[:MAX_AGENT_ITEMS]],
            "edges": [edge.to_dict() for edge in self.edges[:MAX_AGENT_ITEMS]],
            "graph_queries": _safe_text_list(self.graph_queries),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "rationale": _safe_text(self.rationale, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class SnapshotSeed:
    """A reusable state seed for snapshot/dataflow-guided fuzzing."""

    id: str
    setup_sequence: List[SequenceStep] = field(default_factory=list)
    target_state: str = ""
    priority: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "snapshot_seed",
            "setup_sequence": [step.to_dict() for step in self.setup_sequence[:MAX_AGENT_ITEMS]],
            "target_state": _safe_text(self.target_state, MAX_AGENT_TEXT_CHARS) or "",
            "priority": _bounded_confidence(self.priority),
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class FuzzingWaypoint:
    """A dataflow, branch, or state frontier waypoint for a fuzzing campaign."""

    id: str
    kind: str
    target: str
    objective: str = ""
    distance_hint: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "waypoint",
            "kind": _safe_label(self.kind) or "state_frontier",
            "target": _safe_text(self.target, MAX_AGENT_TEXT_CHARS) or "",
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS) or "",
            "distance_hint": _safe_text(self.distance_hint, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class SnapshotFuzzingPlan:
    """Provider-neutral plan for snapshot/dataflow-guided fuzzing."""

    id: str
    objective: str
    target_vulnerability_types: List[str] = field(default_factory=list)
    seeds: List[SnapshotSeed] = field(default_factory=list)
    waypoints: List[FuzzingWaypoint] = field(default_factory=list)
    priority_transactions: List[SequenceStep] = field(default_factory=list)
    oracle: str = ""
    recommended_tools: List[str] = field(default_factory=list)
    budget_hint: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "target_vulnerability_types": _safe_text_list(self.target_vulnerability_types),
            "seeds": [seed.to_dict() for seed in self.seeds[:MAX_AGENT_ITEMS]],
            "waypoints": [waypoint.to_dict() for waypoint in self.waypoints[:MAX_AGENT_ITEMS]],
            "priority_transactions": [
                step.to_dict() for step in self.priority_transactions[:MAX_AGENT_ITEMS]
            ],
            "oracle": _safe_text(self.oracle, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "budget_hint": _safe_text(self.budget_hint, MAX_AGENT_TEXT_CHARS) or "",
            "confidence": _bounded_confidence(self.confidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class CapitalRequirement:
    """Capital, liquidity, or borrowing requirement for an economic attack plan."""

    asset: str
    amount_hint: str
    source: str = ""
    purpose: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": _safe_label(self.asset) or "asset",
            "amount_hint": _safe_text(self.amount_hint, MAX_AGENT_TEXT_CHARS) or "",
            "source": _safe_text(self.source, MAX_AGENT_TEXT_CHARS) or "",
            "purpose": _safe_text(self.purpose, MAX_AGENT_TEXT_CHARS) or "",
        }


@dataclass(frozen=True)
class AssetFlow:
    """One asset movement in a profit-driven DeFi hypothesis."""

    asset: str
    from_actor: str
    to_actor: str
    amount_hint: str = ""
    step_id: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": _safe_label(self.asset) or "asset",
            "from_actor": _safe_label(self.from_actor) or "unknown",
            "to_actor": _safe_label(self.to_actor) or "unknown",
            "amount_hint": _safe_text(self.amount_hint, MAX_AGENT_TEXT_CHARS) or "",
            "step_id": _safe_label(self.step_id) or "",
            "rationale": _safe_text(self.rationale, MAX_AGENT_TEXT_CHARS) or "",
        }


@dataclass(frozen=True)
class EconomicAttackPlan:
    """Provider-neutral plan for validating DeFi economic exploitability."""

    id: str
    objective: str
    target_vulnerability_types: List[str] = field(default_factory=list)
    base_sequence_plan_ids: List[str] = field(default_factory=list)
    base_snapshot_plan_ids: List[str] = field(default_factory=list)
    base_graph_gate_ids: List[str] = field(default_factory=list)
    capital_requirements: List[CapitalRequirement] = field(default_factory=list)
    asset_flows: List[AssetFlow] = field(default_factory=list)
    profit_formula: str = ""
    cost_model: str = ""
    liquidity_assumptions: List[str] = field(default_factory=list)
    oracle_price_assumptions: List[str] = field(default_factory=list)
    break_even_threshold: str = ""
    expected_profit_range: str = ""
    risk_factors: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "target_vulnerability_types": _safe_text_list(self.target_vulnerability_types),
            "base_sequence_plan_ids": _safe_text_list(self.base_sequence_plan_ids),
            "base_snapshot_plan_ids": _safe_text_list(self.base_snapshot_plan_ids),
            "base_graph_gate_ids": _safe_text_list(self.base_graph_gate_ids),
            "capital_requirements": [
                item.to_dict() for item in self.capital_requirements[:MAX_AGENT_ITEMS]
            ],
            "asset_flows": [flow.to_dict() for flow in self.asset_flows[:MAX_AGENT_ITEMS]],
            "profit_formula": _safe_text(
                self.profit_formula, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "cost_model": _safe_text(self.cost_model, MAX_AGENT_TEXT_CHARS) or "",
            "liquidity_assumptions": _safe_text_list(self.liquidity_assumptions),
            "oracle_price_assumptions": _safe_text_list(self.oracle_price_assumptions),
            "break_even_threshold": _safe_text(self.break_even_threshold, MAX_AGENT_TEXT_CHARS)
            or "",
            "expected_profit_range": _safe_text(self.expected_profit_range, MAX_AGENT_TEXT_CHARS)
            or "",
            "risk_factors": _safe_text_list(self.risk_factors),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class MetamorphicRelation:
    """A relation between baseline and variant executions that should hold."""

    id: str
    relation_type: str
    baseline_sequence: List[SequenceStep] = field(default_factory=list)
    variant_sequence: List[SequenceStep] = field(default_factory=list)
    expected_relation: str = ""
    tolerance_hint: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "metamorphic_relation",
            "relation_type": _safe_label(self.relation_type) or "equivalence",
            "baseline_sequence": [
                step.to_dict() for step in self.baseline_sequence[:MAX_AGENT_ITEMS]
            ],
            "variant_sequence": [
                step.to_dict() for step in self.variant_sequence[:MAX_AGENT_ITEMS]
            ],
            "expected_relation": _safe_text(
                self.expected_relation, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "tolerance_hint": _safe_text(self.tolerance_hint, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class DifferentialTestPlan:
    """Provider-neutral metamorphic/differential testing plan."""

    id: str
    objective: str
    target_vulnerability_types: List[str] = field(default_factory=list)
    relations: List[MetamorphicRelation] = field(default_factory=list)
    state_observables: List[str] = field(default_factory=list)
    oracle: str = ""
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "target_vulnerability_types": _safe_text_list(self.target_vulnerability_types),
            "relations": [relation.to_dict() for relation in self.relations[:MAX_AGENT_ITEMS]],
            "state_observables": _safe_text_list(self.state_observables),
            "oracle": _safe_text(self.oracle, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class StorageLayoutChange:
    """A storage-layout delta that may affect an upgradeable proxy."""

    slot: str
    before: str = ""
    after: str = ""
    change_type: str = ""
    risk: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot": _safe_label(self.slot) or "unknown",
            "before": _safe_text(self.before, MAX_AGENT_TEXT_CHARS) or "",
            "after": _safe_text(self.after, MAX_AGENT_TEXT_CHARS) or "",
            "change_type": _safe_label(self.change_type) or "unknown",
            "risk": _safe_text(self.risk, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class UpgradeRisk:
    """A concrete risk introduced or exposed by a proxy upgrade path."""

    id: str
    category: str
    affected_component: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "upgrade_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_component": _safe_text(self.affected_component, MAX_AGENT_TEXT_CHARS) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class UpgradeEvolutionPlan:
    """Provider-neutral plan for upgradeable proxy evolution analysis."""

    id: str
    objective: str
    proxy_pattern: str = ""
    old_implementation: str = ""
    new_implementation: str = ""
    storage_changes: List[StorageLayoutChange] = field(default_factory=list)
    risks: List[UpgradeRisk] = field(default_factory=list)
    migration_checks: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "proxy_pattern": _safe_label(self.proxy_pattern) or "",
            "old_implementation": _safe_text(self.old_implementation, MAX_AGENT_TEXT_CHARS) or "",
            "new_implementation": _safe_text(self.new_implementation, MAX_AGENT_TEXT_CHARS) or "",
            "storage_changes": [
                change.to_dict() for change in self.storage_changes[:MAX_AGENT_ITEMS]
            ],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "migration_checks": _safe_text_list(self.migration_checks),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class SignedAction:
    """A contract action authorized by an off-chain or contract signature."""

    id: str
    function: str
    signer_source: str = ""
    digest_scheme: str = ""
    domain_fields: List[str] = field(default_factory=list)
    nonce_source: str = ""
    deadline_source: str = ""
    value_scope: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "signed_action",
            "function": _safe_label(self.function) or "unknown",
            "signer_source": _safe_text(self.signer_source, MAX_AGENT_TEXT_CHARS) or "",
            "digest_scheme": _safe_label(self.digest_scheme) or "",
            "domain_fields": _safe_text_list(self.domain_fields),
            "nonce_source": _safe_text(self.nonce_source, MAX_AGENT_TEXT_CHARS) or "",
            "deadline_source": _safe_text(self.deadline_source, MAX_AGENT_TEXT_CHARS) or "",
            "value_scope": _safe_text_list(self.value_scope),
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class SignatureDomainRisk:
    """A replay, domain, or signature-verification weakness hypothesis."""

    id: str
    category: str
    affected_action_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "signature_domain_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_action_id": _safe_label(self.affected_action_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class SignatureDomainHardeningPlan:
    """Provider-neutral plan for signed authorization domain hardening."""

    id: str
    objective: str
    signed_actions: List[SignedAction] = field(default_factory=list)
    risks: List[SignatureDomainRisk] = field(default_factory=list)
    replay_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "signed_actions": [
                action.to_dict() for action in self.signed_actions[:MAX_AGENT_ITEMS]
            ],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "replay_tests": _safe_text_list(self.replay_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class CrossChainMessageFlow:
    """A cross-chain message path or bridge handler to harden."""

    id: str
    handler_function: str
    source_domain: str = ""
    destination_domain: str = ""
    trusted_sender_source: str = ""
    message_id_source: str = ""
    replay_guard: str = ""
    finality_assumption: str = ""
    payload_scope: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "cross_chain_message",
            "handler_function": _safe_label(self.handler_function) or "unknown",
            "source_domain": _safe_text(self.source_domain, MAX_AGENT_TEXT_CHARS) or "",
            "destination_domain": _safe_text(self.destination_domain, MAX_AGENT_TEXT_CHARS) or "",
            "trusted_sender_source": _safe_text(self.trusted_sender_source, MAX_AGENT_TEXT_CHARS)
            or "",
            "message_id_source": _safe_text(self.message_id_source, MAX_AGENT_TEXT_CHARS) or "",
            "replay_guard": _safe_text(self.replay_guard, MAX_AGENT_TEXT_CHARS) or "",
            "finality_assumption": _safe_text(self.finality_assumption, MAX_AGENT_TEXT_CHARS) or "",
            "payload_scope": _safe_text_list(self.payload_scope),
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class CrossChainMessageRisk:
    """A cross-chain message validation or replay weakness hypothesis."""

    id: str
    category: str
    affected_flow_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "cross_chain_message_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_flow_id": _safe_label(self.affected_flow_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class CrossChainMessageHardeningPlan:
    """Provider-neutral plan for bridge and cross-chain message hardening."""

    id: str
    objective: str
    message_flows: List[CrossChainMessageFlow] = field(default_factory=list)
    risks: List[CrossChainMessageRisk] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "message_flows": [flow.to_dict() for flow in self.message_flows[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class DelegatecallSurface:
    """A delegatecall entry point and its target-selection evidence."""

    id: str
    caller_function: str
    target_source: str = ""
    selector_source: str = ""
    target_trust_boundary: str = ""
    guard_summary: str = ""
    value_forwarding: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "delegatecall_surface",
            "caller_function": _safe_label(self.caller_function) or "unknown",
            "target_source": _safe_text(self.target_source, MAX_AGENT_TEXT_CHARS) or "",
            "selector_source": _safe_text(self.selector_source, MAX_AGENT_TEXT_CHARS) or "",
            "target_trust_boundary": _safe_text(self.target_trust_boundary, MAX_AGENT_TEXT_CHARS)
            or "",
            "guard_summary": _safe_text(self.guard_summary, MAX_AGENT_TEXT_CHARS) or "",
            "value_forwarding": _safe_text(self.value_forwarding, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class StorageAliasPath:
    """A read/write path where delegatecall may reinterpret caller storage."""

    id: str
    delegatecall_surface_id: str
    caller_slot: str = ""
    callee_slot: str = ""
    caller_semantics: str = ""
    callee_semantics: str = ""
    write_source: str = ""
    path_condition: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "storage_alias_path",
            "delegatecall_surface_id": _safe_label(self.delegatecall_surface_id) or "",
            "caller_slot": _safe_text(self.caller_slot, MAX_AGENT_TEXT_CHARS) or "",
            "callee_slot": _safe_text(self.callee_slot, MAX_AGENT_TEXT_CHARS) or "",
            "caller_semantics": _safe_text(self.caller_semantics, MAX_AGENT_TEXT_CHARS) or "",
            "callee_semantics": _safe_text(self.callee_semantics, MAX_AGENT_TEXT_CHARS) or "",
            "write_source": _safe_text(self.write_source, MAX_AGENT_TEXT_CHARS) or "",
            "path_condition": _safe_text(
                self.path_condition, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class DelegatecallAliasRisk:
    """A delegatecall storage-aliasing or callee-control weakness hypothesis."""

    id: str
    category: str
    affected_surface_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "delegatecall_alias_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_surface_id": _safe_label(self.affected_surface_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class DelegatecallStorageAliasingPlan:
    """Provider-neutral plan for delegatecall storage aliasing analysis."""

    id: str
    objective: str
    delegatecall_surfaces: List[DelegatecallSurface] = field(default_factory=list)
    storage_alias_paths: List[StorageAliasPath] = field(default_factory=list)
    risks: List[DelegatecallAliasRisk] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "delegatecall_surfaces": [
                surface.to_dict() for surface in self.delegatecall_surfaces[:MAX_AGENT_ITEMS]
            ],
            "storage_alias_paths": [
                path.to_dict() for path in self.storage_alias_paths[:MAX_AGENT_ITEMS]
            ],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class OracleFeedSource:
    """An external oracle or price feed consumed by contract logic."""

    id: str
    consumer_function: str
    feed_kind: str = ""
    source_contract: str = ""
    read_method: str = ""
    freshness_source: str = ""
    staleness_threshold: str = ""
    decimals_source: str = ""
    normalization: str = ""
    fallback_source: str = ""
    sequencer_guard: str = ""
    bounds_check: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "oracle_feed",
            "consumer_function": _safe_label(self.consumer_function) or "unknown",
            "feed_kind": _safe_label(self.feed_kind) or "",
            "source_contract": _safe_text(self.source_contract, MAX_AGENT_TEXT_CHARS) or "",
            "read_method": _safe_label(self.read_method) or "",
            "freshness_source": _safe_text(self.freshness_source, MAX_AGENT_TEXT_CHARS) or "",
            "staleness_threshold": _safe_text(self.staleness_threshold, MAX_AGENT_TEXT_CHARS) or "",
            "decimals_source": _safe_text(self.decimals_source, MAX_AGENT_TEXT_CHARS) or "",
            "normalization": _safe_text(self.normalization, MAX_AGENT_TEXT_CHARS) or "",
            "fallback_source": _safe_text(self.fallback_source, MAX_AGENT_TEXT_CHARS) or "",
            "sequencer_guard": _safe_text(self.sequencer_guard, MAX_AGENT_TEXT_CHARS) or "",
            "bounds_check": _safe_text(self.bounds_check, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class OracleFeedRisk:
    """A stale, incomplete, or unsafe oracle-consumption weakness hypothesis."""

    id: str
    category: str
    affected_feed_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "oracle_feed_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_feed_id": _safe_label(self.affected_feed_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class OracleFeedHardeningPlan:
    """Provider-neutral plan for oracle feed validation and hardening."""

    id: str
    objective: str
    feeds: List[OracleFeedSource] = field(default_factory=list)
    risks: List[OracleFeedRisk] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "feeds": [feed.to_dict() for feed in self.feeds[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class OrderingTransaction:
    """One actor transaction in an adversarial ordering scenario."""

    id: str
    role: str
    function: str
    actor: str = ""
    position: str = ""
    value_hint: str = ""
    state_dependency: str = ""
    slippage_or_limit: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "ordering_transaction",
            "role": _safe_label(self.role) or "unknown",
            "function": _safe_label(self.function) or "unknown",
            "actor": _safe_label(self.actor) or "",
            "position": _safe_label(self.position) or "",
            "value_hint": _safe_text(self.value_hint, MAX_AGENT_TEXT_CHARS) or "",
            "state_dependency": _safe_text(self.state_dependency, MAX_AGENT_TEXT_CHARS) or "",
            "slippage_or_limit": _safe_text(self.slippage_or_limit, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class OrderingRisk:
    """A transaction-ordering, front-run, back-run, or sandwich risk hypothesis."""

    id: str
    category: str
    affected_transaction_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "ordering_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_transaction_id": _safe_label(self.affected_transaction_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class AdversarialOrderingPlan:
    """Provider-neutral plan for transaction-ordering and MEV validation."""

    id: str
    objective: str
    ordering_pattern: str = ""
    transactions: List[OrderingTransaction] = field(default_factory=list)
    risks: List[OrderingRisk] = field(default_factory=list)
    oracle: str = ""
    mitigations: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "ordering_pattern": _safe_label(self.ordering_pattern) or "",
            "transactions": [tx.to_dict() for tx in self.transactions[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "oracle": _safe_text(self.oracle, MAX_AGENT_TEXT_CHARS, allow_multiline=True) or "",
            "mitigations": _safe_text_list(self.mitigations),
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class RandomnessSource:
    """A randomness or entropy source consumed by contract logic."""

    id: str
    consumer_function: str
    source_kind: str = ""
    source_expression: str = ""
    entropy_scope: str = ""
    commit_phase: str = ""
    reveal_phase: str = ""
    request_id_source: str = ""
    fulfillment_guard: str = ""
    confirmation_depth: str = ""
    modulo_bias_guard: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "randomness_source",
            "consumer_function": _safe_label(self.consumer_function) or "unknown",
            "source_kind": _safe_label(self.source_kind) or "",
            "source_expression": _safe_text(self.source_expression, MAX_AGENT_TEXT_CHARS) or "",
            "entropy_scope": _safe_text(self.entropy_scope, MAX_AGENT_TEXT_CHARS) or "",
            "commit_phase": _safe_text(self.commit_phase, MAX_AGENT_TEXT_CHARS) or "",
            "reveal_phase": _safe_text(self.reveal_phase, MAX_AGENT_TEXT_CHARS) or "",
            "request_id_source": _safe_text(self.request_id_source, MAX_AGENT_TEXT_CHARS) or "",
            "fulfillment_guard": _safe_text(self.fulfillment_guard, MAX_AGENT_TEXT_CHARS) or "",
            "confirmation_depth": _safe_text(self.confirmation_depth, MAX_AGENT_TEXT_CHARS) or "",
            "modulo_bias_guard": _safe_text(self.modulo_bias_guard, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class RandomnessRisk:
    """A weak randomness, entropy lifecycle, or VRF integration risk hypothesis."""

    id: str
    category: str
    affected_source_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "randomness_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_source_id": _safe_label(self.affected_source_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class RandomnessEntropyHardeningPlan:
    """Provider-neutral plan for randomness and entropy-source validation."""

    id: str
    objective: str
    sources: List[RandomnessSource] = field(default_factory=list)
    risks: List[RandomnessRisk] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "sources": [source.to_dict() for source in self.sources[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class VaultShareSurface:
    """An ERC4626 or vault share-accounting surface consumed by depositors."""

    id: str
    vault_function: str
    asset_function: str = ""
    share_function: str = ""
    total_assets_source: str = ""
    total_supply_source: str = ""
    conversion_formula: str = ""
    rounding_direction: str = ""
    empty_vault_behavior: str = ""
    donation_exposure: str = ""
    mitigation: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "vault_share_surface",
            "vault_function": _safe_label(self.vault_function) or "unknown",
            "asset_function": _safe_label(self.asset_function) or "",
            "share_function": _safe_label(self.share_function) or "",
            "total_assets_source": _safe_text(self.total_assets_source, MAX_AGENT_TEXT_CHARS) or "",
            "total_supply_source": _safe_text(self.total_supply_source, MAX_AGENT_TEXT_CHARS) or "",
            "conversion_formula": _safe_text(self.conversion_formula, MAX_AGENT_TEXT_CHARS) or "",
            "rounding_direction": _safe_label(self.rounding_direction) or "",
            "empty_vault_behavior": _safe_text(self.empty_vault_behavior, MAX_AGENT_TEXT_CHARS)
            or "",
            "donation_exposure": _safe_text(self.donation_exposure, MAX_AGENT_TEXT_CHARS) or "",
            "mitigation": _safe_text(self.mitigation, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class VaultInflationRisk:
    """A vault share inflation, donation, rounding, or accounting risk hypothesis."""

    id: str
    category: str
    affected_surface_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "vault_inflation_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_surface_id": _safe_label(self.affected_surface_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class ERC4626VaultInflationHardeningPlan:
    """Provider-neutral plan for ERC4626 vault inflation and share-math validation."""

    id: str
    objective: str
    surfaces: List[VaultShareSurface] = field(default_factory=list)
    risks: List[VaultInflationRisk] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surfaces": [surface.to_dict() for surface in self.surfaces[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "mitigations": _safe_text_list(self.mitigations),
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class Create2DeploymentSurface:
    """A deterministic deployment surface that uses CREATE2 or precomputed addresses."""

    id: str
    deploy_function: str
    factory_contract: str = ""
    salt_source: str = ""
    init_code_source: str = ""
    address_formula: str = ""
    authorization_guard: str = ""
    collision_check: str = ""
    post_deploy_check: str = ""
    redeploy_assumption: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "create2_deployment_surface",
            "deploy_function": _safe_label(self.deploy_function) or "unknown",
            "factory_contract": _safe_label(self.factory_contract) or "",
            "salt_source": _safe_text(self.salt_source, MAX_AGENT_TEXT_CHARS) or "",
            "init_code_source": _safe_text(self.init_code_source, MAX_AGENT_TEXT_CHARS) or "",
            "address_formula": _safe_text(self.address_formula, MAX_AGENT_TEXT_CHARS) or "",
            "authorization_guard": _safe_text(self.authorization_guard, MAX_AGENT_TEXT_CHARS) or "",
            "collision_check": _safe_text(self.collision_check, MAX_AGENT_TEXT_CHARS) or "",
            "post_deploy_check": _safe_text(self.post_deploy_check, MAX_AGENT_TEXT_CHARS) or "",
            "redeploy_assumption": _safe_text(self.redeploy_assumption, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class Create2DeploymentRisk:
    """A CREATE2 salt, init-code, collision, or deterministic-address risk hypothesis."""

    id: str
    category: str
    affected_surface_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "create2_deployment_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_surface_id": _safe_label(self.affected_surface_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class Create2DeploymentHardeningPlan:
    """Provider-neutral plan for CREATE2 deterministic deployment validation."""

    id: str
    objective: str
    surfaces: List[Create2DeploymentSurface] = field(default_factory=list)
    risks: List[Create2DeploymentRisk] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surfaces": [surface.to_dict() for surface in self.surfaces[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "mitigations": _safe_text_list(self.mitigations),
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class AbiPackedHashSurface:
    """A packed ABI hash surface that may produce ambiguous encodings."""

    id: str
    hash_function: str
    packed_expression: str = ""
    argument_types: List[str] = field(default_factory=list)
    dynamic_argument_count: str = ""
    user_controlled_arguments: List[str] = field(default_factory=list)
    hash_usage: str = ""
    domain_separator: str = ""
    delimiter_or_length_guard: str = ""
    safer_encoding: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "abi_packed_hash_surface",
            "hash_function": _safe_label(self.hash_function) or "unknown",
            "packed_expression": _safe_text(self.packed_expression, MAX_AGENT_TEXT_CHARS) or "",
            "argument_types": _safe_text_list(self.argument_types),
            "dynamic_argument_count": _safe_text(self.dynamic_argument_count, MAX_AGENT_TEXT_CHARS)
            or "",
            "user_controlled_arguments": _safe_text_list(self.user_controlled_arguments),
            "hash_usage": _safe_text(self.hash_usage, MAX_AGENT_TEXT_CHARS) or "",
            "domain_separator": _safe_text(self.domain_separator, MAX_AGENT_TEXT_CHARS) or "",
            "delimiter_or_length_guard": _safe_text(
                self.delimiter_or_length_guard, MAX_AGENT_TEXT_CHARS
            )
            or "",
            "safer_encoding": _safe_text(self.safer_encoding, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class AbiPackedHashRisk:
    """A hash-collision, ambiguous encoding, or packed-domain weakness hypothesis."""

    id: str
    category: str
    affected_surface_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "abi_packed_hash_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_surface_id": _safe_label(self.affected_surface_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class AbiPackedHashCollisionHardeningPlan:
    """Provider-neutral plan for ABI packed hash collision validation."""

    id: str
    objective: str
    surfaces: List[AbiPackedHashSurface] = field(default_factory=list)
    risks: List[AbiPackedHashRisk] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surfaces": [surface.to_dict() for surface in self.surfaces[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "mitigations": _safe_text_list(self.mitigations),
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
        }


@dataclass(frozen=True)
class TokenHookSurface:
    """A token callback or hook surface that can reenter protocol accounting."""

    id: str
    entrypoint: str
    token_standard: str = ""
    hook_function: str = ""
    external_token_call: str = ""
    state_update_order: str = ""
    accounting_fields: List[str] = field(default_factory=list)
    expected_callback_sender: str = ""
    guard: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "token_hook_surface",
            "entrypoint": _safe_label(self.entrypoint) or "unknown",
            "token_standard": _safe_label(self.token_standard) or "",
            "hook_function": _safe_label(self.hook_function) or "",
            "external_token_call": _safe_text(self.external_token_call, MAX_AGENT_TEXT_CHARS) or "",
            "state_update_order": _safe_text(self.state_update_order, MAX_AGENT_TEXT_CHARS) or "",
            "accounting_fields": _safe_text_list(self.accounting_fields),
            "expected_callback_sender": _safe_text(
                self.expected_callback_sender, MAX_AGENT_TEXT_CHARS
            )
            or "",
            "guard": _safe_text(self.guard, MAX_AGENT_TEXT_CHARS) or "",
            "evidence": _safe_text_list(self.evidence),
        }


@dataclass(frozen=True)
class TokenHookReentrancyRisk:
    """A hook-driven reentrancy or callback-authentication weakness hypothesis."""

    id: str
    category: str
    affected_surface_id: str = ""
    severity_hint: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_check: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or "token_hook_reentrancy_risk",
            "category": _safe_label(self.category) or "unknown",
            "affected_surface_id": _safe_label(self.affected_surface_id) or "",
            "severity_hint": _safe_label(self.severity_hint) or "",
            "description": _safe_text(self.description, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "evidence": _safe_text_list(self.evidence),
            "recommended_check": _safe_text(
                self.recommended_check, MAX_AGENT_TEXT_CHARS, allow_multiline=True
            )
            or "",
        }


@dataclass(frozen=True)
class TokenHookReentrancyHardeningPlan:
    """Provider-neutral plan for ERC-777/ERC-1363 hook reentrancy validation."""

    id: str
    objective: str
    surfaces: List[TokenHookSurface] = field(default_factory=list)
    risks: List[TokenHookReentrancyRisk] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": _safe_label(self.id) or _derive_invariant_id(self.objective),
            "objective": _safe_text(self.objective, MAX_AGENT_TEXT_CHARS, allow_multiline=True)
            or "",
            "surfaces": [surface.to_dict() for surface in self.surfaces[:MAX_AGENT_ITEMS]],
            "risks": [risk.to_dict() for risk in self.risks[:MAX_AGENT_ITEMS]],
            "mitigations": _safe_text_list(self.mitigations),
            "validation_tests": _safe_text_list(self.validation_tests),
            "recommended_tools": _safe_text_list(self.recommended_tools),
            "confidence": _bounded_confidence(self.confidence),
            "evidence": _safe_text_list(self.evidence),
            "metadata": _json_safe_mapping(self.metadata),
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


class SequenceOracleAgent:
    """Synthesizes transaction-sequence oracle plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        invariants: Optional[List[InvariantCandidate]] = None,
        max_sequence_length: int = 5,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_invariants = [item.to_dict() for item in (invariants or [])[:25]]
        bounded_sequence_length = _bounded_nonnegative_int(max_sequence_length, 8)
        prompt = _sequence_oracle_prompt(
            safe_source,
            safe_findings,
            safe_invariants,
            bounded_sequence_length,
        )
        return ReasoningTask(
            capability=AgentCapability.SEQUENCE_ORACLE_SYNTHESIS,
            objective=(
                "Synthesize sequence-aware oracle plans for stateful smart-contract "
                "vulnerability validation."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "invariants": safe_invariants,
                "max_sequence_length": bounded_sequence_length,
            },
            output_schema={
                "sequence_oracle_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "bug hypothesis to validate",
                        "invariant_id": "related invariant id",
                        "vulnerability_types": ["oracle_manipulation"],
                        "sequence": [
                            {
                                "function": "deposit",
                                "actor": "attacker|victim|owner|liquidator|any",
                                "arguments": ["amount"],
                                "value_hint": "msg.value hint",
                                "precondition": "state requirement before call",
                                "expected_effect": "state change after call",
                            }
                        ],
                        "oracle": "condition that indicates failure",
                        "recommended_tools": ["foundry", "echidna", "halmos"],
                        "confidence": 0.0,
                        "evidence": ["specific code signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def synthesize(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        invariants: Optional[List[InvariantCandidate]] = None,
        max_sequence_length: int = 5,
    ) -> List[SequenceOraclePlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            invariants=invariants,
            max_sequence_length=max_sequence_length,
        )
        result = self.provider.complete_json(task)
        return parse_sequence_oracle_plans(result.data)


class SemanticGraphGateAgent:
    """Builds semantic graph gating plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        ir_summary: Optional[Mapping[str, Any]] = None,
        max_nodes: int = 25,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_ir_summary = _json_safe_mapping(ir_summary or {})
        bounded_max_nodes = _bounded_nonnegative_int(max_nodes, 100)
        prompt = _semantic_graph_gate_prompt(
            safe_source,
            safe_findings,
            safe_ir_summary,
            bounded_max_nodes,
        )
        return ReasoningTask(
            capability=AgentCapability.SEMANTIC_GRAPH_GATING,
            objective=(
                "Build semantic graph gating plans that prioritize focal code regions "
                "and downstream analysis tools."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "ir_summary": safe_ir_summary,
                "max_nodes": bounded_max_nodes,
            },
            output_schema={
                "semantic_graph_gates": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "analysis goal",
                        "target_vulnerability_types": ["access_control"],
                        "focal_nodes": ["fn_withdraw"],
                        "nodes": [
                            {
                                "id": "fn_withdraw",
                                "kind": "function|state_var|modifier|external_call|event|role",
                                "label": "withdraw(uint256)",
                                "contract": "Vault",
                                "function": "withdraw",
                                "line": 42,
                                "metadata": {},
                            }
                        ],
                        "edges": [
                            {
                                "source": "fn_withdraw",
                                "target": "state_balances",
                                "relation": "writes|reads|calls|guards|authorizes|emits",
                                "confidence": 0.0,
                                "evidence": ["code signal"],
                            }
                        ],
                        "graph_queries": ["MATCH privileged function without guard"],
                        "recommended_tools": ["slither", "mythril", "halmos", "foundry"],
                        "confidence": 0.0,
                        "rationale": "why this graph focus matters",
                    }
                ]
            },
            policy=self.policy,
        )

    def build_gate(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        ir_summary: Optional[Mapping[str, Any]] = None,
        max_nodes: int = 25,
    ) -> List[SemanticGraphGate]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            ir_summary=ir_summary,
            max_nodes=max_nodes,
        )
        result = self.provider.complete_json(task)
        return parse_semantic_graph_gates(result.data)


class SnapshotFuzzingAgent:
    """Builds snapshot/dataflow-guided fuzzing plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        graph_gates: Optional[List[SemanticGraphGate]] = None,
        max_snapshots: int = 8,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_sequences = [item.to_dict() for item in (sequence_plans or [])[:25]]
        safe_gates = [item.to_dict() for item in (graph_gates or [])[:25]]
        bounded_snapshots = _bounded_nonnegative_int(max_snapshots, 50)
        prompt = _snapshot_fuzzing_prompt(
            safe_source,
            safe_findings,
            safe_sequences,
            safe_gates,
            bounded_snapshots,
        )
        return ReasoningTask(
            capability=AgentCapability.SNAPSHOT_FUZZING_GUIDANCE,
            objective=(
                "Build snapshot and dataflow-guided fuzzing plans for stateful "
                "smart-contract vulnerability discovery."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "sequence_plans": safe_sequences,
                "graph_gates": safe_gates,
                "max_snapshots": bounded_snapshots,
            },
            output_schema={
                "snapshot_fuzzing_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "campaign goal",
                        "target_vulnerability_types": ["oracle_manipulation"],
                        "seeds": [
                            {
                                "id": "seed_after_liquidity",
                                "setup_sequence": [],
                                "target_state": "state to snapshot and reuse",
                                "priority": 0.0,
                                "evidence": ["code signal"],
                            }
                        ],
                        "waypoints": [
                            {
                                "id": "branch_health_factor_lt_one",
                                "kind": "branch|dataflow|state_frontier|oracle",
                                "target": "symbol or predicate",
                                "objective": "why this frontier matters",
                                "distance_hint": "comparison or data dependency hint",
                                "evidence": ["code signal"],
                            }
                        ],
                        "priority_transactions": [],
                        "oracle": "condition that indicates failure",
                        "recommended_tools": ["foundry", "echidna", "ityfuzz"],
                        "budget_hint": "bounded run guidance",
                        "confidence": 0.0,
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        graph_gates: Optional[List[SemanticGraphGate]] = None,
        max_snapshots: int = 8,
    ) -> List[SnapshotFuzzingPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            sequence_plans=sequence_plans,
            graph_gates=graph_gates,
            max_snapshots=max_snapshots,
        )
        result = self.provider.complete_json(task)
        return parse_snapshot_fuzzing_plans(result.data)


class EconomicAttackSimulationAgent:
    """Builds DeFi economic exploitability plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        snapshot_plans: Optional[List[SnapshotFuzzingPlan]] = None,
        graph_gates: Optional[List[SemanticGraphGate]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_sequences = [item.to_dict() for item in (sequence_plans or [])[:25]]
        safe_snapshots = [item.to_dict() for item in (snapshot_plans or [])[:25]]
        safe_gates = [item.to_dict() for item in (graph_gates or [])[:25]]
        prompt = _economic_attack_prompt(
            safe_source, safe_findings, safe_sequences, safe_snapshots, safe_gates
        )
        return ReasoningTask(
            capability=AgentCapability.ECONOMIC_ATTACK_SIMULATION,
            objective=(
                "Build provider-neutral economic attack simulation plans for DeFi "
                "exploitability validation."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "sequence_plans": safe_sequences,
                "snapshot_plans": safe_snapshots,
                "graph_gates": safe_gates,
            },
            output_schema={
                "economic_attack_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "economic exploit hypothesis",
                        "target_vulnerability_types": ["oracle_manipulation"],
                        "base_sequence_plan_ids": ["sequence_id"],
                        "base_snapshot_plan_ids": ["snapshot_id"],
                        "base_graph_gate_ids": ["graph_gate_id"],
                        "capital_requirements": [
                            {
                                "asset": "USDC",
                                "amount_hint": "flash-loan amount or range",
                                "source": "flash_loan|attacker_capital|existing_liquidity",
                                "purpose": "why this capital is needed",
                            }
                        ],
                        "asset_flows": [
                            {
                                "asset": "USDC",
                                "from_actor": "flash_pool",
                                "to_actor": "attacker",
                                "amount_hint": "principal",
                                "step_id": "borrow_flash",
                                "rationale": "fund manipulation leg",
                            }
                        ],
                        "profit_formula": "gross proceeds - principal - fees - gas - slippage",
                        "cost_model": "gas, protocol fees, flash-loan premium, swap fees",
                        "liquidity_assumptions": ["pool depth and slippage assumptions"],
                        "oracle_price_assumptions": ["spot/TWAP/staleness assumptions"],
                        "break_even_threshold": "minimum exploitable delta",
                        "expected_profit_range": "bounded qualitative or numeric range",
                        "risk_factors": ["assumptions that may invalidate exploitability"],
                        "recommended_tools": ["foundry", "anvil", "fork-simulation"],
                        "confidence": 0.0,
                        "evidence": ["specific code or plan signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        snapshot_plans: Optional[List[SnapshotFuzzingPlan]] = None,
        graph_gates: Optional[List[SemanticGraphGate]] = None,
    ) -> List[EconomicAttackPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            sequence_plans=sequence_plans,
            snapshot_plans=snapshot_plans,
            graph_gates=graph_gates,
        )
        result = self.provider.complete_json(task)
        return parse_economic_attack_plans(result.data)


class MetamorphicDiffTestingAgent:
    """Builds metamorphic/differential test plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        invariants: Optional[List[InvariantCandidate]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        snapshot_plans: Optional[List[SnapshotFuzzingPlan]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_invariants = [item.to_dict() for item in (invariants or [])[:25]]
        safe_sequences = [item.to_dict() for item in (sequence_plans or [])[:25]]
        safe_snapshots = [item.to_dict() for item in (snapshot_plans or [])[:25]]
        prompt = _metamorphic_diff_prompt(
            safe_source,
            safe_findings,
            safe_invariants,
            safe_sequences,
            safe_snapshots,
        )
        return ReasoningTask(
            capability=AgentCapability.METAMORPHIC_DIFF_TESTING,
            objective=(
                "Build provider-neutral metamorphic and differential testing plans "
                "for Solidity vulnerability discovery."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "invariants": safe_invariants,
                "sequence_plans": safe_sequences,
                "snapshot_plans": safe_snapshots,
            },
            output_schema={
                "differential_test_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "metamorphic or differential hypothesis",
                        "target_vulnerability_types": ["accounting_drift"],
                        "relations": [
                            {
                                "id": "split_merge_deposit",
                                "relation_type": "equivalence|inverse|commutative|idempotent|round_trip|split_merge|monotonic|conservation",
                                "baseline_sequence": [],
                                "variant_sequence": [],
                                "expected_relation": "observable balances and shares match within tolerance",
                                "tolerance_hint": "rounding tolerance, if any",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "state_observables": ["balanceOf(user)", "totalSupply()"],
                        "oracle": "relation violation condition",
                        "recommended_tools": ["foundry", "echidna", "halmos"],
                        "confidence": 0.0,
                        "evidence": ["specific code or plan signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        invariants: Optional[List[InvariantCandidate]] = None,
        sequence_plans: Optional[List[SequenceOraclePlan]] = None,
        snapshot_plans: Optional[List[SnapshotFuzzingPlan]] = None,
    ) -> List[DifferentialTestPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            invariants=invariants,
            sequence_plans=sequence_plans,
            snapshot_plans=snapshot_plans,
        )
        result = self.provider.complete_json(task)
        return parse_differential_test_plans(result.data)


class UpgradeEvolutionAnalysisAgent:
    """Builds upgradeable proxy evolution analysis plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        old_source_code: str,
        new_source_code: str,
        *,
        proxy_source_code: str = "",
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        storage_layout_before: Optional[Mapping[str, Any]] = None,
        storage_layout_after: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_old_source = _bounded_source(old_source_code, self.policy.max_source_chars)
        safe_new_source = _bounded_source(new_source_code, self.policy.max_source_chars)
        safe_proxy_source = _bounded_source(proxy_source_code, self.policy.max_source_chars // 3)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_layout_before = _json_safe_mapping(storage_layout_before or {})
        safe_layout_after = _json_safe_mapping(storage_layout_after or {})
        prompt = _upgrade_evolution_prompt(
            safe_old_source,
            safe_new_source,
            safe_proxy_source,
            safe_findings,
            safe_layout_before,
            safe_layout_after,
        )
        return ReasoningTask(
            capability=AgentCapability.UPGRADE_EVOLUTION_ANALYSIS,
            objective=(
                "Build provider-neutral upgrade evolution analysis plans for "
                "proxy-based Solidity contracts."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "old_source_chars": len(safe_old_source),
                "new_source_chars": len(safe_new_source),
                "proxy_source_chars": len(safe_proxy_source),
                "findings": safe_findings,
                "storage_layout_before": safe_layout_before,
                "storage_layout_after": safe_layout_after,
            },
            output_schema={
                "upgrade_evolution_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "upgrade risk hypothesis",
                        "proxy_pattern": "transparent|uups|beacon|custom|unknown",
                        "old_implementation": "ImplementationV1",
                        "new_implementation": "ImplementationV2",
                        "storage_changes": [
                            {
                                "slot": "0",
                                "before": "address owner",
                                "after": "bool openForSale",
                                "change_type": "type_change|insert_before_existing|delete|rename|gap_change",
                                "risk": "storage collision or semantic corruption risk",
                                "evidence": ["specific layout signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "unprotected_reinitializer",
                                "category": "storage_layout|initializer|admin|selector_collision|delegatecall|migration",
                                "affected_component": "initializeV2",
                                "severity_hint": "high|medium|low",
                                "description": "why the upgrade transition is risky",
                                "evidence": ["specific code or layout signal"],
                                "recommended_check": "test or static check to validate",
                            }
                        ],
                        "migration_checks": ["dry-run upgrade preserves owner and balances"],
                        "recommended_tools": ["openzeppelin-upgrades", "slither", "foundry"],
                        "confidence": 0.0,
                        "evidence": ["specific diff signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        old_source_code: str,
        new_source_code: str,
        *,
        proxy_source_code: str = "",
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        storage_layout_before: Optional[Mapping[str, Any]] = None,
        storage_layout_after: Optional[Mapping[str, Any]] = None,
    ) -> List[UpgradeEvolutionPlan]:
        task = self.build_task(
            old_source_code,
            new_source_code,
            proxy_source_code=proxy_source_code,
            contract_path=contract_path,
            findings=findings,
            storage_layout_before=storage_layout_before,
            storage_layout_after=storage_layout_after,
        )
        result = self.provider.complete_json(task)
        return parse_upgrade_evolution_plans(result.data)


class SignatureDomainHardeningAgent:
    """Builds signed-authorization hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        abi_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_abi_summary = _json_safe_mapping(abi_summary or {})
        prompt = _signature_domain_prompt(safe_source, safe_findings, safe_abi_summary)
        return ReasoningTask(
            capability=AgentCapability.SIGNATURE_DOMAIN_HARDENING,
            objective=(
                "Build provider-neutral signature-domain hardening plans for "
                "Solidity signed authorization flows."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "abi_summary": safe_abi_summary,
            },
            output_schema={
                "signature_domain_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "signed authorization hardening goal",
                        "signed_actions": [
                            {
                                "id": "permit_owner_spender_value",
                                "function": "permit",
                                "signer_source": "owner recovered by ECDSA or ERC-1271",
                                "digest_scheme": "eip712|eth_sign|raw_hash|erc1271|unknown",
                                "domain_fields": [
                                    "name",
                                    "version",
                                    "chainId",
                                    "verifyingContract",
                                ],
                                "nonce_source": "nonces[owner] consumed on success",
                                "deadline_source": "deadline checked against block.timestamp",
                                "value_scope": ["owner", "spender", "value"],
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "missing_chain_id",
                                "category": "domain_separator|nonce|deadline|signer_binding|malleability|erc1271|cross_chain_replay|permit_integration",
                                "affected_action_id": "permit_owner_spender_value",
                                "severity_hint": "high|medium|low",
                                "description": "why replay or misuse is plausible",
                                "evidence": ["specific code signal"],
                                "recommended_check": "test replay across chainId or contract address",
                            }
                        ],
                        "replay_tests": ["reuse the same signature after nonce consumption"],
                        "recommended_tools": ["foundry", "echidna", "slither"],
                        "confidence": 0.0,
                        "evidence": ["specific signature signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        abi_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[SignatureDomainHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            abi_summary=abi_summary,
        )
        result = self.provider.complete_json(task)
        return parse_signature_domain_hardening_plans(result.data)


class CrossChainMessageHardeningAgent:
    """Builds cross-chain message hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        bridge_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_bridge_summary = _json_safe_mapping(bridge_summary or {})
        prompt = _cross_chain_message_prompt(safe_source, safe_findings, safe_bridge_summary)
        return ReasoningTask(
            capability=AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING,
            objective=(
                "Build provider-neutral cross-chain message hardening plans for "
                "bridge, L2 messenger, inbox, outbox, and endpoint handlers."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "bridge_summary": safe_bridge_summary,
            },
            output_schema={
                "cross_chain_message_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "cross-chain message hardening goal",
                        "message_flows": [
                            {
                                "id": "l2_receive_message",
                                "handler_function": "receiveMessage",
                                "source_domain": "source chain or domain id",
                                "destination_domain": "destination chain or domain id",
                                "trusted_sender_source": "trusted remote app or messenger lookup",
                                "message_id_source": "message hash, nonce, packet id, or event id",
                                "replay_guard": "processedMessages[messageId]",
                                "finality_assumption": "proof/root/finality/delay requirement",
                                "payload_scope": ["token", "amount", "recipient"],
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "missing_source_sender_check",
                                "category": "source_domain|trusted_sender|message_id|replay_guard|finality|payload_scope|ordering|value_consistency|sender_aliasing",
                                "affected_flow_id": "l2_receive_message",
                                "severity_hint": "high|medium|low",
                                "description": "why unauthorized or replayed message execution is plausible",
                                "evidence": ["specific code signal"],
                                "recommended_check": "replay same message id or spoof source sender",
                            }
                        ],
                        "validation_tests": ["replay consumed message id must revert"],
                        "recommended_tools": ["foundry", "bridgefuzz", "slither"],
                        "confidence": 0.0,
                        "evidence": ["specific bridge message signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        bridge_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[CrossChainMessageHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            bridge_summary=bridge_summary,
        )
        result = self.provider.complete_json(task)
        return parse_cross_chain_message_hardening_plans(result.data)


class DelegatecallStorageAliasingAgent:
    """Builds delegatecall storage-aliasing plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        layout_summary: Optional[Mapping[str, Any]] = None,
        callee_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_layout_summary = _json_safe_mapping(layout_summary or {})
        safe_callee_summary = _json_safe_mapping(callee_summary or {})
        prompt = _delegatecall_storage_aliasing_prompt(
            safe_source,
            safe_findings,
            safe_layout_summary,
            safe_callee_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.DELEGATECALL_STORAGE_ALIASING,
            objective=(
                "Build provider-neutral delegatecall storage-aliasing plans for "
                "Solidity delegatecall targets, slot semantics, and attack paths."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "layout_summary": safe_layout_summary,
                "callee_summary": safe_callee_summary,
            },
            output_schema={
                "delegatecall_storage_aliasing_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "delegatecall storage aliasing validation goal",
                        "delegatecall_surfaces": [
                            {
                                "id": "fallback_delegatecall",
                                "caller_function": "fallback",
                                "target_source": "implementation address slot or user argument",
                                "selector_source": "msg.data selector forwarded to callee",
                                "target_trust_boundary": "owner-controlled|user-controlled|registry|immutable",
                                "guard_summary": "whitelist, access control, codehash, or none",
                                "value_forwarding": "msg.value preserved by delegatecall",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "storage_alias_paths": [
                            {
                                "id": "owner_slot_collision",
                                "delegatecall_surface_id": "fallback_delegatecall",
                                "caller_slot": "slot 0 owner",
                                "callee_slot": "slot 0 initialized",
                                "caller_semantics": "owner address",
                                "callee_semantics": "initializer boolean or attacker-controlled owner",
                                "write_source": "callee function writes slot 0",
                                "path_condition": "attacker can select callee and function selector",
                                "evidence": ["specific storage or write signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "user_controlled_delegate_target",
                                "category": "target_control|selector_control|storage_collision|slot_semantics|callee_write|initializer_takeover|selfdestruct|value_context|access_context",
                                "affected_surface_id": "fallback_delegatecall",
                                "severity_hint": "high|medium|low",
                                "description": "why caller storage can be corrupted or privileges can change",
                                "evidence": ["specific code signal"],
                                "recommended_check": "prove a callee write reaches caller owner/admin slot",
                            }
                        ],
                        "validation_tests": ["deploy malicious callee that writes caller slot 0"],
                        "recommended_tools": ["foundry", "slither", "symbolic execution"],
                        "confidence": 0.0,
                        "evidence": ["specific delegatecall signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        layout_summary: Optional[Mapping[str, Any]] = None,
        callee_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[DelegatecallStorageAliasingPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            layout_summary=layout_summary,
            callee_summary=callee_summary,
        )
        result = self.provider.complete_json(task)
        return parse_delegatecall_storage_aliasing_plans(result.data)


class OracleFeedHardeningAgent:
    """Builds oracle feed hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        oracle_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_oracle_summary = _json_safe_mapping(oracle_summary or {})
        prompt = _oracle_feed_hardening_prompt(
            safe_source,
            safe_findings,
            safe_oracle_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.ORACLE_FEED_HARDENING,
            objective=(
                "Build provider-neutral oracle feed hardening plans for Solidity "
                "price feeds, TWAPs, fallbacks, and L2 sequencer guards."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "oracle_summary": safe_oracle_summary,
            },
            output_schema={
                "oracle_feed_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "oracle feed hardening goal",
                        "feeds": [
                            {
                                "id": "eth_usd_feed",
                                "consumer_function": "getPrice",
                                "feed_kind": "chainlink|twap|manual|fallback|multi_source|unknown",
                                "source_contract": "AggregatorV3Interface feed address",
                                "read_method": "latestRoundData",
                                "freshness_source": "updatedAt",
                                "staleness_threshold": "maxDelay or heartbeat",
                                "decimals_source": "decimals()",
                                "normalization": "scale to 1e18",
                                "fallback_source": "secondary feed or none",
                                "sequencer_guard": "L2 sequencer uptime feed plus grace period",
                                "bounds_check": "price > 0 and deviation <= maxDeviation",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "stale_price",
                                "category": "stale_round|incomplete_round|decimals_mismatch|zero_negative_price|missing_bounds|sequencer_down|fallback_trust|manual_override|multi_source_deviation",
                                "affected_feed_id": "eth_usd_feed",
                                "severity_hint": "high|medium|low",
                                "description": "why unsafe oracle consumption is plausible",
                                "evidence": ["specific code signal"],
                                "recommended_check": "updatedAt older than threshold must revert",
                            }
                        ],
                        "validation_tests": ["stale updatedAt must revert"],
                        "recommended_tools": ["foundry", "slither", "symbolic execution"],
                        "confidence": 0.0,
                        "evidence": ["specific oracle signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        oracle_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[OracleFeedHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            oracle_summary=oracle_summary,
        )
        result = self.provider.complete_json(task)
        return parse_oracle_feed_hardening_plans(result.data)


class AdversarialTransactionOrderingAgent:
    """Builds transaction-ordering and MEV validation plans through a provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        market_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_market_summary = _json_safe_mapping(market_summary or {})
        prompt = _adversarial_transaction_ordering_prompt(
            safe_source,
            safe_findings,
            safe_market_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING,
            objective=(
                "Build provider-neutral adversarial transaction-ordering plans for "
                "front-running, back-running, sandwich, and liquidation ordering risks."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "market_summary": safe_market_summary,
            },
            output_schema={
                "adversarial_ordering_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "ordering validation goal",
                        "ordering_pattern": "front_run|back_run|sandwich|liquidation_race|permit_nonce_dos|commit_reveal|auction_reorder|unknown",
                        "transactions": [
                            {
                                "id": "victim_swap",
                                "role": "victim|attacker_front|attacker_back|liquidator|keeper|settler",
                                "function": "swapExactTokensForTokens",
                                "actor": "user",
                                "position": "before_victim|victim|after_victim|same_block",
                                "value_hint": "amountIn or debt amount",
                                "state_dependency": "pool reserves or oracle state",
                                "slippage_or_limit": "minOut, deadline, maxPrice, or none",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "missing_min_out",
                                "category": "front_run|back_run|sandwich|transaction_order_dependence|slippage_gap|deadline_gap|commit_reveal_gap|liquidation_race|permit_nonce_dos",
                                "affected_transaction_id": "victim_swap",
                                "severity_hint": "high|medium|low",
                                "description": "why ordering can change the victim outcome",
                                "evidence": ["specific code signal"],
                                "recommended_check": "front-run reserve change makes victim execution worse",
                            }
                        ],
                        "oracle": "victim receives less than min safe amount or attacker captures ordering edge",
                        "mitigations": ["minOut", "deadline", "commit-reveal", "private routing"],
                        "validation_tests": ["attacker front-run before victim worsens execution"],
                        "recommended_tools": ["foundry", "mev simulation", "sequence oracle"],
                        "confidence": 0.0,
                        "evidence": ["specific ordering signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        market_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[AdversarialOrderingPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            market_summary=market_summary,
        )
        result = self.provider.complete_json(task)
        return parse_adversarial_transaction_ordering_plans(result.data)


class RandomnessEntropyHardeningAgent:
    """Builds randomness and entropy hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        randomness_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_randomness_summary = _json_safe_mapping(randomness_summary or {})
        prompt = _randomness_entropy_hardening_prompt(
            safe_source,
            safe_findings,
            safe_randomness_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.RANDOMNESS_ENTROPY_HARDENING,
            objective=(
                "Build provider-neutral randomness and entropy hardening plans for "
                "Solidity weak sources, commit-reveal flows, and VRF integrations."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "randomness_summary": safe_randomness_summary,
            },
            output_schema={
                "randomness_entropy_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "randomness hardening goal",
                        "sources": [
                            {
                                "id": "winner_entropy",
                                "consumer_function": "drawWinner",
                                "source_kind": "blockhash|timestamp|prevrandao|commit_reveal|vrf|oracle|user_seed|unknown",
                                "source_expression": "keccak256(block.timestamp, msg.sender)",
                                "entropy_scope": "lottery winner selection",
                                "commit_phase": "commit hash with salt",
                                "reveal_phase": "reveal after commit deadline",
                                "request_id_source": "VRF requestId",
                                "fulfillment_guard": "only coordinator and requestId match",
                                "confirmation_depth": "request confirmations",
                                "modulo_bias_guard": "rejection sampling or bounded mapping",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "timestamp_randomness",
                                "category": "weak_source|prevrandao_bias|blockhash_expiry|timestamp_bias|commit_reveal_gap|vrf_request_mismatch|vrf_callback_auth|modulo_bias|reorg_bias|replay",
                                "affected_source_id": "winner_entropy",
                                "severity_hint": "high|medium|low",
                                "description": "why randomness can be predicted, biased, or replayed",
                                "evidence": ["specific code signal"],
                                "recommended_check": "validator-controlled timestamp changes selected winner",
                            }
                        ],
                        "validation_tests": ["same seed with manipulated timestamp changes winner"],
                        "recommended_tools": ["foundry", "echidna", "symbolic execution"],
                        "confidence": 0.0,
                        "evidence": ["specific randomness signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        randomness_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[RandomnessEntropyHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            randomness_summary=randomness_summary,
        )
        result = self.provider.complete_json(task)
        return parse_randomness_entropy_hardening_plans(result.data)


class ERC4626VaultInflationHardeningAgent:
    """Builds ERC4626 vault inflation hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        vault_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_vault_summary = _json_safe_mapping(vault_summary or {})
        prompt = _erc4626_vault_inflation_hardening_prompt(
            safe_source,
            safe_findings,
            safe_vault_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.ERC4626_VAULT_INFLATION_HARDENING,
            objective=(
                "Build provider-neutral ERC4626 vault inflation hardening plans for "
                "share accounting, direct donations, low-supply rounding, and preview functions."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "vault_summary": safe_vault_summary,
            },
            output_schema={
                "erc4626_vault_inflation_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "vault inflation hardening goal",
                        "surfaces": [
                            {
                                "id": "deposit_share_math",
                                "vault_function": "deposit",
                                "asset_function": "totalAssets",
                                "share_function": "convertToShares",
                                "total_assets_source": "asset.balanceOf(address(this))",
                                "total_supply_source": "totalSupply()",
                                "conversion_formula": "assets * totalSupply / totalAssets",
                                "rounding_direction": "down|up|mixed|unknown",
                                "empty_vault_behavior": "assets minted 1:1",
                                "donation_exposure": "direct transfer changes assets without shares",
                                "mitigation": "virtual shares, dead shares, internal accounting, or min shares",
                                "evidence": ["specific code signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "first_deposit_donation",
                                "category": "first_depositor|direct_donation|zero_share_mint|rounding_loss|raw_balance_total_assets|missing_min_shares|missing_virtual_offset|preview_mismatch|internal_accounting_gap",
                                "affected_surface_id": "deposit_share_math",
                                "severity_hint": "high|medium|low",
                                "description": "why deposits can mint too few or zero shares",
                                "evidence": ["specific code signal"],
                                "recommended_check": "attacker deposit, donate, victim deposit mints zero shares",
                            }
                        ],
                        "mitigations": ["virtual shares", "virtual assets", "dead shares"],
                        "validation_tests": [
                            "first depositor donation cannot force zero victim shares"
                        ],
                        "recommended_tools": ["foundry", "echidna", "symbolic execution"],
                        "confidence": 0.0,
                        "evidence": ["specific vault signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        vault_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[ERC4626VaultInflationHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            vault_summary=vault_summary,
        )
        result = self.provider.complete_json(task)
        return parse_erc4626_vault_inflation_hardening_plans(result.data)


class Create2DeploymentHardeningAgent:
    """Builds CREATE2 deployment hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        deployment_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_deployment_summary = _json_safe_mapping(deployment_summary or {})
        prompt = _create2_deployment_hardening_prompt(
            safe_source,
            safe_findings,
            safe_deployment_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.CREATE2_DEPLOYMENT_HARDENING,
            objective=(
                "Build provider-neutral CREATE2 deployment hardening plans for "
                "deterministic addresses, salt binding, init-code binding, and deployment races."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "deployment_summary": safe_deployment_summary,
            },
            output_schema={
                "create2_deployment_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "CREATE2 deployment hardening goal",
                        "surfaces": [
                            {
                                "id": "factory_deploy",
                                "deploy_function": "deploy",
                                "factory_contract": "WalletFactory",
                                "salt_source": "user supplied salt",
                                "init_code_source": "abi.encodePacked(type(Wallet).creationCode, owner)",
                                "address_formula": "keccak256(0xff, factory, salt, init_code_hash)",
                                "authorization_guard": "salt includes msg.sender or owner",
                                "collision_check": "predicted.code.length == 0 before deploy",
                                "post_deploy_check": "deployed address and codehash verified",
                                "redeploy_assumption": "no selfdestruct/redeploy trust",
                                "evidence": ["specific CREATE2 signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "salt_squatting",
                                "category": "predictable_salt|salt_squatting|front_run_deploy|init_code_mismatch|missing_codehash_check|address_poisoning|factory_auth_gap|counterfactual_funding|metamorphic_redeploy|cross_chain_replay",
                                "affected_surface_id": "factory_deploy",
                                "severity_hint": "high|medium|low",
                                "description": "why a deterministic deployment can be hijacked or mis-bound",
                                "evidence": ["specific code signal"],
                                "recommended_check": "attacker uses same salt before victim deploy",
                            }
                        ],
                        "mitigations": [
                            "bind salt to owner",
                            "verify init code hash",
                            "check deployed codehash",
                        ],
                        "validation_tests": [
                            "front-run with same salt cannot capture expected address"
                        ],
                        "recommended_tools": ["foundry", "slither", "fork simulation"],
                        "confidence": 0.0,
                        "evidence": ["specific deterministic deployment signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        deployment_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[Create2DeploymentHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            deployment_summary=deployment_summary,
        )
        result = self.provider.complete_json(task)
        return parse_create2_deployment_hardening_plans(result.data)


class AbiPackedHashCollisionHardeningAgent:
    """Builds ABI packed hash collision hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        hash_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_hash_summary = _json_safe_mapping(hash_summary or {})
        prompt = _abi_packed_hash_collision_hardening_prompt(
            safe_source,
            safe_findings,
            safe_hash_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.ABI_PACKED_HASH_COLLISION_HARDENING,
            objective=(
                "Build provider-neutral ABI packed hash collision hardening plans for "
                "keccak256(abi.encodePacked(...)) authorization, signatures, and mapping keys."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "hash_summary": safe_hash_summary,
            },
            output_schema={
                "abi_packed_hash_collision_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "ABI packed hash collision hardening goal",
                        "surfaces": [
                            {
                                "id": "claim_hash",
                                "hash_function": "claim",
                                "packed_expression": "keccak256(abi.encodePacked(a, b))",
                                "argument_types": ["string", "string"],
                                "dynamic_argument_count": "2",
                                "user_controlled_arguments": ["a", "b"],
                                "hash_usage": "signature|mapping_key|authorization|commitment|message_id|identifier",
                                "domain_separator": "chainId or contract address binding",
                                "delimiter_or_length_guard": "none",
                                "safer_encoding": "abi.encode(a, b)",
                                "evidence": ["specific packed hash signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "dynamic_packed_collision",
                                "category": "multiple_dynamic_args|user_controlled_packed_args|signature_collision|mapping_key_collision|auth_bypass|domain_collision|delimiter_absent|length_prefix_absent",
                                "affected_surface_id": "claim_hash",
                                "severity_hint": "high|medium|low",
                                "description": "why different semantic inputs can hash to the same value",
                                "evidence": ["specific code signal"],
                                "recommended_check": "('a','bc') and ('ab','c') collide",
                            }
                        ],
                        "mitigations": ["use abi.encode", "add length prefixes", "bind domain"],
                        "validation_tests": ["crafted dynamic inputs cannot collide"],
                        "recommended_tools": ["foundry", "slither", "property testing"],
                        "confidence": 0.0,
                        "evidence": ["specific packed hash signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        hash_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[AbiPackedHashCollisionHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            hash_summary=hash_summary,
        )
        result = self.provider.complete_json(task)
        return parse_abi_packed_hash_collision_hardening_plans(result.data)


class TokenHookReentrancyHardeningAgent:
    """Builds token hook reentrancy hardening plans through a replaceable provider."""

    def __init__(self, provider: ReasoningProvider, policy: Optional[DPGAgentConfig] = None):
        self.provider = provider
        self.policy = policy or DPGAgentConfig()

    def build_task(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        token_summary: Optional[Mapping[str, Any]] = None,
    ) -> ReasoningTask:
        safe_source = _bounded_source(source_code, self.policy.max_source_chars)
        safe_findings = _json_safe_list(findings or [], max_items=25)
        safe_token_summary = _json_safe_mapping(token_summary or {})
        prompt = _token_hook_reentrancy_hardening_prompt(
            safe_source,
            safe_findings,
            safe_token_summary,
        )
        return ReasoningTask(
            capability=AgentCapability.TOKEN_HOOK_REENTRANCY_HARDENING,
            objective=(
                "Build provider-neutral token hook reentrancy hardening plans for "
                "ERC-777/ERC-1363 callbacks around protocol accounting."
            ),
            prompt=prompt,
            inputs={
                "contract_path": _safe_text(contract_path or "", MAX_AGENT_TEXT_CHARS),
                "source_chars": len(safe_source),
                "findings": safe_findings,
                "token_summary": safe_token_summary,
            },
            output_schema={
                "token_hook_reentrancy_hardening_plans": [
                    {
                        "id": "short_stable_identifier",
                        "objective": "token hook reentrancy hardening goal",
                        "surfaces": [
                            {
                                "id": "deposit_hook_surface",
                                "entrypoint": "deposit",
                                "token_standard": "ERC777|ERC1363|ERC1820",
                                "hook_function": "tokensReceived|tokensToSend|onTransferReceived|onApprovalReceived",
                                "external_token_call": "token.transferFrom(...)",
                                "state_update_order": "external token call before balance update",
                                "accounting_fields": ["balances", "totalSupply"],
                                "expected_callback_sender": "trusted token contract",
                                "guard": "nonReentrant or CEI",
                                "evidence": ["specific hook and accounting signal"],
                            }
                        ],
                        "risks": [
                            {
                                "id": "hook_before_effects",
                                "category": "hook_before_effects|callback_sender_unchecked|cross_function_reentry|read_only_reentry|erc1820_registry_confusion|erc1363_callback_reentry",
                                "affected_surface_id": "deposit_hook_surface",
                                "severity_hint": "high|medium|low",
                                "description": "why token callback can reenter before accounting is final",
                                "evidence": ["specific code signal"],
                                "recommended_check": "malicious token hook reenters before balances update",
                            }
                        ],
                        "mitigations": [
                            "checks-effects-interactions",
                            "nonReentrant",
                            "validate callback sender",
                        ],
                        "validation_tests": [
                            "malicious ERC777/ERC1363 hook cannot reenter accounting"
                        ],
                        "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
                        "confidence": 0.0,
                        "evidence": ["specific hook signal"],
                    }
                ]
            },
            policy=self.policy,
        )

    def plan(
        self,
        source_code: str,
        *,
        contract_path: Optional[str] = None,
        findings: Optional[List[Mapping[str, Any]]] = None,
        token_summary: Optional[Mapping[str, Any]] = None,
    ) -> List[TokenHookReentrancyHardeningPlan]:
        task = self.build_task(
            source_code,
            contract_path=contract_path,
            findings=findings,
            token_summary=token_summary,
        )
        result = self.provider.complete_json(task)
        return parse_token_hook_reentrancy_hardening_plans(result.data)


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


def parse_sequence_oracle_plans(data: Any) -> List[SequenceOraclePlan]:
    """Parse provider output into bounded sequence-aware oracle plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get("sequence_oracle_plans", data.get("plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[SequenceOraclePlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue

        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        oracle = _safe_text(raw.get("oracle"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective or not oracle:
            continue

        raw_steps = raw.get("sequence", [])
        steps: List[SequenceStep] = []
        if isinstance(raw_steps, list):
            for raw_step in raw_steps[:MAX_AGENT_ITEMS]:
                if not isinstance(raw_step, Mapping):
                    continue
                function = _safe_label(raw_step.get("function"))
                if not function:
                    continue
                steps.append(
                    SequenceStep(
                        function=function,
                        actor=_safe_label(raw_step.get("actor")) or "",
                        arguments=_safe_text_list(raw_step.get("arguments")),
                        value_hint=_safe_text(raw_step.get("value_hint"), MAX_AGENT_TEXT_CHARS)
                        or "",
                        precondition=_safe_text(raw_step.get("precondition"), MAX_AGENT_TEXT_CHARS)
                        or "",
                        expected_effect=_safe_text(
                            raw_step.get("expected_effect"), MAX_AGENT_TEXT_CHARS
                        )
                        or "",
                    )
                )
        if not steps:
            continue

        plan_id = _safe_label(raw.get("id")) or _derive_invariant_id(objective)
        plans.append(
            SequenceOraclePlan(
                id=plan_id,
                objective=objective,
                invariant_id=_safe_label(raw.get("invariant_id")) or "",
                vulnerability_types=_safe_text_list(raw.get("vulnerability_types")),
                sequence=steps,
                oracle=oracle,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )

    return plans


def parse_semantic_graph_gates(data: Any) -> List[SemanticGraphGate]:
    """Parse provider output into bounded semantic graph gating plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get("semantic_graph_gates", data.get("graph_gates", []))
    if not isinstance(raw_items, list):
        return []

    gates: List[SemanticGraphGate] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not objective:
            continue

        nodes = _parse_semantic_graph_nodes(raw.get("nodes"))
        edges = _parse_semantic_graph_edges(raw.get("edges"))
        focal_nodes = _safe_text_list(raw.get("focal_nodes"))
        if not nodes and not edges and not focal_nodes:
            continue

        gates.append(
            SemanticGraphGate(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                target_vulnerability_types=_safe_text_list(raw.get("target_vulnerability_types")),
                focal_nodes=focal_nodes,
                nodes=nodes,
                edges=edges,
                graph_queries=_safe_text_list(raw.get("graph_queries")),
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                rationale=_safe_text(raw.get("rationale"), MAX_AGENT_TEXT_CHARS) or "",
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )

    return gates


def parse_snapshot_fuzzing_plans(data: Any) -> List[SnapshotFuzzingPlan]:
    """Parse provider output into bounded snapshot fuzzing campaign plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get("snapshot_fuzzing_plans", data.get("snapshot_campaigns", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[SnapshotFuzzingPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        oracle = _safe_text(raw.get("oracle"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        seeds = _parse_snapshot_seeds(raw.get("seeds"))
        waypoints = _parse_fuzzing_waypoints(raw.get("waypoints"))
        priority_transactions = _parse_sequence_steps(raw.get("priority_transactions"))
        if not objective or not oracle:
            continue
        if not seeds and not waypoints and not priority_transactions:
            continue
        plans.append(
            SnapshotFuzzingPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                target_vulnerability_types=_safe_text_list(raw.get("target_vulnerability_types")),
                seeds=seeds,
                waypoints=waypoints,
                priority_transactions=priority_transactions,
                oracle=oracle,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                budget_hint=_safe_text(raw.get("budget_hint"), MAX_AGENT_TEXT_CHARS) or "",
                confidence=_bounded_confidence(raw.get("confidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_economic_attack_plans(data: Any) -> List[EconomicAttackPlan]:
    """Parse provider output into bounded DeFi economic attack plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get("economic_attack_plans", data.get("economic_simulation_plans", []))
    if not isinstance(raw_items, list):
        return []

    plans: List[EconomicAttackPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        profit_formula = _safe_text(
            raw.get("profit_formula"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
        )
        capital_requirements = _parse_capital_requirements(raw.get("capital_requirements"))
        asset_flows = _parse_asset_flows(raw.get("asset_flows"))
        liquidity_assumptions = _safe_text_list(raw.get("liquidity_assumptions"))
        oracle_price_assumptions = _safe_text_list(raw.get("oracle_price_assumptions"))
        if not objective or not profit_formula:
            continue
        if not capital_requirements and not asset_flows and not liquidity_assumptions:
            continue
        plans.append(
            EconomicAttackPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                target_vulnerability_types=_safe_text_list(raw.get("target_vulnerability_types")),
                base_sequence_plan_ids=_safe_text_list(raw.get("base_sequence_plan_ids")),
                base_snapshot_plan_ids=_safe_text_list(raw.get("base_snapshot_plan_ids")),
                base_graph_gate_ids=_safe_text_list(raw.get("base_graph_gate_ids")),
                capital_requirements=capital_requirements,
                asset_flows=asset_flows,
                profit_formula=profit_formula,
                cost_model=_safe_text(raw.get("cost_model"), MAX_AGENT_TEXT_CHARS) or "",
                liquidity_assumptions=liquidity_assumptions,
                oracle_price_assumptions=oracle_price_assumptions,
                break_even_threshold=_safe_text(
                    raw.get("break_even_threshold"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                expected_profit_range=_safe_text(
                    raw.get("expected_profit_range"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                risk_factors=_safe_text_list(raw.get("risk_factors")),
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_differential_test_plans(data: Any) -> List[DifferentialTestPlan]:
    """Parse provider output into bounded metamorphic/differential test plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "differential_test_plans",
        data.get("metamorphic_test_plans", data.get("metamorphic_diff_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[DifferentialTestPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        oracle = _safe_text(raw.get("oracle"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        relations = _parse_metamorphic_relations(raw.get("relations"))
        if not objective or not oracle or not relations:
            continue
        plans.append(
            DifferentialTestPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                target_vulnerability_types=_safe_text_list(raw.get("target_vulnerability_types")),
                relations=relations,
                state_observables=_safe_text_list(raw.get("state_observables")),
                oracle=oracle,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_upgrade_evolution_plans(data: Any) -> List[UpgradeEvolutionPlan]:
    """Parse provider output into bounded upgrade-evolution analysis plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "upgrade_evolution_plans",
        data.get("upgrade_analysis_plans", data.get("proxy_upgrade_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[UpgradeEvolutionPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        storage_changes = _parse_storage_layout_changes(raw.get("storage_changes"))
        risks = _parse_upgrade_risks(raw.get("risks"))
        migration_checks = _safe_text_list(raw.get("migration_checks"))
        if not objective:
            continue
        if not storage_changes and not risks and not migration_checks:
            continue
        plans.append(
            UpgradeEvolutionPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                proxy_pattern=_safe_label(raw.get("proxy_pattern")) or "",
                old_implementation=_safe_text(raw.get("old_implementation"), MAX_AGENT_TEXT_CHARS)
                or "",
                new_implementation=_safe_text(raw.get("new_implementation"), MAX_AGENT_TEXT_CHARS)
                or "",
                storage_changes=storage_changes,
                risks=risks,
                migration_checks=migration_checks,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_signature_domain_hardening_plans(data: Any) -> List[SignatureDomainHardeningPlan]:
    """Parse provider output into bounded signature-domain hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "signature_domain_hardening_plans",
        data.get("signature_domain_plans", data.get("signed_authorization_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[SignatureDomainHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        signed_actions = _parse_signed_actions(raw.get("signed_actions"))
        risks = _parse_signature_domain_risks(raw.get("risks"))
        replay_tests = _safe_text_list(raw.get("replay_tests"))
        if not objective:
            continue
        if not signed_actions and not risks and not replay_tests:
            continue
        plans.append(
            SignatureDomainHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                signed_actions=signed_actions,
                risks=risks,
                replay_tests=replay_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_cross_chain_message_hardening_plans(data: Any) -> List[CrossChainMessageHardeningPlan]:
    """Parse provider output into bounded cross-chain message hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "cross_chain_message_hardening_plans",
        data.get("bridge_message_hardening_plans", data.get("cross_chain_validation_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[CrossChainMessageHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        message_flows = _parse_cross_chain_message_flows(raw.get("message_flows"))
        risks = _parse_cross_chain_message_risks(raw.get("risks"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not message_flows and not risks and not validation_tests:
            continue
        plans.append(
            CrossChainMessageHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                message_flows=message_flows,
                risks=risks,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_delegatecall_storage_aliasing_plans(
    data: Any,
) -> List[DelegatecallStorageAliasingPlan]:
    """Parse provider output into bounded delegatecall storage-aliasing plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "delegatecall_storage_aliasing_plans",
        data.get("delegatecall_aliasing_plans", data.get("storage_collision_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[DelegatecallStorageAliasingPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        surfaces = _parse_delegatecall_surfaces(raw.get("delegatecall_surfaces"))
        alias_paths = _parse_storage_alias_paths(raw.get("storage_alias_paths"))
        risks = _parse_delegatecall_alias_risks(raw.get("risks"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not surfaces and not alias_paths and not risks and not validation_tests:
            continue
        plans.append(
            DelegatecallStorageAliasingPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                delegatecall_surfaces=surfaces,
                storage_alias_paths=alias_paths,
                risks=risks,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_oracle_feed_hardening_plans(data: Any) -> List[OracleFeedHardeningPlan]:
    """Parse provider output into bounded oracle feed hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "oracle_feed_hardening_plans",
        data.get("oracle_source_hardening_plans", data.get("price_feed_validation_plans", [])),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[OracleFeedHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        feeds = _parse_oracle_feed_sources(raw.get("feeds"))
        risks = _parse_oracle_feed_risks(raw.get("risks"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not feeds and not risks and not validation_tests:
            continue
        plans.append(
            OracleFeedHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                feeds=feeds,
                risks=risks,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_adversarial_transaction_ordering_plans(
    data: Any,
) -> List[AdversarialOrderingPlan]:
    """Parse provider output into bounded adversarial transaction-ordering plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "adversarial_ordering_plans",
        data.get(
            "adversarial_transaction_ordering_plans",
            data.get("transaction_ordering_plans", data.get("mev_oracle_plans", [])),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[AdversarialOrderingPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        transactions = _parse_ordering_transactions(raw.get("transactions"))
        risks = _parse_ordering_risks(raw.get("risks"))
        oracle = _safe_text(raw.get("oracle"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not transactions and not risks and not oracle and not validation_tests:
            continue
        plans.append(
            AdversarialOrderingPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                ordering_pattern=_safe_label(raw.get("ordering_pattern")) or "",
                transactions=transactions,
                risks=risks,
                oracle=oracle or "",
                mitigations=_safe_text_list(raw.get("mitigations")),
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def parse_randomness_entropy_hardening_plans(
    data: Any,
) -> List[RandomnessEntropyHardeningPlan]:
    """Parse provider output into bounded randomness entropy hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "randomness_entropy_hardening_plans",
        data.get(
            "randomness_hardening_plans",
            data.get(
                "entropy_source_hardening_plans",
                data.get("entropy_validation_plans", data.get("randomness_validation_plans", [])),
            ),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[RandomnessEntropyHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        sources = _parse_randomness_sources(raw.get("sources"))
        risks = _parse_randomness_risks(raw.get("risks"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not sources and not risks and not validation_tests:
            continue
        plans.append(
            RandomnessEntropyHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                sources=sources,
                risks=risks,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def _parse_randomness_sources(value: Any) -> List[RandomnessSource]:
    if not isinstance(value, list):
        return []
    sources: List[RandomnessSource] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        source_id = _safe_label(raw.get("id"))
        consumer_function = _safe_label(raw.get("consumer_function"))
        if not source_id or not consumer_function:
            continue
        sources.append(
            RandomnessSource(
                id=source_id,
                consumer_function=consumer_function,
                source_kind=_safe_label(raw.get("source_kind")) or "",
                source_expression=_safe_text(raw.get("source_expression"), MAX_AGENT_TEXT_CHARS)
                or "",
                entropy_scope=_safe_text(raw.get("entropy_scope"), MAX_AGENT_TEXT_CHARS) or "",
                commit_phase=_safe_text(raw.get("commit_phase"), MAX_AGENT_TEXT_CHARS) or "",
                reveal_phase=_safe_text(raw.get("reveal_phase"), MAX_AGENT_TEXT_CHARS) or "",
                request_id_source=_safe_text(raw.get("request_id_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                fulfillment_guard=_safe_text(raw.get("fulfillment_guard"), MAX_AGENT_TEXT_CHARS)
                or "",
                confirmation_depth=_safe_text(raw.get("confirmation_depth"), MAX_AGENT_TEXT_CHARS)
                or "",
                modulo_bias_guard=_safe_text(raw.get("modulo_bias_guard"), MAX_AGENT_TEXT_CHARS)
                or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return sources


def _parse_randomness_risks(value: Any) -> List[RandomnessRisk]:
    if not isinstance(value, list):
        return []
    risks: List[RandomnessRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            RandomnessRisk(
                id=risk_id,
                category=category,
                affected_source_id=_safe_label(raw.get("affected_source_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def parse_erc4626_vault_inflation_hardening_plans(
    data: Any,
) -> List[ERC4626VaultInflationHardeningPlan]:
    """Parse provider output into bounded ERC4626 vault inflation hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "erc4626_vault_inflation_hardening_plans",
        data.get(
            "vault_inflation_hardening_plans",
            data.get(
                "share_inflation_hardening_plans",
                data.get("donation_attack_hardening_plans", data.get("vault_share_math_plans", [])),
            ),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[ERC4626VaultInflationHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        surfaces = _parse_vault_share_surfaces(raw.get("surfaces"))
        risks = _parse_vault_inflation_risks(raw.get("risks"))
        mitigations = _safe_text_list(raw.get("mitigations"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not surfaces and not risks and not mitigations and not validation_tests:
            continue
        plans.append(
            ERC4626VaultInflationHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                surfaces=surfaces,
                risks=risks,
                mitigations=mitigations,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def _parse_vault_share_surfaces(value: Any) -> List[VaultShareSurface]:
    if not isinstance(value, list):
        return []
    surfaces: List[VaultShareSurface] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        surface_id = _safe_label(raw.get("id"))
        vault_function = _safe_label(raw.get("vault_function"))
        if not surface_id or not vault_function:
            continue
        surfaces.append(
            VaultShareSurface(
                id=surface_id,
                vault_function=vault_function,
                asset_function=_safe_label(raw.get("asset_function")) or "",
                share_function=_safe_label(raw.get("share_function")) or "",
                total_assets_source=_safe_text(raw.get("total_assets_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                total_supply_source=_safe_text(raw.get("total_supply_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                conversion_formula=_safe_text(raw.get("conversion_formula"), MAX_AGENT_TEXT_CHARS)
                or "",
                rounding_direction=_safe_label(raw.get("rounding_direction")) or "",
                empty_vault_behavior=_safe_text(
                    raw.get("empty_vault_behavior"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                donation_exposure=_safe_text(raw.get("donation_exposure"), MAX_AGENT_TEXT_CHARS)
                or "",
                mitigation=_safe_text(raw.get("mitigation"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return surfaces


def _parse_vault_inflation_risks(value: Any) -> List[VaultInflationRisk]:
    if not isinstance(value, list):
        return []
    risks: List[VaultInflationRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            VaultInflationRisk(
                id=risk_id,
                category=category,
                affected_surface_id=_safe_label(raw.get("affected_surface_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def parse_create2_deployment_hardening_plans(
    data: Any,
) -> List[Create2DeploymentHardeningPlan]:
    """Parse provider output into bounded CREATE2 deployment hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "create2_deployment_hardening_plans",
        data.get(
            "deterministic_deployment_hardening_plans",
            data.get(
                "create2_salt_hardening_plans",
                data.get(
                    "salt_squatting_hardening_plans", data.get("factory_deployment_plans", [])
                ),
            ),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[Create2DeploymentHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        surfaces = _parse_create2_deployment_surfaces(raw.get("surfaces"))
        risks = _parse_create2_deployment_risks(raw.get("risks"))
        mitigations = _safe_text_list(raw.get("mitigations"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not surfaces and not risks and not mitigations and not validation_tests:
            continue
        plans.append(
            Create2DeploymentHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                surfaces=surfaces,
                risks=risks,
                mitigations=mitigations,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def _parse_create2_deployment_surfaces(value: Any) -> List[Create2DeploymentSurface]:
    if not isinstance(value, list):
        return []
    surfaces: List[Create2DeploymentSurface] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        surface_id = _safe_label(raw.get("id"))
        deploy_function = _safe_label(raw.get("deploy_function"))
        if not surface_id or not deploy_function:
            continue
        surfaces.append(
            Create2DeploymentSurface(
                id=surface_id,
                deploy_function=deploy_function,
                factory_contract=_safe_label(raw.get("factory_contract")) or "",
                salt_source=_safe_text(raw.get("salt_source"), MAX_AGENT_TEXT_CHARS) or "",
                init_code_source=_safe_text(raw.get("init_code_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                address_formula=_safe_text(raw.get("address_formula"), MAX_AGENT_TEXT_CHARS) or "",
                authorization_guard=_safe_text(raw.get("authorization_guard"), MAX_AGENT_TEXT_CHARS)
                or "",
                collision_check=_safe_text(raw.get("collision_check"), MAX_AGENT_TEXT_CHARS) or "",
                post_deploy_check=_safe_text(raw.get("post_deploy_check"), MAX_AGENT_TEXT_CHARS)
                or "",
                redeploy_assumption=_safe_text(raw.get("redeploy_assumption"), MAX_AGENT_TEXT_CHARS)
                or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return surfaces


def _parse_create2_deployment_risks(value: Any) -> List[Create2DeploymentRisk]:
    if not isinstance(value, list):
        return []
    risks: List[Create2DeploymentRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            Create2DeploymentRisk(
                id=risk_id,
                category=category,
                affected_surface_id=_safe_label(raw.get("affected_surface_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def parse_abi_packed_hash_collision_hardening_plans(
    data: Any,
) -> List[AbiPackedHashCollisionHardeningPlan]:
    """Parse provider output into bounded ABI packed hash collision hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "abi_packed_hash_collision_hardening_plans",
        data.get(
            "packed_hash_hardening_plans",
            data.get(
                "packed_hash_collision_plans",
                data.get(
                    "abi_encode_packed_collision_plans",
                    data.get(
                        "encode_packed_collision_plans",
                        data.get(
                            "hash_collision_hardening_plans",
                            data.get(
                                "hash_domain_hardening_plans",
                                data.get("packed_encoding_plans", []),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[AbiPackedHashCollisionHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        surfaces = _parse_abi_packed_hash_surfaces(raw.get("surfaces"))
        risks = _parse_abi_packed_hash_risks(raw.get("risks"))
        mitigations = _safe_text_list(raw.get("mitigations"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not surfaces and not risks and not mitigations and not validation_tests:
            continue
        plans.append(
            AbiPackedHashCollisionHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                surfaces=surfaces,
                risks=risks,
                mitigations=mitigations,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def _parse_abi_packed_hash_surfaces(value: Any) -> List[AbiPackedHashSurface]:
    if not isinstance(value, list):
        return []
    surfaces: List[AbiPackedHashSurface] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        surface_id = _safe_label(raw.get("id"))
        hash_function = _safe_label(raw.get("hash_function"))
        if not surface_id or not hash_function:
            continue
        surfaces.append(
            AbiPackedHashSurface(
                id=surface_id,
                hash_function=hash_function,
                packed_expression=_safe_text(raw.get("packed_expression"), MAX_AGENT_TEXT_CHARS)
                or "",
                argument_types=_safe_text_list(raw.get("argument_types")),
                dynamic_argument_count=_safe_text(
                    raw.get("dynamic_argument_count"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                user_controlled_arguments=_safe_text_list(raw.get("user_controlled_arguments")),
                hash_usage=_safe_text(raw.get("hash_usage"), MAX_AGENT_TEXT_CHARS) or "",
                domain_separator=_safe_text(raw.get("domain_separator"), MAX_AGENT_TEXT_CHARS)
                or "",
                delimiter_or_length_guard=_safe_text(
                    raw.get("delimiter_or_length_guard"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                safer_encoding=_safe_text(raw.get("safer_encoding"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return surfaces


def _parse_abi_packed_hash_risks(value: Any) -> List[AbiPackedHashRisk]:
    if not isinstance(value, list):
        return []
    risks: List[AbiPackedHashRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            AbiPackedHashRisk(
                id=risk_id,
                category=category,
                affected_surface_id=_safe_label(raw.get("affected_surface_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def parse_token_hook_reentrancy_hardening_plans(
    data: Any,
) -> List[TokenHookReentrancyHardeningPlan]:
    """Parse provider output into bounded token hook reentrancy hardening plans."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return []

    if not isinstance(data, Mapping):
        return []

    raw_items = data.get(
        "token_hook_reentrancy_hardening_plans",
        data.get(
            "token_hook_reentrancy_plans",
            data.get(
                "erc777_hook_reentrancy_plans",
                data.get(
                    "erc777_hook_hardening_plans",
                    data.get(
                        "erc1363_callback_reentrancy_plans",
                        data.get(
                            "erc1363_callback_hardening_plans",
                            data.get(
                                "callback_reentrancy_hardening_plans",
                                data.get("token_callback_hardening_plans", []),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    if not isinstance(raw_items, list):
        return []

    plans: List[TokenHookReentrancyHardeningPlan] = []
    for raw in raw_items[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        objective = _safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        surfaces = _parse_token_hook_surfaces(raw.get("surfaces"))
        risks = _parse_token_hook_reentrancy_risks(raw.get("risks"))
        mitigations = _safe_text_list(raw.get("mitigations"))
        validation_tests = _safe_text_list(raw.get("validation_tests"))
        if not objective:
            continue
        if not surfaces and not risks and not mitigations and not validation_tests:
            continue
        plans.append(
            TokenHookReentrancyHardeningPlan(
                id=_safe_label(raw.get("id")) or _derive_invariant_id(objective),
                objective=objective,
                surfaces=surfaces,
                risks=risks,
                mitigations=mitigations,
                validation_tests=validation_tests,
                recommended_tools=_safe_text_list(raw.get("recommended_tools")),
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return plans


def _parse_token_hook_surfaces(value: Any) -> List[TokenHookSurface]:
    if not isinstance(value, list):
        return []
    surfaces: List[TokenHookSurface] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        surface_id = _safe_label(raw.get("id"))
        entrypoint = _safe_label(raw.get("entrypoint"))
        if not surface_id or not entrypoint:
            continue
        surfaces.append(
            TokenHookSurface(
                id=surface_id,
                entrypoint=entrypoint,
                token_standard=_safe_text(raw.get("token_standard"), MAX_AGENT_TEXT_CHARS) or "",
                hook_function=_safe_text(raw.get("hook_function"), MAX_AGENT_TEXT_CHARS) or "",
                external_token_call=_safe_text(raw.get("external_token_call"), MAX_AGENT_TEXT_CHARS)
                or "",
                state_update_order=_safe_text(raw.get("state_update_order"), MAX_AGENT_TEXT_CHARS)
                or "",
                accounting_fields=_safe_text_list(raw.get("accounting_fields")),
                expected_callback_sender=_safe_text(
                    raw.get("expected_callback_sender"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                guard=_safe_text(raw.get("guard"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return surfaces


def _parse_token_hook_reentrancy_risks(value: Any) -> List[TokenHookReentrancyRisk]:
    if not isinstance(value, list):
        return []
    risks: List[TokenHookReentrancyRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            TokenHookReentrancyRisk(
                id=risk_id,
                category=category,
                affected_surface_id=_safe_label(raw.get("affected_surface_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_ordering_transactions(value: Any) -> List[OrderingTransaction]:
    if not isinstance(value, list):
        return []
    transactions: List[OrderingTransaction] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        tx_id = _safe_label(raw.get("id"))
        role = _safe_label(raw.get("role"))
        function = _safe_label(raw.get("function"))
        if not tx_id or not role or not function:
            continue
        transactions.append(
            OrderingTransaction(
                id=tx_id,
                role=role,
                function=function,
                actor=_safe_label(raw.get("actor")) or "",
                position=_safe_label(raw.get("position")) or "",
                value_hint=_safe_text(raw.get("value_hint"), MAX_AGENT_TEXT_CHARS) or "",
                state_dependency=_safe_text(raw.get("state_dependency"), MAX_AGENT_TEXT_CHARS)
                or "",
                slippage_or_limit=_safe_text(raw.get("slippage_or_limit"), MAX_AGENT_TEXT_CHARS)
                or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return transactions


def _parse_ordering_risks(value: Any) -> List[OrderingRisk]:
    if not isinstance(value, list):
        return []
    risks: List[OrderingRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            OrderingRisk(
                id=risk_id,
                category=category,
                affected_transaction_id=_safe_label(raw.get("affected_transaction_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_oracle_feed_sources(value: Any) -> List[OracleFeedSource]:
    if not isinstance(value, list):
        return []
    feeds: List[OracleFeedSource] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        feed_id = _safe_label(raw.get("id"))
        consumer_function = _safe_label(raw.get("consumer_function"))
        if not feed_id or not consumer_function:
            continue
        feeds.append(
            OracleFeedSource(
                id=feed_id,
                consumer_function=consumer_function,
                feed_kind=_safe_label(raw.get("feed_kind")) or "",
                source_contract=_safe_text(raw.get("source_contract"), MAX_AGENT_TEXT_CHARS) or "",
                read_method=_safe_label(raw.get("read_method")) or "",
                freshness_source=_safe_text(raw.get("freshness_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                staleness_threshold=_safe_text(raw.get("staleness_threshold"), MAX_AGENT_TEXT_CHARS)
                or "",
                decimals_source=_safe_text(raw.get("decimals_source"), MAX_AGENT_TEXT_CHARS) or "",
                normalization=_safe_text(raw.get("normalization"), MAX_AGENT_TEXT_CHARS) or "",
                fallback_source=_safe_text(raw.get("fallback_source"), MAX_AGENT_TEXT_CHARS) or "",
                sequencer_guard=_safe_text(raw.get("sequencer_guard"), MAX_AGENT_TEXT_CHARS) or "",
                bounds_check=_safe_text(raw.get("bounds_check"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return feeds


def _parse_oracle_feed_risks(value: Any) -> List[OracleFeedRisk]:
    if not isinstance(value, list):
        return []
    risks: List[OracleFeedRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            OracleFeedRisk(
                id=risk_id,
                category=category,
                affected_feed_id=_safe_label(raw.get("affected_feed_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_delegatecall_surfaces(value: Any) -> List[DelegatecallSurface]:
    if not isinstance(value, list):
        return []
    surfaces: List[DelegatecallSurface] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        surface_id = _safe_label(raw.get("id"))
        caller_function = _safe_label(raw.get("caller_function"))
        if not surface_id or not caller_function:
            continue
        surfaces.append(
            DelegatecallSurface(
                id=surface_id,
                caller_function=caller_function,
                target_source=_safe_text(raw.get("target_source"), MAX_AGENT_TEXT_CHARS) or "",
                selector_source=_safe_text(raw.get("selector_source"), MAX_AGENT_TEXT_CHARS) or "",
                target_trust_boundary=_safe_text(
                    raw.get("target_trust_boundary"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                guard_summary=_safe_text(raw.get("guard_summary"), MAX_AGENT_TEXT_CHARS) or "",
                value_forwarding=_safe_text(raw.get("value_forwarding"), MAX_AGENT_TEXT_CHARS)
                or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return surfaces


def _parse_storage_alias_paths(value: Any) -> List[StorageAliasPath]:
    if not isinstance(value, list):
        return []
    paths: List[StorageAliasPath] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        path_id = _safe_label(raw.get("id"))
        surface_id = _safe_label(raw.get("delegatecall_surface_id"))
        if not path_id or not surface_id:
            continue
        paths.append(
            StorageAliasPath(
                id=path_id,
                delegatecall_surface_id=surface_id,
                caller_slot=_safe_text(raw.get("caller_slot"), MAX_AGENT_TEXT_CHARS) or "",
                callee_slot=_safe_text(raw.get("callee_slot"), MAX_AGENT_TEXT_CHARS) or "",
                caller_semantics=_safe_text(raw.get("caller_semantics"), MAX_AGENT_TEXT_CHARS)
                or "",
                callee_semantics=_safe_text(raw.get("callee_semantics"), MAX_AGENT_TEXT_CHARS)
                or "",
                write_source=_safe_text(raw.get("write_source"), MAX_AGENT_TEXT_CHARS) or "",
                path_condition=_safe_text(
                    raw.get("path_condition"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return paths


def _parse_delegatecall_alias_risks(value: Any) -> List[DelegatecallAliasRisk]:
    if not isinstance(value, list):
        return []
    risks: List[DelegatecallAliasRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            DelegatecallAliasRisk(
                id=risk_id,
                category=category,
                affected_surface_id=_safe_label(raw.get("affected_surface_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_cross_chain_message_flows(value: Any) -> List[CrossChainMessageFlow]:
    if not isinstance(value, list):
        return []
    flows: List[CrossChainMessageFlow] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        flow_id = _safe_label(raw.get("id"))
        handler_function = _safe_label(raw.get("handler_function"))
        if not flow_id or not handler_function:
            continue
        flows.append(
            CrossChainMessageFlow(
                id=flow_id,
                handler_function=handler_function,
                source_domain=_safe_text(raw.get("source_domain"), MAX_AGENT_TEXT_CHARS) or "",
                destination_domain=_safe_text(raw.get("destination_domain"), MAX_AGENT_TEXT_CHARS)
                or "",
                trusted_sender_source=_safe_text(
                    raw.get("trusted_sender_source"), MAX_AGENT_TEXT_CHARS
                )
                or "",
                message_id_source=_safe_text(raw.get("message_id_source"), MAX_AGENT_TEXT_CHARS)
                or "",
                replay_guard=_safe_text(raw.get("replay_guard"), MAX_AGENT_TEXT_CHARS) or "",
                finality_assumption=_safe_text(raw.get("finality_assumption"), MAX_AGENT_TEXT_CHARS)
                or "",
                payload_scope=_safe_text_list(raw.get("payload_scope")),
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return flows


def _parse_cross_chain_message_risks(value: Any) -> List[CrossChainMessageRisk]:
    if not isinstance(value, list):
        return []
    risks: List[CrossChainMessageRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            CrossChainMessageRisk(
                id=risk_id,
                category=category,
                affected_flow_id=_safe_label(raw.get("affected_flow_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_signed_actions(value: Any) -> List[SignedAction]:
    if not isinstance(value, list):
        return []
    actions: List[SignedAction] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        action_id = _safe_label(raw.get("id"))
        function = _safe_label(raw.get("function"))
        if not action_id or not function:
            continue
        actions.append(
            SignedAction(
                id=action_id,
                function=function,
                signer_source=_safe_text(raw.get("signer_source"), MAX_AGENT_TEXT_CHARS) or "",
                digest_scheme=_safe_label(raw.get("digest_scheme")) or "",
                domain_fields=_safe_text_list(raw.get("domain_fields")),
                nonce_source=_safe_text(raw.get("nonce_source"), MAX_AGENT_TEXT_CHARS) or "",
                deadline_source=_safe_text(raw.get("deadline_source"), MAX_AGENT_TEXT_CHARS) or "",
                value_scope=_safe_text_list(raw.get("value_scope")),
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return actions


def _parse_signature_domain_risks(value: Any) -> List[SignatureDomainRisk]:
    if not isinstance(value, list):
        return []
    risks: List[SignatureDomainRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            SignatureDomainRisk(
                id=risk_id,
                category=category,
                affected_action_id=_safe_label(raw.get("affected_action_id")) or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_storage_layout_changes(value: Any) -> List[StorageLayoutChange]:
    if not isinstance(value, list):
        return []
    changes: List[StorageLayoutChange] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        slot = _safe_label(raw.get("slot"))
        risk = _safe_text(raw.get("risk"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        before = _safe_text(raw.get("before"), MAX_AGENT_TEXT_CHARS)
        after = _safe_text(raw.get("after"), MAX_AGENT_TEXT_CHARS)
        if not slot or (not risk and not before and not after):
            continue
        changes.append(
            StorageLayoutChange(
                slot=slot,
                before=before or "",
                after=after or "",
                change_type=_safe_label(raw.get("change_type")) or "",
                risk=risk or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return changes


def _parse_upgrade_risks(value: Any) -> List[UpgradeRisk]:
    if not isinstance(value, list):
        return []
    risks: List[UpgradeRisk] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        risk_id = _safe_label(raw.get("id"))
        category = _safe_label(raw.get("category"))
        description = _safe_text(raw.get("description"), MAX_AGENT_TEXT_CHARS, allow_multiline=True)
        if not risk_id or not category or not description:
            continue
        risks.append(
            UpgradeRisk(
                id=risk_id,
                category=category,
                affected_component=_safe_text(raw.get("affected_component"), MAX_AGENT_TEXT_CHARS)
                or "",
                severity_hint=_safe_label(raw.get("severity_hint")) or "",
                description=description,
                evidence=_safe_text_list(raw.get("evidence")),
                recommended_check=_safe_text(
                    raw.get("recommended_check"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
                )
                or "",
            )
        )
    return risks


def _parse_metamorphic_relations(value: Any) -> List[MetamorphicRelation]:
    if not isinstance(value, list):
        return []
    relations: List[MetamorphicRelation] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        relation_id = _safe_label(raw.get("id"))
        relation_type = _safe_label(raw.get("relation_type"))
        expected_relation = _safe_text(
            raw.get("expected_relation"), MAX_AGENT_TEXT_CHARS, allow_multiline=True
        )
        baseline_sequence = _parse_sequence_steps(raw.get("baseline_sequence"))
        variant_sequence = _parse_sequence_steps(raw.get("variant_sequence"))
        if not relation_id or not relation_type or not expected_relation:
            continue
        if not baseline_sequence or not variant_sequence:
            continue
        relations.append(
            MetamorphicRelation(
                id=relation_id,
                relation_type=relation_type,
                baseline_sequence=baseline_sequence,
                variant_sequence=variant_sequence,
                expected_relation=expected_relation,
                tolerance_hint=_safe_text(raw.get("tolerance_hint"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return relations


def _parse_capital_requirements(value: Any) -> List[CapitalRequirement]:
    if not isinstance(value, list):
        return []
    requirements: List[CapitalRequirement] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        asset = _safe_label(raw.get("asset"))
        amount_hint = _safe_text(raw.get("amount_hint"), MAX_AGENT_TEXT_CHARS)
        if not asset or not amount_hint:
            continue
        requirements.append(
            CapitalRequirement(
                asset=asset,
                amount_hint=amount_hint,
                source=_safe_text(raw.get("source"), MAX_AGENT_TEXT_CHARS) or "",
                purpose=_safe_text(raw.get("purpose"), MAX_AGENT_TEXT_CHARS) or "",
            )
        )
    return requirements


def _parse_asset_flows(value: Any) -> List[AssetFlow]:
    if not isinstance(value, list):
        return []
    flows: List[AssetFlow] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        asset = _safe_label(raw.get("asset"))
        from_actor = _safe_label(raw.get("from_actor"))
        to_actor = _safe_label(raw.get("to_actor"))
        if not asset or not from_actor or not to_actor:
            continue
        flows.append(
            AssetFlow(
                asset=asset,
                from_actor=from_actor,
                to_actor=to_actor,
                amount_hint=_safe_text(raw.get("amount_hint"), MAX_AGENT_TEXT_CHARS) or "",
                step_id=_safe_label(raw.get("step_id")) or "",
                rationale=_safe_text(raw.get("rationale"), MAX_AGENT_TEXT_CHARS) or "",
            )
        )
    return flows


def _parse_sequence_steps(value: Any) -> List[SequenceStep]:
    if not isinstance(value, list):
        return []
    steps: List[SequenceStep] = []
    for raw_step in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw_step, Mapping):
            continue
        function = _safe_label(raw_step.get("function"))
        if not function:
            continue
        steps.append(
            SequenceStep(
                function=function,
                actor=_safe_label(raw_step.get("actor")) or "",
                arguments=_safe_text_list(raw_step.get("arguments")),
                value_hint=_safe_text(raw_step.get("value_hint"), MAX_AGENT_TEXT_CHARS) or "",
                precondition=_safe_text(raw_step.get("precondition"), MAX_AGENT_TEXT_CHARS) or "",
                expected_effect=_safe_text(raw_step.get("expected_effect"), MAX_AGENT_TEXT_CHARS)
                or "",
            )
        )
    return steps


def _parse_snapshot_seeds(value: Any) -> List[SnapshotSeed]:
    if not isinstance(value, list):
        return []
    seeds: List[SnapshotSeed] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        seed_id = _safe_label(raw.get("id"))
        target_state = _safe_text(raw.get("target_state"), MAX_AGENT_TEXT_CHARS)
        setup_sequence = _parse_sequence_steps(raw.get("setup_sequence"))
        if not seed_id or (not target_state and not setup_sequence):
            continue
        seeds.append(
            SnapshotSeed(
                id=seed_id,
                setup_sequence=setup_sequence,
                target_state=target_state or "",
                priority=_bounded_confidence(raw.get("priority")),
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return seeds


def _parse_fuzzing_waypoints(value: Any) -> List[FuzzingWaypoint]:
    if not isinstance(value, list):
        return []
    waypoints: List[FuzzingWaypoint] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        waypoint_id = _safe_label(raw.get("id"))
        target = _safe_text(raw.get("target"), MAX_AGENT_TEXT_CHARS)
        if not waypoint_id or not target:
            continue
        waypoints.append(
            FuzzingWaypoint(
                id=waypoint_id,
                kind=_safe_label(raw.get("kind")) or "state_frontier",
                target=target,
                objective=_safe_text(raw.get("objective"), MAX_AGENT_TEXT_CHARS) or "",
                distance_hint=_safe_text(raw.get("distance_hint"), MAX_AGENT_TEXT_CHARS) or "",
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return waypoints


def _parse_semantic_graph_nodes(value: Any) -> List[SemanticGraphNode]:
    if not isinstance(value, list):
        return []
    nodes: List[SemanticGraphNode] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        node_id = _safe_label(raw.get("id"))
        kind = _safe_label(raw.get("kind"))
        if not node_id or not kind:
            continue
        nodes.append(
            SemanticGraphNode(
                id=node_id,
                kind=kind,
                label=_safe_text(raw.get("label"), MAX_AGENT_TEXT_CHARS) or "",
                contract=_safe_label(raw.get("contract")) or "",
                function=_safe_label(raw.get("function")) or "",
                line=_bounded_nonnegative_int(raw.get("line"), 1_000_000),
                metadata=_json_safe_mapping(raw.get("metadata")),
            )
        )
    return nodes


def _parse_semantic_graph_edges(value: Any) -> List[SemanticGraphEdge]:
    if not isinstance(value, list):
        return []
    edges: List[SemanticGraphEdge] = []
    for raw in value[:MAX_AGENT_ITEMS]:
        if not isinstance(raw, Mapping):
            continue
        source = _safe_label(raw.get("source"))
        target = _safe_label(raw.get("target"))
        relation = _safe_label(raw.get("relation"))
        if not source or not target:
            continue
        edges.append(
            SemanticGraphEdge(
                source=source,
                target=target,
                relation=relation or "related",
                confidence=_bounded_confidence(raw.get("confidence")),
                evidence=_safe_text_list(raw.get("evidence")),
            )
        )
    return edges


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


def _economic_attack_prompt(
    source_code: str,
    findings: List[Any],
    sequence_plans: List[Dict[str, Any]],
    snapshot_plans: List[Dict[str, Any]],
    graph_gates: List[Dict[str, Any]],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    sequences_json = json.dumps(sequence_plans[:25], sort_keys=True)
    snapshots_json = json.dumps(snapshot_plans[:25], sort_keys=True)
    gates_json = json.dumps(graph_gates[:25], sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build economic/profit-driven DeFi attack simulation plans for defensive smart
contract validation. Consume sequence, snapshot, and semantic graph hypotheses
when available, then state whether a path has plausible economic exploitability
under explicit capital, liquidity, fee, slippage, oracle-price, and gas
assumptions.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Do not claim a confirmed vulnerability without replay or counterexample
evidence. Treat these plans as simulation guidance.

Return this shape:
{{
  "economic_attack_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "economic exploit hypothesis",
      "target_vulnerability_types": ["oracle_manipulation"],
      "base_sequence_plan_ids": ["sequence_id"],
      "base_snapshot_plan_ids": ["snapshot_id"],
      "base_graph_gate_ids": ["graph_gate_id"],
      "capital_requirements": [
        {{
          "asset": "USDC",
          "amount_hint": "flash-loan amount or range",
          "source": "flash_loan|attacker_capital|existing_liquidity",
          "purpose": "why this capital is needed"
        }}
      ],
      "asset_flows": [
        {{
          "asset": "USDC",
          "from_actor": "flash_pool",
          "to_actor": "attacker",
          "amount_hint": "principal",
          "step_id": "borrow_flash",
          "rationale": "fund manipulation leg"
        }}
      ],
      "profit_formula": "gross proceeds - principal - fees - gas - slippage",
      "cost_model": "gas, protocol fees, flash-loan premium, swap fees",
      "liquidity_assumptions": ["pool depth and slippage assumptions"],
      "oracle_price_assumptions": ["spot/TWAP/staleness assumptions"],
      "break_even_threshold": "minimum exploitable delta",
      "expected_profit_range": "bounded qualitative or numeric range",
      "risk_factors": ["assumptions that may invalidate exploitability"],
      "recommended_tools": ["foundry", "anvil", "fork-simulation"],
      "confidence": 0.0,
      "evidence": ["specific code or plan signal"]
    }}
  ]
}}

Existing findings, if any:
{findings_json}

Sequence oracle plans, if any:
{sequences_json}

Snapshot fuzzing plans, if any:
{snapshots_json}

Semantic graph gates, if any:
{gates_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _snapshot_fuzzing_prompt(
    source_code: str,
    findings: List[Any],
    sequence_plans: List[Dict[str, Any]],
    graph_gates: List[Dict[str, Any]],
    max_snapshots: int,
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    sequences_json = json.dumps(sequence_plans[:25], sort_keys=True)
    gates_json = json.dumps(graph_gates[:25], sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build snapshot and dataflow-guided fuzzing campaign plans for defensive
smart-contract testing. Identify reusable intermediate states, branch or
dataflow waypoints, priority singleton transactions, and failure oracles that
can guide Foundry, Echidna, Medusa, ItyFuzz-style snapshot fuzzing, or another
replaceable local fuzzing backend.

Do not depend on a specific model, vendor, or external API. Return only JSON.

Return this shape:
{{
  "snapshot_fuzzing_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "campaign goal",
      "target_vulnerability_types": ["oracle_manipulation"],
      "seeds": [
        {{
          "id": "seed_after_liquidity",
          "setup_sequence": [
            {{
              "function": "deposit",
              "actor": "victim|attacker|owner|any",
              "arguments": ["amount"],
              "value_hint": "msg.value hint",
              "precondition": "state requirement",
              "expected_effect": "state after call"
            }}
          ],
          "target_state": "state to snapshot and reuse",
          "priority": 0.0,
          "evidence": ["specific code signal"]
        }}
      ],
      "waypoints": [
        {{
          "id": "branch_health_factor_lt_one",
          "kind": "branch|dataflow|state_frontier|oracle",
          "target": "symbol or predicate",
          "objective": "why this frontier matters",
          "distance_hint": "comparison or data dependency hint",
          "evidence": ["specific code signal"]
        }}
      ],
      "priority_transactions": [],
      "oracle": "condition that indicates failure",
      "recommended_tools": ["foundry", "echidna", "ityfuzz"],
      "budget_hint": "bounded run guidance",
      "confidence": 0.0
    }}
  ]
}}

Constraints:
- Use at most {max_snapshots} snapshot seeds.
- Treat campaign plans as fuzzing guidance, not confirmed findings.
- Prefer reusable states before expensive transaction prefixes.
- Prefer explainable dataflow or branch-distance waypoints over opaque scores.

Existing findings, if any:
{findings_json}

Sequence oracle plans, if any:
{sequences_json}

Semantic graph gates, if any:
{gates_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _metamorphic_diff_prompt(
    source_code: str,
    findings: List[Any],
    invariants: List[Dict[str, Any]],
    sequence_plans: List[Dict[str, Any]],
    snapshot_plans: List[Dict[str, Any]],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    invariants_json = json.dumps(invariants[:25], sort_keys=True)
    sequences_json = json.dumps(sequence_plans[:25], sort_keys=True)
    snapshots_json = json.dumps(snapshot_plans[:25], sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build metamorphic and differential test plans for defensive Solidity
validation. Focus on relations between a baseline execution and a derived
variant execution: split versus merged deposits, mint/redeem round trips,
operation commutativity, idempotent pause/config calls, monotonic accounting,
reference-implementation comparisons, and compiler/configuration differentials.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as test guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "differential_test_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "metamorphic or differential hypothesis",
      "target_vulnerability_types": ["accounting_drift"],
      "relations": [
        {{
          "id": "split_merge_deposit",
          "relation_type": "equivalence|inverse|commutative|idempotent|round_trip|split_merge|monotonic|conservation",
          "baseline_sequence": [
            {{
              "function": "deposit",
              "actor": "user|attacker|owner|any",
              "arguments": ["amount"],
              "value_hint": "msg.value hint",
              "precondition": "state requirement",
              "expected_effect": "state after call"
            }}
          ],
          "variant_sequence": [
            {{
              "function": "deposit",
              "actor": "user|attacker|owner|any",
              "arguments": ["amount / 2"],
              "value_hint": "msg.value hint",
              "precondition": "same starting state",
              "expected_effect": "equivalent final observable"
            }}
          ],
          "expected_relation": "observable balances and shares match within tolerance",
          "tolerance_hint": "rounding tolerance, if any",
          "evidence": ["specific code signal"]
        }}
      ],
      "state_observables": ["balanceOf(user)", "totalSupply()", "totalAssets()"],
      "oracle": "relation violation condition",
      "recommended_tools": ["foundry", "echidna", "halmos"],
      "confidence": 0.0,
      "evidence": ["specific code or plan signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate sequence-oracle plans; use relations to compare executions.
- Do not duplicate snapshot campaigns; reuse snapshot states when available.
- Do not decide profitability; send profit deltas to an economic plan later.
- Prefer relations that expose oracle-problem gaps without requiring a perfect
  expected output for a single execution.

Existing findings, if any:
{findings_json}

Candidate invariants, if any:
{invariants_json}

Sequence oracle plans, if any:
{sequences_json}

Snapshot fuzzing plans, if any:
{snapshots_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _upgrade_evolution_prompt(
    old_source_code: str,
    new_source_code: str,
    proxy_source_code: str,
    findings: List[Any],
    storage_layout_before: Dict[str, Any],
    storage_layout_after: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    layout_before_json = json.dumps(storage_layout_before, sort_keys=True)
    layout_after_json = json.dumps(storage_layout_after, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build upgrade evolution analysis plans for defensive Solidity review. Compare
an old implementation, a new implementation, and optional proxy code to find
upgrade-induced risks: storage layout collisions, unsafe gap changes,
initializer or reinitializer drift, unprotected upgrade/admin paths, UUPS or
transparent proxy misuse, delegatecall context surprises, selector collisions,
and missing migration dry-run checks.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as attribution and validation guidance, not confirmed findings.

Return this shape:
{{
  "upgrade_evolution_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "upgrade risk hypothesis",
      "proxy_pattern": "transparent|uups|beacon|custom|unknown",
      "old_implementation": "ImplementationV1",
      "new_implementation": "ImplementationV2",
      "storage_changes": [
        {{
          "slot": "0",
          "before": "address owner",
          "after": "bool openForSale",
          "change_type": "type_change|insert_before_existing|delete|rename|gap_change",
          "risk": "storage collision or semantic corruption risk",
          "evidence": ["specific layout signal"]
        }}
      ],
      "risks": [
        {{
          "id": "unprotected_reinitializer",
          "category": "storage_layout|initializer|admin|selector_collision|delegatecall|migration",
          "affected_component": "initializeV2",
          "severity_hint": "high|medium|low",
          "description": "why the upgrade transition is risky",
          "evidence": ["specific code or layout signal"],
          "recommended_check": "test or static check to validate"
        }}
      ],
      "migration_checks": ["dry-run upgrade preserves owner and balances"],
      "recommended_tools": ["openzeppelin-upgrades", "slither", "foundry"],
      "confidence": 0.0,
      "evidence": ["specific diff signal"]
    }}
  ]
}}

Constraints:
- Prefer evidence from layout diffs and changed initialization/admin code.
- Do not duplicate semantic graph gates; this plan is about version transition risk.
- Do not claim exploitability without migration replay or counterexample evidence.
- Keep upgrade pattern and assumptions explicit.

Existing findings, if any:
{findings_json}

Storage layout before, if available:
{layout_before_json}

Storage layout after, if available:
{layout_after_json}

Proxy source, if available:
```solidity
{proxy_source_code}
```

Old implementation source:
```solidity
{old_source_code}
```

New implementation source:
```solidity
{new_source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _signature_domain_prompt(
    source_code: str,
    findings: List[Any],
    abi_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    abi_json = json.dumps(abi_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build signature-domain hardening plans for defensive Solidity review. Identify
signed authorization flows such as permit, meta-transactions, delegated votes,
off-chain order fills, whitelist claims, ERC-1271 contract signatures, and
custom ECDSA recover paths. Focus on replay boundaries, domain separators,
chain and contract binding, nonce consumption, deadline checks, signer binding,
value scope, signature malleability, and cross-chain or cross-contract replay.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "signature_domain_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "signed authorization hardening goal",
      "signed_actions": [
        {{
          "id": "permit_owner_spender_value",
          "function": "permit",
          "signer_source": "owner recovered by ECDSA or ERC-1271",
          "digest_scheme": "eip712|eth_sign|raw_hash|erc1271|unknown",
          "domain_fields": ["name", "version", "chainId", "verifyingContract"],
          "nonce_source": "nonces[owner] consumed on success",
          "deadline_source": "deadline checked against block.timestamp",
          "value_scope": ["owner", "spender", "value"],
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "missing_chain_id",
          "category": "domain_separator|nonce|deadline|signer_binding|malleability|erc1271|cross_chain_replay|permit_integration",
          "affected_action_id": "permit_owner_spender_value",
          "severity_hint": "high|medium|low",
          "description": "why replay or misuse is plausible",
          "evidence": ["specific code signal"],
          "recommended_check": "test replay across chainId or contract address"
        }}
      ],
      "replay_tests": ["reuse the same signature after nonce consumption"],
      "recommended_tools": ["foundry", "echidna", "slither"],
      "confidence": 0.0,
      "evidence": ["specific signature signal"]
    }}
  ]
}}

Constraints:
- Prefer EIP-712 domain evidence over generic signature mentions.
- Do not duplicate sequence-oracle plans; this plan is about signature replay boundaries.
- Do not claim exploitability without replay or counterexample evidence.
- Keep signer, nonce, deadline, domain, and value scope assumptions explicit.

Existing findings, if any:
{findings_json}

ABI or function summary, if any:
{abi_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _cross_chain_message_prompt(
    source_code: str,
    findings: List[Any],
    bridge_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    bridge_json = json.dumps(bridge_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build cross-chain message hardening plans for defensive Solidity review. Identify
bridge, L2 messenger, inbox, outbox, endpoint, receive, execute, finalize, and
relay handlers. Focus on source and destination domain binding, trusted remote
sender or messenger checks, message id uniqueness, consumed-message tracking,
proof/root/finality assumptions, payload scope, value consistency, sender
aliasing, ordering, and replay across chains or applications.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "cross_chain_message_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "cross-chain message hardening goal",
      "message_flows": [
        {{
          "id": "l2_receive_message",
          "handler_function": "receiveMessage",
          "source_domain": "source chain or domain id",
          "destination_domain": "destination chain or domain id",
          "trusted_sender_source": "trusted remote app or messenger lookup",
          "message_id_source": "message hash, nonce, packet id, or event id",
          "replay_guard": "processedMessages[messageId]",
          "finality_assumption": "proof/root/finality/delay requirement",
          "payload_scope": ["token", "amount", "recipient"],
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "missing_source_sender_check",
          "category": "source_domain|trusted_sender|message_id|replay_guard|finality|payload_scope|ordering|value_consistency|sender_aliasing",
          "affected_flow_id": "l2_receive_message",
          "severity_hint": "high|medium|low",
          "description": "why unauthorized or replayed message execution is plausible",
          "evidence": ["specific code signal"],
          "recommended_check": "replay same message id or spoof source sender"
        }}
      ],
      "validation_tests": ["replay consumed message id must revert"],
      "recommended_tools": ["foundry", "bridgefuzz", "slither"],
      "confidence": 0.0,
      "evidence": ["specific bridge message signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate signature-domain hardening; focus on bridge/L2 message envelopes.
- Do not duplicate sequence-oracle plans; return message validation checks and tests.
- Do not claim exploitability without replay, spoofing, or finality evidence.
- Keep source domain, trusted sender, message id, finality, and payload assumptions explicit.

Existing findings, if any:
{findings_json}

Bridge or L2 summary, if any:
{bridge_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _delegatecall_storage_aliasing_prompt(
    source_code: str,
    findings: List[Any],
    layout_summary: Dict[str, Any],
    callee_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    layout_json = json.dumps(layout_summary, sort_keys=True)
    callee_json = json.dumps(callee_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build delegatecall storage-aliasing plans for defensive Solidity review.
Identify delegatecall surfaces, target-selection paths, selector control,
caller/callee storage slot semantics, callee writes, initializer or owner slot
takeover paths, selfdestruct/value/msg.sender context risks, and the checks
needed to validate whether a target can corrupt caller storage.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "delegatecall_storage_aliasing_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "delegatecall storage aliasing validation goal",
      "delegatecall_surfaces": [
        {{
          "id": "fallback_delegatecall",
          "caller_function": "fallback",
          "target_source": "implementation address slot or user argument",
          "selector_source": "msg.data selector forwarded to callee",
          "target_trust_boundary": "owner-controlled|user-controlled|registry|immutable",
          "guard_summary": "whitelist, access control, codehash, or none",
          "value_forwarding": "msg.value preserved by delegatecall",
          "evidence": ["specific code signal"]
        }}
      ],
      "storage_alias_paths": [
        {{
          "id": "owner_slot_collision",
          "delegatecall_surface_id": "fallback_delegatecall",
          "caller_slot": "slot 0 owner",
          "callee_slot": "slot 0 initialized",
          "caller_semantics": "owner address",
          "callee_semantics": "initializer boolean or attacker-controlled owner",
          "write_source": "callee function writes slot 0",
          "path_condition": "attacker can select callee and function selector",
          "evidence": ["specific storage or write signal"]
        }}
      ],
      "risks": [
        {{
          "id": "user_controlled_delegate_target",
          "category": "target_control|selector_control|storage_collision|slot_semantics|callee_write|initializer_takeover|selfdestruct|value_context|access_context",
          "affected_surface_id": "fallback_delegatecall",
          "severity_hint": "high|medium|low",
          "description": "why caller storage can be corrupted or privileges can change",
          "evidence": ["specific code signal"],
          "recommended_check": "prove a callee write reaches caller owner/admin slot"
        }}
      ],
      "validation_tests": ["deploy malicious callee that writes caller slot 0"],
      "recommended_tools": ["foundry", "slither", "symbolic execution"],
      "confidence": 0.0,
      "evidence": ["specific delegatecall signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate generic proxy-upgrade analysis; focus on delegatecall target
  control and caller/callee storage aliasing evidence.
- Do not claim exploitability without a callee write path or concrete storage
  semantics mismatch.
- Prefer read/write data-flow and attack-path validation over keyword matches.
- Keep target trust, selector control, storage slots, and access-context
  assumptions explicit.

Existing findings, if any:
{findings_json}

Storage layout or slot summary, if any:
{layout_json}

Callee/library/implementation summary, if any:
{callee_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _oracle_feed_hardening_prompt(
    source_code: str,
    findings: List[Any],
    oracle_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    oracle_json = json.dumps(oracle_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build oracle-feed hardening plans for defensive Solidity review. Identify
Chainlink AggregatorV3Interface reads, latestRoundData metadata use, TWAPs,
manual feeds, fallback feeds, multi-source adapters, decimals normalization,
staleness thresholds, deviation or circuit-breaker checks, answer bounds, and
L2 sequencer uptime feeds with grace periods.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "oracle_feed_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "oracle feed hardening goal",
      "feeds": [
        {{
          "id": "eth_usd_feed",
          "consumer_function": "getPrice",
          "feed_kind": "chainlink|twap|manual|fallback|multi_source|unknown",
          "source_contract": "AggregatorV3Interface feed address",
          "read_method": "latestRoundData",
          "freshness_source": "updatedAt",
          "staleness_threshold": "maxDelay or heartbeat",
          "decimals_source": "decimals()",
          "normalization": "scale to 1e18",
          "fallback_source": "secondary feed or none",
          "sequencer_guard": "L2 sequencer uptime feed plus grace period",
          "bounds_check": "price > 0 and deviation <= maxDeviation",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "stale_price",
          "category": "stale_round|incomplete_round|decimals_mismatch|zero_negative_price|missing_bounds|sequencer_down|fallback_trust|manual_override|multi_source_deviation",
          "affected_feed_id": "eth_usd_feed",
          "severity_hint": "high|medium|low",
          "description": "why unsafe oracle consumption is plausible",
          "evidence": ["specific code signal"],
          "recommended_check": "updatedAt older than threshold must revert"
        }}
      ],
      "validation_tests": ["stale updatedAt must revert"],
      "recommended_tools": ["foundry", "slither", "symbolic execution"],
      "confidence": 0.0,
      "evidence": ["specific oracle signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate economic attack simulation; this plan validates feed safety,
  not attacker profit.
- Do not duplicate sequence-oracle plans; return feed validation checks and tests.
- Do not claim exploitability without stale, incomplete, invalid, deviation, or
  missing sequencer evidence.
- Keep freshness, decimals, bounds, fallback, and L2 sequencer assumptions explicit.

Existing findings, if any:
{findings_json}

Oracle summary, if any:
{oracle_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _adversarial_transaction_ordering_prompt(
    source_code: str,
    findings: List[Any],
    market_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    market_json = json.dumps(market_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build adversarial transaction-ordering plans for defensive Solidity review.
Identify victim, attacker, keeper, liquidator, and settler transactions whose
relative order can change user outcomes. Focus on front-running, back-running,
sandwich attacks, transaction-order dependence, slippage gaps, deadline gaps,
commit-reveal gaps, liquidation races, auction reordering, permit nonce denial
of service, and private-orderflow assumptions.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "adversarial_transaction_ordering_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "ordering validation goal",
      "ordering_pattern": "front_run|back_run|sandwich|liquidation_race|permit_nonce_dos|commit_reveal|auction_reorder|unknown",
      "transactions": [
        {{
          "id": "victim_swap",
          "role": "victim|attacker_front|attacker_back|liquidator|keeper|settler",
          "function": "swapExactTokensForTokens",
          "actor": "user",
          "position": "before_victim|victim|after_victim|same_block",
          "value_hint": "amountIn or debt amount",
          "state_dependency": "pool reserves, oracle state, auction state, or nonce",
          "slippage_or_limit": "minOut, deadline, maxPrice, commit salt, or none",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "missing_min_out",
          "category": "front_run|back_run|sandwich|transaction_order_dependence|slippage_gap|deadline_gap|commit_reveal_gap|liquidation_race|permit_nonce_dos",
          "affected_transaction_id": "victim_swap",
          "severity_hint": "high|medium|low",
          "description": "why ordering can change the victim outcome",
          "evidence": ["specific code signal"],
          "recommended_check": "front-run reserve change makes victim execution worse"
        }}
      ],
      "oracle": "victim receives less than min safe amount or ordering changes winner",
      "mitigations": ["minOut", "deadline", "commit-reveal", "private routing"],
      "validation_tests": ["attacker front-run before victim worsens execution"],
      "recommended_tools": ["foundry", "mev simulation", "sequence oracle"],
      "confidence": 0.0,
      "evidence": ["specific ordering signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate sequence-oracle plans; this plan is about relative ordering
  and permutation assumptions between actor transactions.
- Do not duplicate economic attack simulation; do not calculate capital, fees,
  asset flows, or full profit formulas here.
- Do not claim a confirmed vulnerability without replay, fork simulation, or
  counterexample evidence.
- Make mempool, block-builder, liquidity, slippage, deadline, oracle freshness,
  and private-orderflow assumptions explicit.
- Prefer bounded validation targets such as Foundry fork tests, Anvil block
  ordering, stateful fuzzing, or deterministic replay.

Existing findings, if any:
{findings_json}

Market, mempool, sequence, or economic-plan summary, if any:
{market_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _randomness_entropy_hardening_prompt(
    source_code: str,
    findings: List[Any],
    randomness_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    summary_json = json.dumps(randomness_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build randomness entropy hardening plans for defensive Solidity review. Identify
weak entropy sources such as block.timestamp, block.number, blockhash,
block.prevrandao, block.difficulty, block.coinbase, gasleft, tx.origin, user
seeds, commit-reveal flows, oracle randomness, fallback randomness, and VRF
request/fulfillment integrations. Focus on who can influence the source,
whether commitments and reveals have complete lifecycle checks, whether VRF
callbacks bind request ids and authorized coordinators, whether blockhash values
can expire, and whether modulo mapping introduces bias.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "randomness_entropy_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "randomness hardening goal",
      "sources": [
        {{
          "id": "winner_entropy",
          "consumer_function": "drawWinner",
          "source_kind": "blockhash|timestamp|prevrandao|commit_reveal|vrf|oracle|user_seed|unknown",
          "source_expression": "keccak256(block.timestamp, msg.sender)",
          "entropy_scope": "lottery winner selection",
          "commit_phase": "commit hash with salt",
          "reveal_phase": "reveal after commit deadline",
          "request_id_source": "VRF requestId",
          "fulfillment_guard": "only coordinator and requestId match",
          "confirmation_depth": "request confirmations",
          "modulo_bias_guard": "rejection sampling or bounded mapping",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "timestamp_randomness",
          "category": "weak_source|prevrandao_bias|blockhash_expiry|timestamp_bias|commit_reveal_gap|vrf_request_mismatch|vrf_callback_auth|modulo_bias|reorg_bias|replay",
          "affected_source_id": "winner_entropy",
          "severity_hint": "high|medium|low",
          "description": "why randomness can be predicted, biased, or replayed",
          "evidence": ["specific code signal"],
          "recommended_check": "validator-controlled timestamp changes selected winner"
        }}
      ],
      "validation_tests": ["same seed with manipulated timestamp changes winner"],
      "recommended_tools": ["foundry", "echidna", "symbolic execution"],
      "confidence": 0.0,
      "evidence": ["specific randomness signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate sequence-oracle plans; return randomness and entropy
  validation checks, not full transaction-sequence plans.
- Do not duplicate economic attack simulation; do not calculate capital, fees,
  asset flows, or profit formulas.
- Do not rely on keyword-only or regex-only detection; cite semantic evidence
  from source, findings, ABI, or summaries.
- Do not claim a confirmed vulnerability without replay, fork simulation,
  property test, or counterexample evidence.
- Keep miner/validator/user influence, commit-reveal phases, VRF/oracle trust,
  seed material, fallback behavior, and timing assumptions explicit.

Existing findings, if any:
{findings_json}

Randomness or entropy summary, if any:
{summary_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _erc4626_vault_inflation_hardening_prompt(
    source_code: str,
    findings: List[Any],
    vault_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    summary_json = json.dumps(vault_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build ERC4626 vault inflation hardening plans for defensive Solidity review.
Identify vault share-accounting surfaces such as deposit, mint, withdraw,
redeem, previewDeposit, previewMint, convertToShares, convertToAssets,
totalAssets, totalSupply, and direct asset-balance reads. Focus on first
depositor donation attacks, low-supply rounding, zero-share mints, raw
balance-based totalAssets, missing virtual shares or virtual assets, missing
dead shares, missing minimum-share checks, preview/execution mismatches, and
internal-accounting gaps.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "erc4626_vault_inflation_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "vault inflation hardening goal",
      "surfaces": [
        {{
          "id": "deposit_share_math",
          "vault_function": "deposit",
          "asset_function": "totalAssets",
          "share_function": "convertToShares",
          "total_assets_source": "asset.balanceOf(address(this))",
          "total_supply_source": "totalSupply()",
          "conversion_formula": "assets * totalSupply / totalAssets",
          "rounding_direction": "down|up|mixed|unknown",
          "empty_vault_behavior": "assets minted 1:1",
          "donation_exposure": "direct transfer changes assets without shares",
          "mitigation": "virtual shares, dead shares, internal accounting, or min shares",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "first_deposit_donation",
          "category": "first_depositor|direct_donation|zero_share_mint|rounding_loss|raw_balance_total_assets|missing_min_shares|missing_virtual_offset|preview_mismatch|internal_accounting_gap",
          "affected_surface_id": "deposit_share_math",
          "severity_hint": "high|medium|low",
          "description": "why deposits can mint too few or zero shares",
          "evidence": ["specific code signal"],
          "recommended_check": "attacker deposit, donate, victim deposit mints zero shares"
        }}
      ],
      "mitigations": ["virtual shares", "virtual assets", "dead shares"],
      "validation_tests": ["first depositor donation cannot force zero victim shares"],
      "recommended_tools": ["foundry", "echidna", "symbolic execution"],
      "confidence": 0.0,
      "evidence": ["specific vault signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate sequence-oracle plans; return vault share-math hardening
  surfaces and validation checks, not full transaction sequences.
- Do not duplicate snapshot fuzzing guidance; name state observables only when
  needed to justify a surface or check.
- Do not duplicate economic attack simulation; do not calculate attacker profit,
  capital, fees, or complete asset-flow formulas here.
- Do not rely on keyword-only or regex-only detection; cite semantic evidence
  from conversion formulas, preview functions, totalAssets, totalSupply, and
  deposit/mint guards.
- Do not claim a confirmed vulnerability without a first-depositor, donation,
  low-supply, preview mismatch, or zero-share validation path.
- Keep virtual shares/assets, dead shares, minimum shares, internal accounting,
  rounding direction, and direct donation assumptions explicit.

Existing findings, if any:
{findings_json}

Vault or ERC4626 summary, if any:
{summary_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _create2_deployment_hardening_prompt(
    source_code: str,
    findings: List[Any],
    deployment_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    summary_json = json.dumps(deployment_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build CREATE2 deployment hardening plans for defensive Solidity review.
Identify deterministic deployment surfaces such as create2 assembly calls,
new Contract{{salt: salt}}(...), predicted address helpers, wallet factories,
account-abstraction factories, minimal proxy factories, counterfactual funding
flows, and any path that trusts a precomputed address before code is deployed.
Focus on salt binding, init-code hash binding, factory authorization, deployment
front-running, address poisoning, codehash verification, collision checks,
counterfactual funds, cross-chain salt reuse, and selfdestruct/redeploy or
metamorphic assumptions.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "create2_deployment_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "CREATE2 deployment hardening goal",
      "surfaces": [
        {{
          "id": "factory_deploy",
          "deploy_function": "deploy",
          "factory_contract": "WalletFactory",
          "salt_source": "user supplied salt",
          "init_code_source": "abi.encodePacked(type(Wallet).creationCode, owner)",
          "address_formula": "keccak256(0xff, factory, salt, init_code_hash)",
          "authorization_guard": "salt includes msg.sender or owner",
          "collision_check": "predicted.code.length == 0 before deploy",
          "post_deploy_check": "deployed address and codehash verified",
          "redeploy_assumption": "no selfdestruct/redeploy trust",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "salt_squatting",
          "category": "predictable_salt|salt_squatting|front_run_deploy|init_code_mismatch|missing_codehash_check|address_poisoning|factory_auth_gap|counterfactual_funding|metamorphic_redeploy|cross_chain_replay",
          "affected_surface_id": "factory_deploy",
          "severity_hint": "high|medium|low",
          "description": "why deterministic deployment can be hijacked or mis-bound",
          "evidence": ["specific code signal"],
          "recommended_check": "attacker uses same salt before victim deploy"
        }}
      ],
      "mitigations": ["bind salt to owner", "verify init code hash", "check deployed codehash"],
      "validation_tests": ["front-run with same salt cannot capture expected address"],
      "recommended_tools": ["foundry", "slither", "fork simulation"],
      "confidence": 0.0,
      "evidence": ["specific deterministic deployment signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate metamorphic differential testing; this plan is about
  deployment surface hardening and address binding.
- Do not duplicate upgrade or delegatecall analysis; only mention implementation
  upgrades when they affect CREATE2 address trust.
- Do not rely on keyword-only or regex-only detection; cite semantic evidence
  from salt derivation, init-code construction, predicted address use, factory
  authorization, or post-deploy checks.
- Do not claim a confirmed vulnerability without a front-run deployment,
  salt-squatting, address-poisoning, init-code mismatch, or codehash validation
  path.
- Keep factory address, deployer, salt, chain id, owner, init-code hash,
  collision checks, codehash checks, and counterfactual funding assumptions explicit.

Existing findings, if any:
{findings_json}

Deployment or factory summary, if any:
{summary_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _abi_packed_hash_collision_hardening_prompt(
    source_code: str,
    findings: List[Any],
    hash_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    summary_json = json.dumps(hash_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build ABI packed hash collision hardening plans for defensive Solidity review.
Identify uses of keccak256(abi.encodePacked(...)), sha256/keccak packed inputs,
packed Merkle leaves, mapping keys, signature/message hashes, commitments,
identifiers, and authorization checks where multiple dynamic-length or
user-controlled arguments can be concatenated without length prefixes or
unambiguous domain separators.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "abi_packed_hash_collision_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "ABI packed hash collision hardening goal",
      "surfaces": [
        {{
          "id": "claim_hash",
          "hash_function": "claim",
          "packed_expression": "keccak256(abi.encodePacked(a, b))",
          "argument_types": ["string", "string"],
          "dynamic_argument_count": "2",
          "user_controlled_arguments": ["a", "b"],
          "hash_usage": "signature|mapping_key|authorization|commitment|message_id|identifier",
          "domain_separator": "chainId or contract address binding",
          "delimiter_or_length_guard": "none",
          "safer_encoding": "abi.encode(a, b)",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "dynamic_packed_collision",
          "category": "multiple_dynamic_args|user_controlled_packed_args|signature_collision|mapping_key_collision|auth_bypass|domain_collision|delimiter_absent|length_prefix_absent",
          "affected_surface_id": "claim_hash",
          "severity_hint": "high|medium|low",
          "description": "why different semantic inputs can hash to the same value",
          "evidence": ["specific code signal"],
          "recommended_check": "('a','bc') and ('ab','c') collide"
        }}
      ],
      "mitigations": ["use abi.encode", "add length prefixes", "bind domain"],
      "validation_tests": ["crafted dynamic inputs cannot collide"],
      "recommended_tools": ["foundry", "slither", "property testing"],
      "confidence": 0.0,
      "evidence": ["specific packed hash signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate signature-domain hardening; focus on ambiguous packed
  encoding and hash-collision surfaces, not general replay boundaries.
- Do not duplicate randomness or commit-reveal hardening; only mention
  commitments when packed dynamic inputs create ambiguous encodings.
- Do not duplicate cross-chain message hardening; focus on message-id encoding,
  not source-domain trust or bridge finality.
- Do not rely on keyword-only or regex-only detection; cite semantic evidence
  from argument types, user-controlled fields, packed expression, and hash usage.
- Do not claim a confirmed vulnerability without a crafted collision,
  property test, or concrete pair of shifted dynamic inputs.
- Prefer abi.encode, typed data, explicit length prefixes, fixed-size casts,
  delimiters, and domain binding when they fit the use case.

Existing findings, if any:
{findings_json}

Hash or ABI summary, if any:
{summary_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _token_hook_reentrancy_hardening_prompt(
    source_code: str,
    findings: List[Any],
    token_summary: Dict[str, Any],
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    summary_json = json.dumps(token_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build token hook reentrancy hardening plans for defensive Solidity review.
Focus on ERC-777, ERC-1363, ERC1820, transferAndCall, approveAndCall,
tokensReceived, tokensToSend, onTransferReceived, and onApprovalReceived paths
where a token callback can reenter protocol accounting, pricing, deposits,
withdrawals, claims, or authorization before effects are finalized.

Do not depend on a specific model, vendor, or external API. Return only JSON.
Treat plans as validation guidance, not confirmed vulnerabilities.

Return this shape:
{{
  "token_hook_reentrancy_hardening_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "token hook reentrancy hardening goal",
      "surfaces": [
        {{
          "id": "deposit_hook_surface",
          "entrypoint": "deposit",
          "token_standard": "ERC777|ERC1363|ERC1820",
          "hook_function": "tokensReceived|tokensToSend|onTransferReceived|onApprovalReceived",
          "external_token_call": "token.transferFrom(...)",
          "state_update_order": "external token call before balance update",
          "accounting_fields": ["balances", "totalSupply"],
          "expected_callback_sender": "trusted token contract",
          "guard": "nonReentrant or CEI",
          "evidence": ["specific code signal"]
        }}
      ],
      "risks": [
        {{
          "id": "hook_before_effects",
          "category": "hook_before_effects|callback_sender_unchecked|cross_function_reentry|read_only_reentry|erc1820_registry_confusion|erc1363_callback_reentry",
          "affected_surface_id": "deposit_hook_surface",
          "severity_hint": "high|medium|low",
          "description": "why token callback can reenter before accounting is final",
          "evidence": ["specific code signal"],
          "recommended_check": "malicious token hook reenters before balances update"
        }}
      ],
      "mitigations": ["checks-effects-interactions", "nonReentrant", "validate callback sender"],
      "validation_tests": ["malicious ERC777/ERC1363 hook cannot reenter accounting"],
      "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
      "confidence": 0.0,
      "evidence": ["specific hook signal"]
    }}
  ]
}}

Constraints:
- Do not duplicate generic reentrancy triage; focus on token-standard hooks and
  callbacks that execute during token transfers or approvals.
- Do not duplicate transient storage hardening; EIP-1153 lock design is out of
  scope unless it protects a token hook surface.
- Do not duplicate ERC4626 inflation hardening; only mention vaults when token
  hooks reenter share accounting before effects are final.
- Require concrete callback evidence, expected callback sender, accounting
  fields, and state-update ordering before producing a risk.
- Prefer CEI, nonReentrant, pull accounting, callback sender validation,
  trusted-token allowlists, and malicious token hook tests.

Existing findings, if any:
{findings_json}

Token or hook summary, if any:
{summary_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _semantic_graph_gate_prompt(
    source_code: str,
    findings: List[Any],
    ir_summary: Dict[str, Any],
    max_nodes: int,
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    ir_json = json.dumps(ir_summary, sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Build semantic graph gating plans for defensive smart-contract analysis.
Represent the most security-relevant functions, state variables, modifiers,
external calls, roles, events, and data/control dependencies as a compact graph.
Use that graph to choose focal nodes and recommend downstream tools such as
static analysis, symbolic execution, fuzzing, formal checks, or agentic review.

Do not depend on a specific model, vendor, or external API. Return only JSON.

Return this shape:
{{
  "semantic_graph_gates": [
    {{
      "id": "short_stable_identifier",
      "objective": "analysis goal",
      "target_vulnerability_types": ["access_control"],
      "focal_nodes": ["fn_withdraw"],
      "nodes": [
        {{
          "id": "fn_withdraw",
          "kind": "function|state_var|modifier|external_call|event|role",
          "label": "withdraw(uint256)",
          "contract": "Vault",
          "function": "withdraw",
          "line": 42,
          "metadata": {{}}
        }}
      ],
      "edges": [
        {{
          "source": "fn_withdraw",
          "target": "state_balances",
          "relation": "writes|reads|calls|guards|authorizes|emits",
          "confidence": 0.0,
          "evidence": ["specific code signal"]
        }}
      ],
      "graph_queries": ["query or rule description to validate"],
      "recommended_tools": ["slither", "mythril", "halmos", "foundry"],
      "confidence": 0.0,
      "rationale": "why this graph focus matters"
    }}
  ]
}}

Constraints:
- Use at most {max_nodes} nodes.
- Keep graph nodes stable and short; they may be used as focal-context anchors.
- Treat graph gates as prioritization hypotheses, not confirmed findings.
- Prefer explainable relations over opaque scores.

Existing findings, if any:
{findings_json}

IR or call/data dependency summary, if any:
{ir_json}

Solidity source:
```solidity
{source_code}
```
"""
    return prompt[:MAX_AGENT_PROMPT_CHARS]


def _sequence_oracle_prompt(
    source_code: str,
    findings: List[Any],
    invariants: List[Dict[str, Any]],
    max_sequence_length: int,
) -> str:
    findings_json = json.dumps(findings[:25], sort_keys=True)
    invariants_json = json.dumps(invariants[:25], sort_keys=True)
    prompt = f"""You are an interchangeable security reasoning agent.

Synthesize stateful transaction-sequence oracle plans for defensive
smart-contract validation. Focus on vulnerabilities that are missed by
single-call pattern matching: accounting drift, oracle manipulation, share-price
inflation, liquidation edge cases, governance replay, stuck funds, and
multi-step access-control bypasses.

Do not depend on a specific model, vendor, or external API. Return only JSON.

Return this shape:
{{
  "sequence_oracle_plans": [
    {{
      "id": "short_stable_identifier",
      "objective": "bug hypothesis to validate",
      "invariant_id": "related invariant id, if any",
      "vulnerability_types": ["oracle_manipulation"],
      "sequence": [
        {{
          "function": "functionName",
          "actor": "attacker|victim|owner|liquidator|any",
          "arguments": ["symbolic or concrete argument hints"],
          "value_hint": "msg.value or token amount hint",
          "precondition": "state requirement before this call",
          "expected_effect": "state change expected after this call"
        }}
      ],
      "oracle": "failure condition to assert or falsify",
      "recommended_tools": ["foundry", "echidna", "halmos"],
      "confidence": 0.0,
      "evidence": ["specific code signal"]
    }}
  ]
}}

Constraints:
- Use at most {max_sequence_length} transaction steps per plan.
- Prefer plans that can become Foundry invariant tests, Echidna stateful
  properties, Halmos symbolic checks, or bounded re-scan evidence.
- Keep assumptions explicit; do not claim a bug without an oracle.

Existing findings, if any:
{findings_json}

Candidate invariants, if any:
{invariants_json}

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


def _bounded_nonnegative_int(value: Any, default: int) -> int:
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
    "AbiPackedHashCollisionHardeningAgent",
    "AbiPackedHashCollisionHardeningPlan",
    "AbiPackedHashRisk",
    "AbiPackedHashSurface",
    "AdversarialOrderingPlan",
    "AdversarialTransactionOrderingAgent",
    "AssetFlow",
    "CapitalRequirement",
    "CounterexampleEvidence",
    "Create2DeploymentHardeningAgent",
    "Create2DeploymentHardeningPlan",
    "Create2DeploymentRisk",
    "Create2DeploymentSurface",
    "CrossChainMessageFlow",
    "CrossChainMessageHardeningAgent",
    "CrossChainMessageHardeningPlan",
    "CrossChainMessageRisk",
    "DelegatecallAliasRisk",
    "DelegatecallStorageAliasingAgent",
    "DelegatecallStorageAliasingPlan",
    "DelegatecallSurface",
    "DPGAgentConfig",
    "DifferentialTestPlan",
    "EconomicAttackPlan",
    "EconomicAttackSimulationAgent",
    "ERC4626VaultInflationHardeningAgent",
    "ERC4626VaultInflationHardeningPlan",
    "InvariantCandidate",
    "InvariantCategory",
    "InvariantExtractionAgent",
    "MetamorphicDiffTestingAgent",
    "MetamorphicRelation",
    "OracleFeedHardeningAgent",
    "OracleFeedHardeningPlan",
    "OracleFeedRisk",
    "OracleFeedSource",
    "OrderingRisk",
    "OrderingTransaction",
    "RandomnessEntropyHardeningAgent",
    "RandomnessEntropyHardeningPlan",
    "RandomnessRisk",
    "RandomnessSource",
    "ReasoningProvider",
    "ReasoningResult",
    "ReasoningTask",
    "SemanticGraphEdge",
    "SemanticGraphGate",
    "SemanticGraphGateAgent",
    "SemanticGraphNode",
    "SignatureDomainHardeningAgent",
    "SignatureDomainHardeningPlan",
    "SignatureDomainRisk",
    "SignedAction",
    "FuzzingWaypoint",
    "SnapshotFuzzingAgent",
    "SnapshotFuzzingPlan",
    "SnapshotSeed",
    "StorageAliasPath",
    "StorageLayoutChange",
    "TokenHookReentrancyHardeningAgent",
    "TokenHookReentrancyHardeningPlan",
    "TokenHookReentrancyRisk",
    "TokenHookSurface",
    "UpgradeEvolutionAnalysisAgent",
    "UpgradeEvolutionPlan",
    "UpgradeRisk",
    "VaultInflationRisk",
    "VaultShareSurface",
    "SequenceOracleAgent",
    "SequenceOraclePlan",
    "SequenceStep",
    "parse_invariant_candidates",
    "parse_adversarial_transaction_ordering_plans",
    "parse_abi_packed_hash_collision_hardening_plans",
    "parse_create2_deployment_hardening_plans",
    "parse_cross_chain_message_hardening_plans",
    "parse_delegatecall_storage_aliasing_plans",
    "parse_differential_test_plans",
    "parse_economic_attack_plans",
    "parse_erc4626_vault_inflation_hardening_plans",
    "parse_oracle_feed_hardening_plans",
    "parse_randomness_entropy_hardening_plans",
    "parse_semantic_graph_gates",
    "parse_snapshot_fuzzing_plans",
    "parse_sequence_oracle_plans",
    "parse_signature_domain_hardening_plans",
    "parse_token_hook_reentrancy_hardening_plans",
    "parse_upgrade_evolution_plans",
]
