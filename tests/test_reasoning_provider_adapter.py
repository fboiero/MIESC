"""Tests for replaceable agentic reasoning provider adapters."""

import pytest

from miesc.llm import (
    LLMOrchestratorReasoningProvider as ExportedLLMOrchestratorReasoningProvider,
)
from miesc.llm import (
    LocalHeuristicReasoningProvider as ExportedLocalHeuristicReasoningProvider,
)
from miesc.llm import (
    ReasoningProviderRoute as ExportedReasoningProviderRoute,
)
from miesc.llm import (
    auto_reasoning_provider as exported_auto_reasoning_provider,
)
from miesc.llm.agentic_contracts import (
    AbiPackedHashCollisionHardeningAgent,
    AdversarialTransactionOrderingAgent,
    AgentCapability,
    Create2DeploymentHardeningAgent,
    CrossChainMessageHardeningAgent,
    DelegatecallStorageAliasingAgent,
    DPGAgentConfig,
    EconomicAttackSimulationAgent,
    ERC4626VaultInflationHardeningAgent,
    InvariantExtractionAgent,
    MetamorphicDiffTestingAgent,
    OracleFeedHardeningAgent,
    ReasoningTask,
    SemanticGraphGateAgent,
    SequenceOracleAgent,
    SnapshotFuzzingAgent,
    UpgradeEvolutionAnalysisAgent,
)
from miesc.llm.llm_orchestrator import LLMResponse
from miesc.llm.reasoning_provider_adapter import (
    LLMOrchestratorReasoningProvider,
    LocalHeuristicReasoningProvider,
    ReasoningProviderRoute,
    auto_reasoning_provider,
)


class FakeOrchestrator:
    primary_provider = "local:test-agent"

    def __init__(self, content):
        self.content = content
        self.seen_prompt = None
        self.seen_context = None
        self.seen_provider = None

    async def query(self, prompt, context=None, provider=None):
        self.seen_prompt = prompt
        self.seen_context = context
        self.seen_provider = provider
        return LLMResponse(
            content=self.content,
            provider="local",
            model="test-agent",
            tokens_used=12,
            latency_ms=3.5,
        )


class CustomResponseOrchestrator:
    primary_provider = "local:test-agent"

    def __init__(self, response):
        self.response = response
        self.seen_provider = None

    async def query(self, _prompt, context=None, provider=None):
        self.seen_provider = provider
        return self.response


def test_llm_orchestrator_provider_returns_reasoning_result_from_json():
    orchestrator = FakeOrchestrator("""
        ```json
        {"invariants": [{"statement": "totalAssets covers totalSupply"}]}
        ```
        """)
    provider = LLMOrchestratorReasoningProvider(
        orchestrator,
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"statement": "totalAssets covers totalSupply"}]}
    assert result.provider_kind == "local"
    assert result.implementation_label == "test-agent"
    assert result.local is True
    assert result.metadata["backend_key"] == "local:test-agent"
    assert orchestrator.seen_provider == "local:test-agent"
    assert orchestrator.seen_context["capability"] == "invariant_extraction"


def test_llm_orchestrator_provider_blocks_remote_when_policy_disallows_it():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="remote:test-agent",
            provider_kind="remote",
            implementation_label="test-agent",
            local=False,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    with pytest.raises(ValueError, match="Remote reasoning is disabled"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_requires_replaceable_policy():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(require_replaceable_provider=False),
    )

    with pytest.raises(ValueError, match="replaceable provider contract"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_parses_embedded_json_object():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('analysis follows {"invariants": [{"id": "accounting"}]} done'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "accounting"}]}


def test_llm_orchestrator_provider_uses_later_parseable_fenced_json():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("""
            ```solidity
            contract NotJson {}
            ```
            ```json
            {"invariants": [{"id": "later_json"}]}
            ```
            """),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "later_json"}]}


def test_llm_orchestrator_provider_skips_non_json_bracket_prefix():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('note [not-json] then {"invariants": [{"id": "object"}]}'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": [{"id": "object"}]}


def test_llm_orchestrator_provider_parses_embedded_json_with_trailing_brace():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('prefix {"invariants": []} trailing }'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"invariants": []}


def test_llm_orchestrator_provider_wraps_json_array_response():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('[{"statement": "supply is capped"}]'),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {"items": [{"statement": "supply is capped"}]}


def test_llm_orchestrator_provider_rejects_malformed_json_response():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("this is not json"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {}


@pytest.mark.asyncio
async def test_sync_llm_orchestrator_provider_rejects_active_event_loop():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    with pytest.raises(RuntimeError, match="active event loop"):
        provider.complete_json(task)
    assert provider.orchestrator.seen_prompt is None


def test_local_heuristic_provider_extracts_replaceable_invariants():
    provider = LocalHeuristicReasoningProvider()
    agent = InvariantExtractionAgent(provider)

    invariants = agent.extract("""
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            uint256 public cap;
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function deposit(uint256 amount) external {}
            function mint(uint256 amount) external onlyOwner {}
        }
        """)

    categories = {candidate.category.value for candidate in invariants}
    assert "accounting" in categories
    assert "cap_boundary" in categories
    assert "access_control" in categories
    assert all(candidate.confidence > 0 for candidate in invariants)


def test_local_heuristic_provider_synthesizes_share_price_sequence_oracle():
    provider = LocalHeuristicReasoningProvider()
    agent = SequenceOracleAgent(provider)

    plans = agent.synthesize(
        """
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function donate(uint256 assets) external {}
            function deposit(uint256 assets) external {}
            function convertToShares(uint256 assets) public view returns (uint256) {}
        }
        """,
        max_sequence_length=2,
    )

    assert plans
    plan = plans[0]
    assert "share_price_inflation" in plan.vulnerability_types
    assert [step.function for step in plan.sequence] == ["donate", "deposit"]
    assert len(plan.sequence) <= 2
    assert plan.oracle
    assert {"foundry", "echidna", "halmos"}.issubset(set(plan.recommended_tools))


def test_local_heuristic_provider_synthesizes_oracle_manipulation_sequence():
    provider = LocalHeuristicReasoningProvider()
    agent = SequenceOracleAgent(provider)

    plans = agent.synthesize("""
        contract LendingPool {
            function getReserves() public view returns (uint256) {}
            function swap(uint256 amount) external {}
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
            function price() public view returns (uint256) {}
        }
        """)

    assert any("oracle_manipulation" in plan.vulnerability_types for plan in plans)
    oracle_plan = next(plan for plan in plans if "oracle_manipulation" in plan.vulnerability_types)
    assert [step.function for step in oracle_plan.sequence] == ["swap", "borrow"]
    assert oracle_plan.confidence > 0


def test_local_heuristic_provider_reports_sequence_metadata_and_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.SEQUENCE_ORACLE_SYNTHESIS,
        objective="synthesize sequence oracles",
        prompt="contract Plain { function ping() external {} }",
        inputs={"max_sequence_length": 1},
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"sequence_oracle_plans": []}
    assert result.metadata == {"strategy": "regex_sequence_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_access_control_semantic_graph_gate():
    provider = LocalHeuristicReasoningProvider()
    agent = SemanticGraphGateAgent(provider)

    gates = agent.build_gate(
        """
        contract Vault {
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function withdraw(uint256 amount) external {
                payable(msg.sender).transfer(amount);
            }
            function setOwner(address next) external onlyOwner {
                owner = next;
            }
        }
        """,
        max_nodes=1,
    )

    gate = next(gate for gate in gates if "access_control" in gate.target_vulnerability_types)
    assert gate.focal_nodes
    assert len(gate.nodes) <= 1
    assert any(node.kind == "function" for node in gate.nodes)
    assert gate.edges
    assert gate.graph_queries
    assert {"slither", "mythril", "halmos", "foundry"}.issubset(set(gate.recommended_tools))
    assert gate.confidence > 0


def test_local_heuristic_provider_synthesizes_external_call_semantic_graph_gate():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.SEMANTIC_GRAPH_GATING,
        objective="build graph gates",
        prompt="""
        ```solidity
        contract Executor {
            function execute(address target, bytes calldata data) external {
                (bool ok,) = target.call(data);
                require(ok);
            }
        }
        ```
        """,
        inputs={"max_nodes": 5},
    )

    result = provider.complete_json(task)

    assert result.metadata == {
        "strategy": "regex_semantic_graph_signals",
        "count": len(result.data["semantic_graph_gates"]),
    }
    gate = next(
        gate
        for gate in result.data["semantic_graph_gates"]
        if "reentrancy" in gate["target_vulnerability_types"]
    )
    assert gate["nodes"]
    assert gate["edges"][0]["relation"] == "calls"
    assert gate["focal_nodes"] == ["fn_execute"]


def test_local_heuristic_provider_synthesizes_oracle_semantic_graph_gate():
    provider = LocalHeuristicReasoningProvider()
    agent = SemanticGraphGateAgent(provider)

    gates = agent.build_gate("""
        contract LendingPool {
            function price() public view returns (uint256) {}
            function getReserves() public view returns (uint256) {}
            function swap(uint256 amount) external {}
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
        }
        """)

    gate = next(gate for gate in gates if "oracle_manipulation" in gate.target_vulnerability_types)
    assert gate.edges[0].relation == "reads"
    assert any(node.kind == "oracle" for node in gate.nodes)


def test_local_heuristic_provider_reports_semantic_graph_metadata_and_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.SEMANTIC_GRAPH_GATING,
        objective="build graph gates",
        prompt="contract Plain { function ping() external {} }",
        inputs={"max_nodes": 1},
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"semantic_graph_gates": []}
    assert result.metadata == {"strategy": "regex_semantic_graph_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_share_price_snapshot_fuzzing_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = SnapshotFuzzingAgent(provider)

    plans = agent.plan(
        """
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function donate(uint256 assets) external {}
            function deposit(uint256 assets) external {}
            function convertToShares(uint256 assets) public view returns (uint256) {}
        }
        """,
        max_snapshots=1,
    )

    assert plans
    plan = plans[0]
    assert "share_price_inflation" in plan.target_vulnerability_types
    assert len(plan.seeds) == 1
    assert plan.seeds[0].setup_sequence[0].function == "deposit"
    assert plan.waypoints[0].kind == "dataflow"
    assert plan.priority_transactions[0].function == "donate"
    assert plan.oracle
    assert {"foundry", "echidna", "medusa", "ityfuzz"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_snapshot_metadata_and_bounds_seeds():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.SNAPSHOT_FUZZING_GUIDANCE,
        objective="build snapshot fuzzing plans",
        prompt="""
        ```solidity
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function donate(uint256 assets) external {}
            function deposit(uint256 assets) external {}
            function previewDeposit(uint256 assets) public view returns (uint256) {}
        }
        ```
        """,
        inputs={"max_snapshots": 1},
    )

    result = provider.complete_json(task)

    assert result.metadata == {
        "strategy": "regex_snapshot_fuzzing_signals",
        "count": len(result.data["snapshot_fuzzing_plans"]),
    }
    plan = result.data["snapshot_fuzzing_plans"][0]
    assert len(plan["seeds"]) == 1
    assert plan["seeds"][0]["setup_sequence"][0]["function"] == "deposit"
    assert plan["priority_transactions"][0]["function"] == "donate"


def test_local_heuristic_provider_synthesizes_oracle_snapshot_fuzzing_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = SnapshotFuzzingAgent(provider)

    plans = agent.plan("""
        contract LendingPool {
            function price() public view returns (uint256) {}
            function getReserves() public view returns (uint256) {}
            function swap(uint256 amount) external {}
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
        }
        """)

    plan = next(plan for plan in plans if "oracle_manipulation" in plan.target_vulnerability_types)
    assert plan.seeds[0].id == "seed_after_price_move"
    assert plan.waypoints[0].kind == "oracle"
    assert plan.priority_transactions[0].function == "borrow"


def test_local_heuristic_provider_synthesizes_liquidation_snapshot_fuzzing_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = SnapshotFuzzingAgent(provider)

    plans = agent.plan("""
        contract Liquidator {
            uint256 public collateral;
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
            function health(address user) public view returns (uint256) {}
        }
        """)

    plan = next(
        plan for plan in plans if "liquidation_edge_case" in plan.target_vulnerability_types
    )
    assert plan.seeds[0].setup_sequence[0].function == "borrow"
    assert plan.waypoints[0].kind == "branch"
    assert plan.priority_transactions[0].function == "liquidate"


def test_local_heuristic_provider_reports_snapshot_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.SNAPSHOT_FUZZING_GUIDANCE,
        objective="build snapshot fuzzing plans",
        prompt="contract Plain { function ping() external {} }",
        inputs={"max_snapshots": 1},
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"snapshot_fuzzing_plans": []}
    assert result.metadata == {"strategy": "regex_snapshot_fuzzing_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_oracle_economic_attack_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = EconomicAttackSimulationAgent(provider)

    plans = agent.plan("""
        contract LendingPool {
            function price() public view returns (uint256) {}
            function getReserves() public view returns (uint256) {}
            function swap(uint256 amount) external {}
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
        }
        """)

    plan = next(plan for plan in plans if "oracle_manipulation" in plan.target_vulnerability_types)
    assert plan.capital_requirements[0].source == "flash_loan"
    assert plan.asset_flows
    assert "borrowed_value" in plan.profit_formula
    assert plan.cost_model
    assert plan.liquidity_assumptions
    assert plan.oracle_price_assumptions
    assert plan.break_even_threshold
    assert plan.risk_factors
    assert {"foundry", "anvil", "fork-simulation"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_economic_metadata_and_plan_ids():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.ECONOMIC_ATTACK_SIMULATION,
        objective="build economic attack plans",
        prompt="""
        ```solidity
        contract LendingPool {
            function getReserves() public view returns (uint256) {}
            function swap(uint256 amount) external {}
            function borrow(uint256 amount) external {}
            function price() public view returns (uint256) {}
        }
        ```
        """,
        inputs={
            "sequence_plans": [{"id": "oracle_sequence"}],
            "snapshot_plans": [{"id": "oracle_snapshot"}],
            "graph_gates": [{"id": "oracle_gate"}],
        },
    )

    result = provider.complete_json(task)

    assert result.metadata == {
        "strategy": "regex_economic_attack_signals",
        "count": len(result.data["economic_attack_plans"]),
    }
    plan = result.data["economic_attack_plans"][0]
    assert plan["base_sequence_plan_ids"] == ["oracle_sequence"]
    assert plan["base_snapshot_plan_ids"] == ["oracle_snapshot"]
    assert plan["base_graph_gate_ids"] == ["oracle_gate"]
    assert plan["capital_requirements"]
    assert plan["asset_flows"]


def test_local_heuristic_provider_synthesizes_share_inflation_economic_attack_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = EconomicAttackSimulationAgent(provider)

    plans = agent.plan("""
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function donate(uint256 assets) external {}
            function deposit(uint256 assets) external {}
            function previewDeposit(uint256 assets) public view returns (uint256) {}
        }
        """)

    plan = next(
        plan for plan in plans if "share_price_inflation" in plan.target_vulnerability_types
    )
    assert plan.capital_requirements[0].source == "attacker_capital"
    assert any(flow.step_id == "donate" for flow in plan.asset_flows)
    assert "redeemable_assets" in plan.profit_formula
    assert plan.expected_profit_range


def test_local_heuristic_provider_synthesizes_liquidation_economic_attack_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = EconomicAttackSimulationAgent(provider)

    plans = agent.plan("""
        contract Liquidator {
            uint256 public collateral;
            function borrow(uint256 amount) external {}
            function liquidate(address user, uint256 repay) external {}
            function health(address user) public view returns (uint256) {}
        }
        """)

    plan = next(
        plan for plan in plans if "liquidation_edge_case" in plan.target_vulnerability_types
    )
    assert plan.capital_requirements[0].asset == "DEBT"
    assert any(flow.to_actor == "liquidator" for flow in plan.asset_flows)
    assert "seized_collateral_value" in plan.profit_formula
    assert plan.break_even_threshold
    assert plan.risk_factors


def test_local_heuristic_provider_reports_economic_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.ECONOMIC_ATTACK_SIMULATION,
        objective="build economic attack plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"economic_attack_plans": []}
    assert result.metadata == {"strategy": "regex_economic_attack_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_split_merge_differential_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = MetamorphicDiffTestingAgent(provider)

    plans = agent.plan("""
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function deposit(uint256 assets) external {}
            function withdraw(uint256 assets) external {}
            function convertToShares(uint256 assets) public view returns (uint256) {}
        }
        """)

    plan = next(
        plan for plan in plans if "share_price_inflation" in plan.target_vulnerability_types
    )
    relation = plan.relations[0]
    assert relation.relation_type == "split_merge"
    assert relation.baseline_sequence[0].function == "deposit"
    assert [step.function for step in relation.variant_sequence] == ["deposit", "deposit"]
    assert plan.state_observables
    assert plan.oracle
    assert {"foundry", "echidna", "halmos"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_metamorphic_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.METAMORPHIC_DIFF_TESTING,
        objective="build metamorphic plans",
        prompt="""
        ```solidity
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function deposit(uint256 assets) external {}
            function previewDeposit(uint256 assets) public view returns (uint256) {}
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"differential_test_plans"}
    assert result.metadata == {
        "strategy": "regex_metamorphic_diff_signals",
        "count": len(result.data["differential_test_plans"]),
    }
    relation = result.data["differential_test_plans"][0]["relations"][0]
    assert relation["baseline_sequence"][0]["function"] == "deposit"
    assert relation["variant_sequence"][1]["function"] == "deposit"


def test_local_heuristic_provider_synthesizes_borrow_repay_differential_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = MetamorphicDiffTestingAgent(provider)

    plans = agent.plan("""
        contract LendingPool {
            function borrow(uint256 amount) external {}
            function repay(uint256 amount) external {}
            function debt(address user) public view returns (uint256) {}
            function collateral(address user) public view returns (uint256) {}
            function health(address user) public view returns (uint256) {}
        }
        """)

    plan = next(
        plan for plan in plans if "debt_accounting_drift" in plan.target_vulnerability_types
    )
    relation = plan.relations[0]
    assert relation.relation_type == "round_trip"
    assert [step.function for step in relation.variant_sequence] == ["borrow", "repay"]
    assert "debtOf(user)" in plan.state_observables


def test_local_heuristic_provider_synthesizes_transfer_commutativity_differential_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = MetamorphicDiffTestingAgent(provider)

    plans = agent.plan("""
        contract Token {
            function transfer(address to, uint256 amount) external {}
            function balanceOf(address user) public view returns (uint256) {}
            function totalSupply() public view returns (uint256) {}
        }
        """)

    plan = next(plan for plan in plans if plan.id == "independent_transfer_commutativity_plan")
    relation = plan.relations[0]
    assert relation.relation_type == "commutative"
    assert [step.function for step in relation.baseline_sequence] == ["transfer", "transfer"]
    assert [step.function for step in relation.variant_sequence] == ["transfer", "transfer"]


def test_local_heuristic_provider_reports_metamorphic_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.METAMORPHIC_DIFF_TESTING,
        objective="build metamorphic plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"differential_test_plans": []}
    assert result.metadata == {"strategy": "regex_metamorphic_diff_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_upgrade_storage_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = UpgradeEvolutionAnalysisAgent(provider)

    plans = agent.plan(
        "contract VaultV1 { address owner; uint256 totalAssets; }",
        """
        contract VaultV2 {
            bool openForSale;
            address owner;
            function initializeV2() public {}
            function _authorizeUpgrade(address newImplementation) internal {}
            function proxiableUUID() external view returns (bytes32) {}
        }
        """,
        storage_layout_before={"0": "address owner", "1": "uint256 totalAssets"},
        storage_layout_after={"0": "bool openForSale", "1": "address owner"},
    )

    assert plans
    plan = plans[0]
    assert plan.proxy_pattern == "uups"
    assert plan.storage_changes[0].slot == "0"
    assert plan.storage_changes[0].change_type == "type_change"
    assert any(risk.category == "storage_layout" for risk in plan.risks)
    assert any(risk.category == "initializer" for risk in plan.risks)
    assert any(risk.category == "admin" for risk in plan.risks)
    assert plan.migration_checks
    assert {"openzeppelin-upgrades", "slither", "foundry"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_upgrade_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.UPGRADE_EVOLUTION_ANALYSIS,
        objective="build upgrade plans",
        prompt="""
        ```solidity
        contract Proxy {
            address implementation;
            fallback() external { implementation.delegatecall(msg.data); }
        }
        ```
        ```solidity
        contract VaultV2 { function initializeV2() public {} }
        ```
        """,
        inputs={
            "storage_layout_before": {"0": "address owner"},
            "storage_layout_after": {"0": "bool paused"},
        },
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"upgrade_evolution_plans"}
    assert result.metadata == {
        "strategy": "regex_upgrade_evolution_signals",
        "count": len(result.data["upgrade_evolution_plans"]),
    }
    plan = result.data["upgrade_evolution_plans"][0]
    assert plan["proxy_pattern"] == "custom"
    assert plan["storage_changes"][0]["slot"] == "0"
    assert plan["storage_changes"][0]["change_type"] == "type_change"
    assert plan["risks"]
    assert plan["migration_checks"]


def test_local_heuristic_provider_reports_upgrade_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.UPGRADE_EVOLUTION_ANALYSIS,
        objective="build upgrade plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"upgrade_evolution_plans": []}
    assert result.metadata == {"strategy": "regex_upgrade_evolution_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_cross_chain_message_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = CrossChainMessageHardeningAgent(provider)

    plans = agent.plan(
        """
        contract BridgeReceiver {
            mapping(uint16 => bytes32) public trustedRemote;
            mapping(bytes32 => bool) public processedMessages;
            function lzReceive(
                uint16 srcChainId,
                bytes calldata srcAddress,
                uint64 nonce,
                bytes calldata payload
            ) external {
                bytes32 messageId = keccak256(abi.encode(srcChainId, srcAddress, nonce, payload));
                require(!processedMessages[messageId], "replay");
                processedMessages[messageId] = true;
            }
        }
        """,
        bridge_summary={"handlers": ["lzReceive"]},
    )

    assert plans
    plan = plans[0]
    assert plan.message_flows[0].handler_function == "lzReceive"
    assert plan.message_flows[0].source_domain == "srcChainId"
    assert plan.message_flows[0].trusted_sender_source == "trustedRemote[srcChainId]"
    assert plan.message_flows[0].message_id_source == "messageId"
    assert plan.message_flows[0].replay_guard == "processedMessages[messageId]"
    assert any(test == "replay consumed message id must revert" for test in plan.validation_tests)
    assert any(test == "spoofed remote sender must revert" for test in plan.validation_tests)
    assert {"foundry", "bridgefuzz", "slither"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_cross_chain_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING,
        objective="build cross-chain message plans",
        prompt="""
        ```solidity
        contract Outbox {
            function executeMessage(bytes32 messageHash, bytes calldata payload) external {
                _execute(payload);
            }
        }
        ```
        """,
        inputs={"bridge_summary": {"handlers": ["executeMessage"]}},
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"cross_chain_message_hardening_plans"}
    assert result.metadata == {
        "strategy": "regex_cross_chain_message_signals",
        "count": len(result.data["cross_chain_message_hardening_plans"]),
    }
    plan = result.data["cross_chain_message_hardening_plans"][0]
    assert plan["message_flows"][0]["handler_function"] == "executeMessage"
    assert plan["message_flows"][0]["message_id_source"] == "messageHash"
    assert any(risk["category"] == "replay_guard" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_cross_chain_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING,
        objective="build cross-chain message plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"cross_chain_message_hardening_plans": []}
    assert result.metadata == {"strategy": "regex_cross_chain_message_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_delegatecall_aliasing_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = DelegatecallStorageAliasingAgent(provider)

    plans = agent.plan(
        """
        contract DelegatingVault {
            address public owner;
            address public implementation;
            fallback() external payable {
                (bool ok,) = implementation.delegatecall(msg.data);
                require(ok, "delegate failed");
            }
        }
        """,
        layout_summary={"caller_slots": {"0": "address owner", "1": "address implementation"}},
        callee_summary={"callee_slots": {"0": "bool initialized", "1": "address owner"}},
    )

    assert plans
    plan = plans[0]
    assert plan.delegatecall_surfaces[0].caller_function == "fallback"
    assert plan.delegatecall_surfaces[0].target_source == "implementation"
    assert plan.delegatecall_surfaces[0].selector_source == "msg.data selector forwarded to callee"
    assert plan.storage_alias_paths[0].caller_slot == "slot 0"
    assert plan.storage_alias_paths[0].callee_slot == "slot 0"
    assert any(risk.category == "storage_collision" for risk in plan.risks)
    assert any(risk.category == "selector_control" for risk in plan.risks)
    assert any("caller slot 0" in test for test in plan.validation_tests)
    assert {"foundry", "slither", "symbolic execution"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_delegatecall_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.DELEGATECALL_STORAGE_ALIASING,
        objective="build delegatecall aliasing plans",
        prompt="""
        ```solidity
        contract Router {
            function execute(address target, bytes calldata data) external {
                target.delegatecall(data);
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"delegatecall_storage_aliasing_plans"}
    assert result.metadata == {
        "strategy": "regex_delegatecall_storage_aliasing_signals",
        "count": len(result.data["delegatecall_storage_aliasing_plans"]),
    }
    plan = result.data["delegatecall_storage_aliasing_plans"][0]
    assert plan["delegatecall_surfaces"][0]["caller_function"] == "execute"
    assert plan["delegatecall_surfaces"][0]["target_source"] == "target"
    assert any(risk["category"] == "target_control" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_delegatecall_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.DELEGATECALL_STORAGE_ALIASING,
        objective="build delegatecall aliasing plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"delegatecall_storage_aliasing_plans": []}
    assert result.metadata == {
        "strategy": "regex_delegatecall_storage_aliasing_signals",
        "count": 0,
    }
    assert result.local is True


def test_local_heuristic_provider_synthesizes_oracle_feed_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = OracleFeedHardeningAgent(provider)

    plans = agent.plan(
        """
        interface AggregatorV3Interface {
            function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
            function decimals() external view returns (uint8);
        }
        contract OracleConsumer {
            AggregatorV3Interface public priceFeed;
            uint256 public maxDelay;
            function getPrice() external view returns (uint256) {
                (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
                require(block.timestamp - updatedAt <= maxDelay, "stale");
                require(answer > 0, "bad price");
                return uint256(answer) * 1e18 / (10 ** priceFeed.decimals());
            }
        }
        """,
        oracle_summary={"feeds": ["ETH/USD"]},
    )

    assert plans
    plan = plans[0]
    assert plan.feeds[0].consumer_function == "getPrice"
    assert plan.feeds[0].feed_kind == "chainlink"
    assert plan.feeds[0].read_method == "latestRoundData"
    assert plan.feeds[0].freshness_source == "updatedAt"
    assert plan.feeds[0].staleness_threshold == "maxDelay"
    assert plan.feeds[0].normalization == "scale to 1e18"
    assert "price > 0" in plan.feeds[0].bounds_check
    assert any(risk.category == "incomplete_round" for risk in plan.risks)
    assert "stale updatedAt must revert" in plan.validation_tests
    assert {"foundry", "slither", "symbolic execution"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_oracle_feed_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.ORACLE_FEED_HARDENING,
        objective="build oracle feed plans",
        prompt="""
        ```solidity
        contract Borrower {
            AggregatorV3Interface public priceFeed;
            function collateralValue() external view returns (uint256) {
                (, int256 answer,,,) = priceFeed.latestRoundData();
                return uint256(answer);
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"oracle_feed_hardening_plans"}
    assert result.metadata == {
        "strategy": "regex_oracle_feed_hardening_signals",
        "count": len(result.data["oracle_feed_hardening_plans"]),
    }
    plan = result.data["oracle_feed_hardening_plans"][0]
    assert plan["feeds"][0]["read_method"] == "latestRoundData"
    assert any(risk["category"] == "stale_round" for risk in plan["risks"])
    assert any(risk["category"] == "zero_negative_price" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_oracle_feed_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.ORACLE_FEED_HARDENING,
        objective="build oracle feed plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"oracle_feed_hardening_plans": []}
    assert result.metadata == {"strategy": "regex_oracle_feed_hardening_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_adversarial_ordering_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = AdversarialTransactionOrderingAgent(provider)

    plans = agent.plan(
        """
        contract Router {
            uint256 public reserveIn;
            uint256 public reserveOut;
            function swap(uint256 amountIn) external returns (uint256 amountOut) {
                amountOut = amountIn * reserveOut / reserveIn;
                reserveIn += amountIn;
                reserveOut -= amountOut;
            }
        }
        """,
        market_summary={"liquidity": "constant product", "sequence_plan_ids": ["swap_sequence"]},
    )

    assert plans
    plan = plans[0]
    assert plan.ordering_pattern == "sandwich"
    assert [tx.role for tx in plan.transactions[:2]] == ["attacker_front", "victim"]
    assert plan.transactions[0].function == "swap"
    assert plan.transactions[1].state_dependency == "pool reserves"
    assert any(risk.category == "slippage_gap" for risk in plan.risks)
    assert any(risk.category == "front_run" for risk in plan.risks)
    assert "private routing" in plan.mitigations
    assert any("front-run" in test for test in plan.validation_tests)
    assert {"foundry", "mev simulation", "sequence oracle"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_adversarial_ordering_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING,
        objective="build ordering plans",
        prompt="""
        ```solidity
        contract Router {
            function swap(uint256 amountIn, uint256 amountOutMin, uint256 deadline) external {
                reserves = getReserves();
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"adversarial_transaction_ordering_plans"}
    assert result.metadata == {
        "strategy": "regex_adversarial_transaction_ordering_signals",
        "count": len(result.data["adversarial_transaction_ordering_plans"]),
    }
    plan = result.data["adversarial_transaction_ordering_plans"][0]
    assert plan["ordering_pattern"] == "sandwich"
    assert plan["transactions"][0]["role"] == "attacker_front"
    assert plan["transactions"][1]["slippage_or_limit"] == "amountOutMin"
    assert any(risk["category"] == "front_run" for risk in plan["risks"])


def test_local_heuristic_provider_reports_adversarial_ordering_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING,
        objective="build ordering plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"adversarial_transaction_ordering_plans": []}
    assert result.metadata == {
        "strategy": "regex_adversarial_transaction_ordering_signals",
        "count": 0,
    }
    assert result.local is True


def test_local_heuristic_provider_synthesizes_erc4626_vault_inflation_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = ERC4626VaultInflationHardeningAgent(provider)

    plans = agent.plan(
        """
        contract DonationVault is ERC4626 {
            IERC20 public asset;
            uint256 public totalSupply;
            function totalAssets() public view returns (uint256) {
                return asset.balanceOf(address(this));
            }
            function convertToShares(uint256 assets) public view returns (uint256) {
                return assets * totalSupply / totalAssets();
            }
            function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
                shares = convertToShares(assets);
                _mint(receiver, shares);
            }
        }
        """,
        vault_summary={"standards": ["ERC4626"], "surfaces": ["deposit"]},
    )

    assert plans
    plan = plans[0]
    assert plan.surfaces[0].vault_function == "deposit"
    assert plan.surfaces[0].asset_function == "totalAssets"
    assert plan.surfaces[0].share_function == "convertToShares"
    assert plan.surfaces[0].total_assets_source == "asset.balanceOf(address(this))"
    assert plan.surfaces[0].total_supply_source == "totalSupply"
    assert plan.surfaces[0].rounding_direction == "down"
    assert plan.surfaces[0].donation_exposure == "direct transfer changes raw asset balance"
    assert any(risk.category == "direct_donation" for risk in plan.risks)
    assert any(risk.category == "missing_min_shares" for risk in plan.risks)
    assert any(risk.category == "missing_virtual_offset" for risk in plan.risks)
    assert "add minimum-share guard" in plan.mitigations
    assert any("zero victim shares" in test for test in plan.validation_tests)
    assert {"foundry", "echidna", "symbolic execution"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_erc4626_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.ERC4626_VAULT_INFLATION_HARDENING,
        objective="build ERC4626 vault inflation plans",
        prompt="""
        ```solidity
        contract Vault {
            uint256 public totalSupply;
            function totalAssets() public view returns (uint256) {
                return asset.balanceOf(address(this));
            }
            function previewDeposit(uint256 assets) external view returns (uint256) {
                return convertToShares(assets);
            }
            function convertToShares(uint256 assets) public view returns (uint256) {
                return assets * totalSupply / totalAssets();
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"erc4626_vault_inflation_hardening_plans"}
    assert result.metadata == {
        "strategy": "regex_erc4626_vault_inflation_signals",
        "count": len(result.data["erc4626_vault_inflation_hardening_plans"]),
    }
    plan = result.data["erc4626_vault_inflation_hardening_plans"][0]
    assert plan["surfaces"][0]["share_function"] == "convertToShares"
    assert plan["surfaces"][0]["donation_exposure"] == ("direct transfer changes raw asset balance")
    assert any(risk["category"] == "preview_mismatch" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_erc4626_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.ERC4626_VAULT_INFLATION_HARDENING,
        objective="build ERC4626 vault inflation plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"erc4626_vault_inflation_hardening_plans": []}
    assert result.metadata == {"strategy": "regex_erc4626_vault_inflation_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_create2_deployment_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = Create2DeploymentHardeningAgent(provider)

    plans = agent.plan(
        """
        contract WalletFactory {
            function deployWallet(bytes32 salt, address owner) external returns (address wallet) {
                bytes memory code = abi.encodePacked(type(Wallet).creationCode, owner);
                assembly {
                    wallet := create2(0, add(code, 0x20), mload(code), salt)
                }
            }
        }
        """,
        deployment_summary={"factories": ["WalletFactory"], "opcodes": ["CREATE2"]},
    )

    assert plans
    plan = plans[0]
    assert plan.surfaces[0].deploy_function == "deployWallet"
    assert plan.surfaces[0].factory_contract == "WalletFactory"
    assert plan.surfaces[0].salt_source == "salt bound to caller or owner"
    assert plan.surfaces[0].init_code_source == (
        "abi.encodePacked(type(...).creationCode, constructor args)"
    )
    assert plan.surfaces[0].address_formula == "CREATE2(factory, salt, init code hash)"
    assert any(risk.category == "salt_squatting" for risk in plan.risks)
    assert any(risk.category == "init_code_mismatch" for risk in plan.risks)
    assert "verify init code hash" in plan.mitigations
    assert "add collision check before deploy" in plan.mitigations
    assert any("same salt" in test for test in plan.validation_tests)
    assert {"foundry", "slither", "fork simulation"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_create2_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.CREATE2_DEPLOYMENT_HARDENING,
        objective="build CREATE2 deployment plans",
        prompt="""
        ```solidity
        contract Factory {
            function deploy(bytes32 salt, bytes memory initCode) external returns (address addr) {
                bytes32 initCodeHash = keccak256(initCode);
                addr = computeAddress(salt, initCodeHash);
                require(addr.code.length == 0, "exists");
                assembly { addr := create2(0, add(initCode, 0x20), mload(initCode), salt) }
                require(addr.codehash == initCodeHash, "bad code");
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"create2_deployment_hardening_plans"}
    assert result.metadata == {
        "strategy": "regex_create2_deployment_signals",
        "count": len(result.data["create2_deployment_hardening_plans"]),
    }
    plan = result.data["create2_deployment_hardening_plans"][0]
    assert plan["surfaces"][0]["deploy_function"] == "deploy"
    assert plan["surfaces"][0]["collision_check"] == "predicted address has no code before deploy"
    assert plan["surfaces"][0]["post_deploy_check"] == "deployed codehash verified"
    assert any(risk["category"] == "predictable_salt" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_create2_empty_without_signals():
    provider = LocalHeuristicReasoningProvider()
    empty_task = ReasoningTask(
        capability=AgentCapability.CREATE2_DEPLOYMENT_HARDENING,
        objective="build CREATE2 deployment plans",
        prompt="contract Plain { function ping() external {} }",
    )

    result = provider.complete_json(empty_task)

    assert result.data == {"create2_deployment_hardening_plans": []}
    assert result.metadata == {"strategy": "regex_create2_deployment_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_synthesizes_abi_packed_hash_collision_plan():
    provider = LocalHeuristicReasoningProvider()
    agent = AbiPackedHashCollisionHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Claims {
            mapping(bytes32 => bool) public used;
            function claim(string calldata account, string calldata salt) external {
                bytes32 key = keccak256(abi.encodePacked(account, salt));
                require(!used[key], "used");
                used[key] = true;
            }
        }
        """,
        hash_summary={"packed_hashes": ["claim"]},
    )

    assert plans
    plan = plans[0]
    assert plan.surfaces[0].hash_function == "claim"
    assert plan.surfaces[0].packed_expression == "keccak256(abi.encodePacked(account, salt))"
    assert plan.surfaces[0].argument_types == ["string", "string"]
    assert plan.surfaces[0].dynamic_argument_count == "2"
    assert plan.surfaces[0].hash_usage == "mapping_key"
    assert plan.surfaces[0].safer_encoding == "abi.encode(account, salt)"
    assert any(risk.category == "multiple_dynamic_args" for risk in plan.risks)
    assert any(risk.category == "mapping_key_collision" for risk in plan.risks)
    assert "use abi.encode for typed tuple hashing" in plan.mitigations
    assert any("shifted dynamic boundaries" in test for test in plan.validation_tests)
    assert {"foundry", "slither", "property testing"}.issubset(set(plan.recommended_tools))
    assert plan.confidence > 0


def test_local_heuristic_provider_reports_abi_packed_metadata_and_canonical_key():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.ABI_PACKED_HASH_COLLISION_HARDENING,
        objective="build ABI packed hash collision plans",
        prompt="""
        ```solidity
        contract Auth {
            mapping(bytes32 => bool) public consumed;
            function authorize(bytes calldata a, bytes calldata b, bytes calldata sig) external {
                bytes32 digest = keccak256(abi.encodePacked(a, b));
                require(!consumed[digest], "used");
                consumed[digest] = true;
            }
        }
        ```
        """,
    )

    result = provider.complete_json(task)

    assert set(result.data) == {"abi_packed_hash_collision_hardening_plans"}
    assert result.metadata == {
        "strategy": "regex_abi_packed_hash_collision_signals",
        "count": len(result.data["abi_packed_hash_collision_hardening_plans"]),
    }
    plan = result.data["abi_packed_hash_collision_hardening_plans"][0]
    assert plan["surfaces"][0]["hash_function"] == "authorize"
    assert plan["surfaces"][0]["argument_types"] == ["bytes", "bytes"]
    assert any(risk["category"] == "multiple_dynamic_args" for risk in plan["risks"])
    assert any(risk["category"] == "signature_collision" for risk in plan["risks"])
    assert plan["validation_tests"]


def test_local_heuristic_provider_reports_abi_packed_empty_without_collision_signal():
    provider = LocalHeuristicReasoningProvider()
    safe_task = ReasoningTask(
        capability=AgentCapability.ABI_PACKED_HASH_COLLISION_HARDENING,
        objective="build ABI packed hash collision plans",
        prompt="""
        contract Plain {
            function safe(bytes32 id, uint256 amount) external pure returns (bytes32) {
                return keccak256(abi.encode(id, amount));
            }
            function fixedPacked(bytes32 id, uint256 amount) external pure returns (bytes32) {
                return keccak256(abi.encodePacked(id, amount));
            }
        }
        """,
    )

    result = provider.complete_json(safe_task)

    assert result.data == {"abi_packed_hash_collision_hardening_plans": []}
    assert result.metadata == {"strategy": "regex_abi_packed_hash_collision_signals", "count": 0}
    assert result.local is True


def test_local_heuristic_provider_reports_unsupported_capability():
    provider = LocalHeuristicReasoningProvider()
    task = ReasoningTask(
        capability=AgentCapability.REMEDIATION_CRITIQUE,
        objective="critique remediation",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.data == {}
    assert result.local is True
    assert result.metadata == {"unsupported_capability": "remediation_critique"}


def test_auto_reasoning_provider_prefers_local_fallback_without_orchestrator():
    provider = auto_reasoning_provider()

    assert isinstance(provider, LocalHeuristicReasoningProvider)


def test_auto_reasoning_provider_wraps_provided_local_orchestrator():
    orchestrator = FakeOrchestrator("{}")

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.orchestrator is orchestrator
    assert provider.route == ReasoningProviderRoute(
        backend_key="local:test-agent",
        provider_kind="local",
        implementation_label="test-agent",
        local=True,
    )


def test_auto_reasoning_provider_normalizes_spaced_local_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = " local:test-agent "

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="local:test-agent",
        provider_kind="local",
        implementation_label="test-agent",
        local=True,
    )


def test_auto_reasoning_provider_derives_remote_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = "openai:gpt-test"

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="openai:gpt-test",
        provider_kind="openai",
        implementation_label="gpt-test",
        local=False,
    )


def test_auto_reasoning_provider_derives_plain_local_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = "ollama"

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="ollama",
        provider_kind="ollama",
        implementation_label="ollama",
        local=True,
    )


def test_auto_reasoning_provider_normalizes_plain_ollama_route():
    orchestrator = FakeOrchestrator("{}")
    orchestrator.primary_provider = " ollama "

    provider = auto_reasoning_provider(orchestrator)

    assert isinstance(provider, LLMOrchestratorReasoningProvider)
    assert provider.route == ReasoningProviderRoute(
        backend_key="ollama",
        provider_kind="ollama",
        implementation_label="ollama",
        local=True,
    )


def test_llm_orchestrator_provider_blocks_mismatched_remote_route():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key="openai:gpt-test",
            provider_kind="openai",
            implementation_label="gpt-test",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    with pytest.raises(ValueError, match="Remote reasoning is disabled"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_reports_effective_local_from_backend_key():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator('{"ok": true}'),
        route=ReasoningProviderRoute(
            backend_key=" local:test-agent ",
            provider_kind="remote",
            implementation_label="test-agent",
            local=False,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    result = provider.complete_json(task)

    assert result.local is True
    assert result.metadata["backend_key"] == "local:test-agent"
    assert provider.orchestrator.seen_provider == "local:test-agent"


def test_llm_orchestrator_provider_blocks_malformed_route_without_attribute_error():
    provider = LLMOrchestratorReasoningProvider(
        FakeOrchestrator("{}"),
        route=ReasoningProviderRoute(
            backend_key=None,
            provider_kind=None,
            implementation_label=None,
            local=False,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
        policy=DPGAgentConfig(allow_remote=False),
    )

    with pytest.raises(ValueError, match="Remote reasoning is disabled"):
        provider.complete_json(task)


def test_llm_orchestrator_provider_sanitizes_response_metadata():
    response = LLMResponse(
        content='{"ok": true}',
        provider=" local ",
        model=" model-a ",
        tokens_used=-1,
        latency_ms=float("inf"),
        cached="yes",
        metadata={
            "finish_reason": " stop ",
            "bad\nkey": "ignored",
            "raw": object(),
            "nan": float("nan"),
        },
    )
    orchestrator = CustomResponseOrchestrator(response)
    provider = LLMOrchestratorReasoningProvider(
        orchestrator,
        route=ReasoningProviderRoute(
            backend_key="local:test-agent",
            provider_kind="local",
            implementation_label="test-agent",
            local=True,
        ),
    )
    task = ReasoningTask(
        capability=AgentCapability.INVARIANT_EXTRACTION,
        objective="extract invariants",
        prompt="Return JSON only",
    )

    result = provider.complete_json(task)

    assert result.metadata["response_provider_kind"] == "local"
    assert result.metadata["response_model_label"] == "model-a"
    assert result.metadata["tokens_used"] == 0
    assert result.metadata["latency_ms"] == 0.0
    assert result.metadata["cached"] is False
    assert result.metadata["response_metadata"] == {
        "finish_reason": "stop",
        "raw": "<object>",
        "nan": None,
    }


def test_reasoning_provider_adapter_exports_are_available_from_src_llm():
    assert ExportedLLMOrchestratorReasoningProvider is LLMOrchestratorReasoningProvider
    assert ExportedLocalHeuristicReasoningProvider is LocalHeuristicReasoningProvider
    assert ExportedReasoningProviderRoute is ReasoningProviderRoute
    assert exported_auto_reasoning_provider is auto_reasoning_provider
