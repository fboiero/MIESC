"""
Tests for provider-agnostic agent contracts.
"""

from miesc.llm.agentic_contracts import (
    MAX_AGENT_METADATA_KEYS,
    MAX_AGENT_SOURCE_CHARS,
    MAX_AGENT_TEXT_CHARS,
    AbiPackedHashCollisionHardeningAgent,
    AbiPackedHashCollisionHardeningPlan,
    AbiPackedHashRisk,
    AbiPackedHashSurface,
    AccountAbstractionUserOpHardeningAgent,
    AdversarialOrderingPlan,
    AdversarialTransactionOrderingAgent,
    AgentCapability,
    AssetFlow,
    CapitalRequirement,
    CounterexampleEvidence,
    Create2DeploymentHardeningAgent,
    Create2DeploymentHardeningPlan,
    Create2DeploymentRisk,
    Create2DeploymentSurface,
    CrossChainMessageFlow,
    CrossChainMessageHardeningAgent,
    CrossChainMessageHardeningPlan,
    CrossChainMessageRisk,
    DelegatecallAliasRisk,
    DelegatecallStorageAliasingAgent,
    DelegatecallStorageAliasingPlan,
    DelegatecallSurface,
    DifferentialTestPlan,
    DPGAgentConfig,
    EconomicAttackPlan,
    EconomicAttackSimulationAgent,
    ERC20TokenCompatibilityHardeningAgent,
    ERC4626VaultInflationHardeningAgent,
    ERC4626VaultInflationHardeningPlan,
    ExternalCallReturndataHardeningAgent,
    ExternalCallReturndataHardeningPlan,
    ExternalCallReturndataRisk,
    ExternalCallReturndataSurface,
    FinancialMathPrecisionHardeningAgent,
    FinancialMathPrecisionHardeningPlan,
    FinancialMathPrecisionRisk,
    FinancialMathPrecisionSurface,
    FuzzingWaypoint,
    InvariantCandidate,
    InvariantCategory,
    InvariantExtractionAgent,
    MetamorphicDiffTestingAgent,
    MetamorphicRelation,
    OracleFeedHardeningAgent,
    OracleFeedHardeningPlan,
    OracleFeedRisk,
    OracleFeedSource,
    OrderingRisk,
    OrderingTransaction,
    RandomnessEntropyHardeningAgent,
    RandomnessEntropyHardeningPlan,
    RandomnessRisk,
    RandomnessSource,
    ReasoningResult,
    ReasoningTask,
    SemanticGraphEdge,
    SemanticGraphGate,
    SemanticGraphGateAgent,
    SemanticGraphNode,
    SequenceOracleAgent,
    SequenceOraclePlan,
    SequenceStep,
    SignatureDomainHardeningAgent,
    SignatureDomainHardeningPlan,
    SignatureDomainRisk,
    SignedAction,
    SnapshotFuzzingAgent,
    SnapshotFuzzingPlan,
    SnapshotSeed,
    StorageAliasPath,
    StorageLayoutChange,
    TokenHookReentrancyHardeningAgent,
    UpgradeEvolutionAnalysisAgent,
    UpgradeEvolutionPlan,
    UpgradeRisk,
    VaultInflationRisk,
    VaultShareSurface,
    parse_abi_packed_hash_collision_hardening_plans,
    parse_account_abstraction_userop_hardening_plans,
    parse_adversarial_transaction_ordering_plans,
    parse_create2_deployment_hardening_plans,
    parse_cross_chain_message_hardening_plans,
    parse_delegatecall_storage_aliasing_plans,
    parse_differential_test_plans,
    parse_economic_attack_plans,
    parse_erc20_token_compatibility_hardening_plans,
    parse_erc4626_vault_inflation_hardening_plans,
    parse_external_call_returndata_hardening_plans,
    parse_financial_math_precision_hardening_plans,
    parse_invariant_candidates,
    parse_oracle_feed_hardening_plans,
    parse_randomness_entropy_hardening_plans,
    parse_semantic_graph_gates,
    parse_sequence_oracle_plans,
    parse_signature_domain_hardening_plans,
    parse_snapshot_fuzzing_plans,
    parse_token_hook_reentrancy_hardening_plans,
    parse_upgrade_evolution_plans,
)


class FakeReasoningProvider:
    def __init__(self, payload):
        self.payload = payload
        self.seen_task = None

    def complete_json(self, task: ReasoningTask) -> ReasoningResult:
        self.seen_task = task
        return ReasoningResult(
            data=self.payload,
            provider_kind="local",
            implementation_label="fake-provider",
            local=True,
        )


def test_invariant_extraction_agent_uses_capability_not_provider_name():
    provider = FakeReasoningProvider(
        {
            "invariants": [
                {
                    "id": "asset_conservation",
                    "statement": "totalAssets must cover all issued shares",
                    "category": "accounting",
                    "affected_functions": ["deposit", "withdraw"],
                    "state_variables": ["totalAssets", "totalSupply"],
                    "assertion_hint": "assertGe(totalAssets(), totalSupply())",
                    "confidence": 0.82,
                    "evidence": ["totalAssets and totalSupply appear together"],
                }
            ]
        }
    )
    agent = InvariantExtractionAgent(provider)

    invariants = agent.extract(
        """
        contract Vault {
            uint256 public totalAssets;
            uint256 public totalSupply;
            function deposit(uint256 amount) external {}
            function withdraw(uint256 shares) external {}
        }
        """,
        contract_path="Vault.sol",
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.INVARIANT_EXTRACTION
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "specific model" in prompt_lower
    assert "external api" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(invariants) == 1
    invariant = invariants[0]
    assert invariant.id == "asset_conservation"
    assert invariant.category == InvariantCategory.ACCOUNTING
    assert invariant.affected_functions == ["deposit", "withdraw"]
    assert invariant.confidence == 0.82


def test_sequence_oracle_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "sequence_oracle_plans": [
                {
                    "id": "share_inflation_sequence",
                    "objective": "Validate whether donation before deposit inflates shares",
                    "invariant_id": "asset_conservation",
                    "vulnerability_types": ["share_price_inflation"],
                    "sequence": [
                        {
                            "function": "deposit",
                            "actor": "victim",
                            "arguments": ["1 ether"],
                            "expected_effect": "victim receives baseline shares",
                        },
                        {
                            "function": "donate",
                            "actor": "attacker",
                            "arguments": ["100 ether"],
                            "expected_effect": "assets increase without minting shares",
                        },
                    ],
                    "oracle": "attacker shares are minted above proportional assets",
                    "recommended_tools": ["foundry", "echidna", "halmos"],
                    "confidence": 0.9,
                    "evidence": ["deposit and donate alter the same accounting state"],
                }
            ]
        }
    )
    invariant = InvariantCandidate(
        id="asset_conservation",
        statement="assets and shares must remain proportional",
        category=InvariantCategory.ACCOUNTING,
    )
    agent = SequenceOracleAgent(provider)

    plans = agent.synthesize(
        """
        contract Vault {
            function deposit(uint256 assets) external {}
            function donate(uint256 assets) external {}
        }
        """,
        contract_path="Vault.sol",
        invariants=[invariant],
        max_sequence_length=3,
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.SEQUENCE_ORACLE_SYNTHESIS
    exported_task = provider.seen_task.to_dict()
    assert exported_task["inputs"]["max_sequence_length"] == 3
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "transaction-sequence oracle plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "share_inflation_sequence"
    assert plan.invariant_id == "asset_conservation"
    assert plan.sequence[0].function == "deposit"
    assert plan.sequence[1].actor == "attacker"
    assert plan.recommended_tools == ["foundry", "echidna", "halmos"]
    assert plan.confidence == 0.9


def test_semantic_graph_gate_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "semantic_graph_gates": [
                {
                    "id": "withdraw_access_gate",
                    "objective": "Focus privileged withdraw path for access control review",
                    "target_vulnerability_types": ["access_control"],
                    "focal_nodes": ["fn_withdraw"],
                    "nodes": [
                        {
                            "id": "fn_withdraw",
                            "kind": "function",
                            "label": "withdraw(uint256)",
                            "contract": "Vault",
                            "function": "withdraw",
                            "line": 42,
                        },
                        {
                            "id": "state_owner",
                            "kind": "state_var",
                            "label": "owner",
                        },
                    ],
                    "edges": [
                        {
                            "source": "fn_withdraw",
                            "target": "state_owner",
                            "relation": "missing_guard",
                            "confidence": 0.81,
                            "evidence": ["withdraw writes value without onlyOwner"],
                        }
                    ],
                    "graph_queries": ["find external value movement without role guard"],
                    "recommended_tools": ["slither", "mythril"],
                    "confidence": 0.77,
                    "rationale": "external value movement lacks an authorization edge",
                }
            ]
        }
    )
    agent = SemanticGraphGateAgent(provider)

    gates = agent.build_gate(
        """
        contract Vault {
            address public owner;
            function withdraw(uint256 amount) external {}
        }
        """,
        findings=[{"type": "access-control", "function": "withdraw"}],
        ir_summary={"state_writes": ["owner"], "external_calls": []},
        max_nodes=10,
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.SEMANTIC_GRAPH_GATING
    exported_task = provider.seen_task.to_dict()
    assert exported_task["inputs"]["max_nodes"] == 10
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "semantic graph gating plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(gates) == 1
    gate = gates[0]
    assert gate.id == "withdraw_access_gate"
    assert gate.focal_nodes == ["fn_withdraw"]
    assert gate.nodes[0].kind == "function"
    assert gate.edges[0].relation == "missing_guard"
    assert gate.recommended_tools == ["slither", "mythril"]
    assert gate.confidence == 0.77


def test_snapshot_fuzzing_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "snapshot_fuzzing_plans": [
                {
                    "id": "vault_snapshot_campaign",
                    "objective": "Reuse post-liquidity state to fuzz share inflation",
                    "target_vulnerability_types": ["share_price_inflation"],
                    "seeds": [
                        {
                            "id": "seed_after_liquidity",
                            "setup_sequence": [
                                {
                                    "function": "deposit",
                                    "actor": "victim",
                                    "arguments": ["100 ether"],
                                    "expected_effect": "vault has initial liquidity",
                                }
                            ],
                            "target_state": "vault initialized with nonzero assets and shares",
                            "priority": 0.9,
                            "evidence": ["deposit initializes assets and shares"],
                        }
                    ],
                    "waypoints": [
                        {
                            "id": "waypoint_share_price_delta",
                            "kind": "dataflow",
                            "target": "totalAssets / totalSupply",
                            "objective": "maximize share price drift",
                            "distance_hint": "ratio changes without matching mint",
                            "evidence": ["donate affects assets but not shares"],
                        }
                    ],
                    "priority_transactions": [
                        {"function": "donate", "actor": "attacker", "arguments": ["amount"]}
                    ],
                    "oracle": "share price remains proportional after donation and deposit",
                    "recommended_tools": ["foundry", "echidna", "ityfuzz"],
                    "budget_hint": "bounded snapshot replay before full campaign",
                    "confidence": 0.88,
                }
            ]
        }
    )
    sequence_plan = SequenceOraclePlan(
        id="share_inflation_sequence",
        objective="donate before deposit",
        sequence=[SequenceStep(function="donate"), SequenceStep(function="deposit")],
        oracle="shares remain proportional",
    )
    gate = SemanticGraphGate(
        id="share_graph_gate",
        objective="focus accounting graph",
        focal_nodes=["fn_donate"],
    )
    agent = SnapshotFuzzingAgent(provider)

    plans = agent.plan(
        "contract Vault { function deposit(uint256) external {} function donate(uint256) external {} }",
        sequence_plans=[sequence_plan],
        graph_gates=[gate],
        max_snapshots=4,
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.SNAPSHOT_FUZZING_GUIDANCE
    exported_task = provider.seen_task.to_dict()
    assert exported_task["inputs"]["max_snapshots"] == 4
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "snapshot and dataflow-guided fuzzing" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "vault_snapshot_campaign"
    assert plan.seeds[0].id == "seed_after_liquidity"
    assert plan.seeds[0].setup_sequence[0].function == "deposit"
    assert plan.waypoints[0].kind == "dataflow"
    assert plan.priority_transactions[0].function == "donate"
    assert plan.recommended_tools == ["foundry", "echidna", "ityfuzz"]
    assert plan.confidence == 0.88


def test_economic_attack_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "economic_attack_plans": [
                {
                    "id": "oracle_profit_plan",
                    "objective": "Validate whether price manipulation is profitable after costs",
                    "target_vulnerability_types": ["oracle_manipulation"],
                    "base_sequence_plan_ids": ["oracle_sequence"],
                    "base_snapshot_plan_ids": ["oracle_snapshot"],
                    "base_graph_gate_ids": ["oracle_gate"],
                    "capital_requirements": [
                        {
                            "asset": "USDC",
                            "amount_hint": "flash loan sized to move pool price",
                            "source": "flash_loan",
                            "purpose": "fund swap manipulation leg",
                        }
                    ],
                    "asset_flows": [
                        {
                            "asset": "USDC",
                            "from_actor": "flash_pool",
                            "to_actor": "attacker",
                            "amount_hint": "principal",
                            "step_id": "borrow_flash",
                            "rationale": "temporary capital for price movement",
                        },
                        {
                            "asset": "WETH",
                            "from_actor": "target_protocol",
                            "to_actor": "attacker",
                            "amount_hint": "over-borrowed collateral value",
                            "step_id": "borrow",
                        },
                    ],
                    "profit_formula": "borrowed_value - principal - premium - swap_fees - gas",
                    "cost_model": "flash-loan premium, pool fees, gas, slippage",
                    "liquidity_assumptions": ["pool depth allows bounded slippage"],
                    "oracle_price_assumptions": ["spot reserve price is consumed without TWAP"],
                    "break_even_threshold": "manipulated borrow value exceeds all costs",
                    "expected_profit_range": "positive if price impact exceeds fees",
                    "risk_factors": ["TWAP or liquidity cap would invalidate plan"],
                    "recommended_tools": ["foundry", "anvil", "fork-simulation"],
                    "confidence": 0.78,
                    "evidence": ["swap and borrow depend on the same price path"],
                }
            ]
        }
    )
    sequence_plan = SequenceOraclePlan(
        id="oracle_sequence",
        objective="swap then borrow",
        sequence=[SequenceStep(function="swap"), SequenceStep(function="borrow")],
        oracle="borrow value remains bounded by fair price",
    )
    snapshot_plan = SnapshotFuzzingPlan(
        id="oracle_snapshot",
        objective="snapshot liquid pool",
        oracle="price cannot be profitably moved",
        waypoints=[FuzzingWaypoint(id="price_delta", kind="dataflow", target="price")],
    )
    graph_gate = SemanticGraphGate(
        id="oracle_gate",
        objective="focus oracle dataflow",
        focal_nodes=["oracle_price"],
    )
    agent = EconomicAttackSimulationAgent(provider)

    plans = agent.plan(
        "contract LendingPool { function swap(uint256) external {} function borrow(uint256) external {} }",
        sequence_plans=[sequence_plan],
        snapshot_plans=[snapshot_plan],
        graph_gates=[graph_gate],
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ECONOMIC_ATTACK_SIMULATION
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "economic/profit-driven defi attack simulation" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "oracle_profit_plan"
    assert plan.capital_requirements[0].source == "flash_loan"
    assert plan.asset_flows[0].from_actor == "flash_pool"
    assert plan.asset_flows[1].to_actor == "attacker"
    assert plan.profit_formula == "borrowed_value - principal - premium - swap_fees - gas"
    assert plan.recommended_tools == ["foundry", "anvil", "fork-simulation"]
    assert plan.confidence == 0.78


def test_metamorphic_diff_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "differential_test_plans": [
                {
                    "id": "split_merge_deposit_plan",
                    "objective": "Compare split and merged deposits for share drift",
                    "target_vulnerability_types": ["share_price_inflation"],
                    "relations": [
                        {
                            "id": "split_merge_deposit",
                            "relation_type": "split_merge",
                            "baseline_sequence": [
                                {
                                    "function": "deposit",
                                    "actor": "user",
                                    "arguments": ["100 ether"],
                                    "expected_effect": "mint baseline shares",
                                }
                            ],
                            "variant_sequence": [
                                {
                                    "function": "deposit",
                                    "actor": "user",
                                    "arguments": ["50 ether"],
                                },
                                {
                                    "function": "deposit",
                                    "actor": "user",
                                    "arguments": ["50 ether"],
                                },
                            ],
                            "expected_relation": "final shares and assets match within rounding",
                            "tolerance_hint": "at most one wei",
                            "evidence": ["deposit uses asset/share conversion"],
                        }
                    ],
                    "state_observables": ["balanceOf(user)", "totalSupply()", "totalAssets()"],
                    "oracle": "split and merged executions diverge beyond tolerance",
                    "recommended_tools": ["foundry", "echidna", "halmos"],
                    "confidence": 0.84,
                    "evidence": ["deposit is nonlinear around totalSupply"],
                }
            ]
        }
    )
    invariant = InvariantCandidate(
        id="share_asset_consistency",
        statement="equivalent deposits preserve share accounting",
        category=InvariantCategory.ACCOUNTING,
    )
    sequence_plan = SequenceOraclePlan(
        id="deposit_sequence",
        objective="deposit variants",
        sequence=[SequenceStep(function="deposit")],
        oracle="shares remain proportional",
    )
    snapshot_plan = SnapshotFuzzingPlan(
        id="initialized_vault",
        objective="initialized state",
        seeds=[SnapshotSeed(id="seed_vault", target_state="vault initialized")],
        oracle="no share drift",
    )
    agent = MetamorphicDiffTestingAgent(provider)

    plans = agent.plan(
        "contract Vault { function deposit(uint256) external {} }",
        invariants=[invariant],
        sequence_plans=[sequence_plan],
        snapshot_plans=[snapshot_plan],
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.METAMORPHIC_DIFF_TESTING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "metamorphic and differential test plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "split_merge_deposit_plan"
    assert plan.relations[0].relation_type == "split_merge"
    assert plan.relations[0].baseline_sequence[0].function == "deposit"
    assert plan.relations[0].variant_sequence[1].arguments == ["50 ether"]
    assert plan.state_observables == ["balanceOf(user)", "totalSupply()", "totalAssets()"]
    assert plan.recommended_tools == ["foundry", "echidna", "halmos"]
    assert plan.confidence == 0.84


def test_upgrade_evolution_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "upgrade_evolution_plans": [
                {
                    "id": "owner_slot_collision",
                    "objective": "Validate whether V2 corrupts proxy owner storage",
                    "proxy_pattern": "transparent",
                    "old_implementation": "VaultV1",
                    "new_implementation": "VaultV2",
                    "storage_changes": [
                        {
                            "slot": "0",
                            "before": "address owner",
                            "after": "bool openForSale",
                            "change_type": "type_change",
                            "risk": "owner slot may be overwritten during upgrade",
                            "evidence": ["slot 0 type changed across implementations"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "unprotected_reinitializer",
                            "category": "initializer",
                            "affected_component": "initializeV2",
                            "severity_hint": "high",
                            "description": "initializeV2 lacks an initializer guard",
                            "evidence": ["public initializeV2 writes owner"],
                            "recommended_check": "replay upgrade and assert owner unchanged",
                        }
                    ],
                    "migration_checks": ["dry-run upgrade preserves owner and totalAssets"],
                    "recommended_tools": ["openzeppelin-upgrades", "slither", "foundry"],
                    "confidence": 0.86,
                    "evidence": ["storage layout diff and initializer diff"],
                }
            ]
        }
    )
    agent = UpgradeEvolutionAnalysisAgent(provider)

    plans = agent.plan(
        "contract VaultV1 { address owner; uint256 totalAssets; }",
        "contract VaultV2 { bool openForSale; address owner; function initializeV2() public {} }",
        proxy_source_code="contract Proxy { address implementation; fallback() external {} }",
        storage_layout_before={"0": "address owner"},
        storage_layout_after={"0": "bool openForSale"},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.UPGRADE_EVOLUTION_ANALYSIS
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "upgrade evolution analysis plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "owner_slot_collision"
    assert plan.proxy_pattern == "transparent"
    assert plan.storage_changes[0].slot == "0"
    assert plan.storage_changes[0].change_type == "type_change"
    assert plan.risks[0].category == "initializer"
    assert plan.risks[0].recommended_check == "replay upgrade and assert owner unchanged"
    assert plan.recommended_tools == ["openzeppelin-upgrades", "slither", "foundry"]
    assert plan.confidence == 0.86


def test_signature_domain_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "signature_domain_hardening_plans": [
                {
                    "id": "permit_domain_plan",
                    "objective": "Harden permit signatures against cross-chain replay",
                    "signed_actions": [
                        {
                            "id": "permit_owner_spender_value",
                            "function": "permit",
                            "signer_source": "owner recovered from ECDSA",
                            "digest_scheme": "eip712",
                            "domain_fields": ["name", "version", "chainId", "verifyingContract"],
                            "nonce_source": "nonces[owner] increments on success",
                            "deadline_source": "deadline checked before recover",
                            "value_scope": ["owner", "spender", "value"],
                            "evidence": ["permit digest includes owner spender value"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "missing_chain_id",
                            "category": "domain_separator",
                            "affected_action_id": "permit_owner_spender_value",
                            "severity_hint": "high",
                            "description": "domain separator does not bind chain id",
                            "evidence": ["DOMAIN_SEPARATOR omits chainId"],
                            "recommended_check": "replay same signature across chain ids",
                        }
                    ],
                    "replay_tests": ["reuse signature after nonce consumption"],
                    "recommended_tools": ["foundry", "echidna", "slither"],
                    "confidence": 0.87,
                    "evidence": ["permit and ecrecover are present"],
                }
            ]
        }
    )
    agent = SignatureDomainHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Token {
            mapping(address => uint256) public nonces;
            bytes32 public DOMAIN_SEPARATOR;
            function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata sig) external {}
        }
        """,
        abi_summary={"functions": ["permit"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.SIGNATURE_DOMAIN_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "signature-domain hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "permit_domain_plan"
    assert plan.signed_actions[0].function == "permit"
    assert plan.signed_actions[0].digest_scheme == "eip712"
    assert plan.signed_actions[0].domain_fields == [
        "name",
        "version",
        "chainId",
        "verifyingContract",
    ]
    assert plan.risks[0].category == "domain_separator"
    assert plan.replay_tests == ["reuse signature after nonce consumption"]
    assert plan.recommended_tools == ["foundry", "echidna", "slither"]
    assert plan.confidence == 0.87


def test_cross_chain_message_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "cross_chain_message_hardening_plans": [
                {
                    "id": "l2_message_plan",
                    "objective": "Harden L2 receiveMessage against spoofed remotes",
                    "message_flows": [
                        {
                            "id": "l2_receive_message",
                            "handler_function": "receiveMessage",
                            "source_domain": "Ethereum",
                            "destination_domain": "Optimism",
                            "trusted_sender_source": "trustedRemote[sourceChainId]",
                            "message_id_source": "keccak256(sourceChainId, nonce, payload)",
                            "replay_guard": "processedMessages[messageId]",
                            "finality_assumption": "proof root finalized before execute",
                            "payload_scope": ["token", "amount", "recipient"],
                            "evidence": ["receiveMessage decodes sourceChainId and payload"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "missing_source_sender_check",
                            "category": "trusted_sender",
                            "affected_flow_id": "l2_receive_message",
                            "severity_hint": "high",
                            "description": "handler does not verify the trusted remote sender",
                            "evidence": ["source sender is decoded but not checked"],
                            "recommended_check": "spoof source sender must revert",
                        }
                    ],
                    "validation_tests": ["replay consumed message id must revert"],
                    "recommended_tools": ["foundry", "bridgefuzz", "slither"],
                    "confidence": 0.85,
                    "evidence": ["bridge receive handler is present"],
                }
            ]
        }
    )
    agent = CrossChainMessageHardeningAgent(provider)

    plans = agent.plan(
        """
        contract BridgeReceiver {
            mapping(bytes32 => bool) public processedMessages;
            mapping(uint256 => address) public trustedRemote;
            function receiveMessage(uint256 sourceChainId, uint64 nonce, bytes calldata payload) external {}
        }
        """,
        bridge_summary={"handlers": ["receiveMessage"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.CROSS_CHAIN_MESSAGE_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "cross-chain message hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert provider.seen_task.inputs["bridge_summary"] == {"handlers": ["receiveMessage"]}
    assert "receivemessage" in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "l2_message_plan"
    assert plan.message_flows[0].handler_function == "receiveMessage"
    assert plan.message_flows[0].source_domain == "Ethereum"
    assert plan.message_flows[0].replay_guard == "processedMessages[messageId]"
    assert plan.risks[0].category == "trusted_sender"
    assert plan.validation_tests == ["replay consumed message id must revert"]
    assert plan.recommended_tools == ["foundry", "bridgefuzz", "slither"]
    assert plan.confidence == 0.85


def test_delegatecall_storage_aliasing_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "delegatecall_storage_aliasing_plans": [
                {
                    "id": "fallback_alias_plan",
                    "objective": "Validate fallback delegatecall cannot overwrite owner slot",
                    "delegatecall_surfaces": [
                        {
                            "id": "fallback_delegatecall",
                            "caller_function": "fallback",
                            "target_source": "implementation slot",
                            "selector_source": "msg.data",
                            "target_trust_boundary": "registry-controlled",
                            "guard_summary": "implementation must be whitelisted",
                            "value_forwarding": "msg.value preserved",
                            "evidence": ["fallback delegates msg.data"],
                        }
                    ],
                    "storage_alias_paths": [
                        {
                            "id": "owner_slot_collision",
                            "delegatecall_surface_id": "fallback_delegatecall",
                            "caller_slot": "slot 0",
                            "callee_slot": "slot 0",
                            "caller_semantics": "owner",
                            "callee_semantics": "initialized",
                            "write_source": "callee initialize writes slot 0",
                            "path_condition": "attacker can choose selector",
                            "evidence": ["callee writes first storage slot"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "callee_write_owner_slot",
                            "category": "storage_collision",
                            "affected_surface_id": "fallback_delegatecall",
                            "severity_hint": "high",
                            "description": "callee write can reinterpret caller owner slot",
                            "evidence": ["caller and callee both use slot 0"],
                            "recommended_check": "malicious callee cannot set owner",
                        }
                    ],
                    "validation_tests": ["malicious callee write to slot 0 must fail"],
                    "recommended_tools": ["foundry", "slither", "symbolic execution"],
                    "confidence": 0.83,
                    "evidence": ["delegatecall surface is present"],
                }
            ]
        }
    )
    agent = DelegatecallStorageAliasingAgent(provider)

    plans = agent.plan(
        """
        contract Proxy {
            address public owner;
            address public implementation;
            fallback() external payable {
                implementation.delegatecall(msg.data);
            }
        }
        """,
        layout_summary={"caller_slots": [{"slot": 0, "label": "owner"}]},
        callee_summary={"writes": ["slot 0"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.DELEGATECALL_STORAGE_ALIASING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "delegatecall storage-aliasing plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert provider.seen_task.inputs["layout_summary"] == {
        "caller_slots": [{"slot": 0, "label": "owner"}]
    }
    assert "delegatecall" in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "fallback_alias_plan"
    assert plan.delegatecall_surfaces[0].caller_function == "fallback"
    assert plan.storage_alias_paths[0].caller_semantics == "owner"
    assert plan.risks[0].category == "storage_collision"
    assert plan.validation_tests == ["malicious callee write to slot 0 must fail"]
    assert plan.recommended_tools == ["foundry", "slither", "symbolic execution"]
    assert plan.confidence == 0.83


def test_oracle_feed_hardening_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "oracle_feed_hardening_plans": [
                {
                    "id": "chainlink_feed_plan",
                    "objective": "Harden Chainlink ETH/USD reads against stale answers",
                    "feeds": [
                        {
                            "id": "eth_usd",
                            "consumer_function": "getPrice",
                            "feed_kind": "chainlink",
                            "source_contract": "priceFeed",
                            "read_method": "latestRoundData",
                            "freshness_source": "updatedAt",
                            "staleness_threshold": "1 hours",
                            "decimals_source": "decimals()",
                            "normalization": "scale answer to 1e18",
                            "fallback_source": "none",
                            "sequencer_guard": "sequencer uptime feed plus grace period",
                            "bounds_check": "answer > 0",
                            "evidence": ["latestRoundData result is consumed"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "missing_staleness_check",
                            "category": "stale_round",
                            "affected_feed_id": "eth_usd",
                            "severity_hint": "high",
                            "description": "updatedAt is returned but not bounded by a heartbeat",
                            "evidence": ["updatedAt is ignored"],
                            "recommended_check": "old updatedAt must revert",
                        }
                    ],
                    "validation_tests": ["stale updatedAt must revert"],
                    "recommended_tools": ["foundry", "slither", "symbolic execution"],
                    "confidence": 0.84,
                    "evidence": ["oracle feed is present"],
                }
            ]
        }
    )
    agent = OracleFeedHardeningAgent(provider)

    plans = agent.plan(
        """
        interface AggregatorV3Interface {
            function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
            function decimals() external view returns (uint8);
        }
        contract OracleConsumer {
            AggregatorV3Interface public priceFeed;
            function getPrice() external view returns (uint256) {
                (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
                return uint256(answer);
            }
        }
        """,
        oracle_summary={"feeds": ["ETH/USD"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ORACLE_FEED_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "oracle-feed hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert provider.seen_task.inputs["oracle_summary"] == {"feeds": ["ETH/USD"]}
    assert "latestrounddata" in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "chainlink_feed_plan"
    assert plan.feeds[0].consumer_function == "getPrice"
    assert plan.feeds[0].freshness_source == "updatedAt"
    assert plan.feeds[0].sequencer_guard == "sequencer uptime feed plus grace period"
    assert plan.risks[0].category == "stale_round"
    assert plan.validation_tests == ["stale updatedAt must revert"]
    assert plan.recommended_tools == ["foundry", "slither", "symbolic execution"]
    assert plan.confidence == 0.84


def test_adversarial_transaction_ordering_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "adversarial_transaction_ordering_plans": [
                {
                    "id": "sandwich_plan",
                    "objective": "Validate swap cannot be sandwiched beyond user limits",
                    "ordering_pattern": "sandwich",
                    "transactions": [
                        {
                            "id": "attacker_front",
                            "role": "attacker_front",
                            "function": "swap",
                            "actor": "searcher",
                            "position": "before_victim",
                            "value_hint": "front-run amount",
                            "state_dependency": "pool reserves",
                            "slippage_or_limit": "none",
                            "evidence": ["public swap changes reserves"],
                        },
                        {
                            "id": "victim_swap",
                            "role": "victim",
                            "function": "swap",
                            "actor": "user",
                            "position": "victim",
                            "value_hint": "amountIn",
                            "state_dependency": "pool reserves",
                            "slippage_or_limit": "minOut",
                            "evidence": ["victim supplies amountIn"],
                        },
                    ],
                    "risks": [
                        {
                            "id": "missing_min_out",
                            "category": "slippage_gap",
                            "affected_transaction_id": "victim_swap",
                            "severity_hint": "high",
                            "description": "victim outcome depends on prior reserve-changing transaction",
                            "evidence": ["minOut is absent or unchecked"],
                            "recommended_check": "front-run reserve change must not worsen victim beyond minOut",
                        }
                    ],
                    "oracle": "victim receives at least minOut under adversarial ordering",
                    "mitigations": ["minOut", "deadline"],
                    "validation_tests": ["front-run before victim must respect minOut"],
                    "recommended_tools": ["foundry", "mev simulation", "sequence oracle"],
                    "confidence": 0.82,
                    "evidence": ["public AMM swap is present"],
                }
            ]
        }
    )
    agent = AdversarialTransactionOrderingAgent(provider)

    plans = agent.plan(
        """
        contract Router {
            function swap(uint256 amountIn) external returns (uint256 amountOut) {
                amountOut = amountIn * reserveOut / reserveIn;
            }
        }
        """,
        market_summary={"sequence_plan_ids": ["swap_sequence"], "liquidity": "constant product"},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ADVERSARIAL_TRANSACTION_ORDERING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "adversarial transaction-ordering plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert provider.seen_task.inputs["market_summary"] == {
        "liquidity": "constant product",
        "sequence_plan_ids": ["swap_sequence"],
    }
    assert "do not duplicate economic attack simulation" in prompt_lower

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "sandwich_plan"
    assert plan.ordering_pattern == "sandwich"
    assert plan.transactions[0].role == "attacker_front"
    assert plan.transactions[1].slippage_or_limit == "minOut"
    assert plan.risks[0].category == "slippage_gap"
    assert plan.oracle == "victim receives at least minOut under adversarial ordering"
    assert plan.mitigations == ["minOut", "deadline"]
    assert plan.validation_tests == ["front-run before victim must respect minOut"]
    assert plan.confidence == 0.82


def test_randomness_entropy_hardening_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "randomness_entropy_hardening_plans": [
                {
                    "id": "lottery_entropy_plan",
                    "objective": "Harden winner selection against validator influence",
                    "sources": [
                        {
                            "id": "winner_entropy",
                            "consumer_function": "drawWinner",
                            "source_kind": "timestamp",
                            "source_expression": "keccak256(block.timestamp, msg.sender)",
                            "entropy_scope": "lottery winner selection",
                            "commit_phase": "",
                            "reveal_phase": "",
                            "request_id_source": "",
                            "fulfillment_guard": "",
                            "confirmation_depth": "",
                            "modulo_bias_guard": "none",
                            "evidence": ["timestamp feeds winner hash"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "timestamp_bias",
                            "category": "timestamp_bias",
                            "affected_source_id": "winner_entropy",
                            "severity_hint": "high",
                            "description": "validator-controlled timestamp can bias winner selection",
                            "evidence": ["block.timestamp is hashed into entropy"],
                            "recommended_check": "timestamp mutation changes winner",
                        }
                    ],
                    "validation_tests": ["timestamp mutation changes winner"],
                    "recommended_tools": ["foundry", "echidna", "symbolic execution"],
                    "confidence": 0.86,
                    "evidence": ["random winner function is present"],
                }
            ]
        }
    )
    agent = RandomnessEntropyHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Lottery {
            address[] public players;
            function drawWinner() external view returns (address) {
                uint256 r = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
                return players[r % players.length];
            }
        }
        """,
        randomness_summary={"consumers": ["drawWinner"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.RANDOMNESS_ENTROPY_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "randomness entropy hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate sequence-oracle plans" in prompt_lower
    assert "do not duplicate economic attack simulation" in prompt_lower
    assert "regex-only" in prompt_lower
    assert provider.seen_task.inputs["randomness_summary"] == {"consumers": ["drawWinner"]}

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "lottery_entropy_plan"
    assert plan.sources[0].consumer_function == "drawWinner"
    assert plan.sources[0].source_kind == "timestamp"
    assert plan.sources[0].modulo_bias_guard == "none"
    assert plan.risks[0].category == "timestamp_bias"
    assert plan.validation_tests == ["timestamp mutation changes winner"]
    assert plan.recommended_tools == ["foundry", "echidna", "symbolic execution"]
    assert plan.confidence == 0.86


def test_erc4626_vault_inflation_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "erc4626_vault_inflation_hardening_plans": [
                {
                    "id": "vault_inflation_plan",
                    "objective": "harden first-depositor share inflation",
                    "surfaces": [
                        {
                            "id": "deposit_share_math",
                            "vault_function": "deposit",
                            "asset_function": "totalAssets",
                            "share_function": "convertToShares",
                            "total_assets_source": "asset.balanceOf(address(this))",
                            "total_supply_source": "totalSupply()",
                            "conversion_formula": "assets * totalSupply / totalAssets",
                            "rounding_direction": "down",
                            "empty_vault_behavior": "assets minted 1:1",
                            "donation_exposure": "direct transfer changes assets without shares",
                            "mitigation": "virtual shares",
                            "evidence": ["deposit calls convertToShares"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "first_deposit_donation",
                            "category": "direct_donation",
                            "affected_surface_id": "deposit_share_math",
                            "severity_hint": "high",
                            "description": "donation can make victim mint too few shares",
                            "evidence": ["totalAssets reads raw balance"],
                            "recommended_check": "donate before victim deposit",
                        }
                    ],
                    "mitigations": ["virtual shares", "minimum shares"],
                    "validation_tests": ["victim deposit after donation mints nonzero shares"],
                    "recommended_tools": ["foundry", "echidna", "symbolic execution"],
                    "confidence": 0.84,
                    "evidence": ["ERC4626 share math is present"],
                }
            ]
        }
    )
    agent = ERC4626VaultInflationHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Vault {
            uint256 public totalSupply;
            function totalAssets() public view returns (uint256) {
                return asset.balanceOf(address(this));
            }
            function convertToShares(uint256 assets) public view returns (uint256) {
                return assets * totalSupply / totalAssets();
            }
            function deposit(uint256 assets) external returns (uint256 shares) {
                shares = convertToShares(assets);
            }
        }
        """,
        vault_summary={"standards": ["ERC4626"], "surfaces": ["deposit"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ERC4626_VAULT_INFLATION_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "erc4626 vault inflation hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate sequence-oracle plans" in prompt_lower
    assert "do not duplicate snapshot fuzzing guidance" in prompt_lower
    assert "do not duplicate economic attack simulation" in prompt_lower
    assert "regex-only" in prompt_lower
    assert provider.seen_task.inputs["vault_summary"] == {
        "standards": ["ERC4626"],
        "surfaces": ["deposit"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "vault_inflation_plan"
    assert plan.surfaces[0].vault_function == "deposit"
    assert plan.surfaces[0].share_function == "convertToShares"
    assert plan.surfaces[0].rounding_direction == "down"
    assert plan.risks[0].category == "direct_donation"
    assert plan.mitigations == ["virtual shares", "minimum shares"]
    assert plan.validation_tests == ["victim deposit after donation mints nonzero shares"]
    assert plan.recommended_tools == ["foundry", "echidna", "symbolic execution"]
    assert plan.confidence == 0.84


def test_create2_deployment_hardening_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "create2_deployment_hardening_plans": [
                {
                    "id": "factory_salt_plan",
                    "objective": "bind deterministic wallet deployment to owner",
                    "surfaces": [
                        {
                            "id": "wallet_factory_deploy",
                            "deploy_function": "deployWallet",
                            "factory_contract": "WalletFactory",
                            "salt_source": "user supplied salt",
                            "init_code_source": "type(Wallet).creationCode",
                            "address_formula": "keccak256(0xff, factory, salt, init_code_hash)",
                            "authorization_guard": "salt includes owner",
                            "collision_check": "predicted.code.length == 0",
                            "post_deploy_check": "codehash matches wallet runtime",
                            "redeploy_assumption": "no selfdestruct redeploy",
                            "evidence": ["create2 assembly uses salt"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "salt_squatting",
                            "category": "salt_squatting",
                            "affected_surface_id": "wallet_factory_deploy",
                            "severity_hint": "high",
                            "description": "attacker can deploy first with the same salt",
                            "evidence": ["salt is public input"],
                            "recommended_check": "attacker front-runs deployWallet",
                        }
                    ],
                    "mitigations": ["bind salt to owner", "verify codehash"],
                    "validation_tests": ["same salt from attacker cannot capture wallet"],
                    "recommended_tools": ["foundry", "slither", "fork simulation"],
                    "confidence": 0.85,
                    "evidence": ["CREATE2 factory present"],
                }
            ]
        }
    )
    agent = Create2DeploymentHardeningAgent(provider)

    plans = agent.plan(
        """
        contract WalletFactory {
            function deployWallet(bytes32 salt, address owner) external returns (address wallet) {
                bytes memory code = abi.encodePacked(type(Wallet).creationCode, owner);
                assembly { wallet := create2(0, add(code, 0x20), mload(code), salt) }
            }
        }
        """,
        deployment_summary={"factories": ["WalletFactory"], "opcodes": ["CREATE2"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.CREATE2_DEPLOYMENT_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "create2 deployment hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate metamorphic differential testing" in prompt_lower
    assert "do not duplicate upgrade or delegatecall analysis" in prompt_lower
    assert "regex-only" in prompt_lower
    assert provider.seen_task.inputs["deployment_summary"] == {
        "factories": ["WalletFactory"],
        "opcodes": ["CREATE2"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "factory_salt_plan"
    assert plan.surfaces[0].deploy_function == "deployWallet"
    assert plan.surfaces[0].salt_source == "user supplied salt"
    assert plan.risks[0].category == "salt_squatting"
    assert plan.mitigations == ["bind salt to owner", "verify codehash"]
    assert plan.validation_tests == ["same salt from attacker cannot capture wallet"]
    assert plan.recommended_tools == ["foundry", "slither", "fork simulation"]
    assert plan.confidence == 0.85


def test_abi_packed_hash_collision_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "abi_packed_hash_collision_hardening_plans": [
                {
                    "id": "claim_hash_plan",
                    "objective": "harden packed claim hash",
                    "surfaces": [
                        {
                            "id": "claim_hash",
                            "hash_function": "claim",
                            "packed_expression": "keccak256(abi.encodePacked(a, b))",
                            "argument_types": ["string", "string"],
                            "dynamic_argument_count": "2",
                            "user_controlled_arguments": ["a", "b"],
                            "hash_usage": "mapping_key",
                            "domain_separator": "contract address",
                            "delimiter_or_length_guard": "none",
                            "safer_encoding": "abi.encode(a, b)",
                            "evidence": ["packed dynamic hash"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "ambiguous_dynamic_encoding",
                            "category": "multiple_dynamic_args",
                            "affected_surface_id": "claim_hash",
                            "severity_hint": "high",
                            "description": "different dynamic inputs can produce the same packed bytes",
                            "evidence": ["two string args are packed"],
                            "recommended_check": "('a','bc') collides with ('ab','c')",
                        }
                    ],
                    "mitigations": ["use abi.encode", "add length prefixes"],
                    "validation_tests": ["crafted dynamic inputs cannot collide"],
                    "recommended_tools": ["foundry", "slither", "property testing"],
                    "confidence": 0.87,
                    "evidence": ["keccak256 abi.encodePacked is present"],
                }
            ]
        }
    )
    agent = AbiPackedHashCollisionHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Claims {
            mapping(bytes32 => bool) public used;
            function claim(string calldata a, string calldata b) external {
                bytes32 key = keccak256(abi.encodePacked(a, b));
                require(!used[key], "used");
                used[key] = true;
            }
        }
        """,
        hash_summary={"packed_hashes": ["claim"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ABI_PACKED_HASH_COLLISION_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "abi packed hash collision hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate signature-domain hardening" in prompt_lower
    assert "do not duplicate randomness or commit-reveal hardening" in prompt_lower
    assert "do not duplicate cross-chain message hardening" in prompt_lower
    assert "regex-only" in prompt_lower
    assert provider.seen_task.inputs["hash_summary"] == {"packed_hashes": ["claim"]}

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "claim_hash_plan"
    assert plan.surfaces[0].hash_function == "claim"
    assert plan.surfaces[0].argument_types == ["string", "string"]
    assert plan.surfaces[0].hash_usage == "mapping_key"
    assert plan.risks[0].category == "multiple_dynamic_args"
    assert plan.mitigations == ["use abi.encode", "add length prefixes"]
    assert plan.validation_tests == ["crafted dynamic inputs cannot collide"]
    assert plan.confidence == 0.87


def test_token_hook_reentrancy_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "token_hook_reentrancy_hardening_plans": [
                {
                    "id": "erc777_deposit_hook_plan",
                    "objective": "harden deposit against ERC777 hook reentry",
                    "surfaces": [
                        {
                            "id": "deposit_hook_surface",
                            "entrypoint": "deposit",
                            "token_standard": "ERC777",
                            "hook_function": "tokensReceived",
                            "external_token_call": "token.transferFrom(msg.sender, address(this), amount)",
                            "state_update_order": "external token call before balance update",
                            "accounting_fields": ["balances", "totalDeposits"],
                            "expected_callback_sender": "trusted token contract",
                            "guard": "nonReentrant",
                            "evidence": ["transferFrom can trigger ERC777 hook"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "hook_before_effects",
                            "category": "hook_before_effects",
                            "affected_surface_id": "deposit_hook_surface",
                            "severity_hint": "high",
                            "description": "token hook can reenter deposit before balances update",
                            "evidence": ["external token call precedes accounting"],
                            "recommended_check": "malicious token hook reenters before balances update",
                        }
                    ],
                    "mitigations": ["checks-effects-interactions", "nonReentrant"],
                    "validation_tests": ["malicious ERC777 hook cannot reenter deposit"],
                    "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
                    "confidence": 0.86,
                    "evidence": ["ERC777 callback signal is present"],
                }
            ]
        }
    )
    agent = TokenHookReentrancyHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Vault {
            mapping(address => uint256) public balances;
            IERC777 public token;
            function deposit(uint256 amount) external {
                token.transferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """,
        token_summary={"hooks": ["tokensReceived"], "standards": ["ERC777"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.TOKEN_HOOK_REENTRANCY_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "token hook reentrancy hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate generic reentrancy triage" in prompt_lower
    assert "do not duplicate transient storage hardening" in prompt_lower
    assert "do not duplicate erc4626 inflation hardening" in prompt_lower
    assert provider.seen_task.inputs["token_summary"] == {
        "hooks": ["tokensReceived"],
        "standards": ["ERC777"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "erc777_deposit_hook_plan"
    assert plan.surfaces[0].entrypoint == "deposit"
    assert plan.surfaces[0].token_standard == "ERC777"
    assert plan.surfaces[0].hook_function == "tokensReceived"
    assert plan.risks[0].category == "hook_before_effects"
    assert plan.mitigations == ["checks-effects-interactions", "nonReentrant"]
    assert plan.validation_tests == ["malicious ERC777 hook cannot reenter deposit"]
    assert plan.confidence == 0.86


def test_erc20_token_compatibility_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "erc20_token_compatibility_hardening_plans": [
                {
                    "id": "fee_token_deposit_plan",
                    "objective": "credit only actual received amount for fee tokens",
                    "surfaces": [
                        {
                            "id": "deposit_transfer_surface",
                            "entrypoint": "deposit",
                            "token_call": "token.safeTransferFrom(msg.sender, address(this), amount)",
                            "requested_amount_source": "amount",
                            "balance_before_source": "balanceBefore",
                            "balance_after_source": "balanceAfter",
                            "credited_amount_source": "amount",
                            "token_traits": ["fee_on_transfer", "missing_return"],
                            "accounting_fields": ["balances", "totalDeposits"],
                            "guard": "SafeERC20 without balance delta",
                            "evidence": ["requested amount is credited after transferFrom"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "requested_amount_credit",
                            "category": "fee_on_transfer_misaccounting",
                            "affected_surface_id": "deposit_transfer_surface",
                            "severity_hint": "high",
                            "description": "fee-on-transfer token can credit more than received",
                            "evidence": ["balance delta is not used"],
                            "recommended_check": "fee-on-transfer token credits only actual received amount",
                        }
                    ],
                    "mitigations": ["use SafeERC20", "credit balance delta"],
                    "validation_tests": ["fee-on-transfer deposit credits actual received"],
                    "recommended_tools": ["foundry", "slither", "stateful fuzzing"],
                    "confidence": 0.84,
                    "evidence": ["ERC20 transferFrom and deposit accounting are present"],
                }
            ]
        }
    )
    agent = ERC20TokenCompatibilityHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Vault {
            using SafeERC20 for IERC20;
            mapping(address => uint256) public balances;
            IERC20 public token;
            function deposit(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount);
                balances[msg.sender] += amount;
            }
        }
        """,
        token_summary={"traits": ["fee_on_transfer", "missing_return"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ERC20_TOKEN_COMPATIBILITY_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "erc20 token compatibility and accounting hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate erc4626 vault inflation hardening" in prompt_lower
    assert "do not duplicate token hook reentrancy hardening" in prompt_lower
    assert "do not reduce this to generic unchecked return value triage" in prompt_lower
    assert provider.seen_task.inputs["token_summary"] == {
        "traits": ["fee_on_transfer", "missing_return"]
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "fee_token_deposit_plan"
    assert plan.surfaces[0].entrypoint == "deposit"
    assert plan.surfaces[0].token_traits == ["fee_on_transfer", "missing_return"]
    assert plan.surfaces[0].credited_amount_source == "amount"
    assert plan.risks[0].category == "fee_on_transfer_misaccounting"
    assert plan.mitigations == ["use SafeERC20", "credit balance delta"]
    assert plan.validation_tests == ["fee-on-transfer deposit credits actual received"]
    assert plan.confidence == 0.84


def test_account_abstraction_userop_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "account_abstraction_userop_hardening_plans": [
                {
                    "id": "entrypoint_guard_plan",
                    "objective": "harden validateUserOp caller and replay scope",
                    "surfaces": [
                        {
                            "id": "validate_userop_surface",
                            "component": "account",
                            "entrypoint_function": "validateUserOp",
                            "entrypoint_guard": "missing msg.sender == entryPoint check",
                            "userop_fields": ["sender", "nonce", "callData", "signature"],
                            "signature_scheme": "userOpHash",
                            "nonce_source": "nonces[userOp.sender]",
                            "prefund_source": "missingAccountFunds",
                            "validation_data_source": "validationData",
                            "evidence": ["validateUserOp is public and checks signature"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "missing_entrypoint_guard",
                            "category": "entrypoint_guard",
                            "affected_surface_id": "validate_userop_surface",
                            "severity_hint": "high",
                            "description": "validateUserOp can be called outside the trusted EntryPoint",
                            "evidence": ["no msg.sender EntryPoint require"],
                            "recommended_check": "direct validateUserOp call must revert",
                        }
                    ],
                    "mitigations": ["gate validation to the trusted EntryPoint"],
                    "validation_tests": ["direct validateUserOp call from non-EntryPoint reverts"],
                    "recommended_tools": ["foundry", "erc4337 simulation"],
                    "confidence": 0.83,
                    "evidence": ["ERC-4337 validateUserOp signal is present"],
                }
            ]
        }
    )
    agent = AccountAbstractionUserOpHardeningAgent(provider)

    plans = agent.plan(
        """
        contract SmartAccount {
            IEntryPoint public entryPoint;
            function validateUserOp(
                PackedUserOperation calldata userOp,
                bytes32 userOpHash,
                uint256 missingAccountFunds
            ) external returns (uint256 validationData) {
                _validateSignature(userOp, userOpHash);
                if (missingAccountFunds > 0) payable(msg.sender).transfer(missingAccountFunds);
                return 0;
            }
        }
        """,
        account_summary={"components": ["account"], "functions": ["validateUserOp"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.ACCOUNT_ABSTRACTION_USEROP_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "account abstraction useroperation hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate signature-domain hardening" in prompt_lower
    assert "do not duplicate create2 deployment hardening" in prompt_lower
    assert "do not duplicate cross-chain message hardening" in prompt_lower
    assert "do not duplicate erc20 token compatibility hardening" in prompt_lower
    assert provider.seen_task.inputs["account_summary"] == {
        "components": ["account"],
        "functions": ["validateUserOp"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "entrypoint_guard_plan"
    assert plan.surfaces[0].component == "account"
    assert plan.surfaces[0].entrypoint_function == "validateUserOp"
    assert plan.surfaces[0].userop_fields == ["sender", "nonce", "callData", "signature"]
    assert plan.risks[0].category == "entrypoint_guard"
    assert plan.mitigations == ["gate validation to the trusted EntryPoint"]
    assert plan.validation_tests == ["direct validateUserOp call from non-EntryPoint reverts"]
    assert plan.confidence == 0.83


def test_external_call_returndata_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "external_call_returndata_hardening_plans": [
                {
                    "id": "staticcall_decode_plan",
                    "objective": "bound and validate untrusted staticcall returndata",
                    "surfaces": [
                        {
                            "id": "quote_staticcall_surface",
                            "entrypoint": "quote",
                            "target_source": "oracleAdapter",
                            "call_kind": "staticcall",
                            "calldata_source": "abi.encodeWithSelector(IOracle.quote.selector, amount)",
                            "returndata_source": "bytes memory data",
                            "decode_site": "abi.decode(data, (uint256))",
                            "returndata_size_bound": "none",
                            "success_guard": "require(success)",
                            "trust_boundary": "registry-controlled adapter",
                            "value_forwarding": "none",
                            "evidence": ["staticcall result is decoded without length check"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "malformed_quote_decode",
                            "category": "malformed_returndata_dos",
                            "affected_surface_id": "quote_staticcall_surface",
                            "severity_hint": "medium",
                            "description": "malformed returndata can revert quote path",
                            "evidence": ["data.length is not checked before abi.decode"],
                            "recommended_check": "adapter returning 31 bytes must be handled",
                        }
                    ],
                    "mitigations": ["check data.length before abi.decode"],
                    "validation_tests": ["malformed returndata does not update quote cache"],
                    "recommended_tools": ["foundry", "slither"],
                    "confidence": 0.82,
                    "evidence": ["low-level staticcall and abi.decode are present"],
                }
            ]
        }
    )
    agent = ExternalCallReturndataHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Router {
            address public oracleAdapter;
            uint256 public lastQuote;
            function quote(uint256 amount) external returns (uint256) {
                (bool success, bytes memory data) = oracleAdapter.staticcall(
                    abi.encodeWithSelector(IOracle.quote.selector, amount)
                );
                require(success);
                uint256 value = abi.decode(data, (uint256));
                lastQuote = value;
                return value;
            }
        }
        """,
        call_summary={"call_kinds": ["staticcall"], "decode_sites": ["abi.decode"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.EXTERNAL_CALL_RETURNDATA_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "external call returndata hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate delegatecall storage-aliasing hardening" in prompt_lower
    assert "do not duplicate token hook reentrancy hardening" in prompt_lower
    assert "do not duplicate erc20 token compatibility hardening" in prompt_lower
    assert "do not reduce this to generic unchecked-call triage" in prompt_lower
    assert provider.seen_task.inputs["call_summary"] == {
        "call_kinds": ["staticcall"],
        "decode_sites": ["abi.decode"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "staticcall_decode_plan"
    assert plan.surfaces[0].entrypoint == "quote"
    assert plan.surfaces[0].call_kind == "staticcall"
    assert plan.surfaces[0].decode_site == "abi.decode(data, (uint256))"
    assert plan.risks[0].category == "malformed_returndata_dos"
    assert plan.mitigations == ["check data.length before abi.decode"]
    assert plan.validation_tests == ["malformed returndata does not update quote cache"]
    assert plan.confidence == 0.82


def test_financial_math_precision_agent_uses_provider_neutral_capability():
    provider = FakeReasoningProvider(
        {
            "financial_math_precision_hardening_plans": [
                {
                    "id": "reward_precision_plan",
                    "objective": "reward calculation preserves precision across scales",
                    "surfaces": [
                        {
                            "id": "reward_formula_surface",
                            "entrypoint": "accrue",
                            "formula": "reward = amount / totalShares * rewardRate",
                            "value_flow": "reward distribution",
                            "unit_sources": [
                                "amount:token",
                                "totalShares:shares",
                                "rewardRate:1e18",
                            ],
                            "scale_factor": "1e18",
                            "rounding_direction": "down",
                            "operation_order": "division_before_multiplication",
                            "library_or_helper": "",
                            "unchecked_context": "",
                            "state_fields": ["accRewardPerShare"],
                            "evidence": ["reward formula divides before multiplying"],
                        }
                    ],
                    "risks": [
                        {
                            "id": "division_before_multiplication",
                            "category": "division_before_multiplication",
                            "affected_surface_id": "reward_formula_surface",
                            "severity_hint": "medium",
                            "description": "small rewards can be truncated before scaling",
                            "evidence": ["amount / totalShares occurs before rewardRate multiply"],
                            "recommended_check": "tiny amount still accrues expected scaled reward",
                        }
                    ],
                    "mitigations": ["use full-precision mulDiv"],
                    "validation_tests": ["small and large rewards preserve precision"],
                    "recommended_tools": ["foundry", "slither"],
                    "confidence": 0.84,
                    "evidence": ["financial reward math signal is present"],
                }
            ]
        }
    )
    agent = FinancialMathPrecisionHardeningAgent(provider)

    plans = agent.plan(
        """
        contract Rewards {
            uint256 public accRewardPerShare;
            function accrue(uint256 amount, uint256 totalShares, uint256 rewardRate) external {
                uint256 reward = amount / totalShares * rewardRate;
                accRewardPerShare += reward;
            }
        }
        """,
        math_summary={"surfaces": ["reward"], "units": ["1e18"]},
    )

    assert provider.seen_task is not None
    assert provider.seen_task.capability == AgentCapability.FINANCIAL_MATH_PRECISION_HARDENING
    prompt_lower = provider.seen_task.prompt.lower()
    assert "interchangeable security reasoning agent" in prompt_lower
    assert "financial math precision hardening plans" in prompt_lower
    assert "specific model" in prompt_lower
    assert "deepseek" not in prompt_lower
    assert "openai" not in prompt_lower
    assert "anthropic" not in prompt_lower
    assert "do not duplicate erc4626 vault inflation hardening" in prompt_lower
    assert "do not duplicate oracle feed hardening" in prompt_lower
    assert "do not duplicate economic attack simulation" in prompt_lower
    assert "does not prevent precision/rounding loss" in prompt_lower
    assert provider.seen_task.inputs["math_summary"] == {
        "surfaces": ["reward"],
        "units": ["1e18"],
    }

    assert len(plans) == 1
    plan = plans[0]
    assert plan.id == "reward_precision_plan"
    assert plan.surfaces[0].entrypoint == "accrue"
    assert plan.surfaces[0].formula == "reward = amount / totalShares * rewardRate"
    assert plan.surfaces[0].unit_sources == [
        "amount:token",
        "totalShares:shares",
        "rewardRate:1e18",
    ]
    assert plan.surfaces[0].operation_order == "division_before_multiplication"
    assert plan.surfaces[0].state_fields == ["accRewardPerShare"]
    assert plan.risks[0].category == "division_before_multiplication"
    assert plan.mitigations == ["use full-precision mulDiv"]
    assert plan.validation_tests == ["small and large rewards preserve precision"]
    assert plan.confidence == 0.84


def test_invariant_extraction_task_carries_dpg_policy():
    policy = DPGAgentConfig(local_first=True, allow_remote=False, max_source_chars=40)
    provider = FakeReasoningProvider({"invariants": []})
    agent = InvariantExtractionAgent(provider, policy=policy)

    task = agent.build_task("contract A {" + (" " * 100) + "}", contract_path="A.sol")

    exported = task.to_dict()
    assert exported["policy"]["local_first"] is True
    assert exported["policy"]["allow_remote"] is False
    assert exported["policy"]["require_replaceable_provider"] is True
    assert exported["inputs"]["source_chars"] == 40


def test_parse_invariant_candidates_accepts_json_string_and_bounds_confidence():
    candidates = parse_invariant_candidates("""
        {
          "invariants": [
            {
              "statement": "unlockTime must not increase when user adds no new lock",
              "category": "state-sync",
              "affected_functions": ["lockOnBehalf"],
              "state_variables": ["unlockTime"],
              "confidence": "1.7"
            }
          ]
        }
        """)

    assert len(candidates) == 1
    assert candidates[0].id.startswith("unlocktime_must_not_increase")
    assert candidates[0].category == InvariantCategory.STATE_SYNC
    assert candidates[0].confidence == 1.0


def test_parse_invariant_candidates_rejects_malformed_items():
    candidates = parse_invariant_candidates(
        {
            "invariants": [
                {"id": "missing_statement"},
                ["bad"],
                {"statement": "valid invariant", "category": "unknown", "confidence": -2},
            ]
        }
    )

    assert len(candidates) == 1
    assert candidates[0].statement == "valid invariant"
    assert candidates[0].confidence == 0.0


def test_parse_sequence_oracle_plans_accepts_alias_and_bounds_fields():
    plans = parse_sequence_oracle_plans("""
        {
          "plans": [
            {
              "objective": "liquidation path should preserve solvency",
              "sequence": [
                {"function": "borrow", "actor": "victim", "arguments": ["max"]},
                {"function": "liquidate", "actor": "liquidator"}
              ],
              "oracle": "protocol solvency is not reduced by liquidation",
              "confidence": "1.5",
              "metadata": {"raw": {"nested": true}}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("liquidation_path_should_preserve")
    assert plans[0].sequence[0].function == "borrow"
    assert plans[0].sequence[1].actor == "liquidator"
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"raw": {"nested": True}}


def test_parse_sequence_oracle_plans_rejects_incomplete_or_malformed_items():
    plans = parse_sequence_oracle_plans(
        {
            "sequence_oracle_plans": [
                {"objective": "missing oracle", "sequence": [{"function": "deposit"}]},
                {"objective": "missing steps", "oracle": "bad"},
                {
                    "objective": "valid",
                    "oracle": "fails when balance decreases",
                    "sequence": [{"function": "withdraw"}, {"function": "bad\x00name"}],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid"
    assert plans[0].sequence[0].function == "withdraw"
    assert plans[0].confidence == 0.0


def test_parse_semantic_graph_gates_accepts_alias_and_bounds_fields():
    gates = parse_semantic_graph_gates("""
        {
          "graph_gates": [
            {
              "objective": "Focus reentrancy path",
              "focal_nodes": ["fn_withdraw"],
              "nodes": [
                {"id": "fn_withdraw", "kind": "function", "line": 9999999}
              ],
              "edges": [
                {
                  "source": "fn_withdraw",
                  "target": "state_balances",
                  "relation": "writes",
                  "confidence": "1.4"
                }
              ],
              "confidence": "0.66",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(gates) == 1
    assert gates[0].id.startswith("focus_reentrancy_path")
    assert gates[0].nodes[0].line == 1_000_000
    assert gates[0].edges[0].confidence == 1.0
    assert gates[0].confidence == 0.66
    assert gates[0].metadata == {"source": "local"}


def test_parse_semantic_graph_gates_rejects_empty_focus():
    gates = parse_semantic_graph_gates(
        {
            "semantic_graph_gates": [
                {"objective": "no graph"},
                {
                    "objective": "valid focal only",
                    "focal_nodes": ["fn_deposit"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(gates) == 1
    assert gates[0].objective == "valid focal only"
    assert gates[0].focal_nodes == ["fn_deposit"]
    assert gates[0].confidence == 0.0


def test_parse_snapshot_fuzzing_plans_accepts_alias_and_bounds_fields():
    plans = parse_snapshot_fuzzing_plans("""
        {
          "snapshot_campaigns": [
            {
              "objective": "hit liquidation frontier",
              "seeds": [
                {
                  "id": "seed_debt_position",
                  "target_state": "borrower has debt",
                  "priority": "1.4"
                }
              ],
              "waypoints": [
                {
                  "id": "health_factor_branch",
                  "kind": "branch",
                  "target": "healthFactor < 1",
                  "distance_hint": "minimize healthFactor - 1"
                }
              ],
              "oracle": "liquidation preserves solvency",
              "confidence": "0.7",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("hit_liquidation_frontier")
    assert plans[0].seeds[0].priority == 1.0
    assert plans[0].waypoints[0].kind == "branch"
    assert plans[0].confidence == 0.7
    assert plans[0].metadata == {"source": "local"}


def test_parse_snapshot_fuzzing_plans_rejects_incomplete_items():
    plans = parse_snapshot_fuzzing_plans(
        {
            "snapshot_fuzzing_plans": [
                {"objective": "missing oracle", "seeds": [{"id": "s", "target_state": "x"}]},
                {"objective": "missing guidance", "oracle": "bad"},
                {
                    "objective": "valid",
                    "oracle": "no accounting drift",
                    "priority_transactions": [{"function": "deposit"}],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid"
    assert plans[0].priority_transactions[0].function == "deposit"
    assert plans[0].confidence == 0.0


def test_parse_economic_attack_plans_accepts_alias_and_bounds_fields():
    plans = parse_economic_attack_plans("""
        {
          "economic_simulation_plans": [
            {
              "objective": "check liquidation profitability",
              "capital_requirements": [
                {"asset": "USDC", "amount_hint": "borrower debt range", "source": "flash loan"}
              ],
              "asset_flows": [
                {"asset": "WETH", "from_actor": "protocol", "to_actor": "liquidator"}
              ],
              "profit_formula": "seized_collateral - repaid_debt - fees",
              "liquidity_assumptions": ["collateral can be sold"],
              "confidence": "1.5",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("check_liquidation_profitability")
    assert plans[0].capital_requirements[0].asset == "USDC"
    assert plans[0].capital_requirements[0].source == "flash loan"
    assert plans[0].asset_flows[0].from_actor == "protocol"
    assert plans[0].profit_formula == "seized_collateral - repaid_debt - fees"
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}


def test_parse_economic_attack_plans_rejects_incomplete_items():
    plans = parse_economic_attack_plans(
        {
            "economic_attack_plans": [
                {"objective": "missing formula", "asset_flows": [{"asset": "USDC"}]},
                {"objective": "missing economics", "profit_formula": "x-y"},
                {
                    "objective": "valid",
                    "profit_formula": "profit - cost",
                    "liquidity_assumptions": ["bounded slippage"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid"
    assert plans[0].liquidity_assumptions == ["bounded slippage"]
    assert plans[0].confidence == 0.0


def test_parse_differential_test_plans_accepts_alias_and_bounds_fields():
    plans = parse_differential_test_plans("""
        {
          "metamorphic_test_plans": [
            {
              "objective": "round-trip mint redeem should preserve assets",
              "relations": [
                {
                  "id": "mint_redeem_round_trip",
                  "relation_type": "round_trip",
                  "baseline_sequence": [{"function": "mint", "arguments": ["shares"]}],
                  "variant_sequence": [
                    {"function": "mint", "arguments": ["shares"]},
                    {"function": "redeem", "arguments": ["shares"]}
                  ],
                  "expected_relation": "net assets return to starting value",
                  "tolerance_hint": "one wei"
                }
              ],
              "state_observables": ["asset.balanceOf(user)", "totalSupply()"],
              "oracle": "round trip leaks assets",
              "confidence": "1.3",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("round_trip_mint_redeem")
    assert plans[0].relations[0].id == "mint_redeem_round_trip"
    assert plans[0].relations[0].relation_type == "round_trip"
    assert plans[0].relations[0].variant_sequence[1].function == "redeem"
    assert plans[0].state_observables == ["asset.balanceOf(user)", "totalSupply()"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}


def test_parse_differential_test_plans_rejects_incomplete_items():
    plans = parse_differential_test_plans(
        {
            "differential_test_plans": [
                {"objective": "missing oracle", "relations": []},
                {"objective": "missing relations", "oracle": "bad"},
                {
                    "objective": "bad relation",
                    "oracle": "bad",
                    "relations": [
                        {
                            "id": "missing_variant",
                            "relation_type": "equivalence",
                            "baseline_sequence": [{"function": "deposit"}],
                            "expected_relation": "same shares",
                        }
                    ],
                },
                {
                    "objective": "valid",
                    "oracle": "relations diverge",
                    "relations": [
                        {
                            "id": "split_merge",
                            "relation_type": "split_merge",
                            "baseline_sequence": [{"function": "deposit"}],
                            "variant_sequence": [{"function": "deposit"}],
                            "expected_relation": "same final shares",
                        }
                    ],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid"
    assert plans[0].relations[0].id == "split_merge"
    assert plans[0].confidence == 0.0


def test_parse_upgrade_evolution_plans_accepts_alias_and_bounds_fields():
    plans = parse_upgrade_evolution_plans("""
        {
          "upgrade_analysis_plans": [
            {
              "objective": "detect storage drift during UUPS upgrade",
              "proxy_pattern": "uups",
              "old_implementation": "VaultV1",
              "new_implementation": "VaultV2",
              "storage_changes": [
                {
                  "slot": "1",
                  "before": "uint256 totalAssets",
                  "after": "address feeRecipient",
                  "change_type": "insert_before_existing",
                  "risk": "totalAssets storage shifts to a new slot"
                }
              ],
              "risks": [
                {
                  "id": "owner_reinitializer",
                  "category": "initializer",
                  "description": "reinitializer can reset the owner",
                  "severity_hint": "high"
                }
              ],
              "migration_checks": ["upgrade preserves totalAssets"],
              "confidence": "1.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("detect_storage_drift")
    assert plans[0].proxy_pattern == "uups"
    assert plans[0].storage_changes[0].slot == "1"
    assert plans[0].storage_changes[0].change_type == "insert_before_existing"
    assert plans[0].risks[0].id == "owner_reinitializer"
    assert plans[0].risks[0].severity_hint == "high"
    assert plans[0].migration_checks == ["upgrade preserves totalAssets"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}


def test_parse_upgrade_evolution_plans_rejects_incomplete_items():
    plans = parse_upgrade_evolution_plans(
        {
            "upgrade_evolution_plans": [
                {"storage_changes": [{"slot": "0", "risk": "missing objective"}]},
                {"objective": "missing evidence"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid migration-only plan",
                    "migration_checks": ["dry-run upgrade preserves owner"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid migration-only plan"
    assert plans[0].migration_checks == ["dry-run upgrade preserves owner"]
    assert plans[0].confidence == 0.0


def test_parse_signature_domain_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_signature_domain_hardening_plans("""
        {
          "signature_domain_plans": [
            {
              "objective": "harden permit replay domain",
              "signed_actions": [
                {
                  "id": "permit_action",
                  "function": "permit",
                  "signer_source": "ECDSA.recover",
                  "digest_scheme": "eip712",
                  "domain_fields": ["name", "version", "chainId", "verifyingContract"],
                  "nonce_source": "nonces[owner]",
                  "deadline_source": "deadline",
                  "value_scope": ["owner", "spender", "value"]
                }
              ],
              "risks": [
                {
                  "id": "missing_verifying_contract",
                  "category": "cross_contract_replay",
                  "affected_action_id": "permit_action",
                  "description": "domain omits verifyingContract"
                }
              ],
              "replay_tests": ["replay signature on a second verifying contract"],
              "confidence": "1.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_permit_replay_domain")
    assert plans[0].signed_actions[0].id == "permit_action"
    assert plans[0].signed_actions[0].digest_scheme == "eip712"
    assert plans[0].signed_actions[0].domain_fields == [
        "name",
        "version",
        "chainId",
        "verifyingContract",
    ]
    assert plans[0].risks[0].id == "missing_verifying_contract"
    assert plans[0].risks[0].category == "cross_contract_replay"
    assert plans[0].replay_tests == ["replay signature on a second verifying contract"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}


def test_parse_signature_domain_hardening_plans_rejects_incomplete_items():
    plans = parse_signature_domain_hardening_plans(
        {
            "signature_domain_hardening_plans": [
                {"signed_actions": [{"id": "missing_objective", "function": "permit"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid replay-only plan",
                    "replay_tests": ["same signature fails after nonce increments"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid replay-only plan"
    assert plans[0].replay_tests == ["same signature fails after nonce increments"]
    assert plans[0].confidence == 0.0


def test_parse_cross_chain_message_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_cross_chain_message_hardening_plans("""
        {
          "bridge_message_hardening_plans": [
            {
              "objective": "harden bridge message replay",
              "message_flows": [
                {
                  "id": "outbox_execute",
                  "handler_function": "executeMessage",
                  "source_domain": "L2",
                  "destination_domain": "L1",
                  "trusted_sender_source": "canonicalMessenger",
                  "message_id_source": "messageHash",
                  "replay_guard": "spentMessages[messageHash]",
                  "finality_assumption": "withdrawal delay elapsed",
                  "payload_scope": ["target", "value", "calldata"]
                }
              ],
              "risks": [
                {
                  "id": "missing_replay_guard",
                  "category": "replay_guard",
                  "affected_flow_id": "outbox_execute",
                  "description": "message hash is not marked consumed"
                }
              ],
              "validation_tests": ["execute same message hash twice must revert"],
              "confidence": "1.6",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_bridge_message_replay")
    assert plans[0].message_flows[0].id == "outbox_execute"
    assert plans[0].message_flows[0].handler_function == "executeMessage"
    assert plans[0].message_flows[0].payload_scope == ["target", "value", "calldata"]
    assert plans[0].risks[0].category == "replay_guard"
    assert plans[0].validation_tests == ["execute same message hash twice must revert"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_cross_chain_message_hardening_plans(
        {
            "cross_chain_validation_plans": [
                {
                    "objective": "validate cross-chain replay guard",
                    "validation_tests": ["same message id cannot execute twice"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate cross-chain replay guard"
    assert alias_plans[0].validation_tests == ["same message id cannot execute twice"]


def test_parse_cross_chain_message_hardening_plans_rejects_incomplete_items():
    plans = parse_cross_chain_message_hardening_plans(
        {
            "cross_chain_message_hardening_plans": [
                {"message_flows": [{"id": "missing_objective", "handler_function": "x"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["spoofed remote sender must revert"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["spoofed remote sender must revert"]
    assert plans[0].confidence == 0.0


def test_parse_delegatecall_storage_aliasing_plans_accepts_alias_and_bounds_fields():
    plans = parse_delegatecall_storage_aliasing_plans("""
        {
          "delegatecall_aliasing_plans": [
            {
              "objective": "prove delegatecall storage collision cannot change owner",
              "delegatecall_surfaces": [
                {
                  "id": "fallback_delegate",
                  "caller_function": "fallback",
                  "target_source": "implementation",
                  "selector_source": "msg.data",
                  "target_trust_boundary": "admin registry",
                  "guard_summary": "target is whitelisted",
                  "value_forwarding": "msg.value preserved"
                }
              ],
              "storage_alias_paths": [
                {
                  "id": "owner_slot_alias",
                  "delegatecall_surface_id": "fallback_delegate",
                  "caller_slot": "slot 0",
                  "callee_slot": "slot 0",
                  "caller_semantics": "owner",
                  "callee_semantics": "initialized",
                  "write_source": "initialize() writes slot 0",
                  "path_condition": "selector can reach initialize"
                }
              ],
              "risks": [
                {
                  "id": "owner_takeover",
                  "category": "initializer_takeover",
                  "affected_surface_id": "fallback_delegate",
                  "description": "callee initializer can reinterpret caller owner slot"
                }
              ],
              "validation_tests": ["malicious implementation cannot set owner"],
              "confidence": "1.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("prove_delegatecall_storage_collision")
    assert plans[0].delegatecall_surfaces[0].id == "fallback_delegate"
    assert plans[0].delegatecall_surfaces[0].caller_function == "fallback"
    assert plans[0].storage_alias_paths[0].caller_semantics == "owner"
    assert plans[0].storage_alias_paths[0].callee_semantics == "initialized"
    assert plans[0].risks[0].category == "initializer_takeover"
    assert plans[0].validation_tests == ["malicious implementation cannot set owner"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_delegatecall_storage_aliasing_plans(
        {
            "storage_collision_plans": [
                {
                    "objective": "validate storage aliasing",
                    "validation_tests": ["callee write does not change owner"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate storage aliasing"
    assert alias_plans[0].validation_tests == ["callee write does not change owner"]


def test_parse_delegatecall_storage_aliasing_plans_rejects_incomplete_items():
    plans = parse_delegatecall_storage_aliasing_plans(
        {
            "delegatecall_storage_aliasing_plans": [
                {
                    "delegatecall_surfaces": [
                        {"id": "missing_objective", "caller_function": "fallback"}
                    ]
                },
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["untrusted callee cannot write caller slot"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["untrusted callee cannot write caller slot"]
    assert plans[0].confidence == 0.0


def test_parse_oracle_feed_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_oracle_feed_hardening_plans("""
        {
          "price_feed_validation_plans": [
            {
              "objective": "harden Chainlink price reads",
              "feeds": [
                {
                  "id": "eth_usd",
                  "consumer_function": "getPrice",
                  "feed_kind": "chainlink",
                  "source_contract": "priceFeed",
                  "read_method": "latestRoundData",
                  "freshness_source": "updatedAt",
                  "staleness_threshold": "3600 seconds",
                  "decimals_source": "decimals()",
                  "normalization": "scale to 1e18",
                  "fallback_source": "none",
                  "sequencer_guard": "sequencer uptime feed",
                  "bounds_check": "answer > 0"
                }
              ],
              "risks": [
                {
                  "id": "missing_answer_bounds",
                  "category": "zero_negative_price",
                  "affected_feed_id": "eth_usd",
                  "description": "negative answer can cast to a huge uint"
                }
              ],
              "validation_tests": ["negative answer must revert"],
              "confidence": "1.3",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_chainlink_price_reads")
    assert plans[0].feeds[0].id == "eth_usd"
    assert plans[0].feeds[0].consumer_function == "getPrice"
    assert plans[0].feeds[0].read_method == "latestRoundData"
    assert plans[0].feeds[0].bounds_check == "answer > 0"
    assert plans[0].risks[0].category == "zero_negative_price"
    assert plans[0].validation_tests == ["negative answer must revert"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_oracle_feed_hardening_plans(
        {
            "oracle_source_hardening_plans": [
                {
                    "objective": "validate stale oracle guard",
                    "validation_tests": ["updatedAt older than threshold reverts"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate stale oracle guard"
    assert alias_plans[0].validation_tests == ["updatedAt older than threshold reverts"]


def test_parse_oracle_feed_hardening_plans_rejects_incomplete_items():
    plans = parse_oracle_feed_hardening_plans(
        {
            "oracle_feed_hardening_plans": [
                {"feeds": [{"id": "missing_objective", "consumer_function": "getPrice"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["stale price must revert"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["stale price must revert"]
    assert plans[0].confidence == 0.0


def test_parse_adversarial_transaction_ordering_plans_accepts_alias_and_bounds_fields():
    plans = parse_adversarial_transaction_ordering_plans("""
        {
          "mev_oracle_plans": [
            {
              "objective": "validate sandwich resistance",
              "ordering_pattern": "sandwich",
              "transactions": [
                {
                  "id": "front",
                  "role": "attacker_front",
                  "function": "swap",
                  "actor": "searcher",
                  "position": "before_victim",
                  "value_hint": "front-run size",
                  "state_dependency": "pool reserves",
                  "slippage_or_limit": "none"
                },
                {
                  "id": "victim",
                  "role": "victim",
                  "function": "swap",
                  "actor": "user",
                  "position": "victim",
                  "value_hint": "amountIn",
                  "state_dependency": "pool reserves",
                  "slippage_or_limit": "minOut"
                }
              ],
              "risks": [
                {
                  "id": "tod",
                  "category": "transaction_order_dependence",
                  "affected_transaction_id": "victim",
                  "description": "victim result depends on front-run transaction ordering"
                }
              ],
              "oracle": "victim output is independent of attacker ordering within minOut",
              "mitigations": ["minOut", "deadline"],
              "validation_tests": ["front-run ordering cannot reduce output below minOut"],
              "confidence": "1.5",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("validate_sandwich_resistance")
    assert plans[0].ordering_pattern == "sandwich"
    assert plans[0].transactions[0].role == "attacker_front"
    assert plans[0].transactions[1].slippage_or_limit == "minOut"
    assert plans[0].risks[0].category == "transaction_order_dependence"
    assert plans[0].oracle == "victim output is independent of attacker ordering within minOut"
    assert plans[0].mitigations == ["minOut", "deadline"]
    assert plans[0].validation_tests == ["front-run ordering cannot reduce output below minOut"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_adversarial_transaction_ordering_plans(
        {
            "transaction_ordering_plans": [
                {
                    "objective": "validate liquidation race",
                    "oracle": "same health factor cannot produce inconsistent liquidation winner",
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate liquidation race"
    assert alias_plans[0].oracle == (
        "same health factor cannot produce inconsistent liquidation winner"
    )


def test_parse_adversarial_transaction_ordering_plans_rejects_incomplete_items():
    plans = parse_adversarial_transaction_ordering_plans(
        {
            "adversarial_transaction_ordering_plans": [
                {"transactions": [{"id": "missing_objective", "role": "victim", "function": "x"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid oracle-only plan",
                    "oracle": "commit reveal cannot be opened before commitment",
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid oracle-only plan"
    assert plans[0].oracle == "commit reveal cannot be opened before commitment"
    assert plans[0].confidence == 0.0


def test_parse_randomness_entropy_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_randomness_entropy_hardening_plans("""
        {
          "entropy_validation_plans": [
            {
              "objective": "harden random winner selection",
              "sources": [
                {
                  "id": "winner",
                  "consumer_function": "drawWinner",
                  "source_kind": "prevrandao",
                  "source_expression": "block.prevrandao",
                  "entropy_scope": "winner selection",
                  "confirmation_depth": "none",
                  "modulo_bias_guard": "none"
                }
              ],
              "risks": [
                {
                  "id": "prevrandao_bias",
                  "category": "prevrandao_bias",
                  "affected_source_id": "winner",
                  "description": "validator can bias high-value randomness"
                }
              ],
              "validation_tests": ["prevrandao mutation changes winner"],
              "confidence": "1.7",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_random_winner_selection")
    assert plans[0].sources[0].id == "winner"
    assert plans[0].sources[0].consumer_function == "drawWinner"
    assert plans[0].sources[0].source_kind == "prevrandao"
    assert plans[0].sources[0].source_expression == "block.prevrandao"
    assert plans[0].risks[0].category == "prevrandao_bias"
    assert plans[0].validation_tests == ["prevrandao mutation changes winner"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_randomness_entropy_hardening_plans(
        {
            "randomness_hardening_plans": [
                {
                    "objective": "validate VRF request binding",
                    "validation_tests": ["wrong requestId fulfillment reverts"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate VRF request binding"
    assert alias_plans[0].validation_tests == ["wrong requestId fulfillment reverts"]


def test_parse_randomness_entropy_hardening_plans_rejects_incomplete_items():
    plans = parse_randomness_entropy_hardening_plans(
        {
            "randomness_entropy_hardening_plans": [
                {"sources": [{"id": "missing_objective", "consumer_function": "draw"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["commit cannot reveal before deadline"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["commit cannot reveal before deadline"]
    assert plans[0].confidence == 0.0


def test_parse_erc4626_vault_inflation_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_erc4626_vault_inflation_hardening_plans("""
        {
          "share_inflation_hardening_plans": [
            {
              "objective": "harden vault share math",
              "surfaces": [
                {
                  "id": "deposit_surface",
                  "vault_function": "deposit",
                  "asset_function": "totalAssets",
                  "share_function": "previewDeposit",
                  "total_assets_source": "asset.balanceOf(address(this))",
                  "total_supply_source": "totalSupply()",
                  "conversion_formula": "assets * supply / totalAssets",
                  "rounding_direction": "down",
                  "empty_vault_behavior": "first depositor gets 1:1 shares",
                  "donation_exposure": "raw balance accepts direct donations",
                  "mitigation": "virtual offset"
                }
              ],
              "risks": [
                {
                  "id": "zero_share_mint",
                  "category": "zero_share_mint",
                  "affected_surface_id": "deposit_surface",
                  "description": "victim deposit can round down to zero shares"
                }
              ],
              "mitigations": ["virtual shares", "require shares > 0"],
              "validation_tests": ["donation before deposit does not mint zero shares"],
              "confidence": "2.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_vault_share_math")
    assert plans[0].surfaces[0].id == "deposit_surface"
    assert plans[0].surfaces[0].vault_function == "deposit"
    assert plans[0].surfaces[0].share_function == "previewDeposit"
    assert plans[0].surfaces[0].donation_exposure == "raw balance accepts direct donations"
    assert plans[0].risks[0].category == "zero_share_mint"
    assert plans[0].mitigations == ["virtual shares", "require shares > 0"]
    assert plans[0].validation_tests == ["donation before deposit does not mint zero shares"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_erc4626_vault_inflation_hardening_plans(
        {
            "donation_attack_hardening_plans": [
                {
                    "objective": "validate direct donation handling",
                    "validation_tests": ["direct asset transfer does not alter share price"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate direct donation handling"
    assert alias_plans[0].validation_tests == ["direct asset transfer does not alter share price"]


def test_parse_erc4626_vault_inflation_hardening_plans_rejects_incomplete_items():
    plans = parse_erc4626_vault_inflation_hardening_plans(
        {
            "erc4626_vault_inflation_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "vault_function": "deposit"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid mitigation-only plan",
                    "mitigations": ["seed initial liquidity"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid mitigation-only plan"
    assert plans[0].mitigations == ["seed initial liquidity"]
    assert plans[0].confidence == 0.0


def test_parse_create2_deployment_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_create2_deployment_hardening_plans("""
        {
          "deterministic_deployment_hardening_plans": [
            {
              "objective": "harden wallet factory deployment",
              "surfaces": [
                {
                  "id": "wallet_factory",
                  "deploy_function": "deployWallet",
                  "factory_contract": "WalletFactory",
                  "salt_source": "salt",
                  "init_code_source": "type(Wallet).creationCode",
                  "address_formula": "keccak256(0xff, factory, salt, initCodeHash)",
                  "authorization_guard": "salt binds owner",
                  "collision_check": "wallet.code.length == 0",
                  "post_deploy_check": "codehash verified",
                  "redeploy_assumption": "no metamorphic redeploy"
                }
              ],
              "risks": [
                {
                  "id": "predictable_salt",
                  "category": "predictable_salt",
                  "affected_surface_id": "wallet_factory",
                  "description": "public salt can be squatted before victim deployment"
                }
              ],
              "mitigations": ["salt includes owner", "verify init code hash"],
              "validation_tests": ["attacker cannot deploy same address first"],
              "confidence": "1.6",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_wallet_factory_deployment")
    assert plans[0].surfaces[0].id == "wallet_factory"
    assert plans[0].surfaces[0].deploy_function == "deployWallet"
    assert plans[0].surfaces[0].factory_contract == "WalletFactory"
    assert plans[0].surfaces[0].collision_check == "wallet.code.length == 0"
    assert plans[0].risks[0].category == "predictable_salt"
    assert plans[0].mitigations == ["salt includes owner", "verify init code hash"]
    assert plans[0].validation_tests == ["attacker cannot deploy same address first"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_create2_deployment_hardening_plans(
        {
            "factory_deployment_plans": [
                {
                    "objective": "validate codehash after deployment",
                    "validation_tests": ["wrong init code hash fails post-deploy check"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].objective == "validate codehash after deployment"
    assert alias_plans[0].validation_tests == ["wrong init code hash fails post-deploy check"]


def test_parse_create2_deployment_hardening_plans_rejects_incomplete_items():
    plans = parse_create2_deployment_hardening_plans(
        {
            "create2_deployment_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "deploy_function": "deploy"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["front-run deployment reverts"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["front-run deployment reverts"]
    assert plans[0].confidence == 0.0


def test_parse_abi_packed_hash_collision_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_abi_packed_hash_collision_hardening_plans("""
        {
          "packed_hash_collision_plans": [
            {
              "objective": "harden packed claim hash",
              "surfaces": [
                {
                  "id": "claim_hash",
                  "hash_function": "claim",
                  "packed_expression": "keccak256(abi.encodePacked(a, b))",
                  "argument_types": ["string", "string"],
                  "dynamic_argument_count": "2",
                  "user_controlled_arguments": ["a", "b"],
                  "hash_usage": "mapping_key",
                  "domain_separator": "contract address",
                  "delimiter_or_length_guard": "none",
                  "safer_encoding": "abi.encode(a, b)"
                }
              ],
              "risks": [
                {
                  "id": "ambiguous_dynamic_encoding",
                  "category": "multiple_dynamic_args",
                  "affected_surface_id": "claim_hash",
                  "description": "dynamic string boundaries can shift while preserving packed bytes"
                }
              ],
              "mitigations": ["abi.encode", "length prefixes"],
              "validation_tests": ["('a','bc') does not equal ('ab','c')"],
              "confidence": "1.9",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_packed_claim_hash")
    assert plans[0].surfaces[0].hash_function == "claim"
    assert plans[0].surfaces[0].argument_types == ["string", "string"]
    assert plans[0].surfaces[0].dynamic_argument_count == "2"
    assert plans[0].surfaces[0].hash_usage == "mapping_key"
    assert plans[0].risks[0].category == "multiple_dynamic_args"
    assert plans[0].mitigations == ["abi.encode", "length prefixes"]
    assert plans[0].validation_tests == ["('a','bc') does not equal ('ab','c')"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_abi_packed_hash_collision_hardening_plans(
        {
            "hash_domain_hardening_plans": [
                {
                    "objective": "validate packed auth hash",
                    "validation_tests": ["two dynamic args cannot collide"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["two dynamic args cannot collide"]


def test_parse_abi_packed_hash_collision_hardening_plans_rejects_incomplete_items():
    plans = parse_abi_packed_hash_collision_hardening_plans(
        {
            "abi_packed_hash_collision_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "hash_function": "claim"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["crafted collision pair rejected"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["crafted collision pair rejected"]
    assert plans[0].confidence == 0.0


def test_parse_token_hook_reentrancy_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_token_hook_reentrancy_hardening_plans("""
        {
          "erc777_hook_reentrancy_plans": [
            {
              "objective": "harden ERC777 deposit callback ordering",
              "surfaces": [
                {
                  "id": "deposit_hook_surface",
                  "entrypoint": "deposit",
                  "token_standard": "ERC777",
                  "hook_function": "tokensReceived",
                  "external_token_call": "token.transferFrom(msg.sender, address(this), amount)",
                  "state_update_order": "external token call before balance update",
                  "accounting_fields": ["balances", "totalDeposits"],
                  "expected_callback_sender": "trusted token",
                  "guard": "none"
                }
              ],
              "risks": [
                {
                  "id": "hook_before_effects",
                  "category": "hook_before_effects",
                  "affected_surface_id": "deposit_hook_surface",
                  "description": "ERC777 hook can reenter before accounting effects"
                }
              ],
              "mitigations": ["CEI", "nonReentrant"],
              "validation_tests": ["malicious token hook cannot reenter"],
              "confidence": "1.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id.startswith("harden_erc777_deposit_callback_ordering")
    assert plans[0].surfaces[0].entrypoint == "deposit"
    assert plans[0].surfaces[0].token_standard == "ERC777"
    assert plans[0].surfaces[0].hook_function == "tokensReceived"
    assert plans[0].surfaces[0].accounting_fields == ["balances", "totalDeposits"]
    assert plans[0].risks[0].category == "hook_before_effects"
    assert plans[0].mitigations == ["CEI", "nonReentrant"]
    assert plans[0].validation_tests == ["malicious token hook cannot reenter"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_token_hook_reentrancy_hardening_plans(
        {
            "erc1363_callback_reentrancy_plans": [
                {
                    "objective": "validate ERC1363 callback sender",
                    "validation_tests": ["onTransferReceived from untrusted token reverts"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["onTransferReceived from untrusted token reverts"]


def test_parse_token_hook_reentrancy_hardening_plans_rejects_incomplete_items():
    plans = parse_token_hook_reentrancy_hardening_plans(
        {
            "token_hook_reentrancy_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "entrypoint": "deposit"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["malicious hook cannot reenter"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["malicious hook cannot reenter"]
    assert plans[0].confidence == 0.0


def test_parse_erc20_token_compatibility_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_erc20_token_compatibility_hardening_plans("""
        {
          "fee_on_transfer_accounting_plans": [
            {
              "objective": "harden deposits for fee-on-transfer tokens",
              "surfaces": [
                {
                  "id": "deposit_transfer_surface",
                  "entrypoint": "deposit",
                  "token_call": "token.transferFrom(msg.sender, address(this), amount)",
                  "requested_amount_source": "amount",
                  "balance_before_source": "beforeBalance",
                  "balance_after_source": "afterBalance",
                  "credited_amount_source": "amount",
                  "token_traits": ["fee_on_transfer", "rebasing"],
                  "accounting_fields": ["balances", "totalDeposits"],
                  "guard": "none"
                }
              ],
              "risks": [
                {
                  "id": "requested_amount_credit",
                  "category": "fee_on_transfer_misaccounting",
                  "affected_surface_id": "deposit_transfer_surface",
                  "description": "requested amount can exceed actual received amount"
                }
              ],
              "mitigations": ["credit balance delta", "use SafeERC20"],
              "validation_tests": ["fee token credits actual received"],
              "confidence": "1.7",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id == "harden_deposits_for_fee_on_transfer"
    assert plans[0].surfaces[0].entrypoint == "deposit"
    assert plans[0].surfaces[0].requested_amount_source == "amount"
    assert plans[0].surfaces[0].token_traits == ["fee_on_transfer", "rebasing"]
    assert plans[0].surfaces[0].accounting_fields == ["balances", "totalDeposits"]
    assert plans[0].risks[0].category == "fee_on_transfer_misaccounting"
    assert plans[0].mitigations == ["credit balance delta", "use SafeERC20"]
    assert plans[0].validation_tests == ["fee token credits actual received"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_erc20_token_compatibility_hardening_plans(
        {
            "actual_received_hardening_plans": [
                {
                    "objective": "validate actual received accounting",
                    "validation_tests": ["rebasing token does not drift internal accounting"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["rebasing token does not drift internal accounting"]


def test_parse_erc20_token_compatibility_hardening_plans_rejects_incomplete_items():
    plans = parse_erc20_token_compatibility_hardening_plans(
        {
            "erc20_token_compatibility_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "entrypoint": "deposit"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["fee token credits actual received"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["fee token credits actual received"]
    assert plans[0].confidence == 0.0


def test_parse_account_abstraction_userop_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_account_abstraction_userop_hardening_plans("""
        {
          "paymaster_validation_hardening_plans": [
            {
              "objective": "paymaster cannot be drained by sponsored UserOperations",
              "surfaces": [
                {
                  "id": "paymaster_validation_surface",
                  "component": "paymaster",
                  "entrypoint_function": "validatePaymasterUserOp",
                  "entrypoint_guard": "only EntryPoint can call",
                  "userop_fields": ["sender", "paymasterAndData", "callGasLimit"],
                  "signature_scheme": "sponsor signature over userOpHash",
                  "nonce_source": "sponsor nonces",
                  "prefund_source": "paymaster deposit",
                  "paymaster_context": "encoded sender and maxCost",
                  "post_op_path": "postOp charges user after execution",
                  "validation_data_source": "packed validUntil and validAfter"
                }
              ],
              "risks": [
                {
                  "id": "postop_revert_drain",
                  "category": "postop_revert",
                  "affected_surface_id": "paymaster_validation_surface",
                  "description": "postOp revert can leave sponsorship accounting undercharged"
                }
              ],
              "mitigations": ["make postOp charging non-bypassable"],
              "validation_tests": ["postOp revert path cannot drain paymaster deposit"],
              "confidence": "1.4",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id == "paymaster_cannot_be_drained_by_sponsored"
    assert plans[0].surfaces[0].component == "paymaster"
    assert plans[0].surfaces[0].entrypoint_function == "validatePaymasterUserOp"
    assert plans[0].surfaces[0].userop_fields == [
        "sender",
        "paymasterAndData",
        "callGasLimit",
    ]
    assert plans[0].risks[0].category == "postop_revert"
    assert plans[0].mitigations == ["make postOp charging non-bypassable"]
    assert plans[0].validation_tests == ["postOp revert path cannot drain paymaster deposit"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_account_abstraction_userop_hardening_plans(
        {
            "erc4337_userop_hardening_plans": [
                {
                    "objective": "account nonce cannot be replayed",
                    "validation_tests": ["same UserOperation cannot execute twice"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["same UserOperation cannot execute twice"]


def test_parse_account_abstraction_userop_hardening_plans_rejects_incomplete_items():
    plans = parse_account_abstraction_userop_hardening_plans(
        {
            "account_abstraction_userop_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "component": "account"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["direct validateUserOp call must revert"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["direct validateUserOp call must revert"]
    assert plans[0].confidence == 0.0


def test_parse_external_call_returndata_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_external_call_returndata_hardening_plans("""
        {
          "returndata_decode_hardening_plans": [
            {
              "objective": "staticcall returndata is bounded before decode",
              "surfaces": [
                {
                  "id": "quote_staticcall_surface",
                  "entrypoint": "quote",
                  "target_source": "oracleAdapter",
                  "call_kind": "staticcall",
                  "calldata_source": "abi.encodeWithSelector(...)",
                  "returndata_source": "bytes memory data",
                  "decode_site": "abi.decode(data, (uint256))",
                  "returndata_size_bound": "data.length == 32",
                  "success_guard": "require(success)",
                  "trust_boundary": "registry-controlled adapter",
                  "value_forwarding": "none"
                }
              ],
              "risks": [
                {
                  "id": "malformed_quote_decode",
                  "category": "unsafe_abi_decode",
                  "affected_surface_id": "quote_staticcall_surface",
                  "description": "abi.decode consumes untrusted returned bytes"
                }
              ],
              "mitigations": ["bound returndata length"],
              "validation_tests": ["31 byte return data does not update state"],
              "confidence": "1.6",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id == "staticcall_returndata_is_bounded_before_decode"
    assert plans[0].surfaces[0].entrypoint == "quote"
    assert plans[0].surfaces[0].target_source == "oracleAdapter"
    assert plans[0].surfaces[0].call_kind == "staticcall"
    assert plans[0].surfaces[0].returndata_size_bound == "data.length == 32"
    assert plans[0].risks[0].category == "unsafe_abi_decode"
    assert plans[0].mitigations == ["bound returndata length"]
    assert plans[0].validation_tests == ["31 byte return data does not update state"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_external_call_returndata_hardening_plans(
        {
            "low_level_call_returndata_hardening_plans": [
                {
                    "objective": "huge return data cannot grief memory",
                    "validation_tests": ["oversized returndata target is bounded"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["oversized returndata target is bounded"]


def test_parse_external_call_returndata_hardening_plans_rejects_incomplete_items():
    plans = parse_external_call_returndata_hardening_plans(
        {
            "external_call_returndata_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "entrypoint": "quote"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["malformed returndata is rejected"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["malformed returndata is rejected"]
    assert plans[0].confidence == 0.0


def test_external_call_returndata_plan_export_sanitizes_direct_instances():
    surface = ExternalCallReturndataSurface(
        id="surface\nbad",
        entrypoint="quote",
        target_source="target",
        call_kind="staticcall",
        decode_site="abi.decode(data, (uint256))",
        evidence=["ok", ""],
    )
    risk = ExternalCallReturndataRisk(
        id="risk",
        category="unsafe_abi_decode",
        description="x" * (MAX_AGENT_TEXT_CHARS + 10),
    )
    plan = ExternalCallReturndataHardeningPlan(
        id="plan",
        objective="validate returned bytes",
        surfaces=[surface],
        risks=[risk],
        confidence=2.0,
        metadata={"ok": True, "bad\nkey": "ignored"},
    )

    exported = plan.to_dict()
    assert exported["surfaces"][0]["id"] == "surface_bad"
    assert exported["surfaces"][0]["call_kind"] == "staticcall"
    assert len(exported["risks"][0]["description"]) == MAX_AGENT_TEXT_CHARS
    assert exported["confidence"] == 1.0
    assert exported["metadata"] == {"ok": True, "bad_key": "ignored"}


def test_parse_financial_math_precision_hardening_plans_accepts_alias_and_bounds_fields():
    plans = parse_financial_math_precision_hardening_plans("""
        {
          "fixed_point_math_hardening_plans": [
            {
              "objective": "reward math preserves precision",
              "surfaces": [
                {
                  "id": "reward_formula_surface",
                  "entrypoint": "accrue",
                  "formula": "amount / totalShares * rewardRate",
                  "value_flow": "reward distribution",
                  "unit_sources": ["amount:token", "rewardRate:1e18"],
                  "scale_factor": "1e18",
                  "rounding_direction": "down",
                  "operation_order": "division_before_multiplication",
                  "library_or_helper": "mulDiv",
                  "unchecked_context": "none",
                  "state_fields": ["accRewardPerShare"]
                }
              ],
              "risks": [
                {
                  "id": "division_before_mul",
                  "category": "division_before_multiplication",
                  "affected_surface_id": "reward_formula_surface",
                  "description": "division before multiplication truncates rewards"
                }
              ],
              "mitigations": ["use full-precision mulDiv"],
              "validation_tests": ["tiny rewards do not round to zero"],
              "confidence": "1.3",
              "metadata": {"source": "local"}
            }
          ]
        }
        """)

    assert len(plans) == 1
    assert plans[0].id == "reward_math_preserves_precision"
    assert plans[0].surfaces[0].entrypoint == "accrue"
    assert plans[0].surfaces[0].scale_factor == "1e18"
    assert plans[0].surfaces[0].state_fields == ["accRewardPerShare"]
    assert plans[0].risks[0].category == "division_before_multiplication"
    assert plans[0].mitigations == ["use full-precision mulDiv"]
    assert plans[0].validation_tests == ["tiny rewards do not round to zero"]
    assert plans[0].confidence == 1.0
    assert plans[0].metadata == {"source": "local"}

    alias_plans = parse_financial_math_precision_hardening_plans(
        {
            "division_before_multiplication_hardening_plans": [
                {
                    "objective": "small deposit cannot lose all reward",
                    "validation_tests": ["small deposit reward is nonzero when expected"],
                }
            ]
        }
    )

    assert len(alias_plans) == 1
    assert alias_plans[0].validation_tests == ["small deposit reward is nonzero when expected"]


def test_parse_financial_math_precision_hardening_plans_rejects_incomplete_items():
    plans = parse_financial_math_precision_hardening_plans(
        {
            "financial_math_precision_hardening_plans": [
                {"surfaces": [{"id": "missing_objective", "entrypoint": "accrue"}]},
                {"objective": "missing guidance"},
                {
                    "objective": "bad risk",
                    "risks": [{"id": "missing_category", "description": "bad"}],
                },
                {
                    "objective": "valid validation-only plan",
                    "validation_tests": ["rounding direction is explicit"],
                    "confidence": -1,
                },
            ]
        }
    )

    assert len(plans) == 1
    assert plans[0].objective == "valid validation-only plan"
    assert plans[0].validation_tests == ["rounding direction is explicit"]
    assert plans[0].confidence == 0.0


def test_financial_math_precision_plan_export_sanitizes_direct_instances():
    surface = FinancialMathPrecisionSurface(
        id="surface\nbad",
        entrypoint="accrue",
        formula="amount / totalShares * rewardRate",
        unit_sources=["amount", ""],
        rounding_direction="round down",
        state_fields=["accRewardPerShare"],
        evidence=["ok", ""],
    )
    risk = FinancialMathPrecisionRisk(
        id="risk",
        category="division_before_multiplication",
        description="x" * (MAX_AGENT_TEXT_CHARS + 10),
    )
    plan = FinancialMathPrecisionHardeningPlan(
        id="plan",
        objective="validate financial formula precision",
        surfaces=[surface],
        risks=[risk],
        confidence=2.0,
        metadata={"ok": True, "bad\nkey": "ignored"},
    )

    exported = plan.to_dict()
    assert exported["surfaces"][0]["id"] == "surface_bad"
    assert exported["surfaces"][0]["rounding_direction"] == "round down"
    assert exported["surfaces"][0]["state_fields"] == ["accRewardPerShare"]
    assert len(exported["risks"][0]["description"]) == MAX_AGENT_TEXT_CHARS
    assert exported["confidence"] == 1.0
    assert exported["metadata"] == {"ok": True, "bad_key": "ignored"}


def test_reasoning_result_and_counterexample_evidence_export_safe_dicts():
    result = ReasoningResult(
        data={"ok": True, "bad\nkey": "ignored", "huge": float("inf")},
        provider_kind="local",
        implementation_label="local/mock",
        metadata={"nested": {"a": 1}},
    )
    evidence = CounterexampleEvidence(
        invariant_id="asset_conservation",
        status="counterexample_found",
        tool="foundry",
        compiled=True,
        counterexample_found=True,
        test_name="testAssetConservation",
        details={"raw": object()},
    )

    result_dict = result.to_dict()
    evidence_dict = evidence.to_dict()

    assert result_dict["data"]["ok"] is True
    assert "bad\nkey" not in result_dict["data"]
    assert result_dict["data"]["huge"] is None
    assert evidence_dict["counterexample_found"] is True
    assert evidence_dict["details"]["raw"] == "<object>"


def test_reasoning_task_export_sanitizes_hostile_prompt_fields():
    task = ReasoningTask(
        capability=AgentCapability.FINDING_JUDGMENT,
        objective="judge\x00finding",
        prompt="p" * (MAX_AGENT_TEXT_CHARS * 40),
        inputs={"bad\nkey": "ignored", "ok": float("inf")},
        output_schema={"schema": object()},
        policy=DPGAgentConfig(max_source_chars=-20),
    )

    exported = task.to_dict()

    assert exported["objective"] == ""
    assert len(exported["prompt"]) <= MAX_AGENT_TEXT_CHARS * 35
    assert "bad\nkey" not in exported["inputs"]
    assert exported["inputs"]["ok"] is None
    assert exported["output_schema"]["schema"] == "<object>"
    assert exported["policy"]["max_source_chars"] == 0


def test_invariant_candidate_export_sanitizes_direct_instances():
    candidate = InvariantCandidate(
        id="asset conservation\nbad",
        statement="s" * (MAX_AGENT_TEXT_CHARS + 10),
        category=InvariantCategory.ACCOUNTING,
        affected_functions=["deposit", "bad\x00fn", "withdraw"],
        state_variables=["totalAssets", object(), "totalSupply"],
        assertion_hint="hint\x00bad",
        confidence=float("inf"),
        evidence=["specific code signal", "bad\x00evidence"],
    )

    exported = candidate.to_dict()

    assert exported["id"] == "asset_conservation_bad"
    assert len(exported["statement"]) == MAX_AGENT_TEXT_CHARS
    assert exported["affected_functions"] == ["deposit", "withdraw"]
    assert exported["state_variables"] == ["totalAssets", "totalSupply"]
    assert exported["assertion_hint"] == ""
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific code signal"]


def test_sequence_oracle_plan_export_sanitizes_direct_instances():
    plan = SequenceOraclePlan(
        id="share inflation\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        invariant_id="asset conservation",
        vulnerability_types=["share_price_inflation", "bad\x00type"],
        sequence=[
            SequenceStep(
                function="deposit(uint256)",
                actor="attacker user",
                arguments=["amount", "bad\x00arg"],
                value_hint="1 ether",
                precondition="pool is initialized",
                expected_effect="shares minted",
            )
        ],
        oracle="oracle\x00bad",
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "share_inflation_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["invariant_id"] == "asset_conservation"
    assert exported["vulnerability_types"] == ["share_price_inflation"]
    assert exported["sequence"][0]["function"] == "deposit_uint256"
    assert exported["sequence"][0]["actor"] == "attacker_user"
    assert exported["sequence"][0]["arguments"] == ["amount"]
    assert exported["oracle"] == ""
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["metadata"]["raw"] == "<object>"


def test_semantic_graph_gate_export_sanitizes_direct_instances():
    gate = SemanticGraphGate(
        id="withdraw gate\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        target_vulnerability_types=["access_control", "bad\x00type"],
        focal_nodes=["fn_withdraw", "bad\x00node"],
        nodes=[
            SemanticGraphNode(
                id="fn:withdraw",
                kind="function",
                label="withdraw(uint256)",
                contract="Vault",
                function="withdraw",
                line=-10,
                metadata={"raw": object()},
            )
        ],
        edges=[
            SemanticGraphEdge(
                source="fn:withdraw",
                target="state:balances",
                relation="writes state",
                confidence=float("inf"),
                evidence=["specific edge", "bad\x00edge"],
            )
        ],
        graph_queries=["MATCH missing guard", "bad\x00query"],
        recommended_tools=["slither", "bad\x00tool"],
        confidence=float("inf"),
        rationale="reason\x00bad",
        metadata={"raw": object()},
    )

    exported = gate.to_dict()

    assert exported["id"] == "withdraw_gate_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["target_vulnerability_types"] == ["access_control"]
    assert exported["focal_nodes"] == ["fn_withdraw"]
    assert exported["nodes"][0]["id"] == "fn:withdraw"
    assert exported["nodes"][0]["line"] == 0
    assert exported["nodes"][0]["metadata"]["raw"] == "<object>"
    assert exported["edges"][0]["relation"] == "writes_state"
    assert exported["edges"][0]["confidence"] == 0.0
    assert exported["edges"][0]["evidence"] == ["specific edge"]
    assert exported["graph_queries"] == ["MATCH missing guard"]
    assert exported["recommended_tools"] == ["slither"]
    assert exported["confidence"] == 0.0
    assert exported["rationale"] == ""
    assert exported["metadata"]["raw"] == "<object>"


def test_snapshot_fuzzing_plan_export_sanitizes_direct_instances():
    plan = SnapshotFuzzingPlan(
        id="campaign\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        target_vulnerability_types=["oracle_manipulation", "bad\x00type"],
        seeds=[
            SnapshotSeed(
                id="seed after swap",
                setup_sequence=[SequenceStep(function="swap(uint256)")],
                target_state="pool imbalance",
                priority=float("inf"),
                evidence=["reserve delta", "bad\x00evidence"],
            )
        ],
        waypoints=[
            FuzzingWaypoint(
                id="branch price",
                kind="branch distance",
                target="price < min",
                objective="bad\x00objective",
                distance_hint="minimize price-min",
                evidence=["comparison"],
            )
        ],
        priority_transactions=[SequenceStep(function="borrow(uint256)", actor="attacker user")],
        oracle="oracle\x00bad",
        recommended_tools=["foundry", "bad\x00tool"],
        budget_hint="run\x00bad",
        confidence=float("inf"),
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "campaign_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["target_vulnerability_types"] == ["oracle_manipulation"]
    assert exported["seeds"][0]["id"] == "seed_after_swap"
    assert exported["seeds"][0]["setup_sequence"][0]["function"] == "swap_uint256"
    assert exported["seeds"][0]["priority"] == 0.0
    assert exported["waypoints"][0]["kind"] == "branch_distance"
    assert exported["waypoints"][0]["objective"] == ""
    assert exported["priority_transactions"][0]["actor"] == "attacker_user"
    assert exported["oracle"] == ""
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["budget_hint"] == ""
    assert exported["confidence"] == 0.0
    assert exported["metadata"]["raw"] == "<object>"


def test_economic_attack_plan_export_sanitizes_direct_instances():
    plan = EconomicAttackPlan(
        id="profit plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        target_vulnerability_types=["oracle_manipulation", "bad\x00type"],
        base_sequence_plan_ids=["seq_1", "bad\x00seq"],
        base_snapshot_plan_ids=["snap_1"],
        base_graph_gate_ids=["gate_1"],
        capital_requirements=[
            CapitalRequirement(
                asset="USDC token",
                amount_hint="10m",
                source="flash\x00loan",
                purpose="manipulate pool",
            )
        ],
        asset_flows=[
            AssetFlow(
                asset="WETH",
                from_actor="target protocol",
                to_actor="attacker",
                amount_hint="profit",
                step_id="borrow(uint256)",
                rationale="bad\x00rationale",
            )
        ],
        profit_formula="profit\x00bad",
        cost_model="gas + fees",
        liquidity_assumptions=["deep pool", "bad\x00liquidity"],
        oracle_price_assumptions=["spot price"],
        break_even_threshold="delta > costs",
        expected_profit_range="positive",
        risk_factors=["TWAP", "bad\x00risk"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "profit_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["target_vulnerability_types"] == ["oracle_manipulation"]
    assert exported["base_sequence_plan_ids"] == ["seq_1"]
    assert exported["capital_requirements"][0]["asset"] == "USDC_token"
    assert exported["capital_requirements"][0]["source"] == ""
    assert exported["asset_flows"][0]["from_actor"] == "target_protocol"
    assert exported["asset_flows"][0]["step_id"] == "borrow_uint256"
    assert exported["asset_flows"][0]["rationale"] == ""
    assert exported["profit_formula"] == ""
    assert exported["liquidity_assumptions"] == ["deep pool"]
    assert exported["risk_factors"] == ["TWAP"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_differential_test_plan_export_sanitizes_direct_instances():
    plan = DifferentialTestPlan(
        id="diff plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        target_vulnerability_types=["accounting_drift", "bad\x00type"],
        relations=[
            MetamorphicRelation(
                id="split relation",
                relation_type="split merge",
                baseline_sequence=[SequenceStep(function="deposit(uint256)")],
                variant_sequence=[SequenceStep(function="deposit(uint256)", actor="user account")],
                expected_relation="same\x00state",
                tolerance_hint="one wei",
                evidence=["specific relation", "bad\x00evidence"],
            )
        ],
        state_observables=["totalSupply()", "bad\x00observable"],
        oracle="oracle\x00bad",
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "diff_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["target_vulnerability_types"] == ["accounting_drift"]
    assert exported["relations"][0]["id"] == "split_relation"
    assert exported["relations"][0]["relation_type"] == "split_merge"
    assert exported["relations"][0]["baseline_sequence"][0]["function"] == "deposit_uint256"
    assert exported["relations"][0]["variant_sequence"][0]["actor"] == "user_account"
    assert exported["relations"][0]["expected_relation"] == ""
    assert exported["relations"][0]["evidence"] == ["specific relation"]
    assert exported["state_observables"] == ["totalSupply()"]
    assert exported["oracle"] == ""
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_upgrade_evolution_plan_export_sanitizes_direct_instances():
    plan = UpgradeEvolutionPlan(
        id="upgrade plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        proxy_pattern="transparent proxy",
        old_implementation="VaultV1",
        new_implementation="VaultV2",
        storage_changes=[
            StorageLayoutChange(
                slot="slot 0",
                before="address owner",
                after="bad\x00after",
                change_type="type change",
                risk="risk\x00bad",
                evidence=["layout diff", "bad\x00evidence"],
            )
        ],
        risks=[
            UpgradeRisk(
                id="selector collision",
                category="selector collision",
                affected_component="upgradeTo(address)",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["selector overlap", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        migration_checks=["preserve owner", "bad\x00check"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "upgrade_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["proxy_pattern"] == "transparent_proxy"
    assert exported["storage_changes"][0]["slot"] == "slot_0"
    assert exported["storage_changes"][0]["after"] == ""
    assert exported["storage_changes"][0]["change_type"] == "type_change"
    assert exported["storage_changes"][0]["risk"] == ""
    assert exported["storage_changes"][0]["evidence"] == ["layout diff"]
    assert exported["risks"][0]["id"] == "selector_collision"
    assert exported["risks"][0]["category"] == "selector_collision"
    assert exported["risks"][0]["severity_hint"] == "high_severity"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["migration_checks"] == ["preserve owner"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_signature_domain_plan_export_sanitizes_direct_instances():
    plan = SignatureDomainHardeningPlan(
        id="signature plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        signed_actions=[
            SignedAction(
                id="permit action",
                function="permit(address,address,uint256)",
                signer_source="owner\x00bad",
                digest_scheme="eip712 typed",
                domain_fields=["chainId", "bad\x00domain"],
                nonce_source="nonces[owner]",
                deadline_source="deadline\x00bad",
                value_scope=["owner", "spender", "bad\x00scope"],
                evidence=["permit digest", "bad\x00evidence"],
            )
        ],
        risks=[
            SignatureDomainRisk(
                id="missing chain",
                category="cross chain replay",
                affected_action_id="permit action",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["DOMAIN_SEPARATOR omits chainId", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        replay_tests=["same signature fails after nonce use", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "signature_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["signed_actions"][0]["id"] == "permit_action"
    assert exported["signed_actions"][0]["function"] == "permit_address_address_uint256"
    assert exported["signed_actions"][0]["signer_source"] == ""
    assert exported["signed_actions"][0]["digest_scheme"] == "eip712_typed"
    assert exported["signed_actions"][0]["domain_fields"] == ["chainId"]
    assert exported["signed_actions"][0]["deadline_source"] == ""
    assert exported["signed_actions"][0]["value_scope"] == ["owner", "spender"]
    assert exported["signed_actions"][0]["evidence"] == ["permit digest"]
    assert exported["risks"][0]["id"] == "missing_chain"
    assert exported["risks"][0]["category"] == "cross_chain_replay"
    assert exported["risks"][0]["affected_action_id"] == "permit_action"
    assert exported["risks"][0]["severity_hint"] == "high_severity"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["replay_tests"] == ["same signature fails after nonce use"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_cross_chain_message_plan_export_sanitizes_direct_instances():
    plan = CrossChainMessageHardeningPlan(
        id="bridge plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        message_flows=[
            CrossChainMessageFlow(
                id="l2 flow",
                handler_function="receiveMessage(bytes)",
                source_domain="Ethereum",
                destination_domain="Optimism\x00bad",
                trusted_sender_source="trustedRemote[source]",
                message_id_source="messageHash",
                replay_guard="processed[hash]",
                finality_assumption="finality\x00bad",
                payload_scope=["token", "amount", "bad\x00scope"],
                evidence=["handler decodes payload", "bad\x00evidence"],
            )
        ],
        risks=[
            CrossChainMessageRisk(
                id="missing remote",
                category="trusted sender",
                affected_flow_id="l2 flow",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["remote not checked", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        validation_tests=["spoofed remote sender reverts", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "bridge_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["message_flows"][0]["id"] == "l2_flow"
    assert exported["message_flows"][0]["handler_function"] == "receiveMessage_bytes"
    assert exported["message_flows"][0]["source_domain"] == "Ethereum"
    assert exported["message_flows"][0]["destination_domain"] == ""
    assert exported["message_flows"][0]["payload_scope"] == ["token", "amount"]
    assert exported["message_flows"][0]["evidence"] == ["handler decodes payload"]
    assert exported["risks"][0]["id"] == "missing_remote"
    assert exported["risks"][0]["category"] == "trusted_sender"
    assert exported["risks"][0]["affected_flow_id"] == "l2_flow"
    assert exported["risks"][0]["severity_hint"] == "high_severity"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["validation_tests"] == ["spoofed remote sender reverts"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_delegatecall_storage_aliasing_plan_export_sanitizes_direct_instances():
    plan = DelegatecallStorageAliasingPlan(
        id="delegate plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        delegatecall_surfaces=[
            DelegatecallSurface(
                id="fallback surface",
                caller_function="fallback(bytes)",
                target_source="implementation\x00bad",
                selector_source="msg.data",
                target_trust_boundary="user controlled",
                guard_summary="guard\x00bad",
                value_forwarding="msg.value preserved",
                evidence=["delegatecall msg.data", "bad\x00evidence"],
            )
        ],
        storage_alias_paths=[
            StorageAliasPath(
                id="owner alias",
                delegatecall_surface_id="fallback surface",
                caller_slot="slot 0",
                callee_slot="slot 0",
                caller_semantics="owner\x00bad",
                callee_semantics="initialized",
                write_source="initialize writes slot 0",
                path_condition="condition\x00bad",
                evidence=["callee writes slot", "bad\x00evidence"],
            )
        ],
        risks=[
            DelegatecallAliasRisk(
                id="owner takeover",
                category="initializer takeover",
                affected_surface_id="fallback surface",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["slot collision", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        validation_tests=["malicious callee cannot set owner", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "delegate_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["delegatecall_surfaces"][0]["id"] == "fallback_surface"
    assert exported["delegatecall_surfaces"][0]["caller_function"] == "fallback_bytes"
    assert exported["delegatecall_surfaces"][0]["target_source"] == ""
    assert exported["delegatecall_surfaces"][0]["target_trust_boundary"] == "user controlled"
    assert exported["delegatecall_surfaces"][0]["guard_summary"] == ""
    assert exported["delegatecall_surfaces"][0]["evidence"] == ["delegatecall msg.data"]
    assert exported["storage_alias_paths"][0]["id"] == "owner_alias"
    assert exported["storage_alias_paths"][0]["delegatecall_surface_id"] == "fallback_surface"
    assert exported["storage_alias_paths"][0]["caller_slot"] == "slot 0"
    assert exported["storage_alias_paths"][0]["caller_semantics"] == ""
    assert exported["storage_alias_paths"][0]["evidence"] == ["callee writes slot"]
    assert exported["risks"][0]["id"] == "owner_takeover"
    assert exported["risks"][0]["category"] == "initializer_takeover"
    assert exported["risks"][0]["affected_surface_id"] == "fallback_surface"
    assert exported["risks"][0]["severity_hint"] == "high_severity"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["validation_tests"] == ["malicious callee cannot set owner"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_oracle_feed_hardening_plan_export_sanitizes_direct_instances():
    plan = OracleFeedHardeningPlan(
        id="oracle plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        feeds=[
            OracleFeedSource(
                id="eth feed",
                consumer_function="getPrice()",
                feed_kind="chainlink feed",
                source_contract="priceFeed\x00bad",
                read_method="latestRoundData()",
                freshness_source="updatedAt",
                staleness_threshold="threshold\x00bad",
                decimals_source="decimals()",
                normalization="scale to 1e18",
                fallback_source="fallback\x00bad",
                sequencer_guard="sequencer uptime",
                bounds_check="answer > 0",
                evidence=["latestRoundData used", "bad\x00evidence"],
            )
        ],
        risks=[
            OracleFeedRisk(
                id="stale round",
                category="stale round",
                affected_feed_id="eth feed",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["updatedAt unchecked", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        validation_tests=["stale updatedAt reverts", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "oracle_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["feeds"][0]["id"] == "eth_feed"
    assert exported["feeds"][0]["consumer_function"] == "getPrice"
    assert exported["feeds"][0]["feed_kind"] == "chainlink_feed"
    assert exported["feeds"][0]["source_contract"] == ""
    assert exported["feeds"][0]["read_method"] == "latestRoundData"
    assert exported["feeds"][0]["freshness_source"] == "updatedAt"
    assert exported["feeds"][0]["staleness_threshold"] == ""
    assert exported["feeds"][0]["evidence"] == ["latestRoundData used"]
    assert exported["risks"][0]["id"] == "stale_round"
    assert exported["risks"][0]["category"] == "stale_round"
    assert exported["risks"][0]["affected_feed_id"] == "eth_feed"
    assert exported["risks"][0]["severity_hint"] == "high_severity"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["validation_tests"] == ["stale updatedAt reverts"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_adversarial_ordering_plan_export_sanitizes_direct_instances():
    plan = AdversarialOrderingPlan(
        id="ordering plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        ordering_pattern="sandwich attack",
        transactions=[
            OrderingTransaction(
                id="victim tx",
                role="victim user",
                function="swap(uint256)",
                actor="user account",
                position="victim position",
                value_hint="amount\x00bad",
                state_dependency="pool reserves",
                slippage_or_limit="minOut",
                evidence=["swap is public", "bad\x00evidence"],
            )
        ],
        risks=[
            OrderingRisk(
                id="missing min out",
                category="slippage gap",
                affected_transaction_id="victim tx",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["minOut absent", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        oracle="oracle\x00bad",
        mitigations=["minOut", "bad\x00mitigation"],
        validation_tests=["front-run fails minOut", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "ordering_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["ordering_pattern"] == "sandwich_attack"
    assert exported["transactions"][0]["id"] == "victim_tx"
    assert exported["transactions"][0]["role"] == "victim_user"
    assert exported["transactions"][0]["function"] == "swap_uint256"
    assert exported["transactions"][0]["actor"] == "user_account"
    assert exported["transactions"][0]["value_hint"] == ""
    assert exported["transactions"][0]["evidence"] == ["swap is public"]
    assert exported["risks"][0]["id"] == "missing_min_out"
    assert exported["risks"][0]["category"] == "slippage_gap"
    assert exported["risks"][0]["affected_transaction_id"] == "victim_tx"
    assert exported["risks"][0]["description"] == ""
    assert exported["oracle"] == ""
    assert exported["mitigations"] == ["minOut"]
    assert exported["validation_tests"] == ["front-run fails minOut"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_randomness_entropy_plan_export_sanitizes_direct_instances():
    plan = RandomnessEntropyHardeningPlan(
        id="random plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        sources=[
            RandomnessSource(
                id="winner entropy",
                consumer_function="drawWinner()",
                source_kind="block timestamp",
                source_expression="block.timestamp\x00bad",
                entropy_scope="lottery winner",
                commit_phase="commit\x00bad",
                reveal_phase="reveal after deadline",
                request_id_source="requestId",
                fulfillment_guard="only coordinator",
                confirmation_depth="3 blocks",
                modulo_bias_guard="guard\x00bad",
                evidence=["timestamp in hash", "bad\x00evidence"],
            )
        ],
        risks=[
            RandomnessRisk(
                id="timestamp bias",
                category="timestamp bias",
                affected_source_id="winner entropy",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["timestamp can move", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        validation_tests=["timestamp mutation changes winner", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "random_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["sources"][0]["id"] == "winner_entropy"
    assert exported["sources"][0]["consumer_function"] == "drawWinner"
    assert exported["sources"][0]["source_kind"] == "block_timestamp"
    assert exported["sources"][0]["source_expression"] == ""
    assert exported["sources"][0]["commit_phase"] == ""
    assert exported["sources"][0]["modulo_bias_guard"] == ""
    assert exported["sources"][0]["evidence"] == ["timestamp in hash"]
    assert exported["risks"][0]["id"] == "timestamp_bias"
    assert exported["risks"][0]["category"] == "timestamp_bias"
    assert exported["risks"][0]["affected_source_id"] == "winner_entropy"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["validation_tests"] == ["timestamp mutation changes winner"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_erc4626_vault_inflation_plan_export_sanitizes_direct_instances():
    plan = ERC4626VaultInflationHardeningPlan(
        id="vault plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        surfaces=[
            VaultShareSurface(
                id="deposit surface",
                vault_function="deposit(uint256)",
                asset_function="totalAssets()",
                share_function="convertToShares(uint256)",
                total_assets_source="asset.balanceOf(address(this))\x00bad",
                total_supply_source="totalSupply()",
                conversion_formula="assets * supply / totalAssets\x00bad",
                rounding_direction="round down",
                empty_vault_behavior="1:1 shares",
                donation_exposure="direct donation\x00bad",
                mitigation="virtual shares",
                evidence=["deposit uses convertToShares", "bad\x00evidence"],
            )
        ],
        risks=[
            VaultInflationRisk(
                id="zero share",
                category="zero share mint",
                affected_surface_id="deposit surface",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["raw balance totalAssets", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        mitigations=["virtual shares", "bad\x00mitigation"],
        validation_tests=["donation cannot zero shares", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "vault_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["surfaces"][0]["id"] == "deposit_surface"
    assert exported["surfaces"][0]["vault_function"] == "deposit_uint256"
    assert exported["surfaces"][0]["asset_function"] == "totalAssets"
    assert exported["surfaces"][0]["share_function"] == "convertToShares_uint256"
    assert exported["surfaces"][0]["total_assets_source"] == ""
    assert exported["surfaces"][0]["conversion_formula"] == ""
    assert exported["surfaces"][0]["rounding_direction"] == "round_down"
    assert exported["surfaces"][0]["donation_exposure"] == ""
    assert exported["surfaces"][0]["evidence"] == ["deposit uses convertToShares"]
    assert exported["risks"][0]["id"] == "zero_share"
    assert exported["risks"][0]["category"] == "zero_share_mint"
    assert exported["risks"][0]["affected_surface_id"] == "deposit_surface"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["mitigations"] == ["virtual shares"]
    assert exported["validation_tests"] == ["donation cannot zero shares"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_create2_deployment_plan_export_sanitizes_direct_instances():
    plan = Create2DeploymentHardeningPlan(
        id="create2 plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        surfaces=[
            Create2DeploymentSurface(
                id="factory surface",
                deploy_function="deploy(bytes32)",
                factory_contract="Wallet Factory",
                salt_source="salt\x00bad",
                init_code_source="creationCode",
                address_formula="formula\x00bad",
                authorization_guard="owner-bound salt",
                collision_check="code length",
                post_deploy_check="codehash",
                redeploy_assumption="no selfdestruct",
                evidence=["create2 call", "bad\x00evidence"],
            )
        ],
        risks=[
            Create2DeploymentRisk(
                id="salt squat",
                category="salt squatting",
                affected_surface_id="factory surface",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["salt is public", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        mitigations=["owner-bound salt", "bad\x00mitigation"],
        validation_tests=["front-run cannot deploy same address", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "create2_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["surfaces"][0]["id"] == "factory_surface"
    assert exported["surfaces"][0]["deploy_function"] == "deploy_bytes32"
    assert exported["surfaces"][0]["factory_contract"] == "Wallet_Factory"
    assert exported["surfaces"][0]["salt_source"] == ""
    assert exported["surfaces"][0]["address_formula"] == ""
    assert exported["surfaces"][0]["evidence"] == ["create2 call"]
    assert exported["risks"][0]["id"] == "salt_squat"
    assert exported["risks"][0]["category"] == "salt_squatting"
    assert exported["risks"][0]["affected_surface_id"] == "factory_surface"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["mitigations"] == ["owner-bound salt"]
    assert exported["validation_tests"] == ["front-run cannot deploy same address"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_abi_packed_hash_plan_export_sanitizes_direct_instances():
    plan = AbiPackedHashCollisionHardeningPlan(
        id="packed plan\nbad",
        objective="o" * (MAX_AGENT_TEXT_CHARS + 10),
        surfaces=[
            AbiPackedHashSurface(
                id="claim hash",
                hash_function="claim(bytes)",
                packed_expression="abi.encodePacked(a,b)\x00bad",
                argument_types=["string", "bad\x00type"],
                dynamic_argument_count="2",
                user_controlled_arguments=["a", "bad\x00arg"],
                hash_usage="mapping key",
                domain_separator="domain\x00bad",
                delimiter_or_length_guard="none",
                safer_encoding="abi.encode(a,b)",
                evidence=["packed dynamic args", "bad\x00evidence"],
            )
        ],
        risks=[
            AbiPackedHashRisk(
                id="ambiguous encoding",
                category="multiple dynamic args",
                affected_surface_id="claim hash",
                severity_hint="high severity",
                description="description\x00bad",
                evidence=["dynamic pair", "bad\x00evidence"],
                recommended_check="check\x00bad",
            )
        ],
        mitigations=["abi.encode", "bad\x00mitigation"],
        validation_tests=["crafted pair rejected", "bad\x00test"],
        recommended_tools=["foundry", "bad\x00tool"],
        confidence=float("inf"),
        evidence=["specific signal", "bad\x00evidence"],
        metadata={"raw": object()},
    )

    exported = plan.to_dict()

    assert exported["id"] == "packed_plan_bad"
    assert len(exported["objective"]) == MAX_AGENT_TEXT_CHARS
    assert exported["surfaces"][0]["id"] == "claim_hash"
    assert exported["surfaces"][0]["hash_function"] == "claim_bytes"
    assert exported["surfaces"][0]["packed_expression"] == ""
    assert exported["surfaces"][0]["argument_types"] == ["string"]
    assert exported["surfaces"][0]["user_controlled_arguments"] == ["a"]
    assert exported["surfaces"][0]["hash_usage"] == "mapping key"
    assert exported["surfaces"][0]["domain_separator"] == ""
    assert exported["surfaces"][0]["evidence"] == ["packed dynamic args"]
    assert exported["risks"][0]["id"] == "ambiguous_encoding"
    assert exported["risks"][0]["category"] == "multiple_dynamic_args"
    assert exported["risks"][0]["affected_surface_id"] == "claim_hash"
    assert exported["risks"][0]["description"] == ""
    assert exported["risks"][0]["recommended_check"] == ""
    assert exported["mitigations"] == ["abi.encode"]
    assert exported["validation_tests"] == ["crafted pair rejected"]
    assert exported["recommended_tools"] == ["foundry"]
    assert exported["confidence"] == 0.0
    assert exported["evidence"] == ["specific signal"]
    assert exported["metadata"]["raw"] == "<object>"


def test_counterexample_evidence_export_sanitizes_scalar_fields():
    evidence = CounterexampleEvidence(
        invariant_id="asset\nconservation",
        status="counterexample found",
        tool="foundry/test",
        test_name="bad\u2028name",
        artifact_path="p" * (MAX_AGENT_TEXT_CHARS + 10),
        details={f"bad\x00{i}": i for i in range(MAX_AGENT_METADATA_KEYS + 5)}
        | {"valid_key": True},
    )

    exported = evidence.to_dict()

    assert exported["invariant_id"] == "asset_conservation"
    assert exported["status"] == "counterexample_found"
    assert exported["tool"] == "foundry_test"
    assert exported["test_name"] == ""
    assert len(exported["artifact_path"]) == MAX_AGENT_TEXT_CHARS
    assert exported["details"] == {"valid_key": True}


def test_dpg_config_export_clamps_max_source_chars():
    assert DPGAgentConfig(max_source_chars=-1).to_dict()["max_source_chars"] == 0
    assert (
        DPGAgentConfig(max_source_chars=MAX_AGENT_SOURCE_CHARS * 2).to_dict()["max_source_chars"]
        == MAX_AGENT_SOURCE_CHARS
    )


def test_parse_invariant_candidates_category_variants():
    candidates = parse_invariant_candidates(
        {
            "invariants": [
                {"statement": "cap cannot exceed max", "category": "cap-boundary"},
                {"statement": "only admin can pause", "category": "access control"},
                {"statement": "unknown category", "category": "bad\x00category"},
            ]
        }
    )

    assert [candidate.category for candidate in candidates] == [
        InvariantCategory.CAP_BOUNDARY,
        InvariantCategory.ACCESS_CONTROL,
        InvariantCategory.UNKNOWN,
    ]
