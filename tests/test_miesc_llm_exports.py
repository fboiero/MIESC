"""Compatibility tests for the public miesc.llm package facade."""

import builtins
import importlib
import sys

import miesc.llm as public_llm
import miesc.llm as source_llm

AGENTIC_EXPORTS = [
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
    "LLMOrchestratorReasoningProvider",
    "LocalHeuristicReasoningProvider",
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
    "ReasoningProviderRoute",
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
    "auto_reasoning_provider",
    "parse_abi_packed_hash_collision_hardening_plans",
    "parse_adversarial_transaction_ordering_plans",
    "parse_create2_deployment_hardening_plans",
    "parse_cross_chain_message_hardening_plans",
    "parse_delegatecall_storage_aliasing_plans",
    "parse_differential_test_plans",
    "parse_economic_attack_plans",
    "parse_erc4626_vault_inflation_hardening_plans",
    "parse_invariant_candidates",
    "parse_oracle_feed_hardening_plans",
    "parse_randomness_entropy_hardening_plans",
    "parse_semantic_graph_gates",
    "parse_signature_domain_hardening_plans",
    "parse_snapshot_fuzzing_plans",
    "parse_sequence_oracle_plans",
    "parse_token_hook_reentrancy_hardening_plans",
    "parse_upgrade_evolution_plans",
]


def test_miesc_llm_reexports_agentic_contracts():
    for name in AGENTIC_EXPORTS:
        assert getattr(public_llm, name) is getattr(source_llm, name)
        assert name in public_llm.__all__


def test_miesc_llm_agentic_parser_is_usable():
    candidates = public_llm.parse_invariant_candidates(
        {
            "invariants": [
                {
                    "statement": "totalAssets must cover issued shares",
                    "category": "accounting",
                    "confidence": 0.9,
                }
            ]
        }
    )

    assert len(candidates) == 1
    assert candidates[0].category is public_llm.InvariantCategory.ACCOUNTING
    assert candidates[0].confidence == 0.9


def test_miesc_llm_sequence_oracle_parser_is_usable():
    plans = public_llm.parse_sequence_oracle_plans(
        {
            "sequence_oracle_plans": [
                {
                    "objective": "donation should not inflate shares",
                    "sequence": [{"function": "donate"}, {"function": "deposit"}],
                    "oracle": "shares remain proportional to assets",
                    "confidence": 0.75,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.SequenceOraclePlan)
    assert plans[0].sequence[0].function == "donate"
    assert plans[0].confidence == 0.75


def test_miesc_llm_erc4626_vault_inflation_parser_is_usable():
    plans = public_llm.parse_erc4626_vault_inflation_hardening_plans(
        {
            "vault_inflation_hardening_plans": [
                {
                    "objective": "donation should not force zero victim shares",
                    "surfaces": [
                        {
                            "id": "deposit_share_math",
                            "vault_function": "deposit",
                            "share_function": "convertToShares",
                        }
                    ],
                    "risks": [
                        {
                            "id": "first_deposit_donation",
                            "category": "first_depositor",
                            "description": "first depositor can donate assets before victim deposit",
                        }
                    ],
                    "confidence": 0.81,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.ERC4626VaultInflationHardeningPlan)
    assert plans[0].surfaces[0].vault_function == "deposit"
    assert plans[0].risks[0].category == "first_depositor"
    assert plans[0].confidence == 0.81


def test_miesc_llm_abi_packed_hash_collision_parser_is_usable():
    plans = public_llm.parse_abi_packed_hash_collision_hardening_plans(
        {
            "abi_packed_hash_collision_hardening_plans": [
                {
                    "objective": "packed claim hash cannot collide",
                    "surfaces": [
                        {
                            "id": "claim_hash",
                            "hash_function": "claim",
                            "argument_types": ["string", "string"],
                            "hash_usage": "mapping_key",
                        }
                    ],
                    "validation_tests": ["shifted dynamic strings do not collide"],
                    "confidence": 0.84,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.AbiPackedHashCollisionHardeningPlan)
    assert plans[0].surfaces[0].hash_function == "claim"
    assert plans[0].surfaces[0].argument_types == ["string", "string"]
    assert plans[0].validation_tests == ["shifted dynamic strings do not collide"]
    assert plans[0].confidence == 0.84


def test_miesc_llm_token_hook_reentrancy_parser_is_usable():
    plans = public_llm.parse_token_hook_reentrancy_hardening_plans(
        {
            "token_hook_reentrancy_hardening_plans": [
                {
                    "objective": "ERC777 hook cannot reenter deposit accounting",
                    "surfaces": [
                        {
                            "id": "deposit_hook_surface",
                            "entrypoint": "deposit",
                            "token_standard": "ERC777",
                            "hook_function": "tokensReceived",
                        }
                    ],
                    "risks": [
                        {
                            "id": "hook_before_effects",
                            "category": "hook_before_effects",
                            "description": "token callback can reenter before effects",
                        }
                    ],
                    "validation_tests": ["malicious hook reentry reverts"],
                    "confidence": 0.83,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.TokenHookReentrancyHardeningPlan)
    assert plans[0].surfaces[0].entrypoint == "deposit"
    assert plans[0].surfaces[0].hook_function == "tokensReceived"
    assert plans[0].risks[0].category == "hook_before_effects"
    assert plans[0].confidence == 0.83


def test_miesc_llm_semantic_graph_gate_parser_is_usable():
    gates = public_llm.parse_semantic_graph_gates(
        {
            "semantic_graph_gates": [
                {
                    "objective": "focus withdraw access control",
                    "focal_nodes": ["fn_withdraw"],
                    "nodes": [{"id": "fn_withdraw", "kind": "function"}],
                    "edges": [
                        {
                            "source": "fn_withdraw",
                            "target": "state_owner",
                            "relation": "missing_guard",
                        }
                    ],
                    "confidence": 0.8,
                }
            ]
        }
    )

    assert len(gates) == 1
    assert isinstance(gates[0], public_llm.SemanticGraphGate)
    assert gates[0].nodes[0].kind == "function"
    assert gates[0].edges[0].relation == "missing_guard"
    assert gates[0].confidence == 0.8


def test_miesc_llm_snapshot_fuzzing_parser_is_usable():
    plans = public_llm.parse_snapshot_fuzzing_plans(
        {
            "snapshot_fuzzing_plans": [
                {
                    "objective": "reuse initialized vault state",
                    "seeds": [{"id": "seed_initialized", "target_state": "vault initialized"}],
                    "waypoints": [{"id": "asset_delta", "target": "totalAssets delta"}],
                    "oracle": "assets and shares remain proportional",
                    "confidence": 0.72,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.SnapshotFuzzingPlan)
    assert plans[0].seeds[0].id == "seed_initialized"
    assert plans[0].waypoints[0].target == "totalAssets delta"
    assert plans[0].confidence == 0.72


def test_miesc_llm_economic_attack_parser_is_usable():
    plans = public_llm.parse_economic_attack_plans(
        {
            "economic_attack_plans": [
                {
                    "objective": "evaluate oracle manipulation profit",
                    "capital_requirements": [{"asset": "USDC", "amount_hint": "flash loan"}],
                    "asset_flows": [
                        {"asset": "WETH", "from_actor": "protocol", "to_actor": "attacker"}
                    ],
                    "profit_formula": "borrowed_value - costs",
                    "liquidity_assumptions": ["pool depth supports price move"],
                    "confidence": 0.73,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.EconomicAttackPlan)
    assert plans[0].capital_requirements[0].asset == "USDC"
    assert plans[0].asset_flows[0].to_actor == "attacker"
    assert plans[0].confidence == 0.73


def test_miesc_llm_differential_test_parser_is_usable():
    plans = public_llm.parse_differential_test_plans(
        {
            "differential_test_plans": [
                {
                    "objective": "split deposit should equal merged deposit",
                    "relations": [
                        {
                            "id": "split_merge_deposit",
                            "relation_type": "split_merge",
                            "baseline_sequence": [{"function": "deposit"}],
                            "variant_sequence": [{"function": "deposit"}],
                            "expected_relation": "same final shares",
                        }
                    ],
                    "oracle": "final share accounting diverges",
                    "confidence": 0.74,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.DifferentialTestPlan)
    assert plans[0].relations[0].id == "split_merge_deposit"
    assert plans[0].confidence == 0.74


def test_miesc_llm_upgrade_evolution_parser_is_usable():
    plans = public_llm.parse_upgrade_evolution_plans(
        {
            "upgrade_evolution_plans": [
                {
                    "objective": "upgrade preserves owner slot",
                    "proxy_pattern": "transparent",
                    "storage_changes": [
                        {
                            "slot": "0",
                            "before": "address owner",
                            "after": "bool openForSale",
                            "risk": "owner slot can be corrupted",
                        }
                    ],
                    "confidence": 0.76,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.UpgradeEvolutionPlan)
    assert plans[0].storage_changes[0].slot == "0"
    assert plans[0].proxy_pattern == "transparent"
    assert plans[0].confidence == 0.76


def test_miesc_llm_signature_domain_parser_is_usable():
    plans = public_llm.parse_signature_domain_hardening_plans(
        {
            "signature_domain_hardening_plans": [
                {
                    "objective": "permit signatures cannot replay",
                    "signed_actions": [
                        {
                            "id": "permit_action",
                            "function": "permit",
                            "digest_scheme": "eip712",
                            "domain_fields": ["chainId", "verifyingContract"],
                        }
                    ],
                    "replay_tests": ["same signature fails after nonce increments"],
                    "confidence": 0.77,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.SignatureDomainHardeningPlan)
    assert plans[0].signed_actions[0].function == "permit"
    assert plans[0].signed_actions[0].domain_fields == ["chainId", "verifyingContract"]
    assert plans[0].replay_tests == ["same signature fails after nonce increments"]
    assert plans[0].confidence == 0.77


def test_miesc_llm_cross_chain_message_parser_is_usable():
    plans = public_llm.parse_cross_chain_message_hardening_plans(
        {
            "cross_chain_message_hardening_plans": [
                {
                    "objective": "bridge messages cannot replay",
                    "message_flows": [
                        {
                            "id": "receive_message",
                            "handler_function": "receiveMessage",
                            "message_id_source": "messageHash",
                            "replay_guard": "processedMessages[messageHash]",
                        }
                    ],
                    "validation_tests": ["same message hash fails after consumption"],
                    "confidence": 0.79,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.CrossChainMessageHardeningPlan)
    assert plans[0].message_flows[0].handler_function == "receiveMessage"
    assert plans[0].message_flows[0].replay_guard == "processedMessages[messageHash]"
    assert plans[0].validation_tests == ["same message hash fails after consumption"]
    assert plans[0].confidence == 0.79


def test_miesc_llm_delegatecall_storage_aliasing_parser_is_usable():
    plans = public_llm.parse_delegatecall_storage_aliasing_plans(
        {
            "delegatecall_storage_aliasing_plans": [
                {
                    "objective": "delegatecall cannot overwrite owner slot",
                    "delegatecall_surfaces": [
                        {
                            "id": "fallback_delegate",
                            "caller_function": "fallback",
                            "target_source": "implementation",
                        }
                    ],
                    "storage_alias_paths": [
                        {
                            "id": "owner_alias",
                            "delegatecall_surface_id": "fallback_delegate",
                            "caller_slot": "slot 0",
                            "callee_slot": "slot 0",
                        }
                    ],
                    "validation_tests": ["malicious callee cannot set owner"],
                    "confidence": 0.78,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.DelegatecallStorageAliasingPlan)
    assert plans[0].delegatecall_surfaces[0].caller_function == "fallback"
    assert plans[0].storage_alias_paths[0].caller_slot == "slot 0"
    assert plans[0].validation_tests == ["malicious callee cannot set owner"]
    assert plans[0].confidence == 0.78


def test_miesc_llm_oracle_feed_parser_is_usable():
    plans = public_llm.parse_oracle_feed_hardening_plans(
        {
            "oracle_feed_hardening_plans": [
                {
                    "objective": "oracle feed rejects stale answers",
                    "feeds": [
                        {
                            "id": "eth_usd",
                            "consumer_function": "getPrice",
                            "read_method": "latestRoundData",
                            "freshness_source": "updatedAt",
                        }
                    ],
                    "validation_tests": ["stale updatedAt fails"],
                    "confidence": 0.8,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.OracleFeedHardeningPlan)
    assert plans[0].feeds[0].consumer_function == "getPrice"
    assert plans[0].feeds[0].freshness_source == "updatedAt"
    assert plans[0].validation_tests == ["stale updatedAt fails"]
    assert plans[0].confidence == 0.8


def test_miesc_llm_adversarial_transaction_ordering_parser_is_usable():
    plans = public_llm.parse_adversarial_transaction_ordering_plans(
        {
            "adversarial_transaction_ordering_plans": [
                {
                    "objective": "sandwich ordering respects minOut",
                    "ordering_pattern": "sandwich",
                    "transactions": [
                        {
                            "id": "victim",
                            "role": "victim",
                            "function": "swap",
                            "position": "victim",
                        }
                    ],
                    "oracle": "victim output remains above minOut",
                    "validation_tests": ["front-run before victim respects minOut"],
                    "confidence": 0.81,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.AdversarialOrderingPlan)
    assert plans[0].ordering_pattern == "sandwich"
    assert plans[0].transactions[0].role == "victim"
    assert plans[0].oracle == "victim output remains above minOut"
    assert plans[0].validation_tests == ["front-run before victim respects minOut"]
    assert plans[0].confidence == 0.81


def test_miesc_llm_randomness_entropy_parser_is_usable():
    plans = public_llm.parse_randomness_entropy_hardening_plans(
        {
            "randomness_entropy_hardening_plans": [
                {
                    "objective": "randomness rejects validator-controlled entropy",
                    "sources": [
                        {
                            "id": "winner_entropy",
                            "consumer_function": "drawWinner",
                            "source_kind": "prevrandao",
                            "source_expression": "block.prevrandao",
                        }
                    ],
                    "validation_tests": ["prevrandao mutation changes winner"],
                    "confidence": 0.82,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.RandomnessEntropyHardeningPlan)
    assert plans[0].sources[0].consumer_function == "drawWinner"
    assert plans[0].sources[0].source_kind == "prevrandao"
    assert plans[0].validation_tests == ["prevrandao mutation changes winner"]
    assert plans[0].confidence == 0.82


def test_miesc_llm_erc4626_vault_inflation_parser_is_usable():
    plans = public_llm.parse_erc4626_vault_inflation_hardening_plans(
        {
            "erc4626_vault_inflation_hardening_plans": [
                {
                    "objective": "donation cannot zero victim shares",
                    "surfaces": [
                        {
                            "id": "deposit_surface",
                            "vault_function": "deposit",
                            "share_function": "convertToShares",
                            "rounding_direction": "down",
                        }
                    ],
                    "validation_tests": ["donation before deposit mints nonzero shares"],
                    "confidence": 0.83,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.ERC4626VaultInflationHardeningPlan)
    assert plans[0].surfaces[0].vault_function == "deposit"
    assert plans[0].surfaces[0].share_function == "convertToShares"
    assert plans[0].validation_tests == ["donation before deposit mints nonzero shares"]
    assert plans[0].confidence == 0.83


def test_miesc_llm_create2_deployment_parser_is_usable():
    plans = public_llm.parse_create2_deployment_hardening_plans(
        {
            "create2_deployment_hardening_plans": [
                {
                    "objective": "salt cannot be squatted",
                    "surfaces": [
                        {
                            "id": "factory_deploy",
                            "deploy_function": "deployWallet",
                            "salt_source": "owner-bound salt",
                        }
                    ],
                    "validation_tests": ["attacker same salt deployment reverts"],
                    "confidence": 0.84,
                }
            ]
        }
    )

    assert len(plans) == 1
    assert isinstance(plans[0], public_llm.Create2DeploymentHardeningPlan)
    assert plans[0].surfaces[0].deploy_function == "deployWallet"
    assert plans[0].surfaces[0].salt_source == "owner-bound salt"
    assert plans[0].validation_tests == ["attacker same salt deployment reverts"]
    assert plans[0].confidence == 0.84


# Removed: test_miesc_llm_agentic_exports_degrade_to_none_on_src_import_error.
# Obsolete façade behavior after the src.llm -> miesc.llm unification: agentic
# exports are now a hard import (not an optional-degradation path), and this test
# polluted sys.modules. (Same removal as the package-unification refactor.)
