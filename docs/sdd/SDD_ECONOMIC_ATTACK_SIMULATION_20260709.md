# SDD: Economic/Profit-Driven DeFi Attack Simulation

Date: 2026-07-09
Owner lane: Codex
Status: proposed, first provider-neutral economic plan contract implemented

## 1. Signal

MIESC can already detect DeFi patterns, propose transaction sequences, build
semantic graph gates, and guide snapshot/dataflow fuzzing. The remaining gap is
economic viability: a path may be technically reachable but not profitable once
capital, fees, slippage, price assumptions, gas, and repayment are considered.

This SDD adds a provider-neutral artifact that answers a different question:

> Given a candidate path, state, and focal graph, is there an economically
> plausible exploit hypothesis under explicit assumptions?

Relevant external signals:

- FlashSyn synthesizes flash-loan attack strategies.
- DeFiRanger reasons about price manipulation paths in DeFi applications.
- DeFiTainter tracks tainted price-manipulation flows.
- DeFi attack research repeatedly shows that profitability depends on market
  depth, fees, oracle design, and liquidation or borrowing mechanics.

## 2. Spec

Add `economic_attack_simulation` as a provider-neutral plan type.

Inputs:

- Solidity source.
- Existing findings.
- Optional `SequenceOraclePlan` IDs and objects.
- Optional `SnapshotFuzzingPlan` IDs and objects.
- Optional `SemanticGraphGate` IDs and objects.
- Local-first policy constraints.

Output:

```json
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
          "purpose": "fund swap manipulation leg"
        }
      ],
      "asset_flows": [
        {
          "asset": "USDC",
          "from_actor": "flash_pool",
          "to_actor": "attacker",
          "amount_hint": "principal",
          "step_id": "borrow_flash",
          "rationale": "temporary capital for price movement"
        }
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
      "evidence": ["swap and borrow depend on the same price path"]
    }
  ]
}
```

Non-goals:

- Confirming exploitability without replay or counterexample evidence.
- Replacing sequence-oracle, snapshot fuzzing, or semantic graph gates.
- Adding a fork simulator in this checkpoint.
- Editing frozen paper artifacts or canonical benchmark outputs.
- Binding to a specific model, API, or hosted provider.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.ECONOMIC_ATTACK_SIMULATION`.
2. Add `CapitalRequirement`.
3. Add `AssetFlow`.
4. Add `EconomicAttackPlan`.
5. Add `EconomicAttackSimulationAgent`.
6. Add `parse_economic_attack_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is deliberately a hypothesis artifact. It should feed Foundry fork
tests, Anvil simulations, PoC generation, or future economic evaluators, but it
does not by itself become a vulnerability finding.

False-positive controls:

- Plans require an objective and profit formula.
- Plans require at least one capital requirement, asset flow, or liquidity
  assumption.
- Capital, flows, assumptions, evidence, and confidence are bounded.
- Provider/model details remain outside the contract.
- Risk factors and assumptions are first-class fields.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompts avoid vendor/model binding;
- incomplete economic plans are rejected;
- hostile fields are sanitized;
- parser alias `economic_simulation_plans` is accepted;
- public `miesc.llm` facade exports remain stable.

## 5. Integration Plan

The next 50 activities should remain additive and non-canonical until Fernando
approves a baseline update.

Discovery and schema:

1. Inventory DeFi detector outputs for flash-loan/oracle/liquidation signals.
2. Inventory PoC templates that already log `PROFIT`.
3. Inventory Foundry runner output for numeric logs.
4. Define profit formula grammar subset.
5. Define cost model fields for gas, fees, premium, slippage.
6. Define capital source taxonomy.
7. Define asset flow actor taxonomy.
8. Define liquidity assumption fields.
9. Define oracle price assumption fields.
10. Define break-even promotion criteria.

Contract and local heuristics:

11. Add economic plan contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic provider for oracle manipulation economics.
15. Add local heuristic provider for share inflation economics.
16. Add local heuristic provider for liquidation economics.
17. Consume sequence plan IDs.
18. Consume snapshot seed IDs.
19. Consume semantic graph gate IDs.
20. Keep no-signal output empty.

Simulation and PoC bridge:

21. Convert capital requirements into Foundry setup comments.
22. Convert asset flows into balance-delta assertions.
23. Convert profit formula into a Foundry assertion skeleton.
24. Parse numeric `PROFIT` logs, not just text presence.
25. Add flash-loan premium modeling.
26. Add pool fee modeling.
27. Add gas estimate placeholder.
28. Add slippage bound placeholders.
29. Emit `CounterexampleEvidence` only after replay.
30. Feed successful replay into PoC generation.

Profile and reporting:

31. Add opt-in profile knob.
32. Add CLI JSON output.
33. Add MCP schema exposure.
34. Add report section for economic assumptions.
35. Add report section for break-even analysis.
36. Add report section for rejected unprofitable paths.
37. Add local-first policy test.
38. Add resource/time budget policy.
39. Preserve deterministic plan ordering.
40. Add traceability from plan to finding.

Evaluation:

41. Add fixture for oracle manipulation with profit.
42. Add fixture for unprofitable oracle manipulation.
43. Add fixture for ERC4626 inflation profit.
44. Add fixture for liquidation bonus profitability.
45. Run non-canonical unit fixture suite.
46. Run non-canonical DeFi detector subset.
47. Run non-canonical EVMBench subset if relevant.
48. Compare confirmed economic exploitability only.
49. Prepare promotion memo for Fernando.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- FlashSyn: https://dl.acm.org/doi/10.1145/3597503.3639127
- DeFiRanger: https://arxiv.org/abs/2104.15068
- DeFiTainter: https://arxiv.org/abs/2204.02988
- DeFiHackLabs examples: https://github.com/SunWeb3Sec/DeFiHackLabs
- Flash loan attack taxonomy: https://arxiv.org/abs/2003.03810
