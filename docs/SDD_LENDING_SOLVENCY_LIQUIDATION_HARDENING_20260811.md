# SDD: Lending Solvency and Liquidation Hardening

Date: 2026-08-11
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already has strong partial coverage for DeFi lending risk:

- `economic_attack_simulation` models profit, capital, flash-loan, slippage,
  oracle assumptions, and liquidation economics.
- `oracle_feed_hardening` validates price feed freshness, completeness, bounds,
  decimals, deviation controls, fallback trust, and L2 sequencer assumptions.
- `financial_math_precision_hardening` covers rounding, scale, accumulator,
  debt-index, interest, health-factor, and liquidation-threshold formulas.
- `sequence_oracle_detection` can plan multi-transaction paths such as
  manipulate price, borrow, accrue, repay, and liquidate.
- `snapshot_fuzzing_guidance` can reuse collateralized, insolvent, or
  near-liquidation states.
- `semantic_graph_gating` and SlithIR SSA summaries can anchor state reads,
  writes, oracle reads, debt flows, and liquidation calls.

The missing surface is a unified provider-neutral artifact for **protocol
solvency**. A lending protocol can pass individual oracle checks and still be
unsafe if collateral valuation, debt accounting, liquidation eligibility,
liquidation incentive, interest accrual, reserve accounting, close factors,
pause modes, or bad-debt absorption do not compose correctly over time.

The technique to add is **Lending Solvency and Liquidation Hardening**: synthesize
solvency-state models and liquidation-oracle obligations that connect collateral,
debt, price, interest, liquidation, reserve, and recovery paths. The output is an
advisory validation plan until a replay, local fixture, symbolic counterexample,
or fuzz campaign demonstrates insolvent borrowing, blocked liquidation,
underwater withdrawal, bad-debt amplification, or protocol accounting drift.

## Spec/Goal

Add a future capability named:

```text
lending_solvency_liquidation_hardening
```

Expected output key:

```text
lending_solvency_liquidation_plans
```

Suggested aliases:

```text
solvency_liquidation_hardening
lending_health_factor_hardening
collateral_debt_invariant_plans
liquidation_oracle_hardening
bad_debt_recovery_hardening
```

The capability must produce advisory solvency/liquidation plans, not confirmed
findings. A plan becomes a finding only after deterministic replay, fuzzing,
symbolic execution, local fixture validation, fork validation, or human review
confirms a reachable insolvency, liquidation bypass, bad-debt drift, or unfair
liquidation path.

Primary objectives:

1. Identify lending markets, collateral assets, debt assets, reserves, indexes,
   shares, exchange rates, collateral factors, liquidation thresholds, close
   factors, bonuses, penalties, and bad-debt accounting fields.
2. Identify solvency-critical functions: deposit/supply, withdraw/redeem,
   borrow, repay, accrueInterest, liquidate, seize, absorb, rebalance, pause,
   configureMarket, updateOracle, and emergency recovery.
3. Infer protocol invariants: collateral value covers borrow value under stated
   thresholds, debt indexes are monotonic, reserves remain solvent, withdrawals
   cannot make an account undercollateralized, liquidation reduces risk, and bad
   debt is accounted for once.
4. Generate validation obligations for near-threshold states, stale or shifted
   prices, interest accrual gaps, rounding boundaries, liquidation incentive
   edges, close-factor splits, partial repay paths, oracle downtime, paused
   markets, and post-liquidation accounting.
5. Preserve false-positive controls for deliberately overcollateralized,
   isolated, capped, paused, guardian-controlled, or oracle-protected markets.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
LendingSolvencyLiquidationPlan = {
    "id": "string",
    "objective": "string",
    "market_model": {
        "markets": [
            {
                "id": "string",
                "collateral_asset": "string",
                "debt_asset": "string",
                "price_source": "string",
                "collateral_factor": "string",
                "liquidation_threshold": "string",
                "close_factor": "string",
                "liquidation_bonus": "string",
                "interest_index": "string",
                "reserve_account": "string",
                "source_anchors": ["file:line"],
            }
        ],
        "accounting_fields": ["collateral", "debt", "shares", "indexes", "reserves", "bad_debt"],
        "price_dependencies": ["oracle_feed_id"],
        "configuration_actors": ["admin", "governor", "guardian"],
    },
    "solvency_hypothesis": {
        "category": "insolvent_borrow|unsafe_withdraw|liquidation_bypass|liquidation_over_seizure|liquidation_under_seizure|interest_accrual_gap|oracle_decimal_shift|stale_price_solvency|bad_debt_double_count|reserve_drift|paused_market_recovery_gap|rounding_threshold_flip",
        "attacker_or_market_condition": "string",
        "unsafe_state_transition": "string",
        "affected_market": "string",
        "preconditions": ["string"],
        "negative_checks": ["string"],
    },
    "solvency_oracle": {
        "property": "string",
        "safe_state_condition": "string",
        "forbidden_state_condition": "string",
        "post_liquidation_condition": "string",
        "bad_debt_accounting_condition": "string",
    },
    "execution_plan": {
        "recommended_tools": ["foundry", "halmos", "echidna", "slither", "anvil", "local_fixture", "human_review"],
        "sequence": ["call"],
        "actors": ["borrower", "liquidator", "supplier", "admin", "keeper", "attacker"],
        "inputs_to_mutate": ["prices", "collateral_amounts", "borrow_amounts", "repay_amounts", "time_delta", "rounding_edges"],
        "snapshot_state_hint": "near threshold, underwater, stale oracle, or post-accrual",
        "fork_or_timewarp_hint": "string",
    },
    "promotion": {
        "state": "hypothesis|test_generated|counterexample|replayed|rejected",
        "evidence": ["string"],
        "blockers": ["string"],
    },
    "metadata": {
        "capability": "lending_solvency_liquidation_hardening",
        "schema_version": "1",
    },
}
```

The capability should compose existing MIESC pieces:

- `OracleFeedHardeningPlan` supplies price-source trust and freshness context.
- `FinancialMathPrecisionHardeningPlan` supplies formula, scale, rounding, and
  index-drift risks.
- `EconomicAttackPlan` supplies capital, cost, slippage, and profit assumptions.
- `SequenceOraclePlan` supplies borrow/repay/liquidate/accrue ordering.
- `SnapshotFuzzingPlan` supplies near-threshold and stale-state seeds.
- `SemanticGraphGate` supplies market, account, oracle, and liquidation anchors.
- `SlithIR SSA + Interprocedural State/Taint Summary` supplies precise reads and
  writes for collateral, debt, reserve, and liquidation state.
- `PrivilegedGovernanceLifecyclePlan` supplies configuration authority and
  emergency market controls.
- `ResourceLivenessGriefingPlan` supplies recovery checks for paused or
  unliquidatable markets.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**.
No schema, parser, prompt, or test may bind the capability to a specific vendor,
hosted endpoint, product family, or model.

The reasoning agent must:

- Separate observed accounting surfaces from inferred solvency risk.
- Anchor each market, price read, debt update, collateral update, liquidation
  action, and reserve update to source lines when available.
- Return at least one negative check for every hypothesis.
- Prefer executable solvency oracles over narrative severity.
- Keep oracle, math, governance, and economic assumptions explicit.
- Avoid confirmed-finding language until validation confirms reachability.
- Support deterministic local fallback based on borrow/repay/liquidate/accrue/
  collateral/debt/oracle naming and Slither-derived state writes.

## False-Positive Controls

The capability must avoid noisy lending findings:

- A borrow path is not a finding when collateral checks use fresh, bounded,
  normalized prices and conservative thresholds.
- A withdrawal path is not a finding when it rechecks health after interest and
  price updates.
- Liquidation complexity is not a finding when close factor, bonus, rounding,
  and seize math preserve or improve solvency.
- Stale price risk is not duplicated when it is already fully owned by an
  oracle-feed plan and has no solvency impact.
- Rounding risk is not duplicated when it is already fully owned by a financial
  math plan and has no threshold-flip consequence.
- Paused markets are not findings when liquidation, repay, and emergency
  recovery remain available.
- Bad-debt accounting is not a finding when debt is written off exactly once and
  reserves or socialized loss are explicit.
- Governance-controlled risk parameters are not findings without an unsafe
  transition, missing delay, or critical solvency consequence.
- Provider output must be bounded and parser-validated before integration.

Promotion rules:

- `hypothesis`: market model and solvency risk only.
- `test_generated`: a solvency oracle or liquidation harness exists but has not
  failed.
- `counterexample`: fuzzing or symbolic execution demonstrates an unsafe
  solvency or liquidation transition.
- `replayed`: deterministic local or fork replay demonstrates insolvent borrow,
  unsafe withdrawal, blocked liquidation, bad debt drift, or unfair seizure.
- `rejected`: fresh oracle checks, conservative math, bounded liquidation, safe
  pause/recovery, or explicit bad-debt handling disproves the risk.

## Non-Goals

- No replacement for oracle-feed hardening.
- No replacement for financial math precision hardening.
- No replacement for economic attack simulation or profitability modeling.
- No claim that all centralized risk-parameter control is a vulnerability.
- No canonical benchmark update from this SDD alone.
- No remote-chain dependency in the first implementation.
- No provider-specific dependency.
- No confirmed vulnerability without a reachable unsafe state transition.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add provider-neutral schema contracts and parser tests.
2. Add local market-model extraction for collateral, debt, price, thresholds,
   close factors, bonuses, interest indexes, reserves, and bad-debt fields.
3. Add solvency-critical function classifier for supply/withdraw/borrow/repay/
   accrue/liquidate/seize/absorb/pause/configure paths.
4. Add hypothesis generator for unsafe borrow, unsafe withdrawal, liquidation
   bypass, over/under-seizure, stale price solvency, interest gaps, bad-debt
   drift, reserve drift, and rounding threshold flips.
5. Generate solvency oracles for Foundry/Halmos/Echidna/local fixtures.
6. Add fixtures with safe and unsafe variants for each lending family.
7. Run only non-canonical probes until benchmark promotion is explicitly
   approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory current DeFi detector lending outputs.
2. Inventory oracle-feed hardening price-source fields.
3. Inventory financial-math liquidation/health-factor fields.
4. Inventory economic attack liquidation assumptions.
5. Inventory benchmark categories that mention liquidation, oracle, or lending.
6. Define `LendingMarket` schema.
7. Define `AccountingField` schema.
8. Define `SolvencyHypothesis` schema.
9. Define `SolvencyOracle` schema.
10. Define `LendingSolvencyLiquidationPlan` schema.
11. Add parser for canonical output key.
12. Add parser aliases for solvency/liquidation plans.
13. Add bounded text/list sanitization.
14. Add no-provider-binding regression tests.
15. Export public facade symbols.
16. Detect collateral asset fields.
17. Detect debt asset fields.
18. Detect price source reads.
19. Detect collateral-factor constants.
20. Detect liquidation-threshold constants.
21. Detect close-factor constants.
22. Detect liquidation-bonus constants.
23. Detect debt indexes and interest accrual.
24. Detect reserve and protocol-fee accounting.
25. Detect bad-debt or absorb accounting.
26. Detect supply/deposit functions.
27. Detect withdraw/redeem functions.
28. Detect borrow functions.
29. Detect repay functions.
30. Detect liquidate/seize/absorb functions.
31. Add negative checks for fresh normalized prices.
32. Add negative checks for post-withdraw health checks.
33. Add negative checks for monotonic debt indexes.
34. Add negative checks for bounded close factor and seize math.
35. Add negative checks for pause-safe repay/liquidation/recovery.
36. Generate Foundry solvency property metadata.
37. Generate Halmos health-factor assertion metadata.
38. Generate Echidna near-threshold sequence metadata.
39. Generate local fixture obligations.
40. Bridge market model to semantic graph gates.
41. Bridge borrow/repay/liquidate sequences to sequence-oracle synthesis.
42. Bridge near-threshold states to snapshot fuzzing.
43. Bridge price and accounting math to oracle/math plans.
44. Add fixture: borrow succeeds past safe LTV.
45. Add fixture: safe borrow rejects unsafe LTV.
46. Add fixture: withdrawal makes account insolvent.
47. Add fixture: liquidation fails after stale price.
48. Add fixture: liquidation over-seizes collateral.
49. Add fixture: bad debt double-counts reserves.
50. Add runbook notes for comparing solvency plans with benchmark findings.

Parallel lanes:

- Lane A: schemas, parser, exports, and provider-neutral tests.
- Lane B: market model and solvency-critical function extraction.
- Lane C: solvency hypothesis generation and negative checks.
- Lane D: solvency-oracle generation and tool metadata bridges.
- Lane E: fixtures, non-canonical evidence, benchmark comparison, and runbook
  notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md
git diff --check -- docs/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md
```

Provider/model-name checks should run against the document content during review
and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for market-model extraction.
- Parser tests for bounded provider-neutral output.
- Fixtures for unsafe and safe borrow/withdraw/liquidate paths.
- Local/fork replay tests only when the victim or market source is present.
