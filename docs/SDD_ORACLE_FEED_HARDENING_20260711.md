# SDD: Oracle Feed Hardening

Date: 2026-07-11
Owner: Codex lane
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already covers sequence oracles and economic attack simulation, including
price-manipulation scenarios. The remaining gap is defensive oracle-feed
hardening: when a contract consumes external prices, it should prove freshness,
round completeness, answer bounds, decimals normalization, fallback trust,
deviation controls, and L2 sequencer uptime before using the value.

This SDD adds a provider-neutral artifact for oracle feed hardening. It
inventories Chainlink, TWAP, manual, fallback, and multi-source feeds and emits
validation checks for `latestRoundData`, `updatedAt`, `answeredInRound`,
`answer > 0`, heartbeat/staleness, decimals scaling, deviation/circuit breakers,
fallback source trust, and L2 sequencer uptime grace periods.

Relevant external signals:

- Chainlink documents L2 sequencer uptime feeds and grace periods to avoid stale
  prices after sequencer downtime.
- OWASP SC03:2026 and SCWE-028 classify price oracle manipulation as a core
  smart-contract risk and recommend rejecting stale or incomplete feed data.
- OVer models oracle deviation and synthesizes guard parameters for DeFi
  protocols exposed to skewed oracle input.
- Recent oracle research highlights TWAP delay/manipulation tradeoffs, so
  hardening needs feed-specific assumptions rather than a single generic price
  check.

## 2. Spec

Add a provider-neutral capability:

`oracle_feed_hardening`

The capability emits `oracle_feed_hardening_plans`, each containing:

- `feeds`: consumer function, feed kind, source contract, read method,
  freshness source, staleness threshold, decimals source, normalization,
  fallback source, sequencer guard, bounds check, and evidence.
- `risks`: stale round, incomplete round, decimals mismatch, zero/negative
  price, missing bounds, sequencer down, fallback trust, manual override, and
  multi-source deviation hypotheses.
- `validation_tests`: stale timestamp, incomplete round, negative answer,
  decimals mismatch, sequencer down, grace period, fallback trust, and deviation
  tests.

Parser aliases:

- `oracle_feed_hardening_plans`
- `oracle_source_hardening_plans`
- `price_feed_validation_plans`

Non-goals:

- Replacing economic attack simulation or profitability modeling.
- Replacing sequence-oracle plans for manipulation transactions.
- Replacing regex detectors for obvious oracle misuse.
- Binding to any specific model, hosted API, or vendor.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.ORACLE_FEED_HARDENING`.
2. Add `OracleFeedSource`.
3. Add `OracleFeedRisk`.
4. Add `OracleFeedHardeningPlan`.
5. Add `OracleFeedHardeningAgent`.
6. Add `parse_oracle_feed_hardening_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is feed-validation guidance. It should feed Foundry tests, static
review, symbolic checks, or a future local heuristic provider. It does not by
itself become a vulnerability finding.

False-positive controls:

- Require oracle-read evidence before producing feed records.
- Keep economic/profit assumptions out of this artifact.
- Treat TWAP, Chainlink, manual, fallback, and multi-source feeds separately.
- Require explicit freshness, answer-bound, decimals, fallback, or sequencer
  evidence before high confidence.
- Keep L2 sequencer checks scoped to feed consumption, not rollup governance.

## 4. Validation

Focused tests:

- Provider-neutral agent capability and prompt tests.
- Parser alias and confidence-bound tests.
- Incomplete item rejection.
- Direct dataclass `to_dict()` sanitization.
- Public `miesc.llm` facade export and parser usability.

No frozen papers, canonical benchmark outputs, adapter-owned files, or claims
matrices are part of this checkpoint.

## 5. Integration Plan: 50 Activities

Discovery:

1. Inventory `AggregatorV3Interface` imports.
2. Inventory `latestRoundData()` calls.
3. Inventory `latestAnswer()` legacy calls.
4. Inventory TWAP observation reads.
5. Inventory manual/admin price setters.
6. Inventory fallback price feeds.
7. Inventory multi-source price adapters.
8. Inventory L2 sequencer uptime feed use.
9. Inventory price consumer functions.
10. Classify feed kinds per consumer.

Feed semantics:

11. Extract `updatedAt` use.
12. Extract `answeredInRound` use.
13. Extract `startedAt` use.
14. Extract `roundId` use.
15. Extract `answer > 0` checks.
16. Extract decimals source.
17. Extract scaling target.
18. Extract staleness threshold.
19. Extract heartbeat assumptions.
20. Extract deviation/circuit-breaker assumptions.

Contract and parser:

21. Add oracle feed capability.
22. Add feed source schema.
23. Add oracle risk schema.
24. Add hardening plan schema.
25. Add provider-neutral agent.
26. Add parser aliases.
27. Add direct sanitization tests.
28. Add public exports.
29. Add public facade tests.
30. Keep no-signal output empty.

Validation generation:

31. Generate stale `updatedAt` test.
32. Generate incomplete round test.
33. Generate negative answer test.
34. Generate zero answer test.
35. Generate decimals mismatch test.
36. Generate missing normalization test.
37. Generate sequencer-down test.
38. Generate sequencer grace-period test.
39. Generate fallback feed trust test.
40. Generate multi-source deviation test.

Evaluation:

41. Add safe Chainlink fixture.
42. Add missing staleness fixture.
43. Add missing `answeredInRound` fixture.
44. Add negative answer fixture.
45. Add decimals mismatch fixture.
46. Add missing L2 sequencer fixture.
47. Add TWAP window-too-short fixture.
48. Run non-canonical fixture suite.
49. Compare oracle hardening TPR/FPR only on ground-truth fixtures.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- Chainlink L2 Sequencer Uptime Feeds:
  https://docs.chain.link/data-feeds/l2-sequencer-feeds
- Chainlink Data Feeds:
  https://docs.chain.link/data-feeds
- OWASP SC03:2026 Price Oracle Manipulation:
  https://scs.owasp.org/sctop10/SC03-PriceOracleManipulation/
- OWASP SCWE-028 Price Oracle Manipulation:
  https://scs.owasp.org/SCWE/SCSVS-ORACLE/SCWE-028/
- OVer: Safeguarding DeFi Smart Contracts against Oracle Deviations:
  https://arxiv.org/abs/2401.06044
- Ormer: A Manipulation-resistant and Gas-efficient Blockchain Pricing Oracle
  for DeFi:
  https://arxiv.org/abs/2410.07893
