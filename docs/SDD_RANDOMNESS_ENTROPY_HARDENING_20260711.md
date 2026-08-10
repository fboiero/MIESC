# SDD: Randomness Entropy Hardening Agent Contract

Date: 2026-07-11
Status: implemented in `lane/codex`
Scope: provider-neutral agent contract for Solidity randomness and entropy lifecycle hardening

## Signal

MIESC already has deterministic detectors for weak randomness patterns and agentic contracts for economic, oracle, delegatecall, cross-chain, signature, upgrade, metamorphic, and transaction-ordering analysis. The remaining gap is an agentic planning surface that reasons about the full entropy lifecycle instead of only matching direct weak sources such as `block.timestamp`, `blockhash`, or `block.prevrandao`.

The target technique is entropy-source lifecycle hardening:

- map every randomness consumer to its entropy source and trust boundary;
- distinguish validator/miner influence, user influence, oracle/VRF fulfillment trust, stale `blockhash`, modulo bias, and fallback entropy;
- require validation tests or replay/fork/property evidence before treating a path as confirmed exploitable;
- suggest provider-neutral hardening tests and tools that can be implemented with any model, local analyzer, or future agent backend.

## Why This Matters

Recent smart contract guidance keeps treating block values and weak entropy as high-impact classes, especially when contracts use `block.prevrandao` or related block metadata for high-value outcomes. Modern VRF guidance also shifts the risk from "random number exists" to the request/fulfillment lifecycle: authorization, confirmations, replay resistance, fallback handling, and consumer-side checks.

This SDD does not replace deterministic weak-randomness detectors. It adds a richer agent contract for cases where the bug depends on protocol context, timing, entropy composition, fulfillment gates, or validation strategy.

## Agent Capability

Capability:

```text
randomness_entropy_hardening
```

Primary output key:

```text
randomness_entropy_hardening_plans
```

Accepted aliases:

```text
randomness_hardening_plans
entropy_source_hardening_plans
entropy_validation_plans
randomness_validation_plans
```

The aliases are intentional. They keep the interface stable across hosted models, replacement models, local analyzers, and deterministic heuristic providers.

## Contract Shape

`RandomnessSource`

- `id`
- `consumer_function`
- `source_kind`
- `source_expression`
- `entropy_scope`
- `commit_phase`
- `reveal_phase`
- `request_id_source`
- `fulfillment_guard`
- `confirmation_depth`
- `modulo_bias_guard`
- `evidence`

`RandomnessRisk`

- `id`
- `category`
- `affected_source_id`
- `severity_hint`
- `description`
- `evidence`
- `recommended_check`

`RandomnessEntropyHardeningPlan`

- `id`
- `objective`
- `sources`
- `risks`
- `validation_tests`
- `recommended_tools`
- `confidence`
- `evidence`
- `metadata`

## Prompt Constraints

The agent prompt must:

- stay provider-neutral and avoid vendor-specific model assumptions;
- avoid claiming confirmed vulnerabilities without replay, fork, property, or counterexample evidence;
- separate randomness lifecycle hardening from generic sequence/MEV/economic simulation;
- avoid regex-only SWC-120 style conclusions;
- explicitly inspect validator/miner influence, user influence, commit/reveal phases, VRF/oracle fulfillment, request identifiers, fallback entropy, blockhash expiry, modulo bias, and confirmation assumptions.

## Parallelization Plan

The 50-activity loop is split into lanes that can run concurrently when files do not overlap:

1. Agent contract lane: enum, dataclasses, parser aliases, prompt, public exports.
2. Public API lane: `src.llm` and `miesc.llm` compatibility exports and degradation behavior.
3. Test lane: parser acceptance, parser rejection, prompt neutrality, sanitization, facade smoke tests.
4. Research lane: compare OWASP weak randomness guidance, `prevrandao` risk notes, VRF lifecycle docs, and recent bad-randomness benchmark work.
5. Local-provider lane: future heuristic adapter work for source detection and empty-output behavior, intentionally left separate from this commit because another claim owns adapter files.

Completed in this checkpoint:

- implemented the provider-neutral contract and parser;
- added source/risk/plan sanitization;
- added prompt constraints for lifecycle hardening;
- exported the contract through both public LLM facades;
- added focused tests for plan parsing and facade usability.

Deferred safe follow-up:

- add local heuristic provider support in `src/llm/reasoning_provider_adapter.py` under a separate claim;
- add fixtures that exercise `block.prevrandao`, stale `blockhash`, commit/reveal aborts, VRF callback authorization, and modulo bias;
- wire the capability into benchmark probes only after a non-canonical dry run records baseline behavior.

## Non-Goals

- No frozen paper, claims matrix, or canonical benchmark artifact changes.
- No assertion of benchmark uplift without measured evidence.
- No direct dependency on a specific hosted model or API.
- No duplicate implementation of the adversarial transaction-ordering agent.
- No replacement of deterministic weak-randomness detectors.

## Validation

Focused validation for this checkpoint:

```bash
ruff check --fix src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- OWASP SCWE-153: Insecure use of `block.prevrandao` as a source of randomness.
- OWASP SCWE-024: Weak randomness sources.
- OWASP SCWE-065: Block values as a proxy for time.
- Chainlink VRF documentation for request/fulfillment lifecycle considerations.
- Sigma Prime Ethereum upgrades notes on `prevrandao` after The Merge.
- "A Risk-Stratified Benchmark Dataset for Bad Randomness" for recent benchmark framing.
