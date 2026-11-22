# RAG in MIESC: three mechanisms, and what each one is (and isn't) measured by

**Date:** 2026-11-20
**Status:** Research note (additive). Clarifies terminology after PR #370.
**Scope:** Terminology and measurement map. Introduces no new benchmark numbers
and changes none of the frozen detection evidence.

## Why this note exists

"RAG" in MIESC refers to **three distinct mechanisms** that live in different
modules, are turned on and off independently, and are measured (or not) by
different harnesses. Conflating them leads to two concrete mistakes:

1. Attributing the committed **+28.6pp precision** result to the per-adapter
   embedding retrieval (it comes from a *different* mechanism).
2. Assuming the shipped **detection / arena numbers** quantify the embedding
   retrieval's contribution (they do not — they are measured with everything on).

PR #370 (`fix(rag): make the RAG A/B evaluation actually measure RAG`) repaired
the harness for mechanism **(1)** below. This note records exactly what that did
and did not change.

## The three mechanisms

### (1) Embedding retrieval inside the LLM detection adapters

- **What:** semantic retrieval from a ChromaDB + sentence-transformers knowledge
  base (`miesc/llm/embedding_rag.py`, `EmbeddingRAG`), injected into the prompt of
  the five LLM adapters: `smartllm`, `gptscan`, `llmsmartaudit`, `llmbugscanner`,
  `propertygpt`. On by default when the optional deps are installed.
- **Measured by:** `miesc/evaluation/rag_evaluator.py` — an A/B harness that runs
  an adapter twice on the same contract, once with retrieval and once without,
  toggled through `MIESC_DISABLE_RAG`.
- **Status:** **unmeasured in practice.** Until PR #370 no adapter read
  `MIESC_DISABLE_RAG`, so both A/B arms ran identically and the result was
  meaningless; a second bug let the adapters' result cache return arm A's output
  for arm B. #370 fixed both (per-call gating via `rag_runtime_disabled()` in
  `miesc/llm/rag_utils.py`, plus the effective RAG state folded into each
  adapter's cache key). **There is still no committed isolated contribution
  number for this mechanism** — producing one needs a ground-truth corpus and a
  real model backend, and is left to a separate additive run (see Open items).

### (2) RAG-grounding inside the benign-context FP verifier

- **What:** category-matching benign patterns injected into the verifier's prompt
  as a *reference checklist* (`miesc/ml/benign_context_verifier.py`,
  `BenignContextVerifier`). This is a false-positive–reduction stage, not a
  detection adapter. It does **not** use `EmbeddingRAG`, `rag_evaluator`, or the
  `MIESC_DISABLE_RAG` toggle.
- **Measured by:** the controlled grounded-vs-ungrounded experiment documented in
  `docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md` §11, run on the v2
  benign-context corpus.
- **Status / committed number:** **+28.6pp precision (42.9% → 71.4%, ~1.7×) at
  zero recall cost** (100% recall preserved, recall-safe reference-prompt
  variant; the directive-prompt variant reached +34.9pp but dropped one real vuln
  and was rejected). This result is **independent of mechanism (1)** and is
  **unaffected by PR #370.**

### (3) Keyword / lexical knowledge lookup (fallback)

- **What:** the non-embedding path — `get_relevant_knowledge()` from
  `miesc/adapters/smartllm_rag_knowledge.py` (SmartLLM's fallback when embedding
  RAG is unavailable) and `VulnerabilityRAG.search_similar()` keyword scoring
  (`miesc/llm/vulnerability_rag.py`). Lexical, not semantic.
- **Measured by:** nothing in isolation.
- **Status:** relevant mainly as a confound: an A/B that disables only the
  *embedding* path but leaves the keyword fallback on would measure
  *embedding vs keyword*, not *RAG vs no-RAG*. PR #370's gate closes this by
  disabling the whole retrieval path (including the keyword fallback) in the
  "off" arm.

## What PR #370 did and did not move

| Evidence | Mechanism | Measured with embedding RAG… | Changed by #370? |
|---|---|---|---|
| Arena real-world (v6.0.0, `benchmarks/results/v6.0.0_arena_fullscan_rescored_20260812.md`): in-scope recall 1/4 → **4/4**; access-control 0/3 → **3/3**; reentrancy **1/1**; economic out-of-scope, 0 manufactured | shipped pipeline | on (default) | **No** |
| SmartBugs academic (~83% recall / ~15% precision, FP-filter recall-safe) | shipped pipeline | on (default) | **No** |
| Rekt / historical (7/7) | shipped pipeline | on (default) | **No** |
| **+28.6pp precision** verifier grounding | (2) verifier prompt | n/a — different mechanism | **No** |
| Isolated embedding-RAG contribution to detection | (1) adapter retrieval | the A/B that was broken | **Harness fixed; still no number** |

**Why the absolute numbers do not move:** they are all measured on the shipped
pipeline with retrieval **on**. PR #370 only changes behaviour when retrieval is
turned **off** for measurement; it does not alter the on-path.

**Why the cache-collision bug did not corrupt them:** the collision only occurs
when the *same* contract is analysed with retrieval on and then off within one
process (the A/B scenario). A normal benchmark run keeps retrieval on throughout,
so no on/off collision is possible. (The ablation study additionally disables the
LLM result cache for variance runs — `benchmarks/ablation_study.py`.)

## A caveat on the ablation study

`benchmarks/ablation_study.py` runs `smartllm` and `gptscan` with embedding RAG
on, but its configs measure the **LLM layer's** contribution (static vs
static+LLM), bundling retrieval into that lift. It does **not** isolate the
embedding retrieval. Isolating it is exactly what the repaired A/B now enables.

## Open items (future, additive, recall-safe)

1. ~~**Produce the mechanism-(1) number.**~~ **Done (2026-11-21/22), and it is
   conditional.** On `qwen2.5-coder:32b` (at ceiling): **ΔRecall = −3.2 pp,
   p = 0.625 — no detectable effect**
   (`docs/research/RAG_ISOLATED_ABLATION_20261121.md`). On the weaker
   `qwen2.5-coder:7b`: **+10.9 pp overall (p = 0.12, n.s.)**, carried by
   access_control (**+50 pp, p = 0.0117**) — but reading the findings shows this is
   **mostly vulnerability-class attribution, not raw detection**
   (`docs/research/RAG_ISOLATED_ABLATION_7B_FOLLOWUP_20261122.md`). Net: RAG's
   mechanism-(1) value depends on model strength and class, and lives largely in
   SWC/class attribution rather than recall.
2. ~~**Control for sampling noise.**~~ **Done (2026-11-21).** 3 runs per arm, cache
   disabled; run-to-run flip rate was 0/63 (the 32B model is deterministic on this
   corpus), so sampling variance is not the confound — ceiling and discordant-pair
   scarcity are. Same note.
3. **Keep recall-safety as the gate.** As with mechanism (2), any retrieval change
   that raises precision at the cost of a dropped true positive is rejected.

## References (in-repo)

- `miesc/llm/rag_utils.py` — `rag_runtime_disabled()` (PR #370)
- `miesc/evaluation/rag_evaluator.py` — the A/B harness
- `miesc/ml/benign_context_verifier.py` — mechanism (2)
- `docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md` §11 — the +28.6pp result
- `benchmarks/ablation_study.py` — LLM-layer ablation
- `benchmarks/results/v6.0.0_arena_fullscan_rescored_20260812.md` — arena recall
