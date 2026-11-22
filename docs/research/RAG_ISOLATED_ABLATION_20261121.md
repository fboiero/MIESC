# Isolated EmbeddingRAG ablation: no detectable recall effect on the contested-middle corpus

**Date:** 2026-11-21
**Status:** Research note (additive). Closes Open items #1 and #2 of
`docs/research/RAG_MECHANISMS_MEASUREMENT_MAP_20261120.md`.
**Follow-up:** this null is for the **32B** backend (at ceiling). A weaker 7B
backend does show an effect — conditional and mostly about class attribution — see
`docs/research/RAG_ISOLATED_ABLATION_7B_FOLLOWUP_20261122.md`. Read both together
before concluding anything general about mechanism (1).
**Scope:** Produces the first isolated contribution number for RAG **mechanism (1)**
— the embedding retrieval inside the LLM detection adapters. Introduces no new
benchmark claim, changes no frozen detection evidence, emits no findings.

## Question

What does the per-adapter EmbeddingRAG retrieval (ChromaDB + sentence-transformers,
injected into the LLM prompt) add to **detection recall**, measured in isolation?
The measurement map (2026-11-20) repaired the A/B harness in PR #370 but left the
number unproduced. This note runs that harness on a real corpus and reports it.

## Design

Paired A/B on one adapter instance, retrieval toggled per call through the
`MIESC_DISABLE_RAG` gate that PR #370 wired into the adapters.

| Parameter | Value |
|---|---|
| Adapter | `smartllm` (master `_use_rag` switch; keyword fallback also gated off in the OFF arm) |
| Arms | **ON** = RAG on (default) · **OFF** = `MIESC_DISABLE_RAG=1` |
| Model | `qwen2.5-coder:32b` (Ollama, digest `b92d6a0bd47e`), pinned and asserted via `metadata.model` |
| Embedding model | `all-MiniLM-L6-v2` (EmbeddingRAG default) |
| KB version | `2026-11-15-chain-provenance-v5` |
| Corpus | SmartBugs-curated, 3 "contested-middle" classes: reentrancy (31), access_control (18), arithmetic (15) = 64 contracts |
| Runs | 3 per arm per contract (LLM result cache disabled) |
| Scorer | category-level (`classify_finding`); a contract is a **hit** if its true category is among the detected categories |
| Pairing | per contract, majority vote across runs where **both** arms returned `success`; a contract with < 2 valid paired runs is dropped |
| Test | paired McNemar exact (two-sided binomial on discordant pairs) |
| Repo SHA | `350c914bb9645d2824fe74853b14e919be52b919` |

384 calls (64 × 3 × 2) completed; 381 `success`, 3 `timeout`. Toggle integrity was
total: across all 192 ON calls `metadata.rag_enhanced` was `True` with a mean of
5.0 retrieved hits; across all 192 OFF calls it was `False` with 0 hits.

## Result

**ΔRecall(EmbeddingRAG) = −3.2 pp — indistinguishable from zero. No detectable effect.**

| Slice | n | Recall ON [95% CI] | Recall OFF [95% CI] | Δ (pp) | McNemar p |
|---|---|---|---|---|---|
| **Overall** | 63 | 0.937 [0.848, 0.975] | 0.968 [0.891, 0.991] | **−3.2** | **0.625** |
| reentrancy | 31 | 0.968 | 1.000 | −3.2 | n/s* |
| access_control | 17 | 0.824 | 0.882 | −5.9 | n/s* |
| arithmetic | 15 | 1.000 | 1.000 | 0.0 | n/s* |

Wilson 95% CIs. One contract (`rubixi.sol`) dropped: its 3 ON runs all timed out.
\* Per-category p-values are omitted deliberately — with 0–3 discordant pairs per
category they carry no information.

## Why the −3.2 pp is not evidence that RAG hurts

The point estimate is small, slightly favours OFF, and does not survive scrutiny:

1. **Statistically null, and underpowered by construction.** The entire effect
   rests on **4 discordant contracts out of 63**: ON-only win = 1
   (`FibonacciBalance`), OFF-only wins = 3 (`arbitrary_location_write_simple`,
   `simple_suicide`, `reentrancy_dao`). McNemar on (1, 3) gives p = 0.625. With
   only 4 discordant pairs the **smallest p the design can produce is 0.125** — it
   could not have reached significance regardless of direction.

2. **Partly a spray artifact.** The hit metric rewards emitting more categories.
   Paired over the 189 both-success run-pairs, the OFF arm emits **more** findings
   (1.37 vs 1.27) and **nearly double the off-target categories** (0.30 vs 0.17)
   at essentially identical latency (130.5 s vs 129.5 s). OFF's few extra hits come
   from casting a wider, noisier net — not from superior detection. Read the other
   way: RAG ON is slightly more conservative (fewer findings, fewer off-target
   categories) at equal recall. (This note does **not** claim a precision effect —
   the corpus has no false-positive labels; that is a separate experiment.)

3. **Ceiling effect.** Recall sits at ~94–97 % in both arms. Two factors inflate
   the absolute level equally in both arms (so they cancel in the delta but crush
   the headroom RAG could occupy): inline `@vulnerable_at_lines:` source
   annotations — which the prompt sanitizer does **not** strip (confirmed:
   `sanitize_code_for_prompt` removes only control / zero-width characters and
   truncates) and which reach the model identically in both arms — and
   verificator-timeout-kept findings. Verificator timeouts were **symmetric**
   across arms (213 ON / 215 OFF), so this confound too cancels in the delta.

4. **Zero run-to-run noise.** 0/63 contracts changed hit/miss across the 3 ON
   runs: the 32B model is deterministic on this corpus. The −3.2 pp is therefore a
   real but tiny deterministic difference, not sampling noise — which is exactly
   why a within-arm standard deviation is the wrong noise floor here (it is 0) and
   the per-contract flip rate (also 0) is the right one.

## Interpretation

On this contested-middle corpus, with a strong 32B model, **EmbeddingRAG retrieval
does not measurably change detection recall.** The most defensible reading is
*inconclusive at ceiling*: a large model that already encodes the canonical
reentrancy / access-control / overflow patterns gains no recall headroom from
semantic retrieval here. This is a property of this regime (strong model, annotated
near-ceiling corpus, recall-only metric), not a general verdict on retrieval.

This result is **consistent with**, and does not disturb, the surrounding evidence:

- It does **not** contradict the committed **+28.6 pp precision** result — that is
  RAG **mechanism (2)** (the `BenignContextVerifier` prompt grounding), a different
  module and a different metric (precision, not recall).
- It does **not** move the shipped arena / SmartBugs / Rekt numbers — those are
  measured on the full pipeline with retrieval on; this only characterises what
  turning mechanism (1) off would cost on these categories (within noise, nothing).

## What would change the picture (future, additive, recall-safe — not run here)

- **A harder corpus off the ceiling** (no inline annotations; novel or
  obfuscated contracts) where retrieval has room to help.
- **A weaker backend** (e.g. a 7B model) that lacks the internal pattern
  knowledge the 32B already has — the regime where retrieval is most likely to pay.
  **Done (2026-11-22):** `docs/research/RAG_ISOLATED_ABLATION_7B_FOLLOWUP_20261122.md`.
- **Precision labels** to test the conservative-output signal (fewer off-target
  categories with RAG on) directly.

These are the user's call to commission; this note does not launch them.

## Provenance / reproduce

- Collection script `rag_ab_collect.py` and raw `rag_ab_raw_20261121.json` are
  committed under `docs/research/data/rag_isolated_ablation_20261121/` (contract
  paths repo-relative). The analysis is `rag_ab_compare.py` in that bundle.
- Pinned: SHA `350c914b…`, model digest `b92d6a0bd47e`, KB
  `2026-11-15-chain-provenance-v5`, embedding `all-MiniLM-L6-v2`.
- Harness: the PR #370 gate (`rag_runtime_disabled()` in `miesc/llm/rag_utils.py`
  + effective RAG state folded into each adapter cache key).

## References (in-repo)

- `docs/research/RAG_MECHANISMS_MEASUREMENT_MAP_20261120.md` — the three mechanisms; this closes its Open items #1–#2
- `docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md` §11 — the +28.6pp precision (mechanism 2)
- `miesc/llm/rag_utils.py`, `miesc/evaluation/rag_evaluator.py` — the repaired A/B harness
- `miesc/llm/embedding_rag.py` — `EmbeddingRAG` (mechanism 1)
