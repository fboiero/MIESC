# EmbeddingRAG is conditional: a 7B follow-up to the 32B null

**Date:** 2026-11-22
**Status:** Research note (additive). Follow-up to
`docs/research/RAG_ISOLATED_ABLATION_20261121.md`.
**Scope:** Re-runs the isolated mechanism-(1) A/B on a weaker backend to test
whether retrieval helps off the ceiling, then reads the actual findings to
separate genuine detection from a scoring artifact. No new benchmark claim, no
frozen evidence touched, no findings emitted. Raw data and scripts committed under
`docs/research/data/rag_isolated_ablation_20261121/`.

## Why

The 32B run found **no detectable recall effect** from EmbeddingRAG and argued the
likely reason was a ceiling: a strong model already encodes the canonical patterns.
The sharpest test of that explanation is to repeat the experiment with a model that
does **not** have them internalised. If retrieval matters anywhere, it should show
here.

## Design

Identical to the 32B run (same corpus, toggle, scorer, pairing, 3 runs/arm, cache
off), swapping only the backend: `qwen2.5-coder:7b` (digest `dae161e27b0e`).
384 calls, **all success, zero verificator timeouts** (the 7B is fast enough never
to hit the 180 s ceiling — a cleaner run than the 32B's 213/215 timeouts). Toggle
integrity total: `rag_enhanced=True`/5 hits on every ON call, `False`/0 on every
OFF call. git SHA `deea9b7d`.

## Headline numbers

| Backend | ΔRecall overall | McNemar p | Reading |
|---|---|---|---|
| **32B** | −3.2 pp | 0.625 | null, at ceiling |
| **7B** | **+10.9 pp** | **0.12** | positive, but **overall not significant** |

The overall 7B lift is **not** significant (p = 0.12). It is carried entirely by
one stratum:

| 7B by category | n | Recall ON | Recall OFF | Δ | McNemar p |
|---|---|---|---|---|---|
| reentrancy | 31 | 93.5 % | 100 % | **−6.5** | 0.50 |
| **access_control** | 18 | 72.2 % | 22.2 % | **+50.0** | **0.0117** |
| arithmetic | 15 | 93.3 % | 93.3 % | 0.0 | 1.0 |

So the cross-model picture confirms the *direction* of the ceiling hypothesis — RAG
is inert for the 32B and for the pattern a weak model already knows best
(reentrancy, where it is even slightly negative), and shows a large effect only for
a weak model on the less-canonical class (access_control). access_control's
p = 0.0117 survives Bonferroni correction across the three pre-registered categories
(0.0117 × 3 = 0.035 < 0.05).

**But the category-level scorer overstates what that +50 pp means, so we read the
findings before claiming it.**

## What the +50 pp actually is: attribution, not (only) detection

The scorer keys on SWC id / title text, so a contract counts as an access_control
hit only when the finding carries an access-control SWC. We dumped the actual
finding titles for all 11 discordant access_control contracts, both arms, pre- and
post-verificator (`rag_ab_probe_7b_20261122.json`). The OFF (no-RAG) arm is **rarely
silent** — it usually flags the same suspicious function but **misattributes the
mechanism**, most often to reentrancy (SWC-107), which the scorer does not credit as
access_control. Reading the 11:

- **~Half are a scoring/attribution artifact** — OFF names the real bug under a
  non-AC SWC:
  - `unprotected0`: OFF = *"Unprotected function to change contract owner"*
    (tagged SWC-107) — literally the bug, wrong SWC.
  - `multiowned_vulnerable`: OFF = *"Missing timelock for newOwner function"* —
    same issue as ON, wrong SWC.
  - `incorrect_constructor_name3`: OFF = *"Incorrect constructor name"* (SWC-118) —
    arguably **more precise** than ON, which homogenised it to "Unprotected Ether
    Withdrawal" (SWC-105).
  - `proxy`: both arms produce SWC-112 delegatecall — effectively tied on read.
- **~Half are genuine ON wins** — OFF diagnoses a different mechanism on a different
  line and would mislead an auditor:
  - `parity_wallet_bug_2`, `rubixi`, `wallet_02_refund_nosub`,
    `wallet_04_confused_sign`: OFF reports "reentrancy" / "integer underflow" and
    never flags the access-control flaw.

A side effect cuts **against** RAG: the ON arm collapses 8 of 11 titles to a single
canonical label, "SWC-105 Unprotected Ether Withdrawal", occasionally **less
specific** than the no-RAG label (as in `incorrect_constructor_name3`). RAG steers
the weak model toward the KB's dominant access-control entry — which is what lifts
the category score, and also what flattens the specific diagnosis.

## Honest conclusion

EmbeddingRAG's contribution is **conditional and mostly about vulnerability-class
attribution, not raw detection**:

1. **Conditional on model capability.** Null for the 32B (ceiling); material for the
   7B. Retrieval buys most where the model knows least.
2. **Conditional on class.** Even at 7B it does nothing for reentrancy (the model's
   strongest prior) and everything for access_control.
3. **Mostly attribution.** The headline +50 pp splits roughly in half: genuine
   mechanism correction on one side, a coarse-scorer SWC-labeling effect on the
   other. For a pre-audit triage tool, correct class attribution is useful (routing,
   dedup, report quality) — but this is **not** a "+50 pp more bugs found" result,
   and we do not state it as one.

This does not disturb the surrounding evidence: the 32B conclusion stands, the
committed **+28.6 pp precision** is a different mechanism (the `BenignContextVerifier`
grounding), and the shipped arena / SmartBugs / Rekt numbers (full pipeline,
retrieval on, strong models) are unaffected.

## Limitations (disclosed)

- **Single corpus, single adapter (`smartllm`), category-level scorer.** The
  attribution finding is itself evidence the coarse scorer is the wrong instrument
  for a recall claim here.
- **Effective n < 18.** The access_control set contains near-duplicate families
  (`wallet_0x…`, `incorrect_constructor_name*`, `parity_wallet_bug_*`), so the
  independent-contract count is below the nominal 18.
- **Determinism is within-process.** The 3 runs are identical replicates (0 flips),
  but the instrumented probe (a fresh process) landed closer on one or two borderline
  contracts (e.g. `proxy`), so there is minor cross-restart variability the triplets
  did not capture. Temperature/seed were the adapter defaults (not pinned).
- **KB / corpus overlap not verified.** SmartBugs contracts such as `rubixi` and
  `parity_wallet_bug_*` are well-known exploits that may have near-duplicates in the
  KB; the probe's hit-title capture returned empty, so overlap could not be confirmed
  and the claim is limited to *known* patterns. Confirming this is future work.
- **Overall 7B effect is not significant** (p = 0.12); only the access_control
  stratum is, and only under the pre-registered three-category correction.

## Provenance / reproduce

See `docs/research/data/rag_isolated_ablation_20261121/README.md`. Pinned: SHA
`deea9b7d`, models `b92d6a0bd47e` (32B) / `dae161e27b0e` (7B), embedding
`all-MiniLM-L6-v2`, KB `2026-11-15-chain-provenance-v5`.

## References (in-repo)

- `docs/research/RAG_ISOLATED_ABLATION_20261121.md` — the 32B null this follows up
- `docs/research/RAG_MECHANISMS_MEASUREMENT_MAP_20261120.md` — the three mechanisms
- `docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md` §11 — the +28.6pp precision (mechanism 2)
- `miesc/llm/embedding_rag.py`, `miesc/llm/rag_utils.py` — mechanism (1) and its toggle
