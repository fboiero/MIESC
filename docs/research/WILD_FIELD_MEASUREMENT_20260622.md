# Wild Field Measurement — Recall-Safety Failure & Fix (2026-06-22)

> Additive tool R&D. No frozen paper evidence is touched. This records the FIRST real-data
> (field) measurement of the recall-safe benign-context verifier (`--verify-fp`), the
> recall-safety violation it exposed, the root-cause diagnosis, and the evidence-driven fix.

## Setup — first field run without solc

- **Corpus:** fsalzano (real Ethereum contracts, manual human line-level labels), 60-contract
  subset of the adapted corpus.
- **Scanner:** `--scanner miesc` — MIESC's pure-python intelligence-engine detector
  (`detect_zero_recall_categories`). No Slither, **no solc** — this is what unblocked the
  field measurement on a box where solc-select is broken.
- **Ground truth:** the dataset's human labels, anchored by category + line.
  **Zero circularity** (labels are human, the scanner is independent of them).
- **Labeled set:** 252 findings over 60 contracts → **77 anchored** from ground truth:
  **21 REAL** (category+line match) + **56 FP** (on human-verified-clean contracts).
- **Verifier model:** `qwen2.5-coder:32b` (local Ollama).

## Results — three configurations on the SAME 77 findings

| Config | fp_dropped | recall (anchored) | real_lost | precision before→after |
|--------|-----------|-------------------|-----------|------------------------|
| Rule-only (floor) | 7/56 (12.5%) | **1.00** | **0** | 0.273 → 0.300 |
| **LLM-drop (pre-fix)** | 11/56 (19.6%) | **0.857** ❌ | **3** ❌ | 0.273 → 0.286 |
| LLM-advisory (post-fix) | 7/56 (12.5%) | **1.00** | **0** | 0.273 → 0.300 |

The LLM-drop config bought +7pp FP-drop **by losing 3 of 21 real vulnerabilities** — a
direct violation of the cardinal recall-safety invariant. The harness WARNING fired.

## Root cause — the LLM reasons real vulns away (not a line artifact)

Re-running the 21 real findings through the LLM verifier identified the 3 it dropped. The
detected lines sit EXACTLY on vulnerable code — this is a true verifier failure, not
detector/label line misalignment:

1. `lastContributor.send(this.balance);` — unchecked low-level send (return value ignored).
2. `owner.send(this.balance);` in `flush()` — the canonical unchecked-send vuln.
3. `if (crowdsaleClosed || now < start || ...) throw;` — timestamp dependence on a deadline.

The LLM judged each *benign* with defensible-sounding auditor reasoning ("send is to the
owner, low impact"; "timestamp for a deadline is acceptable"). That is the failure mode: the
LLM does not stay conservative — it actively argues findings away, and on real, complex code
it argues away real bugs. The controlled synthetic pairs (+28.6pp, recall 1.0) never exposed
this because they were clean mitigated-vs-unmitigated cases; **the field set did.**

## Fix — the LLM is advisory only (cannot drop)

`src/ml/benign_context_verifier.py::verify` was changed so the **only** drop path is the
deterministic, function-scoped **benign-pattern (rule) match**. An LLM "false_positive" now
yields `needs_review` (a FLAG for human triage) — it can never drop a finding. Locked by
`tests/test_benign_context_verifier.py::TestLLMNeverDrops` (3 tests).

**Net effect on the product:** `--verify-fp` keeps recall 1.0 on this field set (0/21 real
lost), drops at the rule-only rate (12.5% of FPs here), and surfaces LLM-suspected FPs as
flags rather than acting on them destructively. The LLM's role shifts from *auto-drop* to
*triage* — the honest, safe contract.

## Takeaways

- **Synthetic ≠ field.** A controlled +28.6pp/100%-recall number did not generalize; only the
  real-data run, anchored on human labels, revealed the recall failure. Measure where it counts.
- **Recall-safety must be structural, not prompted.** A "recall-safe" prompt was not
  recall-safe. Removing the LLM's authority to drop is structural and testable.
- **The pure-python scanner makes this reproducible anywhere** (no solc). Re-run:
  `wild_benign_context_eval.py collect <corpus> --scanner miesc --ground-truth <gt> -o w.jsonl`
  then `measure w.jsonl --verify-model qwen2.5-coder:32b`.

Artifact: `docs/research/wild_field_measurement_20260622.json` (all three configs).
Method & sources: [WILD_BENIGN_CONTEXT_EVAL_INSTRUCTIONS.md](WILD_BENIGN_CONTEXT_EVAL_INSTRUCTIONS.md) ·
[DATASET_SOURCE_CLASSIFICATION.md](DATASET_SOURCE_CLASSIFICATION.md).
