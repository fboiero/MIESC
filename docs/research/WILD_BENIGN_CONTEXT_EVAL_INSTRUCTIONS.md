# Wild Benign-Context Evaluation — Field-Number Instructions

> **Purpose.** Produce the *field* measurement of the recall-safe verifier
> (`src/ml/benign_context_verifier.py`, `--verify-fp`): real scanner output on real
> contracts, with benign-context ground-truth labels. This is the number the research
> doc (`AGENTIC_RAG_QUALITY_LOOPS_20260621.md`) lists as environment-blocked on the
> dev box — solc-select is broken here, so Slither cannot compile the legacy corpus.
> Run this **in the paper's reproduction environment**, where solc-select works.
>
> **What this is NOT.** Not a paper claim. This is additive tool R&D. The papers stay
> frozen. The output (`benchmarks/results/wild_benign_context_measurement.json`) is a
> new dated artifact, never a replacement for a canonical claims matrix.

## Why a separate harness

The in-repo measurements so far use the *right thermometer* (benign-context: mitigated
vs unmitigated of the **same** vuln type) but on **synthetic** paired contracts (n=35).
That gives **+28.6pp precision at 100% recall** — honest, but synthetic.

The wild version closes the loop: take whatever a **real scanner (Slither)** flags on
**real contracts**, label each finding as *real* vs *benign-context FP*, then measure how
much the verifier lifts precision **without dropping a single real vuln**. Same recall-safe
invariant, real-world inputs.

The hard part is **labeling** — deciding, per finding, whether the contract actually
mitigates it. That is the bottleneck, and why this needs a human (or at least a careful
independent judge), not just a script.

## Prerequisites (repro env)

```bash
# Working solc-select with the legacy patches the corpus needs
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.26
slither --version          # must run
ollama list                # qwen2.5-coder:32b present (verifier + optional judge)
# OR: export DEEPSEEK_API_KEY=...  (failover for both verifier and judge)
```

A corpus of real `.sol` files. Recommended: **SmartBugs-curated** (143 contracts, the
standard) — same corpus the papers use, so the field number is comparable in spirit.

## Phase 1 — collect (run the real scanner)

```bash
python3 scripts/wild_benign_context_eval.py collect /path/to/smartbugs-curated \
  -o wild_findings.jsonl --max 200
```

Per `.sol`: picks the highest installed solc matching the pragma minor (`solc-select use`),
runs `slither --json`, and emits one JSONL record per finding
(`{contract, check, type, function, line, severity, code, label:null}`). It also writes
`wild_findings_TO_LABEL.csv` — the human-labeling sheet.

> Contracts that don't compile (missing solc, syntax) are **skipped and reported**, not
> silently dropped. Watch the skip count — a high count means a solc version is missing.

## Phase 2 — label (the ground truth)

`label = True` → a **real, unmitigated** vulnerability (verifier must KEEP it).
`label = False` → a **benign-context false positive**: the contract mitigates *this exact*
finding (verifier may DROP it).

Two ways:

### (a) Authoritative — by hand
Open `wild_findings_TO_LABEL.csv`, fill the last column per row, then merge the labels
back into the JSONL (write `label` true/false per record). This is the definitive number;
~50–100 findings is tractable in one sitting and is what you'd cite.

### (b) Fast — independent judge model
```bash
python3 scripts/wild_benign_context_eval.py label wild_findings.jsonl \
  -o wild_labeled.jsonl --judge-model qwen2.5-coder:32b
```
An independent prompt asks a *strict* auditor whether each finding is real or mitigated.

> **Semi-circularity caveat.** Judge and verifier are both LLMs. If they share a model,
> agreement is partly self-fulfilling. Mitigations: use a **different/stronger** model for
> the judge than for `--verify-model`, and **hand-verify a random sample** of the judge's
> labels before trusting the headline. State the caveat wherever the number appears.

## Phase 3 — measure (the lift)

```bash
python3 scripts/wild_benign_context_eval.py measure wild_labeled.jsonl \
  --verify-model qwen2.5-coder:32b
# rule-only floor (no LLM): omit --verify-model
```

Runs `BenignContextVerifier.verify()` on each labeled finding and reports:

| Metric | Meaning |
|---|---|
| `fp_drop_rate` | benign-context FPs the verifier dropped (the win) |
| `recall_retained` | real vulns kept ÷ real vulns — **MUST be 1.0** |
| `real_lost` | real vulns dropped — **MUST be 0**; non-zero = recall-safety violated |
| `precision_before` / `precision_after` | precision lift (the field number) |

Writes `benchmarks/results/wild_benign_context_measurement.json`.

**Acceptance gate:** if `real_lost > 0`, the run prints a WARNING and the precision number
is **not** trustworthy — investigate (usually a benign pattern over-matching) before
citing anything. Recall-safety is the cardinal invariant; precision is secondary.

## Recommended protocol for a citable number

1. `collect` on SmartBugs-curated.
2. Hand-label a random 80–100 findings (method a) → authoritative set.
3. `measure` with `--verify-model qwen2.5-coder:32b` (32b required; 14b lost vulns).
4. Confirm `recall_retained == 1.0`. Report `precision_before → precision_after`.
5. Append the result + the labeling method (hand vs judge, sample size) to
   `AGENTIC_RAG_QUALITY_LOOPS_20260621.md` as a new dated section. Keep the synthetic
   +28.6pp number alongside it — they answer different questions (controlled vs field).
