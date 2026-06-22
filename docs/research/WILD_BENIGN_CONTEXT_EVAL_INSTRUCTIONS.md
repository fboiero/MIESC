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

A labeled corpus. Recommended: **SmartBugs-curated** (143 contracts with line-level
ground truth) — same corpus the papers use, so the field number is comparable in spirit.
Fetch it with the dataset builder (clones to `benchmarks/datasets/smartbugs-curated`,
where both the paper eval and this harness look):

```bash
python benchmarks/build_datasets.py --smartbugs
```

> **Labeled vs unlabeled corpora.** Only labeled corpora (SmartBugs-curated,
> SolidiFI-benchmark) support the hybrid anchor below. Unlabeled "wild" corpora
> (SmartBugs-wild ~47K real contracts, DeFiHackLabs) have no per-finding/line ground
> truth, so every label would fall to the LLM judge — reintroducing the circularity the
> anchor exists to avoid. More contracts is not more rigor; the rigor is in the labels.

### More labeled corpora via adapters

Two other **line-level, non-tool-derived** datasets can feed the anchor through
`scripts/dataset_adapters.py`, which converts each into the same `vulnerabilities.json`
format plus a flat `.sol` corpus (unique basenames — the harness keys by basename):

```bash
# fsalzano — REAL contracts, MANUAL human line-level labels, taxonomy matches ours,
# AND 604 human-verified CLEAN contracts (true negatives, anchored as FP, no LLM).
git clone https://github.com/fsalzano/Empirical-Analysis-of-Vulnerability-Detection-Tools-for-Solidity-Smart-Contracts fsalzano
python3 scripts/dataset_adapters.py fsalzano fsalzano \
  --out-corpus fsalzano_corpus --out-gt fsalzano_gt.json

# SolidiFI — injected bugs with exact location logs (line ranges). solc 0.4–0.5.
git clone https://github.com/DependableSystemsLab/SolidiFI-benchmark solidifi
python3 scripts/dataset_adapters.py solidifi solidifi \
  --out-corpus solidifi_corpus --out-gt solidifi_gt.json

# DAppSCAN — real audit reports, SWC line-level (lineNumber field). solc 0.4–0.8.
git clone https://github.com/InPlusLab/DAppSCAN dappscan
python3 scripts/dataset_adapters.py dappscan dappscan \
  --out-corpus dappscan_corpus --out-gt dappscan_gt.json

# then run the eval on the adapted corpus + ground truth:
python3 scripts/wild_benign_context_eval.py collect fsalzano_corpus \
  --ground-truth fsalzano_gt.json -o wild_findings.jsonl
```

Or fetch all four usable corpora at once (gitignored local copies):
`python benchmarks/build_datasets.py --labeled`. The full rationale for which sources are
usable and why is in [DATASET_SOURCE_CLASSIFICATION.md](DATASET_SOURCE_CLASSIFICATION.md).

### Code4rena (highest quality — via scraper, needs authenticated `gh`)

Competitive human-audit findings with exact file+line locations. No clone of the audited
repos — referenced files are fetched at their pinned SHA via raw.githubusercontent:

```bash
python3 scripts/code4rena_scraper.py contests | grep 2023        # list findings repos
python3 scripts/code4rena_scraper.py scrape 2023-05-ajna-findings --out c4.jsonl
python3 scripts/code4rena_scraper.py build c4.jsonl --out-corpus c4_corpus --out-gt c4_gt.json
python3 scripts/wild_benign_context_eval.py collect c4_corpus --ground-truth c4_gt.json -o wild.jsonl
```

Category is keyword-mapped from free-text titles (noisy); unmapped findings get `other` and
won't anchor — recall-safe. Only High/Med findings are kept.

`fsalzano` is the highest-value source: real contracts, human (not tool) labels, a
taxonomy that already matches the verifier's, and a built-in true-negative set. Its clean
contracts are anchored `label=False` with `label_source=ground_truth_clean` — any finding
on a human-verified-clean contract is a true FP, measured without any LLM.

> **DIVE is intentionally excluded.** 22,330 contracts, but labels are contract-level only
> (no line/function) and tool-derived (6-tool vote) — unusable for per-finding anchoring
> and circular for evaluating a tool-finding verifier. Volume ≠ rigor.

## Phase 1 — collect (run the real scanner + anchor ground truth)

```bash
python3 scripts/wild_benign_context_eval.py collect /path/to/smartbugs-curated \
  --ground-truth /path/to/smartbugs-curated/vulnerabilities.json \
  -o wild_findings.jsonl --max 200
```

Per `.sol`: picks the highest installed solc matching the pragma minor (`solc-select use`),
runs `slither --json`, and emits one JSONL record per finding
(`{contract, check, type, function, line, severity, code, label, label_source}`).

**`--ground-truth` is the hybrid anchor (recommended).** It loads the dataset's own
`vulnerabilities.json` (the same loader the paper eval uses, `benchmarks/smartbugs_evaluation.py:102`)
and, for every finding that matches an annotated vuln by **category + line (± 2)**, sets
`label = True`, `label_source = "ground_truth"`. That is the **recall-critical** label —
the one that defines "did the verifier drop a real vuln?" — fixed by the dataset, **with no
LLM and no circularity**. Only **non-annotated** findings come out `label = null` and need a
benign-vs-real decision in Phase 2.

> The anchor is deliberately conservative: when a category is annotated but lines are
> absent, it labels the finding real. That can only *under*-credit the verifier, never
> inflate it — keeping the precision number honest.

It also writes `wild_findings_TO_LABEL.csv` with the anchored labels pre-filled, so the
human only labels the blanks.

> Contracts that don't compile (missing solc, syntax) are **skipped and reported**, not
> silently dropped. Watch the skip count — a high count means a solc version is missing.

## Phase 2 — label (the ground truth)

`label = True` → a **real, unmitigated** vulnerability (verifier must KEEP it).
`label = False` → a **benign-context false positive**: the contract mitigates *this exact*
finding (verifier may DROP it).

With Phase 1's `--ground-truth`, the `True` (real) labels are already anchored — you are
**only** deciding, for the remaining non-annotated findings, whether each is benign-context
or a real *secondary* issue the dataset didn't annotate. Lower stakes, and LLM noise here
cannot violate recall-safety (the anchored reals already guard that). Two ways:

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
| `anchored_recall` | recall on **ground-truth-anchored** reals — the circularity-free headline; **MUST be 1.0** |
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
