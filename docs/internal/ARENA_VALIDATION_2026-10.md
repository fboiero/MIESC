# MIESC — Arena Validation on SmartBugs-curated (product-level, additive)

**Date:** 2026-10-20
**Base:** `origin/main` @ `8f872577` (miesc 6.1.0), ARM64 macOS.
**What:** A fresh, **additive** experiment — run the real `miesc scan` **product**
(Slither + Aderyn + Solhint → dedup + intelligence engine + FP filter) against a
labeled subset of the SmartBugs-curated corpus and measure category-level recall
vs ground truth, to gauge how useful the tool is on comparable validation cases.

> **Not a paper benchmark.** This does not re-run or modify any frozen paper
> artifact (`benchmarks/results/*`, claims matrices, PDFs). It is a dated,
> additive probe written only to `docs/internal/`. All runs were **LLM-free**
> (`env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY`, no `--model`), so this measures
> the static+intelligence core, not the Layer-5/9 LLM layers. Numbers are from a
> small subset (28 contracts) and a keyword-based category matcher, so they are
> **indicative, not corpus-wide claims**.

## Method

- **Corpus:** `benchmarks/datasets/smartbugs-curated/dataset` — ground truth is the
  SmartBugs convention: each contract sits in its vulnerability-category directory.
- **Sample:** first 3 contracts per category (short_addresses has only 1) → **28 contracts** across 10 categories.
- **Tool:** `miesc scan <contract> -o out.json` (auto solc-select picked 0.4.x/0.5.x per pragma).
- **Scoring (reused from `benchmarks/run_benchmark.py` for comparability):**
  - *Lenient recall* — did the scan produce **any** finding on a known-vulnerable contract?
  - *Category recall* — did at least one finding's text match the expected category via the repo's `CATEGORY_MAPPING` keywords (a **strict lower bound**; see caveats).

## Results

| Category | n | Category recall | Lenient recall | Avg findings |
|----------|:-:|:---------------:|:--------------:|:------------:|
| reentrancy | 3 | **1.00** | 1.00 | 11.3 |
| bad_randomness | 3 | **1.00** | 1.00 | 13.7 |
| denial_of_service | 3 | **1.00** | 1.00 | 4.7 |
| front_running | 3 | **1.00** | 1.00 | 9.3 |
| time_manipulation | 3 | **1.00** | 1.00 | 10.0 |
| unchecked_low_level_calls | 3 | **1.00** | 1.00 | 19.7 |
| other | 3 | **1.00** | 1.00 | 13.0 |
| access_control | 3 | 0.33 | 1.00 | 10.0 |
| arithmetic | 3 | 0.33 | 1.00 | 9.3 |
| short_addresses | 1 | 0.00 | 1.00 | 3.0 |
| **Overall** | **28** | **0.82** | **1.00** | ~11 |

## Interpretation — how useful is it?

**Strong as a recall-first triage tool.** Lenient recall is **1.0**: on every known-
vulnerable contract the scan surfaced *something* (≈11 findings avg) — it never stays
silent on a vulnerable contract, which is exactly what a pre-audit triage pass needs.
Category-matched recall is **0.82** and is understated (see below).

**The two low scores are different stories:**

- **access_control (0.33) is mostly a matching artifact, not a real miss.** The
  "missed" `FibonacciBalance.sol` actually flagged `controlled-delegatecall`,
  `delegatecall_to_untrusted`, `arbitrary-send-eth`, `send-ether-no-checks` — all
  access-control-class issues — but the `CATEGORY_MAPPING` keywords
  (`owner`, `authorization`, `tx-origin`, `suicidal`) don't include "delegatecall"
  or "arbitrary-send", so the strict matcher scored it a miss. Real access-control
  recall on this subset is higher than 0.33.
- **arithmetic (0.33) is a genuine gap.** `BECToken.sol` (the historical
  `batchOverflow` integer overflow) produced 24 findings but **none** about integer
  overflow — the closest was `large-numeric-literal` (a lint hint). Slither/Aderyn
  don't detect integer overflow on legacy Solidity; that class is covered by
  **symbolic execution (Mythril/Manticore/Halmos)** — and on this ARM64 box Mythril
  and Manticore are **not installed** (see the E2E tool report). So the arithmetic
  gap here is a *tool-availability* gap, not an orchestration flaw.
- **short_addresses (0.00, n=1)** is expected: the short-address attack is a
  calldata/ABI-encoding issue that static source analysis essentially cannot see.
  Most tools in the literature score ~0 here.

## Takeaways

1. For the categories that static analysis can reach, the product is **reliable**
   (1.0 category recall on 7 of 10 categories) and **fast** (~1–2 s of tool time per
   contract after solc selection).
2. The real coverage gap on this setup is **integer overflow**, and it is explained
   by the missing symbolic-execution tools on ARM64 — a packaging/availability issue,
   not a detection-logic one. This is the natural place to ask whether the **LLM
   layers** (local Ollama, or frontier APIs) close that gap — the subject of the
   next step (paper review + an optimal local-vs-frontier comparison).
3. The keyword category-matcher is a **lower bound**; a fairer score would map
   detector names to categories (e.g. delegatecall → access_control). Worth improving
   in the benchmark harness if these numbers are ever reported.

## Reproduce

```bash
# LLM-free, outputs to a scratch dir outside the repo; frozen artifacts untouched.
python arena_eval.py benchmarks/datasets/smartbugs-curated/dataset $(command -v miesc) ./arena_out 3
# (arena_eval.py: runs `miesc scan` per contract, derives category from the dir,
#  matches findings with benchmarks/run_benchmark.py's CATEGORY_MAPPING.)
```

Raw per-contract outputs and `arena_summary.json` were kept in the session scratch
dir (not committed).
