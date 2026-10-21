# MIESC — Value-Proposition Improvement Plan (evidence-driven)

**Date:** 2026-10-21
**Basis:** empirical findings from the 2026-10 new-user E2E pass and the arena /
EVMBench validation runs (`docs/internal/TOOL_E2E_TEST_2026-10.md`,
`ARENA_VALIDATION_2026-10.md`, `EVMBENCH_FRONTIER_RUN_2026-10.md`).

> Complementary to `PAPER_LEARNINGS_PLATFORM_ALIGNMENT.md` (which focuses on the
> remediation pipeline / Paper 2 alignment). This plan targets the **trust and
> "does it actually help?"** axis of the value proposition, which the validation
> data exposed. Each item is tied to a measured observation, not opinion.

## Value proposition under test

"50 security tools, 9 layers, one command — recall-first pre-audit triage, free and
local." The data says the **recall** half of that promise is strong; the **trust**
half (precision, reliability, honest coverage) is where the gaps are.

## Prioritized improvements

### P1 — Tame false-positive flooding on the LLM layer *(highest leverage)*
- **Evidence:** EVMBench, local qwen32b, same 10 audits: **55 findings, 48 false
  positives → 12.7% precision** (vs GPT-5 78.9%). The RAG+ML FP filter is not taming
  LLM-layer noise.
- **Why it matters:** a triage tool that emits ~7 false alarms per real finding
  erodes trust and sends users back to Slither-alone. Precision is the trust half of
  "recall-first triage."
- **Proposed:** confirm the FP filter actually scores LLM-sourced findings (not just
  static detectors); add LLM-finding confidence calibration (agreement with static
  layers, RAG support, self-consistency across runs); optionally gate low-confidence
  LLM findings into a `needs_review` bucket instead of HIGH/CRITICAL.
- **Impact:** high · **Effort:** medium.

### P2 — Make LLM output parsing reliable *(recall you silently lose today)*
- **Evidence:** 5 of 10 local responses still failed to parse in the EVMBench run even
  after the json-repair fallback (#174) and #182's llm-json-extraction. Parse failure
  → 0 findings → silent recall loss (original E2E finding (g)).
- **Proposed:** request structured output natively — OpenAI/Anthropic JSON/tool-call
  mode, Ollama `format: json` / grammar-constrained decoding — so the model returns
  valid JSON instead of prose that the parser must repair. Keep json-repair as the
  last-resort net.
- **Impact:** high · **Effort:** medium.

### P3 — Close the arithmetic / symbolic-execution coverage gap on ARM64
- **Evidence:** arena — `BECToken.sol` (batchOverflow) produced 24 findings, **none
  about integer overflow**. Slither/Aderyn don't cover it; Mythril/Manticore are
  **absent on ARM64** (E2E tool report).
- **Proposed:** route arithmetic/overflow detection to **Halmos + SMTChecker**, both
  of which ARE available on ARM64, instead of depending on Mythril; surface a clear
  "arithmetic coverage requires a symbolic tool" note when none is usable.
- **Impact:** medium (coverage credibility) · **Effort:** medium.

### P4 — Put honest, reproducible value messaging up front *(DPG credibility)*
- **Evidence:** repeated doc drift (tool counts, stale `src/`, versions) and a lenient
  benchmark matcher that inflates recall. The honest free-vs-paid picture we measured
  belongs in the value proposition, not buried.
- **Proposed:** a single "What you actually get" table — static-only vs local vs
  frontier vs ensemble, with **both recall and precision** and cost/audit — sourced
  from the claims matrices, plus the standing "historical docs may carry old metrics"
  note.
- **Impact:** medium · **Effort:** low.

### P5 — Fast, working LLM layer by default
- **Evidence:** `--model ollama` defaults to the slow 32B model; quick scans should
  feel instant. Finding (g) / the Ollama docs reconciliation (#173).
- **Proposed:** default the quick-scan LLM path to `qwen2.5-coder:14b`; keep 32B for
  `audit full` / explicit opt-in. (Behavioral — maintainer call; flagged in #173.)
- **Impact:** low-medium · **Effort:** low.

### P6 — Honest benchmark matcher
- **Evidence:** keyword matcher inflates recall (arena access_control 0.33 was a
  matcher artifact; EVMBench null control credits 50%).
- **Proposed:** a detector-name → category map (e.g. `controlled-delegatecall` →
  access_control) replacing substring keyword matching, so reported recall is
  trustworthy for research/DPG.
- **Impact:** low (internal/credibility) · **Effort:** low-medium.

## Already in flight (do not duplicate)

As of 2026-10-21, sibling work already covers P1/P2:
- **P1** (LLM finding trust/confidence): branches `feat/trust-the-findings` (merged as
  #180 — grouping, rule classes, status vocabulary) and
  `fix/hallucination-confidence-coerce`; a "require-tool-corroboration" effort is active.
- **P2** (LLM parsing): #182 / `feat/llm-json-extraction` made json-repair a **core**
  dependency and routed every LLM adapter through one shared JSON extractor.
- Precision on static detectors: #172 (short_addresses/front_running, 20.5%→22.4%).

Root cause we confirmed for P1: `miesc/ml/fp_filter.py` is a **recall-safe benign-pattern
dropper** — it only removes findings that match known-benign patterns. LLM
over-generated findings don't match any benign pattern, so they pass straight through
(hence 48 FP). The fix is corroboration-based confidence for LLM findings, which is
exactly what the sibling branches target — so this session does **not** touch P1/P2.

## Phased plan

| Phase | Items | Owner | Outcome |
|-------|-------|-------|---------|
| 1 | P1 + P2 | sibling sessions (in flight) | Free/local experience stops being noisy and lossy. |
| 2 (this session) | **P3** | here | Arithmetic coverage on Apple Silicon without Mythril. |
| 3 | P4 + P5 + P6 | open | Honest, fast, credible surface and benchmarks. |

## Phase 2 kick-off (P3) — arithmetic via Halmos/SMTChecker

Before wiring anything, measure the opportunity:
1. Run **Halmos** and **SMTChecker** on `BECToken.sol` (the batchOverflow the static
   stack missed) and confirm whether either detects the integer overflow.
2. If yes, wire arithmetic/overflow routing so the available symbolic tool runs on
   Apple Silicon when Mythril/Manticore are absent, and surface a clear coverage note
   when none is usable.
3. Re-check the arena arithmetic category with the symbolic tool enabled.

## Non-goals / guardrails
- No changes to frozen paper artifacts; any benchmark re-runs are additive and dated.
- Behavioral defaults (P5, the 32B→14B flip) are maintainer decisions, proposed not
  imposed.
