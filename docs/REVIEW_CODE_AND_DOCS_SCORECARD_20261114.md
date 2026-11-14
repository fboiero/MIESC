# MIESC v6.8.0 — Code-Quality & Documentation Scorecard (dual reviewer lens)

Date: 2026-11-14
Reviewers simulated: (A) demanding open-source maintainer, (B) academic peer
reviewer (thesis/RIBCI-IEEE). Method: two independent read-only audits with real
tool runs (ruff/black/mypy) + a claims/evidence trace, cross-checked against a
first-hand code map. Every claim carries a `file:line` anchor. Nothing frozen was
modified.

> **This scorecard is an assessment, not a changeset.** It separates *fixable*
> (non-frozen) issues from *score-only* (frozen) ones. README, `paper/**` and
> `benchmarks/results/**` are frozen and were not touched.

## Executive synthesis

The one sentence a reviewer leaves with: **the frozen scholarly core is markedly
more honest than the non-frozen "marketing" surface, and the engineering is
stronger than its own CI proves.** Three independent gaps, all cheap to close:

1. **The research is defensible and unusually candid** (academic 8.0/10) — but its
   headline numbers are re-stated with less nuance in the README than in the paper.
2. **The engineering is well-typed and hygienic** (97/99% annotations, no
   `eval`/`shell=True`, 0 bare excepts) — but the **quality gates are declared and
   then disabled**, so the project looks more gated than it is.
3. **The capability is real but over-labelled** — "50 tools", "ML Detection",
   "Native multi-chain support", and a WebSocket server that claims MCP/Claude-
   Desktop compatibility it does not have.

## Scores

| Lens | Score | One-line verdict |
|---|---|---|
| **A. OSS maintainer — code** | **6.2 / 10** | Credible and far more tested than most research tooling; a tough maintainer requires the gates turned on and the god-modules/coupling addressed before depending on it. |
| **A. OSS maintainer — docs** | **7.0 / 10** | Reproducible quickstart and bilingual docs; pulled down by a self-contradiction, one overstatement, and version skew. |
| **B. Academic reviewer** | **8.0 / 10** | Would pass a thesis defense / RIBCI-IEEE review **with minor revisions**. |

### A-code sub-scores (0–10)
Architecture 5.5 · Code/typing 6.5 · Testing 6.5 · Tooling/hygiene 6.5 · Packaging 6.0.

### A-docs sub-scores
Install reproducibility 8.5 · Structure/bilingual 8.0 · Claims-vs-code accuracy 6.0 ·
Surface honesty 7.0 · Consistency/freshness 6.0.

### B (academic) sub-scores
Reproducibility infra 9.0 · Claims traceability/honesty 8.5 · Statistical rigor 6.5 ·
Benchmark validity/anti-circularity 7.0 · Limitations/threats 8.5 · Related-work honesty 8.0.

## What is genuinely strong (credit where due)

- **Reproducibility infrastructure is real**: `benchmarks/verify_paper_claims.py`
  recomputes each headline value from backing JSON and exits non-zero on mismatch;
  `miesc/core/provenance.py` records version + git SHA + per-tool versions + config
  hash + env + exact command line.
- **Honest dual estimates + null control** for EVMBench (optimistic union vs strict
  GPT-5 judge vs contract-agnostic null control); **limitations encoded as
  first-class claims** in the paper-2 matrix; **Cairo tautology self-disclosed**
  (`benchmarks/README.md:56`).
- **Security hygiene**: no `eval`, no `shell=True`, `pickle` gated by
  `security/safe_deserialize`, optional imports guarded, 0 bare excepts.
- **Type surface**: 97% return / 99% param annotations; 320 dataclasses.
- **Honest self-documentation**: `ERRATA` records the project's own frozen-artifact
  FP-count inconsistency (E-1).

## Fixable issues (non-frozen) — prioritized

| # | Issue | Sev | Evidence | Effort |
|---|---|---|---|---|
| F1 | Quality gates declared-but-off: strict mypy but CI `continue-on-error` with **66** live errors; bandit `--exit-zero` | S2 | `pyproject.toml:263`, `ci.yml:71,190` | M |
| F2 | Coverage split-brain: CI `--cov-fail-under=65` vs pyproject `fail_under=80`; omit list drops ~20% LOC incl. all `llm/*` (which *is* tested) | S2 | `ci.yml:116`, `pyproject.toml:288-453` | S |
| F3 | Dead pre-commit bandit hook scans deleted `src/` (silent no-op) | S2 | `.pre-commit-config.yaml:44` | S |
| F4 | `miesc_analyze_defi` calls non-existent tool key `"defi_analyzer"` (should be `"defi"`) → silently skipped | S2 | `mcp_server.py:352` vs `cli/constants.py:167` | S |
| F5 | `miesc_generate_report` reads only `["results"]`; empty for ML-audit dicts (`raw_findings`/`ml_enhanced`) | S2 | `mcp_server.py:604` | S |
| F6 | WebSocket server falsely claims MCP/Claude-Desktop compat + runs a **simulated** audit | S2 | `mcp_core/websocket_server.py:6,12,352` | S–M |
| F7 | Agentic LLM verifier bypasses sanitizer/validator and **fails open** to `confirmed:true` | S2 | `deep_audit_agent.py:1260` | M |
| F8 | README precision self-contradiction: calls the local qwen setup "best precision of any single model" (30.1%) while its own table shows GPT-5 42.7%, DeepSeek 88.5% | S2 | `README.md:168-179` | S |
| F9 | README "would have flagged 9 of 11 … **before deployment**" — they are attack-code reproductions, not pre-deploy victim contracts (corrected only at L699); linked `evaluate_exploits.py` is recompute-only (contracts not shipped) | S2 | `README.md:158,699` | S |
| F10 | "50 tools" round number (reality 35 = 13 ext + 22 int) across README, `MULTICHAIN`, and `mcp_server.py:831` | S2 | `CITATION.cff`, paper §II | S–M |
| F11 | `COMPARISON.md` "Native support" for Move/Cairo/Solana contradicts MULTICHAIN tiers; stale v5.3.0 | S2 | `COMPARISON.md:138` | S |
| F12 | Layer-6 `smartbugs_ml` labelled "ML Detection"/trained RF-SVM-NN; runtime is rule-based fallback (self-logged "approximate") | S2 | `smartbugs_ml_adapter.py:357-371` | S |
| F13 | `mcp_server.miesc_get_metrics` hardcodes 0.958/0.818/0.925 as literals while claiming "sourced from matrix" | S3 | `mcp_server.py:831-836` | S |
| F14 | Four god-modules >5.7K LOC (`agentic_contracts` 88 classes, `embedding_rag`, `reasoning_provider_adapter`, `vulnerability_rag`) | S2 | file sizes | M–L |
| F15 | Layer inversions `core→cli`, `security→cli` command; package import cycles | S2 | `core/orchestrator.py:19`, `security/remediation_pipeline.py:25` | M |
| F16 | Duplicated Solidity helpers (`_FUNCTION_RE`×8, `_match_brace`×3) despite `llm/_solidity_text.py` | S3 | listed | S |
| F17 | 347 `print()` in library (non-CLI) code; undeclared deps `z3`/`websockets` | S3 | rg; pyproject extras | S–M |

## Score-only issues (FROZEN — disclosure noted, require a new-baseline to touch)

| # | Issue | Disclosed? | Evidence |
|---|---|---|---|
| Z1 | README "50 tools" and headline numbers (same wording as F8–F10 but in the frozen README) | partial | `README.md` (frozen) |
| Z2 | Real-world exploit set n=11/25, Wilson CI [0.52,0.95] wide, attack-code not victims | yes (matrix note) | `paper1_claims_matrix.json` |
| Z3 | EVMBench 92.5% union/lenient-matcher headline vs 27.4% strict GPT-5 judge | yes (both-sided) | matrix, `README.md:694` |
| Z4 | Scorer `_normalize_category` substring/path category attribution — the one **unmitigated** validity threat to frozen per-category recall | partial (REPRODUCE/ERRATA) | `evaluate.py`, REPRODUCE waves |
| Z5 | 97.9% (140/143) attributed three ways without one reconciliation | partial | paper abstract vs matrix |
| Z6 | FP count 481/480/569 across artifacts | yes (ERRATA E-1) | `ERRATA.md` |

## Recommendations (sequenced, freeze-aware)

1. **Turn the gates on** (F1–F3): fix the 66 mypy errors, drop
   `continue-on-error`, align the coverage threshold, arm/clean bandit. Highest
   "declared quality = real quality" signal, no behaviour change.
2. **MCP correctness & honesty slice** (F4–F6, +F13): one PR, existing test
   harness, no frozen path. (See `docs/sdd/SDD_MCP_RAG_AGENTIC_SURFACING_20261114.md`.)
3. **Non-frozen doc truth-ups** (F11, F12): `COMPARISON.md` tiers, adapter
   labelling. Cheap, pure honesty gain.
4. **Agentic safety** (F7): sanitizer + validator + fail-closed.
5. **README truth-ups** (F8–F10) — **frozen; needs an explicit new-baseline
   decision.** These are the single highest credibility items but sit behind the
   freeze.
6. **Structural debt** (F14–F17): lift shared helpers, split one god-module as a
   proof of direction, break the `core/security → cli` inversions. Larger; stage
   after the above.
7. **Archival**: mint a Zenodo/software DOI for the artifact release (academic
   lens).

## Decisions this needs from the maintainer

- **README (frozen):** authorize a new-baseline to fix F8–F10/Z1, or keep
  score-only for now?
- **Execution order:** gates-first (F1–F3) vs MCP slice (F4–F6) vs doc truth-ups
  (F11–F12) vs the whitepaper/SVG surfacing work?
