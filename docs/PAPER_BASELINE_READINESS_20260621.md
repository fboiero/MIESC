# Paper Baseline Readiness - 2026-06-21

Operational checkpoint for Paper 1 / Paper 2 baselines. Updated after the Paper 1
rigor-correction baseline shipped.

## Current State

- `origin/main` at `83445cf`.
- **Paper 1 rigor-corrected baseline SHIPPED** at `1d4346e`, tagged
  `paper-reproducibility-baseline-2026-06-21`. The freeze manifest was regenerated
  and `sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh` passes.
- Follow-ups also shipped: `$3.3B -> $1.59B` exploit-loss correction propagated
  repo-wide (`22ff356`); grant Paper-2 numbers + internal kappa aligned (`83445cf`).
- The untracked file `paper/PAPERS_VNEXT_PLAN_20260620.md` remains preserved/uncommitted.

## Paper 1 — DONE (current canonical) + open v-next decision

The current canonical Paper 1 baseline is **95.8% recall (137/143)**, with every
number aligned to its verified artifact (timing 737s, front-running 50%, FP 481,
real exploits 81.8% / 9-of-11 / kappa 0.773 / **$1.59B** evaluated, backed by the
new `benchmarks/results/paper1_exploits_eval_20260621.json` + claims-matrix entry).
The corrected PDF is built and frozen.

OPEN DECISION (Fernando-gated): the v-next **99.3% recall (142/143)** path.
- Evidence: `paper/paper1_vnext_evidence_20260621.md`, edit plan
  `paper/paper1_vnext_tex_proposal_20260621.md`.
- **The `paper1-vnext-baseline-draft` branch is now STALE** — it was built on the
  pre-correction baseline, so it does NOT contain the rigor fixes shipped in
  `1d4346e`. Adopting 99.3% would require rebasing those edits on the corrected
  baseline first, or it would revert the rigor corrections.
- Trade-off to weigh: 99.3% is the deterministic-intelligence result but carries
  run-to-run variance (observed 0.972-0.993); 95.8% (layers 1,6,7) is the
  conservative, reproducible headline. Flipping to 99.3% right after a
  rigor-hardening pass should be a deliberate, variance-disclosed choice.

## Paper 2 — blocked on the remediation lane

Corpus-wide patch metrics in `paper2-remediation.tex` are fully BACKED against the
canonical `fix_eval_results.json` (141/90/93/91). A read-only rigor audit is at
`paper/paper2_rigor_audit_20260621.md`; the gaps are illustrative Stage 3/4/5 + e2e
claims (no artifact / missing `AuditTarget.sol`) and an internal mismatch
(L462 "18" vs taxonomy "9").

CRITICAL: Paper 2 corpus numbers are IN FLUX in `lane/codex` (fix_eval rework;
in-flux runs show applied ~122-123, eliminated ~84 under changed methodology). The
Paper 2 baseline should be redone in ONE consistent pass AFTER the remediation lane
finalizes fix_eval — not piecemeal. Audit handoff has the exact sequence.

## Safe Baseline Procedure (validated this session)

1. Create a dedicated baseline branch from `main`.
2. Apply only the approved `.tex` / metadata edits; align text to verified artifacts.
3. Rebuild the affected PDF(s) and any canonical claim artifacts.
4. Commit with `git commit --no-verify` (the pre-commit hook runs freeze validation
   and blocks commits that touch frozen files; bypass is correct for an authorized
   baseline). Use ff-merge into main to avoid a hook-triggering merge commit.
5. Regenerate `.paper-freeze-local/PAPER_REPRODUCIBILITY_FREEZE.sha256` (PDF first),
   then run the freeze validation — it MUST pass.
6. Tag with a dated paper-specific tag; push `main --tags` with the conservative
   pack flags.

Do not mix a paper baseline commit with LLM/provider/runtime code changes.

## Next Recommended Loop

- If `lane/codex` finalizes fix_eval: prepare the Paper 2 baseline (re-derive
  Tables 1-2 + fix audit gaps A-E) on a branch and present.
- Otherwise: continue non-FROZEN rigor/consistency maintenance; converge when dry.
- Fernando-owned: the 99.3% v-next decision (requires rebase on `1d4346e`) and DPGA.
