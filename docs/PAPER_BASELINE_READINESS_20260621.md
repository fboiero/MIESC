# Paper Baseline Readiness - 2026-06-21

This is an operational checkpoint for applying a future Paper 1 / Paper 2
baseline. It is not a paper artifact and does not change frozen `.tex`, PDFs,
claim matrices, or canonical benchmark outputs.

## Current State

- Code baseline is applied to `origin/main` at `2e60661`.
- Frozen paper artifacts remain unchanged after the code baseline merge.
- `sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh` passes.
- The untracked integration-worktree file `paper/PAPERS_VNEXT_PLAN_20260620.md`
  was preserved and was not committed.

## Paper 1 Readiness

Paper 1 has v-next evidence prepared by the detection lane:

- Evidence: `paper/paper1_vnext_evidence_20260621.md`
- Proposed edit plan: `paper/paper1_vnext_tex_proposal_20260621.md`
- Reported v-next result: 99.3% recall (142/143), precision 0.264.

Status: ready for a Fernando-gated paper baseline decision. Applying it means
editing frozen paper files and regenerating the freeze manifest.

## Paper 2 Readiness

Paper 2 remediation evidence from the Codex lane is additive and non-canonical:

- Full dry run: `benchmarks/results/fix_eval_full_dry_20260621_codex.json`
- Full dry details: `benchmarks/results/fix_eval_full_dry_details_20260621_codex.json`
- Compile-only reconciliation:
  `benchmarks/results/paper2_vnext_compile_summary_20260621_codex.json`

Current Paper 2 v-next evidence:

- Corpus: 143 contracts.
- Compile-only run: 122 fixes applied, 122/122 compiled, 0 fix failures.
- Full dry run: 121 fixes applied, 121/121 compiled, 77 vulnerabilities eliminated,
  118/121 no-regression, 0 fix failures.
- The earlier 33/119 compile-regression claim did not reproduce in `lane/codex`.
- The remaining no-regression uncertainty is scan/rescan instability, with extra
  delta evidence recorded in
  `benchmarks/results/fix_eval_unchecked_regression_probe_20260621_codex.json`.

Status: code is ready for discussion, but Paper 2 should not be baselined until
Fernando explicitly decides whether the current full-dry evidence is strong
enough or whether to run one more full verification pass.

## Safe Baseline Procedure

Use this sequence if Fernando explicitly authorizes a new paper baseline:

1. Create a dedicated baseline branch from `main`.
2. Apply only the approved `.tex` / metadata edits.
3. Regenerate the affected PDFs and any canonical claim artifacts.
4. Run the paper freeze validation.
5. Update `.paper-freeze-local/PAPER_REPRODUCIBILITY_FREEZE.sha256`.
6. Commit the paper baseline separately from code changes.
7. Tag the baseline with a dated paper-specific tag.

Do not mix a paper baseline commit with LLM/provider/runtime code changes.

## Next Recommended Loop

Before touching frozen paper files, run one of these non-FROZEN checks:

- Paper 2 full dry verification with explicit dated outputs.
- Paper 2 external-tool validation on patched contracts that compile.
- Paper 1 detection-lane handoff review, if Claude has completed the active
  detection claim.

