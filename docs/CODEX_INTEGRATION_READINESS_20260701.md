# Codex Integration Readiness - 2026-07-01

This note records the current `lane/codex` integration state after the
Fernando-authorized Paper 2 v-next baseline promotion. It is an operational
handoff for integrating the lane into `main`; it does not perform the merge or
push.

## Scope

Pending Codex work since current `main` is six local commits:

- `13e55f7 docs: promote post-spank paper2 candidate`
- `f7926f5 docs: add post-spank promotion audit`
- `9a7aa6f docs: triage post-spank reentrancy residuals`
- `2bc8d9a fix: close FiftyFlip wager reentrancy residual`
- `1eaa7b4 docs: audit post-FiftyFlip full evidence`
- `b4ffc1b paper2: promote post-spank vnext baseline`

The lane touches:

- `miesc/cli/commands/fix.py`
- `tests/test_fix_command.py`
- canonical Paper 2 artifacts under `benchmarks/results/fix_eval_results.json`
  and `benchmarks/results/paper2_*.json`
- additive dated Paper 2 evidence under `benchmarks/results/*20260630_codex*.json`
- Paper 2 frozen/public surfaces:
  `paper/paper2-remediation.tex`, `paper/paper2-remediation.pdf`,
  `paper/PAPER2_REPRODUCIBILITY.md`, `paper/ARXIV_SUBMISSION.md`
- public README metric summaries
- non-frozen planning/audit docs under `docs/`

No Paper 1 baseline artifact is changed by this lane.

## Validated State

Promoted canonical Paper 2 v-next totals:

| Metric | Value |
| --- | ---: |
| Corpus contracts | 143 |
| Fixes applied | 123/143 |
| Standalone compilation | 123/123 |
| Target finding eliminated by MIESC re-scan | 88/123 |
| Bounded no-regression | 121/123 |
| Scan-empty retries | 2 |
| External Slither checked | 123 |
| External Slither clean-HIGH | 70/123 |
| External residual HIGH findings | 53 |
| External Slither errors | 0 |

The promoted source is the post-Spank evidence:

- `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json`
- `benchmarks/results/fix_eval_full_external_slither_post_spank_details_20260630_codex.json`

The later FiftyFlip run is retained as additive evidence but is not the global
baseline because it improves one `reentrancy-eth` residual while lowering
`fix_applied`, `vuln_eliminated`, and `no_regression`.

## Validation Run

Already run on `lane/codex`:

```bash
SOURCE_DATE_EPOCH=1782957960 python3 benchmarks/audit_paper2_experiment.py
SOURCE_DATE_EPOCH=1782957960 python3 benchmarks/generate_paper2_artifacts.py
pdflatex paper2-remediation.tex
bibtex paper2-remediation
pdflatex paper2-remediation.tex
pdflatex paper2-remediation.tex
python3 -m pytest -q tests/test_generate_paper2_artifacts.py tests/test_fix_eval_cli.py
python3 -m ruff check benchmarks/audit_paper2_experiment.py benchmarks/generate_paper2_artifacts.py benchmarks/fix_eval.py tests/test_generate_paper2_artifacts.py tests/test_fix_eval_cli.py
git diff --check
PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
git merge-tree $(git merge-base main HEAD) main HEAD
```

Observed results:

- Paper 2 PDF rebuilt successfully: 8 pages.
- LaTeX produced only existing-style typography warnings (`Underfull` boxes);
  no undefined citations or unresolved labels remained after final pass.
- `9 passed` for focused artifact/fix-eval CLI tests.
- Ruff passed.
- `git diff --check` passed.
- Local paper reproducibility freeze validation passed after regenerating the
  local-only freeze manifest for the authorized v-next baseline.
- `git merge-tree` exited 0; no structural merge conflict was reported.

## Integration Risk

Mechanical conflict risk appears low for the tracked files in this lane. The
largest diff is additive dated JSON evidence plus regenerated Paper 2 canonical
JSON/PDF artifacts.

Main worktree risk is operational, not code-level: `/Users/fboiero/Documents/GitHub/MIESC`
currently has many untracked paper submission/build files under
`paper/digital-perspectives-2026/` and `paper/ribci-cyted-2026/`. Do not start
integration until those untracked files are intentionally kept, cleaned, or
stashed by their owner.

Scientific residuals after promotion:

- The baseline still has 53 external HIGH findings.
- Residual classes remain concentrated in semantic redesign areas:
  `controlled-array-length`, `weak-prng`, state shadowing, payout semantics,
  fallback/proxy delegatecall, and a small number of full-corpus
  `reentrancy-eth` findings.
- Do not claim full semantic equivalence or detector-independent closure. The
  paper now reports MIESC re-scan and external Slither clean-HIGH as separate
  metrics.

## Recommended Integration Steps

When Fernando authorizes merge/push:

1. Confirm `main` worktree untracked paper files are expected.
2. Claim `main integration from lane/codex` in `LANES.md`.
3. Merge from the integration worktree only:

   ```bash
   cd /Users/fboiero/Documents/GitHub/MIESC
   git merge --no-ff lane/codex
   ```

4. Re-run focused validation from `main`:

   ```bash
   SOURCE_DATE_EPOCH=1782957960 python3 benchmarks/audit_paper2_experiment.py
   SOURCE_DATE_EPOCH=1782957960 python3 benchmarks/generate_paper2_artifacts.py
   (cd paper && pdflatex paper2-remediation.tex && bibtex paper2-remediation && pdflatex paper2-remediation.tex && pdflatex paper2-remediation.tex)
   python3 -m pytest -q tests/test_generate_paper2_artifacts.py tests/test_fix_eval_cli.py tests/test_fix_command.py
   python3 -m ruff check benchmarks/audit_paper2_experiment.py benchmarks/generate_paper2_artifacts.py benchmarks/fix_eval.py miesc/cli/commands/fix.py tests/test_generate_paper2_artifacts.py tests/test_fix_eval_cli.py tests/test_fix_command.py
   git diff --check HEAD~1..HEAD
   PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
   ```

5. Push with conservative packing only after validation:

   ```bash
   git -c pack.threads=1 -c pack.windowMemory=32m -c pack.packSizeLimit=64m push origin main
   ```
