# Codex Integration Readiness - 2026-06-28

This note records the current `lane/codex` integration state after the Paper 2
fix-eval remediation loop. It is an operational handoff note, not a paper
baseline, and it does not overwrite frozen paper artifacts or canonical
benchmark outputs.

## Scope

Pending Codex work is focused on Paper 2 remediation and fix-eval harness
evidence:

- `miesc/cli/commands/fix.py`
- `benchmarks/fix_eval.py`
- `tests/test_fix_command.py`
- `tests/test_fix_eval_cli.py`
- additive dated JSON evidence under `benchmarks/results/`

`main` has advanced independently with 44 commits, mostly detection, triage, and
coverage work. `lane/codex` has 17 commits pending. The Codex diff against
`main` is additive for evidence artifacts plus focused remediation/harness
changes.

## Validated State

Latest Codex evidence checkpoint:

- Artifact: `benchmarks/results/fix_eval_full_external_slither_retry_20260628_codex_v8.json`
- Details: `benchmarks/results/fix_eval_full_external_slither_retry_details_20260628_codex_v8.json`
- Full corpus: 143 contracts.
- Fixes applied: 123.
- Fixed contracts compiling: 123/123.
- Vulnerabilities eliminated: 88.
- No-regression: 121/123.
- External Slither checked: 123.
- External clean HIGH: 67.
- External HIGH findings: 56.
- External errors: 0.
- Scan-empty retries: 2 total retries, with retry metadata recorded.

Focused validation run from `lane/codex`:

```bash
python3 -m pytest -q tests/test_fix_command.py tests/test_fix_eval_cli.py
python3 -m ruff check benchmarks/fix_eval.py miesc/cli/commands/fix.py tests/test_fix_command.py tests/test_fix_eval_cli.py
git diff --check main...lane/codex
git merge-tree $(git merge-base main lane/codex) main lane/codex
```

Observed results:

- `67 passed` for fix/fix-eval tests.
- Ruff passed.
- `git diff --check` passed.
- `git merge-tree` did not expose conflicts for the Codex-owned files.

## Integration Risk

Low mechanical conflict risk:

- `main` did not change the Codex integration files since the merge base:
  `benchmarks/fix_eval.py`, `miesc/cli/commands/fix.py`,
  `tests/test_fix_command.py`, `tests/test_fix_eval_cli.py`, or the new
  dated `benchmarks/results/fix_eval_*codex*.json` evidence files.
- Claude still has an active detection-lane claim in LANES. Do not edit
  `src/adapters/**`, `src/core/intelligence.py`, or detection benchmark work
  from this lane.

Paper/baseline risk:

- These commits add dated noncanonical evidence. They do not replace
  `benchmarks/results/fix_eval_results.json`.
- Do not treat v8 as a new paper baseline unless Fernando explicitly authorizes
  a frozen paper/baseline update.

Scientific residuals:

- `controlled-array-length`, `weak-prng`, and some `arbitrary-send-eth`
  findings are semantic redesign problems, not honest generic patcher targets.
- Further detector-silencing work should be avoided unless a contract-specific
  policy is available.

## Recommended Next Step

When Fernando authorizes integration:

1. Claim `main integration from lane/codex` in `LANES.md`.
2. Merge from the integration worktree only:

   ```bash
   cd /Users/fboiero/Documents/GitHub/MIESC
   git merge --no-ff lane/codex
   ```

3. Re-run focused validation from `main`:

   ```bash
   python3 -m pytest -q tests/test_fix_command.py tests/test_fix_eval_cli.py
   python3 -m ruff check benchmarks/fix_eval.py miesc/cli/commands/fix.py tests/test_fix_command.py tests/test_fix_eval_cli.py
   git diff --check HEAD~1..HEAD
   sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
   ```

4. Push with the conservative packing form only after validation:

   ```bash
   git -c pack.threads=1 -c pack.windowMemory=32m -c pack.packSizeLimit=64m push origin main
   ```

