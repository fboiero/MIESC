# Paper 2 v-next — finalization template (prepared 2026-06-21)

Equivalent of the Paper 1 baseline process, but Paper 2's new numbers DON'T EXIST YET —
they depend on Codex restoring the patcher. This is the process template + exact spots,
with placeholders for the numbers Codex will produce. ADDITIVE doc; does not modify frozen
`paper2-remediation.tex`.

## Pre-condition (Codex lane — must happen first)
1. Restore patcher self-contained (current code compiles only **28% (33/119)** vs the
   frozen paper's **64% (90/141)** — a regression; see `paper2_vnext_evidence_20260621.md`).
2. (Optional, the validity win) add independent verification (Slither/SMTChecker/Foundry on
   patched-that-compile) to replace the re-scan circularity.
3. Re-run full: `python3 benchmarks/fix_eval.py` (with rescan) → fresh
   `fix_eval_results.json` + derived artifacts.

## DECISION after the re-run — which path?

**Path A — Codex only RESTORES to ~frozen numbers (compile ≈64%, elim ≈66%, no-regr ≈65%):**
The frozen paper is already correct; the bug was code-only. → NO baseline change. Just
confirm fix_eval reproduces the frozen numbers, and the freeze stays valid. Done.

**Path B — Codex IMPROVES beyond frozen, or adds independent verification (changes the
metric meaning):** → new baseline (same process as Paper 1, below).

## Path B — exact `.tex` edits (`paper2-remediation.tex`)
Replace the frozen numbers (90/141=64% compile, 93/141=66% elim, 91/141=65% no-regr,
141/143=99% apply) at ALL these spots with Codex's new values:
- **L68 abstract**: "141/143 fix application, 90/141 standalone compilation, 93/141 ... elimination, 91/141 ... no-regression"
- **L103 contributions**: "99% fix application, 64% standalone compilation, 66% ... elimination, 65% ... no-regression"
- **L268–271 Table~\ref{tab:fix}**: the 4 rows (Fix applied / Compilation / Vuln eliminated / No-regression)
- **L277 text**: "141 receive ... (99%) ... 90 compile standalone (64%), 93 reduce ... (66%), 91 satisfy ... (65%)"
- **L288–293 Table~\ref{tab:fix-category}**: per-category rows + Total row "90 (64%) & 93 (66%) & 91 (65%)"
- **L298–302 text + experiment-validity audit**: per-category narrative, joint metrics
  (42/141 compile+elim, 30/141 compile+elim+no-regr), threshold sensitivity (64/91/139)
- **L416 End-to-End**: "applies fixes to 99% ... compiles 64% standalone, eliminates ... 66%, ... 65%"

If independent verification REPLACES re-scan (Path B with the validity win), these need
PROSE rewrites, not just numbers:
- **§Stage 2 Patch Quality** (L258), **Metric definitions** (L252): redefine "eliminated"
  via independent verification, not self re-scan.
- **§Limitations of Text-Level Patching** (L456) + **§Compilation Rate Analysis** (L468) +
  **§Failure Analysis** (L446): update to reflect the new patcher + verification.
- Kill/soften the re-scan-circularity threat (it's now resolved).

## Artifacts to regenerate (all in the freeze manifest)
benchmarks/results/: `fix_eval_results.json`, `paper2_compile_failure_by_category.json`,
`paper2_compile_failure_taxonomy.json`, `paper2_patch_quality_by_transform.json`,
`paper2_experiment_audit.json`, `paper2_claims_matrix.json`.
(fix_eval.py + the derived-summary scripts produce these.)

## Finalize the baseline (same as Paper 1)
```bash
cd /Users/fboiero/Documents/GitHub/MIESC
# on the paper2 baseline branch, AFTER .tex edits + artifact regen:
pdflatex -output-directory=paper paper/paper2-remediation.tex   # x2-3
m=.paper-freeze-local/PAPER_REPRODUCIBILITY_FREEZE.sha256
awk '{print $2}' "$m" | xargs shasum -a 256 > "$m.new" && mv "$m.new" "$m"
sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
git tag -a paper2-reproducibility-baseline-2026-06-21 -m "Paper 2 v-next: compile <NEW>%"
```
(PDF FIRST, then regen — same order rule as Paper 1. `.paper-freeze-local/` is gitignored.)

## Note
Most likely outcome is **Path A** (restore the regression) unless Codex also lands the
independent-verification validity win, which is the higher-value Path B. Either way the
honest move: report whatever fix_eval actually measures post-fix, not the frozen number.
