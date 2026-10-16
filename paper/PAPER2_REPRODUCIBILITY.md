# Paper 2 — Reproducibility (RIBCi–CYTED 2026 camera-ready)

Version: camera-ready, 2026-10-16.

This document maps the quantitative claims in Paper 2
(`paper/ribci-cyted-2026/paper2-camera-ready.tex`) on automated remediation to
the repository artifacts and commands that produce them. The shared checker
`python benchmarks/verify_paper_claims.py` recomputes the remediation figures
(123/143, 123/123, 88/123, 121/123, 70/123) from `paper2_claims_matrix.json`.
Discrepancies are recorded in `paper/ribci-cyted-2026/ERRATA.md` (see E-2 for the
pre/post HIGH-finding counts).

## Environment

Same toolchain as Paper 1 (see `PAPER1_REPRODUCIBILITY.md`): MIESC v5.4.1
(tag `09ef10f`), Slither 0.11.5 pinned, solc selected per `pragma` via
`solc-select`, Foundry 1.3.5. Generators honour `SOURCE_DATE_EPOCH`; the
camera-ready matrices were regenerated with `SOURCE_DATE_EPOCH` = 2026-10-16.
The remediation experiment adds standalone `solc` compilation of each patched
file and an external Slither validation pass.

## Artifact → claim → command

| Claim (paper value) | Artifact | Command |
|---|---|---|
| Fix applied 123/143 (86.0 %, current scan) | `fix_eval_results.json` | `python benchmarks/fix_eval.py --external-validator slither --scan-timeout 15 --scan-empty-retries 1 --results-output <json> --details-output <details>` |
| Standalone compilation 123/123 (100 %) | `fix_eval_results.json` | same run |
| Vulnerability eliminated (MIESC re-scan) 88/123 (71.5 %) | `fix_eval_results.json` | same run |
| Bounded no-regression 121/123 (98.4 %) | `fix_eval_results.json` | same run |
| External Slither clean-HIGH 70/123 (56.9 %) | `fix_eval_results.json` | same run (external validator) |
| Claims matrix + derived taxonomies | `paper2_claims_matrix.json`, `paper2_patch_quality_by_transform.json`, `paper2_compile_failure_by_category.json` | `SOURCE_DATE_EPOCH=2026-10-16 python benchmarks/generate_paper2_artifacts.py` |
| Original-vs-patched validity audit (142/143 orig, 123/143 patched, 123/142 conditional) | `paper2_experiment_audit.json` | `python benchmarks/audit_paper2_experiment.py` |
| Pre-patch Slither baseline (before/after HIGH checks) | `paper2_prepatch_slither_baseline.json` | `python benchmarks/paper2_prepatch_slither_baseline.py` |

The current-scan filter leaves 18 contracts with no HIGH/CRITICAL finding and 2
with empty scan output before fixes are applied, which is why 123 is the
patched-contract denominator for patch-quality metrics while 143 is the corpus
coverage denominator.

## Known limitations of the artifacts

- **Pre-/post-patch HIGH counts (ERRATA E-2).** The pre-patch baseline reproduces
  the paper's "before" total of 141 HIGH checks exactly, but the "after" total
  computes to 61 where the paper states 60 (a one-unit difference, analogous to
  E-1). The finer before/after figures in the paper (35→69 clean,
  reentrancy-eth 33→3, 28/29→0) are measured on a scope that does not reproduce
  from a single field of the baseline artifact and are pending author
  confirmation.
- **Parser failures.** A small number of contracts fail to parse/compile during
  the baseline and are recorded as such, not dropped; rates reflect only the
  successfully analyzed contracts.
- **No-regression is not semantic equivalence.** No-regression is measured as
  non-growth of the finding count under the same pipeline, allowing up to two
  additional informational findings from inline guard code. It shows the patch
  does not materially worsen the security-finding profile; it does not prove
  functional equivalence.
- **External validation is stricter than the MIESC re-scan.** 70/123 patched
  contracts are HIGH-clean under external Slither while 53 residual HIGH findings
  remain, concentrated in semantic classes that need contract invariants or
  protocol redesign. This is reported separately so the elimination claim is not
  inflated.
- **Standalone, not dependency-aware, compilation.** Patched files are compiled
  standalone, without restoring the original project dependency tree.

## Relationship to Paper 1

Paper 2 uses Paper 1 only as the detection stage and inherits, without
recomputing, the detection claims: SmartBugs 95.8 % recall / 22.2 % precision /
36.0 % F1, and EVMBench local ensemble 92.5 % (111/120). All Paper 2 evidence
concerns post-detection stages (fix application, compilation, re-scan, external
Slither validation).

## Editorial rule

A Paper 2 numeric claim is publishable only if it appears in
`benchmarks/results/paper2_claims_matrix.json` or derives explicitly from the
Paper 1 claims matrix. The superseded `141/90/93/91` baseline is referenced only
to explain the methodological change, never as a current figure.
