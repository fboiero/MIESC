# MIESC Papers

This directory contains the current paper sources, final PDFs, reproducibility
notes, and reviewer-facing research documentation.

## Canonical Artifacts

| Artifact | Purpose |
| --- | --- |
| `miesc-paper.pdf` | Paper 1 final PDF |
| `miesc-paper.tex` | Paper 1 LaTeX source |
| `paper2-remediation.pdf` | Paper 2 final PDF |
| `paper2-remediation.tex` | Paper 2 LaTeX source |
| `references.bib` | Shared bibliography |
| `PAPER1_REPRODUCIBILITY.md` | Paper 1 evidence, commands, and claims |
| `PAPER2_REPRODUCIBILITY.md` | Paper 2 evidence, commands, and claims |
| `RAG_SOURCE_SELECTION_CRITERIA.md` | Reviewer-facing RAG source selection rationale |

## Related Evidence

Paper claims are backed by curated benchmark artifacts:

- `../benchmarks/results/paper1_claims_matrix.json`
- `../benchmarks/results/paper1_smartbugs_eval.json`
- `../benchmarks/results/paper1_smartbugs_eval.jsonl`
- `../benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json`
- `../benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.jsonl`
- `../benchmarks/results/paper1_smartbugs_full_all_layers_smoke_20260506.json`
- `../benchmarks/results/paper1_smartbugs_full_all_layers_smoke_20260506.jsonl`
- `../benchmarks/results/paper2_claims_matrix.json`
- `../benchmarks/results/paper2_compile_failure_by_category.json`
- `../benchmarks/results/paper2_compile_failure_taxonomy.json`
- `../benchmarks/results/paper2_experiment_audit.json`
- `../benchmarks/results/paper2_patch_quality_by_transform.json`

## Scope

Paper 1 evaluates detection and multi-layer smart contract security assessment.
Paper 2 starts from the same detection pipeline and evaluates remediation
artifacts, compile checks, re-scan, and bounded no-regression evidence. Paper 2
does not replace or invalidate Paper 1.

## Generated Files

Do not commit LaTeX build outputs or arXiv tarballs. Regenerate them locally
from the sources when needed.

Ignored examples:

- `*.aux`
- `*.bbl`
- `*.blg`
- `*.log`
- `*.out`
- `*-arxiv.tar.gz`

Build locally:

```bash
cd paper
make
```
