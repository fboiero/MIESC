# Technical Debt Remediation Plan

This document tracks the technical-debt cleanup needed to align the whole MIESC
platform with the current Paper 1 and Paper 2 evidence.

## Goals

- Keep current research claims canonical and reproducible.
- Remove active-code drift between legacy 7-layer/v4.x modules and current
  9-layer/v5.4 platform behavior.
- Make remediation evidence a first-class platform workflow instead of a
  benchmark-only script.
- Keep historical thesis, release, and evidence documents available without
  letting them override current claims.

## Completed in This Pass

| Area | Debt | Remediation |
|------|------|-------------|
| CLI import | `python -m miesc.cli.main` emitted a runpy warning because `miesc.cli.__init__` eagerly imported `miesc.cli.main`. | Replaced eager import with lazy `__getattr__`. |
| Test config | `pytest --collect-only` failed via implicit coverage gate. | Removed global coverage from pytest `addopts`; coverage is now explicit. |
| Async tests | `asyncio_mode = auto` required pytest-asyncio but dev extras did not install it. | Added `pytest-asyncio` to `dev` extras and aligned pytest minimum. |
| Paper claims | README mixed current evidence with ambiguous “all layers” wording. | Added canonical research section and clarified Paper 1 vs Paper 2 scope. |
| Remediation workflow | Paper 2 evidence lived in benchmark scripts only. | Added `src.security.remediation_pipeline` and `miesc remediate`. |
| Active version drift | `miesc.core` hardcoded old versions and 7-layer narrative. | Switched active core modules to shared constants and package version. |
| API docs drift | REST API docstrings still described a 7-layer/29-tool audit. | Updated public API wording to configured multi-layer audit. |
| Benchmark duplication | `benchmarks/fix_eval.py` duplicated compile checks, fix application, re-scan, and failure taxonomy. | Reused the shared remediation pipeline for patch, compile, re-scan, and evidence fields. |
| API/MCP remediation | REST and MCP did not expose Paper 2 evidence bundles. | Added REST remediation endpoints and MCP fix/validation tools. |
| RAG source governance | Source tiers existed in code and Paper 1 notes, but reviewer-facing governance was split across files. | Added `docs/guides/RAG_SOURCE_POLICY.md` and linked it from README and Paper reproducibility docs. |
| Historical-doc ambiguity | Thesis and evidence folders preserve v4.x/v5.1 claims and 7-layer wording. | Added historical notes in `docs/README.md`, `docs/tesis/README.md`, and `docs/evidence/README.md`. |
| Core orchestration ambiguity | `miesc.core.orchestrator` used current layer metadata but still executed only direct legacy subprocess integrations. | Marked it as a compatibility orchestrator and added explicit supported/skipped tool metadata. |
| Optional dependency conflict | `miesc[symbolic]` pulled `mythril`, which conflicts with Flask/MarkupSafe and prevents combined installs. | Kept Mythril as an isolated/Docker tool and made the `symbolic` extra non-conflicting. |
| Local lockfile noise | `uv run` generated an untracked `uv.lock` in a pip-oriented project. | Ignored `uv.lock`; existing clean targets and `.gitignore` already cover Python caches, coverage, docs builds, and benchmark outputs. |
| API/MCP remediation examples | Remediation endpoints existed but reviewer-facing usage examples were missing. | Added `docs/guides/REMEDIATION_API_MCP.md` and linked it from README. |
| Paper 2 artifact regression | Claim generation lacked a focused test around the expected schema and Paper 1 compatibility rule. | Added `tests/test_generate_paper2_artifacts.py` with temporary output paths. |
| Generated/cache artifact hygiene | Local ignored artifacts were hard to inspect without a long `git status --ignored` dump. | Added `make local-artifacts`, `DETAIL=1 make local-artifacts`, and `make clean-local-artifacts`; documented the workflow in `docs/guides/REPOSITORY_HYGIENE.md`. |

## Remaining Debt

No active debt remains in this plan. New debt should be added here only when it
has a concrete owner, scope, and validation path.
