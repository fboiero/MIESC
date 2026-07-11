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
| Optional dependency conflict | `miesc[symbolic]` pulled `mythril`, which conflicts with Slither's dependency set and prevents combined installs. | Kept Mythril as an isolated/Docker tool and made the `symbolic` extra non-conflicting. |
| Local lockfile noise | `uv run` generated an untracked `uv.lock` in a pip-oriented project. | Ignored `uv.lock`; existing clean targets and `.gitignore` already cover Python caches, coverage, docs builds, and benchmark outputs. |
| API/MCP remediation examples | Remediation endpoints existed but reviewer-facing usage examples were missing. | Added `docs/guides/REMEDIATION_API_MCP.md` and linked it from README. |
| Paper 2 artifact regression | Claim generation lacked a focused test around the expected schema and Paper 1 compatibility rule. | Added `tests/test_generate_paper2_artifacts.py` with temporary output paths. |
| Generated/cache artifact hygiene | Local ignored artifacts were hard to inspect without a long `git status --ignored` dump. | Added `make local-artifacts`, `DETAIL=1 make local-artifacts`, and `make clean-local-artifacts`; documented the workflow in `docs/guides/REPOSITORY_HYGIENE.md`. |
| CI gate ambiguity | The CI workflow used `continue-on-error` without a clear release policy, especially around type checking. | Documented blocking vs advisory gates in `docs/policies/RELEASE_VERIFICATION.md` and made the mypy step explicitly advisory in CI summaries. |
| Marketplace advisory checks | The marketplace workflow treated PyPI availability as non-blocking without explaining the policy. | Renamed the step as advisory, added a GitHub summary, and documented marketplace availability in the CI gate policy. |
| Platform split guardrails | The split plan said the core must not import platform modules, but the rule was only manually checked. | Added a regression test that scans core source for imports from platform-only modules, and linked it from the split acceptance criteria. |

## Remaining Debt

### Layer-taxonomy split between the CLI and the config (open)

The 9-layer defense stack is defined **twice, incompatibly**, in active code:

- `miesc/cli/constants.py` (drives `miesc audit --layer N` and the CLI output)
  groups layers 5–9 as: **L5 AI Analysis · L6 ML Detection · L7 Specialized
  Analysis · L8 Cross-Chain & ZK Security · L9 Advanced AI Ensemble**, with real
  adapters per layer (e.g. L8 = `crosschain, zk_circuit, bridge_monitor,
  l2_validator, circom_analyzer`).
- `miesc/data/config/miesc.yaml` (and the README/public docs) groups layers 5–9
  as: **L5 AI/LLM Analysis · L6 Pattern Detection · L7 DeFi Security · L8 Exploit
  Validation · L9 Consensus & Reporting**.

These are not a wording difference; they are two different *tool groupings* of
real adapters. The CLI has a Cross-Chain/ZK layer the README scheme does not
mention; the README scheme has an Exploit-Validation layer the CLI grouping does
not surface as a layer.

**Impact:** public docs cannot be made consistent without either lying about what
the CLI does or misrepresenting the config. Documentation of the layer names was
therefore intentionally left untouched pending this decision.

**Decision (resolved):** the canonical taxonomy is **`miesc/cli/constants.py`** —
it is what the shipping CLI entry point (`miesc.cli.main:cli`) and the REST API
execute, every one of its per-layer adapters exists, and `tests/test_rest_api.py`
already asserts its names ("ML Detection", "Specialized Analysis"). The canonical
L1–L9 are: Static Analysis · Dynamic Testing · Symbolic Execution · Formal
Verification · AI Analysis · ML Detection · Specialized Analysis · Cross-Chain & ZK
Security · Advanced AI Ensemble.

**Done:** README "9 Defense Layers" block and `mcp_server.py` docstring aligned to
`constants.py`.

**Remaining (scoped refactor, not a doc edit):** `miesc/data/config/miesc.yaml`
still encodes the divergent legacy scheme (Pattern Detection / DeFi Security /
Exploit Validation / Consensus & Reporting) read only by the compatibility
orchestrator in `src/core`. Its layer *keys* (`ai_analysis`, `pattern_detection`,
`exploit_validation`, …) are referenced by name in ~19 Python files, so migrating
it must update those references and their tests together — it is a code refactor
with test coverage, deliberately not done as a blind config edit. Also pending:
the layer tables in `docs/index*.md`, `docs/ARCHITECTURE*.md`, and `docs/TOOLS.md`.

**Validation path:** after the refactor, `constants.py`, `miesc.yaml`, the REST API
`/layers` response, and the README "9 Defense Layers" block must all print the same
L1–L9 names, and the full test suite must stay green.
