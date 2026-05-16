# Evolution Control Plan - 2026-05-16

## Baseline

Current working tree baseline was validated before this plan:

- `git diff --check`: passed
- `make build-check`: passed against existing `dist/miesc-5.4.2` wheel and sdist
- Focused API/MCP/package tests: `68 passed, 4 skipped`
- `make quick-check`: `5988 passed, 6 skipped, 5 warnings`

This baseline is the checkpoint for the current evolution. New work should be
added only inside one package at a time and revalidated with the package gate.

## Package Order

### P0 - Release/OSS Packaging Boundary

Purpose: keep the public package clean and publication-ready.

Primary files:

- `pyproject.toml`
- `requirements.txt`
- `Makefile`
- `.gitignore`
- `scripts/check_distribution_contents.py`
- `tests/test_distribution_contents.py`
- deleted platform-only artifacts: `streamlit_app.py`,
  `docs/guides/STREAMLIT_CLOUD_DEPLOYMENT.md`,
  `docs/guides/STREAMLIT_DEPLOY_COWORK.md`

Gate:

```bash
git diff --check
python3 -m pytest tests/test_distribution_contents.py -q
make build-check
```

Acceptance rule: release artifacts must not include hosted/platform-only
components, test-only packages, duplicate artifacts, or platform metadata.

### P1 - Public API, CLI, and MCP Contract

Purpose: keep documented API and exposed commands aligned with implementation.

Primary files:

- `miesc/api/rest.py`
- `miesc/mcp_server.py`
- `miesc/cli/**`
- `miesc/core/**`
- `miesc/detectors/**`
- `miesc/plugins/manager.py`
- `docs/openapi.yaml`
- `tests/test_openapi_contract.py`
- `tests/test_rest_api.py`
- `tests/test_mcp_server.py`
- `tests/conftest.py`
- `src/core/optimized_orchestrator.py`
- `tests/test_core.py`

Gate:

```bash
python3 -m pytest \
  tests/test_openapi_contract.py \
  tests/test_rest_api.py \
  tests/test_mcp_server.py \
  tests/test_core.py::TestOptimizedOrchestratorCoverage::test_clear_cache \
  -q
```

Acceptance rule: every public OpenAPI path/method must map to an implemented
view, MCP tools must preserve their contract, and local caches must be
test-hermetic.

### P2 - Paper Reproducibility and Benchmark Claims

Purpose: preserve paper claims and make benchmark matrices reproducible.

Primary files:

- `benchmarks/complete_evaluation.py`
- `benchmarks/generate_paper1_artifacts.py`
- `benchmarks/generate_paper2_artifacts.py`
- `benchmarks/results/**`
- `paper/INSTRUCCIONES_RELEASE.md`
- `tests/test_generate_paper1_artifacts.py`
- `tests/test_generate_paper2_artifacts.py`
- `tests/test_ensemble_detector.py`

Gate:

```bash
python3 -m pytest \
  tests/test_generate_paper1_artifacts.py \
  tests/test_generate_paper2_artifacts.py \
  tests/test_ensemble_detector.py \
  -q
```

Acceptance rule: generated claim matrices must keep the supported claims stable
unless a paper/reproducibility note explains the change.

### P3 - Documentation, Evidence, Grants, and Examples

Purpose: update user-facing and archival material without hiding code changes.

Primary files:

- `README.md`
- `README_ES.md`
- `docs/**`, except files already owned by P0/P1/P2
- `examples/**`
- `grants/**`
- `CITATION.cff`

Gate:

```bash
git diff --check
python3 -m pytest tests/test_distribution_contents.py tests/test_openapi_contract.py -q
```

Optional gate when documentation tooling is available:

```bash
make docs-build
```

Acceptance rule: docs must match the package/API state and must not introduce
new claims without a source artifact or reproducibility note.

### P4 - CI, Docker, and Operational Packaging

Purpose: keep automation aligned with the release package and local developer
flow.

Primary files:

- `.github/**`
- `docker/**`
- `scripts/install.sh`
- `scripts/miesc-quick`
- `scripts/verify_installation.py`
- `scripts/run_complete_multilayer_audit.py`
- `scripts/run_full_audit.py`
- `scripts/capture_evidence.py`

Gate:

```bash
git diff --check
python3 -m pytest tests/test_distribution_contents.py tests/test_integration.py -q
```

Optional gate when Docker is available:

```bash
docker compose -f docker/docker-compose.yml config
```

Acceptance rule: CI and Docker changes must support the public package boundary
and must not reintroduce hosted/platform-only components into the OSS artifact.

## Iteration Rule

1. Pick one package.
2. Review only that package's diff.
3. Run its gate.
4. Record the gate result in the commit or handoff note.
5. Only then move to the next package.

## Current Recommendation

Close P0 and P1 first because they are the release-blocking packages and already
have green validation. Then handle P2 claims, and leave P3/P4 for last because
they are broad and easier to review once the package/API baseline is fixed.

## Gate Results - 2026-05-16

Executed after this plan was added:

- P0 required gate:
  - `git diff --check`: passed
  - `python3 -m pytest tests/test_distribution_contents.py -q`: 6 passed
  - `make build-check`: passed for existing wheel and sdist
- P1 required gate:
  - `python3 -m pytest tests/test_openapi_contract.py tests/test_rest_api.py tests/test_mcp_server.py tests/test_core.py::TestOptimizedOrchestratorCoverage::test_clear_cache -q`: 61 passed, 4 skipped
- P2 required gate:
  - `python3 -m pytest tests/test_generate_paper1_artifacts.py tests/test_generate_paper2_artifacts.py tests/test_ensemble_detector.py -q`: 55 passed
- P3 required gate:
  - `python3 -m pytest tests/test_distribution_contents.py tests/test_openapi_contract.py -q`: 8 passed
- P4 required gate:
  - `python3 -m pytest tests/test_distribution_contents.py tests/test_integration.py -q`: 26 passed
  - `docker compose -f docker/docker-compose.yml config`: passed

Optional documentation gate:

- `make docs-build`: not executable in this local environment because `make`
  cannot find `mkdocs` on its PATH.
- `/Users/fboiero/Library/Python/3.9/bin/mkdocs build -f docs/mkdocs.yml`: not
  executable because that script points to the missing interpreter
  `/Library/Developer/CommandLineTools/usr/bin/python3`.
- `python3 -m mkdocs build -f docs/mkdocs.yml`: not executable because the
  active Python 3.14 environment does not have `mkdocs` installed.
