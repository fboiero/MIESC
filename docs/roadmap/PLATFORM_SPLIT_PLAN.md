# MIESC Platform Split Plan

Target platform repository:

```text
git@gitlab.com:xcapit/miesc_platform.git
```

## Objective

Keep MIESC Core as the FOSS, reproducible research and developer tool. Move the
commercial platform and workflow layer to the GitLab platform repository without
changing or weakening the paper evidence.

## Migration Sequence

### 1. Freeze The Split Base

Record the core commit used as the split point before removing platform code.
This gives reviewers and developers a stable reference.

Recommended tag name:

```text
core-platform-split-base
```

### 2. Export Platform Candidates

Export or copy the platform-facing paths into `miesc_platform`:

```text
webapp/
.streamlit/
src/licensing/
src/dashboard/
src/utils/web_dashboard.py
src/utils/metrics_dashboard.py
vscode-extension/
```

The platform repository should then reorganize these into its own product
structure, for example:

```text
apps/web/
apps/vscode-extension/
platform/licensing/
platform/dashboards/
packages/miesc-platform/
```

### 3. Pin Core As A Platform Dependency

The platform should consume the public core through one pinned channel:

```text
miesc @ git+https://github.com/fboiero/MIESC.git@<release-tag>
```

or:

```text
ghcr.io/fboiero/miesc:<release-tag>
```

Avoid importing core through relative paths. That keeps the platform honest: it
uses the same released artifact that researchers can inspect.

### 4. Remove Platform Code From Core

Only after the platform repository builds, remove the moved product files from
the core and clean references in non-frozen documentation and packaging:

```text
webapp/
.streamlit/
src/licensing/
src/dashboard/
vscode-extension/
```

Then update:

```text
pyproject.toml
Makefile
requirements/
docs not tied to paper freeze
tests tied to moved modules
```

Do not edit paper source, paper PDFs, claim matrices, or frozen artifacts unless
the change is explicitly part of a paper revision.

### 5. Validate Core After Removal

Run the core checks that prove the public repository still stands alone:

```bash
uv run pytest
uv run python scripts/diagnose-adapters.py
uv run python scripts/run_paper1_claims.py --help
uv run python scripts/run_paper2_claims.py --help
```

If a paper script imports platform code, move only the minimal reproducibility
dependency back into core and document why.

### 6. Validate Platform Separately

Run the platform checks from the GitLab repository:

```bash
pip install -e .
npm install --prefix apps/vscode-extension
npm test --prefix apps/vscode-extension
streamlit run apps/web/app.py
```

The platform tests should prove integration with a pinned core version, not an
untracked local checkout.

## Acceptance Criteria

The split is complete when:

1. Paper 1 and Paper 2 reproduction paths run from the public core only.
2. The core has no imports from platform modules.
3. The platform can run against a pinned core release.
4. Licensing, dashboards, hosted workflow, and IDE product code live outside the
   public core.
5. Public documentation clearly states that platform workflow is a product layer
   over the reproducible core.

## Risks

| Risk | Mitigation |
| --- | --- |
| Moving dashboard code breaks report generation. | Keep static report/export code in core; move only product UI. |
| Platform starts depending on unreleased local core files. | Pin to release tags or image digests. |
| Paper claims become ambiguous. | Keep paper evidence and benchmark scripts in core and cite the core tag. |
| Packaging breaks after removing extras. | Remove platform extras in a dedicated commit and run the core test matrix. |
