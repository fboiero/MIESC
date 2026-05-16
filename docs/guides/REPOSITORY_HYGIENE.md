# Repository Hygiene

This guide defines what belongs in the MIESC repository and what should stay
local or be regenerated. The goal is to keep the project readable for
researchers, security engineers, and package users.

## Canonical Areas

| Area | Purpose | Keep in Git |
| --- | --- | --- |
| `miesc/` | Public Python package and CLI entry points | Yes |
| `src/` | Research engine, adapters, orchestration, and compatibility modules | Yes |
| `tests/` | Unit, regression, and integration tests | Yes |
| `benchmarks/` | Reproducible benchmark code, curated fixtures, and claim matrices | Yes, only curated inputs and selected final evidence |
| `paper/` | Paper sources, final PDFs, reproducibility notes, and source criteria | Yes, not LaTeX build outputs |
| `docs/guides/` | Current user and researcher guides | Yes |
| `docs/evidence/`, `docs/tesis/`, `docs/roadmap/` | Historical thesis, evidence, and planning archive | Yes, but treat as archive |

## Generated Or Local Artifacts

Do not commit:

- virtual environments: `.venv/`, `.venv-test/`, `venv*/`
- tool installations: `.tools/`
- local assistant/editor state: `.claude/`, `.vscode/`, `.idea/`
- Python/test caches: `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `.coverage*`
- package builds: `dist/`, `build/`, `*.egg-info/`
- LaTeX outputs: `paper/*.aux`, `paper/*.bbl`, `paper/*.blg`, `paper/*.log`, `paper/*.out`, `paper/*-arxiv.tar.gz`
- downloaded datasets and raw crawls under `data/datasets/*/_*/` or `data/datasets/*/contracts/`
- ad-hoc run outputs: `analysis/`, `reports/`, `evaluation_results/`
- local secrets: `apik.sh`, `.env`, `*.key`

## Benchmark Evidence Policy

Commit benchmark artifacts only when they support a documented claim or are
needed to reproduce a paper.

Preferred files:

- `benchmarks/results/paper1_claims_matrix.json`
- `benchmarks/results/paper2_claims_matrix.json`
- final paper-specific evaluation JSON/JSONL files referenced from
  `paper/PAPER*_REPRODUCIBILITY.md`
- small curated fixtures in `benchmarks/datasets/`

Avoid committing timestamped exploratory runs unless they are explicitly
referenced by a paper, release note, or reproducibility guide. If they matter,
add a short README explaining why they are canonical.

## Documentation Policy

Current documentation should be easy to find:

- users: `README.md`, `docs/guides/QUICKSTART.md`, `docs/guides/INSTALL.md`
- researchers: `docs/guides/RESEARCH.md`, `docs/guides/RESEARCHER_PACKAGING.md`, `paper/PAPER*_REPRODUCIBILITY.md`
- architecture: `docs/ARCHITECTURE.md`, `docs/architecture/`
- historical material: `docs/tesis/`, `docs/evidence/`, `docs/roadmap/`

New roadmap or investigation notes should either become an issue/ADR or live
under `docs/roadmap/` with a date and clear status.

## Release Checklist

Inspect ignored local artifacts without deleting them:

```bash
make local-artifacts
DETAIL=1 make local-artifacts
```

Clean local caches and generated outputs while preserving paper PDFs, paper
sources, and canonical benchmark evidence:

```bash
make clean-local-artifacts
```

Before committing:

```bash
git status --short
git diff --check
make build-check
uv run pytest tests/test_distribution_contents.py tests/test_doctor_command.py -q
```

`make build-check` validates package metadata and fails if release artifacts
include test-only files, duplicate files, or platform-only components such as
the hosted UI, licensing, dashboard, or IDE client code.

Before publishing:

```bash
make build
make build-check
./scripts/publish.sh
```
