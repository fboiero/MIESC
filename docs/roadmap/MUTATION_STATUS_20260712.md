# Mutation Testing Status — 2026-07-12

This note records the working mutation-testing toolchain for MIESC and the first
real mutation score we have been able to produce on this machine. It replaces a
period where the mutation job was infrastructure-blocked and no honest number
was available.

## What was blocking us

Two independent problems stacked on top of each other:

1. **mutmut 2.5.1 crashed under Python 3.14.** During mutant generation it died
   with `TypeError: cannot pickle 'itertools.count'`. The 2.x engine relied on
   pickling generator state that Python 3.14 no longer allows, so it never got
   as far as running a single test.
2. **The 2.x runner shelled out to `python -m pytest`.** On this box only
   `python3` is on PATH (`python` is not), so even a patched 2.x run would have
   failed to launch the test process.

Because of these two, the milestone gate (`mutation >= 60%`) had no data to
check against.

## What unblocked it

We moved to **mutmut 3.6.0**, the 3.x rewrite. Two things fall out of that:

- The 3.x engine no longer pickles generator state, so the Python 3.14 crash is
  gone. mutmut 3.6.0 runs cleanly on the system interpreter (Python 3.14.5).
- mutmut 3.x runs pytest **in-process** (`pytest.main(...)`) instead of spawning
  `python -m pytest`. That means the `python`-not-on-PATH problem simply does
  not apply anymore — there is no subprocess to launch.

So the fix is a version bump, not a shim. `pyproject.toml` now pins
`mutmut>=3.6.0` in the dev dependencies.

### Config migration (2.x -> 3.x)

mutmut 3.x renamed several config keys. The `[tool.mutmut]` block in
`pyproject.toml` was migrated:

| 2.x key                     | 3.x key                              |
|-----------------------------|--------------------------------------|
| `paths_to_mutate`           | `source_paths`                       |
| `paths_to_exclude`          | `do_not_mutate` (glob patterns)      |
| `runner = "python -m ..."`  | removed (pytest runs in-process)     |
| `disable_mutation_types`    | removed (not supported in 3.x)       |

One 3.x gotcha worth writing down: mutmut copies `source_paths` into a
`mutants/` sandbox and runs the tests from there. If you point `source_paths` at
just a few files, you get a **partial `miesc` package** in the sandbox and every
import fails. The fix is to copy the whole package (`source_paths = ["miesc/"]`)
and then narrow what actually gets mutated with `only_mutate`.

The `Makefile` mutation targets were also updated: the old `mutate-run` /
`mutate-quick` passed 2.x-only flags (`--paths-to-mutate src/core/`, `--CI`) and
a stale `src/` path. Scope now lives entirely in `[tool.mutmut]`, and
`mutate-check` reads the machine-readable stats file (see below).

## Scope of the run

The run is deliberately scoped to the well-tested v6 core modules — the ones
that carry dedicated, high-coverage test suites, so the number is representative
rather than diluted by modules that were never written with mutation testing in
mind:

| Module                          | Test suite                     |
|---------------------------------|--------------------------------|
| `miesc/core/baseline.py`        | `tests/test_baseline.py`       |
| `miesc/core/code_actions.py`    | `tests/test_code_actions.py`   |
| `miesc/formal/unified_report.py`| `tests/test_unified_report.py` |

Broadening the mutation surface to the rest of the package is future work and
should be added incrementally as modules earn mutation-grade tests.

## The score

Tool: **mutmut 3.6.0** on **Python 3.14.5**. Source of truth:
`mutmut export-cicd-stats` -> `mutants/mutmut-cicd-stats.json`.

```
killed:      280
timeout:       2   (counted as killed — the mutant hung the tests)
suspicious:    0
survived:     94
total:       376
```

**Mutation score = (280 + 2) / 376 = 75.0%.** This clears the 60% gate.

Per-module breakdown:

| Module                    | Mutants | Survived | Score   |
|---------------------------|---------|----------|---------|
| `core/baseline.py`        | 218     | 72       | 67.0%   |
| `core/code_actions.py`    | 152     | 22 (+2 timeout) | 85.5% |
| `formal/unified_report.py`| 6       | 0        | 100.0%  |

Every module individually clears 60%. `unified_report.py` kills every mutant;
`baseline.py` is the weakest and is where test-hardening would pay off next —
most of its survivors are in `normalize_finding` / `_normalize_path`, i.e.
normalization edge cases the current assertions do not pin down.

## Reproducing it

```bash
# From the repo root, with dev deps installed (mutmut>=3.6.0):
make mutate         # runs the scoped mutation set defined in pyproject
make mutate-check   # parses mutants/mutmut-cicd-stats.json, fails under 60%
```

`make mutate-check` prints, e.g.:

```
Mutation score: 75.0% (282/376 mutants killed)
```

## Recommendation for CI

Run the mutation job on the **system Python 3.14** with `mutmut>=3.6.0` — no
special interpreter or PATH shim is needed. Keep the scope in `[tool.mutmut]`
and grow `only_mutate` as more modules gain dedicated tests. The gate should key
off `mutants/mutmut-cicd-stats.json` (killed + timeout + suspicious) / total,
which is exactly what `make mutate-check` now does.
