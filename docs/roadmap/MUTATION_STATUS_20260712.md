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
`baseline.py` was the weakest, with most survivors in `normalize_finding` /
`_normalize_path` — normalization edge cases the assertions at the time did
not pin down.

## 2026-08-13 update: baseline.py hardening

Re-ran with **mutmut 3.7.0** (newer patch release, more mutant variants
generated than 3.6.0's run above — the 376-mutant baseline above is not
directly comparable to the counts below).

Before adding targeted tests: **319 killed + 2 timeout / 455 total = 70.5%**,
with **104 of 134 survivors in `baseline.py`** — concentrated in exactly the
gap the note above called out: every existing test drove `normalize_finding`
through one dict shape (`location.file` / `location.function`), leaving
untested: the attribute-based (non-dict) `FindingLike` branch of `_get`,
every rule_id/message/file/symbol fallback key beyond the first, the
`"unknown"` default, empty-string-as-missing handling, and `_normalize_path`
edge cases (backslashes, absolute paths, dot segments).

`tests/test_baseline.py` gained targeted tests for each of those gaps (see
`TestAttributeBasedFindings`, `TestFieldFallbackKeys`,
`TestNormalizePathEdgeCases`, `TestPrivateNormalizationHelpers`). Result:
**415 killed + 2 timeout / 455 total = 91.6%**; `baseline.py` survivors
dropped from 104 to 16.

The remaining `baseline.py` survivors are, on inspection, genuinely
equivalent mutants: encoding-name casing (`"utf-8"` vs `"UTF-8"` — Python's
codec lookup is case-insensitive) and a mutated `if normalized.startswith("./")`
check whose effect is fully subsumed by the dot-segment filter two lines
later (`[p for p in normalized.split("/") if p not in ("", ".")]` strips a
leading `.` either way). Not worth chasing further.

## 2026-08-13 update: code_actions.py hardening + a scope bug

Same pass extended to `code_actions.py`. `_position_at`'s multiline branch
(`newlines > 0`) had no direct test asserting an exact `{line, character}`
result — the only test that exercised a multiline hunk
(`test_multi_line_insertion_range_and_newtext`) checked `newText` only, never
the range. `_common_suffix_len`'s three-way `min(len(a), len(b), cap)` bound
was never tested with mismatched-length inputs where dropping either
`len(a)` or `len(b)` changes the result. And no test replaced more than one
contiguous *original* line, the only case where `compute_text_edits`' silent
`"".join(...)` (vs any other separator) on the deleted-lines hunk is
observable. Added direct tests for all three, plus a `to_code_actions` case
with a no-op fix *followed by* a real one (the existing test only ever
passed a single no-op fix, so a `continue`→`break` mutation went undetected).

Separately, `unified_report.parse_assignments` showed 9 survivors despite
already having a solid dedicated suite
(`tests/test_counterexample_parse.py`) — that file was simply missing from
`[tool.mutmut] pytest_add_cli_args_test_selection`, so mutmut never ran it.
Fixed the scope list instead of writing tests that already existed. Doing so
surfaced one real gap the missing scope had been hiding: every test used a
lowercase-leading variable name, so a mutant narrowing the name regex from
`[A-Za-z_]` to `[a-z_]` survived; added one uppercase-leading-name test to
close it.

Combined result: **443 killed + 2 timeout / 455 total = 97.8%**, up from
70.5% before this round of hardening. The 10 remaining survivors are
equivalent mutants (encoding-name casing, the redundant `./`-strip above,
`_get`'s keyword-default removal — which falls back to the same default the
function already has — and `difflib.SequenceMatcher(autojunk=...)`, whose
effect only differs on inputs with 200+ lines including one repeated past a
1%-of-length threshold; not representative of this codebase's fix hunks).

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
