# Mutation Testing Guide

This guide explains how to use mutation testing to validate test quality in MIESC.

---

## What is Mutation Testing?

Mutation testing measures the effectiveness of your test suite by introducing small code changes (mutants) and checking if tests detect them.

**Key Concepts:**

| Term | Definition |
|------|------------|
| **Mutant** | A small code change (e.g., `+` → `-`, `>` → `>=`) |
| **Killed** | Test suite detected the mutant (test failed) |
| **Survived** | Test suite missed the mutant (tests still pass) |
| **Score** | Percentage of mutants killed |

**Why Use Mutation Testing?**

- Validates test quality beyond code coverage
- Identifies weak or missing test assertions
- Finds dead code that tests don't exercise
- Improves confidence in the test suite

---

## Quick Start

MIESC uses **mutmut 3.x** (pinned `mutmut>=3.6.0` in the dev dependencies).
Scope lives entirely in `pyproject.toml [tool.mutmut]`, so the Make targets take
no path arguments.

```bash
# Install with dev dependencies (brings in mutmut 3.6.0+)
pip install -e ".[dev]"

# Run the scoped mutation suite, then check the score against the gate
make mutate
make mutate-check
```

---

## Make Targets

| Target | Description |
|--------|-------------|
| `make mutate` | Run the scoped mutation suite (`mutmut run`), then print results |
| `make mutate-run` | Alias of `make mutate` (scope lives in pyproject) |
| `make mutate-quick` | Same scoped run, shorthand for local iteration |
| `make mutate-results` | Show the results summary (`mutmut results`) |
| `make mutate-show` | Show surviving mutants (tests failed to catch) |
| `make mutate-html` | Export machine-readable CI stats (`mutmut export-cicd-stats`) |
| `make mutate-check` | CI gate: parse stats JSON, fail if score < 60% |
| `make mutate-clean` | Remove the `mutants/` sandbox and cache |

> Scope is **not** passed on the command line. All targets run `mutmut run` and
> read the scope from `pyproject.toml [tool.mutmut]` (see below).

---

## Running Manually

### Full Analysis

```bash
# Run the scoped mutation suite (scope comes from pyproject.toml)
mutmut run

# View summary
mutmut results

# Example output (mutmut 3.x):
# core/baseline.py: 146/218 killed
# core/code_actions.py: 130/152 killed
# formal/unified_report.py: 6/6 killed
```

### Changing the Scope

Scope is defined in `pyproject.toml [tool.mutmut]`, not on the command line.
mutmut 3.x copies `source_paths` into a `mutants/` sandbox and mutates only the
files listed in `only_mutate`. To mutate a different module, edit those keys —
do not pass `--paths-to-mutate` (a mutmut 2.x flag that no longer exists).

### Viewing and Reviewing Mutants

```bash
# Show results / surviving mutants
mutmut results

# Interactive review of survivors (mutmut 3.x TUI)
mutmut browse
```

---

## Configuration

Mutation testing is configured in `pyproject.toml`. The current block scopes the
run to the v6 core modules that have dedicated mutation-grade tests:

```toml
[tool.mutmut]
# Copy the full package into the sandbox so imports resolve...
source_paths = ["miesc/"]
# ...but only mutate the v6 core modules that have dedicated tests.
only_mutate = [
    "miesc/core/baseline.py",
    "miesc/core/code_actions.py",
    "miesc/formal/unified_report.py",
]
# Scope the test run to the matching suites for fast, representative feedback.
pytest_add_cli_args_test_selection = [
    "tests/test_baseline.py",
    "tests/test_code_actions.py",
    "tests/test_unified_report.py",
]
pytest_add_cli_args = ["--no-cov", "-p", "no:cacheprovider"]
timeout_multiplier = 2.0
```

### Configuration Options (mutmut 3.x)

| Option | Description |
|--------|-------------|
| `source_paths` | Package(s) copied into the `mutants/` sandbox (must be the *whole* package so imports resolve) |
| `only_mutate` | The specific files that actually get mutated |
| `pytest_add_cli_args_test_selection` | Test files run against the mutants |
| `pytest_add_cli_args` | Extra pytest args (mutmut runs pytest **in-process**) |
| `timeout_multiplier` | Test timeout factor |

> **Why copy the whole package but only mutate a few files?** mutmut 3.x runs
> the tests from inside the `mutants/` sandbox. If `source_paths` pointed at just
> a handful of files, the sandbox would contain a *partial* `miesc` package and
> every import would fail. So we copy `miesc/` wholesale and narrow the actual
> mutation target with `only_mutate`.

> **Migrating from mutmut 2.x?** Several keys were renamed: `paths_to_mutate`
> → `source_paths`, `paths_to_exclude` → `do_not_mutate`. The `runner` key and
> `disable_mutation_types` were removed (pytest now runs in-process, and 3.x
> does not support disabling mutation types). See
> [../roadmap/MUTATION_STATUS_20260712.md](../roadmap/MUTATION_STATUS_20260712.md)
> for the full 2.x → 3.x migration notes.

---

## Mutation Types

mutmut applies various mutation operators:

| Type | Example | Description |
|------|---------|-------------|
| **Arithmetic** | `+` → `-` | Change operators |
| **Comparison** | `>` → `>=` | Boundary conditions |
| **Boolean** | `True` → `False` | Logic changes |
| **Return** | `return x` → `return None` | Return values |
| **Keyword** | `break` → `continue` | Control flow |
| **Number** | `0` → `1` | Constant values |

> **Note (mutmut 3.x):** unlike mutmut 2.x, the 3.x engine does not support
> `disable_mutation_types`. We control noise by narrowing *what* gets mutated via
> `only_mutate` rather than by disabling operator classes.

---

## Interpreting Results

### Score Bands

- **> 80%**: Excellent test coverage
- **60-80%**: Good, but room for improvement
- **< 60%**: Tests need strengthening (below the CI gate)

### Current Recorded Score

The current scoped run scores **75.0% (282/376 mutants killed)**, which clears
the 60% gate. Per-module breakdown:

| Module | Score |
|--------|-------|
| `miesc/core/baseline.py` | 67.0% |
| `miesc/core/code_actions.py` | 85.5% |
| `miesc/formal/unified_report.py` | 100.0% |

See [../roadmap/MUTATION_STATUS_20260712.md](../roadmap/MUTATION_STATUS_20260712.md)
for the full record, including the mutmut 2.x → 3.x toolchain fix that unblocked
these numbers.

### Surviving Mutants

Surviving mutants indicate potential test gaps:

```bash
# Review survivors
mutmut results   # summary
mutmut browse    # interactive TUI (mutmut 3.x)

# Illustrative mutant:
# miesc/core/baseline.py
# @@ def severity_score(self):
# -    return self.severity * 10
# +    return self.severity * 11
```

**Actions:**

1. Add a test that catches the mutation
2. Mark as equivalent mutant (rare)
3. Refactor code to be more testable

---

## CI Integration

### GitHub Actions

```yaml
- name: Install dev dependencies
  run: pip install -e ".[dev]"

- name: Run Mutation Testing
  run: make mutate

- name: Check Mutation Score
  run: make mutate-check
```

### Score Threshold

`make mutate-check` exports `mutants/mutmut-cicd-stats.json` and fails if the
score drops below 60%:

```bash
make mutate-check
# Mutation score: 75.0% (282/376 mutants killed)
# ✓ Mutation score check passed
```

---

## Performance Tips

- **Narrow the scope**: keep `only_mutate` in `pyproject.toml` pointed at the
  modules under active work — mutating fewer files is the main speed lever.
- **Scope the tests**: `pytest_add_cli_args_test_selection` runs only the
  matching suites against each mutant instead of the whole test set.
- **Resume after interruption**: mutmut caches progress, so re-running
  `mutmut run` (or `make mutate`) continues from where it stopped.
- **Reset from scratch**: `make mutate-clean` removes the `mutants/` sandbox and
  cache, then re-run `make mutate`.

---

## Best Practices

1. **Start Small**: Test core modules first
2. **Fix Survivors**: Address surviving mutants before adding new code
3. **Maintain Score**: Keep mutation score above threshold
4. **Regular Runs**: Include in PR review process (optional)
5. **Exclude Generated Code**: Don't mutate auto-generated files

---

## Troubleshooting

### "No mutations generated"

Check that the files listed in `only_mutate` exist and contain mutatable code:

```bash
ls -la miesc/core/*.py
```

### Imports fail inside the sandbox

If mutants error on `import miesc...`, make sure `source_paths` copies the
**whole** package (`["miesc/"]`), not just the target files — a partial package
in the `mutants/` sandbox breaks imports.

### Tests timeout

Increase the timeout multiplier:

```toml
[tool.mutmut]
timeout_multiplier = 3.0
```

### Cache / sandbox corruption

Clear the sandbox and restart:

```bash
make mutate-clean
make mutate
```

---

## References

- [mutmut Documentation](https://mutmut.readthedocs.io/)
- [Mutation Testing Theory](https://en.wikipedia.org/wiki/Mutation_testing)
- [MIESC Testing Guide](TESTING.md)
- [Mutation Testing Status (2026-07-12)](../roadmap/MUTATION_STATUS_20260712.md)

---

*Last updated: July 2026 (mutmut 3.x, single-package `miesc/`)*
