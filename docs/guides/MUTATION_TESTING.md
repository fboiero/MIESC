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

```bash
# Install mutmut
pip install mutmut

# Or install with dev dependencies
pip install -e ".[dev]"

# Run mutation testing (quick mode)
make mutate-quick

# View results
make mutate-results

# Generate HTML report
make mutate-html
```

---

## Make Targets

| Target | Description |
|--------|-------------|
| `make mutate` | Full mutation analysis (30-60 min) |
| `make mutate-quick` | Quick test on core modules only |
| `make mutate-results` | Show results summary |
| `make mutate-html` | Generate HTML report |
| `make mutate-show` | Show surviving mutant details |
| `make mutate-check` | CI check (fails if score < 60%) |
| `make mutate-clean` | Clean cache files |

---

## Running Manually

### Full Analysis

```bash
# Run all mutations
mutmut run

# View summary
mutmut results

# Example output:
# Legend for output:
# 🎉 Killed mutants: 142
# ⏰ Timeout: 3
# 🤔 Suspicious: 0
# 🙁 Survived: 18
# 🔇 Skipped: 5
```

### Targeting Specific Files

```bash
# Mutate specific module
mutmut run --paths-to-mutate src/core/

# Mutate single file
mutmut run --paths-to-mutate src/core/finding.py
```

### Viewing Mutants

```bash
# Show all surviving mutants
mutmut show all

# Show specific mutant by ID
mutmut show 42

# Apply mutant temporarily (for debugging)
mutmut apply 42

# Restore original code
mutmut apply 0
```

---

## Configuration

Mutation testing is configured in `pyproject.toml`:

```toml
[tool.mutmut]
# Paths to mutate
paths_to_mutate = "src/"

# Test runner command
runner = "python -m pytest tests/ -x --no-cov -q"

# Files to exclude
paths_to_exclude = [
    "src/*_tool.py",
    "src/miesc_*.py",
    # ... more exclusions
]

# Timeout multiplier
timeout_multiplier = 2.0

# Disabled mutation types
disable_mutation_types = [
    "string",
    "fstring",
    "annotation",
]
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `paths_to_mutate` | Source directories to mutate | Required |
| `runner` | Test command to run | `pytest` |
| `paths_to_exclude` | Files/dirs to skip | None |
| `timeout_multiplier` | Test timeout factor | 1.0 |
| `disable_mutation_types` | Skip certain mutation types | None |

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

### Disabled Types in MIESC

We disable some mutation types that often produce equivalent mutants:

- **string**: String literal changes rarely affect behavior
- **fstring**: F-string mutations often produce valid variants
- **annotation**: Type hints don't affect runtime

---

## Interpreting Results

### Good Score

- **> 80%**: Excellent test coverage
- **60-80%**: Good, but room for improvement
- **< 60%**: Tests need strengthening

### Surviving Mutants

Surviving mutants indicate potential test gaps:

```bash
# View surviving mutant
mutmut show 42

# Example output:
# --- src/core/finding.py
# +++ src/core/finding.py
# @@ -45,7 +45,7 @@
#  def severity_score(self):
# -    return self.severity * 10
# +    return self.severity * 11
```

**Actions:**

1. Add test that catches the mutation
2. Mark as equivalent mutant (rare)
3. Refactor code to be more testable

---

## CI Integration

### GitHub Actions

```yaml
- name: Run Mutation Testing
  run: |
    pip install mutmut
    mutmut run --paths-to-mutate src/core/ --CI

- name: Check Mutation Score
  run: make mutate-check
```

### Score Threshold

The `mutate-check` target enforces a 60% minimum score:

```bash
make mutate-check
# Mutation score: 75.5% (151/200 mutants killed)
# ✓ Mutation score check passed
```

---

## Performance Tips

### Speed Up Testing

```bash
# Use fewer cores
mutmut run --max-workers 2

# Quick feedback mode
mutmut run --paths-to-mutate src/core/ --CI

# Skip slow tests
mutmut run --runner "pytest tests/unit/ -x --no-cov -q"
```

### Incremental Testing

```bash
# Resume after interruption
mutmut run  # Continues from last mutant

# Reset and start fresh
rm -rf .mutmut-cache
mutmut run
```

### Cache Management

```bash
# View cache status
ls -la .mutmut-cache/

# Clear cache
make mutate-clean
```

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

Check that `paths_to_mutate` points to valid Python files:

```bash
ls -la src/core/*.py
```

### Tests timeout

Increase the timeout multiplier:

```toml
[tool.mutmut]
timeout_multiplier = 3.0
```

### Out of memory

Reduce parallelism:

```bash
mutmut run --max-workers 1
```

### Cache corruption

Clear and restart:

```bash
make mutate-clean
mutmut run
```

---

## References

- [mutmut Documentation](https://mutmut.readthedocs.io/)
- [Mutation Testing Theory](https://en.wikipedia.org/wiki/Mutation_testing)
- [MIESC Testing Guide](TESTING.md)

---

*Last updated: February 2026*
