# MIESC Tool Diagnostic Report

**Date**: 2026-05-12
**Version**: 5.4.2
**Target**: local full researcher workstation

---

## Executive Summary

The current local full workstation profile validates all configured tool adapters.

| Target | Pass Rate | Available | Failed | Config Error |
|--------|-----------|-----------|--------|--------------|
| Local full workstation | 100.0% | 50/50 | 0 | 0 |

Validation command:

```bash
OLLAMA_HOST=http://127.0.0.1:11434 uv run python scripts/diagnose-adapters.py
```

Expected summary:

```text
Total adapters checked:  50
Available:               50
Not installed:           0
Configuration error:     0
License required:        0
Pass rate: 100.0%
```

---

## Environment Assumptions

The 50/50 result is a full workstation target, not a minimal PyPI install. It assumes:

- MIESC is installed in the repository `.venv`.
- Heavy tools are installed in isolated `.tools/` environments where needed.
- Ollama is reachable over HTTP through `OLLAMA_HOST`.
- Solidity compiler resolution can find a working `solc` binary.
- Optional licensed tools are installed locally and activated only when credentials are present.

Ignored local files and directories:

| Path | Purpose |
|------|---------|
| `.venv/` | Main local Python environment |
| `.tools/` | Isolated heavyweight tool environments |
| `apik.sh` | Optional local API keys or licensed-tool credentials |
| `diagnostic-report.json` | Generated diagnostic output |
| `.paper-freeze-local/` | Local reproducibility freeze checks |

These files are intentionally not part of the public repository state.

---

## Corrected Issues

### Semgrep launcher

The adapter now prefers `.tools/semgrep/bin/pysemgrep` when present. This avoids a native Semgrep launcher failure observed on macOS where the executable could fail before startup while creating a system certificate authenticator.

Validation:

```bash
uv run python -c "from src.adapters.semgrep_adapter import SemgrepAdapter; a=SemgrepAdapter(); print(a.semgrep_bin); print(a.is_available().name)"
```

Expected:

```text
.tools/semgrep/bin/pysemgrep
AVAILABLE
```

### SMTChecker `solc` resolution

The SMTChecker adapter now selects a working `solc` binary instead of trusting the first executable found on `PATH`. This handles stale shims such as `/usr/local/bin/solc` when a working package-manager binary exists elsewhere.

Validation:

```bash
uv run python -c "from src.adapters.smtchecker_adapter import SMTCheckerAdapter; a=SMTCheckerAdapter(); print(a._solc_cmd); print(a.is_available().name)"
```

Expected:

```text
/opt/homebrew/bin/solc
AVAILABLE
```

### Diagnostic script registry compatibility

`scripts/diagnose-adapters.py` now reads the current registry shape and counts every category, including specialized categories such as gas optimization, MEV detection, audit readiness, and advanced AI ensemble adapters.

---

## Layer-by-Layer Result

| Layer | Result |
|-------|--------|
| Layer 1 - Static Analysis | 6/6 |
| Layer 2 - Dynamic Testing / Fuzzing | 7/7 |
| Layer 3 - Symbolic Execution | 5/5 |
| Layer 4 - Formal Verification | 7/7 |
| Layer 5 - AI Analysis | 12/12 |
| Layer 6 - ML Detection | 1/1 |
| Layer 7 - Specialized Analysis | 1/1 |
| Layer 8 - Cross-Chain & ZK | 3/3 |
| Other categories | 8/8 |

Total: 50/50.

---

## Verification Commands

Use these commands from the repository root.

```bash
git status --short --branch
OLLAMA_HOST=http://127.0.0.1:11434 uv run python scripts/diagnose-adapters.py
uv run ruff check scripts/diagnose-adapters.py src/adapters/semgrep_adapter.py src/adapters/smtchecker_adapter.py tests/test_semgrep_adapter.py tests/test_adapters.py
uv run black --check scripts/diagnose-adapters.py src/adapters/semgrep_adapter.py src/adapters/smtchecker_adapter.py tests/test_semgrep_adapter.py tests/test_adapters.py
uv run pytest tests/test_semgrep_adapter.py tests/test_adapters.py -q
```

Last local verification:

```text
430 passed
```

The latest pushed commit also completed the GitHub workflows successfully:

- MIESC CI/CD Pipeline
- Research Evaluation
- Docker Build and Publish
- Documentation
- MIESC Security Audit
- OpenSSF Scorecard

---

## Docker and External Review

For external reviewers, prefer the published Docker image:

```bash
docker pull ghcr.io/fboiero/miesc:full
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:full \
  python /app/scripts/diagnose-adapters.py
```

Docker and local workstation diagnostics can differ because Docker images intentionally avoid baking local credentials and may use different CPU architecture constraints. For workstation parity with all local tools, use:

```bash
scripts/bootstrap_researcher_tools.sh
```

See [Researcher Packaging Guide](guides/RESEARCHER_PACKAGING.md).

---

*Report generated from MIESC diagnostic workflow v5.4.2.*
