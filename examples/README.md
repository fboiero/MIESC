# MIESC v5.4.2 - Public Core Examples

This directory contains local examples for the public MIESC core surface:
CLI scans, local REST API checks, MCP-compatible analysis, static reports, and
thesis evidence demos. Product/platform UI code is intentionally out of scope
for the public package.

## Available Scripts

| Script | Duration | Description |
|--------|----------|-------------|
| `quick_demo.sh` | 2 min | Fast CLI smoke demo |
| `run_demo.sh` | 10 min | Basic CLI/API demo |
| `run_full_demo.sh` | 15-20 min | Full local evidence demo |
| `demo_thesis_defense.py` | 5-10 min | Thesis-oriented walkthrough |

## Quick Smoke

```bash
miesc --version
miesc doctor
miesc scan tests/fixtures/reentrancy.sol --fp-strictness off --verbose
```

Expected behavior for `tests/fixtures/reentrancy.sol`:

- Scan exits successfully when `--ci` is not used.
- Reentrancy findings are reported.
- `--ci --quiet --fp-strictness off` exits with code 1 because HIGH findings
  are present.

## Core Surfaces Demonstrated

### CLI

```bash
miesc scan tests/fixtures/reentrancy.sol --fp-strictness off
miesc audit quick tests/fixtures/reentrancy.sol -f json
miesc audit full tests/fixtures/reentrancy.sol -f json --timeout 60
miesc doctor
```

### Static HTML Report

```bash
python -m src.utils.web_dashboard --results analysis/results --output analysis/dashboard
```

The generated dashboard is a static local artifact at
`analysis/dashboard/index.html`.

### Local REST API

```bash
python -m miesc.api.rest --host 127.0.0.1 --port 8000
```

Core endpoints:

- `GET /api/v1/health/`
- `GET /api/v1/tools/`
- `GET /api/v1/layers/`
- `POST /api/v1/analyze/quick/`
- `POST /api/v1/analyze/full/`
- `POST /api/v1/analyze/tool/{tool_name}/`

### MCP

```bash
miesc-mcp
```

For local validation without starting a long-running client session, use the
MCP unit and integration smoke tests:

```bash
python -m pytest tests/test_mcp_server.py
```

### ML Pipeline

```python
from src.ml import MLPipeline

pipeline = MLPipeline()
result = pipeline.process(findings)

print(f"FP filtered: {result.fp_filtered}")
```

## Validation Snapshot

Latest local release evidence:

| Check | Result |
|-------|--------|
| Full pytest suite | 5967 passed, 8 skipped |
| Public REST/MCP/OpenAPI/dist suite | 69 passed |
| Known reentrancy contract CLI smoke | 8 findings, 2 HIGH |
| Known reentrancy contract REST Slither smoke | 5 findings |
| Known reentrancy contract MCP quick scan | 10 findings, 6 tools succeeded |
| Wheel/sdist content guard | PASS |

## Requirements

```bash
pip install -e .
miesc --version
miesc doctor
```

Optional REST/MCP extras:

```bash
pip install -e ".[django,mcp]"
```

## Troubleshooting

```bash
# If Slither is unavailable
pip install slither-analyzer
solc-select install 0.8.25
solc-select use 0.8.25

# If the REST API cannot import Django/DRF
pip install django djangorestframework django-cors-headers

# If the MCP server cannot import the SDK
pip install "mcp[cli]>=1.0.0"

# Verify the local install
python scripts/verify_installation.py
```
