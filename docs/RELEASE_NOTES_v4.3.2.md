# MIESC v4.3.2 Release Notes

**Release Date:** January 10, 2026
**Tag:** [v4.3.2](https://github.com/fboiero/MIESC/releases/tag/v4.3.2)

---

## Overview

MIESC v4.3.2 is a maintenance release focused on **PyPI publication**, **optional dependency handling**, and **documentation improvements**. The package is now available on PyPI for easy installation via `pip install miesc`.

---

## Highlights

- **PyPI Publication**: MIESC is now available on [PyPI](https://pypi.org/project/miesc/)
- **Optional Dependencies**: Web frameworks (FastAPI, Django) are now optional
- **Bilingual Documentation**: Complete Spanish quick start guide
- **Improved Navigation**: Enhanced MkDocs site structure
- **Version Consistency**: All version strings synchronized to 4.3.2

---

## Installation

```bash
# From PyPI (recommended)
pip install miesc

# With web UI and API servers
pip install miesc[web]

# With all optional features
pip install miesc[full]

# Development installation
pip install miesc[dev]
```

---

## New Features

### PyPI Package

MIESC is now published on PyPI with proper package structure:

```bash
pip install miesc
miesc --version  # MIESC version 4.3.2
miesc doctor     # Shows 31 adapters loaded
```

**Package extras:**
- `miesc` - Core CLI with 31 security tools
- `miesc[web]` - Adds Streamlit web UI, FastAPI, Django REST
- `miesc[full]` - All features including ML dependencies
- `miesc[dev]` - Development and testing tools

### Optional Web Dependencies

Web frameworks are now optional to reduce installation size:

```python
# Core installation works without web frameworks
from miesc.api import run_tool, run_full_audit

# WebSocket API gracefully handles missing FastAPI
from src.core.websocket_api import WebSocketAPI
# Returns None if FastAPI not installed
```

### Spanish Quick Start Guide

New `QUICKSTART_ES.md` with complete Spanish documentation:
- Installation instructions
- CLI command reference
- 9-layer architecture table
- Batch audit examples
- CI/CD integration

---

## Bug Fixes

### Optional Import Handling

Fixed `NameError` when FastAPI not installed:

```python
# Before: NameError: name 'WebSocket' is not defined
# After: Graceful fallback with WEBSOCKET_AVAILABLE = False

from __future__ import annotations  # Deferred type evaluation

try:
    from fastapi import FastAPI, WebSocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    WebSocket = None  # type: ignore
```

### Version String Consistency

All version strings now synchronized:
- `miesc/__init__.py` → 4.3.2
- `miesc/api/__init__.py` → 4.3.2
- `miesc/api/rest.py` → 4.3.2
- `README.md` badge → 4.3.2
- `README_ES.md` → 4.3.2

---

## Documentation

### New Documentation

- `QUICKSTART.md` - English quick start guide
- `QUICKSTART_ES.md` - Spanish quick start guide
- Improved MkDocs navigation structure

### Updated Documentation

- `README.md` - PyPI badge, installation instructions
- `README_ES.md` - PyPI badge, modernized quick start
- `docs/index.md` - v4.3.2, 9 layers, 31 tools
- `docs/index_es.md` - Spanish version updated
- `CHANGELOG.md` - v4.3.2 release notes

---

## Performance Metrics

Validated on SmartBugs-curated benchmark (50 contracts):

| Metric | Value |
|--------|-------|
| **Precision** | 100% |
| **Recall** | 70% |
| **F1-Score** | 82.35% |
| **False Positives** | 0 |
| **Tools** | 31/31 operational |

### Categories with 100% Recall
- Arithmetic vulnerabilities
- Bad randomness
- Front running

---

## Test Suite

```
Tests:    1833 passed, 53 skipped
Coverage: 80.39%
Time:     ~5 minutes
```

---

## Breaking Changes

None. This is a backward-compatible maintenance release.

---

## Dependencies

### Core (always installed)
- Python 3.12+
- slither-analyzer
- click, pyyaml, requests

### Optional (extras)
- `[web]`: fastapi, uvicorn, streamlit, django
- `[full]`: torch, scikit-learn, transformers
- `[dev]`: pytest, black, ruff, mypy

---

## Upgrade Guide

```bash
# From previous version
pip install --upgrade miesc

# Verify installation
miesc --version
miesc doctor
```

---

## Contributors

- Fernando Boiero (@fboiero)

---

## Links

- **PyPI**: https://pypi.org/project/miesc/
- **GitHub**: https://github.com/fboiero/MIESC
- **Documentation**: https://fboiero.github.io/MIESC/
- **Demo Video**: https://youtu.be/pLa_McNBRRw

---

## Full Changelog

**Commits since v4.3.1:**

- `7b0e54d` fix: update all version strings to 4.3.2
- `24b0cf0` fix: update version to 4.3.2 in API module and tests
- `da741d2` docs: improve mkdocs navigation structure
- `07c525d` docs: add link to QUICKSTART.md in README.md
- `735ad6f` docs: update README_ES.md quick start and link to QUICKSTART_ES.md
- `344f7c0` docs: add Spanish quick start guide (QUICKSTART_ES.md)
- `8b80058` docs: comprehensive documentation update for v4.3.2
- `d14566e` docs: add v4.3.2 release notes to CHANGELOG
- `ea6706a` fix: Resolve optional dependency import issues for PyPI package
- `3c1595b` docs: add QUICKSTART.md with CLI usage and 9-layer architecture
- `a74b52d` refactor: make web frameworks optional dependencies
- `db43526` feat: improve installation and CLI for PyPI publication
