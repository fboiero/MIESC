# Plugin Development Guide

MIESC supports external detector plugins distributed via PyPI. Researchers and developers can publish their own vulnerability detectors as Python packages that MIESC discovers and loads automatically via entry points.

## How Plugin Discovery Works

MIESC uses Python's `importlib.metadata` entry points system:

1. When `miesc audit full` or `miesc scan` runs, MIESC queries the `miesc.detectors` entry point group
2. All packages installed in the current environment that register detectors in this group are discovered
3. Enabled detectors are instantiated and run on the target contract
4. Findings are merged with built-in tool results

## Creating a Plugin

### 1. Project Structure

```
miesc-my-detector/
├── pyproject.toml
├── README.md
├── src/
│   └── miesc_my_detector/
│       ├── __init__.py
│       └── detectors.py
└── tests/
    └── test_detector.py
```

### 2. Detector Implementation

```python
# src/miesc_my_detector/detectors.py
"""My custom vulnerability detector for MIESC."""

from typing import List, Dict, Any


class MyCustomDetector:
    """Detects custom vulnerability pattern."""

    name = "my-custom-detector"
    version = "1.0.0"
    description = "Detects XYZ vulnerability pattern in Solidity contracts"

    def analyze(self, contract_path: str, timeout: int = 300, **kwargs) -> List[Dict[str, Any]]:
        """Run analysis on a contract.

        Args:
            contract_path: Path to the .sol file
            timeout: Maximum execution time in seconds

        Returns:
            List of finding dicts with keys:
                - type: str (vulnerability type identifier)
                - severity: str (CRITICAL | HIGH | MEDIUM | LOW | INFO)
                - title: str (human-readable title)
                - description: str (detailed explanation)
                - location: dict with file, line, function keys
                - confidence: float (0.0 - 1.0, optional)
        """
        findings = []

        with open(contract_path) as f:
            source = f.read()
            lines = source.split("\n")

        # Your detection logic here
        for i, line in enumerate(lines, 1):
            if "delegatecall" in line and "onlyOwner" not in source:
                findings.append({
                    "type": "unprotected-delegatecall",
                    "severity": "CRITICAL",
                    "title": "Unprotected delegatecall",
                    "description": (
                        "Contract uses delegatecall without access control. "
                        "An attacker could change the implementation to a malicious contract."
                    ),
                    "location": {
                        "file": contract_path,
                        "line": i,
                        "function": "",
                    },
                    "confidence": 0.85,
                })

        return findings
```

### 3. pyproject.toml

```toml
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "miesc-my-detector"
version = "1.0.0"
description = "Custom vulnerability detector plugin for MIESC"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.9"
authors = [
    {name = "Your Name", email = "you@example.com"},
]
dependencies = [
    "miesc>=5.4.2",
]

[project.entry-points."miesc.detectors"]
my-custom-detector = "miesc_my_detector.detectors:MyCustomDetector"

[tool.setuptools.packages.find]
where = ["src"]
```

The critical line is `[project.entry-points."miesc.detectors"]` — this registers your detector class so MIESC discovers it automatically after `pip install`.

### 4. Multiple Detectors

Register multiple detectors from one package:

```toml
[project.entry-points."miesc.detectors"]
flash-loan-attack = "miesc_defi.detectors:FlashLoanDetector"
oracle-manipulation = "miesc_defi.detectors:OracleDetector"
price-slippage = "miesc_defi.detectors:SlippageDetector"
```

### 5. Publish to PyPI

```bash
# Build
python -m build

# Upload (requires PyPI account)
python -m twine upload dist/*
```

Users install with:
```bash
pip install miesc-my-detector
```

No configuration needed — MIESC discovers the plugin automatically.

## Managing Plugins

```bash
# List installed plugins
miesc plugins list

# Install from PyPI
miesc plugins install my-detector

# Search for plugins
miesc plugins search "defi"

# Disable a plugin (keeps installed but skips execution)
miesc plugins disable my-detector

# Enable a disabled plugin
miesc plugins enable my-detector

# Uninstall
miesc plugins uninstall my-detector

# Create a new plugin scaffold
miesc plugins create my-detector --output ./my-plugin/
```

## Local Development (without publishing)

For development and testing, install your plugin in editable mode:

```bash
cd miesc-my-detector/
pip install -e .
```

Or place it in the local plugins directory:

```bash
cp -r my_detector/ ~/.miesc/plugins/my_detector/
```

## Plugin API Reference

### Required Interface

Your detector class MUST have:

| Attribute/Method | Type | Description |
|---|---|---|
| `name` | `str` | Unique identifier (used in findings as `tool: "plugin:name"`) |
| `analyze(contract_path, timeout=300)` | method | Main entry point, returns list of finding dicts |

### Optional Attributes

| Attribute | Type | Description |
|---|---|---|
| `version` | `str` | Detector version |
| `description` | `str` | Human-readable description |
| `supported_versions` | `list[str]` | Solidity versions supported (e.g., `["0.8", "0.7"]`) |

### Finding Schema

```python
{
    "type": str,           # REQUIRED: vulnerability type ID
    "severity": str,       # REQUIRED: CRITICAL | HIGH | MEDIUM | LOW | INFO
    "title": str,          # REQUIRED: short title
    "description": str,    # REQUIRED: detailed explanation
    "location": {          # RECOMMENDED
        "file": str,
        "line": int,
        "function": str,
    },
    "confidence": float,   # OPTIONAL: 0.0 - 1.0
    "fix": str,            # OPTIONAL: remediation suggestion
    "references": list,    # OPTIONAL: links to docs/exploits
}
```

## Compatibility

Plugins can declare MIESC version requirements:

```toml
dependencies = [
    "miesc>=5.4.2,<6.0.0",
]
```

MIESC checks compatibility before installation and warns if versions don't match.

## Plugin API Versioning

The MIESC Plugin API (the `MIESCPlugin` protocol and its specialized base
classes) is **versioned, not frozen**. It carries an explicit semantic version
so community plugins can build on a stable, evolving surface:

```python
from miesc.plugins import PLUGIN_API_VERSION  # e.g. "1.0.0"
```

- **MAJOR** — breaking change to the protocol (a method/attribute is removed,
  renamed, or its required signature changes).
- **MINOR** — backward-compatible additions (new optional hooks or services).
- **PATCH** — internal fixes with no protocol impact.

A plugin declares the API version it was built against via the `API_VERSION`
class attribute (the scaffold sets this for you):

```python
class MyDetector(DetectorPlugin):
    API_VERSION = "1.0.0"   # the Plugin API this plugin targets
    ...
```

### Compatibility rule enforced by the loader

When a plugin is loaded, MIESC compares its declared `API_VERSION` against the
host's `PLUGIN_API_VERSION`:

| Situation | Result |
|---|---|
| Same MAJOR, plugin MINOR ≤ host MINOR | Loaded (host is backward compatible) |
| Same MAJOR, plugin MINOR > host MINOR | Rejected — host is too old for the plugin |
| Different MAJOR | Rejected — the protocol is incompatible |
| Non-semver `API_VERSION` | Rejected — invalid declaration |

Rejections raise `PluginAPIIncompatibleError` with an actionable message
instead of silently loading an incompatible plugin. Plugins written before API
versioning existed (no `API_VERSION`) default to the host version and keep
working.

You can check compatibility directly:

```python
from miesc.plugins import check_api_compatibility

result = check_api_compatibility("1.4.0", "1.2.0")
print(result.compatible)  # False
print(result.message)     # host provides v1.2.0, plugin needs MINOR 4 ...
```

## Conformance Suite

Before publishing, verify your plugin conforms to the Plugin API with the
self-service conformance harness. It checks that the class is a concrete
`MIESCPlugin`, instantiates, exposes the required identity properties, declares
a valid and host-compatible API version, implements the required methods with
compatible signatures, and registers cleanly.

From the CLI:

```bash
# Human-readable report (exit code is non-zero on failure)
miesc plugins conformance ./miesc_my_detector/plugin.py

# Machine-readable
miesc plugins conformance ./miesc_my_detector/plugin.py --json
```

Or programmatically:

```python
from miesc.plugins import PluginConformanceChecker

report = PluginConformanceChecker().check(MyDetector)
if not report.passed:
    for issue in report.failures:
        print(f"{issue.check}: {issue.message}")
```

Each report exposes `passed`, `failures` (blocking), and `warnings`
(recommendations such as non-`lowercase-hyphen` names), plus a structured
`to_dict()` for tooling and CI gates.

## Testing Your Plugin

```python
# tests/test_detector.py
from miesc_my_detector.detectors import MyCustomDetector


def test_detects_vulnerability():
    detector = MyCustomDetector()
    findings = detector.analyze("tests/fixtures/vulnerable.sol")
    assert len(findings) > 0
    assert findings[0]["severity"] == "CRITICAL"


def test_no_false_positive():
    detector = MyCustomDetector()
    findings = detector.analyze("tests/fixtures/safe.sol")
    assert len(findings) == 0
```

Run with: `pytest tests/ -v`
