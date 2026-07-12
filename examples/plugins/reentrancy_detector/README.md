# Reentrancy Detector Plugin

Example MIESC `DetectorPlugin` that identifies reentrancy vulnerabilities in
Solidity contracts using regex-based pattern matching.

## What it detects

| Severity | Pattern |
|----------|---------|
| **High** | `.call{value:}` appears **before** a state-zeroing assignment in the same function (Checks-Effects-Interactions violation). |
| **Medium** | Any `.call{value:}` external ETH transfer — state-update order not confirmed. |

The detector implements `SWC-107` (Reentrancy) / `CWE-841`.

## Install

No package installation needed — load directly via the MIESC plugin loader:

```python
from pathlib import Path
from miesc.plugins.loader import PluginLoader
from miesc.plugins.protocol import PluginContext

loader = PluginLoader()
loaded = loader.load_plugin_file(
    Path("examples/plugins/reentrancy_detector/detector.py")
)

context = PluginContext(
    miesc_version="5.1.1",
    config={},
    data_dir=Path("/tmp"),
    cache_dir=Path("/tmp"),
)

plugin = loader.load_and_initialize(loaded[0], context)
```

## Usage

```python
with open("MyContract.sol") as f:
    code = f.read()

result = plugin.execute(code=code, filename="MyContract.sol")

if result.success:
    for finding in result.data:
        print(f"[{finding['severity']}] Line {finding['location']['line']}: {finding['message']}")
```

Or call `detect()` directly:

```python
findings = plugin.detect(code, filename="MyContract.sol")
```

## Entry point (pip-installable)

To distribute as a pip package, add to `setup.cfg` / `pyproject.toml`:

```toml
[project.entry-points."miesc.plugins"]
reentrancy-detector = "reentrancy_detector.detector:ReentrancyDetectorPlugin"
```

## Example output

```
[High]   Line 14: Potential reentrancy: external ETH call before state update
         SWC-107 / CWE-841
         Recommendation: Apply CEI pattern or use OpenZeppelin ReentrancyGuard
```
