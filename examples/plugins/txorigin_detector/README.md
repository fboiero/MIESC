# tx.origin Authentication Detector Plugin

Example MIESC `DetectorPlugin` that flags authorization checks relying on
`tx.origin` in Solidity contracts using regex-based pattern matching.

## What it detects

| Severity | Pattern |
|----------|---------|
| **High** | `tx.origin` used in an equality comparison (`==` / `!=`) — an access-control check that can be defeated by a malicious intermediary contract. |
| **Low** | Any other reference to `tx.origin` — advisory to confirm it is not used for authorization. |

The detector implements `SWC-115` (Authorization through tx.origin) / `CWE-477`.

## Install

No package installation needed — load directly via the MIESC plugin loader:

```python
from pathlib import Path
from miesc.plugins.loader import PluginLoader
from miesc.plugins.protocol import PluginContext

loader = PluginLoader()
loaded = loader.load_plugin_file(
    Path("examples/plugins/txorigin_detector/detector.py")
)

context = PluginContext(
    miesc_version="6.0.0",
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

## Conformance

Verify the plugin against the versioned MIESC Plugin API:

```bash
miesc plugins conformance examples/plugins/txorigin_detector/detector.py
```

## Entry point (pip-installable)

To distribute as a pip package, add to `pyproject.toml`:

```toml
[project.entry-points."miesc.plugins"]
txorigin-auth-detector = "txorigin_detector.detector:TxOriginAuthDetectorPlugin"
```

## Example output

```
[High]   Line 6: Use of tx.origin for authorization
         SWC-115 / CWE-477
         Recommendation: Replace tx.origin with msg.sender for access control
```
