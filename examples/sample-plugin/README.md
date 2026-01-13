# Sample MIESC Detector Plugin

This directory contains a complete example of a MIESC detector plugin that you can use as a template for creating your own custom detectors.

## Plugin Structure

```
miesc-dangerous_delegatecall/
├── pyproject.toml                      # Package configuration with entry points
├── README.md                           # Plugin documentation
├── dangerous_delegatecall/
│   ├── __init__.py                     # Package init
│   └── detectors.py                    # Detector implementation
└── tests/
    ├── __init__.py
    └── test_dangerous_delegatecall.py  # Unit tests
```

## What This Plugin Detects

The `DangerousDelegatecallDetector` identifies several dangerous delegatecall patterns:

| Pattern | Severity | Description |
|---------|----------|-------------|
| User-supplied delegatecall target | CRITICAL | Function parameter used as delegatecall target |
| Unprotected delegatecall | CRITICAL | Public/external function with delegatecall but no access control |
| Proxy delegatecall pattern | MEDIUM | Storage variable used as delegatecall target |
| Assembly delegatecall | HIGH | Low-level delegatecall bypasses Solidity safety checks |
| Delegatecall with encoded data | MEDIUM | abi.encode used with delegatecall |

## Installation

### From this directory (development mode)

```bash
cd examples/sample-plugin/miesc-dangerous_delegatecall
pip install -e .
```

### Verify installation

```bash
# Check plugin is registered
miesc plugins list

# List available detectors
miesc detectors list
```

## Usage

### Run the detector

```bash
# Run against a specific contract
miesc detectors run contract.sol -d dangerous_delegatecall

# Run against the test vulnerable contract
miesc detectors run ../VulnerableProxy.sol -d dangerous_delegatecall
```

### Use in Python

```python
from dangerous_delegatecall.detectors import DangerousDelegatecallDetector

detector = DangerousDelegatecallDetector()

with open("contract.sol") as f:
    code = f.read()

findings = detector.analyze(code, "contract.sol")

for finding in findings:
    print(f"[{finding.severity.name}] Line {finding.location.line}: {finding.title}")
```

## Creating Your Own Plugin

### 1. Generate scaffold

```bash
miesc plugins create my-detector -d "My custom detector" -o ./my-plugins
```

### 2. Implement detection logic

Edit `my_detector/detectors.py`:

```python
from miesc.detectors import BaseDetector, Finding, Severity, Location, Confidence

class MyDetector(BaseDetector):
    name = "my-detector"
    description = "Detects my custom vulnerability pattern"
    category = "security"
    severity_default = Severity.MEDIUM

    def analyze(self, source_code: str, file_path: str | None = None) -> list[Finding]:
        findings = []

        # Your detection logic here
        if "dangerous_pattern" in source_code:
            findings.append(Finding(
                detector=self.name,
                title="Dangerous Pattern Found",
                description="Description of the issue",
                severity=Severity.HIGH,
                location=Location(file=file_path, line=1),
                confidence=Confidence.HIGH,
                recommendation="How to fix the issue",
            ))

        return findings
```

### 3. Install and test

```bash
cd miesc-my_detector
pip install -e .
miesc plugins list
miesc detectors run test_contract.sol -d my-detector
```

## Test Contract

The `VulnerableProxy.sol` file contains a deliberately vulnerable contract for testing:

- **executeOnAddress**: Delegatecall to user-supplied address (CRITICAL)
- **forward**: Unprotected delegatecall (CRITICAL)
- **callWithSelector**: Delegatecall with encoded data (MEDIUM)
- **fallback**: Assembly delegatecall (HIGH)
- **safeForward**: Protected with onlyOwner (SAFE - not flagged)

## License

MIT License
