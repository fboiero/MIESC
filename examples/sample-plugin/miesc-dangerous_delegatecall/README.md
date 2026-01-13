# miesc-dangerous_delegatecall

Detects dangerous delegatecall patterns in smart contracts.

## Installation

```bash
pip install miesc-dangerous_delegatecall
```

Or install in development mode:

```bash
pip install -e .
```

## Usage

Once installed, the detector is automatically available in MIESC:

```bash
# List available detectors (should include dangerous_delegatecall)
miesc detectors list

# Run the detector
miesc detectors run contract.sol -d dangerous_delegatecall

# Or run as part of a full audit
miesc audit quick contract.sol
```

## What It Detects

| Severity | Pattern |
|----------|---------|
| CRITICAL | Delegatecall to user-supplied address |
| CRITICAL | Unprotected delegatecall in public/external functions |
| HIGH | Assembly delegatecall |
| MEDIUM | Proxy delegatecall pattern |
| MEDIUM | Delegatecall with abi.encode |

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/miesc-dangerous_delegatecall.git
cd miesc-dangerous_delegatecall

# Install in development mode
pip install -e .

# Run tests
pytest
```

## License

MIT License
