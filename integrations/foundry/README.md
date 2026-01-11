# MIESC Foundry Integration

Integrate MIESC security scanning into your Foundry projects.

## Quick Start

### Option A: Automatic Setup (Recommended)

```bash
# Install MIESC
pip install miesc

# Initialize Foundry integration (run from project root)
miesc init foundry
```

This automatically:
- Adds `post_build_hook` to your `foundry.toml`
- Configures security scanning on every `forge build`

**Available options:**

```bash
miesc init foundry                      # Basic setup (default profile)
miesc init foundry --profile ci         # Configure CI profile
miesc init foundry --hook-script        # Create full hook script
miesc init foundry --fail-on critical   # Only fail on critical issues
```

### Option B: Manual Setup

#### 1. Install MIESC

```bash
pip install miesc
```

#### 2. Add Post-Build Hook

Add to your `foundry.toml`:

```toml
[profile.default]
# Run MIESC after every build
post_build_hook = "miesc audit quick ./src --ci"
```

Or for more control:

```toml
[profile.default]
# Custom hook script
post_build_hook = "./scripts/miesc-hook.sh"

[profile.ci]
# Stricter CI mode - fail on any high severity issues
post_build_hook = "miesc audit quick ./src --ci --fail-on high"
```

#### 3. Create Hook Script (Optional)

Use the automatic generator:

```bash
miesc init foundry --hook-script
```

Or manually create `scripts/miesc-hook.sh`:

```bash
#!/bin/bash
# MIESC Foundry Post-Build Hook

# Run quick audit on source contracts
miesc audit quick ./src --ci --output json > miesc-report.json

# Check for critical/high issues
CRITICAL=$(jq '.summary.critical' miesc-report.json)
HIGH=$(jq '.summary.high' miesc-report.json)

if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    echo "MIESC found $CRITICAL critical and $HIGH high severity issues"
    jq '.findings[] | select(.severity == "critical" or .severity == "high")' miesc-report.json
    exit 1
fi

echo "MIESC: No critical/high issues found"
```

Make it executable:

```bash
chmod +x scripts/miesc-hook.sh
```

## Configuration Options

### foundry.toml Profiles

```toml
# Development profile - quick scan, no failures
[profile.default]
post_build_hook = "miesc audit quick ./src"

# CI profile - full audit, fail on issues
[profile.ci]
post_build_hook = "miesc audit full ./src --ci --fail-on medium"

# Security audit profile - comprehensive analysis
[profile.audit]
post_build_hook = "miesc audit full ./src --output sarif --ci"
```

### MIESC CLI Options

| Option | Description |
|--------|-------------|
| `--ci` | CI mode - exit code 1 if issues found |
| `--fail-on LEVEL` | Fail on severity: critical, high, medium, low |
| `--output FORMAT` | Output format: json, sarif, markdown |
| `--timeout SECS` | Analysis timeout in seconds |
| `--layers 1,2,3` | Specific layers to run |

## Usage Examples

### Run After Build

```bash
# Build triggers MIESC automatically
forge build

# Or run manually
forge build && miesc audit quick ./src
```

### Pre-Commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    rev: v4.3.2
    hooks:
      - id: miesc-quick
        files: \.sol$
```

### GitHub Actions

Generate workflow automatically:

```bash
miesc init github
```

Or manually create `.github/workflows/security.yml`:

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  miesc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foundry-rs/foundry-toolchain@v1
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install MIESC
        run: pip install miesc

      - name: Build & Audit
        run: |
          forge build
          miesc audit quick ./src --ci --output sarif > miesc.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: miesc.sarif
```

## Forge Script Integration

You can also create a Forge script to run MIESC:

```solidity
// script/SecurityAudit.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

contract SecurityAudit is Script {
    function run() external {
        // This script is a placeholder - actual audit runs via CLI
        console.log("Running MIESC security audit...");
        console.log("Execute: miesc audit quick ./src --ci");
    }
}
```

Run with:

```bash
forge script script/SecurityAudit.s.sol && miesc audit quick ./src --ci
```

## Makefile Integration

Add to your `Makefile`:

```makefile
.PHONY: build test audit audit-full

build:
	forge build

test:
	forge test

# Quick security scan
audit:
	miesc audit quick ./src --ci

# Full security audit
audit-full:
	miesc audit full ./src --output markdown > SECURITY_AUDIT.md

# Build with audit
build-secure: build audit

# CI pipeline
ci: build test audit
```

## Output Examples

### Console Output

```
$ forge build && miesc audit quick ./src --ci

[MIESC] Scanning 5 contracts...
[MIESC] Tools: slither, aderyn, solhint, mythril

Results:
  Critical: 0
  High: 1
  Medium: 3
  Low: 5

[HIGH] Reentrancy vulnerability in Vault.sol:45
  Description: State change after external call
  Recommendation: Use ReentrancyGuard or CEI pattern
```

### SARIF Output

```bash
miesc audit quick ./src --output sarif > results.sarif
```

Compatible with GitHub Code Scanning and VS Code SARIF Viewer.

## Troubleshooting

### "miesc: command not found"

```bash
# Ensure MIESC is installed
pip install miesc

# Or use full path
python -m miesc audit quick ./src
```

### "No Solidity files found"

Ensure your contracts are in `./src` or specify the correct path:

```toml
post_build_hook = "miesc audit quick ./contracts --ci"
```

### Timeout Issues

Increase timeout for large projects:

```bash
miesc audit quick ./src --timeout 600
```

## Links

- [MIESC Documentation](https://fboiero.github.io/MIESC)
- [Foundry Book](https://book.getfoundry.sh)
- [Issue Tracker](https://github.com/fboiero/MIESC/issues)
