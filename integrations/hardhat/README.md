# hardhat-miesc

Hardhat plugin for [MIESC](https://github.com/fboiero/MIESC) smart contract security analysis.

MIESC (Multi-layer Intelligent Evaluation for Smart Contracts) orchestrates **31 security tools** across **9 defense layers** with AI-assisted correlation and ML-based detection.

## Quick Start

### Option A: Automatic Setup (Recommended)

```bash
# Install MIESC
pip install miesc

# Initialize Hardhat integration (run from project root)
miesc init hardhat
```

This automatically:
- Creates `tasks/miesc.js` with Hardhat tasks
- Provides `npx hardhat miesc` command
- Hooks into compile for optional auto-scanning

**Available options:**

```bash
miesc init hardhat                    # Basic setup (fail on high)
miesc init hardhat --fail-on critical # Only fail on critical issues
```

After running, add to your `hardhat.config.js`:

```javascript
require("./tasks/miesc");
```

### Option B: Full Plugin Installation

## Installation

### Prerequisites

1. **Python 3.12+** with pip
2. **Node.js 18+** with npm
3. **Hardhat** project

### Install MIESC

```bash
pip install miesc
miesc doctor  # Verify installation
```

### Install Plugin

**From npm (when published):**

```bash
npm install --save-dev hardhat-miesc
```

**From source:**

```bash
# Copy plugin files to your project
cp -r /path/to/MIESC/integrations/hardhat ./plugins/hardhat-miesc
npm install --save-dev ./plugins/hardhat-miesc
```

### Configure Hardhat

Add to your `hardhat.config.js`:

```javascript
require("hardhat-miesc");

module.exports = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    failOn: "high",
    auditType: "quick",
  },
};
```

Or for TypeScript (`hardhat.config.ts`):

```typescript
import "hardhat-miesc";

const config: HardhatUserConfig = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    failOn: "high",
    auditType: "quick",
  },
};

export default config;
```

## Usage

### Commands

```bash
# Run quick security audit (4 tools)
npx hardhat miesc

# Run full 9-layer audit
npx hardhat miesc --type full

# Run specific layer
npx hardhat miesc --type layer --layer 1

# CI mode with JSON output
npx hardhat miesc --ci --output json --file report.json

# Fail only on critical issues
npx hardhat miesc --ci --fail-on critical

# Verbose output
npx hardhat miesc --verbose
```

### Shorthand Commands

```bash
npx hardhat miesc:quick    # Quick audit
npx hardhat miesc:full     # Full audit
npx hardhat miesc:layer 3  # Specific layer
npx hardhat miesc:doctor   # Check installation
npx hardhat miesc:version  # Show version
```

### Auto-run on Compile

Enable automatic security scanning after compilation:

```javascript
module.exports = {
  miesc: {
    runOnCompile: true,  // Run after every compile
    failOnError: true,   // Fail build on issues
    failOn: "high",      // Severity threshold
  },
};
```

```bash
npx hardhat compile  # MIESC runs automatically
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable plugin |
| `runOnCompile` | boolean | `false` | Auto-run after compilation |
| `failOnError` | boolean | `true` | Fail on security issues |
| `failOn` | string | `"high"` | Severity threshold: critical, high, medium, low |
| `timeout` | number | `300` | Timeout in seconds |
| `outputFormat` | string | `"text"` | Output: text, json, sarif, markdown |
| `outputFile` | string | `null` | Save output to file |
| `contractsPath` | string | `null` | Custom contracts path |
| `exclude` | string[] | `[]` | Glob patterns to exclude |
| `auditType` | string | `"quick"` | Audit type: quick, full, layer |
| `layer` | number | `null` | Layer number (1-9) for layer audit |
| `verbose` | boolean | `false` | Verbose output |

## Configuration Examples

### Development (Fast Feedback)

```javascript
module.exports = {
  miesc: {
    enabled: true,
    runOnCompile: true,
    auditType: "quick",
    failOn: "critical",  // Only fail on critical
    verbose: false,
  },
};
```

### CI/CD (Strict)

```javascript
module.exports = {
  miesc: {
    enabled: true,
    failOnError: true,
    failOn: "high",
    auditType: "quick",
    outputFormat: "json",
    outputFile: "miesc-report.json",
  },
};
```

### Full Security Audit

```javascript
module.exports = {
  miesc: {
    enabled: true,
    auditType: "full",
    timeout: 600,
    outputFormat: "markdown",
    outputFile: "SECURITY_REPORT.md",
  },
};
```

### Layer-by-Layer Analysis

```javascript
module.exports = {
  miesc: {
    auditType: "layer",
    layer: 1,  // Start with static analysis
  },
};
```

## MIESC Layers

| Layer | Name | Tools |
|-------|------|-------|
| 1 | Static Analysis | Slither, Aderyn, Solhint |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos |
| 4 | Formal Verification | Certora, SMTChecker |
| 5 | Property Testing | PropertyGPT, Wake, Vertigo |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan, LLMSmartAudit |
| 7 | Pattern Recognition | DA-GNN, SmartGuard, Clone Detector |
| 8 | DeFi Security | DeFi Analyzer, MEV Detector, Gas Analyzer |
| 9 | Advanced Detection | Advanced Detector, SmartBugs, Threat Model |

## GitHub Actions Integration

Generate workflow automatically:

```bash
miesc init github
```

Or copy `hardhat-miesc.yml` to `.github/workflows/security.yml`:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
    paths: ["**.sol"]
  pull_request:
    paths: ["**.sol"]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: |
          npm ci
          pip install miesc

      - run: npx hardhat compile

      - run: npx hardhat miesc --ci --output sarif > results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

See `hardhat-miesc.yml` for a complete workflow with PR comments and artifacts.

## Package.json Scripts

Add to your `package.json`:

```json
{
  "scripts": {
    "audit": "hardhat miesc",
    "audit:quick": "hardhat miesc:quick",
    "audit:full": "hardhat miesc:full",
    "audit:ci": "hardhat miesc --ci --fail-on high",
    "audit:report": "hardhat miesc --output markdown --file SECURITY.md",
    "security": "hardhat compile && hardhat miesc:full"
  }
}
```

```bash
npm run audit        # Quick audit
npm run audit:full   # Full audit
npm run audit:ci     # CI mode
npm run security     # Compile + full audit
```

## Troubleshooting

### MIESC not found

```bash
pip install miesc
miesc doctor
```

### Permission denied

```bash
pip install --user miesc
export PATH="$HOME/.local/bin:$PATH"
```

### Contracts not found

Ensure your contracts are in the configured path:

```javascript
module.exports = {
  paths: {
    sources: "./contracts",  // Default
  },
  miesc: {
    contractsPath: "./contracts",  // Or specify explicitly
  },
};
```

### Timeout issues

Increase timeout for large projects:

```javascript
module.exports = {
  miesc: {
    timeout: 600,  // 10 minutes
  },
};
```

## Contributing

See the main [MIESC repository](https://github.com/fboiero/MIESC) for contribution guidelines.

## License

AGPL-3.0 - See [LICENSE](https://github.com/fboiero/MIESC/blob/main/LICENSE)

## Links

- [MIESC Repository](https://github.com/fboiero/MIESC)
- [MIESC Documentation](https://fboiero.github.io/MIESC)
- [Hardhat Documentation](https://hardhat.org/docs)
