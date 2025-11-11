# 🧪 MIESC Framework - Complete Regression Testing Guide

**Version**: 1.0
**Last Updated**: October 2025
**Author**: Fernando Boiero

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Test Modes](#test-modes)
4. [Test Coverage](#test-coverage)
5. [Running Tests](#running-tests)
6. [Interpreting Results](#interpreting-results)
7. [CI/CD Integration](#cicd-integration)
8. [Troubleshooting](#troubleshooting)
9. [Adding New Tests](#adding-new-tests)

---

## Overview

The MIESC regression test suite provides comprehensive validation of all framework components:

- **MCP Infrastructure**: Context bus, pub/sub messaging, audit trails
- **11 Specialized Agents**: All agent types from static to AI-powered
- **External Tools**: Slither, Mythril, Echidna, Certora, etc.
- **Integration Workflows**: End-to-end audit pipelines
- **Policy Compliance**: ISO 27001, NIST SSDF, OWASP checks

### Why Regression Testing?

After the repository reorganization (moving files, updating imports), we need to ensure:
- ✅ All imports resolve correctly
- ✅ All agents can be instantiated
- ✅ MCP infrastructure works
- ✅ External tools are accessible
- ✅ Demo scripts are functional
- ✅ End-to-end workflows execute

---

## Quick Start

### Prerequisites

```bash
# Ensure you're in the project root
cd /path/to/MIESC

# Activate virtual environment
source venv/bin/activate

# Install dependencies (if not done)
pip install -r config/requirements_core.txt
```

### Run Tests

```bash
# Quick smoke test (~5 minutes)
python scripts/run_regression_tests.py --mode fast

# Critical path only (~10 minutes) - DEFAULT
python scripts/run_regression_tests.py --mode critical

# Full comprehensive suite (~30 minutes)
python scripts/run_regression_tests.py --mode full
```

### Expected Output

```
╔══════════════════════════════════════════════════════════════╗
║          MIESC REGRESSION TEST SUITE                         ║
╚══════════════════════════════════════════════════════════════╝

Mode: CRITICAL
Test Contract: vulnerable_bank.sol
Timestamp: 2025-10-12 14:30:00

Starting tests...
================================================================

================================================================
PHASE 1: Infrastructure Tests
================================================================

🧪 Running: Import all critical modules... ✅ PASS (0.23s)
🧪 Running: MCP Context Bus... ✅ PASS (0.15s)
🧪 Running: Example contracts accessible... ✅ PASS (0.05s)
...
```

---

## Test Modes

### 1. Fast Mode (`--mode fast`)

**Duration**: ~5 minutes
**Coverage**: Critical smoke tests only

Tests executed:
- ✅ Import verification
- ✅ MCP Context Bus basics
- ✅ Critical agents (Static, AI, Coordinator, Policy)
- ✅ Slither availability

**Use case**: Quick validation after minor changes, pre-commit hooks

```bash
python scripts/run_regression_tests.py --mode fast
```

---

### 2. Critical Mode (`--mode critical`) - DEFAULT

**Duration**: ~10 minutes
**Coverage**: All critical path functionality

Tests executed:
- ✅ All infrastructure tests
- ✅ All 11 agent initializations
- ✅ Critical tool availability (Slither)
- ✅ MCP server tools schema
- ✅ Basic integration tests

**Use case**: Standard regression testing after refactoring, before PRs

```bash
python scripts/run_regression_tests.py --mode critical
# Or simply:
python scripts/run_regression_tests.py
```

---

### 3. Full Mode (`--mode full`)

**Duration**: ~30 minutes
**Coverage**: Comprehensive end-to-end validation

Tests executed:
- ✅ All critical mode tests
- ✅ All external tool integrations (Mythril, Echidna, Manticore, Certora)
- ✅ Complete agent workflows with actual contracts
- ✅ End-to-end audit pipelines
- ✅ Performance benchmarks
- ✅ Compliance validation

**Use case**: Pre-release validation, major version changes, nightly CI builds

```bash
python scripts/run_regression_tests.py --mode full
```

---

## Test Coverage

### Phase 1: Infrastructure Tests

| Test Name | Critical | Description |
|-----------|----------|-------------|
| Import all critical modules | ✅ | Validates all key imports work after reorganization |
| MCP Context Bus | ✅ | Tests pub/sub messaging, stats tracking |
| Example contracts accessible | ✅ | Ensures example contracts are in place |
| Demo scripts exist | ✅ | Verifies demo scripts are accessible |

### Phase 2: Agent Initialization Tests

| Agent | Critical | Description |
|-------|----------|-------------|
| StaticAgent | ✅ | Static analysis orchestration (Slither, Solhint, Surya) |
| DynamicAgent | ⚠️ | Fuzzing orchestration (Echidna, Medusa) |
| SymbolicAgent | ⚠️ | Symbolic execution (Manticore, Mythril) |
| FormalAgent | ⚠️ | Formal verification (Certora) |
| AIAgent | ✅ | AI-powered triage and false positive filtering |
| PolicyAgent | ✅ | ISO/NIST/OWASP compliance checking |
| CoordinatorAgent | ✅ | Multi-agent orchestration |
| GPTScanAgent | ⚠️ | GPT-4 powered vulnerability detection |
| LLMSmartAuditAgent | ⚠️ | LLM-based smart contract auditing |
| SmartLLMAgent | ⚠️ | Advanced LLM auditing with chain-of-thought |

✅ = Critical (always tested)
⚠️ = Non-critical (skipped in fast mode)

### Phase 3: External Tool Availability Tests

| Tool | Critical | Description |
|------|----------|-------------|
| Slither | ✅ | Static analysis framework (required) |
| Mythril | ⚠️ | Symbolic execution tool |
| Echidna | ⚠️ | Property-based fuzzer (optional) |
| Medusa | ⚠️ | Alternative fuzzer (optional) |
| Certora | ⚠️ | Formal verification (optional, requires license) |
| Manticore | ⚠️ | Symbolic execution (optional) |

### Phase 4: Integration Tests

| Test Name | Critical | Description |
|-----------|----------|-------------|
| MCP Server tools schema | ✅ | Validates MCP protocol tool definitions |
| Static analysis on contract | ✅ | Runs StaticAgent on example contract |
| Full audit workflow | ⚠️ | End-to-end CoordinatorAgent execution |
| AI triage workflow | ⚠️ | AI-powered false positive detection |
| Compliance report generation | ⚠️ | ISO/NIST/OWASP report creation |

---

## Running Tests

### Basic Execution

```bash
# From project root
python scripts/run_regression_tests.py
```

### With Specific Mode

```bash
# Fast mode (5 min)
python scripts/run_regression_tests.py --mode fast

# Critical mode (10 min, default)
python scripts/run_regression_tests.py --mode critical

# Full mode (30 min)
python scripts/run_regression_tests.py --mode full
```

### Redirecting Output

```bash
# Save to file
python scripts/run_regression_tests.py --mode critical > test_results.txt 2>&1

# View with timestamps
python scripts/run_regression_tests.py --mode critical | ts '[%Y-%m-%d %H:%M:%S]'
```

### Running Specific Phases

If you want to test only specific components, you can modify the script or run individual test functions:

```python
from scripts.run_regression_tests import RegressionTestSuite

suite = RegressionTestSuite(mode="critical")

# Test only agents
suite.run_test("StaticAgent init", suite.test_static_agent_init, critical=True)
suite.run_test("AIAgent init", suite.test_ai_agent_init, critical=True)

print(suite.results.summary())
```

---

## Interpreting Results

### Success Output

```
╔══════════════════════════════════════════════════════════════╗
║          MIESC REGRESSION TEST SUITE - SUMMARY               ║
╚══════════════════════════════════════════════════════════════╝

📊 Results:
  ✅ Passed:  15/15
  ❌ Failed:  0/15
  ⏭️  Skipped: 0/15

⏱️  Total Time: 127.45s

================================================================

✅ PASSED TESTS:
  • Import all critical modules (0.23s)
  • MCP Context Bus (0.15s)
    Messages: 1
  • Example contracts accessible (0.05s)
    Found 17 contracts
  ...
```

**Exit Code**: `0` (success)

### Failure Output

```
❌ FAILED TESTS:
  • StaticAgent initialization
    Error: ModuleNotFoundError: No module named 'src.agents'
    Traceback:
    File ".../static_agent.py", line 5, in <module>
      from src.mcp.context_bus import get_context_bus
    ModuleNotFoundError: No module named 'src.mcp'
```

**Exit Code**: `1` (failure)

### Results File

Test results are automatically saved to:
```
tests/regression_results.json
```

Example content:
```json
{
  "timestamp": "2025-10-12T14:30:00.123456",
  "mode": "critical",
  "summary": {
    "passed": 15,
    "failed": 0,
    "skipped": 0,
    "duration": 127.45
  },
  "passed": [
    {
      "name": "Import all critical modules",
      "duration": 0.23,
      "details": ""
    },
    ...
  ],
  "failed": [],
  "skipped": []
}
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/regression-tests.yml`:

```yaml
name: Regression Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python 3.9
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r config/requirements_core.txt

    - name: Install Slither
      run: |
        pip install slither-analyzer

    - name: Run regression tests
      run: |
        python scripts/run_regression_tests.py --mode critical

    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: tests/regression_results.json
```

### Pre-commit Hook

Create `.git/hooks/pre-push`:

```bash
#!/bin/bash
echo "Running regression tests before push..."
python scripts/run_regression_tests.py --mode fast

if [ $? -ne 0 ]; then
  echo "❌ Regression tests failed. Push aborted."
  exit 1
fi

echo "✅ All tests passed. Proceeding with push."
```

Make executable:
```bash
chmod +x .git/hooks/pre-push
```

---

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Symptom**:
```
ModuleNotFoundError: No module named 'src.agents'
```

**Solution**:
```bash
# Ensure you're running from project root
cd /path/to/MIESC
python scripts/run_regression_tests.py

# Check PYTHONPATH
echo $PYTHONPATH

# Or set explicitly
export PYTHONPATH="${PYTHONPATH}:/path/to/MIESC"
```

#### 2. Slither Not Found

**Symptom**:
```
❌ FAIL: Slither not installed
```

**Solution**:
```bash
# Install Slither
pip install slither-analyzer

# Verify installation
slither --version
```

#### 3. Test Contract Missing

**Symptom**:
```
❌ FAIL: Test contract not found
```

**Solution**:
```bash
# Ensure examples directory exists
ls -la examples/

# Create test contract if missing
cat > examples/vulnerable_bank.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
EOF
```

#### 4. MCP Context Bus Errors

**Symptom**:
```
❌ FAIL: MCP Context Bus test failed
```

**Solution**:
```bash
# Check MCP module structure
ls -la src/mcp/

# Ensure __init__.py exists
touch src/mcp/__init__.py

# Verify imports
python -c "from src.mcp.context_bus import get_context_bus; print('OK')"
```

---

## Adding New Tests

### Step 1: Define Test Method

Add to `RegressionTestSuite` class in `scripts/run_regression_tests.py`:

```python
def test_my_new_feature(self) -> bool:
    """Test description here"""
    try:
        # Your test logic
        from src.my_module import MyClass
        obj = MyClass()
        assert obj.method() == expected_value

        return {"success": True, "details": "Feature working"}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

### Step 2: Add to Test Runner

In `run_all()` method:

```python
print("\n" + "="*64)
print("PHASE X: My New Tests")
print("="*64)

self.run_test("My new feature", self.test_my_new_feature, critical=True)
```

### Step 3: Document in This Guide

Add to [Test Coverage](#test-coverage) section.

---

## Test Maintenance Checklist

### After Major Refactoring

- [ ] Run full regression suite: `python scripts/run_regression_tests.py --mode full`
- [ ] Update test expectations if behavior intentionally changed
- [ ] Add new tests for new functionality
- [ ] Update this documentation

### Before Releases

- [ ] Run full suite on clean environment
- [ ] Verify all external tools are latest versions
- [ ] Check CI/CD pipeline passes
- [ ] Review and archive test results

### Continuous Monitoring

- [ ] Weekly automated full test runs
- [ ] Track test execution times (detect performance regressions)
- [ ] Monitor flaky tests (fix or quarantine)
- [ ] Keep dependencies updated

---

## Performance Benchmarks

Expected test durations (on standard hardware):

| Mode | Duration | Tests | Use Case |
|------|----------|-------|----------|
| Fast | ~5 min | 8 critical | Pre-commit |
| Critical | ~10 min | 15-20 | Pre-PR |
| Full | ~30 min | 30-40 | Pre-release |

Hardware reference:
- CPU: Intel i7 or equivalent
- RAM: 16GB
- Disk: SSD

---

## Contact & Support

**Maintainer**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Repository**: https://github.com/fboiero/MIESC

For issues related to testing:
1. Check [Troubleshooting](#troubleshooting) section
2. Review test logs in `tests/regression_results.json`
3. Open issue with full error output and environment details

---

**Last Updated**: October 2025
**Document Version**: 1.0
