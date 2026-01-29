# MIESC Testing Guide

This guide covers how to run tests, understand the test structure, and write new tests for MIESC.

## Quick Start

```bash
# Run all tests
make test

# Run tests without coverage (faster)
make test-quick

# Run only integration tests
pytest -m integration --no-cov

# Run a specific test file
pytest tests/test_integration_pipeline.py -v --no-cov
```

## Test Suite Overview

MIESC has a comprehensive test suite with **2800+ tests** covering:

| Category | Files | Tests | Description |
|----------|-------|-------|-------------|
| **Integration** | 5 | ~70 | End-to-end pipeline, reports, multichain |
| **Unit** | 45+ | ~2700 | Individual modules and functions |
| **Adapters** | 10+ | ~400 | Tool adapter functionality |
| **ML Pipeline** | 5+ | ~200 | Correlation, FP filtering, clustering |

## Running Tests

### Using Make (Recommended)

```bash
# Full test suite with coverage
make test

# Quick tests without coverage
make test-quick

# Generate HTML coverage report
make test-coverage
```

### Using Pytest Directly

```bash
# All tests
pytest tests/ --no-cov

# With verbose output
pytest tests/ -v --no-cov

# Stop on first failure
pytest tests/ -x --no-cov

# Run tests matching a pattern
pytest tests/ -k "reentrancy" --no-cov

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing
```

### Test Markers

MIESC uses pytest markers to categorize tests:

```bash
# Run only integration tests
pytest -m integration --no-cov

# Run only slow tests
pytest -m slow --no-cov

# Skip slow tests
pytest -m "not slow" --no-cov

# Run tests requiring external tools
pytest -m requires_tools --no-cov
```

## Test Structure

```
tests/
├── conftest.py                      # Shared fixtures
├── test_integration_pipeline.py     # CLI + aggregation + correlation + ML
├── test_integration_reports.py      # Report generation (JSON, MD, HTML, SARIF)
├── test_integration_multichain.py   # Multichain analysis
├── test_integration_benchmark.py    # Benchmark pipeline validation
├── test_integration.py              # General integration tests
├── test_core.py                     # Core modules (221 tests)
├── test_adapters.py                 # Tool adapters (341 tests)
├── test_correlation_engine.py       # Correlation engine
├── test_ml_pipeline.py              # ML pipeline
├── test_classic_patterns.py         # Pattern detection
└── ...                              # Other unit tests
```

## Integration Tests

The integration test suite validates the full MIESC pipeline end-to-end.

### test_integration_pipeline.py (21 tests)

Tests CLI commands, result aggregation, correlation engine, and ML pipeline.

**Test Classes:**

| Class | Tests | Description |
|-------|-------|-------------|
| `TestAuditPipelineCLI` | 6 | CLI commands via Click's CliRunner |
| `TestResultAggregation` | 4 | Multi-tool result aggregation and deduplication |
| `TestCorrelationEngineIntegration` | 5 | Cross-tool correlation with realistic data |
| `TestMLPipelineEndToEnd` | 4 | FP filtering, clustering, severity prediction |
| `TestCorrelationConvenienceFunction` | 2 | Convenience function tests |

**Example:**
```python
@pytest.mark.integration
class TestAuditPipelineCLI:
    def test_audit_quick_returns_json_output(self, cli_runner, vulnerable_contract):
        """Run audit quick and verify JSON output."""
        from miesc.cli.main import cli

        with patch('miesc.cli.main._run_tool') as mock_run:
            mock_run.return_value = {'tool': 'slither', 'findings': [...]}
            result = cli_runner.invoke(cli, ['audit', 'quick', vulnerable_contract, '-o', 'out.json'])
            assert result.exit_code == 0
```

### test_integration_reports.py (11 tests)

Tests report generation across all formats.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestReportGeneration` | 7 | JSON, Markdown, HTML, SARIF validation |
| `TestReportExporterUnified` | 3 | Unified exporter for multiple formats |
| `TestHTMLReportSave` | 1 | HTML file persistence |

**Validates:**
- JSON reports have required keys (metadata, findings, summary, risk_score)
- Markdown reports have proper sections and tables
- HTML reports have valid structure, CSS, finding cards
- SARIF reports conform to SARIF 2.1.0 schema
- Empty findings handled gracefully
- Critical findings highlighted correctly

### test_integration_multichain.py (10 tests)

Tests end-to-end multichain analysis.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestMultichainPipeline` | 6 | Chain detection → adapter → analysis → report |
| `TestChainTypeHelpers` | 4 | Chain type utilities and mappings |

**Validates:**
- `.sol` files detect as EVM chain
- Aiken contracts use Cardano adapter
- Anchor programs use Solana adapter
- Vulnerability mappings work across chains
- Findings share normalized format

### test_integration_benchmark.py (9 tests)

Tests the SolidiFI benchmark pipeline.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestBenchmarkPipeline` | 5 | Ground truth matching, metrics calculation |
| `TestBenchmarkGroundTruthEdgeCases` | 4 | Edge cases in TP/FP/FN matching |

**Validates:**
- Precision/Recall/F1 calculation
- Ground truth matching with tolerance
- Cross-validation confidence adjustment
- Category breakdown by vulnerability type

## Available Fixtures

Fixtures are defined in `tests/conftest.py`:

### Contract Fixtures

```python
@pytest.fixture
def vulnerable_contract(tmp_path):
    """Creates a temporary vulnerable Solidity contract."""
    # Returns path to VulnerableBank.sol with reentrancy vulnerability
```

```python
@pytest.fixture
def simple_contract():
    """Returns simple contract source code as string."""
```

### Tool Result Fixtures

```python
@pytest.fixture
def sample_tool_result():
    """Sample tool result dictionary."""
    return {
        'tool': 'slither',
        'status': 'success',
        'findings': [...]
    }
```

```python
@pytest.fixture
def multi_tool_findings():
    """Findings from multiple tools (slither, mythril, solhint)."""
    # Returns dict with findings from 3 tools for cross-validation testing
```

### Component Fixtures

```python
@pytest.fixture
def cli_runner():
    """Click CLI test runner."""
    from click.testing import CliRunner
    return CliRunner()
```

```python
@pytest.fixture
def correlation_engine():
    """Pre-configured SmartCorrelationEngine."""
    from src.ml.correlation_engine import SmartCorrelationEngine
    return SmartCorrelationEngine(min_tools_for_validation=2)
```

```python
@pytest.fixture
def report_findings():
    """List of Finding objects for report generation tests."""
```

```python
@pytest.fixture
def report_metadata():
    """AuditMetadata object for report tests."""
```

## Writing New Tests

### Unit Test Example

```python
# tests/test_my_module.py
import pytest
from src.my_module import MyClass

class TestMyClass:
    """Tests for MyClass."""

    def test_basic_functionality(self):
        """Test basic method works."""
        obj = MyClass()
        result = obj.process("input")
        assert result == "expected"

    def test_edge_case(self):
        """Test edge case handling."""
        obj = MyClass()
        with pytest.raises(ValueError):
            obj.process(None)
```

### Integration Test Example

```python
# tests/test_integration_my_feature.py
import pytest
from unittest.mock import patch, MagicMock

@pytest.mark.integration
class TestMyFeatureIntegration:
    """Integration tests for my feature."""

    def test_full_pipeline(self, vulnerable_contract, cli_runner):
        """Test complete pipeline from CLI to report."""
        from miesc.cli.main import cli

        # Mock external tools
        with patch('miesc.cli.main._run_tool') as mock_run:
            mock_run.return_value = {
                'tool': 'slither',
                'status': 'success',
                'findings': [{'type': 'reentrancy', 'severity': 'HIGH'}]
            }

            result = cli_runner.invoke(cli, ['scan', vulnerable_contract])
            assert result.exit_code == 0
```

### Using Markers

```python
import pytest

@pytest.mark.slow
def test_expensive_operation():
    """This test takes a long time."""
    pass

@pytest.mark.integration
def test_end_to_end():
    """This is an integration test."""
    pass

@pytest.mark.requires_tools
def test_with_slither():
    """This test requires Slither installed."""
    pass
```

## Mocking External Tools

Integration tests mock external tools to run without dependencies:

```python
from unittest.mock import patch

def test_with_mocked_tool(vulnerable_contract):
    with patch('miesc.cli.main._run_tool') as mock_run:
        # Configure mock return value
        mock_run.return_value = {
            'tool': 'slither',
            'contract': vulnerable_contract,
            'status': 'success',
            'findings': [
                {
                    'type': 'reentrancy',
                    'severity': 'HIGH',
                    'message': 'Reentrancy in withdraw()',
                    'location': {'file': 'test.sol', 'line': 15}
                }
            ],
            'execution_time': 1.5,
            'timestamp': '2026-01-27T00:00:00'
        }

        # Run test
        result = analyze_contract(vulnerable_contract)

        # Verify mock was called
        mock_run.assert_called_once()
```

## Test Coverage

MIESC targets **80% code coverage**. Check coverage with:

```bash
# Terminal report
pytest tests/ --cov=src --cov-report=term-missing

# HTML report
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html
```

### Coverage Configuration

Coverage settings are in `pyproject.toml`:

```toml
[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/__pycache__/*"]

[tool.coverage.report]
fail_under = 50  # Minimum coverage percentage
```

## Continuous Integration

Tests run automatically on every PR via GitHub Actions:

1. **Linting** - Black, Ruff, Mypy checks
2. **Unit Tests** - Full test suite with coverage
3. **Integration Tests** - End-to-end validation
4. **Security Scan** - Dependency and code scanning

### Running CI Checks Locally

```bash
# Run all CI checks
make ci

# Or individually:
make lint      # Linting
make test      # Tests
make security  # Security scan
```

## Troubleshooting

### Tests Hang During Collection

If pytest hangs during collection, kill any zombie processes:

```bash
pkill -f pytest
sleep 2
pytest tests/ --no-cov -q
```

### Import Errors

Ensure you're in the project root and have dependencies installed:

```bash
pip install -e ".[dev,test]"
```

### Slow Tests

Skip slow tests during development:

```bash
pytest -m "not slow" --no-cov
```

### Coverage Below Threshold

The test suite requires minimum 50% coverage. If coverage drops:

1. Check which files are missing coverage: `pytest --cov-report=term-missing`
2. Add tests for uncovered code paths
3. Or add files to coverage omit list if they're adapters/generated code

## Sample Contracts

Test contracts are available in:

- `tests/conftest.py` - Inline contract strings
- `examples/contracts/` - 13 Solidity contracts for testing

```python
# Access sample contracts in tests
def test_with_sample(vulnerable_contract):
    # vulnerable_contract is a path to VulnerableBank.sol
    assert vulnerable_contract.exists()
```

## Further Reading

- [CONTRIBUTING.md](../../CONTRIBUTING.md) - Contribution guidelines
- [QUICKSTART.md](./QUICKSTART.md) - Getting started guide
- [Architecture Decision Records](../adr/) - Design decisions
