# Test Strategy - MIESC

**Version:** 1.0.0
**Framework:** Test-Driven Development (TDD)
**Coverage Target:** 85% minimum, 90% goal
**Alignment:** NIST SSDF PW.8, ISO 27001 A.14.2.9

---

## 🎯 Testing Philosophy

**Principle:** "Write tests first, code second"

**Benefits:**
- Better design (testable code is good code)
- Confidence in refactoring
- Living documentation
- Fewer bugs in production

---

## 🔄 TDD Cycle (Red-Green-Refactor)

```
1. 🔴 RED: Write a failing test
   ↓
2. 🟢 GREEN: Write minimum code to pass
   ↓
3. 🔵 REFACTOR: Improve code quality
   ↓
Repeat
```

### Example TDD Workflow

```python
# Step 1: Write failing test
def test_correlate_findings_reduces_duplicates():
    """Test that AI correlation removes duplicate findings"""
    findings = [
        {"tool": "slither", "type": "reentrancy", "line": 42},
        {"tool": "mythril", "type": "reentrancy", "line": 42},  # Duplicate
    ]

    correlator = AICorrelator()
    result = correlator.correlate_findings(findings)

    assert len(result) == 1  # Should combine duplicates
    # TEST FAILS - correlate_findings() doesn't exist yet

# Step 2: Implement minimum code
class AICorrelator:
    def correlate_findings(self, findings):
        # Simplified: just return first finding
        return [findings[0]] if findings else []
    # TEST PASSES

# Step 3: Refactor for production
class AICorrelator:
    def correlate_findings(self, findings):
        # Real implementation with deduplication logic
        grouped = self._group_similar(findings)
        return [self._merge(group) for group in grouped]
    # TEST STILL PASSES
```

---

## 📊 Test Levels

### 1. Unit Tests (70% of tests)

**Scope:** Individual functions/classes in isolation

**Tools:**
- `pytest` - Test framework
- `pytest-mock` - Mocking
- `pytest-cov` - Coverage measurement

**Coverage Target:** 90% for core modules

**Example:**
```python
def test_calculate_risk_score():
    """Unit test for risk calculation"""
    engine = RiskEngine()
    score = engine._calculate_risk_score(
        exploitability=0.8,
        impact=0.9,
        likelihood=0.7,
        business_criticality=1.0
    )
    assert 7.0 <= score <= 10.0  # Expected range
```

### 2. Integration Tests (20% of tests)

**Scope:** Multiple components working together

**Coverage Target:** 80%

**Example:**
```python
def test_full_audit_workflow():
    """Integration test for complete audit"""
    miesc = MIESCCore()
    results = miesc.scan_contract("test.sol", tools=["slither"])

    assert "scan_timestamp" in results
    assert "total_findings" in results
    assert results["total_findings"] >= 0
```

### 3. End-to-End Tests (10% of tests)

**Scope:** Full user workflows via CLI or API

**Example:**
```bash
# Test complete audit via CLI
python src/miesc_cli.py run-audit test.sol --enable-ai -o output.json
assert output.json exists
assert output.json contains "compliance_score"
```

---

## 🎯 Coverage Requirements

### Minimum Coverage (85%)

**Must Cover:**
- All public functions
- All error handling paths
- All security-critical code
- All input validation

**Can Skip:**
- `if __name__ == "__main__"` blocks
- Debug/logging statements
- Third-party library wrappers

### Measuring Coverage

```bash
# Run tests with coverage
pytest --cov=src --cov-report=term-missing --cov-report=html

# View HTML report
open htmlcov/index.html

# Fail if below 85%
pytest --cov=src --cov-fail-under=85
```

---

## 🔐 Security Testing

### 1. Input Validation Tests

**Requirement:** Test all input boundaries

```python
def test_scan_contract_invalid_path_raises_error():
    """Test that invalid paths are rejected"""
    miesc = MIESCCore()

    with pytest.raises(FileNotFoundError):
        miesc.scan_contract("../../etc/passwd")  # Path traversal

def test_scan_contract_invalid_extension_raises_error():
    """Test that non-Solidity files are rejected"""
    with pytest.raises(ValueError):
        miesc.scan_contract("malicious.exe")
```

### 2. Authentication/Authorization Tests

```python
def test_mcp_request_requires_valid_api_key():
    """Test that API requires authentication"""
    adapter = MIESCMCPAdapter()
    response = adapter.handle_request({"method": "run_audit"})

    assert response["error"]["code"] == -32001  # Unauthorized
```

### 3. SAST Integration Tests

```python
def test_no_hardcoded_secrets_in_codebase():
    """Test that no secrets are hardcoded"""
    scanner = SecurityScanner()
    results = scanner.scan_secrets()

    assert results["secrets_found"] == 0
```

---

## 🚀 Shift-Left Testing

**Principle:** Test as early as possible in development cycle

### Developer Phase (Before Commit)

```bash
# Pre-commit hook runs:
1. Unit tests (fast, <5 seconds)
2. Linting
3. Type checking
4. Secret scanning
```

### CI/CD Phase (On Push/PR)

```bash
# GitHub Actions runs:
1. All unit tests
2. Integration tests
3. Coverage check (85% minimum)
4. SAST (Bandit, Semgrep)
5. Dependency audit
```

### Pre-Deployment Phase

```bash
# Manual validation:
1. End-to-end tests
2. Performance tests
3. Security review
4. Compliance validation
```

---

## 📈 Test Metrics

### Tracked Metrics

| Metric | Target | Current | Trend |
|--------|--------|---------|-------|
| Line Coverage | 85% | TBD | ↗️ |
| Branch Coverage | 80% | TBD | ↗️ |
| Test Pass Rate | 100% | TBD | ↗️ |
| Test Execution Time | <2 min | TBD | ↘️ |
| Flaky Tests | 0 | TBD | ↘️ |

### Reporting

**Location:** `analysis/test_reports/`

**Frequency:** Every CI/CD run

**Format:** HTML (pytest-html), JSON (pytest-json-report), XML (Cobertura)

---

## 🧪 Test Data Management

### Test Contracts

**Location:** `tests/fixtures/contracts/`

**Types:**
- `vulnerable/` - Known vulnerable contracts
- `safe/` - Secure reference contracts
- `edge_cases/` - Boundary condition tests

### Ground Truth

**Location:** `tests/fixtures/ground_truth.json`

**Format:**
```json
{
  "contract_name.sol": {
    "is_vulnerable": true,
    "vulnerabilities": [
      {"type": "reentrancy", "severity": "High", "line": 42}
    ]
  }
}
```

---

## 🔄 Continuous Improvement

### Test Review Process

**Frequency:** Weekly

**Questions:**
- Are tests still relevant?
- Can flaky tests be fixed?
- Are new features adequately tested?
- Can test execution time be reduced?

### Adding New Tests

**When to Add:**
- New feature implemented
- Bug fixed (regression test)
- Security vulnerability patched
- Edge case discovered

**Template:**
```python
def test_[feature]_[scenario]_[expected]:
    """
    Test that [feature] [does what] when [condition].

    Given: [setup]
    When: [action]
    Then: [assertion]
    """
    # Arrange
    setup_data()

    # Act
    result = function_under_test()

    # Assert
    assert result == expected
```

---

## 📚 References

1. **TDD by Example** - Kent Beck
2. **pytest Documentation:** https://docs.pytest.org/
3. **NIST SSDF PW.8:** Testing and Test Data
4. **ISO 27001 A.14.2.9:** System Acceptance Testing

---

**Version:** 1.0.0
**Last Updated:** 2025-01-01
**Maintainer:** Fernando Boiero - UNDEF
