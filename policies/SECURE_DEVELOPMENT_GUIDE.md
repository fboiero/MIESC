# Secure Development Guide - MIESC

**Version:** 1.0.0
**Audience:** MIESC Developers and Contributors
**Alignment:** NIST SSDF, OWASP Top 10, CWE Top 25

---

## 🎯 Purpose

This guide provides practical secure coding standards for MIESC development to prevent common vulnerabilities and ensure code quality.

---

## 🔐 Secure Coding Principles

### 1. Input Validation

**Rule:** Never trust user input

```python
# ❌ BAD: No validation
def analyze_contract(contract_path: str):
    with open(contract_path, 'r') as f:  # Path traversal risk!
        return f.read()

# ✅ GOOD: Validate and sanitize
def analyze_contract(contract_path: str):
    # Validate path
    path = Path(contract_path).resolve()
    if not path.exists() or not path.is_file():
        raise ValueError("Invalid contract path")
    if path.suffix != ".sol":
        raise ValueError("Only .sol files allowed")

    # Safe to proceed
    return path.read_text()
```

### 2. Command Injection Prevention

**Rule:** Never use `shell=True`, always validate commands

```python
# ❌ BAD: Shell injection risk
subprocess.run(f"slither {contract_path}", shell=True)  # DANGEROUS!

# ✅ GOOD: Use list arguments
subprocess.run(["slither", contract_path], shell=False, timeout=300)
```

### 3. Secrets Management

**Rule:** No hardcoded credentials

```python
# ❌ BAD: Hardcoded API key
OPENAI_API_KEY = "sk-1234567890abcdef"  # NEVER DO THIS!

# ✅ GOOD: Use environment variables
import os
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable required")
```

### 4. Path Traversal Protection

**Rule:** Validate all file paths

```python
# ❌ BAD: No validation
def read_report(filename: str):
    return open(filename).read()  # Can read /etc/passwd!

# ✅ GOOD: Restrict to safe directory
from pathlib import Path
def read_report(filename: str):
    base_dir = Path("analysis/results")
    filepath = (base_dir / filename).resolve()

    # Ensure path is within base_dir
    if not str(filepath).startswith(str(base_dir.resolve())):
        raise ValueError("Path traversal attempt detected")

    return filepath.read_text()
```

### 5. SQL Injection Prevention (If using databases)

**Rule:** Use parameterized queries

```python
# ❌ BAD: String concatenation
cursor.execute(f"SELECT * FROM findings WHERE id = {user_id}")

# ✅ GOOD: Parameterized query
cursor.execute("SELECT * FROM findings WHERE id = ?", (user_id,))
```

### 6. Error Handling

**Rule:** Don't leak sensitive information in errors

```python
# ❌ BAD: Exposes system details
try:
    process_contract()
except Exception as e:
    return {"error": str(e)}  # May leak paths, credentials

# ✅ GOOD: Generic errors, log details
try:
    process_contract()
except FileNotFoundError:
    logger.error("Contract not found", exc_info=True)
    return {"error": "Contract not found"}
except Exception as e:
    logger.error("Unexpected error", exc_info=True)
    return {"error": "Internal server error"}
```

---

## 📦 Dependency Security

### Dependency Selection Criteria

✅ **Use if:**
- Active maintenance (commits within 6 months)
- Security track record (no critical CVEs)
- Popular (>100 stars, used by reputable projects)
- Well-documented

❌ **Avoid if:**
- Unmaintained (>1 year no updates)
- Known vulnerabilities (check pip-audit)
- Suspicious (typosquatting, unclear purpose)

### Dependency Audit Workflow

```bash
# 1. Check for vulnerabilities
pip-audit

# 2. Review dependencies
pip list --outdated

# 3. Update with care
pip install --upgrade <package>

# 4. Pin versions
pip freeze > requirements.txt

# 5. Test after updates
pytest tests/
```

---

## 🧪 Testing Requirements

### Minimum Coverage

- **Unit Tests:** 85% minimum
- **Integration Tests:** Critical paths 100%
- **Security Tests:** All input validation paths

### Test Naming Convention

```python
def test_[function_name]_[scenario]_[expected_result]:
    """Test that [function] [does what] when [condition]"""
    pass

# Examples:
def test_scan_contract_valid_input_returns_findings():
    pass

def test_scan_contract_invalid_path_raises_error():
    pass
```

---

## 🔍 Code Review Checklist

### Security Review

- [ ] No hardcoded secrets
- [ ] Input validation present
- [ ] Command injection prevented
- [ ] Path traversal protected
- [ ] Error handling doesn't leak info
- [ ] Dependencies are pinned versions
- [ ] SAST findings addressed

### Quality Review

- [ ] Tests added/updated
- [ ] Coverage meets 85% minimum
- [ ] Type hints present
- [ ] Docstrings for public functions
- [ ] Logging for errors
- [ ] No commented-out code

---

## 🚀 Pre-Commit Workflow

```bash
# 1. Format code
black src/

# 2. Lint
ruff check src/ --fix
flake8 src/

# 3. Type check
mypy src/ --ignore-missing-imports

# 4. Security scan
bandit -r src/

# 5. Run tests
pytest tests/ --cov=src --cov-fail-under=85

# 6. Commit only if all pass
git add .
git commit -m "feat: description"
```

**Automated:** Install pre-commit hooks (see `.pre-commit-config.yaml`)

---

## 🛡️ Common Vulnerabilities to Avoid

### CWE Top 25 Relevant to Python

| CWE ID | Vulnerability | Prevention |
|--------|---------------|------------|
| CWE-79 | XSS | Escape output, use templating |
| CWE-89 | SQL Injection | Parameterized queries |
| CWE-20 | Improper Input Validation | Validate all inputs |
| CWE-78 | OS Command Injection | Avoid `shell=True` |
| CWE-22 | Path Traversal | Validate file paths |
| CWE-352 | CSRF | Use tokens for state-changing ops |
| CWE-94 | Code Injection | Never use `eval()` |
| CWE-798 | Hardcoded Credentials | Use env vars |

---

## 📚 Resources

1. **OWASP Secure Coding Practices:** https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
2. **Python Security Best Practices:** https://python.readthedocs.io/en/latest/library/security_warnings.html
3. **CWE Top 25:** https://cwe.mitre.org/top25/
4. **NIST SSDF:** https://csrc.nist.gov/publications/detail/sp/800-218/final

---

**Version:** 1.0.0
**Last Updated:** 2025-01-01
**Maintainer:** Fernando Boiero - UNDEF
