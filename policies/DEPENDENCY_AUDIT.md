# Dependency Audit Policy

**Version:** 1.0
**Framework:** NIST SP 800-218 (PW.4), ISO 27001 (A.8.8)
**Effective Date:** 2025-01-18

---

## 🎯 Purpose

This policy establishes requirements for managing third-party dependencies to prevent supply chain attacks and ensure software integrity in the MIESC project.

---

## 📋 Policy Statements

### 1. Dependency Selection

**Requirements:**
- Use only dependencies from trusted sources (PyPI official repository)
- Prefer dependencies with:
  - Active maintenance (commits within last 6 months)
  - Security track record (no known critical CVEs)
  - Clear licensing (GPL-compatible)
  - Adequate documentation

### 2. Version Pinning

**Requirements:**
- All dependencies MUST be pinned to specific versions in `requirements.txt`
- Format: `package==X.Y.Z` (exact version)
- Rationale: Reproducibility and security

**Example:**
```
# ✅ GOOD: Pinned versions
numpy==1.24.3
pandas==2.0.2
flask==2.3.2

# ❌ BAD: Unpinned versions
numpy
pandas>=2.0
flask~=2.3
```

### 3. Vulnerability Scanning

**Requirements:**
- Run `pip-audit` before every major release
- Run automated scan weekly via CI/CD
- Critical vulnerabilities (CVSS ≥ 9.0) MUST be fixed within 24 hours
- High vulnerabilities (CVSS ≥ 7.0) MUST be fixed within 7 days

**Tools:**
- `pip-audit` - OSV database scanning
- Dependabot - Automated pull requests
- GitHub Security Advisories - Vulnerability alerts

### 4. Dependency Updates

**Process:**
1. Review change logs for security fixes
2. Test in isolated environment
3. Run full test suite (≥85% coverage)
4. Update `requirements.txt` with new pinned version
5. Document in `CHANGELOG.md`

**Frequency:**
- Security updates: Immediate
- Feature updates: Monthly review
- Major version updates: Quarterly evaluation

### 5. License Compliance

**Requirements:**
- All dependencies MUST have compatible licenses
- Approved licenses:
  - MIT
  - Apache 2.0
  - BSD 3-Clause
  - GPL-3.0 (matches MIESC license)

**Prohibited licenses:**
- Proprietary/commercial licenses
- Copyleft licenses incompatible with GPL-3.0

---

## 🛠️ Implementation

### Automated Scanning

```bash
# Install pip-audit
pip install pip-audit

# Run vulnerability scan
pip-audit --format=json --output=audit_report.json

# Check for critical vulnerabilities
pip-audit --vulnerability-service=osv
```

### CI/CD Integration

```yaml
# .github/workflows/secure-dev-pipeline.yml
dependency-audit:
  runs-on: ubuntu-latest
  steps:
    - name: Run pip-audit
      run: |
        pip install pip-audit
        pip-audit --format=json --output=pip-audit-report.json

    - name: Fail on critical vulnerabilities
      run: |
        CRITICAL=$(jq '.dependencies | map(select(.vulns[].severity == "CRITICAL")) | length' pip-audit-report.json)
        if [ "$CRITICAL" -gt 0 ]; then
          echo "❌ Critical vulnerabilities found: $CRITICAL"
          exit 1
        fi
```

### PolicyAgent Integration

The PolicyAgent automatically checks:
- **DEP-001:** Dependency vulnerability audit (pip-audit)
- **DEP-002:** Version pinning validation

---

## 📊 Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Critical vulnerabilities** | 0 | pip-audit scan |
| **High vulnerabilities** | ≤ 2 | pip-audit scan |
| **Unpinned dependencies** | 0 | requirements.txt analysis |
| **Dependency update lag** | ≤ 30 days | Last update timestamp |
| **License compliance** | 100% | Manual review |

---

## 🚨 Incident Response

### Critical Vulnerability Discovered

1. **Detection:** Automated pip-audit or GitHub Security Advisory
2. **Triage:** Assess impact on MIESC (within 2 hours)
3. **Remediation:**
   - If patch available: Update immediately
   - If no patch: Evaluate alternatives or mitigation
4. **Testing:** Run full test suite
5. **Deployment:** Emergency release if in production
6. **Documentation:** Update CHANGELOG.md

### Example: Log4Shell-style Event

```
Time: T+0h    - Vulnerability announced (CVE-YYYY-XXXXX)
Time: T+1h    - MIESC team notified by GitHub Security Advisory
Time: T+2h    - Impact assessment complete (dependency X affected)
Time: T+4h    - Patch released by upstream (version X.Y.Z+1)
Time: T+6h    - MIESC updated, tested, released (emergency v3.2.1)
Time: T+24h   - Post-mortem document created
```

---

## 📚 Approved Dependencies

### Core Dependencies (as of v3.2.0)

| Package | Version | Purpose | License | Risk Level |
|---------|---------|---------|---------|------------|
| **slither-analyzer** | 0.10.0 | Smart contract analysis | AGPL-3.0 | Low |
| **mythril** | 0.24.0 | Symbolic execution | MIT | Low |
| **openai** | 1.0.0 | AI correlation | MIT | Medium (API) |
| **flask** | 2.3.2 | MCP REST adapter | BSD-3-Clause | Low |
| **pytest** | 7.4.0 | Testing framework | MIT | Low |

### Development Dependencies

| Package | Version | Purpose | License | Risk Level |
|---------|---------|---------|---------|------------|
| **bandit** | 1.7.6 | SAST | Apache-2.0 | Low |
| **ruff** | 0.1.14 | Linting | MIT | Low |
| **black** | 24.1.1 | Formatting | MIT | Low |
| **mypy** | 1.8.0 | Type checking | MIT | Low |

---

## 🔄 Review Process

### Quarterly Dependency Review

**Checklist:**
- [ ] Run `pip list --outdated`
- [ ] Review CVE databases for known vulnerabilities
- [ ] Check for abandoned packages (no commits in 12 months)
- [ ] Evaluate alternative packages if needed
- [ ] Update approved dependencies list
- [ ] Document decisions in meeting minutes

---

## 📖 References

1. **NIST SP 800-218** - Practice PW.4 (Review software components)
2. **ISO/IEC 27001:2022** - Control A.8.8 (Management of technical vulnerabilities)
3. **OWASP Dependency-Check** - https://owasp.org/www-project-dependency-check/
4. **OSV Database** - https://osv.dev/
5. **PyPI Security** - https://pypi.org/security/

---

**Policy Owner:** Fernando Boiero
**Review Frequency:** Quarterly
**Last Reviewed:** 2025-01-18
**Next Review:** 2025-04-18
