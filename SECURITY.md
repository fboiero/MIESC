# Security Policy

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

---

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 4.x.x   | :white_check_mark: | Current release, actively maintained |
| 3.x.x   | :white_check_mark: | Security fixes only |
| 2.x.x   | :x:                | End of life |
| < 2.0   | :x:                | End of life |

---

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Contact

**Email**: fboiero@frvm.utn.edu.ar

**Subject Line**: `[SECURITY] MIESC - Brief description`

### What to Include

1. **Description**: Clear explanation of the vulnerability
2. **Impact**: Potential security impact
3. **Steps to Reproduce**: Detailed reproduction steps
4. **Affected Versions**: Which versions are affected
5. **Suggested Fix**: If you have one (optional)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgment | 48 hours |
| Severity assessment | 5 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

### Severity Levels

| Level | Response Time | Examples |
|-------|---------------|----------|
| Critical | 24-48 hours | Remote code execution, data breach |
| High | 1 week | Privilege escalation, authentication bypass |
| Medium | 2 weeks | Information disclosure, DoS |
| Low | 1 month | Minor issues, hardening |

---

## Security Measures

### Development Practices

| Practice | Implementation |
|----------|----------------|
| Code Review | All PRs require review |
| Static Analysis | Bandit, Semgrep on every commit |
| Dependency Scanning | Snyk, GitHub Dependabot |
| Secret Scanning | Pre-commit hooks |
| Signed Commits | GPG signing encouraged |

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
security-scan:
  - bandit (Python security linter)
  - semgrep (SAST)
  - safety (dependency vulnerabilities)
  - trivy (container scanning)
```

### Dependency Management

- Dependencies pinned to specific versions
- Weekly automated dependency updates
- Security advisories monitored via GitHub

---

## Security Architecture

### Data Flow Security

```
┌──────────────────────────────────────────────────────────┐
│                    User Environment                       │
│                                                          │
│  ┌─────────────┐                      ┌─────────────┐   │
│  │ Source Code │──────────────────────▶│   MIESC    │   │
│  │   (Input)   │                      │  (Local)    │   │
│  └─────────────┘                      └──────┬──────┘   │
│                                              │          │
│                                              ▼          │
│                                       ┌─────────────┐   │
│                                       │   Reports   │   │
│                                       │  (Output)   │   │
│                                       └─────────────┘   │
│                                                          │
│  ════════════════════════════════════════════════════   │
│  ║  All processing is local - No external data flow ║   │
│  ════════════════════════════════════════════════════   │
└──────────────────────────────────────────────────────────┘
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Malicious contracts | Sandboxed tool execution |
| Dependency attacks | Pinned versions, security scanning |
| Code injection | Input validation, no shell=True |
| Data exfiltration | Local processing only |
| Supply chain | Signed releases, reproducible builds |

---

## Secure Usage Guidelines

### For Users

1. **Verify Downloads**
   ```bash
   # Verify release signature (when available)
   gpg --verify miesc-4.0.0.tar.gz.asc
   ```

2. **Use Virtual Environments**
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Keep Updated**
   ```bash
   pip install --upgrade miesc
   ```

4. **Review AI Outputs**
   - AI-generated analysis may contain errors
   - Always verify critical findings manually

### For Developers

1. **Sign Your Commits**
   ```bash
   git config --global commit.gpgsign true
   ```

2. **Run Security Checks Locally**
   ```bash
   make security-check
   # or
   bandit -r src/
   safety check
   ```

3. **Never Commit Secrets**
   - Use environment variables
   - Check `.gitignore` includes sensitive files

---

## Known Security Considerations

### AI Components

| Component | Consideration | Mitigation |
|-----------|---------------|------------|
| Local LLM (Ollama) | Model may generate incorrect analysis | Human review required |
| Optional Cloud AI | Data sent to third party | Opt-in only, documented |

### Third-Party Tools

| Tool | Security Note |
|------|---------------|
| Slither | Executes Solidity compiler |
| Mythril | Symbolic execution (sandboxed) |
| Echidna | Fuzzing (sandboxed) |
| Certora | Cloud service (optional) |

### Output Handling

- Reports may contain sensitive contract logic
- Secure storage of analysis results is user responsibility
- Avoid sharing reports publicly without review

---

## Incident Response

### If You Suspect a Breach

1. **Isolate**: Stop using affected version
2. **Report**: Contact security email immediately
3. **Preserve**: Keep logs and evidence
4. **Update**: Apply patches when available

### Our Response Process

1. Triage and assess severity
2. Develop and test fix
3. Release security update
4. Notify affected users (if applicable)
5. Publish security advisory
6. Post-mortem analysis

---

## Security Advisories

Security advisories are published via:

- GitHub Security Advisories
- Release notes
- Direct notification (critical issues)

**Advisory Archive**: [github.com/fboiero/MIESC/security/advisories](https://github.com/fboiero/MIESC/security/advisories)

---

## Bug Bounty

Currently, MIESC does not have a formal bug bounty program. However, we recognize and acknowledge security researchers who responsibly disclose vulnerabilities.

**Recognition**:
- Credit in SECURITY.md
- Credit in release notes
- Recommendation letters (upon request)

---

## Compliance

MIESC development follows security best practices aligned with:

- OWASP Secure Coding Practices
- NIST SP 800-218 (Secure Software Development Framework)
- CIS Controls (where applicable)

---

## Contact

**Security Issues**: fboiero@frvm.utn.edu.ar

**Response Time**: 48 hours (business days)

**PGP Key**: Available upon request

---

*Last Updated: December 2024*
