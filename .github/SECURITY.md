# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MIESC, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email**: Send details to [fboiero@frvm.utn.edu.ar](mailto:fboiero@frvm.utn.edu.ar)
2. **Subject**: `[SECURITY] MIESC - Brief description`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development | Within 30 days |
| Public disclosure | After fix is released |

### Scope

In scope:
- MIESC framework code (`src/`, `miesc/`)
- Docker images (`docker/`)
- GitHub Action (`action.yml`)
- Web dashboard (`webapp/`)
- LLM prompt injection in security analysis pipeline

Out of scope:
- Third-party tools (Slither, Mythril, etc.) — report to their maintainers
- Vulnerabilities in contracts being analyzed (that's what MIESC detects)

### Supported Versions

| Version | Supported |
|---------|-----------|
| 5.1.x   | Yes       |
| < 5.0   | No        |

### Recognition

We acknowledge security researchers who responsibly disclose vulnerabilities in our CONTRIBUTORS.md and release notes.

## Security Best Practices

MIESC follows these security practices:
- Pre-commit hooks: Bandit (SAST), detect-secrets, Ruff
- CI/CD: Semgrep, pip-audit, safety checks
- Dependencies: Weekly vulnerability scanning
- Docker: Non-root user, minimal base image
- LLM: Local-first (Ollama), prompt sanitization
