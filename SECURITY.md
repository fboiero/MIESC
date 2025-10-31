# 🔒 Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take security seriously. If you discover a security vulnerability in MIESC Agent Protocol, please report it responsibly.

### How to Report

**Email:** [email protected]

**Please include:**
- Description of the vulnerability
- Detailed steps to reproduce the issue
- Potential impact and severity assessment
- Proof of concept (if available)
- Suggested fix or mitigation (if you have one)
- Your contact information for follow-up

### What to Expect

- **Acknowledgment**: We'll respond within **48 hours** to confirm receipt
- **Assessment**: We'll assess the vulnerability within **5 business days**
- **Updates**: We'll keep you informed of our progress
- **Fix**: Critical vulnerabilities will be patched within **7 days**
- **Credit**: With your permission, we'll credit you in the security advisory

### Scope

**In Scope:**
- MIESC core system (`src/core/`, `src/orchestrator.py`)
- Agent protocol implementation (`src/core/agent_protocol.py`)
- MCP server (`mcp_server.py`)
- Web interface and GitHub Pages site
- Built-in agents (`src/agents/`)
- Authentication and authorization mechanisms
- Data handling and storage
- Dependency vulnerabilities

**Out of Scope:**
- Third-party security tools (Slither, Mythril, etc.)
- User-created agents (unless they expose MIESC vulnerabilities)
- Social engineering attacks
- Physical attacks
- Denial of service (unless exploitable by design flaw)

### Responsible Disclosure

We follow responsible disclosure principles:

1. **Private Disclosure**: Report privately to us first
2. **Coordination**: Work with us on disclosure timeline
3. **Public Disclosure**: After fix is released and users have time to update
4. **CVE Assignment**: For critical vulnerabilities, we'll request a CVE

**Please do NOT:**
- Exploit the vulnerability beyond proof-of-concept
- Access or modify user data
- Disrupt MIESC services
- Share vulnerability details publicly before coordinated disclosure

---

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Status                          |
| ------- | ------------------ | ------------------------------- |
| 2.x.x   | ✅ Yes            | Active development              |
| 1.5.x   | ⚠️ Limited        | Security fixes only             |
| 1.4.x   | ⚠️ Limited        | Critical security fixes only    |
| < 1.4   | ❌ No             | No longer supported             |

**Recommendation:** Always use the latest stable version (2.x.x).

### Version Support Timeline

- **Active Support**: Latest major version (2.x.x)
  - Feature updates, bug fixes, security patches

- **Security Support**: Previous major version (1.x.x)
  - Security patches only, for 6 months after new major release

- **End of Life**: Older versions
  - No updates, users should upgrade

---

## Security Features

MIESC implements multiple security layers:

### 1. Agent Isolation
- Agents run in separate processes (future: containers)
- Resource limits prevent denial of service
- Filesystem access restrictions

### 2. Input Validation
- All contract paths are sanitized
- File size limits enforced (max 10MB)
- Solidity syntax validation before analysis
- Prevention of directory traversal attacks

### 3. Dependency Management
- All dependencies pinned to specific versions
- Regular security audits with `pip-audit`
- Minimal dependencies to reduce attack surface
- No execution of untrusted code

### 4. MCP Security
- Authentication required for MCP server
- Rate limiting on analysis requests
- Input sanitization on all MCP tool calls
- Secure communication protocols

### 5. Web Security
- XSS protection in dashboard
- CSRF tokens on forms
- Content Security Policy headers
- No inline JavaScript execution

---

## Security Best Practices for Users

### For Auditors Using MIESC

✅ **DO:**
- Run MIESC in isolated environments
- Keep MIESC updated to latest version
- Review analysis results manually
- Use official agents from trusted sources
- Verify agent signatures (when available)

❌ **DON'T:**
- Run as root/administrator
- Analyze untrusted contracts on production systems
- Install unverified third-party agents
- Share sensitive contracts publicly
- Disable security features

### For Agent Developers

✅ **DO:**
- Validate all inputs
- Use subprocess timeouts
- Handle errors gracefully
- Document security considerations
- Follow the SecurityAgent protocol strictly

❌ **DON'T:**
- Execute arbitrary code from contracts
- Make unvalidated network requests
- Store sensitive data in logs
- Use eval() or exec() on untrusted input
- Bypass protocol security checks

### For Protocol Teams (CI/CD Integration)

✅ **DO:**
- Run MIESC in containerized CI/CD
- Use read-only filesystem mounts
- Set resource limits (CPU, memory, time)
- Review analysis results before deployment
- Keep secrets out of contract code

❌ **DON'T:**
- Run with admin privileges
- Store results in public locations
- Deploy contracts with unresolved criticals
- Use default configurations in production
- Skip manual review of findings

---

## Known Security Considerations

### 1. Malicious Contracts

**Risk:** Analyzing contracts designed to exploit analysis tools.

**Mitigation:**
- Never execute contract code
- Use static analysis only
- Sandboxed environments for dynamic analysis
- Timeout enforcement
- Resource limits

### 2. Supply Chain Attacks

**Risk:** Compromised dependencies introducing vulnerabilities.

**Mitigation:**
- Pinned dependency versions
- Regular `pip-audit` scans
- Minimal dependency tree
- Reproducible builds
- Verification of critical dependencies

### 3. Agent Marketplace Risks

**Risk:** Malicious agents in future marketplace.

**Mitigation (Planned v2.1):**
- Code signing and verification
- Community trust ratings
- Sandboxed agent execution
- Permission system
- Automated security scanning

### 4. False Negatives

**Risk:** Missing critical vulnerabilities.

**Mitigation:**
- Multi-agent analysis (defense-in-depth)
- Regular updates to detection patterns
- Community-driven agent ecosystem
- Human review of findings
- Continuous improvement via feedback

---

## Security Updates and Advisories

### Where to Find Security Updates

- **GitHub Security Advisories**: https://github.com/fboiero/MIESC/security/advisories
- **Releases Page**: https://github.com/fboiero/MIESC/releases
- **Changelog**: [CHANGELOG.md](./CHANGELOG.md)
- **Email Notifications**: Watch the repository

### Notification Channels

Subscribe to security updates:

1. **GitHub Watch**: Click "Watch" → "Custom" → "Security alerts"
2. **Release Notifications**: Watch releases on GitHub
3. **RSS Feed**: Subscribe to releases RSS
4. **Discord**: Join our Discord for announcements

### CVE Assignment

For vulnerabilities receiving CVEs:
- Published on GitHub Security Advisory
- Listed in National Vulnerability Database (NVD)
- Linked in MIESC documentation
- CVSS score provided

---

## Security Audit History

### External Audits

| Date       | Auditor            | Scope         | Findings | Status    |
| ---------- | ------------------ | ------------- | -------- | --------- |
| 2025-09-15 | Internal Team      | Core Protocol | 3 Low    | Fixed v2.0.1 |
| 2025-11-20 | (Planned)          | Full System   | TBD      | Scheduled |

### Penetration Testing

Periodic penetration testing:
- **Last Test**: September 2025
- **Next Test**: December 2025
- **Scope**: MCP server, web interface, agent isolation
- **Findings**: Available on request for verified researchers

---

## Bug Bounty Program

### Status: Coming Soon (Q1 2026)

We're planning a bug bounty program to reward security researchers:

**Anticipated Rewards:**
- Critical: $500 - $2,000
- High: $200 - $500
- Medium: $50 - $200
- Low: Recognition + Swag

**Program Details:** TBA

**Interested?** Email [email protected] to be notified when program launches.

---

## Security Research

We encourage security research on MIESC:

✅ **Allowed:**
- Security testing on your own installations
- Static analysis of MIESC code
- Testing with your own contracts
- Responsible disclosure of findings

❌ **Not Allowed:**
- Attacking public MIESC instances
- Testing on others' MIESC installations without permission
- Accessing other users' data
- Disrupting services

### Academic Research

Using MIESC for security research? We'd love to hear about it!

**Contact:** [email protected]

**We can provide:**
- Technical guidance
- Test datasets
- Collaboration on papers
- Citation information

---

## Compliance and Standards

MIESC follows security standards:

- **OWASP Top 10**: Regular assessment against web vulnerabilities
- **CWE**: Common Weakness Enumeration for categorization
- **CVSS**: Common Vulnerability Scoring System for severity
- **ISO 27001**: Information security management principles

---

## Security Contact

**Primary Contact:** Fernando Boiero
**Email:** [email protected]
**PGP Key:** (Available on request)

**Response Times:**
- Critical vulnerabilities: 24-48 hours
- High severity: 48-72 hours
- Medium/Low severity: 5-7 business days

**Alternative Contact:**
GitHub: @fboiero

---

## Acknowledgments

We thank the following security researchers for responsible disclosure:

<!-- List will be updated as vulnerabilities are reported and fixed -->

*No vulnerabilities reported yet. Be the first!*

---

## Legal

**Safe Harbor:** We commit to:
- Not pursue legal action against security researchers who follow this policy
- Work with you to understand and fix the issue
- Credit you for the discovery (with your permission)

**Out of Scope:** Activities outside this policy may be subject to legal action.

---

## Latest Security Scan Results (v3.3.0)

### SAST Scan (Bandit v1.8.6) - October 20, 2025

```
Total issues: 9
├─ Critical: 0 ✅
├─ High: 0 ✅
├─ Medium: 2 ✅ (mitigated)
└─ Low: 7 ℹ️ (informational)

Lines of code scanned: 1,559
Security-clean files: 5/10
```

**Medium Issues (Mitigated):**
- CWE-605: Hardcoded bind to 0.0.0.0
  - **Status:** ✅ Fixed in v3.3.0
  - **Mitigation:** Default changed to 127.0.0.1, configurable via MIESC_HOST environment variable

**Low Issues (Informational):**
- Try-except-pass patterns in cleanup code
  - **Status:** ✅ Improved in v3.3.0
  - **Mitigation:** Added proper exception logging with specific exception types
- Subprocess module usage warnings
  - **Status:** ✅ Already mitigated
  - **Mitigation:** Whitelist validation, no shell=True, comprehensive input validation

### Dependency Scan (pip-audit v2.9.0) - October 20, 2025

**Critical Updates Applied:**
- ✅ aiohttp: 3.8.4 → 3.13.1 (11 CVEs resolved)
- ✅ astropy: 5.1 → 6.0.1 (RCE vulnerability resolved)
- ✅ black: 22.6.0 → 25.9.0 (dev dependency)

**Status:** All critical vulnerabilities in core MIESC code resolved.

For detailed security analysis, see [SECURITY_SCAN_REPORT.md](./SECURITY_SCAN_REPORT.md).

### Test Coverage - October 20, 2025

```
Total Tests: 97 (100% pass rate)
├─ Unit Tests: 54
├─ API Integration Tests: 23
└─ CLI Integration Tests: 20

Code Coverage: 72-95% across core modules
Security Test Coverage: Comprehensive input validation tests
```

### Production Readiness

**Security Checklist Status:**
- ✅ SAST scanning (Bandit) - 0 critical/high issues
- ✅ Dependency scanning (pip-audit) - Critical updates applied
- ✅ Input validation - Comprehensive (315 LOC, zero issues)
- ✅ Secure defaults - Host binding defaults to 127.0.0.1
- ✅ Exception logging - Proper error handling implemented
- ✅ CI/CD security automation - GitHub Actions configured
- ✅ Security documentation - This policy and detailed reports

**Recommendation:** MIESC v3.3.0 is production-ready for deployment behind reverse proxy with proper firewall configuration.

---

**Last Updated:** October 20, 2025
**Policy Version:** 1.1
**MIESC Version:** 3.3.0

For questions about this policy: [email protected]
