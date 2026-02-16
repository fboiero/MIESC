# MIESC Security Audit Report

**Version:** 5.1.1
**Audit Date:** February 16, 2026
**Auditor:** Internal Security Review
**Classification:** Internal Use

---

## Executive Summary

### Overall Security Score: 8.2/10 (Strong)

| Category | Score | Status |
|----------|-------|--------|
| Secrets Management | 7.5/10 | Needs Fix |
| Input Validation | 9.5/10 | Excellent |
| Injection Protection | 9.0/10 | Excellent |
| Dependencies | 8.5/10 | Good |
| Docker Security | 8.0/10 | Good |
| LLM/AI Security | 9.5/10 | Excellent |
| CI/CD Security | 9.0/10 | Excellent |

### Risk Summary

| Severity | Count | Status |
|----------|-------|--------|
| **CRITICAL** | 2 | Requires Immediate Fix |
| **HIGH** | 2 | Fix This Sprint |
| **MEDIUM** | 8 | Fix Soon |
| **LOW** | 6 | Backlog |
| **INFO** | 5 | Best Practices |

---

## Table of Contents

1. [Critical Findings](#1-critical-findings)
2. [High Priority Findings](#2-high-priority-findings)
3. [Medium Priority Findings](#3-medium-priority-findings)
4. [Low Priority Findings](#4-low-priority-findings)
5. [Positive Security Controls](#5-positive-security-controls)
6. [Recommendations](#6-recommendations)
7. [Compliance Status](#7-compliance-status)
8. [Appendix](#8-appendix)

---

## 1. Critical Findings

### CRIT-001: Hardcoded Default Admin API Key

**Severity:** CRITICAL
**CVSS Score:** 9.1 (Critical)
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Location:**
- `src/licensing/admin_api.py:38`
- `docker/docker-compose.prod.yml:55`

**Vulnerable Code:**
```python
# src/licensing/admin_api.py:38
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY", "miesc-admin-secret-key")
```

```yaml
# docker/docker-compose.prod.yml:55
- MIESC_ADMIN_API_KEY=${MIESC_ADMIN_API_KEY:-miesc-admin-secret-key}
```

**Impact:**
- Unauthorized access to license administration API
- Potential license manipulation or bypass
- Default credential exposed in source code and Docker images

**Remediation:**
```python
# Option 1: Require explicit configuration
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY")
if not ADMIN_API_KEY:
    raise RuntimeError("MIESC_ADMIN_API_KEY environment variable is required")

# Option 2: Generate secure default at startup (not recommended for production)
import secrets
ADMIN_API_KEY = os.getenv("MIESC_ADMIN_API_KEY") or secrets.token_urlsafe(32)
```

```yaml
# docker-compose.prod.yml - Require variable
- MIESC_ADMIN_API_KEY=${MIESC_ADMIN_API_KEY:?ERROR: MIESC_ADMIN_API_KEY is required}
```

---

### CRIT-002: CORS Misconfiguration Allows All Origins

**Severity:** CRITICAL
**CVSS Score:** 8.6 (High)
**CWE:** CWE-942 (Overly Permissive Cross-domain Whitelist)

**Location:** `src/licensing/admin_api.py:28-35`

**Vulnerable Code:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # DANGEROUS: Allows any origin
    allow_credentials=True,        # DANGEROUS: Combined with * = CSRF risk
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Impact:**
- Cross-Site Request Forgery (CSRF) attacks possible
- Credential theft via malicious websites
- Session hijacking

**Remediation:**
```python
ALLOWED_ORIGINS = os.getenv("MIESC_ALLOWED_ORIGINS", "").split(",")
if not ALLOWED_ORIGINS or ALLOWED_ORIGINS == [""]:
    ALLOWED_ORIGINS = ["http://localhost:8501"]  # Default to local only

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)
```

---

## 2. High Priority Findings

### HIGH-001: Admin API Exposed Without Reverse Proxy

**Severity:** HIGH
**CWE:** CWE-284 (Improper Access Control)

**Location:** `docker/docker-compose.prod.yml:50-52`

**Issue:**
```yaml
admin-api:
  ports:
    - "5002:5002"  # Directly exposed to network
```

**Impact:** License administration API accessible without additional authentication layer.

**Remediation:**
- Remove direct port exposure
- Route through Nginx with authentication
- Implement IP allowlisting

---

### HIGH-002: SSRF Vulnerability in Marketplace Client

**Severity:** HIGH
**CVSS Score:** 7.5
**CWE:** CWE-918 (Server-Side Request Forgery)

**Location:** `src/plugins/marketplace.py:260-267`

**Vulnerable Code:**
```python
req = urllib.request.Request(
    self.index_url,  # User-controlled URL without validation
    headers={...},
)
with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
    data = json.loads(response.read().decode("utf-8"))
```

**Attack Vectors:**
- `http://localhost:8080/admin` - Internal service access
- `http://169.254.169.254/latest/meta-data/` - AWS metadata theft
- `http://192.168.1.1/config` - Internal network scanning

**Remediation:**
```python
def _validate_url(self, url: str) -> str:
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)

    # Enforce HTTPS
    if parsed.scheme != 'https':
        raise MarketplaceError("Only HTTPS URLs allowed")

    # Block private/reserved IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            raise MarketplaceError("Access to private IPs blocked")
    except ValueError:
        pass  # Hostname, not IP - OK

    # Whitelist known hosts
    ALLOWED_HOSTS = ['raw.githubusercontent.com', 'api.github.com']
    if parsed.hostname not in ALLOWED_HOSTS:
        raise MarketplaceError(f"Host not in whitelist: {parsed.hostname}")

    return url
```

---

## 3. Medium Priority Findings

### MED-001: Temporary File Race Conditions (TOCTOU)

**Severity:** MEDIUM
**CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)

**Locations:**
- `src/adapters/dagnn_adapter.py:130`
- `src/adapters/exploit_synthesizer_adapter.py:164`

**Vulnerable Code:**
```python
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True)  # Race condition possible
```

**Remediation:**
```python
import os
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True, mode=0o700)  # Restrict permissions
os.chmod(self.cache_dir, 0o700)  # Ensure correct permissions
```

---

### MED-002: Unpinned NPM Packages in Docker

**Severity:** MEDIUM
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

**Location:** `docker/Dockerfile:85`, `docker/Dockerfile.prod:25`

**Issue:**
```dockerfile
RUN npm install -g solhint    # No version pinning
```

**Remediation:**
```dockerfile
RUN npm install -g solhint@5.0.3
```

---

### MED-003: Curl-to-Shell Without Hash Verification

**Severity:** MEDIUM
**CWE:** CWE-494 (Download of Code Without Integrity Check)

**Location:** `docker/Dockerfile:35-40`

**Issue:**
```dockerfile
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN curl -L https://foundry.paradigm.xyz | bash
```

**Remediation:**
```dockerfile
# Download and verify before executing
RUN curl -sSf https://sh.rustup.rs -o /tmp/rustup.sh && \
    echo "EXPECTED_SHA256 /tmp/rustup.sh" | sha256sum -c - && \
    sh /tmp/rustup.sh -y && \
    rm /tmp/rustup.sh
```

---

### MED-004: Ollama API Exposed Without Authentication

**Severity:** MEDIUM
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Location:** `docker/docker-compose.yml:234-236`

**Issue:**
```yaml
ollama:
  ports:
    - "11434:11434"  # LLM API exposed without auth
```

**Remediation:**
- Development: Bind to localhost only (`127.0.0.1:11434:11434`)
- Production: Don't expose; use internal Docker network

---

### MED-005: Base Image Not Pinned by Digest

**Severity:** MEDIUM
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

**Location:** `docker/Dockerfile.prod:1`

**Issue:**
```dockerfile
FROM python:3.11-slim  # No Debian version or digest
```

**Remediation:**
```dockerfile
FROM python:3.11-slim-bookworm@sha256:abc123...
```

---

### MED-006: Python Lock File Generated for Wrong Version

**Severity:** MEDIUM

**Location:** `requirements-lock.txt:2-3`

**Issue:**
```
# This file is autogenerated by pip-compile with Python 3.9
```

Project requires Python 3.12+, but lock file generated with 3.9.

**Remediation:**
```bash
pip-compile pyproject.toml --python-version=3.12 -o requirements-lock.txt
```

---

### MED-007: WebSocket Missing Authentication

**Severity:** MEDIUM
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Location:** `src/core/websocket_api.py`

**Issue:** WebSocket connections don't validate authentication tokens.

**Remediation:** Implement token validation in connection handler:
```python
async def websocket_handler(websocket):
    token = websocket.request_headers.get("Authorization")
    if not validate_token(token):
        await websocket.close(1008, "Unauthorized")
        return
```

---

### MED-008: SSL Certificates on Filesystem

**Severity:** MEDIUM

**Location:** `docker/docker-compose.prod.yml:76`

**Issue:**
```yaml
volumes:
  - ./ssl:/etc/nginx/ssl:ro
```

**Checklist:**
- [ ] Verify `./ssl` is in `.gitignore`
- [ ] Verify certificate files have mode 0600
- [ ] Consider using Docker secrets instead

---

## 4. Low Priority Findings

### LOW-001: Test Code Contains Hardcoded Credentials

**Location:** Multiple test files

**Issue:** Test files contain strings like `"test-openai-key"`, `"secret123"`

**Status:** Acceptable for test code, but recommend using fixtures.

---

### LOW-002: Python 3.10 EOL in Dockerfile.x86

**Location:** `docker/Dockerfile.x86:1`

**Issue:** Python 3.10 reaches EOL October 2026.

**Remediation:** Migrate to Python 3.12.

---

### LOW-003: `:latest` Tag Used in Dockerfile.full

**Location:** `docker/Dockerfile.full:1`

**Issue:**
```dockerfile
FROM ghcr.io/fboiero/miesc:latest
```

**Remediation:** Use specific version tag.

---

### LOW-004: Development Volume Mounts Read-Write

**Location:** `docker/docker-compose.yml:164-166`

**Issue:** Development shell mounts allow write access.

**Status:** Acceptable for development, ensure production uses `:ro`.

---

### LOW-005: Binary Downloads Without Checksum

**Location:** `docker/Dockerfile.full` (Echidna, Medusa)

**Issue:** GitHub releases downloaded without SHA verification.

---

### LOW-006: Default pycryptodome Backend

**Location:** Transitive dependency via eth-hash

**Issue:** pycryptodome is acceptable but `cryptography` library preferred for new code.

---

## 5. Positive Security Controls

### Excellent Implementation

| Control | Location | Rating |
|---------|----------|--------|
| **Prompt Injection Protection** | `src/security/prompt_sanitizer.py` | 10/10 |
| **Path Traversal Protection** | `src/security/input_validator.py` | 10/10 |
| **Secure Logging (Redaction)** | `src/security/secure_logging.py` | 10/10 |
| **LLM Output Validation** | `src/security/llm_output_validator.py` | 9/10 |
| **Pre-commit Secret Detection** | `.pre-commit-config.yaml` | 9/10 |
| **Input Validation Functions** | `src/security/input_validator.py` | 9/10 |
| **Non-root Docker User** | All Dockerfiles | 9/10 |
| **Multi-stage Docker Builds** | All Dockerfiles | 9/10 |
| **Health Checks** | docker-compose files | 9/10 |
| **Resource Limits** | docker-compose.prod-llm.yml | 8/10 |
| **.gitignore Coverage** | `.gitignore` | 9/10 |
| **Environment Variable Masking** | `src/security/reproducibility.py` | 9/10 |

### Prompt Injection Protection Details

The `prompt_sanitizer.py` module implements industry-leading LLM security:

- **60+ Attack Patterns Detected:**
  - Instruction overrides ("ignore previous instructions")
  - Role injection ("system:", "assistant:")
  - Output manipulation ("report no vulnerabilities")
  - Jailbreak attempts ("DAN mode", "pretend you are")
  - Hidden Unicode characters (zero-width spaces)
  - Template injection (`${`, `{{`)

- **Risk Classification:** NONE → LOW → MEDIUM → HIGH → CRITICAL

- **Sanitization Features:**
  - XML-style content wrapping
  - HTML entity escaping
  - Character filtering
  - Length limits (100KB code, 50KB context)

### Secure Logging (Redaction)

The `secure_logging.py` module redacts 15+ sensitive patterns:

```python
REDACTION_PATTERNS = [
    # API Keys
    r"(sk-[a-zA-Z0-9]{20,})",           # OpenAI
    r"(sk-ant-[a-zA-Z0-9-]{20,})",      # Anthropic
    r"(hf_[a-zA-Z0-9]{20,})",           # HuggingFace
    # Tokens
    r"(Bearer\s+[a-zA-Z0-9_\-\.]+)",    # Bearer tokens
    r"(ghp_[a-zA-Z0-9]{36})",           # GitHub PAT
    r"(xox[baprs]-[a-zA-Z0-9-]+)",      # Slack
    # Credentials
    r"(AKIA[0-9A-Z]{16})",              # AWS Access Key
    r"(-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----)", # Private keys
    # Database
    r"(postgres://[^@]+@[^\s]+)",       # Connection strings
    r"(mongodb\+srv://[^@]+@[^\s]+)",
]
```

---

## 6. Recommendations

### Immediate Actions (Week 1)

| # | Action | File | Priority |
|---|--------|------|----------|
| 1 | Remove hardcoded admin API key default | `src/licensing/admin_api.py:38` | CRITICAL |
| 2 | Fix CORS configuration | `src/licensing/admin_api.py:28-35` | CRITICAL |
| 3 | Remove admin API port exposure | `docker/docker-compose.prod.yml:50` | HIGH |
| 4 | Add URL validation to marketplace | `src/plugins/marketplace.py:260` | HIGH |

### Short-term Actions (Sprint 2)

| # | Action | Priority |
|---|--------|----------|
| 5 | Fix temp file permissions | MEDIUM |
| 6 | Pin NPM package versions | MEDIUM |
| 7 | Add script hash verification | MEDIUM |
| 8 | Restrict Ollama to localhost | MEDIUM |
| 9 | Pin Docker base images | MEDIUM |
| 10 | Regenerate lock file for Python 3.12 | MEDIUM |

### Medium-term Actions (Q1 2026)

| # | Action | Priority |
|---|--------|----------|
| 11 | Implement WebSocket authentication | MEDIUM |
| 12 | Add Docker image scanning to CI | LOW |
| 13 | Generate SBOM during builds | LOW |
| 14 | Migrate Dockerfile.x86 to Python 3.12 | LOW |
| 15 | Replace `:latest` with specific tags | LOW |

### Long-term Actions (Q2 2026)

- Consider distroless base images
- Implement provenance attestation
- Add runtime security monitoring
- Implement secret rotation strategy

---

## 7. Compliance Status

### OWASP Top 10 (2021)

| Category | Status | Notes |
|----------|--------|-------|
| A01: Broken Access Control | ⚠️ | CORS misconfiguration |
| A02: Cryptographic Failures | ✅ | No issues found |
| A03: Injection | ✅ | Excellent protection |
| A04: Insecure Design | ✅ | Good architecture |
| A05: Security Misconfiguration | ⚠️ | Default credentials |
| A06: Vulnerable Components | ✅ | Active scanning |
| A07: Auth Failures | ⚠️ | WebSocket auth missing |
| A08: Software/Data Integrity | ⚠️ | Some unverified downloads |
| A09: Logging/Monitoring | ✅ | Secure logging implemented |
| A10: SSRF | ⚠️ | Marketplace vulnerability |

### CWE Coverage

| CWE | Description | Status |
|-----|-------------|--------|
| CWE-22 | Path Traversal | ✅ Protected |
| CWE-78 | OS Command Injection | ✅ Protected |
| CWE-79 | XSS | ✅ Protected |
| CWE-89 | SQL Injection | ✅ N/A (no SQL) |
| CWE-94 | Code Injection | ✅ Protected |
| CWE-798 | Hardcoded Credentials | ❌ Found |
| CWE-918 | SSRF | ❌ Found |
| CWE-942 | CORS Misconfiguration | ❌ Found |

### NIST Cybersecurity Framework

| Function | Maturity | Notes |
|----------|----------|-------|
| Identify | High | Good asset inventory |
| Protect | Medium | Some gaps in access control |
| Detect | High | Logging and monitoring |
| Respond | Medium | Incident response needs documentation |
| Recover | Low | Backup strategy needs documentation |

---

## 8. Appendix

### A. Files Analyzed

**Source Code:**
- `src/security/*.py` (7 files)
- `src/licensing/*.py` (2 files)
- `src/adapters/*.py` (59 files)
- `src/core/*.py` (15 files)
- `src/plugins/*.py` (6 files)
- `src/ml/*.py` (18 files)
- `src/llm/*.py` (8 files)

**Configuration:**
- `pyproject.toml`
- `requirements-lock.txt`
- `.pre-commit-config.yaml`
- `.gitignore`
- `.secrets.baseline`

**Docker:**
- `docker/Dockerfile` (4 variants)
- `docker/docker-compose*.yml` (4 files)
- `docker/.dockerignore`

**CI/CD:**
- `.github/workflows/*.yml` (11 workflows)

### B. Tools Used

- Manual code review
- grep/ripgrep pattern matching
- Static analysis concepts (SAST patterns)
- Dependency analysis

### C. Severity Definitions

| Level | CVSS | Description |
|-------|------|-------------|
| CRITICAL | 9.0-10.0 | Immediate exploitation risk, data breach |
| HIGH | 7.0-8.9 | Significant risk, remediation needed |
| MEDIUM | 4.0-6.9 | Security concern, should address |
| LOW | 0.1-3.9 | Best practice violation |
| INFO | N/A | Informational, no immediate risk |

### D. Verification Commands

```bash
# Check for hardcoded secrets
grep -r "miesc-admin-secret-key" .

# Verify .gitignore coverage
cat .gitignore | grep -E "\.env|\.key|\.pem"

# Check for API key patterns in source
grep -r "sk-\|sk-ant-\|hf_" src/ --include="*.py" | grep -v test

# Verify pre-commit hooks
cat .pre-commit-config.yaml | grep -A 5 "detect-secrets"

# Check subprocess usage
grep -r "shell=True" src/ --include="*.py"

# Check eval/exec usage
grep -r "eval\|exec\|compile" src/ --include="*.py"
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-16 | Security Team | Initial audit |

---

**Confidentiality Notice:** This document contains security-sensitive information about the MIESC project. Distribution should be limited to authorized personnel only.
