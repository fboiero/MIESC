# MIESC Security Issues Backlog

**Created:** 2026-02-16
**Last Updated:** 2026-02-16
**Status:** Active Tracking

---

## Overview

This document tracks security issues identified during the security audit that require remediation. Critical and High priority issues have been fixed. This backlog contains Medium and Low priority items for future sprints.

## Fixed Issues (2026-02-16)

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| CRIT-001 | CRITICAL | Hardcoded admin API key | **FIXED** |
| CRIT-002 | CRITICAL | CORS allows all origins | **FIXED** |
| HIGH-001 | HIGH | Admin API port exposed | **FIXED** |
| HIGH-002 | HIGH | SSRF in marketplace client | **FIXED** |

---

## Medium Priority Issues

### MED-001: Temporary File Race Conditions (TOCTOU)

**Severity:** MEDIUM
**CWE:** CWE-367
**Status:** PENDING

**Locations:**
- `src/adapters/dagnn_adapter.py:130`
- `src/adapters/exploit_synthesizer_adapter.py:164`

**Current Code:**
```python
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True)  # Race condition possible
```

**Required Fix:**
```python
import os
self.cache_dir = Path(tempfile.gettempdir()) / "miesc_dagnn_cache"
self.cache_dir.mkdir(exist_ok=True, mode=0o700)
os.chmod(self.cache_dir, 0o700)  # Ensure restrictive permissions
```

**Effort:** 1 hour
**Assignee:** TBD

---

### MED-002: Unpinned NPM Packages in Docker

**Severity:** MEDIUM
**CWE:** CWE-1104
**Status:** PENDING

**Locations:**
- `docker/Dockerfile:85`
- `docker/Dockerfile.prod:25`

**Current Code:**
```dockerfile
RUN npm install -g solhint
```

**Required Fix:**
```dockerfile
RUN npm install -g solhint@5.0.3
```

**Effort:** 30 minutes
**Assignee:** TBD

---

### MED-003: Curl-to-Shell Without Hash Verification

**Severity:** MEDIUM
**CWE:** CWE-494
**Status:** PENDING

**Location:** `docker/Dockerfile:35-40`

**Current Code:**
```dockerfile
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN curl -L https://foundry.paradigm.xyz | bash
```

**Required Fix:**
```dockerfile
# Option 1: Download and verify
RUN curl -sSf https://sh.rustup.rs -o /tmp/rustup.sh && \
    echo "EXPECTED_SHA256  /tmp/rustup.sh" | sha256sum -c - && \
    sh /tmp/rustup.sh -y && \
    rm /tmp/rustup.sh

# Option 2: Use package manager
RUN apt-get install -y rustup
```

**Effort:** 2 hours (need to research current hashes)
**Assignee:** TBD

---

### MED-004: Ollama API Exposed Without Authentication

**Severity:** MEDIUM
**CWE:** CWE-306
**Status:** PENDING

**Location:** `docker/docker-compose.yml:234-236`

**Current Code:**
```yaml
ollama:
  ports:
    - "11434:11434"
```

**Required Fix:**
```yaml
ollama:
  ports:
    # Development: localhost only
    - "127.0.0.1:11434:11434"
  # OR Production: don't expose, use internal network only
```

**Effort:** 30 minutes
**Assignee:** TBD

---

### MED-005: Base Image Not Pinned by Digest

**Severity:** MEDIUM
**CWE:** CWE-1104
**Status:** PENDING

**Location:** `docker/Dockerfile.prod:1`

**Current Code:**
```dockerfile
FROM python:3.11-slim
```

**Required Fix:**
```dockerfile
FROM python:3.11-slim-bookworm@sha256:<current_digest>
```

**Effort:** 30 minutes
**Assignee:** TBD

---

### MED-006: Python Lock File for Wrong Version

**Severity:** MEDIUM
**Status:** PENDING

**Location:** `requirements-lock.txt`

**Issue:** Lock file generated for Python 3.9, project requires 3.12+

**Required Fix:**
```bash
pip-compile pyproject.toml --python-version=3.12 -o requirements-lock.txt
```

**Effort:** 30 minutes
**Assignee:** TBD

---

### MED-007: WebSocket Missing Authentication

**Severity:** MEDIUM
**CWE:** CWE-306
**Status:** PENDING

**Location:** `src/core/websocket_api.py`

**Required Fix:**
```python
async def websocket_handler(websocket):
    token = websocket.request_headers.get("Authorization")
    if not token or not validate_token(token):
        await websocket.close(1008, "Unauthorized")
        return
    # Continue with authenticated connection
```

**Effort:** 2 hours
**Assignee:** TBD

---

### MED-008: SSL Certificates on Filesystem

**Severity:** MEDIUM
**Status:** PENDING

**Location:** `docker/docker-compose.prod.yml:76`

**Checklist:**
- [ ] Verify `./ssl` is in `.gitignore`
- [ ] Verify certificate files have mode 0600
- [ ] Document certificate management process
- [ ] Consider Docker secrets for production

**Effort:** 1 hour
**Assignee:** TBD

---

## Low Priority Issues

### LOW-001: Test Code Contains Hardcoded Credentials

**Severity:** LOW
**Status:** PENDING

**Locations:**
- `tests/test_ensemble_detector.py:54-55`
- `tests/test_integration_multi_provider.py:91-92`
- `tests/test_reproducibility.py:267`

**Issue:** Test files contain strings like `"test-openai-key"`, `"secret123"`

**Recommendation:** Use pytest fixtures instead:
```python
@pytest.fixture
def mock_api_key():
    return "test-key-" + secrets.token_hex(8)
```

**Effort:** 2 hours
**Assignee:** TBD

---

### LOW-002: Python 3.10 EOL in Dockerfile.x86

**Severity:** LOW
**Status:** PENDING

**Location:** `docker/Dockerfile.x86:1`

**Issue:** Python 3.10 reaches EOL October 2026

**Required Fix:**
```dockerfile
FROM --platform=linux/amd64 python:3.12-slim-bookworm
```

**Effort:** 1 hour (may require dependency updates)
**Assignee:** TBD

---

### LOW-003: `:latest` Tag Used in Dockerfile.full

**Severity:** LOW
**Status:** PENDING

**Location:** `docker/Dockerfile.full:1`

**Current Code:**
```dockerfile
FROM ghcr.io/fboiero/miesc:latest
```

**Required Fix:**
```dockerfile
FROM ghcr.io/fboiero/miesc:5.1.1
```

**Effort:** 15 minutes
**Assignee:** TBD

---

### LOW-004: Development Volume Mounts Read-Write

**Severity:** LOW
**Status:** PENDING

**Location:** `docker/docker-compose.yml:164-166`

**Issue:** Development shell mounts allow write access

**Recommendation:** Add documentation noting this is development-only, production should use `:ro`

**Effort:** 30 minutes
**Assignee:** TBD

---

### LOW-005: Binary Downloads Without Checksum

**Severity:** LOW
**Status:** PENDING

**Location:** `docker/Dockerfile.full` (Echidna, Medusa downloads)

**Current Code:**
```dockerfile
RUN curl -L "https://github.com/crytic/echidna/releases/..." | tar xz
```

**Required Fix:**
```dockerfile
RUN curl -L "https://github.com/crytic/echidna/releases/..." -o /tmp/echidna.tar.gz && \
    echo "EXPECTED_SHA256  /tmp/echidna.tar.gz" | sha256sum -c - && \
    tar xz -C /usr/local/bin/ -f /tmp/echidna.tar.gz
```

**Effort:** 1 hour
**Assignee:** TBD

---

### LOW-006: Default pycryptodome Backend

**Severity:** LOW
**Status:** INFORMATIONAL

**Location:** Transitive dependency via `eth-hash[pycryptodome]`

**Issue:** pycryptodome is acceptable but `cryptography` library is preferred for new cryptographic code.

**Recommendation:** Monitor for migration opportunities. No immediate action required.

**Effort:** N/A
**Assignee:** N/A

---

## Progress Tracking

| Sprint | Issues Addressed | Notes |
|--------|-----------------|-------|
| 2026-02-16 | CRIT-001, CRIT-002, HIGH-001, HIGH-002 | Critical/High fixes |
| TBD | MED-001 to MED-004 | Temp files, NPM, Docker |
| TBD | MED-005 to MED-008 | Images, WebSocket, SSL |
| TBD | LOW-001 to LOW-006 | Cleanup items |

---

## Verification Checklist

After fixing each issue, verify:

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Docker build succeeds
- [ ] No new security warnings
- [ ] Documentation updated if needed

---

## References

- [MIESC Security Audit Report](./SECURITY_AUDIT_REPORT.md)
- [MIESC Security Audit Report (ES)](./SECURITY_AUDIT_REPORT_ES.md)
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
