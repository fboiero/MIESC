# Privacy Policy

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

*Last Updated: December 2024*

---

## Overview

MIESC is committed to protecting user privacy. This document describes our data handling practices and privacy commitments.

**Key Principle**: MIESC processes all data locally on your machine. Your code and analysis results never leave your system unless you explicitly choose to share them.

---

## Data Collection

### What We DO NOT Collect

| Data Type | Collected? | Notes |
|-----------|------------|-------|
| Source code | No | Processed locally only |
| Analysis results | No | Stored locally only |
| Personal information | No | No user accounts required |
| Usage telemetry | No | No analytics by default |
| IP addresses | No | No network requests to MIESC servers |
| Cookies | No | No web tracking |

### What We MAY Process Locally

| Data Type | Purpose | Storage |
|-----------|---------|---------|
| Solidity source files | Security analysis | Temporary, deleted after analysis |
| Compilation artifacts | Tool execution | Temporary cache, user-controlled |
| Analysis reports | User deliverable | Local filesystem only |
| Configuration files | User preferences | Local filesystem only |

---

## Local Processing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR LOCAL MACHINE                        │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Source Code  │───▶│    MIESC     │───▶│   Reports    │  │
│  │   (Input)    │    │   (Local)    │    │   (Output)   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                             │                               │
│                             ▼                               │
│                    ┌──────────────┐                         │
│                    │ Local LLM    │                         │
│                    │  (Ollama)    │                         │
│                    └──────────────┘                         │
│                                                              │
│          ══════════════════════════════════════             │
│          ║  NO DATA LEAVES THIS BOUNDARY  ║                 │
│          ══════════════════════════════════════             │
└─────────────────────────────────────────────────────────────┘
```

---

## AI/ML Components

### Local LLM (Default)

MIESC uses **Ollama** for AI-assisted analysis by default:

- Runs entirely on your local machine
- No API calls to external services
- No data transmission to cloud providers
- Models downloaded once, run offline

### Optional Cloud AI

If you choose to enable cloud AI features (GPT-4, Claude):

- **Opt-in only**: Requires explicit configuration
- **Your responsibility**: You must review the provider's privacy policy
- **Data transmission**: Source code snippets may be sent to the API
- **Recommendation**: Use local models for sensitive code

---

## Third-Party Tools

MIESC orchestrates third-party security tools. Each tool has its own privacy characteristics:

| Tool | Network Access | Data Sent Externally |
|------|----------------|---------------------|
| Slither | None | None |
| Mythril | None | None |
| Echidna | None | None |
| Foundry | Optional (dependencies) | Package checksums only |
| Halmos | None | None |
| Certora | Yes (if used) | Code sent to Certora cloud |
| SMTChecker | None | None |

**Note**: Certora's cloud verification service requires sending code to their servers. This is optional and clearly documented when enabled.

---

## Data Retention

### Automatic Cleanup

| Data Type | Retention | Cleanup Method |
|-----------|-----------|----------------|
| Temporary files | Session only | Deleted on exit |
| Compilation cache | User-controlled | Manual or `make clean` |
| Analysis reports | Permanent | User manages |
| Logs | 7 days default | Configurable |

### User Control

Users have full control over all stored data:

```bash
# Clear all temporary data
make clean

# Clear analysis cache
rm -rf .miesc_cache/

# Clear logs
rm -rf logs/
```

---

## Legal Compliance

### GDPR (EU General Data Protection Regulation)

| Requirement | MIESC Compliance |
|-------------|------------------|
| Lawful basis | Not applicable (no personal data processing) |
| Data minimization | Only processes files explicitly provided |
| Purpose limitation | Security analysis only |
| Storage limitation | User-controlled retention |
| Right to erasure | User deletes local files |
| Data portability | All exports in open formats |

### CCPA (California Consumer Privacy Act)

| Requirement | MIESC Compliance |
|-------------|------------------|
| Right to know | This policy documents all data handling |
| Right to delete | User controls all local data |
| Right to opt-out | No data sale (no data collection) |
| Non-discrimination | Free tool, no user differentiation |

### Argentina Data Protection Law (Ley 25.326)

| Requirement | MIESC Compliance |
|-------------|------------------|
| Purpose specification | Security analysis only |
| Data quality | No personal data stored |
| Security measures | Local processing, no transmission |
| User rights | Full user control over data |

---

## Security Measures

### Data Protection

| Measure | Implementation |
|---------|----------------|
| Encryption at rest | User filesystem encryption (OS-level) |
| Encryption in transit | N/A (no data transmission) |
| Access control | User filesystem permissions |
| Audit logging | Optional, local only |

### Vulnerability Handling

- Security issues: fboiero@frvm.utn.edu.ar
- Response time: <48 hours
- Disclosure policy: Coordinated disclosure

---

## Children's Privacy

MIESC is a developer tool intended for professional use. We do not:
- Knowingly collect data from children under 13
- Market to children
- Provide features designed for minors

---

## International Data Transfers

**No international data transfers occur** because:
- All processing is local
- No data sent to MIESC servers
- No cloud services required by default

If you enable optional cloud AI features, transfers are governed by the provider's policies.

---

## Changes to This Policy

We will update this policy as needed. Changes will be:
- Documented in repository commits
- Noted in release notes
- Effective immediately upon publication

---

## Contact

**Privacy Questions**: fboiero@frvm.utn.edu.ar

**Project Repository**: https://github.com/fboiero/MIESC

---

## Summary

| Question | Answer |
|----------|--------|
| Does MIESC collect my data? | No |
| Does MIESC send data externally? | No (by default) |
| Where is my code processed? | Your local machine only |
| Who can access my analysis results? | Only you |
| Do I need an account? | No |
| Is there telemetry? | No |

**Your code stays on your machine. Always.**
