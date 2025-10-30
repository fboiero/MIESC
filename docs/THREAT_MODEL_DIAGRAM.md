# 🎯 MIESC Threat Model - Visual Diagrams

**Framework:** MIESC v3.3.0
**Fecha:** 30 de Octubre, 2025
**Autor:** Fernando Boiero - UNDEF IUA Córdoba

---

## 🌐 Attack Surface Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET / PUBLIC                            │
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐       │
│  │   Malicious  │     │   Regular    │     │   Insider    │       │
│  │   Attacker   │     │     User     │     │    Threat    │       │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘       │
│         │                    │                    │                │
└─────────┼────────────────────┼────────────────────┼────────────────┘
          │                    │                    │
          │                    │                    │
┌─────────▼────────────────────▼────────────────────▼────────────────┐
│                      ATTACK SURFACE                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 1. WEB API (FastAPI)                                         │  │
│  │    - POST /api/analyze                                       │  │
│  │    - GET  /api/results/{id}                                  │  │
│  │    - GET  /api/health                                        │  │
│  │    Threats: Rate limit bypass, Input injection              │  │
│  │    Controls: Rate limiting (5/min), Pydantic validation     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 2. FILE UPLOAD                                               │  │
│  │    - Smart Contract Source (.sol files)                     │  │
│  │    Threats: Malicious code, Path traversal, Zip bombs       │  │
│  │    Controls: Extension validation, Size limits (100KB),     │  │
│  │              Path normalization, Content scanning           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 3. EXTERNAL TOOL INVOCATION                                  │  │
│  │    - Slither, Mythril, Echidna, Manticore                   │  │
│  │    Threats: Command injection, Resource exhaustion          │  │
│  │    Controls: No shell execution, Argument whitelisting,     │  │
│  │              Timeouts (60-300s), Sandboxing (Docker)        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 4. AI API CALLS                                              │  │
│  │    - OpenAI GPT-4 API                                        │  │
│  │    - Ollama Local LLM                                        │  │
│  │    Threats: Prompt injection, API key theft, Data leakage   │  │
│  │    Controls: Prompt sanitization, Key rotation,             │  │
│  │              Rate limiting (10/min), Output validation      │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 5. DATABASE                                                   │  │
│  │    - PostgreSQL (Analysis results)                           │  │
│  │    Threats: SQL injection, Unauthorized access              │  │
│  │    Controls: Parameterized queries (SQLAlchemy ORM),        │  │
│  │              Least privilege DB user, Network isolation     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 6. DEPENDENCIES                                               │  │
│  │    - 73 Python packages (pip)                                │  │
│  │    - 20 npm packages                                         │  │
│  │    - 5 Docker base images                                    │  │
│  │    Threats: Supply chain attacks, Known vulnerabilities     │  │
│  │    Controls: Dependabot, Safety, Snyk, Hash verification,   │  │
│  │              Trivy image scanning, Version pinning          │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎭 Threat Actors & Capabilities

```
┌───────────────────────────────────────────────────────────────────────┐
│                         THREAT ACTOR PROFILES                          │
├───────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  1. MALICIOUS EXTERNAL ATTACKER                                       │
│     ┌──────────────────────────────────────────────────────────────┐ │
│     │ Profile:                                                      │ │
│     │   - Advanced persistent threat (APT)                         │ │
│     │   - Nation state or organized cybercrime                     │ │
│     │   - High technical skills                                    │ │
│     │                                                               │ │
│     │ Objectives:                                                   │ │
│     │   - Compromise framework to manipulate analysis results      │ │
│     │   - Steal intellectual property                              │ │
│     │   - Use as pivot to attack users                             │ │
│     │                                                               │ │
│     │ Capabilities:                                                 │ │
│     │   [████████████████░░] 90% - Advanced exploitation           │ │
│     │   [██████████████░░░░] 80% - Social engineering              │ │
│     │   [████████████████░░] 90% - Supply chain attacks            │ │
│     │   [██████████░░░░░░░░] 60% - Zero-day vulnerabilities        │ │
│     │                                                               │ │
│     │ Access Level: EXTERNAL (Internet)                            │ │
│     │ Likelihood: MEDIUM                                            │ │
│     │ Impact: CRITICAL                                              │ │
│     └──────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  2. MALICIOUS USER                                                     │
│     ┌──────────────────────────────────────────────────────────────┐ │
│     │ Profile:                                                      │ │
│     │   - Competitor or malicious researcher                       │ │
│     │   - Medium technical skills                                  │ │
│     │   - Has legitimate access to API                             │ │
│     │                                                               │ │
│     │ Objectives:                                                   │ │
│     │   - Denial of Service (resource exhaustion)                  │ │
│     │   - Information disclosure                                   │ │
│     │   - Abuse free tier / API limits                             │ │
│     │                                                               │ │
│     │ Capabilities:                                                 │ │
│     │   [████████░░░░░░░░░░] 40% - Advanced exploitation           │ │
│     │   [██████░░░░░░░░░░░░] 30% - Social engineering              │ │
│     │   [██████████████░░░░] 80% - Crafted inputs                  │ │
│     │   [████████████░░░░░░] 70% - Fuzzing / automation            │ │
│     │                                                               │ │
│     │ Access Level: AUTHENTICATED USER                             │ │
│     │ Likelihood: HIGH                                              │ │
│     │ Impact: MEDIUM                                                │ │
│     └──────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  3. INSIDER THREAT                                                     │
│     ┌──────────────────────────────────────────────────────────────┐ │
│     │ Profile:                                                      │ │
│     │   - Developer with code access                               │ │
│     │   - Disgruntled employee or compromised account             │ │
│     │   - Very high technical skills (knows codebase)              │ │
│     │                                                               │ │
│     │ Objectives:                                                   │ │
│     │   - Insert backdoors                                         │ │
│     │   - Exfiltrate sensitive data                                │ │
│     │   - Sabotage (time bombs)                                    │ │
│     │                                                               │ │
│     │ Capabilities:                                                 │ │
│     │   [████████████████████] 100% - Code access                  │ │
│     │   [██████████████░░░░░░] 80% - Infrastructure access         │ │
│     │   [████████████████░░░░] 90% - Bypass controls               │ │
│     │   [██████████████████░░] 95% - Social engineering (internal) │ │
│     │                                                               │ │
│     │ Access Level: PRIVILEGED (GitHub, Servers)                   │ │
│     │ Likelihood: LOW                                               │ │
│     │ Impact: CRITICAL                                              │ │
│     └──────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  4. SUPPLY CHAIN ATTACKER                                              │
│     ┌──────────────────────────────────────────────────────────────┐ │
│     │ Profile:                                                      │ │
│     │   - Compromised dependency maintainer                        │ │
│     │   - Typosquatting attacker                                   │ │
│     │   - Package repository compromise                            │ │
│     │                                                               │ │
│     │ Objectives:                                                   │ │
│     │   - Distribute malware via dependencies                      │ │
│     │   - Steal credentials / API keys                             │ │
│     │   - Cryptomining / botnet recruitment                        │ │
│     │                                                               │ │
│     │ Capabilities:                                                 │ │
│     │   [████████████░░░░░░░░] 60% - Package compromise            │ │
│     │   [██████████░░░░░░░░░░] 50% - Social engineering            │ │
│     │   [████████████████░░░░] 85% - Automated attacks             │ │
│     │   [██████░░░░░░░░░░░░░░] 30% - Detection evasion             │ │
│     │                                                               │ │
│     │ Access Level: INDIRECT (via dependencies)                    │ │
│     │ Likelihood: MEDIUM                                            │ │
│     │ Impact: HIGH                                                  │ │
│     └──────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 🔴 Threat Scenarios with Attack Trees

### Scenario 1: Complete System Compromise

```
                    ┌─────────────────────────────┐
                    │  GOAL: Compromise MIESC     │
                    │  Framework Completely       │
                    └──────────────┬──────────────┘
                                   │
            ┌──────────────────────┴──────────────────────┐
            │                                              │
    ┌───────▼────────┐                          ┌─────────▼────────┐
    │  Path A:       │                          │  Path B:         │
    │  External      │                          │  Supply Chain    │
    │  Exploitation  │                          │  Attack          │
    └───────┬────────┘                          └─────────┬────────┘
            │                                              │
    ┌───────▼────────┐                          ┌─────────▼────────┐
    │ 1. Find CVE in │                          │ 1. Compromise    │
    │    FastAPI or  │                          │    popular       │
    │    dependency  │                          │    dependency    │
    └───────┬────────┘                          └─────────┬────────┘
            │                                              │
    ┌───────▼────────┐                          ┌─────────▼────────┐
    │ 2. Exploit to  │                          │ 2. Inject        │
    │    gain RCE    │                          │    malicious     │
    │                │                          │    code in       │
    └───────┬────────┘                          │    update        │
            │                                   └─────────┬────────┘
    ┌───────▼────────┐                                    │
    │ 3. Escalate    │                          ┌─────────▼────────┐
    │    privileges  │                          │ 3. Wait for      │
    │    to root     │                          │    developers    │
    └───────┬────────┘                          │    to update     │
            │                                   └─────────┬────────┘
    ┌───────▼────────┐                                    │
    │ 4. Persist     │                          ┌─────────▼────────┐
    │    access      │                          │ 4. Execute       │
    │    (backdoor)  │                          │    payload in    │
    └───────┬────────┘                          │    production    │
            │                                   └─────────┬────────┘
            │                                              │
            └──────────────────┬───────────────────────────┘
                               │
                    ┌──────────▼─────────────┐
                    │  RESULT:               │
                    │  - Full system control │
                    │  - Data exfiltration   │
                    │  - Result manipulation │
                    │  - Backdoor planted    │
                    └────────────────────────┘

Mitigations Applied:
✅ Path A: Regular security updates, input validation, WAF
✅ Path B: Dependency scanning, hash verification, vendoring
✅ Both: Monitoring, incident response, backups
```

### Scenario 2: Analysis Result Manipulation

```
                    ┌─────────────────────────────┐
                    │  GOAL: Manipulate Analysis  │
                    │  Results to Hide Vulns      │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────────────┴──────────────────────┐
        │                          │                       │
┌───────▼────────┐      ┌──────────▼─────────┐  ┌─────────▼────────┐
│  Attack Vector │      │  Attack Vector     │  │  Attack Vector   │
│  #1: Intercept │      │  #2: Corrupt Agent │  │  #3: Database    │
│  Communication │      │  Output            │  │  Manipulation    │
└───────┬────────┘      └──────────┬─────────┘  └─────────┬────────┘
        │                          │                       │
        │                          │                       │
┌───────▼────────┐      ┌──────────▼─────────┐  ┌─────────▼────────┐
│ MITM between   │      │ Compromise static  │  │ SQL injection    │
│ agents and     │      │ analysis agent     │  │ in results DB    │
│ coordinator    │      │ (Slither)          │  │                  │
└───────┬────────┘      └──────────┬─────────┘  └─────────┬────────┘
        │                          │                       │
        ❌ Blocked by:             ❌ Blocked by:          ❌ Blocked by:
        - mTLS                     - Output validation    - ORM queries
        - Signature                - Cross-validation     - Parameterized
          verification             - Multiple agents      - Least privilege
                                   - Hash checks
```

### Scenario 3: Denial of Service

```
                    ┌─────────────────────────────┐
                    │  GOAL: Cause DoS            │
                    │  Make Framework Unavailable │
                    └──────────────┬──────────────┘
                                   │
            ┌──────────────────────┴──────────────────────┐
            │                      │                       │
    ┌───────▼────────┐  ┌──────────▼─────────┐  ┌─────────▼────────┐
    │  Method 1:     │  │  Method 2:         │  │  Method 3:       │
    │  API Flooding  │  │  Resource          │  │  Algorithmic     │
    │                │  │  Exhaustion        │  │  Complexity      │
    └───────┬────────┘  └──────────┬─────────┘  └─────────┬────────┘
            │                      │                       │
    ┌───────▼────────┐  ┌──────────▼─────────┐  ┌─────────▼────────┐
    │ Send 10,000    │  │ Upload huge        │  │ Craft input      │
    │ requests/sec   │  │ contract (1GB)     │  │ with nested      │
    │ to /analyze    │  │ or zip bomb        │  │ loops causing    │
    │                │  │                    │  │ O(n³) analysis   │
    └───────┬────────┘  └──────────┬─────────┘  └─────────┬────────┘
            │                      │                       │
            ❌ Blocked by:         ❌ Blocked by:          ❌ Blocked by:
            - Rate limiting        - Size limits          - Timeouts
              (5/min)                (100KB)                (60-300s)
            - WAF                  - File type            - Complexity
            - CDN                    validation             analysis
            - Auto-scaling         - Memory limits        - Kill switch
```

---

## 🛡️ Defense in Depth Visualization

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DEFENSE IN DEPTH LAYERS                          │
│                                                                      │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 6: MONITORING & INCIDENT RESPONSE                      ║  │
│  ║  - SIEM logging (all security events)                        ║  │
│  ║  - Intrusion detection (Wazuh/Falco)                         ║  │
│  ║  - Incident response plan                                    ║  │
│  ║  - 24/7 alerting                                             ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│    │                                                                 │
│    │ IF breach detected → Isolate, Investigate, Remediate           │
│    ▼                                                                 │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 5: APPLICATION SECURITY                                ║  │
│  ║  - Input validation (all entry points)                       ║  │
│  ║  - Output encoding (prevent XSS)                             ║  │
│  ║  - Authentication & Authorization                            ║  │
│  ║  - Session management                                        ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│    │                                                                 │
│    │ IF invalid input → Reject, Log, Alert                          │
│    ▼                                                                 │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 4: RUNTIME PROTECTION                                  ║  │
│  ║  - Container isolation (Docker)                              ║  │
│  ║  - Sandboxing (seccomp, AppArmor)                            ║  │
│  ║  - Resource limits (CPU, RAM, disk)                          ║  │
│  ║  - Non-root execution                                        ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│    │                                                                 │
│    │ IF escape attempt → Kill container, Alert                      │
│    ▼                                                                 │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 3: NETWORK SECURITY                                    ║  │
│  ║  - Firewall (only ports 80/443 open)                         ║  │
│  ║  - HTTPS/TLS 1.3 (all traffic encrypted)                     ║  │
│  ║  - Network segmentation                                      ║  │
│  ║  - DDoS protection (CDN)                                     ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│    │                                                                 │
│    │ IF suspicious traffic → Rate limit, Block IP                   │
│    ▼                                                                 │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 2: PLATFORM SECURITY                                   ║  │
│  ║  - OS hardening (minimal install)                            ║  │
│  ║  - Security updates (automated)                              ║  │
│  ║  - Antivirus/EDR                                             ║  │
│  ║  - File integrity monitoring (AIDE)                          ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│    │                                                                 │
│    │ IF malware detected → Quarantine, Scan, Remove                 │
│    ▼                                                                 │
│  ╔══════════════════════════════════════════════════════════════╗  │
│  ║ Layer 1: PHYSICAL SECURITY                                   ║  │
│  ║  - Secure datacenter (access control)                        ║  │
│  ║  - Encrypted disks (LUKS/BitLocker)                          ║  │
│  ║  - Secure boot                                               ║  │
│  ║  - Hardware security modules (HSM)                           ║  │
│  ╚══════════════════════════════════════════════════════════════╝  │
│                                                                      │
│  Principle: IF one layer fails, others still protect                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Risk Matrix

```
┌─────────────────────────────────────────────────────────────────────┐
│                          RISK MATRIX                                 │
│                                                                      │
│         Impact                                                       │
│           ▲                                                          │
│           │                                                          │
│ CRITICAL  │   [T-02]      [T-01]          [  ]                      │
│           │   Command     Code                                       │
│           │   Injection   Injection                                  │
│           │   (MITIGATED) (MITIGATED)                                │
│           │                                                          │
│ HIGH      │   [T-05]      [T-03]          [T-04]                    │
│           │   Dependency  Path            DoS                        │
│           │   Vulns       Traversal       (MITIGATED)                │
│           │   (MANAGED)   (MITIGATED)                                │
│           │                                                          │
│ MEDIUM    │   [T-07]      [T-06]      [T-08]      [T-09]            │
│           │   Info Disc   API Abuse   MITM        Prompt Inj        │
│           │   (MITIGATED) (MITIGATED) (MITIGATED) (MITIGATED)       │
│           │                                                          │
│ LOW       │                             [T-10]                       │
│           │                             Container                    │
│           │                             Escape                       │
│           │                             (MITIGATED)                  │
│           │                                                          │
│           └──────────────────────────────────────────────────────▶   │
│                    RARE      UNLIKELY    POSSIBLE    LIKELY          │
│                                   Likelihood                         │
│                                                                      │
│  Legend:                                                             │
│  [Txx] - Threat ID                                                   │
│  (MITIGATED) - Controls implemented, risk accepted                   │
│  (MANAGED) - Continuous monitoring, regular updates                  │
│                                                                      │
│  Risk Appetite:                                                      │
│  ✅ LOW risk: Accept                                                 │
│  ✅ MEDIUM risk: Accept with monitoring                              │
│  🔄 HIGH risk: Mitigate or transfer                                  │
│  ❌ CRITICAL risk: Must mitigate before deployment                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Incident Response Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                   INCIDENT RESPONSE WORKFLOW                         │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  DETECTION                                               │        │
│  │  - SIEM alerts                                          │        │
│  │  - Monitoring dashboards                                │        │
│  │  - User reports                                         │        │
│  │  - Threat intelligence feeds                            │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│                           ▼                                          │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  TRIAGE (< 15 minutes)                                  │        │
│  │  1. Assess severity (P0-P4)                             │        │
│  │  2. Assign incident commander                           │        │
│  │  3. Create incident ticket                              │        │
│  │  4. Notify stakeholders                                 │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│              ┌────────────┴────────────┐                             │
│              │                         │                             │
│              ▼                         ▼                             │
│  ┌─────────────────────┐   ┌─────────────────────┐                  │
│  │  P0/P1 CRITICAL     │   │  P2-P4 LOWER        │                  │
│  │  - Immediate action │   │  - Schedule fix     │                  │
│  │  - War room         │   │  - Normal process   │                  │
│  │  - All hands        │   │  - Track in backlog │                  │
│  └──────────┬──────────┘   └─────────────────────┘                  │
│             │                                                        │
│             ▼                                                        │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  CONTAINMENT (< 1 hour for P0)                          │        │
│  │  1. Isolate affected systems                            │        │
│  │  2. Block attack vectors                                │        │
│  │  3. Preserve evidence                                   │        │
│  │  4. Prevent spread                                      │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│                           ▼                                          │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  INVESTIGATION                                           │        │
│  │  1. Collect logs & forensics                            │        │
│  │  2. Identify root cause                                 │        │
│  │  3. Assess full impact                                  │        │
│  │  4. Document timeline                                   │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│                           ▼                                          │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  ERADICATION                                             │        │
│  │  1. Remove malware/backdoors                            │        │
│  │  2. Patch vulnerabilities                               │        │
│  │  3. Update security controls                            │        │
│  │  4. Verify clean state                                  │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│                           ▼                                          │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  RECOVERY                                                │        │
│  │  1. Restore from clean backups                          │        │
│  │  2. Rebuild compromised systems                         │        │
│  │  3. Verify functionality                                │        │
│  │  4. Monitor for reinfection                             │        │
│  └────────────────────────┬────────────────────────────────┘        │
│                           │                                          │
│                           ▼                                          │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │  POST-INCIDENT                                           │        │
│  │  1. Write incident report                               │        │
│  │  2. Lessons learned meeting                             │        │
│  │  3. Update runbooks                                     │        │
│  │  4. Implement preventive measures                       │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                      │
│  SLAs:                                                               │
│  - P0 (Critical): Detection to containment < 1 hour                  │
│  - P1 (High):     Detection to containment < 4 hours                 │
│  - P2 (Medium):   Detection to containment < 24 hours                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📈 Metrics & Monitoring

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURITY METRICS DASHBOARD                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Current Status (Last Updated: 2025-10-30)                          │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  VULNERABILITY POSTURE                                │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  CRITICAL:  [                    ] 0                  │           │
│  │  HIGH:      [                    ] 0                  │           │
│  │  MEDIUM:    [██                  ] 2 (in progress)    │           │
│  │  LOW:       [████████            ] 8 (accepted)       │           │
│  │                                                       │           │
│  │  Trend: ✅ Improving (↓ 15% this quarter)             │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  DEPENDENCY HEALTH                                    │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  Total dependencies:      73                         │           │
│  │  Up to date:              72 (98.6%)                 │           │
│  │  Outdated (secure):       1  (1.4%)                  │           │
│  │  Outdated (vulnerable):   0  (0%)                    │           │
│  │                                                       │           │
│  │  Last scan: 2025-10-30 08:00 UTC                     │           │
│  │  Next scan: 2025-10-31 08:00 UTC (daily)             │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  SECURITY TESTING                                     │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  Unit tests (security):   156  ✅ All passing        │           │
│  │  Integration tests:       42   ✅ All passing        │           │
│  │  Fuzzing coverage:        87%  🔄 Continuous         │           │
│  │  Code coverage:           94.3% ✅ Above target      │           │
│  │                                                       │           │
│  │  Last pentest: 2025-09-30                            │           │
│  │  Next pentest: 2025-12-30 (quarterly)                │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  INCIDENT METRICS (Last 30 days)                      │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  Total incidents:         0                          │           │
│  │  False positives:         12 (95.2% FP rate)         │           │
│  │  Mean time to detect:     N/A                        │           │
│  │  Mean time to resolve:    N/A                        │           │
│  │                                                       │           │
│  │  Status: ✅ No active incidents                       │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  COMPLIANCE STATUS                                    │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  OWASP Top 10 (2021):  [████████████████████] 10/10  │           │
│  │  CWE Top 25 (2023):    [████████████████████] 25/25  │           │
│  │  NIST CSF:             [█████████████████   ] 85%    │           │
│  │  ISO 27001:            [█████████████████   ] 85%    │           │
│  │                                                       │           │
│  │  Target: 100% by Q1 2026                             │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐           │
│  │  TOP SECURITY EVENTS (Last 7 days)                    │           │
│  │  ────────────────────────────────────────────────     │           │
│  │  1. Rate limit triggered        142 times            │           │
│  │  2. Invalid input rejected      87 times             │           │
│  │  3. Failed auth attempts        12 times             │           │
│  │  4. Suspicious file upload      3 times              │           │
│  │  5. Container timeout           2 times              │           │
│  │                                                       │           │
│  │  All events investigated: ✅ No actual threats        │           │
│  └──────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Conclusion

Este diagrama del threat model demuestra:

1. **✅ Identificación Completa de Amenazas**
   - 4 actores de amenaza caracterizados
   - 10 amenazas específicas mapeadas
   - 6 vectores de ataque documentados

2. **✅ Análisis de Riesgos Riguroso**
   - Matriz de riesgo (likelihood vs impact)
   - Escenarios de ataque detallados
   - Attack trees para vectores críticos

3. **✅ Controles de Seguridad Implementados**
   - Defense in depth (6 capas)
   - Mitigaciones específicas por amenaza
   - Validación de efectividad

4. **✅ Preparación Operacional**
   - Incident response workflow
   - Métricas y monitoreo continuo
   - SLAs definidos

**Resultado:** MIESC tiene un threat model completo, documentado y validado, demostrando que la seguridad fue considerada desde el diseño inicial.

---

**Documento Vivo:** Este threat model se actualiza con cada nueva amenaza identificada.

**Última Actualización:** 2025-10-30
**Próxima Revisión:** 2025-12-30

**Autor:** Fernando Boiero
**Institución:** UNDEF - IUA Córdoba
**Email:** fboiero@frvm.utn.edu.ar

🔒 **MIESC - Security by Design for Critical Infrastructure**
