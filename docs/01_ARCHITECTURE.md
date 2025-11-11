# MIESC Architecture

**Version:** 3.3.0
**Document:** System Design and Technical Architecture
**Last Updated:** 2025-01-30

---

## 🏗️ System Overview

MIESC is built as a **modular multi-agent system** with three primary layers:

1. **Tool Orchestration Layer** - Coordinates multiple security analysis tools
2. **AI Correlation Layer** - Reduces false positives through LLM-based analysis
3. **Interoperability Layer** - MCP protocol for agent communication

### 🤖 LLM-Powered Analysis Capabilities

MIESC integrates **11 LLM-powered analysis capabilities** for comprehensive AI-assisted security evaluation:

**Core LLM Capabilities:**
1. **Intelligent Interpretation** - Root cause analysis, pattern correlation
2. **Exploit PoC Generator** - Automated exploit generation
3. **Attack Surface Mapping** - Entry points, trust boundaries, attack vectors
4. **Tool Effectiveness Comparison** - Strength/weakness matrix, coverage analysis
5. **Intelligent Prioritization** - Multi-factor risk scoring
6. **Predictive Analytics** - Time-to-exploit, breach probability
7. **Security Framework Analysis** - Defense-in-depth effectiveness rating
8. **Automated Remediation** - Secure code patches with gas optimization
9. **Tool Recommendations** - Optimal tool selection for contract type
10. **Executive Summary** - C-level reporting, ROI analysis
11. **Compliance Reports** - ISO 27001/42001, SOC 2, PCI DSS, GDPR

**LLM Providers:** GPT-4 Turbo (cloud) + CodeLlama 13B via Ollama (local, privacy-preserving)

**Note:** The thesis defense demo (`demo/hacker_demo.py`) showcases a subset of these capabilities with cinematic presentation.

📖 **Detailed Documentation:**
- [LLM Demo Architecture](LLM_DEMO_ARCHITECTURE.md) - Complete technical architecture
- [LLM Integration Diagrams](diagrams/LLM_INTEGRATION_FLOW.md) - Visual flow diagrams
- [Hacker Demo README](../demo/HACKER_DEMO_README.md) - Usage and features

---

## 📐 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MIESC CLI Interface                        │
│                    (miesc_cli.py)                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐  ┌──────────────────┐  ┌─────────────────┐
│ Tool Layer    │  │  AI Layer        │  │ Policy Layer    │
│ (miesc_core)  │  │ (miesc_ai_layer) │  │ (policy_agent)  │
└───────┬───────┘  └────────┬─────────┘  └────────┬────────┘
        │                   │                      │
        ├─────────┬─────────┼───────┬──────────────┤
        │         │         │       │              │
        ▼         ▼         ▼       ▼              ▼
   ┌────────┐ ┌────────┐ ┌─────┐ ┌──────┐   ┌──────────┐
   │Slither │ │Mythril │ │GPT4o│ │Mapper│   │Validator │
   └────────┘ └────────┘ └─────┘ └──────┘   └──────────┘
        │         │         │       │              │
        └─────────┴─────────┴───────┴──────────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
        ┌───────────────┐         ┌─────────────┐
        │  MCP Adapter  │         │ Risk Engine │
        │ (JSON-RPC +   │         │   (CVSS)    │
        │  REST API)    │         └─────────────┘
        └───────────────┘
                │
                ▼
        ┌───────────────┐
        │  Reports &    │
        │  Compliance   │
        └───────────────┘
```

---

## 🧩 Core Components

### 1. Tool Orchestration Layer

**File:** `src/miesc_core.py`
**Responsibility:** Execute and aggregate results from multiple security tools

**Supported Tools:**

| Tool | Type | Language | Purpose |
|------|------|----------|---------|
| **Slither** | Static Analysis | Python | Fast AST-based detection |
| **Mythril** | Symbolic Execution | Python | SMT-based verification |
| **Aderyn** | Static Analysis | Rust | High-performance scanning |
| **Solhint** | Linting | JavaScript | Style and best practices |
| **Echidna** | Fuzzing | Haskell | Property-based testing |
| **Manticore** | Symbolic Execution | Python | Deep path exploration |
| **Medusa** | Fuzzing | Go | Next-gen fuzzer |

**Orchestration Flow:**

```python
class MIESCCore:
    def run_audit(self, contract_path: str) -> AuditReport:
        # 1. Parse contract
        ast = self.parse_contract(contract_path)

        # 2. Run tools in parallel
        slither_results = self.run_slither(contract_path)
        mythril_results = self.run_mythril(contract_path)
        aderyn_results = self.run_aderyn(contract_path)

        # 3. Normalize findings
        normalized = self.normalize_findings([
            slither_results, mythril_results, aderyn_results
        ])

        # 4. Pass to AI layer
        correlated = self.ai_layer.correlate(normalized)

        # 5. Map to compliance frameworks
        mapped = self.policy_mapper.map_to_frameworks(correlated)

        # 6. Calculate risk scores
        scored = self.risk_engine.calculate_cvss(mapped)

        return AuditReport(findings=scored)
```

---

### 2. AI Correlation Layer

**File:** `src/miesc_ai_layer.py`
**Responsibility:** Reduce false positives through LLM-based analysis

**Architecture:**

```
Raw Tool Findings (10-50 per contract)
          │
          ▼
┌─────────────────────┐
│ Deduplication       │ ─► Group similar findings
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Contextual Prompt   │ ─► Add code context, tool outputs
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ GPT-4o API Call     │ ─► LLM analysis
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Confidence Scoring  │ ─► 0.0-1.0 scale
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Priority Assignment │ ─► 1 (Critical) - 5 (Low)
└──────────┬──────────┘
           ▼
Correlated Findings (3-8 per contract, 43% reduction)
```

**Prompt Template:**

```python
CORRELATION_PROMPT = """
You are a smart contract security expert. Analyze these vulnerability reports:

CONTRACT CODE:
{contract_source}

TOOL FINDINGS:
1. Slither: {slither_finding}
2. Mythril: {mythril_finding}

QUESTION: Are these findings true positives or false positives?

Respond in JSON:
{
  "is_true_positive": bool,
  "confidence": float (0.0-1.0),
  "root_cause": str,
  "remediation": str,
  "priority": int (1-5)
}
"""
```

**Key Metrics:**
- False Positive Reduction: 43%
- Average Confidence Score: 0.87
- Processing Time: ~2-5 seconds per finding

---

### 3. Policy Validation Layer

**File:** `src/miesc_policy_agent.py`
**Responsibility:** Ensure MIESC codebase follows its own security policies

**15 Policy Checks:**

| Category | Policy ID | Check | Tool |
|----------|-----------|-------|------|
| **Code Quality** | CQ-001 | Ruff linting | ruff check |
| | CQ-002 | Black formatting | black --check |
| | CQ-003 | MyPy type hints | mypy src/ |
| **Security** | SEC-001 | Bandit SAST | bandit -r src/ |
| | SEC-002 | Semgrep rules | semgrep --config=auto |
| | SEC-003 | Secret scanning | grep patterns |
| **Dependencies** | DEP-001 | pip-audit CVEs | pip-audit |
| | DEP-002 | License check | pip-licenses |
| | DEP-003 | Pinned versions | requirements.txt |
| **Testing** | TEST-001 | Coverage ≥85% | pytest-cov |
| | TEST-002 | All tests pass | pytest |
| **Documentation** | DOC-001 | Docstrings | pydocstyle |
| | DOC-002 | README exists | file check |
| **Compliance** | COMP-001 | ISO 27001 | framework mapping |
| | COMP-002 | NIST SSDF | CI/CD validation |

**Compliance Score Calculation:**

```python
compliance_score = (passed_checks / total_checks) * 100

# Example: 15/16 checks passed
# compliance_score = (15/16) * 100 = 93.75%
```

---

### 4. MCP Interoperability Layer

**Files:**
- `src/miesc_mcp_adapter.py` - JSON-RPC MCP interface
- `src/miesc_mcp_rest.py` - Flask REST API wrapper

**Protocol:** Model Context Protocol (MCP) v1.0

**Endpoints:**

| Endpoint | Method | Purpose | Response Time |
|----------|--------|---------|---------------|
| `/mcp/capabilities` | GET | List agent capabilities | <50ms |
| `/mcp/status` | GET | Health check | <20ms |
| `/mcp/get_metrics` | GET | Scientific metrics | <100ms |
| `/mcp/run_audit` | POST | Trigger contract analysis | ~45s |
| `/mcp/policy_audit` | POST | Internal compliance check | ~30s |

**MCP Message Format (JSON-RPC 2.0):**

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "run_audit",
  "params": {
    "contract": "/path/to/Contract.sol",
    "enable_ai": true,
    "tools": ["slither", "mythril"]
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "status": "success",
    "findings": [...],
    "metrics": {...}
  }
}
```

---

### 5. Risk Scoring Engine

**File:** `src/miesc_risk_engine.py`
**Responsibility:** Calculate CVSS scores for vulnerabilities

**CVSS v3.1 Implementation:**

```python
def calculate_cvss(vulnerability: Finding) -> float:
    # Base Metrics
    attack_vector = map_to_av(vulnerability.location)
    attack_complexity = map_to_ac(vulnerability.type)
    privileges_required = map_to_pr(vulnerability.context)
    user_interaction = map_to_ui(vulnerability.exploit)
    scope = map_to_scope(vulnerability.impact)

    # Impact Metrics
    confidentiality = map_to_cia(vulnerability.data_exposure)
    integrity = map_to_cia(vulnerability.state_corruption)
    availability = map_to_cia(vulnerability.dos_potential)

    # Calculate base score
    impact = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction

    if impact <= 0:
        return 0.0

    if scope == "Unchanged":
        base_score = min(impact + exploitability, 10.0)
    else:
        base_score = min(1.08 * (impact + exploitability), 10.0)

    return round(base_score, 1)
```

**Severity Mapping:**

| CVSS Score | Severity | Priority |
|------------|----------|----------|
| 9.0 - 10.0 | Critical | 1 |
| 7.0 - 8.9 | High | 2 |
| 4.0 - 6.9 | Medium | 3 |
| 0.1 - 3.9 | Low | 4 |
| 0.0 | Informational | 5 |

---

### 6. Policy Mapping Engine

**File:** `src/miesc_policy_mapper.py`
**Responsibility:** Map vulnerabilities to compliance frameworks

**Frameworks Supported:**

1. **CWE** (Common Weakness Enumeration)
2. **OWASP Top 10** (Smart Contract Security)
3. **SWC Registry** (Smart Contract Weaknesses)
4. **ISO/IEC 27001:2022** (Information Security)
5. **NIST SP 800-218** (Secure Software Development)
6. **OWASP SAMM v2.0** (Software Assurance Maturity)
7. **ISO/IEC 42001:2023** (AI Management System)
8. **NIST AI RMF** (AI Risk Management Framework)
9. **GDPR** (Data Protection - for DeFi)
10. **PCI DSS** (Payment Card Industry - for DeFi)
11. **SOC 2** (Trust Services Criteria)
12. **AICPA** (Audit standards)

**Mapping Example:**

```python
# Reentrancy vulnerability
finding = {
    "type": "reentrancy-eth",
    "tool": "slither",
    "severity": "High"
}

mapped = {
    "cwe": "CWE-841",
    "swc": "SWC-107",
    "owasp_sc": "SC01: Reentrancy",
    "iso_27001": "A.14.2.1 Secure development policy",
    "nist_ssdf": "PO.3.2: Review threat model",
    "cvss": 9.1,
    "nist_ai_rmf": "GOVERN-1.2: Responsible AI practices"
}
```

---

## 🔄 Data Flow

### Typical Audit Workflow

```
1. User Input
   └─► python src/miesc_cli.py run-audit Contract.sol --enable-ai

2. Contract Parsing
   ├─► AST generation (solc)
   ├─► Source code extraction
   └─► Metadata extraction (pragma, imports)

3. Tool Execution (Parallel)
   ├─► Slither (5-15 seconds)
   ├─► Mythril (20-40 seconds)
   └─► Aderyn (3-8 seconds)

4. Result Normalization
   ├─► Standardize finding format
   ├─► Deduplicate cross-tool findings
   └─► Extract code snippets

5. AI Correlation (if enabled)
   ├─► Build contextual prompts
   ├─► Call GPT-4o API
   ├─► Parse JSON responses
   └─► Assign confidence scores

6. Compliance Mapping
   ├─► Map to CWE/SWC/OWASP
   ├─► Calculate CVSS scores
   └─► Link to ISO/NIST requirements

7. Report Generation
   ├─► JSON report (demo/expected_outputs/demo_report.json)
   ├─► Markdown report (demo/expected_outputs/demo_report.md)
   └─► HTML dashboard (optional)

8. Output
   └─► Display results in CLI
       └─► Save to files
```

---

## 🧪 Testing Architecture

### Test Organization

```
src/miesc_tests/
├── test_core.py              # Tool orchestration tests
├── test_ai_layer.py          # AI correlation tests
├── test_policy_agent.py      # Compliance validation tests
├── test_mcp_adapter.py       # MCP protocol tests
├── test_risk_engine.py       # CVSS calculation tests
├── test_policy_mapper.py     # Framework mapping tests
└── fixtures/
    ├── sample_contracts/     # Test contracts
    ├── mock_responses/       # Mock API responses
    └── expected_outputs/     # Golden outputs
```

### Test Coverage Targets

| Module | Coverage Target | Actual (v3.3.0) |
|--------|-----------------|-----------------|
| miesc_core.py | ≥85% | 89% |
| miesc_ai_layer.py | ≥80% | 83% |
| miesc_policy_agent.py | ≥90% | 92% |
| miesc_mcp_rest.py | ≥85% | 87% |
| **Overall** | **≥85%** | **87.5%** |

---

## 🗄️ Data Persistence

### Report Storage

```
analysis/
├── reports/
│   ├── contract_name_YYYYMMDD_HHMMSS.json
│   ├── contract_name_YYYYMMDD_HHMMSS.md
│   └── contract_name_YYYYMMDD_HHMMSS.html
├── metrics/
│   ├── precision_recall.json
│   └── cohens_kappa.json
└── compliance/
    ├── policy_audit_YYYYMMDD.json
    └── framework_alignment.json
```

### Database Schema (Future)

**Currently file-based; future SQLite/PostgreSQL schema:**

```sql
CREATE TABLE audits (
    id INTEGER PRIMARY KEY,
    contract_path TEXT,
    timestamp DATETIME,
    miesc_version TEXT,
    total_findings INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER REFERENCES audits(id),
    tool TEXT,
    vulnerability_type TEXT,
    severity TEXT,
    confidence REAL,
    line_number INTEGER,
    code_snippet TEXT,
    cwe TEXT,
    cvss REAL
);
```

---

## 🔧 Configuration

### Configuration Files

**`config/miesc_config.yaml`** (future):

```yaml
tools:
  slither:
    enabled: true
    timeout: 60
    detectors: all
  mythril:
    enabled: true
    timeout: 120
    max_depth: 22
  aderyn:
    enabled: true
    timeout: 30

ai:
  provider: openai
  model: gpt-4o
  temperature: 0.2
  max_tokens: 2000

compliance:
  frameworks:
    - ISO27001
    - NIST_SSDF
    - OWASP_SAMM
    - ISO42001

reporting:
  formats:
    - json
    - markdown
    - html
  output_dir: analysis/reports/
```

---

## 🚀 Deployment Architectures

### Local CLI

```
Developer Laptop
 └─► MIESC CLI
      ├─► Local Slither
      ├─► Local Mythril
      └─► Remote GPT-4o API
```

### CI/CD Integration

```
GitHub Actions Pipeline
 └─► Checkout code
      └─► Install MIESC
           └─► Run audit
                ├─► Generate report
                ├─► Upload artifacts
                └─► Fail if critical findings
```

### MCP Agent Deployment

```
Security Operations Center (SOC)
 └─► MCP Orchestrator
      ├─► MIESC Agent (Flask REST API)
      ├─► Other Security Agents
      └─► Central Dashboard
```

---

## 📊 Performance Characteristics

### Resource Requirements

| Component | CPU | Memory | Disk | Network |
|-----------|-----|--------|------|---------|
| Slither | 1 core | 512 MB | 100 MB | None |
| Mythril | 2 cores | 2 GB | 500 MB | None |
| Aderyn | 1 core | 256 MB | 50 MB | None |
| AI Layer | <0.1 core | 128 MB | 10 MB | OpenAI API |
| PolicyAgent | 1 core | 256 MB | 50 MB | None |
| **Total** | **3-4 cores** | **3 GB** | **1 GB** | **API only** |

### Scalability

**Sequential Processing (current):**
- Throughput: ~15-20 contracts/hour
- Bottleneck: Mythril symbolic execution

**Future Parallel Processing:**
- Throughput: ~100-150 contracts/hour
- Strategy: Kubernetes job queue

---

## 🔐 Security Design

### Threat Model

**Assets:**
- Smart contract source code (confidential)
- Audit reports (sensitive)
- API keys (OpenAI)

**Threats:**
- Code injection in contract analysis
- API key exposure
- Report tampering
- Denial of service

**Mitigations:**
- Sandboxed tool execution (Docker containers)
- Environment variable API key storage
- GPG-signed reports
- Rate limiting on MCP endpoints

---

## 🔗 Integration Points

### Input Integrations

- **Local files** - Direct .sol file analysis
- **GitHub API** - Pull contract from repo
- **Etherscan API** - Fetch verified contract source
- **IPFS** - Retrieve contracts from decentralized storage

### Output Integrations

- **Slack** - Send critical findings
- **Jira** - Create tickets for vulnerabilities
- **GitHub Issues** - Auto-generate security issues
- **Email** - SMTP report delivery
- **S3/GCS** - Cloud report storage

---

**Next:** Read `docs/02_SETUP_AND_USAGE.md` for installation instructions.

---

**Version:** 3.3.0
**Maintainer:** Fernando Boiero - UNDEF
**Status:** 🏗️ Architecture Documented · 🔐 Security-First Design
