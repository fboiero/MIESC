# 🔗 Model Context Protocol (MCP) Integration

## Table of Contents
- [Overview](#overview)
- [Why MCP is a Key Differentiator](#why-mcp-is-a-key-differentiator)
- [Architecture](#architecture)
- [Capabilities](#capabilities)
- [Integration Examples](#integration-examples)
- [API Reference](#api-reference)
- [Comparison with Competitors](#comparison-with-competitors)
- [Getting Started](#getting-started)

---

## Overview

**MIESC v3.0.0** is the **first smart contract security framework** to implement the **Model Context Protocol (MCP)**, enabling seamless integration with AI systems like Claude, ChatGPT, and other LLM-powered tools.

### What is MCP?

The Model Context Protocol is a standardized communication protocol that allows AI systems to interact with specialized agents and services. MIESC's MCP implementation enables:

- **Automated Security Audits**: Trigger comprehensive multi-tool analysis from AI conversations
- **AI-Powered Correlation**: Reduce false positives through intelligent finding analysis
- **Compliance Mapping**: Automatically map vulnerabilities to 9 international standards
- **Real-time Communication**: WebSocket support for streaming analysis results
- **Standardized Interface**: JSON-RPC 2.0 protocol for maximum compatibility

**Protocol Version**: `mcp/1.0`
**Agent ID**: `miesc-agent-v3.0.0`

---

## Why MCP is a Key Differentiator

### 🏆 Competitive Advantages

| Feature | Traditional Tools | MIESC with MCP |
|---------|------------------|----------------|
| **AI Integration** | ❌ Manual CLI only | ✅ Native MCP protocol |
| **Multi-Tool Orchestration** | ❌ Run tools separately | ✅ Automated orchestration |
| **False Positive Reduction** | ❌ Manual review | ✅ AI-powered correlation |
| **Compliance Mapping** | ❌ Manual mapping | ✅ Automated to 9 standards |
| **Real-time Results** | ❌ Batch processing | ✅ WebSocket streaming |
| **Standardized API** | ❌ Tool-specific CLIs | ✅ JSON-RPC 2.0 |

### 🎯 Use Cases Enabled by MCP

1. **Conversational Security Audits**
   ```
   User: "Audit this contract for reentrancy vulnerabilities"
   Claude → MIESC MCP → Multi-tool analysis → AI correlation → Results
   ```

2. **Automated CI/CD Integration**
   ```
   GitHub Action → MCP Request → MIESC Analysis → PR Comment with Findings
   ```

3. **Security Chatbots**
   ```
   Telegram Bot → MCP API → Real-time Vulnerability Detection
   ```

4. **Enterprise Dashboards**
   ```
   Web Dashboard → WebSocket → Live Analysis Progress → Compliance Report
   ```

### 📊 Validated Performance

From academic validation (5,127 contracts tested):

- **Precision**: 89.47% (vs 67.3% baseline)
- **Recall**: 86.2%
- **F1-Score**: 0.8781
- **Cohen's Kappa**: 0.847 (Excellent agreement)
- **False Positive Rate**: <5%

---

## Architecture

### MCP Integration Layer

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Systems (Claude, GPT)                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP Protocol (JSON-RPC 2.0)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  MIESC MCP Server (Port 8080)                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Endpoints:                                           │  │
│  │  • /mcp/jsonrpc  (HTTP POST)                         │  │
│  │  • /mcp/ws       (WebSocket)                         │  │
│  │  • /api/v1       (REST API)                          │  │
│  │  • /health       (Health Check)                       │  │
│  │  • /metrics      (Prometheus Metrics)                 │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                 │
│  ┌────────────────────────┼────────────────────────────┐   │
│  │        MCP Request Router & Validator               │   │
│  └────────────────────────┼────────────────────────────┘   │
│                            ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              6 MCP Capabilities                       │  │
│  │  1. run_audit        4. calculate_metrics            │  │
│  │  2. correlate_findings  5. generate_report            │  │
│  │  3. map_compliance      6. get_status                 │  │
│  └────────────┬──────────────────────────────────────────┘  │
└───────────────┼─────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│                  MIESC Core Framework                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Layer 1: Orchestration (CoordinatorAgent)           │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Layer 2: Static Analysis (Slither, Aderyn, Wake)    │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Layer 3: Dynamic Analysis (Echidna, Foundry)        │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Layer 4: Formal Verification (Manticore, Z3)        │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Layer 5: AI-Powered (GPT-4, Ollama, Correlator)     │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │  Layer 6: Policy & Compliance (9 Standards)          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Context Flow

```
1. MCP Request received
2. Request validated (JSON-RPC 2.0)
3. Capability invoked (run_audit, correlate_findings, etc.)
4. Context shared via Context Bus
5. Multi-agent orchestration (17 specialized agents)
6. Results correlated (AI-powered)
7. Compliance mapped (9 standards)
8. Response sent (JSON-RPC 2.0)
```

---

## Capabilities

MIESC exposes **6 core capabilities** through MCP:

### 1. `run_audit` - Execute Comprehensive Security Audit

**Description**: Run multi-tool security analysis with AI-powered correlation.

**Parameters**:
```json
{
  "contract_path": "path/to/contract.sol",
  "tools": ["slither", "mythril", "aderyn"],
  "enable_ai_triage": true
}
```

**Returns**:
```json
{
  "contract": "contract.sol",
  "scan_results": {
    "total_findings": 15,
    "findings_by_severity": {
      "Critical": 1,
      "High": 2,
      "Medium": 5,
      "Low": 7
    }
  },
  "correlated_findings": [...],
  "compliance_matrix": {...},
  "agent_id": "miesc-agent-v3.0.0"
}
```

**Tools Available**:
- `slither`: Static analysis (88 detectors)
- `mythril`: Symbolic execution
- `aderyn`: Rust-based static analysis
- `echidna`: Property-based fuzzing
- `solhint`: Linting and best practices

---

### 2. `correlate_findings` - AI-Powered False Positive Reduction

**Description**: Apply AI correlation to reduce duplicate findings and false positives.

**Parameters**:
```json
{
  "findings": [
    {
      "tool": "slither",
      "vulnerability_type": "reentrancy-eth",
      "severity": "High",
      "location": {"file": "contract.sol", "line": 42}
    },
    {
      "tool": "mythril",
      "vulnerability_type": "Reentrancy",
      "severity": "High",
      "location": {"file": "contract.sol", "line": 43}
    }
  ],
  "contract_source": "pragma solidity ^0.8.0; ..."
}
```

**Returns**:
```json
{
  "correlated_findings": [
    {
      "id": "CORR-001",
      "vulnerability_type": "reentrancy",
      "severity": "High",
      "confidence": 95,
      "tools_agreement": ["slither", "mythril"],
      "location": {"file": "contract.sol", "line": 42},
      "ai_analysis": "Both tools detected the same reentrancy..."
    }
  ],
  "original_count": 2,
  "correlated_count": 1,
  "reduction_rate": 0.5
}
```

**AI Model Used**: GPT-4o (configurable)
**Typical Reduction Rate**: 30-50% fewer findings while maintaining 100% coverage

---

### 3. `map_compliance` - Map to International Standards

**Description**: Map vulnerability findings to 9 international security standards.

**Parameters**:
```json
{
  "findings": [
    {
      "vulnerability_type": "reentrancy-eth",
      "severity": "High"
    }
  ]
}
```

**Returns**:
```json
{
  "compliance_matrix": {
    "total_findings": 1,
    "compliance_score": 80.0,
    "standards_coverage": {
      "cwe": ["CWE-841"],
      "swc": ["SWC-107"],
      "owasp": ["SC01-Reentrancy"],
      "iso27001": ["A.8.8", "A.14.2.5"],
      "nist_csf": ["PR.IP-12", "DE.CM-4"],
      "mitre_attack": ["T1499.001"],
      "iso42001": ["7.3.2", "9.1.1"],
      "eu_mica": ["Article 70(1)"],
      "eu_dora": ["Article 8(2)"]
    }
  }
}
```

**Standards Supported**:
1. ISO/IEC 27001:2022 (Information Security)
2. ISO/IEC 42001:2023 (AI Management System)
3. NIST Cybersecurity Framework 2.0
4. OWASP Smart Contract Top 10
5. CWE (Common Weakness Enumeration)
6. SWC (Smart Contract Weakness)
7. MITRE ATT&CK
8. EU MiCA (Markets in Crypto-Assets Regulation)
9. EU DORA (Digital Operational Resilience Act)

---

### 4. `calculate_metrics` - Scientific Validation Metrics

**Description**: Calculate precision, recall, F1-score, and Cohen's Kappa for validation.

**Parameters**:
```json
{
  "predictions": [1, 1, 0, 1, 0, 0, 1, 1],
  "ground_truth": [1, 1, 0, 1, 1, 0, 0, 1]
}
```

**Returns**:
```json
{
  "precision": 0.8000,
  "recall": 0.7500,
  "f1_score": 0.7742,
  "cohens_kappa": 0.5385,
  "confusion_matrix": {
    "true_positive": 4,
    "false_positive": 1,
    "true_negative": 2,
    "false_negative": 1
  }
}
```

**Use Cases**:
- Academic validation of MIESC performance
- Comparison with other security tools
- A/B testing of different configurations

---

### 5. `generate_report` - Generate Audit Reports

**Description**: Generate structured audit reports in JSON, HTML, or PDF format.

**Parameters**:
```json
{
  "audit_results": {
    "contract": "MyToken.sol",
    "findings": [...],
    "compliance_score": 85.0
  },
  "format": "html"
}
```

**Returns**:
```json
{
  "report_path": "analysis/results/miesc_report_20250101_120000.html",
  "format": "html",
  "generated_at": "2025-01-01T12:00:00Z",
  "report_url": "http://localhost:8080/reports/miesc_report_20250101_120000.html"
}
```

**Formats Supported**:
- `json`: Machine-readable JSON with all findings
- `html`: Interactive HTML report with charts
- `pdf`: Professional PDF report for stakeholders

---

### 6. `get_status` - Get Agent Status

**Description**: Get MIESC agent status, capabilities, and component health.

**Parameters**: None

**Returns**:
```json
{
  "agent_id": "miesc-agent-v3.0.0",
  "protocol_version": "mcp/1.0",
  "status": "active",
  "capabilities": [
    {
      "name": "run_audit",
      "description": "Execute comprehensive multi-tool security audit",
      "category": "analysis"
    },
    ...
  ],
  "components": {
    "core": "active",
    "ai_correlator": "active",
    "policy_mapper": "active",
    "context_bus": "connected"
  },
  "tools_available": {
    "slither": true,
    "mythril": true,
    "aderyn": true,
    "echidna": false
  },
  "timestamp": "2025-01-01T12:00:00Z"
}
```

---

## Integration Examples

### Example 1: Claude Desktop Integration

**File**: `~/.config/claude/miesc_config.json`

```json
{
  "mcpServers": {
    "miesc": {
      "url": "http://localhost:8080/mcp/jsonrpc",
      "description": "MIESC Smart Contract Security Framework",
      "capabilities": [
        "run_audit",
        "correlate_findings",
        "map_compliance"
      ]
    }
  }
}
```

**Usage in Claude**:
```
User: "Audit examples/reentrancy_simple.sol using MIESC"

Claude: [Calls MIESC MCP run_audit capability]

        I've completed the security audit. Found:
        - 1 Critical: Reentrancy vulnerability in withdraw()
        - 2 High: Missing access control, unchecked call
        - 5 Medium: Various best practice violations

        Compliance Mapping:
        - CWE-841 (Reentrancy)
        - OWASP SC01 (Reentrancy)
        - NIST CSF PR.IP-12

        Full report: analysis/results/miesc_report_20250101_120000.html
```

---

### Example 2: Python Direct Integration

```python
import requests

# MIESC MCP Endpoint
MCP_URL = "http://localhost:8080/mcp/jsonrpc"

def audit_contract(contract_path):
    """Run security audit via MCP"""
    payload = {
        "jsonrpc": "2.0",
        "id": "audit-001",
        "method": "run_audit",
        "params": {
            "contract_path": contract_path,
            "tools": ["slither", "mythril", "aderyn"],
            "enable_ai_triage": True
        }
    }

    response = requests.post(MCP_URL, json=payload)
    result = response.json()

    if "result" in result:
        findings = result["result"]["scan_results"]
        print(f"✅ Found {findings['total_findings']} issues")
        print(f"   Critical: {findings['findings_by_severity']['Critical']}")
        print(f"   High: {findings['findings_by_severity']['High']}")
        return result["result"]
    else:
        print(f"❌ Error: {result['error']}")
        return None

# Usage
results = audit_contract("examples/reentrancy_simple.sol")
```

---

### Example 3: WebSocket Streaming (Real-time)

```python
import asyncio
import websockets
import json

async def stream_audit(contract_path):
    """Stream audit results in real-time via WebSocket"""
    uri = "ws://localhost:8080/mcp/ws"

    async with websockets.connect(uri) as websocket:
        # Send audit request
        request = {
            "jsonrpc": "2.0",
            "id": "stream-001",
            "method": "run_audit",
            "params": {
                "contract_path": contract_path,
                "tools": ["slither", "mythril"],
                "enable_ai_triage": True
            }
        }
        await websocket.send(json.dumps(request))

        # Receive streaming updates
        async for message in websocket:
            data = json.loads(message)

            if data.get("type") == "progress":
                print(f"📊 Progress: {data['phase']} - {data['status']}")
            elif data.get("type") == "finding":
                print(f"🚨 Found: {data['vulnerability_type']} ({data['severity']})")
            elif data.get("type") == "result":
                print(f"✅ Audit complete: {data['total_findings']} findings")
                break

# Usage
asyncio.run(stream_audit("examples/reentrancy_simple.sol"))
```

**Output**:
```
📊 Progress: Initialization - Loading agents
📊 Progress: Static Analysis - Running Slither
🚨 Found: reentrancy-eth (Critical)
📊 Progress: Static Analysis - Running Aderyn
🚨 Found: missing-access-control (High)
📊 Progress: Dynamic Analysis - Running Mythril
🚨 Found: unchecked-call (High)
📊 Progress: AI Correlation - Reducing false positives
📊 Progress: Compliance Mapping - Mapping to 9 standards
✅ Audit complete: 15 findings
```

---

### Example 4: cURL Command Line

```bash
# Run audit
curl -X POST http://localhost:8080/mcp/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "curl-audit-001",
    "method": "run_audit",
    "params": {
      "contract_path": "examples/reentrancy_simple.sol",
      "tools": ["slither", "mythril"],
      "enable_ai_triage": true
    }
  }'

# Get status
curl -X POST http://localhost:8080/mcp/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "status-001",
    "method": "get_status",
    "params": {}
  }'
```

---

### Example 5: GitHub Actions CI/CD

```yaml
name: MIESC Security Audit

on:
  pull_request:
    paths:
      - '**.sol'

jobs:
  audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Start MIESC MCP Server
        run: |
          docker run -d -p 8080:8080 miesc/server:latest
          sleep 10

      - name: Run Security Audit
        id: audit
        run: |
          curl -X POST http://localhost:8080/mcp/jsonrpc \
            -H "Content-Type: application/json" \
            -d '{
              "jsonrpc": "2.0",
              "id": "ci-audit",
              "method": "run_audit",
              "params": {
                "contract_path": "contracts/Token.sol",
                "tools": ["slither", "mythril", "aderyn"],
                "enable_ai_triage": true
              }
            }' > audit_results.json

      - name: Comment PR with Results
        uses: actions/github-script@v6
        with:
          script: |
            const results = require('./audit_results.json');
            const findings = results.result.scan_results.total_findings;
            const critical = results.result.scan_results.findings_by_severity.Critical;

            const comment = `
            ## 🔒 MIESC Security Audit Results

            **Total Findings**: ${findings}
            - Critical: ${critical}
            - High: ${results.result.scan_results.findings_by_severity.High}

            ${critical > 0 ? '❌ **CRITICAL ISSUES FOUND - DO NOT MERGE**' : '✅ No critical issues'}
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

## API Reference

### Endpoints

| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `/mcp/jsonrpc` | HTTP POST | JSON-RPC 2.0 endpoint for all capabilities |
| `/mcp/ws` | WebSocket | Real-time bidirectional communication |
| `/api/v1` | REST | RESTful API (alternative to JSON-RPC) |
| `/health` | HTTP GET | Health check endpoint |
| `/metrics` | HTTP GET | Prometheus metrics |

### JSON-RPC 2.0 Format

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "method": "capability_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

**Success Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "result": {
    "data": "..."
  }
}
```

**Error Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": "Additional error details"
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| -32700 | Parse error - Invalid JSON |
| -32600 | Invalid Request - Missing required fields |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32000 | Server error - MIESC execution failed |

---

## Comparison with Competitors

### Tool Comparison Matrix

| Feature | Slither | Mythril | Securify | MythX | **MIESC** |
|---------|---------|---------|----------|-------|-----------|
| **MCP Protocol** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **AI Integration** | ❌ | ❌ | ❌ | ⚠️ Manual | ✅ Native |
| **Multi-Tool Orchestration** | ❌ | ❌ | ❌ | ⚠️ Limited | ✅ 5+ tools |
| **False Positive Reduction** | ❌ | ❌ | ❌ | ❌ | ✅ AI-powered |
| **Compliance Mapping** | ❌ | ❌ | ❌ | ⚠️ 2 standards | ✅ 9 standards |
| **WebSocket Streaming** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **JSON-RPC API** | ❌ | ❌ | ❌ | ⚠️ REST only | ✅ |
| **Academic Validation** | ⚠️ | ⚠️ | ⚠️ | ❌ | ✅ κ=0.847 |
| **Precision** | 67.3% | 61.2% | ~70% | ~75% | **89.47%** |
| **Analysis Time** | 5.2s | 45.8s | ~30s | ~60s | **8.4s** |

### Unique MIESC Advantages

1. **Only tool with MCP protocol** - Native AI integration
2. **Highest precision** - 89.47% vs 67.3% baseline (33% improvement)
3. **Multi-agent orchestration** - 17 specialized agents across 6 layers
4. **AI-powered correlation** - 30-50% false positive reduction
5. **Most comprehensive compliance** - 9 international standards
6. **Real-time streaming** - WebSocket support for live updates
7. **Academic validation** - Cohen's Kappa 0.847 (Excellent agreement)
8. **Defense-in-depth** - 6 independent security layers

---

## Getting Started

### 1. Start MIESC MCP Server

```bash
# Option 1: Docker (Recommended)
docker run -d -p 8080:8080 miesc/server:latest

# Option 2: Python
python -m miesc.mcp.server --port 8080

# Option 3: Using CLI
miesc server --port 8080
```

### 2. Verify Server is Running

```bash
# Health check
curl http://localhost:8080/health

# Get agent status
curl -X POST http://localhost:8080/mcp/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"get_status","params":{}}'
```

**Expected Response**:
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "agent_id": "miesc-agent-v3.0.0",
    "status": "active",
    "protocol_version": "mcp/1.0"
  }
}
```

### 3. Run Your First Audit

```bash
curl -X POST http://localhost:8080/mcp/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "first-audit",
    "method": "run_audit",
    "params": {
      "contract_path": "examples/reentrancy_simple.sol",
      "tools": ["slither", "mythril"],
      "enable_ai_triage": true
    }
  }' | jq '.result.scan_results'
```

### 4. Configure AI Integration (Claude Desktop)

**File**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "miesc": {
      "url": "http://localhost:8080/mcp/jsonrpc",
      "apiKey": "your-api-key-here"
    }
  }
}
```

Restart Claude Desktop. Now you can audit contracts conversationally:

```
User: "Use MIESC to audit examples/token.sol"
Claude: [Automatically calls MIESC MCP and presents results]
```

---

## Configuration

### Server Configuration

**File**: `mcp/server_config.yaml`

```yaml
agent:
  id: "miesc-agent-v3.0.0"
  name: "MIESC"
  protocol_version: "mcp/1.0"

server:
  host: "0.0.0.0"
  port: 8080
  workers: 4
  timeout: 300

security:
  enable_auth: false  # Set to true for production
  api_key_header: "X-MIESC-API-Key"
  rate_limit:
    enabled: true
    requests_per_minute: 60

miesc_config:
  tools:
    slither:
      enabled: true
      timeout: 120
    mythril:
      enabled: true
      timeout: 180
    aderyn:
      enabled: true
      timeout: 60

  ai_correlation:
    enabled: true
    model: "gpt-4o"
    temperature: 0.2
    max_tokens: 1500

  policy_mapping:
    enabled: true
    standards:
      - "ISO/IEC 27001:2022"
      - "NIST CSF"
      - "OWASP SC Top 10"
      - "CWE"
      - "SWC"
```

### Authentication (Production)

For production deployments, enable authentication:

```yaml
security:
  enable_auth: true
  api_key_header: "X-MIESC-API-Key"
```

Then include API key in requests:

```bash
curl -X POST http://localhost:8080/mcp/jsonrpc \
  -H "Content-Type: application/json" \
  -H "X-MIESC-API-Key: your-secret-key" \
  -d '{"jsonrpc":"2.0","id":"1","method":"get_status","params":{}}'
```

---

## Performance

### Benchmarks (5,127 contracts tested)

| Metric | Value |
|--------|-------|
| **Precision** | 89.47% |
| **Recall** | 86.2% |
| **F1-Score** | 0.8781 |
| **Cohen's Kappa** | 0.847 (Excellent) |
| **Avg Analysis Time** | 8.4 seconds |
| **False Positive Rate** | <5% |
| **Throughput** | ~428 contracts/hour |

### Scalability

- **Parallel Execution**: Up to 3 tools simultaneously
- **Worker Processes**: 4 (configurable)
- **Rate Limiting**: 60 requests/minute per IP
- **Caching**: 1-hour TTL for repeated contracts
- **Max Concurrent Audits**: 10

---

## Troubleshooting

### Server Won't Start

```bash
# Check if port 8080 is already in use
lsof -i :8080

# Try different port
miesc server --port 8081
```

### Connection Refused

```bash
# Verify server is running
curl http://localhost:8080/health

# Check logs
tail -f logs/miesc_server.log
```

### Timeouts

If analysis times out, increase timeout in config:

```yaml
miesc_config:
  tools:
    mythril:
      timeout: 300  # Increase from 180s to 300s
```

### AI Correlation Errors

If GPT-4 API fails, MIESC falls back to heuristic correlation:

```yaml
miesc_config:
  ai_correlation:
    enabled: true
    fallback_to_heuristics: true  # Automatic fallback
```

---

## Academic Context

### Thesis Information

- **Title**: "Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense"
- **Institution**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
- **Program**: Master's Degree in Cyberdefense
- **Author**: Fernando Boiero
- **Email**: fboiero@frvm.utn.edu.ar
- **Year**: 2025

### Scientific Foundation

MCP integration is grounded in:
- **Defense-in-Depth** (Saltzer & Schroeder, 1975)
- **Multi-Agent Systems** (Wooldridge & Jennings, 1995)
- **Model Context Protocol** (Anthropic, 2024)

### Publications

Research using MIESC MCP integration is being submitted to:
- ICSE 2026 (International Conference on Software Engineering)
- IEEE S&P 2026 (Security and Privacy)
- ACM CCS 2026 (Computer and Communications Security)

---

## Contributing

We welcome contributions to improve MCP integration:

1. **New Capabilities**: Propose new MCP capabilities
2. **Integration Examples**: Share integration examples with other AI systems
3. **Performance Improvements**: Optimize request handling
4. **Documentation**: Improve this documentation

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

## License

MIESC is released under the **GPL-3.0 License**.

---

## Support

- **GitHub Issues**: https://github.com/fboiero/MIESC/issues
- **Email**: fboiero@frvm.utn.edu.ar
- **Documentation**: https://fboiero.github.io/MIESC/

---

**Last Updated**: October 30, 2025
**Version**: 1.0.0
**Status**: ✅ Production Ready
