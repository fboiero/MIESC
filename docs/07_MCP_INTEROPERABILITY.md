# MCP Interoperability

**Version:** 3.3.0
**Document:** Model Context Protocol Integration
**Last Updated:** 2025-01-18

---

## 🌐 What is MCP?

**Model Context Protocol (MCP)** is an open protocol developed by Anthropic for enabling **communication between AI agents and external tools/systems**.

**Think of it as:** "HTTP for AI agents" - a standardized way for LLM-based systems to interact with each other.

**Official Specification:** [https://spec.modelcontextprotocol.io/](https://spec.modelcontextprotocol.io/)

---

## 🎯 Why MIESC Implements MCP

### Problem: Isolated Security Tools

Traditional security tools operate in silos:

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Slither  │  │  Mythril │  │  Manual  │
│  (CLI)   │  │  (CLI)   │  │  Auditor │
└──────────┘  └──────────┘  └──────────┘
     ↓              ↓              ↓
  Results       Results        Report
  (JSON)        (JSON)         (PDF)

No communication ❌
No context sharing ❌
No collaborative analysis ❌
```

---

### Solution: MCP-Enabled Collaborative Security

With MCP, security agents can collaborate:

```
┌─────────────────────────────────────────────────┐
│         Security Operations Center (SOC)         │
│                MCP Orchestrator                  │
└───────────┬─────────────┬──────────────┬─────────┘
            │             │              │
            ▼             ▼              ▼
    ┌───────────┐  ┌───────────┐  ┌───────────┐
    │   MIESC   │  │  Fuzzing  │  │  Runtime  │
    │   Agent   │  │   Agent   │  │  Monitor  │
    │   (MCP)   │  │   (MCP)   │  │   (MCP)   │
    └───────────┘  └───────────┘  └───────────┘
         ↕              ↕              ↕
     Share findings → Aggregate → Consensus report
```

**Benefits:**
- ✅ Shared context across agents
- ✅ Collaborative threat detection
- ✅ Unified reporting
- ✅ Real-time communication
- ✅ Vendor-agnostic integration

---

## 🏗️ MIESC MCP Architecture

### Dual Interface Design

MIESC exposes MCP through **two complementary interfaces**:

#### 1. JSON-RPC MCP Adapter (Standard)

**File:** `src/miesc_mcp_adapter.py`
**Protocol:** JSON-RPC 2.0 over stdio/websocket
**Use Case:** Direct agent-to-agent communication

```python
from miesc_mcp_adapter import MIESCMCPAdapter

# Initialize
adapter = MIESCMCPAdapter()

# Register capabilities
adapter.register_capability("run_audit", run_audit_handler)
adapter.register_capability("get_metrics", get_metrics_handler)

# Start listening
adapter.listen()  # Waits for JSON-RPC messages on stdin
```

---

#### 2. REST API Wrapper (Practical)

**File:** `src/miesc_mcp_rest.py`
**Protocol:** HTTP REST
**Use Case:** Web-friendly access, testing, dashboards

```python
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/mcp/capabilities', methods=['GET'])
def get_capabilities():
    return jsonify({
        "agent_id": "miesc-agent-v3.3.0",
        "protocol": "mcp/1.0",
        "capabilities": {...}
    })

app.run(host='0.0.0.0', port=5001)
```

**Both interfaces** provide the same underlying MCP functionality.

---

## 📡 MCP Endpoints

### 1. Get Capabilities

**Purpose:** Discover what MIESC can do
**Endpoint:** `GET /mcp/capabilities`
**JSON-RPC:** `{"method": "capabilities"}`

**Request:**

```bash
curl http://localhost:5001/mcp/capabilities
```

**Response:**

```json
{
  "agent_id": "miesc-agent-v3.3.0",
  "protocol": "mcp/1.0",
  "capabilities": {
    "run_audit": {
      "description": "Analyze smart contract for vulnerabilities",
      "input_schema": {
        "type": "object",
        "properties": {
          "contract": {"type": "string", "description": "Path or code"},
          "enable_ai": {"type": "boolean", "default": true},
          "tools": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["contract"]
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "findings": {"type": "array"},
          "summary": {"type": "object"},
          "metadata": {"type": "object"}
        }
      }
    },
    "get_metrics": {
      "description": "Retrieve scientific validation metrics",
      "input_schema": {"type": "object", "properties": {}},
      "output_schema": {
        "type": "object",
        "properties": {
          "precision": {"type": "number"},
          "recall": {"type": "number"},
          "f1_score": {"type": "number"},
          "cohens_kappa": {"type": "number"}
        }
      }
    },
    "policy_audit": {
      "description": "Run PolicyAgent internal compliance check",
      "input_schema": {
        "type": "object",
        "properties": {
          "repo_path": {"type": "string"}
        }
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "compliance_score": {"type": "number"},
          "checks": {"type": "array"}
        }
      }
    }
  }
}
```

---

### 2. Health Check

**Purpose:** Verify MIESC agent is running
**Endpoint:** `GET /mcp/status`
**JSON-RPC:** `{"method": "status"}`

**Request:**

```bash
curl http://localhost:5001/mcp/status
```

**Response:**

```json
{
  "status": "healthy",
  "version": "3.3.0",
  "uptime_seconds": 3627,
  "last_analysis": "2025-01-18T14:23:15Z",
  "total_analyses": 42,
  "queue_length": 0
}
```

---

### 3. Get Metrics

**Purpose:** Retrieve MIESC's scientific validation metrics
**Endpoint:** `GET /mcp/get_metrics`
**JSON-RPC:** `{"method": "get_metrics"}`

**Request:**

```bash
curl http://localhost:5001/mcp/get_metrics | jq
```

**Response:**

```json
{
  "metrics": {
    "precision": 0.8947,
    "recall": 0.862,
    "f1_score": 0.8781,
    "cohens_kappa": 0.847,
    "false_positive_reduction": 0.43,
    "average_confidence": 0.87
  },
  "dataset": {
    "name": "SmartBugs Wild",
    "contracts_analyzed": 5127,
    "vulnerabilities_found": 4012,
    "true_positives": 3589,
    "false_positives": 423
  },
  "benchmark_date": "2025-01-15",
  "miesc_version": "3.3.0"
}
```

---

### 4. Run Audit

**Purpose:** Trigger contract analysis
**Endpoint:** `POST /mcp/run_audit`
**JSON-RPC:** `{"method": "run_audit", "params": {...}}`

**Request:**

```bash
curl -X POST http://localhost:5001/mcp/run_audit \
  -H "Content-Type: application/json" \
  -d '{
    "contract": "demo/sample_contracts/Reentrancy.sol",
    "enable_ai": true,
    "tools": ["slither", "mythril"]
  }'
```

**Response:**

```json
{
  "status": "success",
  "analysis_id": "audit-20250118-142315-abc123",
  "metadata": {
    "contract": "Reentrancy.sol",
    "timestamp": "2025-01-18T14:23:15Z",
    "analysis_duration": 42.3,
    "tools_used": ["slither", "mythril"],
    "ai_correlation_enabled": true
  },
  "summary": {
    "total_findings": 6,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "findings": [
    {
      "id": "MIESC-001",
      "vulnerability_type": "reentrancy-eth",
      "severity": "Critical",
      "confidence": 0.95,
      "location": {"file": "Reentrancy.sol", "line": 41},
      "description": "Reentrancy vulnerability in withdraw function",
      "remediation": "Apply Checks-Effects-Interactions pattern",
      "cvss": 9.1,
      "references": {
        "cwe": "CWE-841",
        "swc": "SWC-107",
        "owasp": "SC01"
      }
    }
  ]
}
```

---

### 5. Policy Audit

**Purpose:** Run PolicyAgent compliance check
**Endpoint:** `POST /mcp/policy_audit`
**JSON-RPC:** `{"method": "policy_audit", "params": {...}}`

**Request:**

```bash
curl -X POST http://localhost:5001/mcp/policy_audit \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "."}'
```

**Response:**

```json
{
  "status": "success",
  "compliance_score": 94.2,
  "timestamp": "2025-01-18T14:30:00Z",
  "checks": [
    {
      "policy_id": "CQ-001",
      "name": "Ruff Linting",
      "status": "pass",
      "severity": "medium"
    },
    {
      "policy_id": "SEC-001",
      "name": "Bandit SAST",
      "status": "pass",
      "severity": "critical"
    }
  ],
  "framework_alignment": {
    "ISO_27001": {"compliance": 100.0},
    "NIST_SSDF": {"compliance": 91.7}
  }
}
```

---

## 🔌 Integration Examples

### Example 1: Python Client

```python
import requests
import json

class MIESCClient:
    def __init__(self, base_url="http://localhost:5001"):
        self.base_url = base_url

    def get_capabilities(self):
        """Discover MIESC capabilities"""
        response = requests.get(f"{self.base_url}/mcp/capabilities")
        return response.json()

    def run_audit(self, contract_path: str, enable_ai: bool = True):
        """Analyze a smart contract"""
        response = requests.post(
            f"{self.base_url}/mcp/run_audit",
            json={
                "contract": contract_path,
                "enable_ai": enable_ai
            }
        )
        return response.json()

    def get_metrics(self):
        """Get scientific metrics"""
        response = requests.get(f"{self.base_url}/mcp/get_metrics")
        return response.json()

# Usage
client = MIESCClient()

# Discover capabilities
caps = client.get_capabilities()
print(f"Agent ID: {caps['agent_id']}")

# Run analysis
result = client.run_audit("contracts/MyContract.sol")
print(f"Found {result['summary']['total_findings']} vulnerabilities")

# Get metrics
metrics = client.get_metrics()
print(f"Precision: {metrics['metrics']['precision']}")
```

---

### Example 2: JavaScript/Node.js Client

```javascript
const axios = require('axios');

class MIESCClient {
  constructor(baseURL = 'http://localhost:5001') {
    this.client = axios.create({ baseURL });
  }

  async getCapabilities() {
    const response = await this.client.get('/mcp/capabilities');
    return response.data;
  }

  async runAudit(contractPath, enableAI = true) {
    const response = await this.client.post('/mcp/run_audit', {
      contract: contractPath,
      enable_ai: enableAI
    });
    return response.data;
  }

  async getMetrics() {
    const response = await this.client.get('/mcp/get_metrics');
    return response.data;
  }
}

// Usage
(async () => {
  const miesc = new MIESCClient();

  // Run audit
  const result = await miesc.runAudit('contracts/MyContract.sol');
  console.log(`Critical findings: ${result.summary.critical}`);

  // Get metrics
  const metrics = await miesc.getMetrics();
  console.log(`F1 Score: ${metrics.metrics.f1_score}`);
})();
```

---

### Example 3: Bash/curl Script

```bash
#!/bin/bash
# miesc_mcp_client.sh

MCP_URL="http://localhost:5001"

# Get capabilities
echo "Fetching MIESC capabilities..."
curl -s "$MCP_URL/mcp/capabilities" | jq '.agent_id'

# Run audit
echo "Running audit on contract..."
RESULT=$(curl -s -X POST "$MCP_URL/mcp/run_audit" \
  -H "Content-Type: application/json" \
  -d '{"contract": "demo/sample_contracts/Reentrancy.sol"}')

# Extract critical findings
CRITICAL=$(echo "$RESULT" | jq '.summary.critical')
echo "Critical findings: $CRITICAL"

# Get metrics
echo "Fetching metrics..."
curl -s "$MCP_URL/mcp/get_metrics" | jq '.metrics.precision'
```

---

## 🔗 Multi-Agent Collaboration

### Use Case: Security Operations Center (SOC)

**Scenario:** Multiple specialized security agents collaborate to analyze a DeFi protocol.

**Agents:**
1. **MIESC** - Static/symbolic analysis
2. **FuzzingAgent** - Property-based fuzzing
3. **RuntimeMonitor** - Mainnet transaction monitoring
4. **ThreatIntel** - Known exploit patterns

**Workflow:**

```
┌─────────────────────────────────────────────────────┐
│                   SOC Orchestrator                  │
│              (Claude 3.5 Sonnet + MCP)              │
└───────┬──────────┬──────────┬──────────┬────────────┘
        │          │          │          │
        ▼          ▼          ▼          ▼
    ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐
    │MIESC  │  │Fuzzer │  │Runtime│  │Threat │
    │ Agent │  │ Agent │  │Monitor│  │ Intel │
    └───┬───┘  └───┬───┘  └───┬───┘  └───┬───┘
        │          │          │          │
        │  1. Deploy contract to testnet  │
        ◄─────────────────────────────────┘
        │
        │  2. MIESC: "Found reentrancy on line 41"
        ├──────────────────────────────────►
        │
        │  3. Orchestrator: "FuzzAgent, verify"
        ├──────────────────────────────────►
        │                   │
        │  4. Fuzzer: "Confirmed! Generated exploit"
        ◄───────────────────┘
        │
        │  5. Orchestrator: "RuntimeMonitor, watch mainnet"
        ├──────────────────────────────────►
        │                                  │
        │  6. Monitor: "No exploits yet"   │
        ◄──────────────────────────────────┘
        │
        │  7. Orchestrator: "ThreatIntel, check history"
        ├──────────────────────────────────►
        │                                             │
        │  8. ThreatIntel: "Similar to DAO Hack 2016"│
        ◄─────────────────────────────────────────────┘
        │
        ▼
  ┌────────────────────────────────┐
  │ SOC Dashboard:                 │
  │ ✅ Static analysis: Critical   │
  │ ✅ Fuzzing: Exploit found      │
  │ ⏳ Runtime: Monitoring          │
  │ ⚠️ ThreatIntel: Known pattern  │
  │                                │
  │ Recommendation: DO NOT DEPLOY  │
  └────────────────────────────────┘
```

**MCP enables:**
- **Context sharing** - Each agent sees prior findings
- **Collaborative verification** - Cross-agent confirmation
- **Unified dashboard** - Single pane of glass
- **Intelligent routing** - Orchestrator assigns tasks

---

## 🛠️ Deployment Scenarios

### Scenario 1: Standalone MCP Server

```bash
# Start MIESC as MCP server
python src/miesc_mcp_rest.py --host 0.0.0.0 --port 5001

# Access from anywhere
curl http://miesc-server.example.com:5001/mcp/status
```

**Use Case:** Centralized security service for multiple teams

---

### Scenario 2: Docker Container

```dockerfile
# Dockerfile
FROM python:3.10

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/
EXPOSE 5001

CMD ["python", "src/miesc_mcp_rest.py", "--host", "0.0.0.0", "--port", "5001"]
```

```bash
# Build and run
docker build -t miesc-mcp .
docker run -p 5001:5001 miesc-mcp

# Kubernetes deployment
kubectl apply -f k8s/miesc-mcp-deployment.yaml
```

---

### Scenario 3: Serverless (AWS Lambda)

```python
# lambda_handler.py
import json
from miesc_mcp_adapter import handle_mcp_request

def lambda_handler(event, context):
    """AWS Lambda handler for MCP requests"""
    body = json.loads(event['body'])
    result = handle_mcp_request(body)

    return {
        'statusCode': 200,
        'body': json.dumps(result)
    }
```

**Trigger:** API Gateway → Lambda → MIESC MCP

---

## 🔐 Security Considerations

### Authentication

**Current (v3.3.0):** No authentication (localhost only)

**Future (v3.4.0):** API key authentication

```python
# Future implementation
@app.before_request
def authenticate():
    api_key = request.headers.get('X-API-Key')
    if api_key != os.getenv('MIESC_API_KEY'):
        abort(401, "Unauthorized")
```

---

### Rate Limiting

```python
# Future implementation
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["100 per hour"]
)

@app.route('/mcp/run_audit', methods=['POST'])
@limiter.limit("10 per minute")
def run_audit():
    # ... audit logic
```

---

### Input Validation

```python
# Current implementation
from pydantic import BaseModel, validator

class AuditRequest(BaseModel):
    contract: str
    enable_ai: bool = True
    tools: list[str] = ["slither", "mythril"]

    @validator('contract')
    def validate_contract(cls, v):
        if not v.endswith('.sol'):
            raise ValueError('Must be a .sol file')
        if '../' in v:
            raise ValueError('Path traversal not allowed')
        return v
```

---

## 📊 Performance

### Latency Benchmarks

| Endpoint | Avg Latency | P95 Latency | P99 Latency |
|----------|-------------|-------------|-------------|
| `/mcp/capabilities` | 12 ms | 25 ms | 42 ms |
| `/mcp/status` | 8 ms | 15 ms | 28 ms |
| `/mcp/get_metrics` | 95 ms | 180 ms | 320 ms |
| `/mcp/run_audit` | 45 s | 72 s | 98 s |
| `/mcp/policy_audit` | 28 s | 42 s | 58 s |

**Note:** Audit endpoints are intentionally slow (deep analysis)

---

### Scalability

**Current (v3.3.0):** Single-threaded, synchronous

**Future (v3.4.0):** Async with Celery task queue

```python
# Planned architecture
from celery import Celery
celery = Celery('miesc_mcp', broker='redis://localhost:6379')

@celery.task
def async_run_audit(contract_path):
    # Run audit in background
    result = miesc.run_audit(contract_path)
    return result

@app.route('/mcp/run_audit', methods=['POST'])
def run_audit():
    data = request.json
    task = async_run_audit.delay(data['contract'])
    return jsonify({"task_id": task.id, "status": "queued"})
```

**Expected:** 10x throughput increase

---

## 🔮 Future Roadmap

### v3.4.0 (Q2 2025)

- [ ] Async processing with Celery
- [ ] API key authentication
- [ ] Rate limiting
- [ ] WebSocket support for real-time updates

### v3.5.0 (Q3 2025)

- [ ] Native MCP JSON-RPC over WebSocket
- [ ] Multi-agent collaboration examples
- [ ] MCP compliance test suite
- [ ] Official MCP registry listing

### v4.0.0 (Q4 2025)

- [ ] Full MCP v2.0 support
- [ ] Agent-to-agent direct communication
- [ ] Distributed MIESC cluster
- [ ] LangChain/LlamaIndex integration

---

**Next:** Read `docs/08_METRICS_AND_RESULTS.md` for scientific validation.

---

**Version:** 3.3.0
**Maintainer:** Fernando Boiero - UNDEF
**MCP Protocol:** v1.0 (Anthropic)
**Status:** 🚀 Production Ready
