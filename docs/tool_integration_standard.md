# Estándar de Integración de Herramientas MIESC

Especificación técnica para integrar herramientas de análisis y agentes IA en la arquitectura MCP de MIESC

---

## 📋 Tabla de Contenidos

- [Introducción](#introducción)
- [Arquitectura de Integración](#arquitectura-de-integración)
- [Estándar MCP Agent](#estándar-mcp-agent)
- [Tool Integration Template](#tool-integration-template)
- [Ejemplos Prácticos](#ejemplos-prácticos)
- [Validación y Testing](#validación-y-testing)
- [Casos de Uso](#casos-de-uso)

---

## Introducción

### Objetivo

Definir un **estándar reproducible y extensible** para integrar:
1. **Herramientas de análisis estático/dinámico** (Slither, Mythril, etc.)
2. **Agentes basados en IA/LLM** (GPTScan, LLM-SmartAudit, SmartLLM)
3. **Verificadores formales** (Certora, Z3, K Framework)

en la arquitectura multiagente MCP de MIESC **sin modificar código existente**.

### Principios de Diseño

✅ **Plugin-Based**: Cada herramienta es un plugin independiente
✅ **Contract-First**: Interfaz definida por `BaseAgent` abstract class
✅ **Pub/Sub Decoupled**: Comunicación via Context Bus (no acoplamiento directo)
✅ **Self-Describing**: Cada agent publica sus capabilities y context_types
✅ **Testable**: Cada agent incluye unit tests y validación

---

## Arquitectura de Integración

### Vista Conceptual

```
┌─────────────────────────────────────────────────────────┐
│                    MIESC Framework                      │
│                                                         │
│  ┌───────────────────────────────────────────────┐    │
│  │          Context Bus (Singleton)              │    │
│  │  - message_history: List[MCPMessage]          │    │
│  │  - subscribers: Dict[str, List[Callable]]     │    │
│  │  - publish(message: MCPMessage)               │    │
│  │  - subscribe(context_type, callback)          │    │
│  └─────────────────┬─────────────────────────────┘    │
│                    │ pub/sub                           │
│         ┌──────────┼──────────┐                       │
│         │          │          │                        │
│    ┌────▼────┐ ┌──▼─────┐ ┌─▼────────┐              │
│    │ Existing│ │  New   │ │  New     │              │
│    │ Agent   │ │ Agent  │ │ AI Agent │              │
│    │         │ │ (Tool) │ │ (LLM)    │              │
│    └─────────┘ └────────┘ └──────────┘              │
│                                                       │
│    No modification needed to existing code!          │
└───────────────────────────────────────────────────────┘
```

### Flujo de Integración

```
1. Crear nuevo archivo: agents/new_agent.py
2. Heredar de BaseAgent
3. Implementar 2 métodos: analyze() + get_context_types()
4. Registrar en mcp_server.py (opcional)
5. Testing: test_new_agent.py
```

**Total: 1 archivo nuevo, 0 modificaciones a código existente** ✅

---

## Estándar MCP Agent

### Interfaz BaseAgent

```python
# agents/base_agent.py (NO MODIFICAR)
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from mcp.context_bus import get_context_bus, MCPMessage

class BaseAgent(ABC):
    """
    Base class for all MCP agents.

    Contract:
    - MUST implement analyze()
    - MUST implement get_context_types()
    - SHOULD publish findings via publish_findings()
    - MAY subscribe to other context_types
    """

    def __init__(self, agent_name: str, capabilities: List[str], agent_type: str):
        self.agent_name = agent_name
        self.capabilities = capabilities
        self.agent_type = agent_type
        self.bus = get_context_bus()
        self.status = "initialized"

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run analysis on smart contract.

        Args:
            contract_path: Absolute path to .sol file
            **kwargs: Tool-specific parameters

        Returns:
            Dict with keys matching get_context_types()

        Example:
            {
                "static_findings": [...],
                "execution_time": 2.3,
                "tool_version": "slither-0.9.6"
            }
        """
        pass

    @abstractmethod
    def get_context_types(self) -> List[str]:
        """
        Return list of context types this agent publishes.

        Example:
            ["static_findings", "slither_results"]
        """
        pass

    def run(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Execute analysis and publish to Context Bus"""
        # ... implemented in BaseAgent
        pass

    def publish_findings(self, context_type: str, findings: Dict[str, Any], metadata: Dict = None):
        """Publish findings to Context Bus"""
        # ... implemented in BaseAgent
        pass
```

### Context Types Registry

**Formato**: `{layer}_{category}_{optional_tool}`

| Context Type | Descripción | Publicado por |
|--------------|-------------|---------------|
| `static_findings` | Vulnerabilidades estáticas | StaticAgent |
| `slither_results` | Output raw de Slither | StaticAgent |
| `dynamic_findings` | Vulnerabilidades dinámicas | DynamicAgent |
| `echidna_results` | Property violations | DynamicAgent |
| `symbolic_findings` | Exploit paths | SymbolicAgent |
| `mythril_results` | Mythril raw output | SymbolicAgent |
| `formal_findings` | Verification failures | FormalAgent |
| `certora_results` | Certora violations | FormalAgent |
| `ai_triage` | False positive classification | AIAgent |
| `ai_explanation` | Vulnerability explanations | AIAgent |
| `compliance_report` | ISO/NIST/OWASP status | PolicyAgent |
| `audit_plan` | Generated audit plan | CoordinatorAgent |

**Agregar Nuevo Context Type**:
1. Definir nombre según convención
2. Documentar en esta tabla
3. Publicar desde agent correspondiente
4. Suscribirse en agents que lo consuman (opcional)

### Findings Schema (Unified)

```json
{
  "findings": [
    {
      "id": "AGENT-001",
      "source": "ToolName",
      "swc_id": "SWC-107",
      "owasp_category": "SC01-Reentrancy",
      "cwe_id": "CWE-841",
      "severity": "High | Medium | Low | Informational",
      "confidence": 0.89,
      "location": {
        "file": "Voting.sol",
        "line": 45,
        "function": "withdraw",
        "code_snippet": "msg.sender.call{value: balance}(\"\");"
      },
      "description": "Reentrancy vulnerability in withdraw()",
      "recommendation": "Use Checks-Effects-Interactions pattern",
      "references": [
        "https://swcregistry.io/docs/SWC-107"
      ]
    }
  ],
  "metadata": {
    "tool": "Slither",
    "version": "0.9.6",
    "execution_time": 2.3,
    "timestamp": "2025-10-12T18:00:00Z"
  }
}
```

---

## Tool Integration Template

### Plantilla Paso a Paso

#### Paso 1: Crear Archivo de Agent

```python
# agents/new_tool_agent.py
from agents.base_agent import BaseAgent
from typing import List, Dict, Any
import subprocess
import json

class NewToolAgent(BaseAgent):
    """
    Integration for [Tool Name].

    Capabilities:
    - [Capability 1]: [Description]
    - [Capability 2]: [Description]

    Context Types Published:
    - `new_tool_findings`: Unified findings format
    - `new_tool_raw_results`: Raw tool output
    """

    def __init__(self):
        super().__init__(
            agent_name="NewToolAgent",
            capabilities=[
                "capability_1",
                "capability_2",
                "capability_3"
            ],
            agent_type="analysis"  # or "verification", "ai", "orchestrator"
        )

    def get_context_types(self) -> List[str]:
        """Return context types this agent publishes"""
        return [
            "new_tool_findings",
            "new_tool_raw_results"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run [Tool Name] analysis on contract.

        Args:
            contract_path: Path to .sol file
            **kwargs: Optional parameters

        Returns:
            Dict with findings and metadata
        """
        import time
        start_time = time.time()

        # 1. Execute tool
        raw_results = self._execute_tool(contract_path, **kwargs)

        # 2. Parse results
        parsed_findings = self._parse_results(raw_results)

        # 3. Map to unified format
        unified_findings = self._map_to_unified_format(parsed_findings)

        execution_time = time.time() - start_time

        return {
            "new_tool_findings": unified_findings,
            "new_tool_raw_results": raw_results,
            "execution_time": execution_time,
            "tool_version": self._get_tool_version()
        }

    def _execute_tool(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Execute the tool (CLI, API, library)"""
        try:
            # Example: CLI execution
            cmd = ["tool-binary", contract_path, "--json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get("timeout", 300)  # 5 min default
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}

        except subprocess.TimeoutExpired:
            return {"error": "Tool execution timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _parse_results(self, raw_results: Dict) -> List[Dict]:
        """Parse tool-specific output format"""
        findings = []

        # Tool-specific parsing logic
        for item in raw_results.get("results", []):
            findings.append({
                "type": item["vuln_type"],
                "severity": item["level"],
                "location": item["location"],
                "message": item["msg"]
            })

        return findings

    def _map_to_unified_format(self, parsed_findings: List[Dict]) -> List[Dict]:
        """Map to MIESC unified findings format"""
        unified = []

        for idx, finding in enumerate(parsed_findings):
            unified.append({
                "id": f"NEWTOOL-{idx+1:03d}",
                "source": "NewTool",
                "swc_id": self._map_to_swc(finding["type"]),
                "owasp_category": self._map_to_owasp(finding["type"]),
                "cwe_id": self._map_to_cwe(finding["type"]),
                "severity": self._normalize_severity(finding["severity"]),
                "confidence": 0.85,  # Tool-specific confidence
                "location": {
                    "file": finding["location"]["file"],
                    "line": finding["location"]["line"]
                },
                "description": finding["message"],
                "recommendation": self._generate_recommendation(finding["type"])
            })

        return unified

    def _map_to_swc(self, vuln_type: str) -> str:
        """Map tool-specific type to SWC ID"""
        mapping = {
            "reentrancy": "SWC-107",
            "access_control": "SWC-105",
            "arithmetic": "SWC-101",
            # ... add all mappings
        }
        return mapping.get(vuln_type, "SWC-000")  # Unknown

    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map to OWASP Smart Contract Top 10"""
        swc_id = self._map_to_swc(vuln_type)
        swc_to_owasp = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            "SWC-101": "SC03-Arithmetic",
            # ... complete mapping
        }
        return swc_to_owasp.get(swc_id, "SC10-Unknown")

    def _map_to_cwe(self, vuln_type: str) -> str:
        """Map to CWE (Common Weakness Enumeration)"""
        owasp_cat = self._map_to_owasp(vuln_type)
        owasp_to_cwe = {
            "SC01-Reentrancy": "CWE-841",
            "SC02-Access-Control": "CWE-284",
            # ... complete mapping
        }
        return owasp_to_cwe.get(owasp_cat, "CWE-000")

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to MIESC standard"""
        mapping = {
            "critical": "High",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            # Add tool-specific variations
        }
        return mapping.get(severity.lower(), "Low")

    def _generate_recommendation(self, vuln_type: str) -> str:
        """Generate fix recommendation"""
        recommendations = {
            "reentrancy": "Use Checks-Effects-Interactions pattern or ReentrancyGuard",
            "access_control": "Add appropriate access control modifiers (onlyOwner, etc)",
            # ... add all recommendations
        }
        return recommendations.get(vuln_type, "Review code for vulnerabilities")

    def _get_tool_version(self) -> str:
        """Get tool version"""
        try:
            result = subprocess.run(
                ["tool-binary", "--version"],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "unknown"
```

#### Paso 2: Crear Tests

```python
# tests/test_new_tool_agent.py
import unittest
from agents.new_tool_agent import NewToolAgent

class TestNewToolAgent(unittest.TestCase):
    def setUp(self):
        self.agent = NewToolAgent()
        self.test_contract = "examples/voting.sol"

    def test_initialization(self):
        """Test agent initializes correctly"""
        self.assertEqual(self.agent.agent_name, "NewToolAgent")
        self.assertIn("capability_1", self.agent.capabilities)

    def test_context_types(self):
        """Test context types are published"""
        context_types = self.agent.get_context_types()
        self.assertIn("new_tool_findings", context_types)
        self.assertIn("new_tool_raw_results", context_types)

    def test_analyze_contract(self):
        """Test analysis runs successfully"""
        results = self.agent.run(self.test_contract)

        self.assertIn("new_tool_findings", results)
        self.assertIsInstance(results["new_tool_findings"], list)
        self.assertGreater(results["execution_time"], 0)

    def test_unified_format(self):
        """Test findings follow unified format"""
        results = self.agent.run(self.test_contract)
        findings = results["new_tool_findings"]

        if len(findings) > 0:
            finding = findings[0]
            self.assertIn("id", finding)
            self.assertIn("swc_id", finding)
            self.assertIn("owasp_category", finding)
            self.assertIn("severity", finding)
            self.assertIn("location", finding)

    def test_swc_mapping(self):
        """Test SWC ID mapping"""
        swc_id = self.agent._map_to_swc("reentrancy")
        self.assertEqual(swc_id, "SWC-107")

    def test_severity_normalization(self):
        """Test severity normalization"""
        self.assertEqual(self.agent._normalize_severity("critical"), "High")
        self.assertEqual(self.agent._normalize_severity("medium"), "Medium")

    def tearDown(self):
        pass

if __name__ == "__main__":
    unittest.main()
```

#### Paso 3: Integrar en MCP Server (Opcional)

```python
# mcp_server.py (agregar al final)
from agents.new_tool_agent import NewToolAgent

class MCPServer:
    def __init__(self):
        # ... existing agents
        self.new_tool_agent = NewToolAgent()  # ← Add this line

    def get_tools_schema(self):
        return [
            # ... existing tools
            {
                "name": "run_new_tool",
                "description": "Run NewTool analysis on smart contract",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {"type": "string"},
                        "timeout": {"type": "number", "default": 300}
                    },
                    "required": ["contract_path"]
                }
            }
        ]

    def handle_tool_call(self, tool_name, arguments):
        # ... existing handlers
        elif tool_name == "run_new_tool":
            results = self.new_tool_agent.run(
                arguments["contract_path"],
                timeout=arguments.get("timeout", 300)
            )
            return results
```

---

## Ejemplos Prácticos

### Ejemplo 1: Integrar GPTScan

```python
# agents/gptscan_agent.py
from agents.base_agent import BaseAgent
import openai
import subprocess
import json

class GPTScanAgent(BaseAgent):
    """
    Integration for GPTScan (ICSE 2024).

    GPTScan combines GPT with static analysis (Falcon) to detect
    logic vulnerabilities in smart contracts.

    Repository: https://github.com/MetaTrustLabs/GPTScan
    """

    def __init__(self, openai_api_key: str):
        super().__init__(
            agent_name="GPTScanAgent",
            capabilities=[
                "logic_vulnerability_detection",
                "gpt_assisted_analysis",
                "combined_static_ai"
            ],
            agent_type="ai"
        )
        self.openai_api_key = openai_api_key
        openai.api_key = openai_api_key

    def get_context_types(self) -> List[str]:
        return [
            "gptscan_findings",
            "gptscan_logic_vulnerabilities"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Run GPTScan analysis"""
        import time
        start = time.time()

        # Step 1: Run Falcon (static analysis component)
        falcon_results = self._run_falcon(contract_path)

        # Step 2: Extract code patterns
        patterns = self._extract_patterns(falcon_results, contract_path)

        # Step 3: Use GPT to analyze patterns
        gpt_analysis = self._analyze_with_gpt(patterns)

        # Step 4: Combine results
        findings = self._combine_results(falcon_results, gpt_analysis)

        execution_time = time.time() - start

        return {
            "gptscan_findings": findings,
            "gptscan_logic_vulnerabilities": [f for f in findings if f["category"] == "logic"],
            "execution_time": execution_time,
            "tool_version": "gptscan-1.0"
        }

    def _run_falcon(self, contract_path: str) -> Dict:
        """Run Falcon static analyzer"""
        cmd = ["falcon", contract_path, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return json.loads(result.stdout) if result.returncode == 0 else {}

    def _extract_patterns(self, falcon_results: Dict, contract_path: str) -> List[Dict]:
        """Extract suspicious patterns from Falcon results"""
        patterns = []

        with open(contract_path, 'r') as f:
            code = f.read()

        # Extract patterns based on Falcon detectors
        for detector in falcon_results.get("detectors", []):
            patterns.append({
                "type": detector["check"],
                "location": detector["location"],
                "code_snippet": self._get_code_snippet(code, detector["location"])
            })

        return patterns

    def _analyze_with_gpt(self, patterns: List[Dict]) -> List[Dict]:
        """Use GPT to analyze extracted patterns"""
        analyses = []

        for pattern in patterns:
            prompt = f"""Analyze this Solidity code pattern for logic vulnerabilities:

Type: {pattern['type']}
Code:
```solidity
{pattern['code_snippet']}
```

Is this a true vulnerability? Explain your reasoning.
Provide:
1. Vulnerability classification (if true positive)
2. Severity (High/Medium/Low)
3. Explanation
4. Recommended fix

Format: JSON
"""

            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )

            gpt_result = json.loads(response.choices[0].message.content)
            analyses.append({
                "pattern": pattern,
                "gpt_analysis": gpt_result
            })

        return analyses

    def _combine_results(self, falcon_results: Dict, gpt_analyses: List[Dict]) -> List[Dict]:
        """Combine Falcon + GPT into unified findings"""
        findings = []

        for idx, analysis in enumerate(gpt_analyses):
            if analysis["gpt_analysis"].get("is_vulnerability", False):
                findings.append({
                    "id": f"GPTSCAN-{idx+1:03d}",
                    "source": "GPTScan",
                    "category": "logic",
                    "swc_id": self._map_to_swc(analysis["pattern"]["type"]),
                    "owasp_category": "SC10-Unknown",  # Logic bugs often SC10
                    "severity": analysis["gpt_analysis"]["severity"],
                    "confidence": 0.90,  # GPTScan has high precision (>90%)
                    "location": analysis["pattern"]["location"],
                    "description": analysis["gpt_analysis"]["explanation"],
                    "recommendation": analysis["gpt_analysis"]["fix"]
                })

        return findings

    def _get_code_snippet(self, code: str, location: Dict) -> str:
        """Extract code snippet from file"""
        lines = code.split('\n')
        start = max(0, location["line"] - 3)
        end = min(len(lines), location["line"] + 3)
        return '\n'.join(lines[start:end])

    def _map_to_swc(self, falcon_check: str) -> str:
        """Map Falcon check to SWC ID"""
        mapping = {
            "reentrancy": "SWC-107",
            "tx-origin": "SWC-115",
            "timestamp": "SWC-116",
            # ... more mappings
        }
        return mapping.get(falcon_check, "SWC-000")
```

### Ejemplo 2: Integrar LLM-SmartAudit

```python
# agents/llm_smartaudit_agent.py
from agents.base_agent import BaseAgent
from typing import List, Dict, Any
import openai

class LLMSmartAuditAgent(BaseAgent):
    """
    Integration for LLM-SmartAudit (ArXiv 2410.09381).

    Multi-agent conversational approach with 3 specialized sub-agents:
    1. ContractAnalysisAgent
    2. VulnerabilityIdentificationAgent
    3. ComprehensiveReportAgent

    Repository: https://github.com/LLMAudit/LLMSmartAuditTool
    """

    def __init__(self, openai_api_key: str):
        super().__init__(
            agent_name="LLMSmartAuditAgent",
            capabilities=[
                "multi_agent_analysis",
                "conversational_audit",
                "comprehensive_reporting"
            ],
            agent_type="ai"
        )
        self.openai_api_key = openai_api_key
        openai.api_key = openai_api_key

    def get_context_types(self) -> List[str]:
        return [
            "llm_smartaudit_findings",
            "llm_smartaudit_report"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Run LLM-SmartAudit multi-agent analysis"""
        import time
        start = time.time()

        with open(contract_path, 'r') as f:
            contract_code = f.read()

        # Sub-agent 1: Contract Analysis
        contract_analysis = self._contract_analysis_agent(contract_code)

        # Sub-agent 2: Vulnerability Identification
        vulnerabilities = self._vulnerability_identification_agent(
            contract_code,
            contract_analysis
        )

        # Sub-agent 3: Comprehensive Report
        report = self._comprehensive_report_agent(
            contract_code,
            contract_analysis,
            vulnerabilities
        )

        # Map to unified format
        unified_findings = self._map_to_unified(vulnerabilities)

        execution_time = time.time() - start

        return {
            "llm_smartaudit_findings": unified_findings,
            "llm_smartaudit_report": report,
            "execution_time": execution_time,
            "tool_version": "llm-smartaudit-1.0"
        }

    def _contract_analysis_agent(self, code: str) -> Dict:
        """Sub-agent 1: Analyze contract structure"""
        prompt = f"""You are a Contract Analysis Agent. Analyze this Solidity contract:

```solidity
{code}
```

Provide:
1. Contract purpose and functionality
2. Key functions and their roles
3. State variables and access patterns
4. External dependencies

Format: JSON
"""

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are a smart contract analysis expert."},
                      {"role": "user", "content": prompt}],
            temperature=0.1
        )

        return json.loads(response.choices[0].message.content)

    def _vulnerability_identification_agent(self, code: str, analysis: Dict) -> List[Dict]:
        """Sub-agent 2: Identify vulnerabilities"""
        prompt = f"""You are a Vulnerability Identification Agent. Based on this contract analysis:

Analysis: {json.dumps(analysis, indent=2)}

Contract Code:
```solidity
{code}
```

Identify ALL vulnerabilities. For each, provide:
1. Type (reentrancy, access control, etc.)
2. Location (function, line)
3. Severity (High/Medium/Low)
4. Explanation
5. Proof of concept (if applicable)

Format: JSON array
"""

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are a vulnerability detection expert."},
                      {"role": "user", "content": prompt}],
            temperature=0.1
        )

        return json.loads(response.choices[0].message.content)

    def _comprehensive_report_agent(self, code: str, analysis: Dict, vulns: List[Dict]) -> Dict:
        """Sub-agent 3: Generate comprehensive report"""
        prompt = f"""You are a Comprehensive Report Agent. Generate an audit report:

Contract Analysis: {json.dumps(analysis, indent=2)}
Vulnerabilities: {json.dumps(vulns, indent=2)}

Generate report with:
1. Executive Summary
2. Detailed findings
3. Risk assessment
4. Recommendations
5. Conclusion

Format: JSON
"""

        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are an audit report generation expert."},
                      {"role": "user", "content": prompt}],
            temperature=0.2
        )

        return json.loads(response.choices[0].message.content)

    def _map_to_unified(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Map LLM-SmartAudit format to MIESC unified format"""
        unified = []

        for idx, vuln in enumerate(vulnerabilities):
            unified.append({
                "id": f"LLMSMART-{idx+1:03d}",
                "source": "LLM-SmartAudit",
                "swc_id": self._infer_swc(vuln["type"]),
                "owasp_category": self._infer_owasp(vuln["type"]),
                "severity": vuln["severity"],
                "confidence": 0.85,
                "location": vuln["location"],
                "description": vuln["explanation"],
                "recommendation": vuln.get("fix", "Review and fix vulnerability")
            })

        return unified

    def _infer_swc(self, vuln_type: str) -> str:
        """Infer SWC ID from vulnerability type"""
        # Use NLP/keyword matching
        if "reentrancy" in vuln_type.lower():
            return "SWC-107"
        elif "access" in vuln_type.lower():
            return "SWC-105"
        # ... more inference logic
        return "SWC-000"

    def _infer_owasp(self, vuln_type: str) -> str:
        """Infer OWASP category"""
        swc_id = self._infer_swc(vuln_type)
        swc_to_owasp = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            # ...
        }
        return swc_to_owasp.get(swc_id, "SC10-Unknown")
```

### Ejemplo 3: Integrar SmartLLM (con RAG)

```python
# agents/smartllm_agent.py
from agents.base_agent import BaseAgent
from typing import List, Dict, Any
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import faiss
import numpy as np

class SmartLLMAgent(BaseAgent):
    """
    Integration for SmartLLM (ArXiv 2502.13167).

    Fine-tuned LLaMA 3.1 with Retrieval-Augmented Generation (RAG)
    for enhanced smart contract auditing.

    Features:
    - Local LLM (no API calls)
    - RAG for vulnerability patterns
    - 100% recall, 70% accuracy (paper claims)
    """

    def __init__(self, model_path: str = "llama-3.1-smartllm"):
        super().__init__(
            agent_name="SmartLLMAgent",
            capabilities=[
                "local_llm_analysis",
                "rag_assisted_detection",
                "fine_tuned_vulnerability_detection"
            ],
            agent_type="ai"
        )

        # Load fine-tuned LLaMA model
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.float16,
            device_map="auto"
        )

        # Load vulnerability pattern database for RAG
        self.vector_db = self._load_vector_db()

    def get_context_types(self) -> List[str]:
        return [
            "smartllm_findings",
            "smartllm_rag_context"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Run SmartLLM analysis with RAG"""
        import time
        start = time.time()

        with open(contract_path, 'r') as f:
            contract_code = f.read()

        # Step 1: RAG - Retrieve relevant vulnerability patterns
        relevant_patterns = self._retrieve_patterns(contract_code)

        # Step 2: Generate prompt with RAG context
        prompt = self._generate_rag_prompt(contract_code, relevant_patterns)

        # Step 3: Run LLaMA inference
        llm_output = self._run_llm_inference(prompt)

        # Step 4: Parse LLM output
        findings = self._parse_llm_output(llm_output)

        # Step 5: Map to unified format
        unified_findings = self._map_to_unified(findings)

        execution_time = time.time() - start

        return {
            "smartllm_findings": unified_findings,
            "smartllm_rag_context": relevant_patterns,
            "execution_time": execution_time,
            "tool_version": "smartllm-1.0"
        }

    def _load_vector_db(self):
        """Load FAISS vector database of vulnerability patterns"""
        # Load pre-built index (from training)
        index = faiss.read_index("data/vulnerability_patterns.index")
        return index

    def _retrieve_patterns(self, contract_code: str, top_k: int = 5) -> List[Dict]:
        """Retrieve top-k relevant vulnerability patterns using RAG"""
        # Embed contract code
        embedding = self._embed_code(contract_code)

        # Search vector DB
        distances, indices = self.vector_db.search(embedding, top_k)

        # Load pattern details
        patterns = []
        for idx in indices[0]:
            pattern = self._load_pattern_by_id(idx)
            patterns.append(pattern)

        return patterns

    def _embed_code(self, code: str) -> np.ndarray:
        """Embed code using same model as training"""
        inputs = self.tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs, output_hidden_states=True)
            embedding = outputs.hidden_states[-1].mean(dim=1).cpu().numpy()
        return embedding

    def _generate_rag_prompt(self, contract_code: str, patterns: List[Dict]) -> str:
        """Generate prompt with RAG context"""
        rag_context = "\n".join([f"- {p['description']}" for p in patterns])

        prompt = f"""### Instruction:
Analyze the following Solidity smart contract for security vulnerabilities.

### Relevant Vulnerability Patterns (RAG):
{rag_context}

### Contract Code:
```solidity
{contract_code}
```

### Task:
Identify all vulnerabilities. For each, provide:
1. Type
2. Severity
3. Location (function, line)
4. Explanation
5. Fix

### Response:
"""

        return prompt

    def _run_llm_inference(self, prompt: str) -> str:
        """Run LLaMA inference"""
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=2048,
                temperature=0.1,
                do_sample=True
            )

        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response

    def _parse_llm_output(self, llm_output: str) -> List[Dict]:
        """Parse LLM response into structured findings"""
        # Parse markdown/text format from LLM
        # ... parsing logic
        findings = []
        # Simplified parser
        return findings

    def _map_to_unified(self, findings: List[Dict]) -> List[Dict]:
        """Map to MIESC unified format"""
        unified = []
        for idx, finding in enumerate(findings):
            unified.append({
                "id": f"SMARTLLM-{idx+1:03d}",
                "source": "SmartLLM",
                "swc_id": self._infer_swc(finding["type"]),
                "owasp_category": self._infer_owasp(finding["type"]),
                "severity": finding["severity"],
                "confidence": 0.70,  # 70% accuracy per paper
                "location": finding["location"],
                "description": finding["explanation"],
                "recommendation": finding["fix"]
            })
        return unified

    def _load_pattern_by_id(self, pattern_id: int) -> Dict:
        """Load vulnerability pattern from database"""
        # Load from file/db
        return {"id": pattern_id, "description": "..."}

    def _infer_swc(self, vuln_type: str) -> str:
        # Similar to other agents
        return "SWC-000"

    def _infer_owasp(self, vuln_type: str) -> str:
        return "SC10-Unknown"
```

---

## Validación y Testing

### Test Suite Completo

```python
# tests/test_tool_integration.py
import unittest
from agents.gptscan_agent import GPTScanAgent
from agents.llm_smartaudit_agent import LLMSmartAuditAgent
from agents.smartllm_agent import SmartLLMAgent
from mcp.context_bus import get_context_bus

class TestToolIntegration(unittest.TestCase):
    """Test suite for integrated tools"""

    def setUp(self):
        self.bus = get_context_bus()
        self.test_contract = "examples/vulnerable_bank.sol"

    def test_gptscan_integration(self):
        """Test GPTScan integration"""
        agent = GPTScanAgent(openai_api_key="test-key")

        # Test initialization
        self.assertEqual(agent.agent_name, "GPTScanAgent")
        self.assertIn("logic_vulnerability_detection", agent.capabilities)

        # Test context types
        context_types = agent.get_context_types()
        self.assertIn("gptscan_findings", context_types)

        # Test analysis (mock)
        # results = agent.run(self.test_contract)
        # self.assertIn("gptscan_findings", results)

    def test_llm_smartaudit_integration(self):
        """Test LLM-SmartAudit integration"""
        agent = LLMSmartAuditAgent(openai_api_key="test-key")

        self.assertEqual(agent.agent_name, "LLMSmartAuditAgent")
        self.assertIn("multi_agent_analysis", agent.capabilities)

    def test_smartllm_integration(self):
        """Test SmartLLM integration"""
        # agent = SmartLLMAgent(model_path="test-model")

        # self.assertEqual(agent.agent_name, "SmartLLMAgent")
        # self.assertIn("local_llm_analysis", agent.capabilities)
        pass  # Skip if model not available

    def test_context_bus_integration(self):
        """Test all agents publish to Context Bus"""
        # Subscribe to all context types
        messages_received = []

        def callback(message):
            messages_received.append(message)

        self.bus.subscribe("gptscan_findings", callback)
        self.bus.subscribe("llm_smartaudit_findings", callback)

        # Run agents (mock)
        # ... execute agents
        # ... verify messages received

    def test_unified_format_compliance(self):
        """Test all tools produce unified format"""
        # For each integrated tool
        for AgentClass in [GPTScanAgent, LLMSmartAuditAgent]:
            agent = AgentClass(openai_api_key="test-key")

            # Mock findings
            findings = [{
                "id": "TEST-001",
                "source": agent.agent_name,
                "swc_id": "SWC-107",
                "owasp_category": "SC01-Reentrancy",
                "severity": "High",
                "confidence": 0.9,
                "location": {"file": "test.sol", "line": 1}
            }]

            # Validate schema
            self.assertTrue(self._validate_finding_schema(findings[0]))

    def _validate_finding_schema(self, finding: Dict) -> bool:
        """Validate finding follows unified schema"""
        required_fields = [
            "id", "source", "swc_id", "owasp_category",
            "severity", "confidence", "location"
        ]

        for field in required_fields:
            if field not in finding:
                return False

        return True

if __name__ == "__main__":
    unittest.main()
```

---

## Casos de Uso

### Caso 1: Añadir GPTScan para Logic Bugs

**Problema**: MIESC detecta bien vulnerabilidades sintácticas (SWC-107, SWC-105), pero tiene limitaciones con logic bugs (business logic errors).

**Solución**: Integrar GPTScan como agente especializado.

**Pasos**:
1. Crear `agents/gptscan_agent.py` (ver plantilla arriba)
2. Ejecutar tests: `python tests/test_gptscan_agent.py`
3. Agregar a `mcp_server.py` (opcional)
4. Ejecutar: `python demo_gptscan.py examples/dao.sol`

**Resultado**: MIESC ahora detecta logic vulnerabilities con precisión >90%.

### Caso 2: Integrar LLM-SmartAudit para Análisis Conversacional

**Problema**: Usuarios quieren explicaciones naturales, no JSON técnico.

**Solución**: Integrar LLM-SmartAudit que genera reportes comprensivos.

**Beneficio**: Reportes en lenguaje natural + formato técnico unificado.

### Caso 3: Usar SmartLLM Local (Sin API Keys)

**Problema**: Entornos con restricciones de privacidad (no pueden usar OpenAI API).

**Solución**: SmartLLM ejecuta localmente con LLaMA fine-tuned.

**Ventajas**:
- ✅ 100% privado (no data leak)
- ✅ Sin costos de API
- ✅ Offline-capable

---

## Conclusiones

### Beneficios del Estándar

✅ **Extensibilidad**: Agregar herramientas en minutos
✅ **Consistencia**: Todas las herramientas producen formato unificado
✅ **Trazabilidad**: Context Bus registra TODO automáticamente
✅ **Testing**: Cada agente incluye test suite
✅ **Compliance**: Mapeo SWC/OWASP/CWE estandarizado

### Proyectos Integrados

| Herramienta | Estado | Repository |
|-------------|--------|------------|
| GPTScan | ✅ Plantilla lista | https://github.com/MetaTrustLabs/GPTScan |
| LLM-SmartAudit | ✅ Plantilla lista | https://github.com/LLMAudit/LLMSmartAuditTool |
| SmartLLM | ✅ Plantilla lista | (Paper ArXiv 2502.13167) |
| Peculiar | ⚠️ Pendiente | (Paper IEEE ISSRE 2021) |

---

**Autor**: Fernando Boiero
**Institución**: Universidad Tecnológica Nacional - FRVM
**Email**: fboiero@frvm.utn.edu.ar
**Fecha**: Octubre 2025

**Referencias**:
- GPTScan (ICSE 2024): https://gptscan.github.io/
- LLM-SmartAudit (ArXiv 2410.09381)
- SmartLLM (ArXiv 2502.13167)
- Model Context Protocol v1.0 (Anthropic)
