# MIESC Developer Guide

**Version:** 3.3.0
**Audience:** Contributors, Maintainers, Researchers Extending MIESC
**Last Updated:** 2025-01-18

---

## 🎯 Purpose

This guide explains MIESC's **internal architecture**, **module lifecycle**, and **extension points** for developers who want to:

- **Contribute code** to MIESC
- **Add new security tools** or analysis techniques
- **Extend AI capabilities** with new models
- **Integrate MIESC** into larger systems
- **Debug and troubleshoot** MIESC internals

---

## 📐 System Architecture

### High-Level Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      MIESC Framework                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  CLI Interface (miesc_cli.py)                            │ │
│  │  Entry point for command-line usage                      │ │
│  └──────────────────┬───────────────────────────────────────┘ │
│                     │                                          │
│  ┌──────────────────▼───────────────────────────────────────┐ │
│  │  Coordinator Agent (coordinator_agent.py)                │ │
│  │  Orchestrates multi-agent workflow                       │ │
│  └──────────────────┬───────────────────────────────────────┘ │
│                     │                                          │
│         ┌───────────┼───────────┬───────────┐                 │
│         │           │           │           │                 │
│  ┌──────▼──┐  ┌────▼────┐  ┌───▼───┐  ┌───▼────┐            │
│  │StaticAgt│  │ AIAgent │  │ Policy│  │  MCP   │            │
│  │ (tools) │  │ (GPT-4o)│  │ Agent │  │Adapter │            │
│  └─────────┘  └─────────┘  └───────┘  └────────┘            │
│       │             │           │           │                 │
│  ┌────▼─────────────▼───────────▼───────────▼─────┐          │
│  │  Context Bus (shared state & communication)     │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Output Layer (Reports, MCP API, Files)                  │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Core Components

### 1. CLI Interface (`src/miesc_cli.py`)

**Role:** Command-line entry point

**Key Functions:**
- `run_audit(contract_path)` - Single contract analysis
- `run_batch(directory)` - Batch analysis
- `generate_report(findings)` - Create output

**Extension Point:**
Add new CLI commands by creating subcommands in the Click framework.

**Example:**
```python
@cli.command()
@click.argument('contract_path')
@click.option('--format', default='json')
def custom_command(contract_path, format):
    """Your custom analysis command."""
    # Implementation
    pass
```

---

### 2. Coordinator Agent (`src/agents/coordinator_agent.py`)

**Role:** Orchestrates analysis workflow

**Responsibilities:**
1. Parse contract
2. Dispatch to analysis agents (Static, AI, Symbolic)
3. Aggregate findings
4. Trigger PolicyAgent if needed
5. Generate final report

**Key Method:**
```python
def coordinate_analysis(self, contract_path: str) -> Dict:
    # 1. Initialize context
    context = self.create_context(contract_path)

    # 2. Run static analysis
    static_findings = self.static_agent.analyze(context)

    # 3. AI correlation
    correlated = self.ai_agent.correlate(static_findings)

    # 4. Compliance mapping
    mapped = self.policy_mapper.map_to_frameworks(correlated)

    # 5. Generate report
    return self.report_generator.create(mapped)
```

**Extension Point:**
Add new workflow steps in the `coordinate_analysis` method.

---

### 3. Static Analysis Agent (`src/agents/static_agent.py`)

**Role:** Run SAST tools (Slither, Solhint, etc.)

**Tool Integration:**
```python
class StaticAgent:
    def __init__(self):
        self.tools = {
            "slither": SlitherWrapper(),
            "solhint": SolhintWrapper(),
            # Add your tool here
        }

    def analyze(self, context):
        findings = []
        for tool_name, tool in self.tools.items():
            result = tool.run(context.contract_path)
            findings.extend(result)
        return findings
```

**Adding a New Tool:**
1. Create wrapper class implementing `run(contract_path)` method
2. Register in `self.tools` dict
3. Add tests in `tests/agents/test_static_agent.py`

---

### 4. AI Agent (`src/agents/ai_agent.py`)

**Role:** LLM-based false positive reduction

**Architecture:**
```python
class AIAgent:
    def __init__(self, model="gpt-4o"):
        self.client = OpenAI()
        self.model = model

    def correlate(self, findings):
        # Group similar findings
        grouped = self._group_findings(findings)

        # Analyze each group
        correlated = []
        for group in grouped:
            prompt = self._build_prompt(group)
            response = self._query_llm(prompt)
            if response["is_true_positive"]:
                correlated.append(self._merge(group, response))

        return correlated
```

**Extension Points:**
- **Add new LLM:** Modify `_query_llm()` to support different APIs
- **Custom prompts:** Override `_build_prompt()` with domain-specific templates
- **Ensemble models:** Extend to query multiple LLMs and vote

---

### 5. Policy Agent (`src/miesc_policy_agent.py`)

**Role:** Self-audit MIESC codebase

**Check Structure:**
```python
def _run_policy_check(self, policy_id: str):
    """
    Execute a single policy check.

    Args:
        policy_id: Policy identifier (e.g., "CQ-001")

    Returns:
        PolicyCheckResult with status, severity, details
    """
    if policy_id == "CQ-001":  # Ruff linting
        result = subprocess.run(["ruff", "check", "src/"])
        return PolicyCheckResult(
            policy_id="CQ-001",
            status="pass" if result.returncode == 0 else "fail",
            severity="medium",
            details=result.stdout
        )
```

**Adding New Checks:**
1. Create method `_check_<name>()`
2. Register in `self.checks` list
3. Add to compliance framework mapping

---

### 6. MCP Adapter (`src/miesc_mcp_rest.py`)

**Role:** Expose MIESC via Model Context Protocol

**Endpoint Structure:**
```python
@app.route('/mcp/run_audit', methods=['POST'])
def run_audit():
    data = request.get_json()
    contract = data['contract']

    # Delegate to Coordinator
    result = coordinator.coordinate_analysis(contract)

    return jsonify({
        "status": "success",
        "findings": result["findings"],
        "summary": result["summary"]
    })
```

**Extension Point:**
Add new MCP capabilities by creating new Flask routes.

---

## 🔄 Module Lifecycle

### Analysis Workflow

```
1. User Input
   └─► CLI parses arguments
       └─► contract_path, options

2. Coordinator Init
   └─► Creates Context object
       └─► Parses contract AST
       └─► Extracts metadata

3. Static Analysis Phase
   └─► For each tool (Slither, Mythril, etc.):
       ├─► Execute tool
       ├─► Parse output
       └─► Normalize to standard format

4. AI Correlation Phase
   └─► Group similar findings
   └─► Query GPT-4o for each group
   └─► Filter false positives

5. Compliance Mapping
   └─► Map findings to CWE/SWC/OWASP
   └─► Calculate CVSS scores
   └─► Link to ISO/NIST requirements

6. Report Generation
   └─► Create JSON report
   └─► Create Markdown report
   └─► (Optional) Create HTML dashboard

7. Output
   └─► Write to files
   └─► Display summary in CLI
   └─► Return via MCP API (if enabled)
```

---

## 🛠️ Extension Guide

### Adding a New Security Tool

**Step 1: Create Tool Wrapper**

```python
# src/agents/wrappers/mytool_wrapper.py

from typing import List, Dict
import subprocess
import json

class MyToolWrapper:
    """
    Wrapper for MyTool static analyzer.

    Reference:
        Author et al. (2024). MyTool: Fast Contract Analysis.
        arXiv:2024.12345
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def run(self, contract_path: str) -> List[Dict]:
        """
        Execute MyTool on contract.

        Args:
            contract_path: Path to Solidity file

        Returns:
            List of findings in standard format
        """
        # Execute tool
        result = subprocess.run(
            ["mytool", "analyze", contract_path, "--json"],
            capture_output=True,
            timeout=self.timeout
        )

        # Parse output
        raw_findings = json.loads(result.stdout)

        # Normalize to MIESC format
        normalized = []
        for finding in raw_findings:
            normalized.append({
                "tool": "mytool",
                "type": finding["vulnerability_type"],
                "severity": finding["severity"],
                "line": finding["line_number"],
                "description": finding["message"]
            })

        return normalized
```

**Step 2: Register Tool**

```python
# src/agents/static_agent.py

from agents.wrappers.mytool_wrapper import MyToolWrapper

class StaticAgent:
    def __init__(self):
        self.tools = {
            "slither": SlitherWrapper(),
            "mythril": MythrilWrapper(),
            "mytool": MyToolWrapper(),  # Add here
        }
```

**Step 3: Add Tests**

```python
# tests/agents/test_mytool_wrapper.py

import pytest
from src.agents.wrappers.mytool_wrapper import MyToolWrapper

def test_mytool_detects_reentrancy():
    wrapper = MyToolWrapper()
    findings = wrapper.run("examples/reentrancy.sol")

    assert len(findings) > 0
    assert any(f["type"] == "reentrancy" for f in findings)
```

---

### Adding a New AI Model

**Step 1: Create Model Interface**

```python
# src/agents/llm_interfaces/claude_interface.py

from anthropic import Anthropic

class ClaudeInterface:
    def __init__(self, model="claude-3-5-sonnet-20241022"):
        self.client = Anthropic()
        self.model = model

    def query(self, prompt: str) -> Dict:
        """Query Claude with prompt."""
        response = self.client.messages.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2000
        )
        return json.loads(response.content[0].text)
```

**Step 2: Integrate into AIAgent**

```python
# src/agents/ai_agent.py

def _query_llm(self, prompt):
    if self.model.startswith("gpt-"):
        return self.openai_interface.query(prompt)
    elif self.model.startswith("claude-"):
        return self.claude_interface.query(prompt)
    else:
        raise ValueError(f"Unsupported model: {self.model}")
```

---

### Adding a New Compliance Framework

**Step 1: Create Framework Mapper**

```python
# src/agents/policy_mapper.py

def map_to_new_framework(self, findings):
    """
    Map findings to New Framework Standard.

    Standard: NEW-FRAMEWORK-2025
    URL: https://example.com/standard

    Requirements:
        REQ-1: Code must be free of reentrancy
        REQ-2: No integer overflow
        ...
    """
    compliance = {
        "framework": "NEW-FRAMEWORK-2025",
        "requirements": []
    }

    # Check REQ-1
    reentrancy_findings = [
        f for f in findings if f["type"] == "reentrancy"
    ]
    compliance["requirements"].append({
        "id": "REQ-1",
        "description": "No reentrancy vulnerabilities",
        "status": "pass" if len(reentrancy_findings) == 0 else "fail",
        "evidence": reentrancy_findings
    })

    # ... check other requirements

    return compliance
```

**Step 2: Document Mapping**

Create `standards/NEW_FRAMEWORK_mapping.md` with detailed requirement mappings.

---

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── unit/                  # Unit tests (isolated components)
│   ├── test_static_agent.py
│   ├── test_ai_agent.py
│   └── test_policy_agent.py
├── integration/           # Integration tests (multi-component)
│   ├── test_full_pipeline.py
│   └── test_mcp_api.py
├── regression/            # Regression tests (benchmark contracts)
│   └── test_smartbugs_curated.py
└── fixtures/              # Test data
    ├── contracts/
    └── expected_outputs/
```

### Writing Tests

```python
import pytest
from src.agents.static_agent import StaticAgent

class TestStaticAgent:
    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return StaticAgent()

    @pytest.fixture
    def vulnerable_contract(self, tmp_path):
        """Create test contract with reentrancy."""
        contract = tmp_path / "reentrancy.sol"
        contract.write_text("""
        pragma solidity ^0.8.0;
        contract Vulnerable {
            mapping(address => uint) balances;
            function withdraw() public {
                uint amt = balances[msg.sender];
                msg.sender.call{value: amt}("");
                balances[msg.sender] = 0;  // Vulnerable!
            }
        }
        """)
        return str(contract)

    def test_detects_reentrancy(self, agent, vulnerable_contract):
        """Test that static agent detects reentrancy."""
        findings = agent.analyze(vulnerable_contract)

        # Assert reentrancy detected
        reentrancy_findings = [
            f for f in findings if "reentrancy" in f["type"].lower()
        ]
        assert len(reentrancy_findings) > 0
        assert reentrancy_findings[0]["severity"] in ["High", "Critical"]
```

---

## 🐛 Debugging Tips

### Enable Debug Logging

```python
# src/miesc_cli.py

import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.debug("Starting analysis of %s", contract_path)
```

### Profile Performance

```bash
# Profile specific script
python -m cProfile -s cumtime src/miesc_cli.py run-audit contract.sol

# Line-by-line profiling
kernprof -l -v src/miesc_cli.py run-audit contract.sol
```

### Interactive Debugging

```python
# Add breakpoint in code
import ipdb; ipdb.set_trace()

# Or use built-in breakpoint (Python 3.7+)
breakpoint()
```

---

## 📚 Code Style

**Follow:**
- PEP 8 (enforced by `black` and `flake8`)
- Type hints for all public functions
- Google-style docstrings

**Example:**
```python
def analyze_contract(
    contract_path: str,
    tools: List[str],
    enable_ai: bool = True
) -> Dict[str, Any]:
    """
    Analyze smart contract with specified tools.

    Args:
        contract_path: Path to Solidity contract file.
        tools: List of tool names to run.
        enable_ai: Whether to enable AI correlation (default: True).

    Returns:
        Dictionary containing findings, summary, and metadata.

    Raises:
        FileNotFoundError: If contract_path does not exist.
        ToolExecutionError: If a tool fails to execute.

    Example:
        >>> results = analyze_contract("contract.sol", ["slither"])
        >>> len(results["findings"])
        5
    """
    # Implementation
    pass
```

---

## 🚀 Performance Optimization

### Profiling Bottlenecks

Common bottlenecks:
1. **Mythril symbolic execution** (70% of time)
2. **AI API calls** (15% of time)
3. **Report generation** (5% of time)

### Optimization Strategies

**1. Parallelize Tool Execution:**
```python
from concurrent.futures import ThreadPoolExecutor

def run_tools_parallel(contract_path, tools):
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(tool.run, contract_path): tool
            for tool in tools
        }
        results = [future.result() for future in futures]
    return results
```

**2. Cache AI Responses:**
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def query_ai_cached(prompt_hash):
    # Cache AI responses for identical prompts
    return ai_agent.query(prompt)
```

**3. Early Termination:**
```python
# Stop analysis after finding critical vulnerabilities
if any(f["severity"] == "Critical" for f in findings):
    return early_report(findings)
```

---

## 🔐 Security Considerations

**Critical:** MIESC analyzes potentially malicious contracts.

**Rules:**
1. **Never execute contract code directly**
2. **Validate all file paths** (prevent directory traversal)
3. **Limit file sizes** (max 1MB per contract)
4. **Sandbox tool execution** (use Docker when possible)
5. **Pin all dependencies** (prevent supply chain attacks)

**Example Input Validation:**
```python
import os

def validate_contract_path(path: str) -> str:
    """Validate and sanitize contract path."""
    # Check file exists
    if not os.path.exists(path):
        raise FileNotFoundError(f"Contract not found: {path}")

    # Check is file (not directory)
    if not os.path.isfile(path):
        raise ValueError(f"Path is not a file: {path}")

    # Check extension
    if not path.endswith(".sol"):
        raise ValueError(f"Not a Solidity file: {path}")

    # Check size (max 1MB)
    if os.path.getsize(path) > 1024 * 1024:
        raise ValueError(f"File too large: {path}")

    # Resolve to absolute path (prevent traversal)
    return os.path.abspath(path)
```

---

## 📞 Getting Help

**Questions?** Contact:
- **Email:** fboiero@frvm.utn.edu.ar
- **GitHub Issues:** [https://github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)
- **Contributing Guide:** [../CONTRIBUTING.md](../CONTRIBUTING.md)

---

**Version:** 3.3.0
**Maintainer:** Fernando Boiero - UNDEF
**For:** Contributors, Maintainers, Researchers
