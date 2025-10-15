# MIESC Agent Development Guide
## Complete Guide to Building Security Analysis Agents

**Version:** 1.0.0
**Last Updated:** October 2025

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Understanding the Protocol](#understanding-the-protocol)
3. [Creating Your First Agent](#creating-your-first-agent)
4. [Testing Your Agent](#testing-your-agent)
5. [Publishing Your Agent](#publishing-your-agent)
6. [Best Practices](#best-practices)
7. [Advanced Topics](#advanced-topics)
8. [FAQ](#faq)

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Basic understanding of smart contract security
- Your security analysis tool or algorithm

### Installation

```bash
# Install MIESC
pip install miesc

# Verify installation
miesc --version

# Initialize development environment
miesc dev init my-agent
```

This creates:
```
my-agent/
├── my_agent.py          # Main agent file
├── tests/
│   └── test_agent.py    # Unit tests
├── examples/
│   └── vulnerable.sol   # Test contracts
├── README.md            # Documentation
└── requirements.txt     # Dependencies
```

---

## Understanding the Protocol

### Core Concepts

**1. SecurityAgent Interface**

All agents implement this abstract base class:

```python
from src.core.agent_protocol import SecurityAgent

class MyAgent(SecurityAgent):
    # Required: Agent metadata
    @property
    def name(self) -> str: ...

    # Required: Analysis method
    def analyze(self, contract: str) -> AnalysisResult: ...

    # Required: Availability check
    def is_available(self) -> bool: ...
```

**2. Standard Result Format**

All agents return `AnalysisResult`:

```python
AnalysisResult(
    agent="my-agent",
    version="1.0.0",
    status=AnalysisStatus.SUCCESS,
    timestamp=datetime.now(),
    execution_time=5.2,
    findings=[...],
    summary={'critical': 2, 'high': 5}
)
```

**3. Discovery & Registration**

Agents are discovered automatically:
- Place in `~/.miesc/agents/`
- Name file `*_agent.py`
- Implement `SecurityAgent`
- Done! MIESC finds it

---

## Creating Your First Agent

### Step 1: Basic Structure

```python
# my_simple_agent.py

from src.core.agent_protocol import (
    SecurityAgent,
    AgentCapability,
    AgentSpeed,
    AnalysisResult,
    AnalysisStatus,
    Finding,
    FindingSeverity
)
from typing import List
from datetime import datetime
import time

class SimpleAgent(SecurityAgent):
    """A simple example agent"""

    # ===== Required Properties =====

    @property
    def name(self) -> str:
        return "simple-agent"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Simple pattern matching for common vulnerabilities"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.STATIC_ANALYSIS,
            AgentCapability.PATTERN_MATCHING
        ]

    @property
    def supported_languages(self) -> List[str]:
        return ["solidity"]

    @property
    def cost(self) -> float:
        return 0.0  # Free

    @property
    def speed(self) -> AgentSpeed:
        return AgentSpeed.FAST

    # ===== Required Methods =====

    def is_available(self) -> bool:
        """Check if agent can run"""
        # Check dependencies, binaries, etc.
        return True

    def can_analyze(self, file_path: str) -> bool:
        """Check if file is analyzable"""
        from pathlib import Path
        path = Path(file_path)
        return path.exists() and path.suffix == '.sol'

    def analyze(self, contract: str, **kwargs) -> AnalysisResult:
        """Main analysis method"""
        start_time = time.time()

        try:
            # Read contract
            with open(contract, 'r') as f:
                code = f.read()

            # Find vulnerabilities
            findings = self._find_vulnerabilities(code)

            # Calculate summary
            summary = self._calculate_summary(findings)

            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.SUCCESS,
                timestamp=datetime.now(),
                execution_time=time.time() - start_time,
                findings=findings,
                summary=summary
            )

        except Exception as e:
            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.ERROR,
                timestamp=datetime.now(),
                execution_time=time.time() - start_time,
                findings=[],
                summary={},
                error=str(e)
            )

    # ===== Helper Methods =====

    def _find_vulnerabilities(self, code: str) -> List[Finding]:
        """Look for vulnerabilities in code"""
        findings = []

        # Example: Check for .call() usage
        if '.call(' in code:
            findings.append(Finding(
                type="low-level-call",
                severity=FindingSeverity.MEDIUM,
                location="contract.sol:unknown",
                message="Low-level call detected",
                description="Using .call() can be dangerous",
                recommendation="Consider using a higher-level function",
                confidence="high"
            ))

        return findings

    def _calculate_summary(self, findings: List[Finding]) -> dict:
        """Calculate summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.severity.value
            summary[severity] = summary.get(severity, 0) + 1

        summary['total'] = len(findings)
        return summary
```

### Step 2: Test Locally

```bash
# Copy to agents directory
cp my_simple_agent.py ~/.miesc/agents/

# Verify discovery
miesc agents list
# Should show: simple-agent v1.0.0

# Test on a contract
miesc analyze examples/reentrancy_simple.sol --use simple-agent

# View results
cat output/reentrancy_simple/simple-agent.txt
```

---

## Testing Your Agent

### Unit Tests

```python
# tests/test_simple_agent.py

import pytest
from pathlib import Path
from my_simple_agent import SimpleAgent
from src.core.agent_protocol import AnalysisStatus

class TestSimpleAgent:
    def setup_method(self):
        self.agent = SimpleAgent()

    def test_metadata(self):
        """Test agent metadata"""
        assert self.agent.name == "simple-agent"
        assert self.agent.version == "1.0.0"
        assert len(self.agent.capabilities) > 0

    def test_availability(self):
        """Test availability check"""
        assert self.agent.is_available() == True

    def test_can_analyze_solidity(self):
        """Test file type detection"""
        assert self.agent.can_analyze("test.sol") == True
        assert self.agent.can_analyze("test.py") == False

    def test_analyze_success(self):
        """Test successful analysis"""
        result = self.agent.analyze("examples/vulnerable.sol")

        assert result.status == AnalysisStatus.SUCCESS
        assert result.agent == "simple-agent"
        assert isinstance(result.findings, list)
        assert isinstance(result.summary, dict)

    def test_analyze_error(self):
        """Test error handling"""
        result = self.agent.analyze("nonexistent.sol")

        assert result.status == AnalysisStatus.ERROR
        assert result.error is not None

# Run tests
# pytest tests/test_simple_agent.py -v
```

### Integration Tests

```bash
# Test with MIESC orchestrator
miesc test my-agent --contract examples/vulnerable.sol

# Test discovery
miesc agents discover --verify

# Test in pipeline
miesc analyze examples/vulnerable.sol \
  --use my-agent \
  --output test-output
```

---

## Publishing Your Agent

### Step 1: Prepare Metadata

Create `agent_metadata.json`:

```json
{
  "name": "simple-agent",
  "version": "1.0.0",
  "description": "Simple pattern matching for common vulnerabilities",
  "author": "Your Name",
  "email": "[email protected]",
  "license": "MIT",
  "homepage": "https://github.com/you/simple-agent",
  "repository": "https://github.com/you/simple-agent",
  "documentation": "https://docs.simple-agent.io",
  "tags": ["security", "static-analysis", "solidity"],
  "capabilities": ["static_analysis", "pattern_matching"],
  "languages": ["solidity"],
  "cost": 0.0,
  "speed": "fast",
  "requirements": ["python>=3.8"],
  "tested_on": [
    "Ubuntu 20.04",
    "macOS 12+",
    "Windows 10+"
  ]
}
```

### Step 2: Write Documentation

```markdown
# Simple Agent

Fast pattern-matching security analysis for Solidity contracts.

## Features

- ✓ Zero configuration
- ✓ < 5 second analysis
- ✓ 20+ vulnerability patterns
- ✓ Free and open source

## Installation

```bash
miesc agents install simple-agent
```

## Usage

```bash
miesc analyze contract.sol --use simple-agent
```

## Detected Vulnerabilities

- Low-level calls
- Reentrancy patterns
- Integer overflow
- ... (list all)

## Contributing

PRs welcome! See CONTRIBUTING.md
```

### Step 3: Publish

```bash
# Validate agent
miesc agents validate my_simple_agent.py

# Test thoroughly
miesc agents test my_simple_agent.py \
  --contracts examples/*.sol

# Publish to marketplace
miesc agents publish my_simple_agent.py \
  --metadata agent_metadata.json \
  --readme README.md \
  --examples examples/

# Confirm publication
miesc agents info simple-agent --remote
```

---

## Best Practices

### Performance

**1. Fast Availability Check**
```python
def is_available(self) -> bool:
    # Cache result to avoid repeated checks
    if not hasattr(self, '_available'):
        self._available = self._check_availability()
    return self._available
```

**2. Efficient Analysis**
```python
def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    # Parse once
    ast = self._parse_contract(contract)

    # Reuse parsed data for all checks
    findings = []
    findings.extend(self._check_reentrancy(ast))
    findings.extend(self._check_overflow(ast))
    # ...
```

**3. Timeout Handling**
```python
import signal

def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    timeout = kwargs.get('timeout', 300)  # 5 minutes default

    def timeout_handler(signum, frame):
        raise TimeoutError("Analysis timeout")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        # Analysis code
        pass
    finally:
        signal.alarm(0)  # Cancel alarm
```

### Error Handling

**1. Graceful Degradation**
```python
def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    findings = []

    # Try multiple detection methods
    try:
        findings.extend(self._method1(contract))
    except Exception as e:
        logger.warning(f"Method 1 failed: {e}")

    try:
        findings.extend(self._method2(contract))
    except Exception as e:
        logger.warning(f"Method 2 failed: {e}")

    # Return partial results rather than error
    return AnalysisResult(..., findings=findings)
```

**2. Detailed Error Messages**
```python
try:
    result = subprocess.run(cmd, check=True, capture_output=True)
except subprocess.CalledProcessError as e:
    error_msg = f"""
    Command failed: {' '.join(cmd)}
    Exit code: {e.returncode}
    Stdout: {e.stdout.decode()}
    Stderr: {e.stderr.decode()}
    """
    return AnalysisResult(..., status=AnalysisStatus.ERROR, error=error_msg)
```

### Result Quality

**1. Accurate Location Info**
```python
Finding(
    type="reentrancy",
    severity=FindingSeverity.HIGH,
    location="Contract.sol:42-48 in withdraw()",  # Precise
    # Not: "Contract.sol:unknown"
)
```

**2. Actionable Recommendations**
```python
Finding(
    ...
    recommendation="""
    Fix: Use checks-effects-interactions pattern
    1. Update state before external call
    2. Add ReentrancyGuard modifier
    3. Consider pull payment pattern

    Example:
    function withdraw() public nonReentrant {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;  // Update first
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
    """
)
```

**3. Confidence Scoring**
```python
Finding(
    ...
    confidence="high",  # Definite vulnerability
    # vs
    confidence="medium",  # Likely issue, needs review
    # vs
    confidence="low",  # Possible issue, false positive likely
)
```

### Documentation

**1. Inline Comments**
```python
def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    """
    Analyze contract for security vulnerabilities.

    This agent uses pattern matching to detect common issues:
    - Reentrancy in withdrawal functions
    - Integer overflow in arithmetic
    - Unchecked external calls

    Args:
        contract: Path to Solidity contract file
        **kwargs: Optional parameters
            - timeout (int): Max seconds (default: 300)
            - rules (str): Path to custom rules file
            - exclude (list): Patterns to exclude

    Returns:
        AnalysisResult with findings and metadata

    Raises:
        TimeoutError: If analysis exceeds timeout
        ValueError: If contract file doesn't exist

    Example:
        >>> agent = SimpleAgent()
        >>> result = agent.analyze("contract.sol", timeout=60)
        >>> print(f"Found {len(result.findings)} issues")
    """
```

**2. README Template**
```markdown
# Your Agent Name

One-line description.

## Quick Start

```bash
miesc agents install your-agent
miesc analyze contract.sol --use your-agent
```

## Features

- Feature 1
- Feature 2

## Requirements

- Dependency 1
- Dependency 2

## Configuration

Optional configuration details.

## Examples

Show common use cases.

## Known Limitations

Be honest about what it can't do.

## Contributing

Link to CONTRIBUTING.md

## License

Your license
```

---

## Advanced Topics

### Custom Configuration

```python
def get_config_schema(self) -> dict:
    """JSON schema for configuration"""
    return {
        "type": "object",
        "properties": {
            "rules_file": {
                "type": "string",
                "description": "Path to custom rules"
            },
            "strict_mode": {
                "type": "boolean",
                "default": False
            },
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 10
            }
        }
    }

def configure(self, config: dict):
    """Apply configuration"""
    self.rules_file = config.get('rules_file')
    self.strict_mode = config.get('strict_mode', False)
    self.max_depth = config.get('max_depth', 10)
```

Usage:
```bash
miesc analyze contract.sol --use your-agent \
  --agent-config '{"strict_mode": true, "max_depth": 20}'
```

### Integration with External Tools

```python
def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    # Call external binary
    result = subprocess.run([
        '/path/to/tool',
        '--format', 'json',
        contract
    ], capture_output=True, text=True, timeout=300)

    # Parse tool's output
    tool_data = json.loads(result.stdout)

    # Convert to MIESC format
    findings = self._convert_findings(tool_data)

    return AnalysisResult(...)
```

### Caching Results

```python
import hashlib
import pickle
from pathlib import Path

def analyze(self, contract: str, **kwargs) -> AnalysisResult:
    # Calculate contract hash
    contract_hash = hashlib.sha256(
        Path(contract).read_bytes()
    ).hexdigest()

    # Check cache
    cache_file = Path(f"~/.miesc/cache/{self.name}/{contract_hash}.pkl")
    if cache_file.exists() and not kwargs.get('force'):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)

    # Run analysis
    result = self._do_analysis(contract)

    # Cache result
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, 'wb') as f:
        pickle.dump(result, f)

    return result
```

---

## FAQ

**Q: Do I need to modify MIESC core code?**
A: No! Just implement `SecurityAgent` and place in `~/.miesc/agents/`

**Q: Can my agent call external APIs?**
A: Yes, but consider cost and privacy. Document API usage clearly.

**Q: How do I charge for my agent?**
A: Set `cost` property. MIESC handles payment integration.

**Q: Can I update my agent after publishing?**
A: Yes, publish new version. Users can update with `miesc agents update`

**Q: What if my agent has large dependencies?**
A: Document in `requirements.txt`. Consider optional dependencies.

**Q: Can I see other agents' code?**
A: Yes, all published agents are open source (per marketplace rules)

**Q: How do I handle multiple file analysis?**
A: Implement batch processing or call `analyze()` multiple times

**Q: What about language-specific agents?**
A: Perfectly fine! Set `supported_languages` appropriately

**Q: Can I combine multiple techniques?**
A: Absolutely! Add multiple capabilities

**Q: How do I debug my agent?**
A: Use `logging` module, `miesc --verbose`, and unit tests

---

## Support

- **Documentation:** https://docs.miesc.io
- **Discord:** https://discord.gg/miesc
- **Forum:** https://forum.miesc.io
- **Email:** [email protected]

---

## Contributing

We welcome contributions! See:
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

---

**Happy Agent Building! 🚀**
