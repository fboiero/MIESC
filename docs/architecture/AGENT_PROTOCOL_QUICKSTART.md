# 🚀 MIESC Agent Protocol - Quick Start

## For Tool Developers: Create Your Agent in 15 Minutes

### 1. Copy the Template

```python
# my_agent.py
from src.core.agent_protocol import (
    SecurityAgent, AgentCapability, AgentSpeed,
    AnalysisResult, AnalysisStatus, Finding, FindingSeverity
)
from typing import List
from datetime import datetime
import time

class MyAgent(SecurityAgent):
    @property
    def name(self) -> str:
        return "my-agent"  # Unique name

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Description of what your agent does"

    @property
    def author(self) -> str:
        return "Your Name"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [AgentCapability.STATIC_ANALYSIS]

    @property
    def supported_languages(self) -> List[str]:
        return ["solidity"]

    @property
    def cost(self) -> float:
        return 0.0  # Free

    @property
    def speed(self) -> AgentSpeed:
        return AgentSpeed.FAST

    def is_available(self) -> bool:
        """Check if your tool is installed"""
        return True  # Add your check here

    def can_analyze(self, file_path: str) -> bool:
        """Check if file can be analyzed"""
        return file_path.endswith('.sol')

    def analyze(self, contract: str, **kwargs) -> AnalysisResult:
        """Your analysis logic here"""
        start_time = time.time()

        try:
            # TODO: Add your analysis logic
            findings = []  # Your findings here

            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.SUCCESS,
                timestamp=datetime.now(),
                execution_time=time.time() - start_time,
                findings=findings,
                summary={'total': len(findings)}
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
```

### 2. Test It

```bash
# Copy to agents directory
cp my_agent.py ~/.miesc/agents/

# Test discovery
python -c "
from src.core.agent_registry import AgentRegistry
registry = AgentRegistry()
registry.discover_all()
print('Agents found:', list(registry.agents.keys()))
"

# Test analysis with orchestrator
python -c "
from src.orchestrator import AgentOrchestrator, SelectionCriteria

orch = AgentOrchestrator()
orch.initialize()

criteria = SelectionCriteria(specific_agents=['my-agent'])
agents = orch.select_agents('test.sol', criteria)

print('Selected agents:', [a.name for a in agents])
"
```

### 3. Publish It

```bash
# Publish to marketplace (when ready)
miesc agents publish my_agent.py \
  --description "Your agent description" \
  --tags "security,analysis"
```

Done! Your agent is now:
- ✅ Discoverable by MIESC
- ✅ Usable in orchestrated analysis
- ✅ Available to all MIESC users

---

## For Security Auditors: Use Multiple Agents

### Quick Demo

```bash
# 1. Initialize and see available agents
python -c "
from src.orchestrator import AgentOrchestrator

orchestrator = AgentOrchestrator()
orchestrator.initialize()

print('Available agents:')
for agent_name in orchestrator.get_available_agents():
    info = orchestrator.get_agent_info(agent_name)
    print(f'  • {agent_name} - {info[\"description\"]}')
"

# 2. Run analysis with multiple agents
python -c "
from src.orchestrator import AgentOrchestrator, SelectionCriteria

orchestrator = AgentOrchestrator()
orchestrator.initialize()

# Select all free, fast agents for Solidity
criteria = SelectionCriteria(
    language='solidity',
    free_only=True
)

agents = orchestrator.select_agents('contract.sol', criteria)
print(f'Selected {len(agents)} agents')

# Run analysis
result = orchestrator.analyze('contract.sol', agents)
print(f'Analysis complete: {result.agents_success}/{result.agents_run} successful')
print(f'Total findings: {result.get_summary()[\"total_findings\"]}')
"
```

---

## For Protocols: CI/CD Integration

### GitHub Actions (Coming Soon)

```yaml
# .github/workflows/security.yml
name: Security Analysis

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup MIESC
        run: pip install miesc

      - name: Run Analysis
        run: |
          python -c "
          from src.orchestrator import AgentOrchestrator, SelectionCriteria

          orchestrator = AgentOrchestrator()
          orchestrator.initialize()

          criteria = SelectionCriteria(language='solidity', free_only=True)
          agents = orchestrator.select_agents('contracts/', criteria)

          result = orchestrator.analyze('contracts/', agents)
          orchestrator.save_results(result, 'security-report/')
          "

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report/
```

---

## Example: Semgrep Agent

See `examples/agents/semgrep_agent.py` for a complete example of an external agent.

Key features demonstrated:
- External tool integration (Semgrep CLI)
- JSON parsing
- Error handling
- Timeout management
- Configuration schema
- Standalone testing

Run it:
```bash
python examples/agents/semgrep_agent.py
```

---

## Documentation

- **Full Whitepaper:** [AGENT_PROTOCOL_WHITEPAPER.md](./AGENT_PROTOCOL_WHITEPAPER.md)
- **Developer Guide:** [docs/AGENT_DEVELOPMENT_GUIDE.md](./docs/AGENT_DEVELOPMENT_GUIDE.md)
- **Implementation Details:** [AGENT_ORCHESTRATOR_IMPLEMENTATION_COMPLETE.md](./AGENT_ORCHESTRATOR_IMPLEMENTATION_COMPLETE.md)

---

## Support

- **GitHub:** https://github.com/miesc-io/miesc
- **Discord:** https://discord.gg/miesc
- **Email:** [email protected]

---

**Let's build the future of smart contract security together! 🔐**
