# Ollama & CrewAI Integration Guide

## Overview

This guide covers the integration of:
- **Ollama**: Local LLM for cost-free, private AI analysis
- **CrewAI**: Multi-agent coordination framework

## Why Use Ollama?

### Benefits

✅ **Zero Cost**
- No API fees
- Unlimited usage
- No rate limits

✅ **Complete Privacy**
- Data never leaves your machine
- No cloud dependencies
- GDPR/compliance friendly

✅ **Performance**
- No network latency
- Works offline
- Consistent response times

✅ **Customizable**
- Multiple model options
- Fine-tune for your needs
- Mix and match models

### Limitations

⚠️ **Resource Requirements**
- 8-16GB RAM minimum
- 2-4GB disk space per model
- CPU/GPU for inference

⚠️ **Quality vs Speed Tradeoff**
- Smaller models = faster but less accurate
- Larger models = slower but more accurate
- Generally lower quality than GPT-4

⚠️ **Setup Required**
- Must install Ollama CLI
- Must download models
- Initial setup time

---

## Installation

### 1. Install Ollama

```bash
# macOS / Linux
curl https://ollama.ai/install.sh | sh

# Verify installation
ollama --version
```

### 2. Download Models

Use our setup script:
```bash
bash scripts/setup_ollama.sh
```

Or manually:
```bash
# Minimal (fast, 3.8GB)
ollama pull codellama:7b

# Recommended (balanced, 11GB)
ollama pull codellama:13b
ollama pull deepseek-coder:6.7b

# Best quality (slow, 19GB)
ollama pull deepseek-coder:33b
```

### 3. Install Python Dependencies

```bash
pip install -r requirements_agents.txt
```

This installs:
- `crewai` - Multi-agent framework
- `crewai-tools` - Additional tools
- `langchain` - LLM integration
- `langchain-community` - Ollama support

---

## Quick Start

### Using OllamaAgent

```python
from src.agents.ollama_agent import OllamaAgent

# Create agent
agent = OllamaAgent(model="codellama:13b")

# Analyze contract
results = agent.run("examples/reentrancy.sol")

# Access findings
findings = results["ollama_findings"]
for finding in findings:
    print(f"{finding['severity']}: {finding['description']}")
```

### Using CrewAI Coordinator

```python
from src.agents.crewai_coordinator import CrewAICoordinator

# Create coordinator
coordinator = CrewAICoordinator(
    use_local_llm=True,
    llm_model="ollama/codellama:13b"
)

# Run multi-agent analysis
results = coordinator.run("examples/reentrancy.sol")

# Access crew findings
crew_findings = results["crew_findings"]
```

### Command Line

```bash
# Using Ollama
python src/agents/ollama_agent.py examples/reentrancy.sol

# Using CrewAI
python src/agents/crewai_coordinator.py examples/reentrancy.sol

# Run examples
python examples/use_ollama_crewai.py
```

---

## Model Selection Guide

### By Use Case

| Use Case | Recommended Model | Reason |
|----------|------------------|--------|
| **Development** | `codellama:7b` | Fast feedback (30s) |
| **CI/CD** | `deepseek-coder:6.7b` | Balance of speed & quality |
| **Pre-Audit** | `codellama:13b` | Good quality (60s) |
| **Final Audit** | `deepseek-coder:33b` | Best quality (120s) |
| **Explanations** | `mistral:7b-instruct` | Clear, user-friendly |
| **Low Resources** | `phi:latest` | Minimal RAM (4GB) |

### Model Comparison

```
Speed:       phi < mistral < codellama:7b < deepseek:6.7b < codellama:13b < deepseek:33b
Quality:     phi < codellama:7b < mistral < deepseek:6.7b < codellama:13b < deepseek:33b
Size:        phi (1.6GB) < codellama:7b (3.8GB) < codellama:13b (7.4GB) < deepseek:33b (19GB)
```

### Switching Models

```python
# Fast development
agent = OllamaAgent(model="codellama:7b")

# Production analysis
agent = OllamaAgent(model="deepseek-coder:33b")

# Fallback chain
primary = OllamaAgent(model="codellama:13b")
fallback = OllamaAgent(model="codellama:7b")
```

---

## CrewAI Architecture

### Agent Roles

CrewAI uses specialized agents with defined roles:

1. **Senior Auditor**
   - Role: Find vulnerabilities
   - Tools: Static analysis, pattern matching
   - Delegation: Yes (can delegate to others)

2. **Security Critic**
   - Role: Validate findings
   - Tools: Logic verification, false positive detection
   - Delegation: No (final validator)

3. **Compliance Officer**
   - Role: Map to standards
   - Tools: SWC, OWASP, ISO mappings
   - Delegation: No

4. **Report Writer**
   - Role: Synthesize results
   - Tools: Natural language generation
   - Delegation: No

### Workflow

```
Contract
   ↓
┌──────────────────┐
│ Senior Auditor   │ → Finds vulnerabilities
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Security Critic  │ → Validates findings
└────────┬─────────┘
         ↓
┌──────────────────┐
│Compliance Officer│ → Maps to standards
└────────┬─────────┘
         ↓
┌──────────────────┐
│  Report Writer   │ → Synthesizes report
└──────────────────┘
         ↓
    Final Report
```

---

## Cost Comparison

### OpenAI vs Ollama

| Metric | OpenAI GPT-4 | OpenAI GPT-3.5 | Ollama (Local) |
|--------|--------------|----------------|----------------|
| Per analysis | $0.03 | $0.002 | $0.00 |
| 100 analyses | $3.00 | $0.20 | $0.00 |
| Monthly (3000) | $90.00 | $6.00 | $0.00 |
| **Annual savings** | **$1,080** | **$72** | **$0 cost** |

### ROI Calculation

```
Scenario: Analyze 10 contracts/day

OpenAI GPT-4:
  - 10 × $0.03 × 365 days = $109.50/year

Ollama:
  - Hardware: $0 (use existing)
  - Electricity: ~$5/year
  - Total: $5/year

Savings: $104.50/year (95% reduction)
```

---

## Best Practices

### 1. Development Workflow

```python
# Fast feedback during development
dev_agent = OllamaAgent(model="codellama:7b")

while developing:
    results = dev_agent.run("contract.sol")
    fix_issues(results)
```

### 2. CI/CD Pipeline

```yaml
# .github/workflows/security.yml
- name: MIESC Ollama Check
  run: |
    ollama pull codellama:7b
    python src/agents/ollama_agent.py contracts/MyToken.sol
```

### 3. Hybrid Approach

```python
# Use Ollama for bulk, GPT-4 for critical
if contract_value < $100k:
    agent = OllamaAgent()
else:
    agent = GPTAgent()  # Use expensive model for high-value
```

### 4. Caching Strategy

```python
from src.cache import cache_analysis_result

@cache_analysis_result(tool='ollama', use_cache=True)
def analyze_with_ollama(contract_path):
    agent = OllamaAgent()
    return agent.run(contract_path)

# First call: runs Ollama (60s)
result = analyze_with_ollama("contract.sol")

# Second call: cached (instant)
result = analyze_with_ollama("contract.sol")
```

---

## Troubleshooting

### Ollama Not Found

```bash
# Check installation
which ollama

# Reinstall
curl https://ollama.ai/install.sh | sh
```

### Model Not Downloaded

```bash
# List models
ollama list

# Download missing model
ollama pull codellama:13b
```

### Out of Memory

```bash
# Use smaller model
ollama pull codellama:7b

# Or increase swap
# macOS: System Settings → Memory
# Linux: sudo fallocate -l 16G /swapfile
```

### Slow Performance

```bash
# Check if Ollama is using GPU
ollama ps

# Use faster model
ollama pull phi:latest  # Smallest model
```

### CrewAI Import Error

```bash
# Install dependencies
pip install crewai crewai-tools langchain langchain-community
```

---

## Advanced Usage

### Custom Prompts

```python
agent = OllamaAgent(model="codellama:13b")

# Override system prompt
custom_prompt = """You are an expert in DeFi security.
Focus on:
- Flash loan attacks
- Oracle manipulation
- MEV vulnerabilities
"""

agent.SYSTEM_PROMPT = custom_prompt
```

### Multi-Model Analysis

```python
models = ["codellama:7b", "codellama:13b", "deepseek-coder:6.7b"]

results = []
for model in models:
    agent = OllamaAgent(model=model)
    result = agent.run("contract.sol")
    results.append(result)

# Aggregate findings
all_findings = merge_findings(results)
```

### Custom CrewAI Agents

```python
from crewai import Agent

custom_agent = Agent(
    role='DeFi Security Specialist',
    goal='Find DeFi-specific vulnerabilities',
    backstory='Expert in DeFi protocols...',
    llm=ollama_llm
)

coordinator.add_agent(custom_agent)
```

---

## Performance Tuning

### Temperature Settings

```python
# More deterministic (recommended for security)
agent = OllamaAgent(temperature=0.1)

# More creative (for explanations)
agent = OllamaAgent(temperature=0.5)
```

### Token Limits

```python
# Faster but less detailed
agent = OllamaAgent(max_tokens=1000)

# Slower but more comprehensive
agent = OllamaAgent(max_tokens=4000)
```

### Parallel Analysis

```python
from concurrent.futures import ThreadPoolExecutor

def analyze_contract(path):
    agent = OllamaAgent()
    return agent.run(path)

contracts = ["c1.sol", "c2.sol", "c3.sol"]

with ThreadPoolExecutor(max_workers=3) as executor:
    results = list(executor.map(analyze_contract, contracts))
```

---

## Examples

See `examples/use_ollama_crewai.py` for complete examples:

1. Basic Ollama usage
2. Model comparison
3. CrewAI coordination
4. Hybrid workflow
5. Cost comparison
6. Production workflow

Run examples:
```bash
python examples/use_ollama_crewai.py
```

---

## FAQ

**Q: Can I use Ollama with Docker?**

A: Yes, see `docker-compose.optimized.yml` for Ollama service.

**Q: Which model is best?**

A: For most uses: `codellama:13b` (balanced). For CI/CD: `codellama:7b` (fast).

**Q: How much RAM do I need?**

A: Minimum 8GB. Recommended 16GB for larger models.

**Q: Can I fine-tune models?**

A: Yes, with Ollama `create` command. See Ollama documentation.

**Q: Does Ollama support GPU?**

A: Yes, automatically detects and uses GPU if available.

**Q: Can I use CrewAI with OpenAI instead of Ollama?**

A: Yes, set `use_local_llm=False` in CrewAICoordinator.

---

## Resources

- Ollama: https://ollama.ai
- CrewAI: https://github.com/joaomdmoura/crewAI
- Model configs: `config/ollama_models.yml`
- Setup script: `scripts/setup_ollama.sh`
- Examples: `examples/use_ollama_crewai.py`

---

## License

GPL-3.0 (same as MIESC framework)
