# MIESC AI Agents - Quick Start Guide

Get started with Ollama and CrewAI integration in 5 minutes.

## Prerequisites

- Python 3.8+
- 8GB+ RAM (16GB recommended)
- 10GB free disk space

## Step 1: Install Dependencies (2 minutes)

```bash
# Install Python dependencies
pip install -r requirements_agents.txt

# Install Ollama (macOS/Linux)
curl https://ollama.ai/install.sh | sh

# Verify Ollama installation
ollama --version
```

## Step 2: Download Models (3 minutes)

```bash
# Quick setup (one model, 3.8GB)
ollama pull codellama:7b

# Recommended setup (two models, 11GB)
ollama pull codellama:13b
ollama pull deepseek-coder:6.7b

# Or use automated script
bash scripts/setup_ollama.sh
```

## Step 3: Run Your First Analysis (30 seconds)

### Option A: Interactive Test Runner

```bash
# Run interactive test suite
python scripts/test_ollama_crewai.py
```

This will:
- Check your system requirements
- Test Ollama installation
- Run sample analysis with OllamaAgent
- Run sample analysis with CrewAI
- Display results with rich console interface

### Option B: Command Line

```bash
# Basic analysis with Ollama
python main_ai.py examples/reentrancy.sol test --use-ollama

# Multi-agent analysis
python main_ai.py examples/reentrancy.sol test --use-ollama --use-crewai

# Quick mode (fastest)
python main_ai.py examples/reentrancy.sol test --quick
```

### Option C: Python Script

```python
from src.agents.ollama_agent import OllamaAgent

# Create agent
agent = OllamaAgent(model="codellama:13b")

# Analyze contract
results = agent.run("examples/reentrancy.sol")

# Access findings
for finding in results["ollama_findings"]:
    print(f"{finding['severity']}: {finding['description']}")
```

## What You Get

### OllamaAgent Features
- ✅ **Cost-free analysis** - No API fees
- ✅ **Complete privacy** - Data never leaves your machine
- ✅ **Multiple models** - Choose speed vs quality
- ✅ **SWC/OWASP mapping** - Industry standard compliance
- ✅ **JSON output** - Easy integration

### CrewAI Features
- ✅ **Multi-agent coordination** - 4 specialized agents
- ✅ **Hierarchical workflow** - Auditor → Critic → Compliance → Reporter
- ✅ **Higher confidence** - Multiple AI perspectives
- ✅ **Collaborative reasoning** - Agents validate each other

## Common Use Cases

### 1. Development Workflow (Fast Feedback)

```bash
# Fast model for quick feedback
python main_ai.py contract.sol dev --use-ollama --ollama-model codellama:7b
```

**Time:** ~30 seconds
**Cost:** $0

### 2. CI/CD Pipeline (Automated Checks)

```bash
# Balanced model for CI/CD
python main_ai.py contract.sol cicd --use-ollama --ollama-model deepseek-coder:6.7b
```

**Time:** ~45 seconds
**Cost:** $0

### 3. Pre-Audit (Comprehensive Analysis)

```bash
# High-quality model + multi-agent
python main_ai.py contract.sol audit --use-ollama --use-crewai
```

**Time:** ~2 minutes
**Cost:** $0

## Model Selection Guide

| Model | Speed | Quality | RAM | Use For |
|-------|-------|---------|-----|---------|
| `phi:latest` | ⚡⚡⚡ | ⭐⭐ | 4GB | Quick scans |
| `codellama:7b` | ⚡⚡ | ⭐⭐⭐ | 8GB | **Development** |
| `codellama:13b` | ⚡ | ⭐⭐⭐⭐ | 12GB | **Recommended** |
| `deepseek-coder:6.7b` | ⚡⚡ | ⭐⭐⭐⭐ | 8GB | CI/CD |
| `deepseek-coder:33b` | 🐌 | ⭐⭐⭐⭐⭐ | 24GB | Production |

**Default:** `codellama:13b` (best balance)

## Configuration

Update `config/config.py`:

```python
class ModelConfig:
    # Enable Ollama
    use_ollama = True
    ollama_model = "codellama:13b"

    # Enable CrewAI
    use_crewai = True
    crewai_use_local_llm = True
    crewai_llm_model = "ollama/codellama:13b"
```

Or use command-line flags:

```bash
python main_ai.py contract.sol test \
  --use-ollama \
  --ollama-model codellama:13b \
  --use-crewai \
  --crewai-model ollama/codellama:13b
```

## Output

Analysis results are saved to `output/<tag>/`:

```
output/test/
├── Ollama.txt        # Ollama findings
├── CrewAI.txt        # CrewAI findings
├── Slither.txt       # Slither findings (if enabled)
├── summary.txt       # Combined summary
└── conclusion.txt    # Conclusions
```

## Cost Savings

### Traditional (OpenAI GPT-4)
- Per analysis: **$0.03**
- 100 analyses: **$3.00**
- Annual (3000): **$90.00**

### With Ollama
- Per analysis: **$0.00**
- 100 analyses: **$0.00**
- Annual (3000): **$0.00**

**Savings: $90/year (100% reduction!)**

## Next Steps

1. **Explore Examples**
   ```bash
   python examples/use_ollama_crewai.py
   python examples/specific_use_cases.py
   ```

2. **Read Documentation**
   - Complete guide: `docs/OLLAMA_CREWAI_GUIDE.md`
   - Model optimization: `config/model_optimization.yml`
   - Agent README: `docs/agents/README.md`

3. **Integrate into Workflow**
   - Add to CI/CD pipeline
   - Create custom prompts
   - Combine with traditional tools

4. **Advanced Usage**
   - Multi-model validation
   - Custom agent roles
   - DeFi-specific analysis

## Troubleshooting

### Ollama not found

```bash
# Check installation
which ollama

# Reinstall
curl https://ollama.ai/install.sh | sh
```

### Model not downloaded

```bash
# List models
ollama list

# Download missing model
ollama pull codellama:13b
```

### Out of memory

```bash
# Use smaller model
ollama pull codellama:7b

# Or minimal model
ollama pull phi:latest
```

### Slow performance

```bash
# Check if Ollama is using GPU
ollama ps

# Use faster model
ollama pull codellama:7b
```

### Import errors

```bash
# Install all dependencies
pip install -r requirements_agents.txt

# Or individually
pip install crewai crewai-tools langchain langchain-community rich
```

## Getting Help

- **Documentation**: `docs/OLLAMA_CREWAI_GUIDE.md`
- **Examples**: `examples/use_ollama_crewai.py`
- **Tests**: `tests/agents/test_ollama_agent.py`
- **Issues**: [GitHub Issues](https://github.com/your-repo/MIESC/issues)

## Frequently Asked Questions

**Q: Do I need an API key?**
A: No! Ollama runs completely locally. No API keys, no cloud services.

**Q: Which model should I use?**
A: Start with `codellama:13b` (best balance). Use `codellama:7b` for speed, `deepseek-coder:33b` for quality.

**Q: Can I use GPU?**
A: Yes! Ollama automatically detects and uses GPU if available (2-4x speedup).

**Q: How accurate is it compared to GPT-4?**
A: Slightly lower quality than GPT-4, but still very good. See benchmarks in `docs/OLLAMA_CREWAI_GUIDE.md`.

**Q: Can I use both Ollama and OpenAI?**
A: Yes! Use Ollama for development/testing, OpenAI for critical contracts. Best of both worlds.

**Q: Is this production-ready?**
A: Yes! Ollama is mature and stable. Many teams use it in production.

## Example Output

```
════════════════════════════════════════════════════════════
MIESC - Multi-agent Integrated Security

Contract: examples/reentrancy.sol
Output: output/test/
════════════════════════════════════════════════════════════

┌─────────────────────────────────┐
│ Analysis Tools                  │
├─────────────────────────────────┤
│ ✓ Slither                       │
│ ✓ Ollama (codellama:13b)        │
│ ✓ CrewAI                        │
└─────────────────────────────────┘

Running Ollama analysis (codellama:13b)...
✓ Analysis complete in 45.23s
Found 3 potential issues

Running CrewAI multi-agent analysis...
✓ Multi-agent analysis complete!
Found 4 issues

════════════════════════════════════════════════════════════
✓ Analysis Complete

Results saved to: output/test/
Tools used: 3
════════════════════════════════════════════════════════════
```

## Success!

You're now ready to use MIESC with Ollama and CrewAI! 🎉

For more advanced usage, see:
- `docs/OLLAMA_CREWAI_GUIDE.md` - Complete 60+ page guide
- `examples/specific_use_cases.py` - Real-world examples
- `config/model_optimization.yml` - Performance tuning
