# Xaudit Usage Guide

## Quick Start

### Basic Usage

```bash
# Using the convenience script
./run_audit.sh examples/voting.sol 0.8.0 voting_audit

# Direct Python execution
python main.py examples/voting.sol voting_audit
```

## Command-Line Arguments

```
python main.py <contract_path> <tag>
```

- `contract_path`: Path to the Solidity contract file
- `tag`: Identifier for this audit (creates output directory)

## Configuration

Edit `config.py` to enable/disable tools and report sections:

```python
class ModelConfig:
    # Analysis Tools
    use_slither = True        # Enable Slither static analysis
    use_mythril = True        # Enable Mythril symbolic execution
    use_rawGPT = False        # Enable direct GPT-4 analysis
    use_GPTLens = True        # Enable GPTLens two-stage analysis
    use_rawLlama = False      # Enable local Llama 2 analysis

    # Report Sections
    include_introduction = True     # Add introduction section
    include_tools_output = True     # Include raw tool outputs
    include_summary = True          # Generate AI summary
    include_unitary_test = False    # Suggest unit tests
    include_conclusion = True       # Add conclusion section
```

## Environment Variables

Create a `.env` file in the project root:

```bash
# Required for GPTLens and rawGPT
OPENAI_API_KEY=sk-your-openai-api-key-here

# Optional: For future integrations
ANTHROPIC_API_KEY=your-anthropic-key
```

## Workflow Examples

### Example 1: Quick Security Scan

Use only fast tools (Slither) for rapid feedback:

```python
# config.py
class ModelConfig:
    use_slither = True
    use_mythril = False
    use_GPTLens = False
    # ...
```

```bash
./run_audit.sh examples/Whitelist.sol 0.8.20 quick_scan
```

### Example 2: Comprehensive Audit

Enable all tools for thorough analysis:

```python
# config.py
class ModelConfig:
    use_slither = True
    use_mythril = True
    use_GPTLens = True
    include_summary = True
    include_conclusion = True
```

```bash
./run_audit.sh examples/Xscrow.sol 0.8.9 comprehensive_audit
```

### Example 3: AI-Only Analysis

Skip traditional tools, use only AI models:

```python
# config.py
class ModelConfig:
    use_slither = False
    use_mythril = False
    use_GPTLens = True
    use_rawGPT = True
```

```bash
./run_audit.sh examples/ManualOracle.sol 0.8.9 ai_only
```

### Example 4: Privacy-Preserving Audit

Use only local tools (no API calls):

```python
# config.py
class ModelConfig:
    use_slither = True
    use_mythril = True
    use_GPTLens = False
    use_rawGPT = False
    use_rawLlama = True  # Requires local setup
```

## Output Structure

After running an audit, outputs are organized as follows:

```
output/
└── <tag>/
    ├── Slither.txt          # Slither raw output
    ├── Mythril.txt          # Mythril raw output
    ├── GPTLens.txt          # GPTLens analysis
    └── rawchatGPT.txt       # GPT-4 analysis
output.pdf                   # Consolidated PDF report
```

## Understanding Reports

### Slither Output

```
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation

HIGH severity issues: Immediate action required
MEDIUM severity issues: Should be addressed
LOW severity issues: Best practices
INFORMATIONAL: Code quality suggestions
```

### Mythril Output

```
==== [Vulnerability Type] ====
SWC ID: [Standard Weakness Classification]
Severity: [High/Medium/Low]
Contract: [ContractName]
Function name: [functionName]
PC address: [Program Counter]

Description: [Detailed explanation]
```

### GPTLens Output

JSON format with ranked vulnerabilities:

```json
[
  {
    "function_name": "delegate",
    "code": "while (voters[to].delegate != address(0)) { ... }",
    "vulnerability": "Denial of Service",
    "reason": "Unbounded loop in delegation chain",
    "correctness": "0.9",
    "severity": "0.8",
    "profitability": "0.3",
    "final_score": "0.73"
  }
]
```

**Score Interpretation:**
- `correctness`: Confidence this is a real vulnerability (0-1)
- `severity`: Impact if exploited (0-1)
- `profitability`: Attacker's potential gain (0-1)
- `final_score`: Weighted average (50% correctness, 25% severity, 25% profit)

## Advanced Usage

### Batch Auditing

Create a script to audit multiple contracts:

```bash
#!/bin/bash
for contract in examples/*.sol; do
    filename=$(basename "$contract" .sol)
    ./run_audit.sh "$contract" 0.8.0 "$filename"
done
```

### Custom Solidity Versions

The tool automatically detects the Solidity version from pragma:

```solidity
pragma solidity ^0.8.9;  // Auto-detected
```

Or specify manually as the second argument.

### Timeout Configuration

For large contracts, increase timeouts in tool files:

```python
# src/slither_tool.py
result = subprocess.run(
    ["slither", contract_path],
    timeout=600  # 10 minutes
)
```

### API Rate Limiting

For GPT-4, rate limiting is automatically handled:

```python
# src/GPTLens_tool.py
if model == "gpt-4":
    time.sleep(30)  # 30-second delay between calls
```

## Troubleshooting

### Issue: "solc-select not found"

```bash
pip install solc-select
```

### Issue: "Slither not found"

```bash
pip install slither-analyzer
```

### Issue: "OpenAI API Error"

1. Check your API key in `.env`
2. Verify your OpenAI account has credits
3. Check rate limits

### Issue: "Mythril timeout"

Mythril can be slow on complex contracts. Either:
- Disable Mythril for quick scans
- Increase timeout in `src/mythril_tool.py`

### Issue: "Import errors"

Ensure virtual environment is activated:
```bash
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

## Best Practices

1. **Start with Slither**: Fast feedback on common issues
2. **Use GPTLens for logic bugs**: AI excels at business logic
3. **Mythril for critical contracts**: Deep analysis when stakes are high
4. **Version control your config**: Different configs for different contexts
5. **Review outputs manually**: Tools suggest, humans decide
6. **Iterative auditing**: Re-audit after fixes

## Performance Tips

- **Disable unused tools**: Faster execution
- **Use caching**: Avoid re-running unchanged analyses
- **Parallel execution**: Run Slither and Mythril simultaneously (future feature)
- **GPU for local LLMs**: Essential for Llama 2

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install slither-analyzer
      - name: Run audit
        run: |
          python main.py contracts/MyContract.sol ci_audit
```

## Getting Help

- **Documentation**: Check `docs/` directory
- **Issues**: Report bugs on GitHub
- **Examples**: See `examples/` for sample contracts
