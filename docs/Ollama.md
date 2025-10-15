# Ollama - Local LLM for Smart Contract Analysis

## Overview

Ollama provides local Large Language Model (LLM) analysis for smart contracts, offering:
- **Cost-free** analysis ($0 per audit)
- **100% privacy** (all processing local)
- **No API keys** required
- **Unlimited usage** (no rate limits)
- **Offline capable** (works without internet)

## Models

Ollama supports multiple models optimized for code analysis:
- **codellama:7b** - Fast analysis (~30s per contract)
- **codellama:13b** - Balanced performance (~60s, recommended)
- **deepseek-coder:33b** - Maximum quality (~120s)

## Capabilities

Ollama agent performs comprehensive security analysis:
1. **Vulnerability Detection** - Identifies common smart contract vulnerabilities
2. **Code Quality Review** - Evaluates coding standards and best practices
3. **Gas Optimization** - Suggests gas-efficient alternatives
4. **SWC/OWASP Mapping** - Maps findings to security standards

## Analysis Process

1. Parses Solidity contract source code
2. Sends to local Ollama model for analysis
3. Extracts security findings and recommendations
4. Maps vulnerabilities to SWC IDs and OWASP categories
5. Calculates risk scores for each finding

## Benefits

- **Privacy-Preserving**: All analysis runs locally, no data leaves your machine
- **Cost-Effective**: Zero API costs, unlimited audits
- **Fast**: Local processing with GPU acceleration (M1/M2/M3 Macs)
- **Customizable**: Multiple model choices based on speed/quality trade-offs

## Integration

Ollama integrates seamlessly with MIESC's multi-tool analysis framework:
- Works alongside Slither, Mythril, and other tools
- Results aggregated into comprehensive audit report
- Can be combined with CrewAI for multi-agent analysis

## Usage

```bash
# Basic Ollama analysis
python main_ai.py contract.sol output --use-ollama

# Specify model
python main_ai.py contract.sol output --use-ollama --ollama-model codellama:7b

# Quick mode (uses codellama:7b)
python main_ai.py contract.sol output --quick
```

## Performance

Typical analysis times on Apple Silicon (M1/M2):
- Small contracts (<200 lines): 30-45 seconds
- Medium contracts (200-500 lines): 60-90 seconds
- Large contracts (>500 lines): 90-180 seconds

## Limitations

- Requires 8-16GB RAM depending on model size
- First run may be slower while model loads into memory
- Quality depends on model chosen (larger = better but slower)
- May miss novel/complex vulnerabilities not in training data

## Comparison with Commercial LLMs

| Feature | Ollama | GPT-4 |
|---------|--------|-------|
| Cost | $0 | ~$0.05 per audit |
| Privacy | 100% local | Sends to OpenAI |
| Speed | 60s (local) | 30s (API) |
| Quality | F1: 75-79 | F1: 82 |
| Rate Limits | None | API limits apply |

## Recommendations

- Use **codellama:13b** for regular development audits
- Use **codellama:7b** in CI/CD pipelines (faster)
- Use **deepseek-coder:33b** for pre-production audits (higher quality)
- Combine with **Slither** for comprehensive coverage

## Further Information

- Official site: https://ollama.ai
- Model library: https://ollama.ai/library
- MIESC docs: docs/OLLAMA_CREWAI_GUIDE.md
