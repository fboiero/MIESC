# MIESC Docker Quick Start

Quick guide to run security audits using MIESC with Docker. No installation required.

**[Versión en Español](DOCKER_QUICKSTART_ES.md)**

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Docker Desktop** | Version 20+ with 8GB+ RAM |
| **Ollama** | For AI-powered analysis (optional but recommended) |
| **Disk space** | ~12GB (Docker image ~4GB + LLM models ~8GB) |

### Install Ollama (for AI features)

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Download AI models (one-time, ~8GB total)
ollama pull deepseek-coder:6.7b
ollama pull codellama
ollama pull mistral

# Start Ollama (keep running in background)
ollama serve
```

---

## 1. Prepare Your Contracts

Create a folder and place your `.sol` files there:

```bash
mkdir contracts
cd contracts

# Copy your contracts here
cp /path/to/MyToken.sol .
cp /path/to/MyVault.sol .
```

> **Note:** This `contracts/` folder is where you place the contracts you want to audit. MIESC will analyze all `.sol` files found here.

### Sample Contracts for Testing

If you want to test with vulnerable contracts:

```bash
# Download real vulnerable contract examples
curl -O https://raw.githubusercontent.com/crytic/not-so-smart-contracts/master/reentrancy/Reentrancy.sol
curl -O https://raw.githubusercontent.com/crytic/not-so-smart-contracts/master/integer_overflow/integer_overflow_1.sol
```

**Repositories with vulnerable contracts for demos:**

| Repository | Description |
|------------|-------------|
| [crytic/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) | Classic vulnerability examples |
| [SunWeb3Sec/DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) | Real DeFi vulnerabilities |
| [smartbugs/smartbugs](https://github.com/smartbugs/smartbugs) | Vulnerable contracts dataset |

---

## 2. Quick Scan (~30 seconds)

Fast 4-tool analysis:

```bash
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MyContract.sol
```

---

## 3. Full Audit with AI (5-8 min)

Complete 9-layer audit with 30+ tools:

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MyContract.sol \
  --skip-unavailable \
  -o /contracts/results.json
```

---

## 4. Batch Audit (All Contracts)

Audit all contracts in the folder:

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts \
  -o /contracts/batch_results.json
```

---

## 5. Generate Professional PDF Report (2-3 min)

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json \
  -t premium -f pdf \
  --llm-interpret \
  --client "Client Name" \
  --auditor "Your Name" \
  --contract-name "Project Name" \
  -o /contracts/audit_report.pdf

# Open the PDF
open audit_report.pdf   # macOS
xdg-open audit_report.pdf   # Linux
```

---

## 6. Check Available Tools

```bash
# Without Ollama (static tools only)
docker run --rm ghcr.io/fboiero/miesc:full doctor

# With Ollama (includes LLM adapters)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:full doctor
```

---

## Folder Structure

After running audits, your folder will look like:

```
contracts/                    ← Your contracts folder
├── MyToken.sol              ← Your .sol contracts
├── MyVault.sol
├── results.json             ← Audit results (generated)
├── batch_results.json       ← Batch results (generated)
└── audit_report.pdf         ← PDF report (generated)
```

---

## Command Reference

| Command | Time | Description |
|---------|------|-------------|
| `scan` | 30s | Quick 4-tool analysis |
| `audit quick` | 1min | Basic scan |
| `audit full` | 5-8min | 9 layers, 30+ tools, AI |
| `audit batch` | varies | Multiple contracts |
| `report -t premium` | 2-3min | Professional PDF with AI |
| `doctor` | 10s | Show available tools |

---

## Available Docker Images

| Image | Size | Contents |
|-------|------|----------|
| `ghcr.io/fboiero/miesc:latest` | ~3GB | Standard: Slither, Aderyn, Solhint, Foundry (~15 tools) |
| `ghcr.io/fboiero/miesc:full` | ~4GB | Full: + Mythril, Halmos, Semgrep, Wake (~30 tools) |

---

## Troubleshooting

### "Cannot connect to Ollama"

```bash
# Make sure Ollama is running
ollama list

# If not running, start it
ollama serve
```

### "Out of memory"

- Increase Docker Desktop RAM to 10GB+ in Settings → Resources

### Linux users

Use `--network host` instead of `host.docker.internal`:

```bash
docker run --rm --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MyContract.sol
```

---

## Documentation

- **Full guide:** [DOCKER_AUDIT_GUIDE.md](DOCKER_AUDIT_GUIDE.md)
- **Website:** https://fboiero.github.io/MIESC
- **Repository:** https://github.com/fboiero/MIESC
