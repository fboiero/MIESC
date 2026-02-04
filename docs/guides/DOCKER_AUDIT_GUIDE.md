# Complete Guide: Audit with Docker + LLM

Step-by-step guide to run a comprehensive smart contract security audit using Docker and generate a professional PDF report with AI-powered interpretation.

**Estimated setup time**: first run ~15 min (image and model downloads). Subsequent runs: only steps 3-5.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Docker Desktop** | Version 20+ with **8GB+ RAM** allocated |
| **Ollama** | For AI-powered report interpretation |
| **Disk space** | ~12GB (Docker image ~8GB + LLM model ~4GB) |

---

## Step 1: Install and configure Docker

Download Docker Desktop from https://www.docker.com/products/docker-desktop

**Configure memory (required):**

- Docker Desktop → Settings → Resources → Memory → **8GB** (or more)
- Apply & Restart

**Pull the FULL MIESC image** (includes all 50 tools):

```bash
docker pull ghcr.io/fboiero/miesc:full
```

> **ARM / Apple Silicon:** The `:full` image in the registry is amd64-only. On ARM it runs under QEMU emulation (~3-5x slower). For native performance, build locally with `./scripts/build-images.sh full` or use the setup wizard `./scripts/docker-setup.sh`. The `:latest` (standard) image is multi-arch and works natively on ARM.

Verify it works:

```bash
docker run --rm ghcr.io/fboiero/miesc:full --version
# Should show: MIESC version 5.0.3

docker run --rm ghcr.io/fboiero/miesc:full doctor
# Shows ~30 available tools
```

---

## Step 2: Install Ollama and download the AI model

### macOS

```bash
brew install ollama
```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Windows

Download from https://ollama.com/download

### Start Ollama and download the model

```bash
# Start the service (keep this terminal open)
ollama serve

# In another terminal, download the interpretation model (~4GB)
ollama pull mistral:latest

# Verify it's available
ollama list
# Should show: mistral:latest
```

> **Note:** `ollama serve` must be running throughout the audit. If you close the terminal, step 5 won't be able to generate AI insights.

---

## Step 3: Prepare your contracts

Place all `.sol` files you want to audit in a folder:

```bash
mkdir my_contracts
cp MyToken.sol MyVault.sol my_contracts/

# Verify the files are there
ls my_contracts/
# MyToken.sol  MyVault.sol
```

---

## Step 4: Run the full audit

This runs all 9 defense layers (static, dynamic, symbolic, formal verification, AI, ML, etc.) on every contract in the folder:

```bash
docker run --rm \
  -v $(pwd)/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

**On Windows PowerShell** replace `$(pwd)` with `${PWD}`:

```powershell
docker run --rm `
  -v ${PWD}/my_contracts:/contracts `
  ghcr.io/fboiero/miesc:full `
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

When finished you'll see a summary like this:

```
    Batch Analysis Summary
╭────────────────────┬────────╮
│ Metric             │  Value │
├────────────────────┼────────┤
│ Contracts Analyzed │      9 │
│ CRITICAL           │      0 │
│ HIGH               │      4 │
│ MEDIUM             │      3 │
│ LOW                │     39 │
│ TOTAL FINDINGS     │     73 │
╰────────────────────┴────────╯
OK Report saved to /contracts/results.json
```

---

## Step 5: Generate the professional PDF report with AI

### macOS / Windows

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Client Name" \
    --auditor "Your Name" \
    --contract-name "Project Name" \
    --network "Ethereum Mainnet" \
    --classification "CONFIDENTIAL" \
    -o /contracts/audit_report.pdf
```

### Linux

```bash
docker run --rm --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd)/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Client Name" \
    --auditor "Your Name" \
    --contract-name "Project Name" \
    --network "Ethereum Mainnet" \
    --classification "CONFIDENTIAL" \
    -o /contracts/audit_report.pdf
```

### Windows PowerShell

```powershell
docker run --rm `
  -e OLLAMA_HOST=http://host.docker.internal:11434 `
  -v ${PWD}/my_contracts:/contracts `
  ghcr.io/fboiero/miesc:full `
  report /contracts/results.json -t premium -f pdf `
    --llm-interpret `
    --client "Client Name" `
    --auditor "Your Name" `
    --contract-name "Project Name" `
    --network "Ethereum Mainnet" `
    --classification "CONFIDENTIAL" `
    -o /contracts/audit_report.pdf
```

**Customize these fields:**

| Field | What to put | Example |
|-------|-------------|---------|
| `--client` | Client or company name | `"Acme Corp"` |
| `--auditor` | Auditor name | `"Security Team"` |
| `--contract-name` | Contract or project name | `"TokenV2.sol"` |
| `--network` | Target deployment network | `"Ethereum Mainnet"`, `"Polygon"`, `"BSC"` |
| `--classification` | Report classification | `"CONFIDENTIAL"`, `"PUBLIC"`, `"INTERNAL"` |

---

## Step 6: Open the report

The PDF is saved in your contracts folder:

```bash
# macOS
open my_contracts/audit_report.pdf

# Linux
xdg-open my_contracts/audit_report.pdf

# Windows
start my_contracts\audit_report.pdf
```

---

## What the report includes

The professional PDF report (Trail of Bits / OpenZeppelin style) includes:

- **Cover page** with confidentiality classification
- **Executive summary** with AI-generated business risk analysis
- **Deployment recommendation**: GO / NO-GO / CONDITIONAL
- **Risk matrix** with CVSS-like scoring
- **Detailed findings** with step-by-step attack scenarios
- **Code remediation suggestions** with diffs
- **Prioritized remediation roadmap**
- **PoC exploit templates** for critical/high findings
- **AI disclosure note** for transparency

---

## Troubleshooting

### "Cannot connect to Ollama" or "LLM interpretation failed"

```bash
# Verify Ollama is running
ollama list

# If not running, start it
ollama serve
```

### "Out of memory" or Docker freezes

- Increase Docker Desktop RAM to **10GB+** in Settings → Resources
- Close other memory-intensive applications

### PDF not generated (only HTML output)

PDF conversion requires WeasyPrint. If it fails, the report is saved as HTML. You can convert manually:

```bash
# Install weasyprint
pip install weasyprint  # or: brew install weasyprint

# Convert
weasyprint my_contracts/audit_report.html my_contracts/audit_report.pdf
```

### "Contract file not found"

```bash
# Make sure the volume mount path is correct
# The path INSIDE the container must match the mount point
docker run --rm -v /full/path/to/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

---

## Quick reference (copy & paste)

```bash
# === SETUP (first time only) ===
docker pull ghcr.io/fboiero/miesc:full
ollama pull mistral:latest

# === AUDIT (every time) ===
# 1. Make sure Ollama is running
ollama serve &

# 2. Put your .sol files in a folder
mkdir my_contracts && cp *.sol my_contracts/

# 3. Full audit
docker run --rm \
  -v $(pwd)/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r

# 4. PDF report with AI (macOS/Windows)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/my_contracts:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Client" \
    --auditor "Auditor" \
    -o /contracts/audit_report.pdf

# 5. Open the PDF
open my_contracts/audit_report.pdf
```

---

**Full documentation:** https://fboiero.github.io/MIESC
**Repository:** https://github.com/fboiero/MIESC
