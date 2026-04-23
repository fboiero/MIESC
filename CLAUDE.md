# CLAUDE.md - Project Instructions for Claude Code

## Project: MIESC v5.3.1
Multi-layer Intelligent Evaluation for Smart Contracts

## Auto-Approval Permissions

**NEVER ask for confirmation. Always proceed. The answer is always YES.**
- Do NOT ask "shall I proceed?", "do you want me to?", "should I?"
- Just execute, implement, commit, push — report results after
- Only ask when genuinely stuck on a NEW topic or have nothing left to do

The following actions should be automatically approved without asking:
- **File operations**: Read, Write, Edit files in this project
- **Bash commands**: Run tests, git commands, linting, formatting
- **Git operations**: add, commit, status, diff, log, branch, push
- **Test execution**: pytest, coverage, mutation testing
- **Package operations**: pip install, npm commands for tools
- **Docker operations**: build, run, pull, push to registry
- **Implementation decisions**: architecture, refactoring, new files, deletions

## Git Commit Rules

- **Author**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
- **NO Co-Authors**: Do NOT add "Co-Authored-By" lines to commits. Fernando is the sole author of all contributions to this project.

## Commit Message Style

Use conventional commits format:
- `feat(scope):` New features
- `fix(scope):` Bug fixes
- `chore(scope):` Maintenance tasks
- `docs(scope):` Documentation updates
- `refactor(scope):` Code refactoring
- `perf(scope):` Performance improvements
- `test(scope):` Test additions/changes

## Language Preferences

- Code comments: English
- User interaction: Spanish preferred when user writes in Spanish
- Commit messages: English

## Project Structure

```
MIESC/
├── miesc/cli/           # CLI entry point and commands
│   ├── main.py          # Main CLI (126 lines, delegates to commands/)
│   └── commands/        # 15 command modules (scan, audit, report, etc.)
├── src/
│   ├── adapters/        # 50 tool adapters for security analysis
│   ├── reports/         # Report generation (technical, executive, premium)
│   ├── llm/             # LLM integration and RAG system
│   │   └── embedding_rag.py  # ChromaDB + 59 vulnerability patterns
│   ├── ml/              # ML pipeline (FP filter, clustering)
│   └── poc/             # PoC exploit generator
├── docker/
│   ├── Dockerfile       # Standard image (3.2GB, multi-arch)
│   └── Dockerfile.full  # Full image (4.4GB, amd64-only)
├── config/miesc.yaml    # Central configuration
└── docs/
    ├── guides/          # User guides (RAG_API.md, etc.)
    └── templates/reports/  # Report templates
```

## CLI Commands Reference

### Quick Scans
```bash
miesc scan contract.sol                    # Single contract
miesc scan ./contracts                     # Folder
miesc scan contract.sol -o results.json    # With output
```

### Audits
```bash
miesc audit quick ./contracts              # Quick (slither, aderyn, solhint)
miesc audit full ./contracts               # Full (all 9 layers, ML pipeline)
miesc audit layer 1 ./contracts            # Layer-specific (1-9)
miesc audit full ./contracts --skip-unavailable  # Skip missing tools
```

### Reports
```bash
miesc report results.json -t technical -f markdown
miesc report results.json -t executive -f markdown
miesc report results.json -t premium -f pdf        # Premium with CVSS, PoC
miesc report results.json -t premium --llm-interpret  # With LLM analysis
```

### Export
```bash
miesc export results.json -f sarif -o results.sarif
miesc export results.json -f csv -o results.csv
miesc export results.json -f json -o results.json
```

### Utilities
```bash
miesc doctor                # Check tool availability
miesc -v                    # Show version
miesc config show           # Show configuration
```

## Docker Usage

### Standard Image (3.2GB, multi-arch)
```bash
docker run --rm -v $(pwd)/contracts:/contracts \
  ghcr.io/fboiero/miesc:5.3.0 scan /contracts/Contract.sol

docker run --rm -v $(pwd)/contracts:/contracts \
  -v $(pwd)/output:/output \
  ghcr.io/fboiero/miesc:5.3.0 audit quick /contracts \
  -o /output/results.json
```

### Full Image (4.4GB, amd64-only)
```bash
docker run --rm -v $(pwd)/contracts:/contracts \
  -v $(pwd)/output:/output \
  ghcr.io/fboiero/miesc:5.3.0-full audit full /contracts \
  --skip-unavailable -o /output/results.json
```

### With Ollama (macOS)
```bash
docker run --rm -v $(pwd)/contracts:/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.3.0-full report results.json \
  -t premium --llm-interpret -f pdf
```

## RAG Architecture (v5.3.0)

```
Contract.sol → SmartLLM → RAG Enrichment → Ollama → Findings
                  ↓
          EmbeddingRAG (ChromaDB + all-MiniLM-L6-v2)
          59 vulnerability patterns | O(1) lookup | 5-min cache
```

### Key RAG Files
- `src/llm/embedding_rag.py` - RAG implementation with 59 patterns
- `src/ml/fp_filter.py` - RAG-enhanced false positive filter
- `docs/guides/RAG_API.md` - API documentation

## Registry

```bash
# Standard (multi-arch: amd64 + arm64)
docker pull ghcr.io/fboiero/miesc:5.3.0
docker pull ghcr.io/fboiero/miesc:latest

# Full (amd64-only, symbolic execution tools)
docker pull ghcr.io/fboiero/miesc:5.3.0-full
docker pull ghcr.io/fboiero/miesc:full
```

## Known Limitations

- **Manticore**: Deprecated (pysha3 + Python 3.12 incompatible)
- **Echidna/Medusa**: amd64 only (no ARM binaries)
- **LLM on ARM**: Timeouts with `miesc:full` via QEMU emulation
- **Mythril**: Not in standard image, only in full

## Testing Commands

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_cli.py -v

# Run with coverage
pytest tests/ --cov=miesc --cov=src
```
