# Research Integration Guide

MIESC provides a scientific evaluation framework designed for researchers studying smart contract security. This guide covers reproducible benchmarking, ablation studies, extending the tool with custom detectors, and exporting structured data for analysis pipelines.

## Quick Start for Researchers

```bash
# Install from PyPI
pip install miesc

# Verify installation
miesc doctor

# Run evaluation on SmartBugs-curated (included in repo)
miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \
  --layers 1,5,7,9 \
  --output results.json \
  --jsonl results.jsonl
```

## Evaluation Framework

### Corpus Evaluation (`miesc evaluate corpus`)

Runs MIESC against an annotated benchmark corpus and reports precision, recall, F1, per-category breakdown, and timing data.

```bash
# Full evaluation with all available layers
miesc evaluate corpus <corpus_dir> \
  --layers 1,3,5,7,9 \
  --timeout 120 \
  --output evaluation_results.json \
  --jsonl streaming_results.jsonl

# Filter to specific vulnerability categories
miesc evaluate corpus <corpus_dir> \
  --categories reentrancy,arithmetic \
  --limit 50

# Quick test (3 contracts, 1 layer)
miesc evaluate corpus <corpus_dir> --layers 1 --limit 3
```

**Corpus format**: The corpus must follow the SmartBugs-curated directory structure:
```
corpus_dir/
├── reentrancy/
│   ├── contract1.sol
│   └── contract2.sol
├── access_control/
│   └── contract3.sol
├── arithmetic/
│   └── ...
└── ...
```

Each subdirectory name is treated as the ground-truth vulnerability category.

### Ablation Studies (`miesc evaluate ablation`)

Measures each layer's marginal contribution to detection by evaluating layers independently and then combined.

```bash
# Full ablation across 5 layers
miesc evaluate ablation <corpus_dir> \
  --layers 1,3,5,7,9 \
  --output ablation_results.json

# Quick ablation (20 contracts)
miesc evaluate ablation <corpus_dir> \
  --layers 1,5 \
  --limit 20 \
  --jsonl ablation_stream.jsonl
```

Output includes:
- Per-layer recall, precision, F1
- Combined metrics (all layers together)
- Marginal contribution analysis
- Per-layer average execution time

### Comparing Runs (`miesc evaluate compare`)

Compares two evaluation runs and shows statistical differences:

```bash
miesc evaluate compare run_v5.2.json run_v5.3.json
```

Shows per-metric deltas and per-category recall changes.

## Output Formats

### JSON (full results)

The `--output` flag produces a complete JSON file with:
- `experiment_card`: reproducibility metadata (version, timestamp, layers, timeout, platform)
- `provenance`: the environment that produced the run — tool versions as the binaries
  report them, solc builds per contract, config hash, git SHA (see [Run provenance](#run-provenance))
- `aggregate`: precision, recall, F1, hit_rate, timing
- `per_category`: breakdown by vulnerability category
- `per_contract`: individual contract results with per-layer findings and timing

### JSONL (streaming, ML-friendly)

The `--jsonl` flag streams one JSON object per contract as evaluation progresses:

```jsonl
{"type": "contract_eval", "contract": "reentrancy/dao.sol", "ground_truth": ["reentrancy"], "detected": ["reentrancy"], "missed": [], "hit": true, "timing": {"layer_1": 1.2, "layer_5": 3.4}}
{"type": "contract_eval", "contract": "arithmetic/overflow.sol", ...}
{"type": "summary", "precision": 0.85, "recall": 0.965, "f1": 0.90}
```

Use with standard tools:
```bash
# Count hits
cat results.jsonl | jq 'select(.type=="contract_eval") | .hit' | sort | uniq -c

# Extract timing data for analysis
cat results.jsonl | jq 'select(.type=="contract_eval") | {contract, timing}' > timing.jsonl

# Load in Python/pandas
import pandas as pd
df = pd.read_json("results.jsonl", lines=True)
```

### JSONL Export (from any scan)

Export findings from any MIESC scan as one-finding-per-line JSONL:

```bash
miesc scan contract.sol -o results.json
miesc export results.json -f jsonl -o findings.jsonl
```

Each line contains: `tool`, `severity`, `type`, `title`, `description`, `file`, `line`, `function`, `confidence`, `category`.

## Layer Architecture

MIESC evaluates contracts across 9 independent defense layers:

| Layer | Name | Tools | Use Case |
|-------|------|-------|----------|
| 1 | Static Analysis | slither, aderyn, solhint, wake, semgrep | Pattern-based, fast |
| 2 | Dynamic Testing | echidna, medusa, foundry | Fuzzing, property testing |
| 3 | Symbolic Execution | mythril, halmos, oyente | Path exploration |
| 4 | Formal Verification | certora, smtchecker, scribble | Mathematical proofs |
| 5 | AI Analysis | smartllm, gptscan, gptlens | LLM vulnerability detection |
| 6 | ML Detection | dagnn, smartbugs_ml | ML classifiers |
| 7 | Specialized | threat_model, gas_analyzer, mev_detector | Domain-specific |
| 8 | Cross-Chain & ZK | crosschain, zk_circuit | Bridge/circuit security |
| 9 | AI Ensemble | llmbugscanner, audit_consensus | Multi-LLM consensus |

Select layers with `--layers 1,5,7` to control what runs.

## Timing and Profiling

All audit and evaluation outputs include per-layer timing:

```json
{
  "timing": {
    "per_layer": {"1": 1.234, "5": 4.567, "7": 0.891},
    "total_s": 6.692
  }
}
```

Use this to measure cost-benefit tradeoffs per layer.

## Extending MIESC

### Custom Detector Plugins

Create a detector plugin in `~/.miesc/plugins/` or the project's `plugins/` directory:

```python
# plugins/my_detector.py
from miesc.plugins import DetectorPlugin

class MyDetector(DetectorPlugin):
    name = "my-detector"
    version = "1.0.0"
    description = "Custom vulnerability detector"

    def analyze(self, contract_path: str, **kwargs) -> list:
        """Return list of findings dicts."""
        findings = []
        source = open(contract_path).read()
        # Your detection logic here
        if "delegatecall" in source:
            findings.append({
                "type": "unsafe-delegatecall",
                "severity": "HIGH",
                "title": "Unprotected delegatecall",
                "description": "Contract uses delegatecall without access control",
                "location": {"file": contract_path, "line": 42},
            })
        return findings
```

Register with: `miesc plugins install ./plugins/my_detector.py`

### Custom Adapter

For deeper integration, create an adapter in `miesc/adapters/`:

```python
# miesc/adapters/my_tool_adapter.py
from miesc.core.tool_protocol import ToolAdapter

class MyToolAdapter(ToolAdapter):
    TOOL_NAME = "my-tool"

    def is_available(self) -> bool:
        """Check if the external tool is installed."""
        return shutil.which("my-tool") is not None

    def run(self, contract_path: str, timeout: int = 300) -> dict:
        """Run analysis and return normalized results."""
        # Run your tool
        result = subprocess.run(["my-tool", contract_path], ...)
        # Parse and normalize findings
        return {
            "tool": self.TOOL_NAME,
            "status": "success",
            "findings": self._parse_output(result.stdout),
        }
```

## Reproducibility

### Experiment Cards

Every evaluation run generates an experiment card:

```json
{
  "experiment_card": {
    "tool": "MIESC",
    "version": "5.3.1",
    "timestamp": "2026-04-29T22:45:00",
    "corpus": "/path/to/smartbugs-curated/dataset",
    "corpus_size": 143,
    "layers_evaluated": [1, 5, 7, 9],
    "timeout_per_tool_s": 120,
    "python_version": "3.12.0",
    "platform": "darwin"
  },
  "reproducibility": {
    "command": "miesc evaluate corpus ... --layers 1,5,7,9 --timeout 120",
    "seed": "42",
    "llm_provider": "anthropic",
    "llm_model": "claude-sonnet-4-6"
  }
}
```

### Run provenance

The experiment card says *what* was evaluated; the `provenance` block says *with what*.
It is written into every result JSON of `miesc scan`, `miesc audit quick|full`,
`miesc evaluate corpus|ablation` and the run report of `miesc fix`, so any result can be
cited and re-run. It is built once per run by `miesc.core.provenance`; a version probe
that fails records `"unknown"` and never aborts the run.

```json
{
  "provenance": {
    "schema": 1,
    "command": "evaluate corpus",
    "command_line": "miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 --no-llm -o run.json",
    "argv": ["miesc", "evaluate", "corpus", "...", "--no-llm", "-o", "run.json"],
    "cwd": "/work/MIESC",
    "timestamp": "2026-10-20T21:04:10",
    "miesc": {"version": "6.1.1", "git_sha": "abff8a7b7a49…", "git_dirty": false},
    "python": {"version": "3.12.6", "implementation": "CPython", "executable": "/work/.venv/bin/python"},
    "platform": {"system": "Darwin", "release": "25.4.0", "machine": "arm64"},
    "tools": {
      "slither": "0.11.6",
      "aderyn": "aderyn 0.1.9",
      "solhint": "6.0.1",
      "fouranalyzer": "unknown",
      "smartbugs_detector": "built-in (miesc 6.1.1)"
    },
    "python_packages": {"slither-analyzer": "0.11.6", "scikit-learn": "1.9.1", "solc-select": "1.1.0"},
    "solc": {
      "per_contract": {"…/reentrancy/simple_dao.sol": "0.4.26", "…/arithmetic/overflow.sol": "0.4.25"},
      "binaries": {"0.4.25": "Version: 0.4.25+commit.59dbf8f1…", "0.4.26": "Version: 0.4.26+commit.4563c3fc…"},
      "path_default": "Version: 0.8.10+commit.fc410830…"
    },
    "config": {"path": "/work/MIESC/miesc/data/config/miesc.yaml", "exists": true, "sha256": "c4c40f2a…"},
    "env": {"MIESC_SEED": "42"},
    "llm_free": true
  }
}
```

| Field | Meaning |
|---|---|
| `miesc.git_sha`, `git_dirty` | Commit of the checkout MIESC runs from; `null` for a wheel install. |
| `tools` | One entry per tool that **executed** (status `success`, `error` or `timeout`), with the first version-looking line its binary prints. Adapters that resolve their own executable (Slither's priority paths, Mythril's `.tools` install) are probed through that executable, so the version matches the binary that produced the findings. `built-in (miesc X)` marks detectors shipped with MIESC; `unknown` means the tool has no version flag; `not_installed` means the probe found no executable. Tools that did not run are not listed. |
| `python_packages` | Releases of the Python libraries that move results (`slither-analyzer`, `scikit-learn`, `solc-select`, …), when installed. |
| `solc.per_contract` | The compiler version the Slither adapter selected for each contract's `pragma`; `solc.binaries` is what each selected solc-select artifact reports (`not_installed` when the artifact is missing and Slither fell back). |
| `config` | The configuration file in effect (`MIESC_CONFIG`, `./miesc.yaml`, or the packaged default) and its SHA-256. |
| `env` | `MIESC_SEED`, `MIESC_LLM_PROVIDER`, `MIESC_LLM_MODEL` — only the ones that were set. |
| `llm_free` | `true` when no LLM-backed adapter ran and no `--llm-enhance`/`--model`/`--verify-model` was used; `null` when the command cannot tell (agentic scan profiles). |
| `argv`, `command_line` | The exact command line, as a list and shell-quoted. |

Useful queries:

```bash
jq '.provenance.tools' run.json
jq '.provenance.solc.binaries' run.json
jq -r '.provenance.command_line' run.json
miesc evaluate compare paper_run.json run.json     # "Run Provenance" table, differing rows highlighted
```

Artifacts written before this block existed (the Paper 1 files) show
`n/a (pre-provenance artifact)` in `evaluate compare`; their versions are the hand-written
ones in [REPRODUCE.md](../../REPRODUCE.md).

### Environment Variables

Control reproducibility with environment variables:

```bash
export MIESC_SEED=42                    # Random seed for reproducibility
export MIESC_LLM_PROVIDER=anthropic     # LLM provider (anthropic, openai, ollama)
export MIESC_LLM_MODEL=claude-sonnet-4-6  # Specific model
export ANTHROPIC_API_KEY=sk-...         # API key for frontier models
export OPENAI_API_KEY=sk-...            # OpenAI API key
export OLLAMA_HOST=http://localhost:11434  # Local Ollama endpoint
```

### Docker for Exact Reproducibility

```bash
# Pin to exact version for reproducible results
docker run --rm -v $(pwd)/corpus:/corpus \
  ghcr.io/fboiero/miesc:5.3.1 \
  evaluate corpus /corpus --layers 1,5,7 -o /corpus/results.json
```

## Benchmark Datasets

### Included

- **SmartBugs-curated**: 143 contracts, 10 categories (`benchmarks/datasets/smartbugs-curated/`)
- **Solidifi**: Additional benchmark contracts (`benchmarks/datasets/solidifi-benchmark/`)

### Adding Custom Corpora

Any directory following the `category_name/*.sol` structure works:

```bash
my_corpus/
├── oracle_manipulation/
│   ├── compound_oracle.sol
│   └── chainlink_stale.sol
├── flash_loan/
│   └── euler_attack.sol
└── governance/
    └── vote_manipulation.sol
```

Run: `miesc evaluate corpus my_corpus/ --layers 1,5,7,9`

## Citing MIESC

If you use MIESC in your research, please cite:

```bibtex
@article{boiero2025miesc,
  title={{MIESC}: Multi-layer Intelligent Evaluation for Smart Contracts},
  author={Boiero, Fernando},
  journal={arXiv preprint},
  year={2025}
}
```

## API Reference

### Finding Schema

Every finding follows this structure:

```python
{
    "type": str,           # Vulnerability type (e.g., "reentrancy-eth")
    "severity": str,       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "title": str,          # Human-readable title
    "description": str,    # Detailed explanation
    "location": {
        "file": str,       # File path
        "line": int,       # Line number
        "function": str,   # Function name (if available)
    },
    "tool": str,           # Source tool name
    "confidence": float,   # 0.0 - 1.0 (after intelligence engine)
    "canonical_category": str,  # Normalized category
    "fp_suppressed": bool,      # False positive flag
}
```

### Intelligence Engine

The intelligence engine (`miesc/core/intelligence.py`) provides:

1. **Cross-tool confidence scoring** — Bayesian posterior from per-tool weights
2. **Semantic deduplication** — Groups findings by category + function ±15 lines
3. **Zero-recall pattern detection** — 25+ patterns for categories static tools miss
4. **Context-aware FP suppression** — Removes findings when mitigations are present
5. **Severity calibration** — Normalizes severity across tools

Access programmatically:

```python
from miesc.core.intelligence import enhance_findings

enhanced = enhance_findings(
    findings_list,
    source_code=contract_source,
    file_path="contract.sol"
)
```
