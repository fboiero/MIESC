# MIESC Architecture

This document describes the architecture of MIESC and the relationship between its packages.

---

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Input
        A[Contract.sol] --> B[CLI / API]
    end

    subgraph Core["MIESC Core"]
        B --> C[Orchestrator]
        C --> D[Layer Manager]
        D --> E[Tool Adapters]
    end

    subgraph Layers["9 Defense Layers"]
        E --> L1[Layer 1: Static]
        E --> L2[Layer 2: Dynamic]
        E --> L3[Layer 3: Symbolic]
        E --> L4[Layer 4: Formal]
        E --> L5[Layer 5: Property]
        E --> L6[Layer 6: AI/LLM]
        E --> L7[Layer 7: ML]
        E --> L8[Layer 8: DeFi]
        E --> L9[Layer 9: Advanced]
    end

    subgraph Processing
        L1 & L2 & L3 & L4 & L5 & L6 & L7 & L8 & L9 --> F[Finding Aggregator]
        F --> G[ML Pipeline]
        G --> H[RAG Context]
        H --> I[FP Filter]
    end

    subgraph Output
        I --> J[Report Generator]
        J --> K[JSON / PDF / SARIF]
    end

    style Core fill:#e1f5fe
    style Layers fill:#fff3e0
    style Processing fill:#f3e5f5
```

---

## Package Structure Overview

MIESC uses a dual-package structure to maintain backward compatibility while providing a clean public API:

```
MIESC/
├── miesc/                  # Public API package (installed via pip)
│   ├── __init__.py        # Version and top-level exports
│   ├── cli/               # Command-line interface
│   │   ├── main.py        # CLI entry point
│   │   └── commands/      # 15 command modules
│   ├── api/               # Python API
│   ├── detectors/         # Custom detector API
│   ├── core/              # Core abstractions
│   └── mcp/               # MCP protocol support
│
├── src/                    # Internal implementation
│   ├── adapters/          # 50 tool adapters
│   ├── agents/            # Analysis agents
│   ├── core/              # Core framework
│   ├── detectors/         # Built-in detectors
│   ├── llm/               # LLM integration
│   ├── ml/                # ML pipeline
│   ├── mcp_core/          # MCP implementation
│   └── reports/           # Report generation
│
└── config/                 # Configuration files
    └── miesc.yaml         # Central configuration
```

---

## Package Relationships

### miesc/ - Public API

The `miesc/` package is the **public API** that users import:

```python
# User-facing imports
from miesc.api import run_tool, run_full_audit
from miesc.detectors import BaseDetector, Finding, Severity
```

This package:
- Provides stable, documented APIs
- Re-exports from `src/` for backward compatibility
- Is installed when users run `pip install miesc`

### src/ - Internal Implementation

The `src/` package contains the **internal implementation**:

- Tool adapters (`src/adapters/`)
- Core framework (`src/core/`)
- Analysis agents (`src/agents/`)
- Report generation (`src/reports/`)

This package:
- Contains the actual implementation code
- May change between versions without notice
- Should not be imported directly by external users

### Relationship Diagram

```mermaid
flowchart TB
    subgraph UserCode["User Code"]
        UC[Application / Script]
    end

    subgraph PublicAPI["miesc/ (Public API)"]
        CLI[cli/]
        API[api/]
        DET[detectors/]
        CORE[core/]
    end

    subgraph Internal["src/ (Internal Implementation)"]
        ADAP[adapters/]
        AGEN[agents/]
        ICORE[core/]
        ML[ml/]
        LLM[llm/]
        REP[reports/]
    end

    UC --> CLI
    UC --> API
    UC --> DET

    CLI --> ADAP
    CLI --> AGEN
    API --> ICORE
    DET --> ADAP
    CORE --> ICORE
    CORE --> ML

    ADAP --> LLM
    AGEN --> LLM
    ML --> LLM
    ICORE --> REP

    style PublicAPI fill:#e3f2fd
    style Internal fill:#fce4ec
```

**ASCII Fallback:**

```
┌─────────────────────────────────────────────────────────────┐
│                      User Code                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   miesc/ (Public API)                       │
│  ┌─────────┐  ┌─────────┐  ┌───────────┐  ┌─────────────┐  │
│  │   cli   │  │   api   │  │ detectors │  │    core     │  │
│  └────┬────┘  └────┬────┘  └─────┬─────┘  └──────┬──────┘  │
└───────┼────────────┼─────────────┼───────────────┼──────────┘
        │            │             │               │
        ▼            ▼             ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                src/ (Internal Implementation)               │
│  ┌──────────┐  ┌────────┐  ┌────────┐  ┌────────┐          │
│  │ adapters │  │ agents │  │  core  │  │   ml   │   ...    │
│  └──────────┘  └────────┘  └────────┘  └────────┘          │
└─────────────────────────────────────────────────────────────┘
```

---

## 9-Layer Defense Architecture

MIESC implements a 9-layer security analysis architecture:

```mermaid
graph LR
    subgraph Layer1["Layer 1: Static Analysis"]
        S1[Slither]
        S2[Aderyn]
        S3[Solhint]
    end

    subgraph Layer2["Layer 2: Dynamic Testing"]
        D1[Echidna]
        D2[Foundry]
        D3[Medusa]
    end

    subgraph Layer3["Layer 3: Symbolic Execution"]
        SY1[Mythril]
        SY2[Halmos]
    end

    subgraph Layer4["Layer 4: Formal Verification"]
        F1[Certora]
        F2[SMTChecker]
    end

    subgraph Layer5["Layer 5: Property Testing"]
        P1[PropertyGPT]
        P2[Wake]
        P3[Vertigo]
    end

    subgraph Layer6["Layer 6: AI/LLM Analysis"]
        A1[SmartLLM]
        A2[GPTScan]
        A3[LLMSmartAudit]
    end

    subgraph Layer7["Layer 7: Pattern Recognition"]
        M1[DA-GNN]
        M2[SmartGuard]
        M3[Clone Detector]
    end

    subgraph Layer8["Layer 8: DeFi Security"]
        DF1[DeFi Analyzer]
        DF2[MEV Detector]
        DF3[Gas Analyzer]
    end

    subgraph Layer9["Layer 9: Advanced Detection"]
        AD1[Threat Model]
        AD2[SmartBugs]
        AD3[Ensemble]
    end

    Contract[Contract.sol] --> Layer1
    Layer1 --> Layer2
    Layer2 --> Layer3
    Layer3 --> Layer4
    Layer4 --> Layer5
    Layer5 --> Layer6
    Layer6 --> Layer7
    Layer7 --> Layer8
    Layer8 --> Layer9
    Layer9 --> Results[Aggregated Findings]

    style Layer1 fill:#c8e6c9
    style Layer2 fill:#bbdefb
    style Layer3 fill:#d1c4e9
    style Layer4 fill:#ffe0b2
    style Layer5 fill:#f8bbd9
    style Layer6 fill:#b2ebf2
    style Layer7 fill:#dcedc8
    style Layer8 fill:#ffccbc
    style Layer9 fill:#cfd8dc
```

| Layer | Name | Tools | Purpose |
|-------|------|-------|---------|
| 1 | Static Analysis | Slither, Aderyn, Solhint | Code patterns, linting |
| 2 | Dynamic Testing | Echidna, Foundry, Medusa | Fuzzing, property testing |
| 3 | Symbolic Execution | Mythril, Halmos | Path exploration |
| 4 | Formal Verification | Certora, SMTChecker | Mathematical proofs |
| 5 | Property Testing | PropertyGPT, Wake, Vertigo | Mutation testing |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan | LLM-based detection |
| 7 | Pattern Recognition | DA-GNN, SmartGuard | ML-based patterns |
| 8 | DeFi Security | MEV Detector, DeFi Analyzer | Protocol-specific |
| 9 | Advanced Detection | Threat Model, SmartBugs | Ensemble analysis |

---

## Plugin System

### Creating Custom Detectors

Users can create custom detectors by extending `BaseDetector`:

```python
from miesc.detectors import BaseDetector, Finding, Severity, Location

class MyDetector(BaseDetector):
    name = "my-detector"
    description = "Detects my custom pattern"
    category = "custom"

    def analyze(self, source_code: str, file_path: str = None) -> list[Finding]:
        findings = []
        if "dangerous_pattern" in source_code:
            findings.append(Finding(
                detector=self.name,
                title="Dangerous Pattern Found",
                description="The code contains a dangerous pattern",
                severity=Severity.HIGH,
                location=Location(file=file_path or "", line=1),
                recommendation="Remove the dangerous pattern"
            ))
        return findings
```

### Registering Detectors

Register via entry points in `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
my-detector = "my_package.detectors:MyDetector"
```

Or programmatically:

```python
from miesc.detectors import register_detector
register_detector(MyDetector)
```

### Plugin Discovery

MIESC discovers plugins from:
1. Entry points (`miesc.detectors` namespace)
2. Local plugins directory (`~/.miesc/plugins/`)
3. Project plugins (`./miesc_plugins/`)

---

## CLI Architecture

The CLI is built with Click and organized into command modules:

```
miesc/cli/
├── main.py              # CLI entry point (126 lines)
└── commands/            # 15 command modules
    ├── scan.py          # miesc scan
    ├── audit.py         # miesc audit
    ├── report.py        # miesc report
    ├── export.py        # miesc export
    ├── doctor.py        # miesc doctor
    ├── version.py       # miesc version
    ├── config.py        # miesc config
    ├── server.py        # miesc server
    ├── benchmark.py     # miesc benchmark
    ├── watch.py         # miesc watch
    ├── detectors.py     # miesc detectors
    ├── plugins.py       # miesc plugins
    ├── mcp.py           # miesc mcp
    ├── init.py          # miesc init
    └── web.py           # miesc web
```

---

## Data Flow

### Audit Flow

```
Contract.sol
     │
     ▼
┌─────────────────┐
│  CLI/API Call   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Orchestrator   │◄──── Config (miesc.yaml)
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│Layer 1│ │Layer 2│ ... Layer 9
└───┬───┘ └───┬───┘
    │         │
    └────┬────┘
         ▼
┌─────────────────┐
│   ML Pipeline   │◄──── RAG Context
│  (FP Filter)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Report Generator│
└────────┬────────┘
         │
         ▼
    results.json
```

### RAG Integration

```mermaid
flowchart TB
    Q["Query: 'reentrancy vulnerability'"] --> ER[EmbeddingRAG]

    subgraph RAG["RAG System"]
        ER --> EMB[Embedding Model<br/>all-MiniLM-L6-v2]
        EMB --> CACHE{Cache<br/>LRU 256}
        CACHE -->|Hit| CTX[Context]
        CACHE -->|Miss| VDB[(ChromaDB<br/>59 patterns)]
        VDB --> CTX
    end

    CTX --> LLM[LLM / Verificator]
    LLM --> FIND[Enhanced Findings]

    style RAG fill:#e8f5e9
    style CACHE fill:#fff9c4
    style VDB fill:#e3f2fd
```

**Performance:**
- O(1) document lookup with caching
- 5-minute TTL, 256-entry LRU cache
- 50-75% faster verificator stage with batch search

**ASCII Fallback:**

```
Query: "reentrancy vulnerability"
         │
         ▼
┌─────────────────────────┐
│   EmbeddingRAG          │
│   (ChromaDB + MiniLM)   │
└────────────┬────────────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌────────┐     ┌─────────────┐
│ Cache  │     │ Vector DB   │
│ (LRU)  │     │ (59 patterns)│
└───┬────┘     └──────┬──────┘
    │                 │
    └────────┬────────┘
             │
             ▼
    Context for LLM/Verificator
```

---

## Configuration

### Central Configuration

All settings in `config/miesc.yaml`:

```yaml
# General settings
general:
  default_solc_version: "0.8.19"
  timeout: 300
  parallel_tools: 4

# Layer configuration
layers:
  static:
    tools: [slither, aderyn, solhint]
    timeout: 60
  symbolic:
    tools: [mythril, halmos]
    timeout: 300

# LLM settings
llm:
  provider: ollama
  model: mistral:latest
  timeout: 120
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `OLLAMA_HOST` | Ollama server URL |
| `MIESC_CONFIG` | Custom config path |
| `MIESC_CACHE_DIR` | Cache directory |
| `MIESC_LOG_LEVEL` | Logging level |

---

## Contributing to Architecture

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new adapters
- Creating custom detectors
- Extending the CLI
- Adding new layers

---

*Last updated: February 2026*
