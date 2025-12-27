# MIESC Tool Reference

Complete list of 32 security tools integrated across 9 defense layers.

## Layer 1: Static Analysis

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| [Slither](https://github.com/crytic/slither) | 0.10.x | AGPL-3.0 | 90+ vulnerability detectors |
| [Aderyn](https://github.com/Cyfrin/aderyn) | 0.6.x | MIT | Rust-based AST analyzer |
| [Solhint](https://github.com/protofire/solhint) | 5.0.x | MIT | Linter with 200+ rules |

## Layer 2: Dynamic Testing

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| [Echidna](https://github.com/crytic/echidna) | 2.2.x | AGPL-3.0 | Property-based fuzzer |
| [Medusa](https://github.com/crytic/medusa) | 0.1.x | AGPL-3.0 | Coverage-guided fuzzer |
| [Foundry](https://github.com/foundry-rs/foundry) | nightly | MIT | Testing toolkit |
| [DogeFuzz](https://github.com/) | - | Research | AFL-style fuzzing |

## Layer 3: Symbolic Execution

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| [Mythril](https://github.com/ConsenSys/mythril) | 0.24.x | MIT | Symbolic execution |
| [Manticore](https://github.com/trailofbits/manticore) | 0.3.x | AGPL-3.0 | Multi-platform symbolic |
| [Halmos](https://github.com/a16z/halmos) | 0.2.x | AGPL-3.0 | Foundry integration |

## Layer 4: Formal Verification

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| [Certora](https://www.certora.com/) | 2024.11 | Commercial | CVL-based verifier |
| [SMTChecker](https://docs.soliditylang.org/) | 0.8.20+ | GPL-3.0 | Built-in Solidity |
| [Wake](https://github.com/Ackee-Blockchain/wake) | 4.x | ISC | Python framework |
| PropertyGPT | - | AGPL-3.0 | Automated CVL generation |

## Layer 5: AI Analysis

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| SmartLLM | - | AGPL-3.0 | Local LLM via Ollama |
| GPTScan | - | Research | GPT-4 semantic analysis |
| LLM-SmartAudit | - | AGPL-3.0 | Multi-agent framework |

## Layer 6: ML Detection

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| DA-GNN | - | Research | Graph Neural Networks |
| SmartBugs ML | - | Research | ML classifiers |

## Layer 7: Threat Modeling

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| ThreatModelAdapter | - | AGPL-3.0 | Attack surface analysis |
| MEV Detector | - | AGPL-3.0 | MEV vulnerability detection |
| Gas Analyzer | - | AGPL-3.0 | Gas optimization issues |

## Layer 8: Cross-Chain & ZK Security

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| CrossChainAdapter | - | AGPL-3.0 | Bridge security |
| ZKCircuitAdapter | - | AGPL-3.0 | Circom/Noir analysis |

## Layer 9: Advanced AI Ensemble

| Tool | Version | License | Focus |
|------|---------|---------|-------|
| LLMBugScanner | - | AGPL-3.0 | Multi-LLM consensus |

## Installation

### Required (minimum)
```bash
pip install slither-analyzer
```

### Recommended
```bash
pip install slither-analyzer mythril
cargo install aderyn
npm install -g solhint
```

### Full suite
```bash
# Use Docker for complete environment
docker pull ghcr.io/fboiero/miesc:latest
```

## Custom Tool Integration

Implement the `ToolAdapter` interface:

```python
from src.core.tool_protocol import ToolAdapter, ToolStatus

class MyToolAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "mytool"

    @property
    def layer(self) -> int:
        return 1  # Static analysis

    def analyze(self, contract_path: str) -> dict:
        # Run analysis
        return {"findings": [...]}

    def check_availability(self) -> ToolStatus:
        # Check if tool is installed
        return ToolStatus.AVAILABLE
```

Register in `miesc/api/rest.py`:
```python
ADAPTER_MAP["mytool"] = "MyToolAdapter"
LAYERS[1]["tools"].append("mytool")
```
