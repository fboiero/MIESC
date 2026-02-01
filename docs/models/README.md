# MIESC ML Model Requirements

## Overview

Layer 6 (ML Detection) adapters can optionally use pre-trained machine learning
models for improved accuracy. Without models, adapters fall back to
pattern-based or heuristic detection (reduced accuracy but still functional).

## Model Locations

| Adapter | Model Path | Format | Notes |
|---------|-----------|--------|-------|
| Peculiar | `~/.miesc/models/peculiar/` | PyTorch (.pt) | Heterogeneous Graph Neural Network |
| DA-GNN | Configured via `model_path` | PyTorch (.pt) | Deep Attention GNN on CFG+DFG |
| SmartBugs ML | N/A (scikit-learn) | Rule-based | No external model needed |
| SmartGuard | N/A (LLM-based) | Uses Ollama | Requires running Ollama instance |

## Fallback Behavior

All Layer 6 adapters work without pre-trained models:

- **Peculiar**: Uses 7 regex-based vulnerability detection patterns
- **DA-GNN**: Uses heuristic scoring based on code features (45 dimensions)
- **SmartBugs ML**: Uses rule-based feature extraction with threshold detection
- **SmartGuard**: Uses keyword-based retrieval with Ollama LLM analysis

## Setup Instructions

### Peculiar GNN Model

```bash
mkdir -p ~/.miesc/models/peculiar
# Place pre-trained model files here:
# - model.pt (GNN weights)
# - config.json (model configuration)
```

### DA-GNN Model

The model path is configurable. Default location depends on adapter initialization.
Place the pre-trained PyTorch model at the configured path.

## Environment Variables

- `OLLAMA_HOST`: Ollama API URL (default: `http://localhost:11434`)
- `MIESC_LLM_MODEL`: Default LLM model (default: `deepseek-coder:6.7b`)
