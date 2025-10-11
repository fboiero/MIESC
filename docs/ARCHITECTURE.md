# Xaudit Architecture

## Overview

Xaudit is designed as a modular smart contract auditing framework that combines traditional static analysis tools with AI-powered vulnerability detection.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py                               │
│                  (Orchestration Layer)                       │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Static Tools  │    │  AI Models    │    │   Report      │
│               │    │               │    │  Generator    │
├───────────────┤    ├───────────────┤    ├───────────────┤
│ • Slither     │    │ • GPTLens     │    │ • PDF Gen     │
│ • Mythril     │    │ • GPT-4       │    │ • Text Gen    │
│               │    │ • Llama 2     │    │ • Markdown    │
└───────────────┘    └───────────────┘    └───────────────┘
```

## Core Components

### 1. Main Orchestrator (`main.py`)

The entry point that coordinates all audit tools and generates final reports.

**Key Responsibilities:**
- Parse command-line arguments
- Load configuration from `config.py`
- Execute enabled audit tools
- Aggregate results
- Generate consolidated reports

### 2. Static Analysis Tools

#### Slither (`src/slither_tool.py`)
- **Purpose**: Fast static analysis for common vulnerabilities
- **Technology**: Pattern matching and data flow analysis
- **Strengths**: Speed, comprehensive coverage of common issues
- **Output**: Detailed vulnerability list with severity ratings

#### Mythril (`src/mythril_tool.py`)
- **Purpose**: Symbolic execution and deep security analysis
- **Technology**: Symbolic execution, SMT solving
- **Strengths**: Detection of complex logical vulnerabilities
- **Output**: Detailed exploit scenarios

### 3. AI-Powered Analysis

#### GPTLens (`src/GPTLens_tool.py`)
- **Purpose**: Two-stage AI analysis (Auditor → Critic)
- **Technology**: OpenAI GPT models with specialized prompts
- **Process**:
  1. **Auditor**: Identifies potential vulnerabilities
  2. **Critic**: Validates and scores findings
  3. **Ranker**: Prioritizes by severity and probability
- **Output**: Ranked vulnerability list with confidence scores

#### Raw GPT (`src/rawchatGPT_tool.py`)
- **Purpose**: Direct GPT-4 analysis
- **Use Case**: Quick assessment and code review
- **Output**: Natural language vulnerability description

#### Llama 2 (`src/Llama2_tool.py`)
- **Purpose**: Local LLM alternative (privacy-preserving)
- **Technology**: Meta's Llama 2 with RAG
- **Requirements**: GPU with sufficient VRAM
- **Output**: Similar to GPT but runs locally

### 4. Report Generation

#### Audit Generator (`src/audit_generator.py`)
- Consolidates all tool outputs
- Generates PDF reports with multiple sections:
  - Introduction
  - Tool outputs
  - Summary
  - Unit test suggestions
  - Conclusions

#### Text Generator (`src/text_generator.py`)
- Creates natural language summaries
- Generates test case suggestions
- Produces conclusions based on findings

## Data Flow

```
Contract File (.sol)
        │
        ├──> Slither Analysis ──┐
        │                        │
        ├──> Mythril Analysis ──┤
        │                        ├──> Aggregate Results
        ├──> GPTLens Analysis ──┤
        │                        │
        └──> GPT/Llama Analysis ─┘
                                 │
                                 ▼
                         Report Generator
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
               PDF Report              Text Outputs
```

## Configuration System

The `config.py` file uses a class-based configuration:

```python
class ModelConfig:
    # Enable/disable tools
    use_slither = True
    use_mythril = True
    use_rawGPT = False
    use_GPTLens = True
    use_rawLlama = False

    # Report sections
    include_introduction = True
    include_tools_output = True
    include_summary = True
    include_unitary_test = False
    include_conclusion = True
```

## Extension Points

### Adding New Analysis Tools

1. Create a new file in `src/` (e.g., `new_tool.py`)
2. Implement `audit_contract(contract_path, version)` function
3. Add configuration flag in `config.py`
4. Import and call in `main.py`

Example:
```python
# src/new_tool.py
def audit_contract(contract_path, version):
    # Your analysis logic
    return analysis_output

# config.py
class ModelConfig:
    use_new_tool = True

# main.py
if model_config.use_new_tool:
    audit_information['NewTool'] = new_tool_audit_contract(path_to_file, solidity_version)
```

### Adding Custom Report Sections

Modify `src/audit_generator.py` to include new sections in the PDF generation logic.

## Dependencies

### Core Dependencies
- `openai`: GPT API integration
- `solc-select`: Solidity version management
- `slither-analyzer`: Static analysis
- `mythril`: Symbolic execution (optional)
- `fpdf2`: PDF generation
- `markdown`: Report formatting

### AI/ML Dependencies (Optional)
- `torch`: PyTorch for local LLMs
- `transformers`: Hugging Face models
- `langchain`: LLM orchestration
- `chromadb`: Vector database for RAG

## Performance Considerations

- **Slither**: Fast (~seconds)
- **Mythril**: Slow (~minutes), use timeout
- **GPT API**: Rate-limited, costs per request
- **Local LLMs**: Requires GPU, high memory usage

## Security Considerations

- API keys stored in `.env` file (not committed)
- Supports local LLM deployment for sensitive contracts
- No data persistence beyond audit reports
- Contracts analyzed locally

## Future Architecture Plans

1. **Plugin System**: Dynamic tool loading
2. **REST API**: Web service interface
3. **Database**: Persistent audit history
4. **CI/CD Integration**: GitHub Actions support
5. **Multi-chain Support**: Beyond Ethereum
