# Privacy Policy

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**
**Last updated:** 2026-03-31

## Overview

MIESC is a smart contract security analysis framework that runs **entirely on your local machine** or your own infrastructure. Privacy by design is a core principle of this project.

## Data Collection

### What MIESC processes

MIESC analyzes **smart contract source code** (Solidity, Vyper, Rust, Move, etc.) for security vulnerabilities. The source code analyzed is:

- Provided by the user explicitly (file paths, uploaded files, or pasted code)
- Processed locally on the user's machine or self-hosted infrastructure
- Never transmitted to external servers by MIESC itself

### What MIESC does NOT collect

- No personal data (names, emails, IP addresses)
- No telemetry or usage analytics
- No crash reports sent externally
- No tracking cookies or identifiers
- No smart contract source code sent to third parties

## Data Flow

### Local execution (default)

```
User's contract files --> MIESC CLI --> Local analysis --> Local report output
```

All processing happens locally. No network calls are made except when explicitly requested by the user (e.g., installing dependencies).

### LLM integration (optional, user-initiated)

When the user **explicitly enables** LLM interpretation (`--llm-interpret` flag):

- **Ollama (local):** All LLM processing happens on the user's machine. No data leaves the local network.
- **Remote LLM providers (OpenAI, Anthropic):** If the user configures a remote LLM provider, code snippets from findings may be sent to that provider's API. This is:
  - Only triggered by explicit user action
  - Governed by the remote provider's privacy policy
  - Configurable and optional

Users who handle sensitive or proprietary code should use **Ollama** for fully local LLM processing.

### Docker execution

When running MIESC in Docker containers, all analysis happens within the container. Volume mounts are used to access contract files, and results are written to mounted volumes. No data is exfiltrated from the container.

### CI/CD integration (GitHub Action)

When using the MIESC GitHub Action:

- Analysis runs within the GitHub Actions runner
- Results are stored as GitHub Actions artifacts (governed by GitHub's policies)
- SARIF reports may be uploaded to GitHub's Security tab (governed by GitHub's policies)
- No data is sent to MIESC servers or infrastructure

## Data Retention

MIESC does not retain any user data. All analysis results are:

- Written to user-specified output files
- Stored locally or in the user's CI/CD environment
- Under the user's full control for retention and deletion

## Third-party Dependencies

MIESC integrates with third-party security tools (Slither, Mythril, Echidna, etc.). Each tool has its own privacy practices. MIESC:

- Invokes these tools as local subprocesses
- Does not add network capabilities to any tool
- Does not intercept or modify tool communications

## Web Interface

The optional Streamlit web interface (`make webapp`) runs locally on `localhost:8501`. It does not expose any external endpoints unless explicitly configured by the user.

## Compliance

MIESC's architecture supports compliance with:

- **GDPR** (EU General Data Protection Regulation): No personal data processing
- **CCPA** (California Consumer Privacy Act): No consumer data collection
- **LGPD** (Brazil's General Data Protection Law): No personal data processing

## Contact

For privacy-related questions or concerns:

- **Maintainer:** Fernando Boiero
- **Email:** fboiero@frvm.utn.edu.ar
- **Issue tracker:** [GitHub Issues](https://github.com/fboiero/MIESC/issues)

## Changes to this Policy

Changes to this privacy policy will be documented in the project's CHANGELOG and committed to the repository with a clear commit message.
