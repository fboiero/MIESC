# MIESC Security Auditor - VS Code Extension

<p align="center">
  <img src="media/shield.svg" alt="MIESC Logo" width="128" height="128">
</p>

**Multi-layer Intelligent Evaluation for Smart Contracts**

Visual Studio Code extension for Solidity smart contract security auditing using the MIESC 9-layer defense-in-depth framework with 31 integrated tools.

## Features

### 9-Layer Security Analysis

| Layer | Technique | Tools |
|-------|-----------|-------|
| 1 | Static Analysis | Slither, Aderyn, Solhint |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos |
| 4 | Formal Verification | Certora, SMTChecker |
| 5 | Property Testing | PropertyGPT, Wake, Vertigo |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan, LLMSmartAudit |
| 7 | Pattern Recognition | DA-GNN, SmartGuard, Clone Detector |
| 8 | DeFi Security | DeFi Analyzer, MEV Detector, Gas Analyzer |
| 9 | Advanced Detection | Advanced Detector, SmartBugs, Threat Model |

### Key Features

- **Inline Diagnostics**: Vulnerability warnings directly in the editor
- **Hover Information**: Detailed vulnerability info on hover
- **Quick Fixes**: Code actions for common vulnerability remediation
- **Sidebar Panel**: Findings organized by severity
- **HTML Reports**: Detailed reports with recommendations
- **Auto-audit on Save**: Automatic scanning when saving `.sol` files
- **Real-time Analysis**: Background scanning as you code

## Requirements

- VS Code 1.85.0+
- Python 3.12+
- MIESC installed (`pip install miesc`)
- Analysis tools (Slither required, others optional)

## Installation

### From VSIX

```bash
cd vscode-extension
npm install
npm run compile
npm run package
code --install-extension miesc-security-auditor-0.4.0.vsix
```

### From Source (Development)

```bash
cd vscode-extension
npm install
npm run compile
# Press F5 in VS Code to open Extension Development Host
```

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `miesc.serverUrl` | MIESC REST API server URL | `http://localhost:8000` |
| `miesc.pythonPath` | Python interpreter path | `python3` |
| `miesc.miescPath` | MIESC installation directory | `` |
| `miesc.defaultLayers` | Default layers to run | `[1, 2, 3, 6]` |
| `miesc.autoAuditOnSave` | Auto-scan on save | `false` |
| `miesc.showInlineWarnings` | Show inline warnings | `true` |
| `miesc.severityThreshold` | Minimum severity to display | `medium` |
| `miesc.timeout` | Audit timeout in seconds | `300` |
| `miesc.useLocalLLM` | Use local LLM (Ollama) | `true` |
| `miesc.ollamaModel` | Ollama model for AI analysis | `deepseek-coder:6.7b` |

## Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| `MIESC: Audit Current File` | `Ctrl+Shift+M` / `Cmd+Shift+M` | Audit current file |
| `MIESC: Quick Scan` | `Ctrl+Shift+Q` / `Cmd+Shift+Q` | Quick scan (Layer 1 only) |
| `MIESC: Deep Audit` | - | Full 9-layer audit |
| `MIESC: Audit Workspace` | - | Audit all workspace files |
| `MIESC: Audit Selection` | - | Audit selected code |
| `MIESC: Configure Layers` | - | Configure active layers |
| `MIESC: Show Report` | - | Show last audit report |
| `MIESC: Start Server` | - | Start MIESC server |
| `MIESC: Stop Server` | - | Stop MIESC server |

## Usage

### Quick Start

1. Open a `.sol` file in VS Code
2. Press `Ctrl+Shift+M` (or `Cmd+Shift+M` on Mac)
3. View results in the sidebar and inline diagnostics

### Hover for Details

Hover over any highlighted line to see:
- Vulnerability severity and title
- Detailed description
- SWC ID with link to registry
- Recommended fix
- Detection tool and confidence

### Quick Fixes

Click the lightbulb icon or press `Ctrl+.` to see available fixes:
- Add ReentrancyGuard modifier
- Add return value checks
- Replace tx.origin with msg.sender
- Lock Solidity version
- Add zero address checks
- Mark as reviewed

### Context Menu

Right-click on a `.sol` file:
- In editor: "MIESC: Audit Current File"
- With selection: "MIESC: Audit Selected Code"
- In explorer: "MIESC: Audit Current File"

### Sidebar

The extension adds a "MIESC Security" panel with:
- **Security Findings**: Findings by severity
- **Analysis Layers**: Layer status and tools
- **Audit History**: Previous audit results

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              VS Code Extension                       │
│  ┌────────────────────────────────────────────────┐ │
│  │  Commands → REST Client → MIESC Server         │ │
│  └────────────────────────────────────────────────┘ │
│           ↓                                          │
│  ┌────────────────────────────────────────────────┐ │
│  │   DiagnosticCollection (Inline Warnings)       │ │
│  │   HoverProvider (Vulnerability Details)        │ │
│  │   CodeActionsProvider (Quick Fixes)            │ │
│  │   TreeView (Findings Panel)                    │ │
│  │   WebView (HTML Reports)                       │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                      ↓ HTTP
┌─────────────────────────────────────────────────────┐
│            MIESC REST API Server                     │
│  ┌───┬───┬───┬───┬───┬───┬───┬───┬───┐             │
│  │ L1│ L2│ L3│ L4│ L5│ L6│ L7│ L8│ L9│  9 Layers  │
│  └───┴───┴───┴───┴───┴───┴───┴───┴───┘             │
│              31 Security Tools                       │
└─────────────────────────────────────────────────────┘
```

## Development

### Setup

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC/vscode-extension
npm install
```

### Build

```bash
npm run compile    # Compile TypeScript
npm run watch      # Watch mode
npm run lint       # Linting
npm run test       # Tests
npm run package    # Create VSIX
```

### Debug

1. Open `vscode-extension` folder in VS Code
2. Press `F5` to start Extension Development Host
3. Open a `.sol` file in the new window
4. Test MIESC commands

## Troubleshooting

### "MIESC server not running"

```bash
# Start server manually
miesc server rest --port 8000
```

### "Python not found"

Configure `miesc.pythonPath` with the correct Python interpreter path.

### "Timeout during analysis"

Increase `miesc.timeout` or use Quick Scan for faster analysis.

## License

AGPL-3.0 - See [LICENSE](../LICENSE)

## Author

**Fernando Boiero**
fboiero@frvm.utn.edu.ar
Master's in Cyberdefense - UNDEF

## Links

- [MIESC Repository](https://github.com/fboiero/MIESC)
- [Documentation](https://fboiero.github.io/MIESC)
- [PyPI Package](https://pypi.org/project/miesc/)
- [Issue Tracker](https://github.com/fboiero/MIESC/issues)
