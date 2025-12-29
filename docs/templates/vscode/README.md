# VS Code Integration for MIESC

This folder contains VS Code configuration templates for integrating MIESC into your Solidity development workflow.

## Quick Setup

Copy these files to your project's `.vscode` folder:

```bash
cp -r docs/templates/vscode/* .vscode/
```

## Files Included

- **settings.json** - Workspace settings for Python, Solidity, and MIESC integration
- **tasks.json** - Build tasks for running MIESC audits from VS Code
- **extensions.json** - Recommended VS Code extensions

## Available Tasks

After copying the configuration, you can use these tasks (Ctrl+Shift+B or Cmd+Shift+B):

| Task | Description |
|------|-------------|
| MIESC: Quick Audit | Run quick analysis on current file |
| MIESC: Full Audit | Complete 7-layer audit with SARIF output |
| MIESC: Batch Audit | Analyze all .sol files in workspace |
| MIESC: Watch Mode | Continuous monitoring for changes |
| MIESC: CI Check | Fail on critical/high severity findings |

## SARIF Integration

The tasks generate SARIF files that can be viewed with the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer).

This provides inline diagnostics in VS Code showing vulnerabilities directly in your code.

## Requirements

- MIESC installed (`pip install miesc`)
- Python 3.12+
- Recommended: Solidity extension for syntax highlighting
