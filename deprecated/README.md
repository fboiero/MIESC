# Deprecated Code

This directory contains legacy code that has been superseded by the refactored MIESC v4.1 architecture.

**DO NOT USE** - These files are kept for historical reference only.

## Migration Guide

| Deprecated File | Replacement |
|----------------|-------------|
| `*_tool.py` | `src/adapters/*_adapter.py` |
| `miesc_cli.py` | `miesc/cli/commands.py` |
| `miesc_core.py` | `src/core/optimized_orchestrator.py` |
| `miesc_ai_layer.py` | `src/agents/ai_agent.py` |
| `miesc_mcp_*.py` | `src/mcp/` |
| `orchestrator.py` | `src/core/optimized_orchestrator.py` |
| `project_analyzer.py` | `src/core/result_aggregator.py` |
| `audit_generator.py` | `src/core/persistence.py` |

## Removal Date

These files will be permanently deleted in MIESC v5.0.0.

*Last updated: 2025-12-13*
