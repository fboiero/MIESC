# ADR 0004: Dual Package Structure (src/ and miesc/)

## Status

Accepted

## Date

2026-02-08

## Context

MIESC evolved from a research project to a production-ready tool. The original code lived in `src/`, but we needed a proper Python package structure for PyPI distribution and easier imports.

We faced several challenges:
1. **Import complexity**: Users had to use `from src.adapters import ...` which is non-standard
2. **Lazy loading**: The full codebase has 50+ adapters, loading all at startup would be slow
3. **Backwards compatibility**: Existing scripts and documentation referenced `src/`
4. **Entry points**: CLI and MCP server needed clean entry points

## Decision

We maintain a **dual package structure**:

```
MIESC/
├── miesc/           # Public API package (installed via pip)
│   ├── __init__.py  # Version, lazy imports
│   ├── cli/         # CLI commands
│   ├── core/        # Core abstractions (re-exports from src)
│   ├── adapters/    # Adapter registry (re-exports from src)
│   └── mcp/         # MCP server
│
└── src/             # Implementation package
    ├── adapters/    # All 50+ tool adapters
    ├── agents/      # Analysis agents
    ├── llm/         # LLM integration
    ├── ml/          # ML models
    └── core/        # Core framework
```

### Key Design Decisions

1. **`miesc/` is the public API**: Users install and import from `miesc`
2. **`src/` contains implementations**: Internal code, not intended for direct import
3. **Lazy imports**: `miesc/__init__.py` uses `__getattr__` for lazy loading
4. **Re-exports**: `miesc/core/` re-exports from `src/core/` for backwards compat
5. **Both packages installed**: `pyproject.toml` includes both in `packages`

## Consequences

### Positive

- **Faster startup**: Lazy imports reduce CLI startup time from ~3s to ~0.5s
- **Clean API**: Users import from `miesc`, not `src`
- **Backwards compat**: Old scripts using `src.` still work
- **Smaller surface area**: Public API is smaller than full implementation

### Negative

- **Complexity**: Two packages to maintain
- **Import confusion**: Contributors may not know which to use
- **Path manipulation**: Some modules need `sys.path.insert`

### Neutral

- **Documentation overhead**: Must document both for different audiences

## Migration Path (Future v6.0)

In v6.0, we may consolidate to a single `miesc/` package:

1. Move all `src/` code into `miesc/`
2. Add deprecation warnings for `src.` imports
3. Maintain `src/` as symlinks for one major version
4. Remove `src/` in v7.0

## Related

- ADR-0001: Adapter Pattern for Tool Integration
- ADR-0003: Optional Tools for DPGA Compliance
