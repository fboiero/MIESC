# ADR-0003: Optional Tools for DPGA Compliance

## Status

Accepted

## Context

MIESC aims to be recognized as a Digital Public Good (DPG) by the DPGA. One key requirement is avoiding vendor lock-in:

> "The project does not create vendor lock-in by requiring specific proprietary services, software, or infrastructure"

Our tool ecosystem includes:
- Open source tools (Slither, Mythril, Echidna)
- Commercial tools (Certora requires license)
- Cloud-dependent tools (some LLM integrations)

We needed to ensure MIESC works without any specific tool being mandatory.

## Decision

Mark **all tools as optional** with `is_optional=True` in their metadata:

```python
@dataclass
class ToolMetadata:
    # ...
    is_optional: bool = True  # Default: all tools are optional
```

Enforce this at registration time:

```python
# In register_all_adapters()
non_optional = [a for a in registered if not a.get("optional", True)]
if non_optional:
    logger.warning(f"DPGA WARNING: Non-optional tools detected: {non_optional}")
```

MIESC core functionality works with **zero** external tools:
- Basic parsing and analysis work standalone
- Each tool adds capabilities but isn't required
- Graceful degradation when tools unavailable

## Consequences

### Positive

- **DPGA compliance**: No vendor lock-in
- **Accessibility**: Works in restricted environments
- **Resilience**: Tool failures don't break the system
- **Freedom**: Users choose which tools to install

### Negative

- **Reduced capability**: Without tools, analysis is limited
- **User confusion**: May not understand why results are sparse
- **Testing burden**: Must test with various tool combinations

### Neutral

- Need clear documentation about which tools provide which capabilities
- Need graceful UI messaging when tools are unavailable

## References

- [DPGA Standard](https://digitalpublicgoods.net/standard/)
- [DPGA Indicator: No Vendor Lock-in](https://digitalpublicgoods.net/standard/#9c)
- [src/core/tool_protocol.py](../../src/core/tool_protocol.py)
