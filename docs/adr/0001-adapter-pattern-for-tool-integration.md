# ADR-0001: Adapter Pattern for Tool Integration

## Status

Accepted

## Context

MIESC needs to integrate with 31+ different security analysis tools, each with:
- Different command-line interfaces
- Different output formats (JSON, SARIF, plain text, etc.)
- Different installation methods and dependencies
- Different availability (some tools require licenses, some are open source)

We needed a design that would:
1. Allow adding new tools without modifying core code
2. Normalize outputs to a common format
3. Handle tool unavailability gracefully
4. Avoid vendor lock-in (DPGA requirement)

## Decision

Implement the **Adapter Pattern** with a formal protocol (`ToolAdapter` ABC) that all tool integrations must implement.

```python
class ToolAdapter(ABC):
    @abstractmethod
    def get_metadata(self) -> ToolMetadata: ...

    @abstractmethod
    def is_available(self) -> ToolStatus: ...

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]: ...

    @abstractmethod
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]: ...
```

Each adapter:
- Encapsulates tool-specific logic
- Normalizes output to MIESC's standard finding format
- Reports its own availability status
- Provides metadata for the registry

## Consequences

### Positive

- **Extensibility**: New tools can be added by creating a single adapter file
- **Testability**: Each adapter can be unit tested in isolation
- **Loose coupling**: Core code doesn't depend on specific tools
- **Graceful degradation**: Unavailable tools don't break the system
- **DPGA compliance**: All tools marked as optional, no vendor lock-in

### Negative

- **Boilerplate**: Each new tool requires implementing 4 abstract methods
- **Maintenance**: 31 adapters to maintain and update
- **Complexity**: Indirection layer adds some complexity

### Neutral

- Learning curve for contributors wanting to add tools
- Need to document the adapter protocol clearly

## References

- [Adapter Pattern - Refactoring Guru](https://refactoring.guru/design-patterns/adapter)
- [src/core/tool_protocol.py](../../src/core/tool_protocol.py)
- [src/adapters/](../../src/adapters/)
