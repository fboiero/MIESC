"""Process-wide wall-clock budget for LLM-backed adapters (``--llm-timeout``).

Static analyzers finish in seconds; an LLM adapter can take minutes per
contract. ``--llm-timeout`` lets a run cap only the adapters whose metadata
declares ``requires_llm`` while every other tool keeps its own timeout. The
state lives here (not in the CLI package) so the ML orchestrator and the CLI
tool runner apply the same budget.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from typing import Any, Optional

_BUDGET_S: Optional[int] = None


def set_llm_timeout(seconds: Optional[int]) -> None:
    """Set the budget in seconds; ``None`` or ``0`` clears it."""
    global _BUDGET_S
    _BUDGET_S = int(seconds) if seconds else None


def get_llm_timeout() -> Optional[int]:
    """Current budget in seconds, or ``None`` when none is set."""
    return _BUDGET_S


def adapter_requires_llm(adapter: Any) -> bool:
    """True when the adapter's metadata declares ``requires_llm``."""
    get_metadata = getattr(adapter, "get_metadata", None)
    if get_metadata is None:
        return False
    try:
        return bool(getattr(get_metadata(), "requires_llm", False))
    except Exception:  # noqa: BLE001 - metadata must never break a run
        return False


def budget_for(adapter: Any, timeout: int) -> int:
    """The timeout to hand to ``adapter``: the LLM budget when one is set and
    the adapter is LLM-backed, otherwise ``timeout`` unchanged."""
    if _BUDGET_S and adapter_requires_llm(adapter):
        return _BUDGET_S
    return timeout
