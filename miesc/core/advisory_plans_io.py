"""Shared, provider-neutral I/O for the advisory-plan inventory (Phase 3).

The agentic deep-audit phase (``DeepAuditAgent._extract_advisory_plans``) builds a
deterministic, LLM-free inventory of privileged authority under
``report["phases"]["advisory_plans"]`` — but *only* when ``enable_advisory_plans`` is
set. The agentic audit writer (``miesc.cli.commands.audit._run_agentic_audit_profile``)
hoists that whole block to a stable top-level key in the output JSON, and the premium
report reader (``miesc.cli.commands.report``) reads it back from the same key to render
§4.5 "Trust Model & Privileged Roles".

This module owns the key name and both the write-side and read-side accessors so the
writer and reader cannot drift apart. It never fabricates data: the write side only
copies a block the agent already produced, and the read side only descends it.

The inventory is **advisory**: a static authority graph, never a ``Finding``, never a
"missing timelock" accusation, and never a statement about verified key custody. See
``miesc.llm.privileged_governance_lifecycle``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, cast

# Stable top-level key in the agentic audit output JSON, and the per-miner key inside
# the ``capabilities`` map. Both the writer and the reader import these constants so a
# rename can never silently desynchronise the two sides.
ADVISORY_PLANS_KEY = "advisory_plans"
GOVERNANCE_CAPABILITY_KEY = "privileged_governance"

# Mirrors ``miesc.llm.agentic_contracts.MAX_AGENT_ITEMS`` — the per-list cap the miner
# applies to actors / roles / edges. When a list is exactly this long the inventory may
# have been truncated, which the report must disclose.
MAX_AGENT_ITEMS = 100


def hoist_advisory_plans(result: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the advisory-plan block to persist at the top level, or ``None``.

    ``result`` is the full :meth:`DeepAuditAgent.analyze` return. The advisory-plan
    phase exists under ``result["phases"]["advisory_plans"]`` only when the agent ran
    with ``enable_advisory_plans`` (see ``deep_audit_agent``), so this returns ``None``
    for the default path — the writer then omits the key entirely and the output JSON
    is structurally identical to today (never a ``null`` or empty-dict pollutant).

    The whole block is returned (``enabled``/``count``/``capabilities`` for every miner),
    not just governance, so later phases can surface other plans without re-plumbing.
    """
    if not isinstance(result, Mapping):
        return None
    phases = result.get("phases")
    if not isinstance(phases, Mapping):
        return None
    block = phases.get(ADVISORY_PLANS_KEY)
    if not isinstance(block, Mapping) or not block:
        return None
    return dict(block)


def read_governance_plans(results: Mapping[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Read the privileged-governance plans back from the persisted top-level key.

    Returns:
        * ``None`` when the ``advisory_plans`` key is absent — the inventory was not
          extracted in this engagement (the common default path).
        * ``[]`` when the key is present but no governance plans were produced — static
          extraction ran and identified no privileged actors or roles.
        * a list of plan dicts (each already ``PrivilegedGovernanceLifecyclePlan.to_dict``
          shaped: ``id``, ``objective``, ``authority_graph``, ``promotion``, ``metadata``)
          otherwise.

    The three states are distinct on purpose: "not extracted" and "extraction found
    nothing" are different honest statements and the report renders them differently.
    """
    if not isinstance(results, Mapping):
        return None
    block = results.get(ADVISORY_PLANS_KEY)
    if not isinstance(block, Mapping):
        return None
    capabilities = block.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return []
    governance = capabilities.get(GOVERNANCE_CAPABILITY_KEY)
    if not isinstance(governance, Mapping):
        return []
    plans = governance.get("plans")
    if not isinstance(plans, list):
        return []
    return cast(List[Dict[str, Any]], [p for p in plans if isinstance(p, Mapping)])


__all__ = [
    "ADVISORY_PLANS_KEY",
    "GOVERNANCE_CAPABILITY_KEY",
    "MAX_AGENT_ITEMS",
    "hoist_advisory_plans",
    "read_governance_plans",
]
