"""Compatibility tests for the public miesc.llm package facade."""

import builtins
import importlib
import sys

import miesc.llm as public_llm
import miesc.llm as source_llm

AGENTIC_EXPORTS = [
    "AgentCapability",
    "CounterexampleEvidence",
    "DPGAgentConfig",
    "InvariantCandidate",
    "InvariantCategory",
    "InvariantExtractionAgent",
    "LLMOrchestratorReasoningProvider",
    "LocalHeuristicReasoningProvider",
    "ReasoningProvider",
    "ReasoningProviderRoute",
    "ReasoningResult",
    "ReasoningTask",
    "auto_reasoning_provider",
    "parse_invariant_candidates",
]


def test_miesc_llm_reexports_agentic_contracts():
    for name in AGENTIC_EXPORTS:
        assert getattr(public_llm, name) is getattr(source_llm, name)
        assert name in public_llm.__all__


def test_miesc_llm_agentic_parser_is_usable():
    candidates = public_llm.parse_invariant_candidates(
        {
            "invariants": [
                {
                    "statement": "totalAssets must cover issued shares",
                    "category": "accounting",
                    "confidence": 0.9,
                }
            ]
        }
    )

    assert len(candidates) == 1
    assert candidates[0].category is public_llm.InvariantCategory.ACCOUNTING
    assert candidates[0].confidence == 0.9


# Removed: test_miesc_llm_agentic_exports_degrade_to_none_on_src_import_error.
# It asserted the FAÇADE gracefully degraded agentic exports to None when the
# src.llm import failed. After unifying src.llm into miesc.llm, agentic_contracts
# is a hard (required) import, not an optional-degradation path — so the behavior
# no longer exists. The test also polluted sys.modules and broke sibling tests.
