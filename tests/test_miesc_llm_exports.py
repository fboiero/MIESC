"""Compatibility tests for the public miesc.llm package facade."""

import builtins
import importlib
import sys

import miesc.llm as public_llm
import src.llm as source_llm

AGENTIC_EXPORTS = [
    "AgentCapability",
    "CounterexampleEvidence",
    "DPGAgentConfig",
    "InvariantCandidate",
    "InvariantCategory",
    "InvariantExtractionAgent",
    "ReasoningProvider",
    "ReasoningResult",
    "ReasoningTask",
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


def test_miesc_llm_agentic_exports_degrade_to_none_on_src_import_error(monkeypatch):
    original_import = builtins.__import__
    original_module = sys.modules.get("miesc.llm")

    def fail_src_llm(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "src.llm":
            raise ImportError("simulated optional dependency failure")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_src_llm)
    sys.modules.pop("miesc.llm", None)
    try:
        degraded = importlib.import_module("miesc.llm")

        for name in AGENTIC_EXPORTS:
            assert getattr(degraded, name) is None
            assert name in degraded.__all__
    finally:
        sys.modules.pop("miesc.llm", None)
        if original_module is not None:
            sys.modules["miesc.llm"] = original_module
