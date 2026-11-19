"""Tests for honest RAG A/B evaluation.

The RAG evaluator toggles ``MIESC_DISABLE_RAG`` between two ``analyze()`` calls on
one adapter instance to measure RAG's impact. For that A/B to measure anything,
three things must hold, and these tests pin each:

1. ``rag_runtime_disabled()`` honours the env var, read per call.
2. Every LLM adapter gates the retrieved context it injects on that runtime
   state — so the "off" arm sends NO retrieved context (not even the keyword
   fallback), and the "on" arm sends it.
3. The adapters' result cache keys encode the effective RAG state, so a
   with-RAG run and a without-RAG run of the same contract do not collide on one
   cached result (which would silently make both arms identical).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _fake_rag_hit(title: str = "Reentrancy via external call") -> SimpleNamespace:
    """A fake EmbeddingRAG search hit with string fields the adapters slice."""
    return SimpleNamespace(
        document=SimpleNamespace(
            title=title,
            swc_id="SWC-107",
            severity="HIGH",
            description="External call before state update enables reentrant withdrawal.",
            attack_scenario="Attacker re-enters withdraw() before the balance is zeroed.",
        )
    )


SENTINEL = "Reentrancy via external call"
CONTRACT = "pragma solidity ^0.8.20; contract A { function f() public {} }"


# --------------------------------------------------------------------------- #
# 1. The runtime toggle helper
# --------------------------------------------------------------------------- #
class TestRagRuntimeDisabled:
    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "  1  ", "yes"])
    def test_truthy_values_disable(self, monkeypatch, value):
        from miesc.llm.rag_utils import rag_runtime_disabled

        monkeypatch.setenv("MIESC_DISABLE_RAG", value)
        assert rag_runtime_disabled() is True

    @pytest.mark.parametrize("value", ["", "0", "no", "false", "off", "disable"])
    def test_other_values_keep_rag_enabled(self, monkeypatch, value):
        from miesc.llm.rag_utils import rag_runtime_disabled

        monkeypatch.setenv("MIESC_DISABLE_RAG", value)
        assert rag_runtime_disabled() is False

    def test_unset_keeps_rag_enabled(self, monkeypatch):
        from miesc.llm.rag_utils import rag_runtime_disabled

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        assert rag_runtime_disabled() is False

    def test_read_per_call_not_cached(self, monkeypatch):
        """The evaluator flips the var between two calls — it must be read live."""
        from miesc.llm.rag_utils import rag_runtime_disabled

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        assert rag_runtime_disabled() is False
        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        assert rag_runtime_disabled() is True
        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        assert rag_runtime_disabled() is False


# --------------------------------------------------------------------------- #
# 2. _rag_active() honours the runtime toggle on every adapter
# --------------------------------------------------------------------------- #
class TestRagActiveHonoursToggle:
    def _embedding_adapter(self, name):
        if name == "gptscan":
            from miesc.adapters.gptscan_adapter import GPTScanAdapter

            adapter = GPTScanAdapter()
        elif name == "llmsmartaudit":
            from miesc.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter

            adapter = LLMSmartAuditAdapter()
        elif name == "llmbugscanner":
            from miesc.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

            adapter = LLMBugScannerAdapter()
        elif name == "propertygpt":
            from miesc.adapters.propertygpt_adapter import PropertyGPTAdapter

            adapter = PropertyGPTAdapter()
        else:  # pragma: no cover - guard
            raise ValueError(name)
        adapter._use_rag = True
        adapter._embedding_rag = MagicMock()
        return adapter

    @pytest.mark.parametrize("name", ["gptscan", "llmsmartaudit", "llmbugscanner", "propertygpt"])
    def test_embedding_adapters(self, monkeypatch, name):
        adapter = self._embedding_adapter(name)

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        assert adapter._rag_active() is True

        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        assert adapter._rag_active() is False

    def test_smartllm_master_switch(self, monkeypatch):
        from miesc.adapters.smartllm_adapter import SmartLLMAdapter

        adapter = SmartLLMAdapter()
        adapter._use_rag = True

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        assert adapter._rag_active() is True

        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        assert adapter._rag_active() is False


# --------------------------------------------------------------------------- #
# 3. Retrieved context is present in arm A, absent in arm B
# --------------------------------------------------------------------------- #
class TestRetrievedContextGated:
    def test_smartllm_prompt(self, monkeypatch):
        from miesc.adapters.smartllm_adapter import SmartLLMAdapter

        adapter = SmartLLMAdapter()
        adapter._use_rag = True
        adapter._use_embedding_rag = True
        adapter._embedding_rag = MagicMock()
        adapter._embedding_rag.search.return_value = [_fake_rag_hit()]

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        on_prompt = adapter._generate_analysis_prompt(CONTRACT)
        assert SENTINEL in on_prompt

        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        off_prompt = adapter._generate_analysis_prompt(CONTRACT)
        assert SENTINEL not in off_prompt
        # No retrieved-context block at all — not even the keyword fallback.
        assert "KNOWN VULNERABILITY PATTERNS" not in off_prompt

    @pytest.mark.parametrize("name", ["gptscan", "llmsmartaudit"])
    def test_ollama_adapters_prompt(self, monkeypatch, name):
        if name == "gptscan":
            from miesc.adapters.gptscan_adapter import GPTScanAdapter

            adapter = GPTScanAdapter()
        else:
            from miesc.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter

            adapter = LLMSmartAuditAdapter()

        adapter._use_rag = True
        adapter._embedding_rag = MagicMock()
        adapter._embedding_rag.search.return_value = [_fake_rag_hit()]

        captured: dict = {}

        def fake_generate(prompt, *args, **kwargs):
            captured["prompt"] = prompt
            return ""

        adapter._ollama_generate = fake_generate  # type: ignore[assignment]

        def run():
            if name == "gptscan":
                adapter._run_ollama_analysis(CONTRACT, timeout=1)
            else:
                adapter._run_ollama_audit(CONTRACT, timeout=1)

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        run()
        assert SENTINEL in captured["prompt"]

        captured.clear()
        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        run()
        assert SENTINEL not in captured["prompt"]

    def test_llmbugscanner_prompt(self, monkeypatch):
        from miesc.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

        adapter = LLMBugScannerAdapter()
        adapter._use_rag = True
        adapter._embedding_rag = MagicMock()
        adapter._embedding_rag.search.return_value = [_fake_rag_hit()]

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        on_prompt = adapter._generate_analysis_prompt(CONTRACT, "reentrancy")
        assert SENTINEL in on_prompt

        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        off_prompt = adapter._generate_analysis_prompt(CONTRACT, "reentrancy")
        assert SENTINEL not in off_prompt

    def test_propertygpt_prompt(self, monkeypatch):
        from miesc.adapters.propertygpt_adapter import PropertyGPTAdapter

        adapter = PropertyGPTAdapter()
        adapter._use_rag = True
        adapter._embedding_rag = MagicMock()
        adapter._embedding_rag.search.return_value = [_fake_rag_hit()]
        info = {"name": "A", "functions": [], "state_vars": []}

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        on_prompt = adapter._build_propertygpt_prompt(CONTRACT, info)
        assert SENTINEL in on_prompt

        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        off_prompt = adapter._build_propertygpt_prompt(CONTRACT, info)
        assert SENTINEL not in off_prompt


# --------------------------------------------------------------------------- #
# 4. Cache keys encode the effective RAG state (arms can't collide)
# --------------------------------------------------------------------------- #
class TestCacheKeyEncodesRagState:
    def test_gptscan(self):
        from miesc.adapters.gptscan_adapter import GPTScanAdapter

        adapter = GPTScanAdapter()
        on = adapter._get_cache_key(CONTRACT, "m", True)
        off = adapter._get_cache_key(CONTRACT, "m", False)
        assert on != off

    def test_llmsmartaudit(self):
        from miesc.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter

        adapter = LLMSmartAuditAdapter()
        on = adapter._get_cache_key(CONTRACT, "m", True)
        off = adapter._get_cache_key(CONTRACT, "m", False)
        assert on != off

    def test_llmbugscanner(self):
        from miesc.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

        adapter = LLMBugScannerAdapter()
        on = adapter._get_cache_key(CONTRACT, True)
        off = adapter._get_cache_key(CONTRACT, False)
        assert on != off

    def test_smartllm(self, monkeypatch):
        from miesc.adapters.smartllm_adapter import SmartLLMAdapter

        adapter = SmartLLMAdapter()
        adapter._use_rag = True
        adapter._use_embedding_rag = True
        adapter._embedding_rag = MagicMock()

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        on = adapter._get_cache_key(CONTRACT)
        monkeypatch.setenv("MIESC_DISABLE_RAG", "1")
        off = adapter._get_cache_key(CONTRACT)
        assert on != off


# --------------------------------------------------------------------------- #
# 5. The evaluator labels each arm by the RAG state actually applied
# --------------------------------------------------------------------------- #
class TestEvaluatorReadsEffectiveState:
    def _result(self, rag_enhanced):
        return {
            "tool": "fake",
            "status": "success",
            "findings": [],
            "metadata": {"rag_enhanced": rag_enhanced},
        }

    def test_effective_rag_reads_metadata(self):
        from miesc.evaluation.rag_evaluator import RAGEvaluator

        assert RAGEvaluator._effective_rag(self._result(True)) is True
        assert RAGEvaluator._effective_rag(self._result(False)) is False

    def test_effective_rag_unknown_when_absent(self):
        from miesc.evaluation.rag_evaluator import RAGEvaluator

        assert RAGEvaluator._effective_rag({"metadata": {}}) is None
        assert RAGEvaluator._effective_rag({}) is None
        assert RAGEvaluator._effective_rag("not a dict") is None

    def test_restore_env_roundtrip(self, monkeypatch):
        import os

        from miesc.evaluation.rag_evaluator import RAGEvaluator

        monkeypatch.delenv("MIESC_DISABLE_RAG", raising=False)
        RAGEvaluator._restore_env("MIESC_DISABLE_RAG", None)
        assert "MIESC_DISABLE_RAG" not in os.environ
        RAGEvaluator._restore_env("MIESC_DISABLE_RAG", "1")
        assert os.environ["MIESC_DISABLE_RAG"] == "1"
        RAGEvaluator._restore_env("MIESC_DISABLE_RAG", None)
        assert "MIESC_DISABLE_RAG" not in os.environ
