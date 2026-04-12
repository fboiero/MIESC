"""Tests for GPTScan adapter prompt construction.

Focused on prompt-template integrity — no Ollama calls required.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def adapter():
    # Import lazily to avoid triggering Ollama availability checks during collection
    from src.adapters.gptscan_adapter import GPTScanAdapter
    return GPTScanAdapter()


class TestSecurityPromptTemplate:
    def test_template_has_both_placeholders(self, adapter):
        """Template must contain both %CONTRACT_CODE% and %RAG_CONTEXT_PLACEHOLDER%."""
        assert "%CONTRACT_CODE%" in adapter.SECURITY_PROMPT
        assert "%RAG_CONTEXT_PLACEHOLDER%" in adapter.SECURITY_PROMPT

    def test_template_has_chain_of_thought_structure(self, adapter):
        """Prompt must include all 4 CoT steps (per Bloque 2 of the roadmap)."""
        t = adapter.SECURITY_PROMPT
        assert "STEP 1" in t
        assert "STEP 2" in t
        assert "STEP 3" in t
        assert "STEP 4" in t and "SELF-VERIFICATION" in t

    def test_template_has_few_shot_real_exploits(self, adapter):
        """Prompt must include concrete real-world exploit examples."""
        t = adapter.SECURITY_PROMPT
        assert "FEW-SHOT EXAMPLES" in t
        # At least the three reference incidents
        assert "Cream" in t or "cream" in t.lower()
        assert "Euler" in t or "euler" in t.lower()
        assert "BNB" in t or "bnb" in t.lower()

    def test_template_requires_structured_json_output(self, adapter):
        """Output schema must enforce reasoning + fp-check + remediation fields."""
        t = adapter.SECURITY_PROMPT
        assert "reasoning" in t.lower()
        assert "false_positive_check" in t
        assert "recommendation" in t


class TestRAGInjection:
    def test_placeholder_replaced_when_rag_unavailable(self, adapter):
        """If RAG is disabled, the placeholder must be replaced with an empty string,
        not left literal in the prompt sent to the model."""
        adapter._use_rag = False
        adapter._embedding_rag = None

        # Stub the HTTP call so we only exercise the prompt builder
        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"response": "{}"}'
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp

            try:
                adapter._run_ollama_analysis("pragma solidity ^0.8.20; contract A {}", timeout=1)
            except Exception:
                # We only care about the prompt that was sent, not the full run
                pass

            sent_request = mock_open.call_args[0][0]
            body = sent_request.data.decode("utf-8")
            # %RAG_CONTEXT_PLACEHOLDER% and %CONTRACT_CODE% MUST NOT appear verbatim
            assert "%RAG_CONTEXT_PLACEHOLDER%" not in body
            assert "%CONTRACT_CODE%" not in body

    def test_rag_context_injected_when_available(self, adapter):
        """With RAG results available, the context is interpolated at the placeholder."""
        fake_result = MagicMock()
        fake_result.document.title = "Reentrancy via external call"
        fake_result.document.swc_id = "SWC-107"
        fake_result.document.description = "External call before state update enables reentrant withdrawal."

        adapter._use_rag = True
        adapter._embedding_rag = MagicMock()
        adapter._embedding_rag.search.return_value = [fake_result]

        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"response": "{}"}'
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp

            try:
                adapter._run_ollama_analysis("pragma solidity ^0.8.20; contract A {}", timeout=1)
            except Exception:
                pass

            sent_request = mock_open.call_args[0][0]
            body = sent_request.data.decode("utf-8")
            assert "Reentrancy via external call" in body
            assert "SWC-107" in body
            # Enforcement sentence must be present
            assert "Compare each finding" in body
            assert "%RAG_CONTEXT_PLACEHOLDER%" not in body
