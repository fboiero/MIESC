"""Tests for Ollama model discovery and selection helpers.

select_ollama_model is exercised via the `installed` param (no network);
list_ollama_models is exercised by mocking urllib.request.urlopen.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from miesc.core.ollama_models import list_ollama_models, select_ollama_model


@pytest.fixture(autouse=True)
def _drop_llm_model_env(monkeypatch):
    """``select_ollama_model`` honours ``MIESC_LLM_MODEL`` before anything else.

    Drop any inherited value so these tests exercise the real selection
    heuristic and never depend on the host's environment / Ollama state.
    """
    monkeypatch.delenv("MIESC_LLM_MODEL", raising=False)


def _tags_response(names, status=200):
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = json.dumps({"models": [{"name": n} for n in names]}).encode("utf-8")
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


class TestListOllamaModels:
    def test_success_returns_names(self):
        with patch("urllib.request.urlopen", return_value=_tags_response(["a:1", "b:2"])):
            assert list_ollama_models() == ["a:1", "b:2"]

    def test_non_200_returns_empty(self):
        with patch("urllib.request.urlopen", return_value=_tags_response([], status=503)):
            assert list_ollama_models() == []

    def test_url_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            assert list_ollama_models() == []

    def test_skips_entries_without_name(self):
        resp = _tags_response([])
        resp.__enter__.return_value.read.return_value = json.dumps(
            {"models": [{"name": "ok"}, {"size": 1}, {"name": ""}]}
        ).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=resp):
            assert list_ollama_models() == ["ok"]


class TestSelectOllamaModel:
    def test_exact_match(self):
        assert select_ollama_model(["llama3:8b"], installed=["llama3:8b"]) == "llama3:8b"

    def test_exact_match_case_insensitive(self):
        assert select_ollama_model(["LLAMA3:8B"], installed=["llama3:8b"]) == "llama3:8b"

    def test_family_prefix_match(self):
        assert select_ollama_model(["llama3"], installed=["llama3:8b"]) == "llama3:8b"

    def test_fallback_exact_match(self):
        result = select_ollama_model(["mistral"], installed=["llama3:8b"], fallback="llama3:8b")
        assert result == "llama3:8b"

    def test_fallback_family_prefix(self):
        result = select_ollama_model(["mistral"], installed=["llama3:8b"], fallback=["llama3"])
        assert result == "llama3:8b"

    def test_no_match_returns_first_installed(self):
        assert select_ollama_model(["zzz"], installed=["only:1"]) == "only:1"

    def test_no_models_returns_fallback_name(self):
        assert select_ollama_model(["zzz"], installed=[], fallback="default:1") == "default:1"

    def test_no_models_no_fallback_returns_empty(self):
        assert select_ollama_model(["zzz"], installed=[]) == ""
