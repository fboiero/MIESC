"""Tests for the generic OpenAI-compatible endpoint support in FrontierLLMAdapter.

When ``MIESC_OPENAI_BASE_URL`` is set, the adapter must point the OpenAI client at
that endpoint for *any* model — including ``deepseek``-named models, which would
otherwise be force-routed to ``api.deepseek.com``. This is what lets MIESC run
against OpenAI-compatible gateways such as Huawei Cloud MaaS, vLLM or Together.
"""

from unittest.mock import MagicMock, patch

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter


def _mock_openai_returning(content):
    """Build a patch target whose client returns ``content`` as the completion."""
    resp = MagicMock()
    resp.choices[0].message.content = content
    mock_cls = MagicMock()
    mock_cls.return_value.chat.completions.create.return_value = resp
    return mock_cls


def test_compat_base_url_overrides_deepseek_routing(monkeypatch):
    monkeypatch.setenv("MIESC_OPENAI_BASE_URL", "https://maas.example.com/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "token-xyz")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    mock_cls = _mock_openai_returning("[]")
    with patch("openai.OpenAI", mock_cls):
        adapter = FrontierLLMAdapter(provider="openai")
        # A deepseek-named model would normally be forced to api.deepseek.com.
        adapter._analyze_openai(
            "contract C { function f() public {} }", model="deepseek-v4.1-flash"
        )

    assert mock_cls.call_count == 1
    _, kwargs = mock_cls.call_args
    assert kwargs.get("base_url") == "https://maas.example.com/v1"
    assert kwargs.get("api_key") == "token-xyz"


def test_no_compat_base_url_keeps_deepseek_default(monkeypatch):
    monkeypatch.delenv("MIESC_OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")

    mock_cls = _mock_openai_returning("[]")
    with patch("openai.OpenAI", mock_cls):
        adapter = FrontierLLMAdapter(provider="deepseek")
        adapter._analyze_openai("contract C {}", model="deepseek-v4.1-flash")

    _, kwargs = mock_cls.call_args
    assert kwargs.get("base_url") == "https://api.deepseek.com"
