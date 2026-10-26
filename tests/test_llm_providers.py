"""LLM provider registry (miesc.core.llm_providers): resolution, config overlay, clients.

No network and no real SDK: clients are built against fake ``openai`` / ``anthropic``
modules injected into ``sys.modules``.
"""

import sys
import types

import pytest

from miesc.core import llm_providers as lp


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "MOONSHOT_API_KEY",
        "KIMI_API_KEY",
        "DEEPSEEK_BASE_URL",
        "KIMI_BASE_URL",
        "MOONSHOT_BASE_URL",
        "OLLAMA_HOST",
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
        "OLLAMA_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(lp, "get_llm_config", lambda: {})


class TestResolution:
    @pytest.mark.parametrize(
        "text, provider, model",
        [
            ("claude", "anthropic", "claude-sonnet-4-6"),
            ("claude-opus", "anthropic", "claude-opus-4-6"),
            ("gpt", "openai", "gpt-4o"),
            ("gpt-5", "openai", "gpt-5"),
            ("deepseek-v4-pro", "deepseek", "deepseek-v4-pro"),
            ("deepseek-v4-flash", "deepseek", "deepseek-v4-flash"),
            ("ollama", "ollama", "qwen2.5-coder:14b"),
            ("qwen32b", "ollama", "qwen2.5-coder:32b"),
            ("qwen14b", "ollama", "qwen2.5-coder:14b"),
            ("codellama", "ollama", "codellama:13b"),
        ],
    )
    def test_historical_aliases_keep_their_meaning(self, text, provider, model):
        choice = lp.resolve_model(text)
        assert (choice.provider.name, choice.model) == (provider, model)

    def test_provider_colon_model(self):
        choice = lp.resolve_model("kimi:kimi-k2-thinking")
        assert (choice.provider.name, choice.model, choice.how) == (
            "kimi",
            "kimi-k2-thinking",
            "explicit",
        )

    def test_ollama_tags_keep_their_colon(self):
        assert lp.resolve_model("ollama:qwen2.5-coder:32b").model == "qwen2.5-coder:32b"
        bare = lp.resolve_model("qwen2.5-coder:32b")
        assert (bare.provider.name, bare.model) == ("ollama", "qwen2.5-coder:32b")

    def test_bare_provider_name_gives_its_default(self):
        assert lp.resolve_model("deepseek").model == "deepseek-v4-flash"
        assert lp.resolve_model("KIMI").provider.name == "kimi"

    def test_provider_model_aliases(self):
        assert lp.resolve_model("kimi:thinking").model == "kimi-k2-thinking"
        assert lp.resolve_model("deepseek:pro").model == "deepseek-v4-pro"

    def test_bare_model_id_is_inferred_from_its_prefix(self):
        assert lp.resolve_model("claude-opus-4-6").provider.name == "anthropic"
        assert lp.resolve_model("o3-mini").provider.name == "openai"
        assert lp.resolve_model("deepseek-chat").provider.name == "deepseek"
        assert lp.resolve_model("moonshot-v1-128k").provider.name == "kimi"
        assert lp.resolve_model("llama3.1:8b").provider.name == "ollama"

    @pytest.mark.parametrize(
        "tag",
        [
            "codellama:instruct",
            "llama2:chat",
            "mistral:text",
            "llama3:latest",
            "qwen2.5-coder:7b-instruct-q4_K_M",
        ],
    )
    def test_bare_ollama_tags_without_digits_still_go_to_ollama(self, tag):
        choice = lp.resolve_model(tag)
        assert (choice.provider.name, choice.model) == ("ollama", tag)

    def test_unknown_prefix_names_the_known_providers(self):
        with pytest.raises(lp.UnknownProviderError) as err:
            lp.resolve_model("nope:some-model")
        assert "anthropic" in str(err.value) and "kimi" in str(err.value)

    def test_empty_is_none(self):
        assert lp.resolve_model(None) is None
        assert lp.resolve_model("  ") is None


class TestConfigOverlay:
    def test_custom_openai_compatible_provider(self, monkeypatch):
        monkeypatch.setattr(
            lp,
            "get_llm_config",
            lambda: {
                "providers": {
                    "openrouter": {
                        "kind": "openai",
                        "base_url": "https://openrouter.ai/api/v1/",
                        "api_key_env": "OPENROUTER_API_KEY",
                        "default_model": "qwen/qwen-2.5-coder-32b-instruct",
                    }
                }
            },
        )
        spec = lp.get_provider("openrouter")
        assert spec.kind == "openai" and spec.base_url == "https://openrouter.ai/api/v1"
        assert spec.api_key_env == ("OPENROUTER_API_KEY",) and spec.source == "config"
        choice = lp.resolve_model("openrouter:meta-llama/llama-3.3-70b")
        assert choice.provider.name == "openrouter"

    def test_builtin_fields_can_be_overridden(self, monkeypatch):
        monkeypatch.setattr(
            lp,
            "get_llm_config",
            lambda: {"providers": {"kimi": {"default_model": "kimi-k2-thinking"}}},
        )
        spec = lp.get_provider("kimi")
        assert spec.default_model == "kimi-k2-thinking"
        assert spec.base_url == "https://api.moonshot.ai/v1" and spec.api_key_env == (
            "MOONSHOT_API_KEY",
            "KIMI_API_KEY",
        )

    @pytest.mark.parametrize(
        "raw",
        [
            {"kind": "grpc", "default_model": "x", "api_key_env": "K"},  # unknown kind
            {"kind": "openai", "default_model": "x"},  # cloud without key env
            {"kind": "openai", "default_model": "x", "api_key_env": "lower"},  # bad env name
            {"kind": "openai", "default_model": "x", "api_key_env": "K", "base_url": "ftp://x"},
            {
                "kind": "openai",
                "default_model": "x",
                "api_key_env": "K",
                "base_url": "https://u:p@host/v1",
            },
        ],
    )
    def test_invalid_entries_are_ignored(self, monkeypatch, raw):
        monkeypatch.setattr(lp, "get_llm_config", lambda: {"providers": {"bad": raw}})
        assert "bad" not in lp.load_providers()

    def test_env_base_url_overrides(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://proxy.example/deepseek/")
        monkeypatch.setenv("MOONSHOT_BASE_URL", "https://api.moonshot.cn/v1")
        assert lp.get_provider("deepseek").base_url == "https://proxy.example/deepseek"
        assert lp.get_provider("kimi").base_url == "https://api.moonshot.cn/v1"


class TestCredentialsAndClients:
    def test_key_lookup_order_and_configured(self, monkeypatch):
        kimi = lp.get_provider("kimi")
        assert lp.api_key_for(kimi) is None and not lp.is_configured(kimi)
        monkeypatch.setenv("KIMI_API_KEY", "k2")
        assert lp.api_key_for(kimi) == "k2"
        monkeypatch.setenv("MOONSHOT_API_KEY", "m1")
        assert lp.api_key_for(kimi) == "m1" and lp.is_configured(kimi)
        assert lp.is_configured(lp.get_provider("ollama"))

    def test_make_client_openai_compatible_uses_base_url_and_key(self, monkeypatch):
        seen = {}

        class FakeOpenAI:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        monkeypatch.setitem(
            sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI, AsyncOpenAI=FakeOpenAI)
        )
        monkeypatch.setenv("MOONSHOT_API_KEY", "secret")
        lp.make_client(lp.get_provider("kimi"))
        assert seen == {
            "api_key": "secret",
            "timeout": 300,
            "base_url": "https://api.moonshot.ai/v1",
            "max_retries": 5,
        }

    def test_make_client_anthropic(self, monkeypatch):
        seen = {}

        class FakeAnthropic:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        monkeypatch.setitem(
            sys.modules,
            "anthropic",
            types.SimpleNamespace(Anthropic=FakeAnthropic, AsyncAnthropic=FakeAnthropic),
        )
        monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
        lp.make_client(lp.get_provider("anthropic"), timeout=42)
        assert seen == {"api_key": "a", "timeout": 42, "max_retries": 5}

    def test_make_client_sets_max_retries(self, monkeypatch):
        """429/5xx are retried via the SDK backoff; MIESC_LLM_MAX_RETRIES wins,
        and a non-integer value falls back to the default instead of raising."""
        seen = {}

        class FakeOpenAI:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        monkeypatch.setitem(
            sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI, AsyncOpenAI=FakeOpenAI)
        )
        monkeypatch.setenv("MOONSHOT_API_KEY", "secret")
        lp.make_client(lp.get_provider("kimi"))
        assert seen["max_retries"] == 5

        seen.clear()
        monkeypatch.setenv("MIESC_LLM_MAX_RETRIES", "9")
        lp.make_client(lp.get_provider("kimi"))
        assert seen["max_retries"] == 9

        seen.clear()
        monkeypatch.setenv("MIESC_LLM_MAX_RETRIES", "not-an-int")
        lp.make_client(lp.get_provider("kimi"))
        assert seen["max_retries"] == 5

    def test_make_client_without_key_names_the_variables(self):
        with pytest.raises(RuntimeError) as err:
            lp.make_client(lp.get_provider("deepseek"))
        assert "DEEPSEEK_API_KEY" in str(err.value)

    def test_openai_without_key_defers_to_the_sdk(self, monkeypatch):
        """The SDK reads OPENAI_API_KEY itself; only non-default providers fail early."""
        seen = {}

        class FakeOpenAI:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        monkeypatch.setitem(
            sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI, AsyncOpenAI=FakeOpenAI)
        )
        lp.make_client(lp.get_provider("openai"))
        assert "api_key" not in seen and "base_url" not in seen

    def test_make_client_without_sdk_names_the_provider(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "openai", None)
        monkeypatch.setenv("MOONSHOT_API_KEY", "k")
        with pytest.raises(ImportError) as err:
            lp.make_client(lp.get_provider("kimi"))
        assert "Kimi" in str(err.value)

    def test_ollama_has_no_sdk_client(self):
        with pytest.raises(RuntimeError):
            lp.make_client(lp.get_provider("ollama"))


class TestDescribe:
    def test_rows_never_contain_key_values(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-very-secret")
        rows = {r["name"]: r for r in lp.describe_providers()}
        assert rows["openai"]["configured"] is True and rows["openai"]["host"] == "api.openai.com"
        assert rows["kimi"]["configured"] is False and rows["kimi"]["host"] == "api.moonshot.ai"
        assert "sk-very-secret" not in repr(rows)
        assert set(rows) >= {"anthropic", "openai", "deepseek", "kimi", "ollama"}
