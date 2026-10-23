"""The EVMBench harness resolves --model through the shared provider registry."""

import importlib.util
import pathlib

import pytest

HARNESS = pathlib.Path(__file__).resolve().parents[1] / "benchmarks" / "evmbench_eval.py"


@pytest.fixture(scope="module")
def harness():
    spec = importlib.util.spec_from_file_location("evmbench_eval_under_test", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _no_config(monkeypatch):
    import miesc.core.llm_providers as lp

    monkeypatch.setattr(lp, "get_llm_config", lambda: {})


@pytest.mark.parametrize(
    "spelled, provider, model",
    [
        ("claude", "anthropic", "claude-sonnet-4-6"),
        ("gpt", "openai", "gpt-4o"),
        ("gpt-5", "openai", "gpt-5"),
        ("deepseek", "deepseek", "deepseek-chat"),  # harness meaning kept
        ("deepseek-r", "deepseek", "deepseek-reasoner"),
        ("ollama", "ollama", "qwen2.5-coder:32b"),  # benchmarked local model, not scan's 14b
        ("qwen14b", "ollama", "qwen2.5-coder:14b"),
        ("kimi", "kimi", "kimi-k2-turbo-preview"),
        ("kimi:kimi-k2-thinking", "kimi", "kimi-k2-thinking"),
        ("ollama:llama3:8b", "ollama", "llama3:8b"),
    ],
)
def test_model_spellings_resolve_through_the_registry(harness, spelled, provider, model):
    assert harness.resolve_frontier_model(spelled) == (provider, model, f"{provider}:{model}")


def test_unset_model_is_none(harness):
    assert harness.resolve_frontier_model(None) is None
    assert harness.resolve_frontier_model("") is None


def test_unknown_provider_raises_before_any_call(harness):
    from miesc.core.llm_providers import UnknownProviderError

    with pytest.raises(UnknownProviderError):
        harness.resolve_frontier_model("nope:some-model")


def test_no_hardcoded_provider_tables_remain():
    text = HARNESS.read_text()
    assert "provider_map" not in text and "model_map" not in text
