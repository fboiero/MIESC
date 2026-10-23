"""
Shared LLM provider registry — one source of truth for the configurable providers.

Both the recall-safe FP verifier (`miesc.ml.benign_context_verifier`, which talks to the
providers over dependency-free urllib) and the business-logic detector
(`miesc.adapters.frontier_llm_adapter`, which uses the ``openai``/``anthropic`` SDKs) resolve
provider connection facts from here, so a key/base-URL/alias is defined once and cannot drift
between the two call paths.

What is SHARED is the *connection spec* (API style, key env vars, base URL, the default
model) and the ``--model`` / ``--verify-model`` string parser. The call paths are NOT shared:
the verifier returns a boolean verdict and only ever flags; the detector returns a findings
list. Only the plumbing is common.

Author: Fernando Boiero · License: AGPL-3.0
"""

from __future__ import annotations

import os
from typing import NamedTuple, Optional


class ProviderSpec(NamedTuple):
    """Connection facts for one provider (not the use-case default model)."""

    api_style: str  # "openai" (chat/completions), "anthropic" (messages), "ollama"
    key_envs: tuple[str, ...]  # API-key env vars, tried in order
    base_url_env: str  # env var that overrides the base URL
    base_url_default: str  # default base URL
    chat_path: str  # path appended to base URL for the urllib verifier path
    model_env: str  # env var that overrides the fallback model
    model_default: str  # last-resort model when the caller passes none


#: provider -> connection spec. The ``model_default`` here is a cheap fallback used when the
#: caller passes no model (e.g. ``--verify-model gpt``); detection call sites pass an explicit
#: model from their own map, so the fallback does not weaken them.
PROVIDERS: dict[str, ProviderSpec] = {
    "deepseek": ProviderSpec(
        "openai",
        ("DEEPSEEK_API_KEY",),
        "DEEPSEEK_BASE_URL",
        "https://api.deepseek.com",
        "/chat/completions",
        "DEEPSEEK_MODEL",
        "deepseek-chat",
    ),
    "openai": ProviderSpec(
        "openai",
        ("OPENAI_API_KEY",),
        "OPENAI_BASE_URL",
        "https://api.openai.com",
        "/v1/chat/completions",
        "MIESC_OPENAI_MODEL",
        "gpt-4o-mini",
    ),
    "kimi": ProviderSpec(
        "openai",
        ("KIMI_API_KEY", "MOONSHOT_API_KEY"),
        "KIMI_BASE_URL",
        "https://api.moonshot.ai",
        "/v1/chat/completions",
        "KIMI_MODEL",
        "moonshot-v1-8k",
    ),
    "anthropic": ProviderSpec(
        "anthropic",
        ("ANTHROPIC_API_KEY",),
        "ANTHROPIC_BASE_URL",
        "https://api.anthropic.com",
        "/v1/messages",
        "MIESC_ANTHROPIC_MODEL",
        "claude-3-5-sonnet-latest",
    ),
}

#: Spoken aliases accepted on the CLI / config -> canonical provider key above.
PROVIDER_ALIASES: dict[str, str] = {
    "gpt": "openai",
    "openai": "openai",
    "claude": "anthropic",
    "anthropic": "anthropic",
    "kimi": "kimi",
    "moonshot": "kimi",
    "deepseek": "deepseek",
}


def parse_model(model: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Resolve a model string to ``(provider, model_name)``.

    Accepts ``provider`` or ``provider:model`` (e.g. ``gpt``, ``claude:claude-3-5-sonnet``,
    ``ollama:qwen2.5-coder:32b``). A bare string that is not a known provider alias is treated
    as an Ollama model name (backward compatible). ``(None, None)`` disables the LLM path.
    """
    if not model:
        return None, None
    raw = model.strip()
    head, sep, tail = raw.partition(":")
    hl = head.lower()
    if sep:
        if hl in PROVIDER_ALIASES:
            return PROVIDER_ALIASES[hl], (tail or None)
        if hl == "ollama":
            return "ollama", tail or None
    if raw.lower() in PROVIDER_ALIASES:
        return PROVIDER_ALIASES[raw.lower()], None
    return "ollama", raw


def resolve_key(provider: str) -> str:
    """First present API key for the provider, or '' (recall-safe: caller treats as skip)."""
    spec = PROVIDERS.get(provider)
    if not spec:
        return ""
    return next((os.environ[k] for k in spec.key_envs if os.environ.get(k)), "")


def resolve_base_url(provider: str) -> str:
    """Base URL for the provider (env override, then default)."""
    spec = PROVIDERS[provider]
    return os.environ.get(spec.base_url_env, spec.base_url_default).rstrip("/")


def resolve_model(provider: str, model: Optional[str] = None) -> str:
    """Model for the provider: explicit arg, then env override, then the cheap default."""
    spec = PROVIDERS[provider]
    return model or os.environ.get(spec.model_env) or spec.model_default


__all__ = [
    "ProviderSpec",
    "PROVIDERS",
    "PROVIDER_ALIASES",
    "parse_model",
    "resolve_key",
    "resolve_base_url",
    "resolve_model",
]
