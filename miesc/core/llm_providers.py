"""LLM provider registry: one place that says which backends exist and how to reach them.

Every entry point that talks to a model (``scan --model``, ``audit --llm-provider``,
``MIESC_LLM_PROVIDER`` for the orchestrator, ``doctor``) reads this registry instead of
carrying its own table of names, endpoints and environment variables.

Built-in providers: ``anthropic``, ``openai``, ``deepseek``, ``kimi`` (Moonshot) and
``ollama`` (local). Any OpenAI-compatible endpoint (vLLM, OpenRouter, Together, a
corporate gateway) is added from the configuration file::

    llm:
      providers:
        openrouter:
          kind: openai
          base_url: https://openrouter.ai/api/v1
          api_key_env: OPENROUTER_API_KEY
          default_model: qwen/qwen-2.5-coder-32b-instruct
        kimi:                      # override a built-in field
          default_model: kimi-k2-thinking

Selection is ``provider:model`` (``kimi:kimi-k2-thinking``, ``ollama:qwen2.5-coder:32b``),
a bare provider name (its default model), one of the historical aliases (``claude``,
``gpt-5``, ``qwen32b``, ...) or a bare model id, whose provider is inferred from its prefix.

API keys are read from environment variables named by the provider and never stored,
logged or reported; :func:`describe_providers` only says whether a key is set.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlparse

from miesc.core.llm_config import get_llm_config, get_ollama_host

__all__ = [
    "ProviderSpec",
    "ModelChoice",
    "UnknownProviderError",
    "KINDS",
    "BUILTIN_PROVIDERS",
    "MODEL_ALIASES",
    "load_providers",
    "get_provider",
    "resolve_model",
    "api_key_for",
    "is_configured",
    "make_client",
    "describe_providers",
    "base_url_host",
]

KINDS = ("anthropic", "openai", "ollama")
"""Client protocols: Anthropic Messages API, OpenAI-compatible chat API, Ollama HTTP API."""

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_MAX_TIMEOUT = 3600
_OLLAMA_TAG_RE = re.compile(r"^(?:latest|[A-Za-z0-9._-]*\d[A-Za-z0-9._-]*)$")


class UnknownProviderError(ValueError):
    """Raised when a ``provider:model`` prefix or provider name is not registered."""


@dataclass(frozen=True)
class ProviderSpec:
    """How to reach one LLM backend."""

    name: str
    kind: str
    default_model: str
    base_url: Optional[str] = None
    api_key_env: Tuple[str, ...] = ()
    models: Mapping[str, str] = field(default_factory=dict)
    timeout: int = 300
    label: str = ""
    source: str = "builtin"

    @property
    def display_name(self) -> str:
        return self.label or self.name

    @property
    def needs_api_key(self) -> bool:
        return self.kind != "ollama"


@dataclass(frozen=True)
class ModelChoice:
    """A resolved ``--model`` value."""

    provider: ProviderSpec
    model: str
    how: str
    """``explicit`` (provider:model), ``alias``, ``provider`` (default model) or ``inferred``."""


BUILTIN_PROVIDERS: Dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic",
        kind="anthropic",
        default_model="claude-sonnet-4-6",
        api_key_env=("ANTHROPIC_API_KEY",),
        models={"sonnet": "claude-sonnet-4-6", "opus": "claude-opus-4-6"},
        label="Anthropic",
    ),
    "openai": ProviderSpec(
        name="openai",
        kind="openai",
        default_model="gpt-4o",
        api_key_env=("OPENAI_API_KEY",),
        models={"gpt-4o": "gpt-4o", "gpt-4.1": "gpt-4.1", "gpt-5": "gpt-5"},
        label="OpenAI",
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        kind="openai",
        default_model="deepseek-v4-flash",
        base_url="https://api.deepseek.com",
        api_key_env=("DEEPSEEK_API_KEY",),
        models={"flash": "deepseek-v4-flash", "pro": "deepseek-v4-pro"},
        label="DeepSeek",
    ),
    "kimi": ProviderSpec(
        name="kimi",
        kind="openai",
        # Moonshot's OpenAI-compatible endpoint (api.moonshot.cn for the China region).
        # Model ids follow Moonshot's catalogue; `miesc doctor --verbose` lists what
        # the configured key can see, and `llm.providers.kimi.default_model` overrides.
        default_model="kimi-k2-turbo-preview",
        base_url="https://api.moonshot.ai/v1",
        api_key_env=("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        models={"turbo": "kimi-k2-turbo-preview", "thinking": "kimi-k2-thinking"},
        label="Kimi (Moonshot)",
    ),
    "ollama": ProviderSpec(
        name="ollama",
        kind="ollama",
        default_model="qwen2.5-coder:14b",
        models={
            "qwen14b": "qwen2.5-coder:14b",
            "qwen32b": "qwen2.5-coder:32b",
            "codellama": "codellama:13b",
        },
        label="Ollama (local)",
    ),
}

MODEL_ALIASES: Dict[str, Tuple[str, str]] = {
    # The historical `scan --model` choices keep resolving to exactly what they did.
    "claude": ("anthropic", "claude-sonnet-4-6"),
    "claude-sonnet": ("anthropic", "claude-sonnet-4-6"),
    "claude-opus": ("anthropic", "claude-opus-4-6"),
    "gpt": ("openai", "gpt-4o"),
    "gpt-4o": ("openai", "gpt-4o"),
    "gpt-4.1": ("openai", "gpt-4.1"),
    "gpt-5": ("openai", "gpt-5"),
    "deepseek-v4-pro": ("deepseek", "deepseek-v4-pro"),
    "deepseek-v4-flash": ("deepseek", "deepseek-v4-flash"),
    "qwen32b": ("ollama", "qwen2.5-coder:32b"),
    "qwen14b": ("ollama", "qwen2.5-coder:14b"),
    "codellama": ("ollama", "codellama:13b"),
}

_PREFIX_TO_PROVIDER: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (("claude",), "anthropic"),
    (("gpt-", "o1", "o3", "o4"), "openai"),
    (("deepseek-",), "deepseek"),
    (("kimi", "moonshot"), "kimi"),
)


# --------------------------------------------------------------------------- config
def _text(value: Any, *, max_chars: int = 512) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > max_chars or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return ""
    return text


def _valid_base_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.hostname) and "@" not in value


def _env_names(value: Any) -> Tuple[str, ...]:
    raw = value if isinstance(value, (list, tuple)) else [value]
    names = []
    for item in raw[:8]:
        name = _text(item, max_chars=64)
        if name and _ENV_RE.match(name):
            names.append(name)
    return tuple(names)


def _models(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: Dict[str, str] = {}
    for alias, model in list(value.items())[:64]:
        alias_text = _text(alias, max_chars=64).lower()
        model_text = _text(model, max_chars=128)
        if alias_text and model_text and _MODEL_RE.match(model_text):
            out[alias_text] = model_text
    return out


def _spec_from_config(
    name: str, raw: Mapping[str, Any], base: Optional[ProviderSpec]
) -> Optional[ProviderSpec]:
    kind = _text(raw.get("kind"), max_chars=16).lower() or (base.kind if base else "")
    if kind not in KINDS:
        return None
    default_model = _text(raw.get("default_model"), max_chars=128) or (
        base.default_model if base else ""
    )
    if not default_model or not _MODEL_RE.match(default_model):
        return None
    base_url = _text(raw.get("base_url"), max_chars=2048) or (base.base_url if base else None)
    if base_url and not _valid_base_url(base_url):
        return None
    api_key_env = (
        _env_names(raw.get("api_key_env"))
        if "api_key_env" in raw
        else (base.api_key_env if base else ())
    )
    if kind != "ollama" and not api_key_env:
        return None
    timeout_raw = raw.get("timeout")
    timeout = base.timeout if base else 300
    if (
        isinstance(timeout_raw, int)
        and not isinstance(timeout_raw, bool)
        and 1 <= timeout_raw <= _MAX_TIMEOUT
    ):
        timeout = timeout_raw
    models = dict(base.models) if base else {}
    models.update(_models(raw.get("models")))
    label = _text(raw.get("label"), max_chars=64) or (base.label if base else name)
    return ProviderSpec(
        name=name,
        kind=kind,
        default_model=default_model,
        base_url=base_url.rstrip("/") if base_url else None,
        api_key_env=api_key_env,
        models=models,
        timeout=timeout,
        label=label,
        source="config",
    )


def _apply_env_overrides(spec: ProviderSpec) -> ProviderSpec:
    """``<NAME>_BASE_URL`` (and the historical ``DEEPSEEK_BASE_URL``/``MOONSHOT_BASE_URL``) win."""
    candidates = [f"{spec.name.upper().replace('-', '_')}_BASE_URL"]
    if spec.name == "kimi":
        candidates.append("MOONSHOT_BASE_URL")
    for env_name in candidates:
        value = _text(os.environ.get(env_name), max_chars=2048)
        if value and _valid_base_url(value):
            return replace(spec, base_url=value.rstrip("/"))
    if spec.kind == "ollama":
        return replace(spec, base_url=get_ollama_host())
    return spec


def load_providers() -> Dict[str, ProviderSpec]:
    """Built-in providers overlaid with ``llm.providers`` from the configuration."""
    providers: Dict[str, ProviderSpec] = dict(BUILTIN_PROVIDERS)
    try:
        configured = get_llm_config().get("providers")
    except Exception:  # config errors must never take the CLI down
        configured = None
    if isinstance(configured, Mapping):
        for raw_name, raw in list(configured.items())[:64]:
            name = _text(raw_name, max_chars=32).lower()
            if not name or not _NAME_RE.match(name) or not isinstance(raw, Mapping):
                continue
            spec = _spec_from_config(name, raw, providers.get(name))
            if spec is not None:
                providers[name] = spec
    return {name: _apply_env_overrides(spec) for name, spec in providers.items()}


def get_provider(name: str) -> ProviderSpec:
    providers = load_providers()
    key = (name or "").strip().lower()
    if key not in providers:
        raise UnknownProviderError(
            f"Unknown LLM provider '{name}'. Known providers: {', '.join(sorted(providers))}"
        )
    return providers[key]


# --------------------------------------------------------------------------- selection
def resolve_model(
    text: Optional[str], default_provider: Optional[str] = None
) -> Optional[ModelChoice]:
    """Turn a ``--model`` / ``MIESC_LLM_MODEL`` value into a provider and a model id.

    ``None``/empty returns ``None`` (the caller decides what "no model" means).
    """
    value = (text or "").strip()
    if not value:
        return None
    providers = load_providers()
    lowered = value.lower()

    if ":" in value:
        prefix, _, rest = value.partition(":")
        prefix_key = prefix.strip().lower()
        if prefix_key in providers:
            spec = providers[prefix_key]
            model = rest.strip()
            model = spec.models.get(model.lower(), model) if model else spec.default_model
            if not _MODEL_RE.match(model):
                raise UnknownProviderError(
                    f"Malformed model id '{rest}' for provider '{prefix_key}'"
                )
            return ModelChoice(spec, model, "explicit")
        # Not a provider prefix. An Ollama tag (`qwen2.5-coder:32b`, `llama3:latest`) has a
        # version-like suffix; anything else with a colon is a typo in the provider name.
        if not _OLLAMA_TAG_RE.match(rest.strip()) and default_provider != "ollama":
            raise UnknownProviderError(
                f"Unknown LLM provider '{prefix.strip()}' in '{text}'. Known providers: "
                f"{', '.join(sorted(providers))}"
            )

    if lowered in MODEL_ALIASES:
        provider_name, model = MODEL_ALIASES[lowered]
        return ModelChoice(providers[provider_name], model, "alias")

    if lowered in providers:
        spec = providers[lowered]
        return ModelChoice(spec, spec.default_model, "provider")

    if default_provider and default_provider in providers:
        spec = providers[default_provider]
        return ModelChoice(spec, spec.models.get(lowered, value), "inferred")

    for prefixes, provider_name in _PREFIX_TO_PROVIDER:
        if lowered.startswith(prefixes):
            spec = providers[provider_name]
            return ModelChoice(spec, spec.models.get(lowered, value), "inferred")

    if not _MODEL_RE.match(value):
        raise UnknownProviderError(
            f"Cannot resolve model '{text}'. Use provider:model with one of: "
            f"{', '.join(sorted(providers))}"
        )
    return ModelChoice(providers["ollama"], value, "inferred")


# --------------------------------------------------------------------------- credentials & clients
def api_key_for(spec: ProviderSpec) -> Optional[str]:
    for env_name in spec.api_key_env:
        value = os.environ.get(env_name)
        if value and value.strip():
            return value.strip()
    return None


def is_configured(spec: ProviderSpec) -> bool:
    """A cloud provider is configured when one of its key variables is set; Ollama always is."""
    return not spec.needs_api_key or api_key_for(spec) is not None


def base_url_host(spec: ProviderSpec) -> str:
    """Host part of the endpoint, safe to log and to record in provenance."""
    if not spec.base_url:
        return {"anthropic": "api.anthropic.com", "openai": "api.openai.com"}.get(spec.kind, "")
    try:
        return urlparse(spec.base_url).hostname or ""
    except ValueError:
        return ""


def make_client(
    spec: ProviderSpec, *, async_client: bool = False, timeout: Optional[int] = None
) -> Any:
    """Build the SDK client for ``spec`` (lazy imports; Ollama uses plain HTTP, not a client).

    Raises ``ImportError`` when the SDK extra is not installed and ``RuntimeError`` when
    the provider's key variable is not set, naming the provider in both cases.
    """
    if spec.kind == "ollama":
        raise RuntimeError("Ollama is called over HTTP; there is no SDK client to build")
    key = api_key_for(spec)
    if key is None:
        raise RuntimeError(
            f"{spec.display_name}: no API key found; set {' or '.join(spec.api_key_env)}"
        )
    kwargs: Dict[str, Any] = {"api_key": key, "timeout": timeout or spec.timeout}
    if spec.base_url:
        kwargs["base_url"] = spec.base_url
    if spec.kind == "anthropic":
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                f"{spec.display_name} needs the anthropic SDK: pip install anthropic"
            ) from exc
        return anthropic.AsyncAnthropic(**kwargs) if async_client else anthropic.Anthropic(**kwargs)
    try:
        import openai
    except ImportError as exc:
        raise ImportError(
            f"{spec.display_name} is OpenAI-compatible and needs the openai SDK: pip install openai"
        ) from exc
    return openai.AsyncOpenAI(**kwargs) if async_client else openai.OpenAI(**kwargs)


def describe_providers() -> list[Dict[str, Any]]:
    """Rows for ``miesc doctor``: never the key itself, only whether one is set."""
    rows = []
    for name, spec in sorted(load_providers().items()):
        rows.append(
            {
                "name": name,
                "label": spec.display_name,
                "kind": spec.kind,
                "host": base_url_host(spec),
                "api_key_env": list(spec.api_key_env),
                "configured": is_configured(spec),
                "default_model": spec.default_model,
                "source": spec.source,
            }
        )
    return rows
