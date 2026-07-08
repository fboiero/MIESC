"""
Shared provider health helpers for OpenAI-compatible LLM APIs.
"""

import asyncio
import inspect
import json
import logging
import math
from collections.abc import Mapping
from typing import Any, Set
from urllib.parse import urlsplit

import aiohttp

logger = logging.getLogger(__name__)
MAX_MODEL_ID_CHARS = 200
MAX_MODEL_IDS = 1000

PROVIDER_HEALTH_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    TimeoutError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)


def _safe_text(value: Any, *, limit: int = 200) -> str:
    """Return bounded scalar text with control characters removed."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(value, str):
        return ""
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in "\u2028\u2029" for ch in value):
        return ""
    try:
        text = value.strip()
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return ""
    if not text:
        return ""
    if len(text) > limit:
        text = text[:limit]
    return text


def _mapping_get(mapping: Any, key: str, default: Any = None) -> Any:
    """Read mapping keys without trusting hostile mapping subclasses."""
    if not isinstance(mapping, Mapping):
        return default
    try:
        return mapping.get(key, default)
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        return default


def _safe_exception_summary(error: Any) -> str:
    """Return only exception class names for logs, never response bodies."""
    if isinstance(error, BaseException):
        return error.__class__.__name__
    return "unknown"


def extract_openai_compatible_model_ids(payload: Any) -> Set[str]:
    """Extract model identifiers from OpenAI-compatible model list payloads."""
    if not isinstance(payload, dict):
        return set()

    models = _model_list(payload)
    if not isinstance(models, list):
        return set()

    model_ids: Set[str] = set()
    for model in models:
        if not isinstance(model, dict):
            continue
        model_id = _model_id_text(_mapping_get(model, "id")) or _model_id_text(
            _mapping_get(model, "name")
        )
        if not model_id or model_id in model_ids:
            continue
        model_ids.add(model_id)
        if len(model_ids) >= MAX_MODEL_IDS:
            break
    return model_ids


def _model_list(payload: dict[str, Any]) -> Any:
    """Return supported OpenAI-compatible model list aliases."""
    models = _mapping_get(payload, "data")
    if isinstance(models, list):
        return models
    models = _mapping_get(payload, "models")
    if isinstance(models, list):
        return models
    if isinstance(models, Mapping):
        nested_data = _mapping_get(models, "data")
        if isinstance(nested_data, list):
            return nested_data
        nested_models = _mapping_get(models, "models")
        if isinstance(nested_models, list):
            return nested_models
        nested_items = _mapping_get(models, "items")
        if isinstance(nested_items, list):
            return nested_items
        nested_model = _mapping_get(models, "model")
        if isinstance(nested_model, list):
            return nested_model
    return None


def _model_id_text(value: Any) -> str:
    """Return model identifiers only from scalar text fields."""
    text = _safe_text(value, limit=MAX_MODEL_ID_CHARS + 1)
    if not text or len(text) > MAX_MODEL_ID_CHARS:
        return ""
    return text


async def fetch_openai_compatible_model_ids(
    base_url: str,
    api_key: str,
    *,
    timeout: int = 10,
    provider_name: str = "provider",
) -> Set[str]:
    """Fetch model identifiers from an OpenAI-compatible /v1/models endpoint."""
    provider_label = _provider_label(provider_name)
    if not isinstance(base_url, str) or not isinstance(api_key, str):
        logger.debug("%s model check received malformed endpoint credentials", provider_label)
        return set()
    base_url = _safe_text(base_url, limit=2048)
    if not _valid_model_base_url(base_url):
        logger.debug("%s model check received malformed endpoint credentials", provider_label)
        return set()
    api_key = _safe_api_key(api_key)
    if not api_key:
        logger.debug("%s model check received malformed endpoint credentials", provider_label)
        return set()
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        logger.debug("%s model check received malformed timeout", provider_label)
        return set()
    if not math.isfinite(float(timeout)) or timeout <= 0:
        logger.debug("%s model check received malformed timeout", provider_label)
        return set()

    headers = _authorization_headers(api_key)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base_url.rstrip('/')}/v1/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                status = getattr(resp, "status", None)
                if not isinstance(status, int) or isinstance(status, bool):
                    logger.debug("%s model check returned malformed response status", provider_label)
                    return set()
                if status != 200:
                    logger.debug("%s model check failed with status %s", provider_label, status)
                    return set()

                json_method = getattr(resp, "json", None)
                if not callable(json_method):
                    logger.debug("%s model check returned malformed JSON accessor", provider_label)
                    return set()
                raw_payload = json_method()
                payload = await raw_payload if inspect.isawaitable(raw_payload) else raw_payload
                if not isinstance(payload, dict):
                    logger.debug("%s model check returned malformed JSON body", provider_label)
                    return set()
                return extract_openai_compatible_model_ids(payload)
    except PROVIDER_HEALTH_ERRORS as e:
        logger.debug("%s model check failed: %s", provider_label, _safe_exception_summary(e))
        return set()


def _authorization_headers(api_key: str) -> dict[str, str]:
    """Build auth headers without exposing credentials to logging paths."""
    key = _safe_api_key(api_key)
    if not key:
        return {"Authorization": "Bearer "}
    return {"Authorization": f"Bearer {key}"}


def _safe_api_key(api_key: Any) -> str:
    """Return a header-safe API key without truncating oversized credentials."""
    if isinstance(api_key, bytes):
        try:
            api_key = api_key.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(api_key, str):
        return ""
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in "\u2028\u2029" for ch in api_key):
        return ""
    try:
        stripped = api_key.strip()
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return ""
    if len(stripped) > MAX_MODEL_ID_CHARS:
        return ""
    return _safe_text(stripped, limit=MAX_MODEL_ID_CHARS)


def _provider_label(provider_name: Any) -> str:
    """Return a bounded provider label for logs."""
    label = _safe_text(provider_name, limit=80)
    return label or "provider"


def _valid_model_base_url(base_url: str) -> bool:
    """Accept only HTTP(S) provider URLs without embedded credentials."""
    try:
        parsed = urlsplit(base_url)
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and not (parsed.username or parsed.password)
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in base_url)
    )
