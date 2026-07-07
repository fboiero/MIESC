"""
Shared provider health helpers for OpenAI-compatible LLM APIs.
"""

import asyncio
import inspect
import json
import logging
import math
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
        model_id = _model_id_text(model.get("id")) or _model_id_text(model.get("name"))
        if not model_id or model_id in model_ids:
            continue
        model_ids.add(model_id)
        if len(model_ids) >= MAX_MODEL_IDS:
            break
    return model_ids


def _model_list(payload: dict[str, Any]) -> Any:
    """Return supported OpenAI-compatible model list aliases."""
    models = payload.get("data")
    if isinstance(models, list):
        return models
    models = payload.get("models")
    if isinstance(models, list):
        return models
    if isinstance(models, dict):
        nested_data = models.get("data")
        if isinstance(nested_data, list):
            return nested_data
        nested_models = models.get("models")
        if isinstance(nested_models, list):
            return nested_models
        nested_items = models.get("items")
        if isinstance(nested_items, list):
            return nested_items
        nested_model = models.get("model")
        if isinstance(nested_model, list):
            return nested_model
    return None


def _model_id_text(value: Any) -> str:
    """Return model identifiers only from scalar text fields."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    model_id = value.strip() if isinstance(value, str) else ""
    if not model_id or len(model_id) > MAX_MODEL_ID_CHARS:
        return ""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in model_id):
        return ""
    return model_id


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
    base_url = base_url.strip()
    if not _valid_model_base_url(base_url):
        logger.debug("%s model check received malformed endpoint credentials", provider_label)
        return set()
    api_key = api_key.strip()
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
                if not isinstance(status, int):
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
        logger.debug("%s model check failed: %s", provider_label, e)
        return set()


def _authorization_headers(api_key: str) -> dict[str, str]:
    """Build auth headers without exposing credentials to logging paths."""
    if isinstance(api_key, bytes):
        try:
            api_key = api_key.decode("utf-8", errors="replace")
        except Exception:
            return {"Authorization": "Bearer "}
    if not isinstance(api_key, str):
        return {"Authorization": "Bearer "}
    key = api_key.strip()
    if not key or any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
        return {"Authorization": "Bearer "}
    return {"Authorization": f"Bearer {key}"}


def _provider_label(provider_name: Any) -> str:
    """Return a bounded provider label for logs."""
    if isinstance(provider_name, bytes):
        try:
            provider_name = provider_name.decode("utf-8", errors="replace")
        except Exception:
            return "provider"
    label = provider_name.strip() if isinstance(provider_name, str) else ""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in label):
        return "provider"
    return (label or "provider")[:80]


def _valid_model_base_url(base_url: str) -> bool:
    """Accept only HTTP(S) provider URLs without embedded credentials."""
    parsed = urlsplit(base_url)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and not (parsed.username or parsed.password)
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in base_url)
    )
