"""
Shared provider health helpers for OpenAI-compatible LLM APIs.
"""

import asyncio
import inspect
import json
import logging
import math
from typing import Any, Set

import aiohttp

logger = logging.getLogger(__name__)
MAX_MODEL_ID_CHARS = 200

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

    models = payload.get("data")
    if not isinstance(models, list):
        models = payload.get("models")
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
    return model_ids


def _model_id_text(value: Any) -> str:
    """Return model identifiers only from scalar text fields."""
    model_id = value.strip() if isinstance(value, str) else ""
    if not model_id or len(model_id) > MAX_MODEL_ID_CHARS:
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
    provider_label = provider_name.strip() if isinstance(provider_name, str) else ""
    provider_label = provider_label or "provider"
    if not isinstance(base_url, str) or not isinstance(api_key, str):
        logger.debug("%s model check received malformed endpoint credentials", provider_label)
        return set()
    base_url = base_url.strip()
    if not base_url:
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

    headers = {"Authorization": f"Bearer {api_key}"}
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

                raw_payload = resp.json()
                payload = await raw_payload if inspect.isawaitable(raw_payload) else raw_payload
                if not isinstance(payload, dict):
                    logger.debug("%s model check returned malformed JSON body", provider_label)
                    return set()

                return extract_openai_compatible_model_ids(payload)
    except PROVIDER_HEALTH_ERRORS as e:
        logger.debug("%s model check failed: %s", provider_label, e)
        return set()
