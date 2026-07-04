"""
Shared provider health helpers for OpenAI-compatible LLM APIs.
"""

import asyncio
import json
import logging
from typing import Any, Set

import aiohttp

logger = logging.getLogger(__name__)

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
        model_id = model.get("id") or model.get("name")
        if isinstance(model_id, str) and model_id:
            model_ids.add(model_id)
    return model_ids


async def fetch_openai_compatible_model_ids(
    base_url: str,
    api_key: str,
    *,
    timeout: int = 10,
    provider_name: str = "provider",
) -> Set[str]:
    """Fetch model identifiers from an OpenAI-compatible /v1/models endpoint."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base_url.rstrip('/')}/v1/models",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                if resp.status != 200:
                    logger.debug("%s model check failed with status %s", provider_name, resp.status)
                    return set()

                return extract_openai_compatible_model_ids(await resp.json())
    except PROVIDER_HEALTH_ERRORS as e:
        logger.debug("%s model check failed: %s", provider_name, e)
        return set()
