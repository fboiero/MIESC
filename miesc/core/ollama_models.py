"""Helpers for selecting installed Ollama models."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Iterable, List, Optional, Union

from miesc.core.llm_config import get_ollama_host

logger = logging.getLogger(__name__)


def list_ollama_models(timeout: int = 5) -> List[str]:
    """Return installed Ollama model names exactly as reported by /api/tags."""
    tags_url = f"{get_ollama_host()}/api/tags"
    req = urllib.request.Request(tags_url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TypeError) as exc:
        logger.debug("Could not list Ollama models from %s: %s", tags_url, exc)
        return []
    return [m.get("name", "") for m in data.get("models", []) if m.get("name")]


def select_ollama_model(
    preferred: Iterable[str],
    *,
    installed: Optional[Iterable[str]] = None,
    fallback: Optional[Union[str, Iterable[str]]] = None,
) -> str:
    """Select the first installed model matching exact name or family prefix.

    An explicit ``MIESC_LLM_MODEL`` override always wins over the availability
    heuristic (e.g. pinning a run to 14B to avoid loading a huge model that
    thrashes RAM). This mirrors the override honoured by the gptscan/iaudit
    adapters so the escape hatch works consistently across every Ollama path.
    """
    env_model = os.environ.get("MIESC_LLM_MODEL")
    if env_model:
        logger.info("Using MIESC_LLM_MODEL override '%s'", env_model)
        return env_model

    models = list(installed) if installed is not None else list_ollama_models()
    by_lower = {model.lower(): model for model in models}
    fallback_candidates: List[str]
    if fallback is None:
        fallback_candidates = []
    elif isinstance(fallback, str):
        fallback_candidates = [fallback]
    else:
        fallback_candidates = list(fallback)

    for candidate in preferred:
        wanted = candidate.lower()
        if wanted in by_lower:
            return by_lower[wanted]

    for candidate in preferred:
        wanted = candidate.lower()
        for installed_model in models:
            installed_lower = installed_model.lower()
            if installed_lower.startswith(f"{wanted}:") or wanted in installed_lower:
                return installed_model

    selected = ""
    for candidate in fallback_candidates:
        wanted = candidate.lower()
        if wanted in by_lower:
            selected = by_lower[wanted]
            break
        for installed_model in models:
            installed_lower = installed_model.lower()
            if installed_lower.startswith(f"{wanted}:") or wanted in installed_lower:
                selected = installed_model
                break
        if selected:
            break

    if not selected:
        selected = models[0] if models else (fallback_candidates[0] if fallback_candidates else "")
    if selected:
        logger.warning("No preferred Ollama model found; using %s", selected)
    return selected
