"""Helpers for selecting installed Ollama models."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Iterable, List, Optional, Union

from src.core.llm_config import get_ollama_host

logger = logging.getLogger(__name__)


def list_ollama_models(timeout: int = 5) -> List[str]:
    """Return installed Ollama model names exactly as reported by /api/tags."""
    tags_url = f"{get_ollama_host()}/api/tags"
    req = urllib.request.Request(tags_url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            return []
        data = json.loads(resp.read().decode("utf-8"))
    return [m.get("name", "") for m in data.get("models", []) if m.get("name")]


def select_ollama_model(
    preferred: Iterable[str],
    *,
    installed: Optional[Iterable[str]] = None,
    fallback: Optional[Union[str, Iterable[str]]] = None,
) -> str:
    """Select the first installed model matching exact name or family prefix."""
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
        selected = models[0] if models else ""
    if selected:
        logger.warning("No preferred Ollama model found; using %s", selected)
    return selected
