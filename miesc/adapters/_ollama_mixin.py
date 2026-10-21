"""Shared Ollama HTTP caller for LLM adapters.

All LLM-layer adapters (gptlens, iaudit, llmsmartaudit, llamaaudit, gptscan,
smartllm) talk to the same Ollama ``/api/generate`` endpoint and need the same
behaviour around timeouts: a request killed by the clock is NOT a clean
"no findings" result, so it must surface distinctly instead of being masked as
a successful empty analysis.

Before this mixin each adapter reimplemented (and subtly diverged on) that
retry + timeout-detection loop. Centralising it here:

- guarantees consistent timeout handling across the whole LLM layer, and
- sets ``self._timed_out`` on a FINAL clock-kill (one a retry recovers from is
  not flagged), which adapters read in ``analyze()`` to report
  ``status="timeout"``.

Mix it in BEFORE the adapter base, e.g.::

    class GPTLensAdapter(OllamaCallMixin, ToolAdapter):
        ...
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, cast

logger = logging.getLogger(__name__)

# Returned to callers that distinguish "the call failed" from a real empty
# response. Adapters that historically returned "" can pass empty_return="".
_DEFAULT_OPTIONS: Dict[str, Any] = {"temperature": 0.1, "num_ctx": 8192}

# Ask Ollama for native JSON output (``"format": "json"``) so the model returns
# a valid document instead of prose the extractor must repair. Opt-in via
# MIESC_OLLAMA_FORMAT_JSON=1 until it is measured on the full LLM profile; the
# shared extractor stays as the safety net either way.
_FORMAT_JSON_ENV = "MIESC_OLLAMA_FORMAT_JSON"


def ollama_format_json_default() -> bool:
    """True when MIESC_OLLAMA_FORMAT_JSON is set to a truthy value."""
    return os.environ.get(_FORMAT_JSON_ENV, "").strip().lower() in ("1", "true", "yes", "on")


class OllamaCallMixin:
    """Provides a single, timeout-aware Ollama ``/api/generate`` caller.

    The host adapter must define ``self._timed_out`` (reset per run in its
    ``analyze``); this mixin only ever sets it to ``True`` on a final timeout.
    """

    def _ollama_generate(
        self,
        prompt: str,
        *,
        url: str,
        model: str,
        timeout: int,
        options: Optional[Dict[str, Any]] = None,
        max_attempts: int = 1,
        retry_delay: float = 2.0,
        log_prefix: str = "Ollama",
        format_json: Optional[bool] = None,
    ) -> Optional[str]:
        """POST ``prompt`` to Ollama and return the response text, or ``None``.

        ``format_json`` adds Ollama's ``"format": "json"`` (native structured
        output); ``None`` follows ``MIESC_OLLAMA_FORMAT_JSON``.

        On a final timeout failure (after exhausting ``max_attempts``) sets
        ``self._timed_out = True``. A timeout on an attempt that a later retry
        recovers from does NOT flag the run.
        """
        body: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options or dict(_DEFAULT_OPTIONS),
        }
        if format_json is None:
            format_json = ollama_format_json_default()
        if format_json:
            body["format"] = "json"
        payload = json.dumps(body).encode("utf-8")

        # Only a FINAL timeout failure marks the run as timed out.
        last_error_timeout = False
        for attempt in range(1, max_attempts + 1):
            last_error_timeout = False
            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        text = json.loads(resp.read().decode("utf-8")).get("response", "")
                        if text:
                            return cast(Optional[str], text)
                        logger.warning("%s: empty response (attempt %d)", log_prefix, attempt)
                    else:
                        logger.warning(
                            "%s: Ollama returned status %d (attempt %d)",
                            log_prefix,
                            resp.status,
                            attempt,
                        )
            except TimeoutError as e:
                last_error_timeout = True
                logger.warning(
                    "%s: Ollama timed out after %ss (attempt %d): %s",
                    log_prefix,
                    timeout,
                    attempt,
                    e,
                )
            except urllib.error.URLError as e:
                if isinstance(e.reason, TimeoutError) or "timed out" in str(e.reason):
                    last_error_timeout = True
                logger.warning("%s: Ollama URL error (attempt %d): %s", log_prefix, attempt, e)
            except json.JSONDecodeError as e:
                logger.warning(
                    "%s: invalid JSON from Ollama (attempt %d): %s", log_prefix, attempt, e
                )
            except Exception as e:  # noqa: BLE001 - last-resort, logged
                logger.error("%s: unexpected Ollama error (attempt %d): %s", log_prefix, attempt, e)

            if attempt < max_attempts:
                time.sleep(retry_delay)

        if last_error_timeout:
            self._timed_out = True
        return None
