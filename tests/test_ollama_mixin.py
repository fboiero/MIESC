"""Unit tests for the shared OllamaCallMixin timeout handling.

These exercise the REAL retry + timeout-detection loop (by mocking
urllib.request.urlopen), unlike the per-adapter tests which mock the call
method itself.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from src.adapters._ollama_mixin import OllamaCallMixin


class _Host(OllamaCallMixin):
    def __init__(self):
        self._timed_out = False


def _ok_response(text: str = '{"findings": []}'):
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = json.dumps({"response": text}).encode("utf-8")
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


def test_final_timeout_sets_flag_and_returns_none():
    host = _Host()
    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
        out = host._ollama_generate(
            "p", url="http://x/api/generate", model="m", timeout=10, max_attempts=1
        )
    assert out is None
    assert host._timed_out is True


def test_success_does_not_flag_timeout():
    host = _Host()
    with patch("urllib.request.urlopen", return_value=_ok_response('{"response":"ok"}')):
        out = host._ollama_generate(
            "p", url="http://x/api/generate", model="m", timeout=10, max_attempts=1
        )
    assert out  # non-empty response text
    assert host._timed_out is False


def test_recovered_retry_does_not_flag_timeout():
    host = _Host()
    # First attempt times out, second succeeds -> NOT flagged as timed out.
    with patch(
        "urllib.request.urlopen",
        side_effect=[TimeoutError("timed out"), _ok_response('{"response":"ok"}')],
    ):
        out = host._ollama_generate(
            "p",
            url="http://x/api/generate",
            model="m",
            timeout=10,
            max_attempts=2,
            retry_delay=0,
        )
    assert out
    assert host._timed_out is False
