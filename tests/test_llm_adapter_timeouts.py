from __future__ import annotations

import json

from src.adapters.hardhat_adapter import HardhatAdapter
from src.adapters.propertygpt_adapter import PropertyGPTAdapter
from src.adapters.smartllm_adapter import SmartLLMAdapter
from src.adapters.zk_circuit_adapter import ZKCircuitAdapter
from src.core.tool_protocol import ToolStatus


class _FakeResponse:
    status = 200

    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def test_propertygpt_ollama_call_uses_cli_timeout(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResponse({"response": '[{"name":"p","confidence":0.9}]'})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    adapter = PropertyGPTAdapter()
    adapter.ollama_model = "codellama"

    properties = adapter._generate_with_ollama("prompt", timeout=7)

    assert seen["timeout"] == 7
    assert properties == [{"name": "p", "confidence": 0.9}]


def test_smartllm_generator_call_uses_cli_timeout(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResponse({"response": "analysis"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    adapter = SmartLLMAdapter()
    adapter._max_retries = 1

    response = adapter._call_ollama_with_retry("prompt", timeout=9)

    assert seen["timeout"] == 9
    assert response == "analysis"


def test_smartllm_timeout_reports_timeout_status(monkeypatch, tmp_path):
    """C6: a generator call killed by the clock must surface status='timeout',
    NOT a misleading degraded 'success' that masks the missed analysis."""
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")

    adapter = SmartLLMAdapter()
    monkeypatch.setattr(adapter, "is_available", lambda: ToolStatus.AVAILABLE)
    monkeypatch.setattr(adapter, "_get_cached_result", lambda cache_key: None)

    def _timeout(prompt, timeout=300):
        adapter._timed_out = True  # what a real clock-kill sets via the mixin
        return None

    monkeypatch.setattr(adapter, "_call_ollama_with_retry", _timeout)

    result = adapter.analyze(str(contract), timeout=3)

    assert result["status"] == "timeout"
    assert result["findings"] == []
    assert result["metadata"]["timed_out"] is True


def test_smartllm_empty_generator_is_degraded_success(monkeypatch, tmp_path):
    """A non-timeout empty generator response is a real (degraded) success, not
    a timeout."""
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")

    adapter = SmartLLMAdapter()
    monkeypatch.setattr(adapter, "is_available", lambda: ToolStatus.AVAILABLE)
    monkeypatch.setattr(adapter, "_get_cached_result", lambda cache_key: None)
    monkeypatch.setattr(adapter, "_call_ollama_with_retry", lambda prompt, timeout=300: None)

    result = adapter.analyze(str(contract), timeout=3)

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["metadata"]["degraded"] is True
    assert result["metadata"]["degraded_reason"] == "ollama_generator_empty_response"


def test_hardhat_without_project_is_skipped_success(tmp_path, monkeypatch):
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")

    adapter = HardhatAdapter()
    monkeypatch.setattr(adapter, "is_available", lambda: ToolStatus.AVAILABLE)

    result = adapter.analyze(str(contract))

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["metadata"]["skipped"] is True


def test_zk_circuit_solidity_file_is_skipped_success(tmp_path):
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")

    result = ZKCircuitAdapter().analyze(str(contract))

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["metadata"]["skipped"] is True
