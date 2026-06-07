import aiohttp
import pytest

from src.llm.finding_validator import (
    LLMFindingValidator,
    ValidationResult,
    ValidatorConfig,
)


@pytest.mark.asyncio
async def test_is_available_returns_false_on_client_error(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeSession:
        def get(self, *_args, **_kwargs):
            raise aiohttp.ClientError("connection refused")

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
async def test_validate_finding_degrades_to_uncertain_on_runtime_error(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {
        "id": "F-1",
        "type": "reentrancy",
        "severity": "high",
        "location": {"file": "Bank.sol", "line": 42},
        "message": "External call before state update",
    }

    async def fail_call(_prompt):
        raise RuntimeError("Ollama API error 500: failed")

    monkeypatch.setattr(validator, "_call_ollama", fail_call)

    validation = await validator.validate_finding(finding, "contract Bank {}")

    assert validation.finding_id == "F-1"
    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.confidence == 0.5
    assert "Ollama API error" in validation.reasoning
