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


def test_parse_response_accepts_wrapped_json():
    validator = LLMFindingValidator(ValidatorConfig())
    response = """
    Analysis:
    {
        "result": "false_positive",
        "confidence": 0.91,
        "reasoning": "Guarded by onlyOwner.",
        "suggested_severity": null,
        "remediation_hint": null
    }
    """

    validation = validator._parse_response(response, "F-2")

    assert validation.finding_id == "F-2"
    assert validation.result == ValidationResult.FALSE_POSITIVE
    assert validation.confidence == 0.91
    assert validation.reasoning == "Guarded by onlyOwner."


def test_parse_response_maps_simple_is_valid_payload():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"is_valid": false, "confidence": 0.73, "reasoning": "Protected path."}'

    validation = validator._parse_response(response, "F-3")

    assert validation.result == ValidationResult.LIKELY_FP
    assert validation.confidence == 0.73
    assert validation.reasoning == "Protected path."


@pytest.mark.parametrize(
    ("response", "expected_result", "expected_confidence"),
    [
        (
            "This is a false positive because the state is updated first.",
            ValidationResult.LIKELY_FP,
            0.6,
        ),
        (
            "This is a real vulnerability reachable by an attacker.",
            ValidationResult.LIKELY_VALID,
            0.6,
        ),
        ("The model response is inconclusive.", ValidationResult.UNCERTAIN, 0.5),
    ],
)
def test_parse_response_text_fallback(response, expected_result, expected_confidence):
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response(response, "F-4")

    assert validation.result == expected_result
    assert validation.confidence == expected_confidence
    assert validation.reasoning == response
