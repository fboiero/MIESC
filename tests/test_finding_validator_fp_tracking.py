import asyncio
import json
from unittest.mock import AsyncMock, patch

from miesc.llm.finding_validator import (
    LLMFindingValidator,
    LLMValidation,
    ValidationResult,
    ValidatorConfig,
)


def finding():
    return {
        "id": "f1",
        "type": "reentrancy",
        "severity": "high",
        "tool": "slither",
        "location": {"file": "C.sol", "line": 10},
        "message": "possible reentrancy",
        "confidence": 0.7,
    }


def test_confirmed_fp_is_tagged_and_retained_for_audit_trail():
    validator = LLMFindingValidator(ValidatorConfig(confirm_false_positives=False))

    async def response(_prompt):
        return json.dumps({"result": "false_positive", "confidence": 0.9, "reasoning": "guarded"})

    with (
        patch.object(validator, "is_available", new=AsyncMock(return_value=True)),
        patch.object(validator, "_call_llm", side_effect=response),
    ):
        kept, validations = asyncio.run(validator.validate_findings_batch([finding()]))

    assert kept == []
    assert len(validations) == 1
    assert validator.filtered_out_findings[0]["status"] == "filtered_fp"
    assert validator.filtered_out_findings[0]["_llm_validation"]["reasoning"] == "guarded"


def test_false_positive_without_reasoning_is_not_filtered():
    validator = LLMFindingValidator()
    validation = validator._parse_response(
        json.dumps({"result": "false_positive", "confidence": 0.9}), "f1"
    )
    assert validation.result == ValidationResult.UNCERTAIN


def test_second_pass_disagreement_keeps_finding():
    validator = LLMFindingValidator()
    responses = iter(
        [
            json.dumps({"result": "false_positive", "confidence": 0.8, "reasoning": "guarded"}),
            json.dumps(
                {
                    "confirms_false_positive": False,
                    "confidence": 0.7,
                    "reasoning": "guard can be bypassed",
                }
            ),
        ]
    )

    async def response(_prompt):
        return next(responses)

    with (
        patch.object(validator, "is_available", new=AsyncMock(return_value=True)),
        patch.object(validator, "_call_llm", side_effect=response),
    ):
        kept, _validations = asyncio.run(validator.validate_findings_batch([finding()]))

    assert kept[0]["_llm_validation"]["result"] == "likely_fp"
    assert validator.filtered_out_findings == []


def test_second_pass_agreement_filters_but_preserves_finding():
    validator = LLMFindingValidator()
    responses = iter(
        [
            json.dumps({"result": "false_positive", "confidence": 0.8, "reasoning": "guarded"}),
            json.dumps(
                {
                    "confirms_false_positive": True,
                    "confidence": 0.85,
                    "reasoning": "confirmed guarded",
                }
            ),
        ]
    )

    async def response(_prompt):
        return next(responses)

    with (
        patch.object(validator, "is_available", new=AsyncMock(return_value=True)),
        patch.object(validator, "_call_llm", side_effect=response),
    ):
        kept, _validations = asyncio.run(validator.validate_findings_batch([finding()]))

    assert kept == []
    assert validator.filtered_out_findings[0]["status"] == "filtered_fp"


def test_cli_provider_dispatch():
    validator = LLMFindingValidator(ValidatorConfig(provider="claude_code", cli_model="opus"))
    with patch("miesc.llm.cli_subscription.call_claude_cli", return_value="OK") as call:
        assert asyncio.run(validator._call_llm("prompt")) == "OK"
    assert call.call_args.kwargs["model"] == "opus"


def test_apply_validation_never_returns_none():
    validator = LLMFindingValidator()
    updated = validator._apply_validation(
        finding(),
        LLMValidation("f1", ValidationResult.FALSE_POSITIVE, 0.9, "guarded"),
    )
    assert updated["status"] == "filtered_fp"
