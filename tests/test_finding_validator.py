import aiohttp
import pytest

from src.llm.finding_validator import (
    LLMFindingValidator,
    LLMValidation,
    ValidationResult,
    ValidatorConfig,
    validate_findings_sync,
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
@pytest.mark.parametrize(
    "payload",
    [
        ["not a dict"],
        {"models": "not a list"},
        {"models": ["not a dict", {"name": ["not text"]}]},
    ],
)
async def test_is_available_returns_false_for_malformed_tags_payload(monkeypatch, payload):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return payload

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["200", True, None])
async def test_is_available_returns_false_for_malformed_response_status(monkeypatch, status):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            raise AssertionError("malformed status should short-circuit before JSON parsing")

    FakeResponse.status = status

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
async def test_is_available_trims_model_names(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    configured_model = validator.config.model

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": [{"name": f" {configured_model} "}, {"name": "  "}]}

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is True


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


@pytest.mark.asyncio
async def test_validate_finding_uses_defaults_for_malformed_location(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}
    finding = {
        "id": "F-1b",
        "type": "reentrancy",
        "severity": "high",
        "location": ["Bank.sol", 42],
        "message": "External call before state update",
    }

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    validation = await validator.validate_finding(finding, "contract Bank {}")

    assert validation.finding_id == "F-1b"
    assert validation.result == ValidationResult.VALID
    assert "- **Location**: unknown:0" in captured["prompt"]


@pytest.mark.asyncio
async def test_validate_finding_defaults_malformed_prompt_scalar_fields(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}
    finding = {
        "id": ["F-1c"],
        "type": {"name": "reentrancy"},
        "severity": True,
        "tool": ["slither"],
        "location": {"file": {"path": "Bank.sol"}, "line": False},
        "message": ["External call before state update"],
        "description": {"text": "fallback"},
    }

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    validation = await validator.validate_finding(finding, "contract Bank {}")

    assert validation.finding_id == "unknown"
    assert "- **Type**: unknown" in captured["prompt"]
    assert "- **Reported Severity**: unknown" in captured["prompt"]
    assert "- **Tool**: unknown" in captured["prompt"]
    assert "- **Location**: unknown:0" in captured["prompt"]
    assert "- **Message**: No message" in captured["prompt"]
    assert "['F-1c']" not in captured["prompt"]
    assert "{'name': 'reentrancy'}" not in captured["prompt"]
    assert "True" not in captured["prompt"]


@pytest.mark.asyncio
async def test_validate_finding_uses_valid_description_when_message_missing(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {
            "id": "F-1d",
            "type": "reentrancy",
            "severity": "high",
            "tool": "slither",
            "description": "External call before state update",
        },
        "contract Bank {}",
    )

    assert "- **Message**: External call before state update" in captured["prompt"]


@pytest.mark.asyncio
async def test_call_ollama_returns_empty_string_for_non_string_response(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"response": ["not text"]}

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [["not a dict"], "not a dict", None])
async def test_call_ollama_returns_empty_string_for_non_object_payload(monkeypatch, payload):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return payload

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == ""


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


def test_parse_response_defaults_malformed_finding_id():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response('{"result": "valid", "confidence": 0.8}', ["F-2"])

    assert validation.finding_id == "unknown"
    assert validation.result == ValidationResult.VALID


def test_parse_response_maps_simple_is_valid_payload():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"is_valid": false, "confidence": 0.73, "reasoning": "Protected path."}'

    validation = validator._parse_response(response, "F-3")

    assert validation.result == ValidationResult.LIKELY_FP
    assert validation.confidence == 0.73
    assert validation.reasoning == "Protected path."


def test_parse_response_normalizes_result_enum_text():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"result": " FALSE-POSITIVE ", "confidence": 0.73, "reasoning": "Guarded."}'

    validation = validator._parse_response(response, "F-3a")

    assert validation.result == ValidationResult.FALSE_POSITIVE
    assert validation.confidence == 0.73


def test_parse_response_ignores_non_bool_is_valid_payload():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"is_valid": "false", "confidence": 0.73, "reasoning": "String flag."}'

    validation = validator._parse_response(response, "F-3b")

    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.confidence == 0.73
    assert validation.reasoning == "String flag."


def test_parse_response_repairs_common_llm_json_errors():
    validator = LLMFindingValidator(ValidatorConfig())
    response = """
    ```json
    {
        result: "likely_valid",
        confidence: 0.82,
        reasoning: "State update happens after the external call",
    }
    ```
    """

    validation = validator._parse_response(response, "F-4")

    assert validation.result == ValidationResult.LIKELY_VALID
    assert validation.confidence == 0.82
    assert validation.reasoning == "State update happens after the external call"


def test_parse_response_repairs_invalid_backslash_escapes():
    validator = LLMFindingValidator(ValidatorConfig())
    response = r'{"result": "valid", "confidence": 0.77, "reasoning": "pattern \d+ matched"}'

    validation = validator._parse_response(response, "F-5")

    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.77
    assert validation.reasoning == r"pattern \d+ matched"


def test_parse_response_defaults_malformed_confidence():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"result": "valid", "confidence": ["high"], "reasoning": "Confirmed."}'

    validation = validator._parse_response(response, "F-5b")

    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.5
    assert validation.reasoning == "Confirmed."


@pytest.mark.parametrize("confidence", ['"nan"', '"inf"', -0.1, 1.5, "true", "false"])
def test_parse_response_defaults_non_finite_or_out_of_range_confidence(confidence):
    validator = LLMFindingValidator(ValidatorConfig())
    response = f'{{"result": "valid", "confidence": {confidence}, "reasoning": "Confirmed."}}'

    validation = validator._parse_response(response, "F-5d")

    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.5


def test_parse_response_defaults_malformed_text_fields():
    validator = LLMFindingValidator(ValidatorConfig())
    response = """
    {
        "result": "valid",
        "confidence": 0.8,
        "reasoning": ["not text"],
        "suggested_severity": ["HIGH"],
        "remediation_hint": {"fix": "use CEI"}
    }
    """

    validation = validator._parse_response(response, "F-5c")

    assert validation.result == ValidationResult.VALID
    assert validation.reasoning == "No reasoning provided"
    assert validation.suggested_severity is None
    assert validation.remediation_hint is None


def test_parse_response_strips_blank_optional_text_fields():
    validator = LLMFindingValidator(ValidatorConfig())
    response = (
        '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed.", '
        '"suggested_severity": " HIGH ", "remediation_hint": "  "}'
    )

    validation = validator._parse_response(response, "F-5b")

    assert validation.suggested_severity == "HIGH"
    assert validation.remediation_hint is None


def test_parse_response_bounds_reasoning_text():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"result": "valid", "confidence": 0.8, "reasoning": "' + ("x" * 2500) + '"}'

    validation = validator._parse_response(response, "F-5e")

    assert validation.result == ValidationResult.VALID
    assert validation.reasoning == "x" * 2000


def test_parse_response_bounds_optional_text_fields():
    validator = LLMFindingValidator(ValidatorConfig())
    response = (
        '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed.", '
        '"remediation_hint": "' + ("x" * 700) + '"}'
    )

    validation = validator._parse_response(response, "F-5f")

    assert validation.remediation_hint == "x" * 500


def test_parse_response_accepts_single_object_array_payload():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response('[{"result": "valid", "confidence": 0.9}]', "F-6")

    assert validation.finding_id == "F-6"
    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.9


def test_parse_response_bounds_confidence_from_single_object_array_payload():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response('[{"result": "valid", "confidence": 1.7}]', "F-6b")

    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.5


def test_parse_response_falls_back_for_non_object_json():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response('[{"result": "valid"}, {"result": "likely_fp"}]', "F-6c")

    assert validation.finding_id == "F-6c"
    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.confidence == 0.5


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


def test_parse_response_text_fallback_defaults_malformed_reasoning():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response(["not", "text"], "F-7b")

    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.reasoning == "Parse error"


def test_init_applies_environment_overrides(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.local:11434")
    monkeypatch.setenv("MIESC_LLM_MODEL", "local-model:latest")

    validator = LLMFindingValidator(ValidatorConfig())

    assert validator.config.ollama_host == "http://ollama.local:11434"
    assert validator.config.model == "local-model:latest"


def test_init_preserves_explicit_config_over_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.local:11434")
    monkeypatch.setenv("MIESC_LLM_MODEL", "local-model:latest")
    config = ValidatorConfig(
        ollama_host="http://explicit.local:11434",
        model="explicit-model",
        enabled=False,
    )

    validator = LLMFindingValidator(config)

    assert validator.config.ollama_host == "http://explicit.local:11434"
    assert validator.config.model == "explicit-model"
    assert validator.config.enabled is False
    assert config.model == "explicit-model"


def test_init_normalizes_endpoint_model_and_batch_config():
    validator = LLMFindingValidator(
        ValidatorConfig(
            ollama_host=" http://ollama.local:11434 ",
            model=" local-model ",
            batch_size=0,
        )
    )

    assert validator.config.ollama_host == "http://ollama.local:11434"
    assert validator.config.model == "local-model"
    assert validator.config.batch_size == ValidatorConfig().batch_size


@pytest.mark.parametrize("timeout", [0, -1, True, ["60"]])
def test_init_defaults_malformed_timeout_config(timeout):
    validator = LLMFindingValidator(ValidatorConfig(timeout_seconds=timeout))

    assert validator.config.timeout_seconds == ValidatorConfig().timeout_seconds


@pytest.mark.parametrize("min_severity", [None, ["high"], "urgent"])
def test_init_defaults_malformed_min_severity_config(min_severity):
    validator = LLMFindingValidator(ValidatorConfig(min_severity_to_validate=min_severity))

    assert validator.config.min_severity_to_validate == ValidatorConfig().min_severity_to_validate
    assert validator.should_validate({"severity": "medium"}) is True


def test_init_normalizes_min_severity_config():
    validator = LLMFindingValidator(ValidatorConfig(min_severity_to_validate=" HIGH "))

    assert validator.config.min_severity_to_validate == "high"
    assert validator.should_validate({"severity": "medium"}) is False


def test_should_validate_respects_enabled_flag_and_min_severity():
    disabled = LLMFindingValidator(ValidatorConfig(enabled=False))
    high_only = LLMFindingValidator(ValidatorConfig(min_severity_to_validate="high"))

    assert disabled.should_validate({"severity": "critical"}) is False
    assert high_only.should_validate({"severity": "medium"}) is False
    assert high_only.should_validate({"severity": "HIGH"}) is True
    assert high_only.should_validate({"severity": "critical"}) is True
    assert high_only.should_validate({"severity": "unknown"}) is False
    assert high_only.should_validate({"severity": ["HIGH"]}) is False
    assert high_only.should_validate(["not", "a", "finding"]) is False


@pytest.mark.parametrize(
    ("validation", "expected_confidence", "filtered", "severity_adjusted"),
    [
        (
            LLMValidation("F-1", ValidationResult.VALID, 0.9, "confirmed"),
            0.85,
            False,
            False,
        ),
        (
            LLMValidation("F-1", ValidationResult.LIKELY_VALID, 0.8, "likely"),
            0.75,
            False,
            False,
        ),
        (
            LLMValidation("F-1", ValidationResult.LIKELY_FP, 0.7, "weak signal"),
            0.42,
            False,
            False,
        ),
        (
            LLMValidation("F-1", ValidationResult.UNCERTAIN, 0.5, "unclear"),
            0.7,
            False,
            False,
        ),
        (
            LLMValidation("F-1", ValidationResult.FALSE_POSITIVE, 0.95, "not real"),
            None,
            True,
            False,
        ),
        (
            LLMValidation(
                "F-1",
                ValidationResult.VALID,
                0.9,
                "confirmed",
                suggested_severity="CRITICAL",
            ),
            0.85,
            False,
            True,
        ),
    ],
)
def test_apply_validation_updates_or_filters_findings(
    validation, expected_confidence, filtered, severity_adjusted
):
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": 0.7}

    updated = validator._apply_validation(finding, validation)

    if filtered:
        assert updated is None
        return

    assert updated is not finding
    assert updated["confidence"] == pytest.approx(expected_confidence)
    assert updated["_llm_validation"]["result"] == validation.result.value
    assert updated["_llm_validation"]["reasoning"] == validation.reasoning
    assert updated["_llm_validation"].get("severity_adjusted", False) is severity_adjusted


def test_apply_validation_defaults_malformed_original_confidence():
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": ["high"]}
    validation = LLMValidation("F-1", ValidationResult.VALID, 0.9, "confirmed")

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["confidence"] == pytest.approx(0.85)


@pytest.mark.parametrize("confidence", ["nan", float("inf"), -0.1, 1.5])
def test_apply_validation_defaults_non_finite_or_out_of_range_original_confidence(confidence):
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": confidence}
    validation = LLMValidation("F-1", ValidationResult.LIKELY_FP, 0.9, "weak signal")

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["confidence"] == pytest.approx(0.42)


def test_apply_validation_ignores_unknown_suggested_severity():
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": 0.7}
    validation = LLMValidation(
        "F-1",
        ValidationResult.VALID,
        0.9,
        "confirmed",
        suggested_severity="urgent",
    )

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["_llm_validation"].get("severity_adjusted", False) is False


def test_apply_validation_handles_malformed_current_severity():
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": ["high"], "confidence": 0.7}
    validation = LLMValidation(
        "F-1",
        ValidationResult.VALID,
        0.9,
        "confirmed",
        suggested_severity="critical",
    )

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["_llm_validation"]["severity_adjusted"] is True


@pytest.mark.parametrize("validation_time_ms", [True, -1, float("inf"), ["12"]])
def test_apply_validation_defaults_malformed_validation_time(validation_time_ms):
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": 0.7}
    validation = LLMValidation(
        "F-1",
        ValidationResult.VALID,
        0.9,
        "confirmed",
        validation_time_ms=validation_time_ms,
    )

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["_llm_validation"]["validation_time_ms"] == 0


def test_apply_validation_preserves_valid_validation_time():
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "F-1", "severity": "high", "confidence": 0.7}
    validation = LLMValidation(
        "F-1",
        ValidationResult.VALID,
        0.9,
        "confirmed",
        validation_time_ms=12.9,
    )

    updated = validator._apply_validation(finding, validation)

    assert updated is not None
    assert updated["_llm_validation"]["validation_time_ms"] == 12


def test_get_statistics_reports_counts_and_config():
    validator = LLMFindingValidator(ValidatorConfig(model="test-model", enabled=False))
    validator._validated_count = 4
    validator._fp_detected_count = 1

    stats = validator.get_statistics()

    assert stats["validated_count"] == 4
    assert stats["fp_detected_count"] == 1
    assert stats["fp_rate"] == 0.25
    assert stats["config"] == {
        "model": "test-model",
        "min_severity": "medium",
        "enabled": False,
    }


def test_get_statistics_avoids_division_by_zero():
    validator = LLMFindingValidator(ValidatorConfig())

    assert validator.get_statistics()["fp_rate"] == 0


def test_validate_findings_sync_rejects_malformed_findings_container(monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(
            "src.llm.finding_validator.LLMFindingValidator",
            lambda *_args, **_kwargs: pytest.fail("validator should not be constructed"),
        )

        validated, validations = validate_findings_sync({"id": "F-1"})

    assert validated == []
    assert validations == []


def test_get_statistics_defaults_mutated_malformed_config_metadata():
    validator = LLMFindingValidator(ValidatorConfig(model="test-model", enabled=True))
    validator.config.model = ["test-model"]
    validator.config.min_severity_to_validate = {"level": "high"}
    validator.config.enabled = "yes"

    stats = validator.get_statistics()

    assert stats["config"] == {
        "model": ValidatorConfig().model,
        "min_severity": ValidatorConfig().min_severity_to_validate,
        "enabled": False,
    }


@pytest.mark.asyncio
async def test_validate_finding_success_updates_counters(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    async def fake_call(prompt):
        assert "External call before state update" in prompt
        return '{"result": "false_positive", "confidence": 0.9, "reasoning": "guarded"}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    validation = await validator.validate_finding(
        {
            "id": "F-9",
            "type": "reentrancy",
            "severity": "high",
            "tool": "slither",
            "location": {"file": "Vault.sol", "line": 12},
            "message": "External call before state update",
        },
        code_context="contract Vault {}",
        contract_context="mainnet vault",
    )

    assert validation.result == ValidationResult.FALSE_POSITIVE
    assert validation.validation_time_ms >= 0
    assert validator.get_statistics()["validated_count"] == 1
    assert validator.get_statistics()["fp_detected_count"] == 1


@pytest.mark.asyncio
async def test_validate_findings_batch_skips_when_disabled():
    validator = LLMFindingValidator(ValidatorConfig(enabled=False))
    findings = [{"id": "F-1", "severity": "critical"}]

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated is findings
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_skips_when_unavailable(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    findings = [{"id": "F-1", "severity": "critical"}]

    async def unavailable():
        return False

    monkeypatch.setattr(validator, "is_available", unavailable)

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated is findings
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_returns_original_when_nothing_matches(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(min_severity_to_validate="high"))
    findings = [{"id": "F-1", "severity": "low"}]

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated is findings
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_applies_results_and_preserves_unvalidated(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(batch_size=1))
    findings = [
        {
            "id": "A",
            "severity": "high",
            "confidence": 0.6,
            "location": {"file": "A.sol"},
        },
        {
            "id": "B",
            "severity": "critical",
            "confidence": 0.8,
            "location": {"snippet": "contract B {}"},
        },
        {"id": "C", "severity": "low", "confidence": 0.4},
    ]
    seen_contexts = []

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fake_validate(finding, code_context):
        seen_contexts.append((finding["id"], code_context))
        if finding["id"] == "B":
            return LLMValidation(finding["id"], ValidationResult.FALSE_POSITIVE, 0.95, "fp")
        return LLMValidation(finding["id"], ValidationResult.VALID, 0.9, "valid")

    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    validated, validations = await validator.validate_findings_batch(
        findings,
        code_contexts={"A.sol": "contract A {}"},
    )

    assert seen_contexts == [("A", "contract A {}"), ("B", "contract B {}")]
    assert [validation.finding_id for validation in validations] == ["A", "B"]
    assert [finding["id"] for finding in validated] == ["A", "C"]
    assert validated[0]["confidence"] == pytest.approx(0.75)
    assert validated[0]["_llm_validation"]["result"] == "valid"


@pytest.mark.asyncio
async def test_validate_findings_batch_preserves_malformed_entries(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    malformed_entry = ["not", "a", "finding"]
    malformed_severity = {"id": "B", "severity": ["high"]}
    findings = [
        {
            "id": "A",
            "severity": "high",
            "confidence": 0.6,
            "location": ["A.sol"],
        },
        malformed_entry,
        malformed_severity,
    ]
    seen_contexts = []

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fake_validate(finding, code_context):
        seen_contexts.append((finding["id"], code_context))
        return LLMValidation(finding["id"], ValidationResult.VALID, 0.9, "valid")

    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    validated, validations = await validator.validate_findings_batch(
        findings,
        code_contexts={"A.sol": "contract A {}"},
    )

    assert seen_contexts == [("A", "")]
    assert [validation.finding_id for validation in validations] == ["A"]
    assert validated[0]["id"] == "A"
    assert validated[0]["_llm_validation"]["result"] == "valid"
    assert malformed_entry in validated
    assert malformed_severity in validated


@pytest.mark.asyncio
async def test_validate_findings_batch_defaults_malformed_exception_finding_id(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(batch_size=1))
    finding = {"id": ["F-1"], "severity": "high"}

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fail_validate(_finding, _code_context):
        raise RuntimeError("validation exploded")

    monkeypatch.setattr(validator, "validate_finding", fail_validate)

    validated, validations = await validator.validate_findings_batch([finding])

    assert validated == [finding]
    assert validations[0].finding_id == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("findings", [None, {"id": "A"}, "high finding"])
async def test_validate_findings_batch_rejects_malformed_top_level_container(
    monkeypatch, findings
):
    validator = LLMFindingValidator(ValidatorConfig())

    async def available():
        raise AssertionError("availability should not be checked for malformed containers")

    monkeypatch.setattr(validator, "is_available", available)

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated == []
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_ignores_malformed_code_context_values(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    findings = [
        {
            "id": "A",
            "severity": "high",
            "confidence": 0.6,
            "location": {"file": "A.sol", "snippet": "contract fallback {}"},
        }
    ]
    seen_contexts = []

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fake_validate(finding, code_context):
        seen_contexts.append((finding["id"], code_context))
        return LLMValidation(finding["id"], ValidationResult.VALID, 0.9, "valid")

    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    validated, validations = await validator.validate_findings_batch(
        findings,
        code_contexts={"A.sol": ["not", "source"]},
    )

    assert seen_contexts == [("A", "")]
    assert [validation.finding_id for validation in validations] == ["A"]
    assert validated[0]["id"] == "A"


@pytest.mark.asyncio
async def test_validate_findings_batch_records_validation_exceptions(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    finding = {"id": "A", "severity": "high"}

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def raise_validation(_finding, _code_context):
        raise RuntimeError("model crashed")

    monkeypatch.setattr(validator, "validate_finding", raise_validation)

    validated, validations = await validator.validate_findings_batch([finding])

    assert validated == [finding]
    assert validations[0].finding_id == "A"
    assert validations[0].result == ValidationResult.UNCERTAIN
    assert "model crashed" in validations[0].reasoning


def test_validate_findings_sync_delegates_and_closes(monkeypatch):
    events = []

    class FakeValidator:
        def __init__(self, config):
            events.append(("init", config))

        async def validate_findings_batch(self, findings, code_contexts):
            events.append(("validate", findings, code_contexts))
            return ["validated"], ["validation"]

        async def close(self):
            events.append(("close",))

    monkeypatch.setattr("src.llm.finding_validator.LLMFindingValidator", FakeValidator)
    config = ValidatorConfig(model="fake")

    result = validate_findings_sync([{"id": "F-1"}], {"Vault.sol": "code"}, config)

    assert result == (["validated"], ["validation"])
    assert events == [
        ("init", config),
        ("validate", [{"id": "F-1"}], {"Vault.sol": "code"}),
        ("close",),
    ]
