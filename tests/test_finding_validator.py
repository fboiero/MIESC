import aiohttp
import pytest

from src.llm.finding_validator import (
    MAX_VALIDATION_JSON_KEYS,
    MAX_VALIDATION_RESPONSE_CHARS,
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
async def test_is_available_rejects_substring_model_name_match(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="deepseek-coder:6.7b"))

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": [{"name": "not-deepseek-coder-plus:latest"}]}

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
async def test_is_available_accepts_same_model_with_different_tag(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="custom-coder:6.7b"))

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": [{"name": " Custom-Coder:latest "}]}

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is True


@pytest.mark.asyncio
async def test_is_available_rejects_control_char_model_names(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="deepseek-coder:6.7b"))

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": [{"name": "deepseek-coder:6.7b\x7f"}]}

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

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


@pytest.mark.asyncio
@pytest.mark.parametrize("finding", [None, ["not", "a", "finding"], "finding"])
async def test_validate_finding_returns_uncertain_for_malformed_finding_container(
    monkeypatch, finding
):
    validator = LLMFindingValidator(ValidatorConfig())

    async def fail_call(_prompt):
        raise AssertionError("malformed findings should not call Ollama")

    monkeypatch.setattr(validator, "_call_ollama", fail_call)

    validation = await validator.validate_finding(finding)  # type: ignore[arg-type]

    assert validation.finding_id == "unknown"
    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.reasoning == "Malformed finding container"


@pytest.mark.asyncio
async def test_validate_finding_defaults_malformed_code_context(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {"id": "F-code", "type": "reentrancy", "severity": "high"},
        code_context={"bad": "context"},
    )

    assert "{'bad': 'context'}" not in captured["prompt"]
    assert "```solidity\nNot available\n```" in captured["prompt"]


@pytest.mark.asyncio
async def test_validate_finding_bounds_code_context_and_allows_multiline(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}
    code_context = "contract Vault {\n" + ("x" * 1600) + "\n}"

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {"id": "F-code2", "type": "reentrancy", "severity": "high"},
        code_context=code_context,
    )

    assert "contract Vault {\n" in captured["prompt"]
    assert len(captured["prompt"].split("```solidity\n", 1)[1].split("\n```", 1)[0]) == 1500


@pytest.mark.asyncio
async def test_validate_finding_defaults_control_char_contexts(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {"id": "F-code3", "type": "reentrancy", "severity": "high"},
        code_context="contract Vault {}\x00",
        contract_context="mainnet\x7f",
    )

    assert "```solidity\nNot available\n```" in captured["prompt"]
    assert "\n## Contract Context\nNot available\n" in captured["prompt"]


@pytest.mark.asyncio
async def test_validate_finding_handles_malformed_exception_text(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class BadException(RuntimeError):
        def __str__(self):
            raise RuntimeError("bad str")

    async def fail_call(_prompt):
        raise BadException()

    monkeypatch.setattr(validator, "_call_ollama", fail_call)

    validation = await validator.validate_finding(
        {"id": "F-bad", "type": "reentrancy", "severity": "high"},
        code_context="contract Vault {}",
    )

    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.reasoning == "Validation failed: Exception: BadException"


@pytest.mark.asyncio
async def test_validate_finding_sanitizes_exception_reason_control_chars(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    async def fail_call(_prompt):
        raise RuntimeError("bad\nfailure")

    monkeypatch.setattr(validator, "_call_ollama", fail_call)

    validation = await validator.validate_finding(
        {"id": "F-bad2", "type": "reentrancy", "severity": "high"},
        code_context="contract Vault {}",
    )

    assert validation.reasoning == "Validation failed: Exception: RuntimeError"


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
async def test_validate_finding_defaults_malformed_contract_context(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {"id": "F-1e", "type": "reentrancy", "severity": "high"},
        "contract Bank {}",
        contract_context={"bad": "context"},
    )

    assert "{'bad': 'context'}" not in captured["prompt"]


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


@pytest.mark.asyncio
async def test_call_ollama_sanitizes_non_200_error_text(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 500

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def text(self):
            return "bad\n" + ("x" * 500)

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    with pytest.raises(RuntimeError) as excinfo:
        await validator._call_ollama("prompt")

    assert str(excinfo.value) == "Ollama API error 500: error"


@pytest.mark.asyncio
async def test_call_ollama_uses_normalized_payload_config(monkeypatch):
    validator = LLMFindingValidator(
        ValidatorConfig(model=" model ", temperature=0.5, max_tokens=256)
    )
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"response": "ok"}

    class FakeSession:
        def post(self, *_args, **kwargs):
            captured["payload"] = kwargs["json"]
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == "ok"
    assert captured["payload"]["model"] == "model"
    assert captured["payload"]["options"] == {"temperature": 0.5, "num_predict": 256}


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


def test_parse_response_ignores_unknown_suggested_severity():
    validator = LLMFindingValidator(ValidatorConfig())
    response = (
        '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed.", '
        '"suggested_severity": "urgent"}'
    )

    validation = validator._parse_response(response, "F-5g")

    assert validation.result == ValidationResult.VALID
    assert validation.suggested_severity is None


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


def test_init_defaults_malformed_config_container(monkeypatch):
    monkeypatch.delenv("MIESC_LLM_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    validator = LLMFindingValidator({"model": "bad"})  # type: ignore[arg-type]

    assert validator.config == ValidatorConfig()


def test_init_defaults_partial_config_like_object():
    class PartialConfig:
        model = " partial-model "
        enabled = False

    validator = LLMFindingValidator(PartialConfig())  # type: ignore[arg-type]

    assert validator.config.model == "partial-model"
    assert validator.config.enabled is False
    assert validator.config.ollama_host == ValidatorConfig().ollama_host


@pytest.mark.parametrize("temperature", [True, -0.1, 2.1, float("inf"), ["0.1"]])
def test_init_defaults_malformed_temperature_config(temperature):
    validator = LLMFindingValidator(ValidatorConfig(temperature=temperature))

    assert validator.config.temperature == ValidatorConfig().temperature


@pytest.mark.parametrize("temperature", [0, 0.5, 2])
def test_init_preserves_valid_temperature_config(temperature):
    validator = LLMFindingValidator(ValidatorConfig(temperature=temperature))

    assert validator.config.temperature == float(temperature)


@pytest.mark.parametrize("max_tokens", [0, -1, True, 1.5, ["1024"]])
def test_init_defaults_malformed_max_tokens_config(max_tokens):
    validator = LLMFindingValidator(ValidatorConfig(max_tokens=max_tokens))

    assert validator.config.max_tokens == ValidatorConfig().max_tokens


def test_init_defaults_malformed_enabled_config():
    validator = LLMFindingValidator(ValidatorConfig(enabled="yes"))  # type: ignore[arg-type]

    assert validator.config.enabled is ValidatorConfig().enabled


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


def test_should_validate_defaults_mutated_malformed_min_severity():
    validator = LLMFindingValidator(ValidatorConfig())
    validator.config.min_severity_to_validate = ["high"]

    assert validator.should_validate({"severity": "medium"}) is True


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


def test_get_statistics_normalizes_control_char_config_text():
    validator = LLMFindingValidator(ValidatorConfig(model="test-model", enabled=True))
    validator.config.model = "  test-model\n"
    validator.config.min_severity_to_validate = " high\t"

    stats = validator.get_statistics()

    assert stats["config"] == {
        "model": "test-model",
        "min_severity": "high",
        "enabled": True,
    }


def test_safe_counter_and_config_text_helpers_handle_mutated_values():
    validator = LLMFindingValidator(ValidatorConfig())

    assert validator._safe_counter("7") == 7
    assert validator._safe_counter(True) == 0
    assert validator._safe_counter(-3) == 0

    validator.config.model = b"  custom-model  "
    assert validator._config_text(validator.config, "model", ValidatorConfig().model) == (
        "custom-model"
    )
    validator.config.enabled = object()
    assert validator._config_enabled(validator.config) is False


def test_parse_optional_text_rejects_control_chars():
    validator = LLMFindingValidator(ValidatorConfig())

    assert validator._parse_optional_text("  remediation hint  ") == "remediation hint"
    assert validator._parse_optional_text("remediation\nhint") is None


def test_parse_text_rejects_control_chars():
    validator = LLMFindingValidator(ValidatorConfig())

    assert validator._parse_text(" remediation hint ", "fallback") == "remediation hint"
    assert validator._parse_text("remediation\nhint", "fallback") == "fallback"


def test_parse_location_line_rejects_control_chars():
    assert LLMFindingValidator._parse_location_line(" 42 ") == "42"
    assert LLMFindingValidator._parse_location_line("4\n2") == 0


@pytest.mark.parametrize("line", ["42:7", "line 42", "abc", "-1"])
def test_parse_location_line_rejects_non_numeric_strings(line):
    assert LLMFindingValidator._parse_location_line(line) == 0


@pytest.mark.parametrize("line", [-1, 10_000_001, "10000001"])
def test_parse_location_line_rejects_negative_or_oversized_values(line):
    assert LLMFindingValidator._parse_location_line(line) == 0


@pytest.mark.asyncio
async def test_validate_finding_defaults_prompt_line_for_non_numeric_string(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    captured = {}

    async def fake_call(prompt):
        captured["prompt"] = prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "Confirmed."}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    await validator.validate_finding(
        {
            "id": "F-line",
            "type": "reentrancy",
            "severity": "high",
            "location": {"file": "Vault.sol", "line": "line 42"},
        },
        code_context="contract Vault {}",
    )

    assert "- **Location**: Vault.sol:0" in captured["prompt"]


def test_parse_confidence_strips_and_rejects_control_chars():
    assert LLMFindingValidator._parse_confidence(" 0.75 ") == 0.75
    assert LLMFindingValidator._parse_confidence("0.75\x7f") == 0.5


def test_parse_suggested_severity_and_exception_reason_sanitize_text():
    assert LLMFindingValidator._parse_suggested_severity("  HIGH  ") == "HIGH"
    assert LLMFindingValidator._parse_suggested_severity("high\n") == "HIGH"
    assert LLMFindingValidator._exception_reason(RuntimeError("  bad failure  ")) == (
        "Exception: bad failure"
    )
    assert LLMFindingValidator._exception_reason(RuntimeError("bad\nfailure")) == (
        "Exception: RuntimeError"
    )


def test_parse_nonnegative_int_accepts_numeric_strings_and_rejects_control_chars():
    assert LLMFindingValidator._parse_nonnegative_int(" 12 ") == 12
    assert LLMFindingValidator._parse_nonnegative_int("12\x7f") == 0
    assert LLMFindingValidator._parse_nonnegative_int("-3") == 0


def test_get_statistics_defaults_malformed_config_container():
    validator = LLMFindingValidator(ValidatorConfig(model="test-model", enabled=True))
    validator.config = {
        "model": ["test-model"],
        "min_severity_to_validate": {"level": "high"},
        "enabled": "yes",
    }

    stats = validator.get_statistics()

    assert stats["config"] == {
        "model": ValidatorConfig().model,
        "min_severity": ValidatorConfig().min_severity_to_validate,
        "enabled": False,
    }


def test_get_statistics_defaults_malformed_counter_state():
    validator = LLMFindingValidator(ValidatorConfig())
    validator._validated_count = ["10"]
    validator._fp_detected_count = 3

    stats = validator.get_statistics()

    assert stats["validated_count"] == 0
    assert stats["fp_detected_count"] == 0
    assert stats["fp_rate"] == 0


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
async def test_validate_findings_batch_handles_malformed_exception_text(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(batch_size=1))
    finding = {"id": "F-1", "severity": "high"}

    class BadException(RuntimeError):
        def __str__(self):
            raise RuntimeError("bad str")

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fail_validate(_finding, _code_context):
        raise BadException()

    monkeypatch.setattr(validator, "validate_finding", fail_validate)

    validated, validations = await validator.validate_findings_batch([finding])

    assert validated == [finding]
    assert validations[0].reasoning == "Exception: BadException"


@pytest.mark.asyncio
@pytest.mark.parametrize("findings", [None, {"id": "A"}, "high finding"])
async def test_validate_findings_batch_rejects_malformed_top_level_container(monkeypatch, findings):
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
async def test_validate_findings_batch_bounds_code_context_values(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    findings = [{"id": "A", "severity": "high", "location": {"file": "A.sol"}}]
    seen_contexts = []

    async def available():
        return True

    monkeypatch.setattr(validator, "is_available", available)

    async def fake_validate(finding, code_context):
        seen_contexts.append((finding["id"], code_context))
        return LLMValidation(finding["id"], ValidationResult.VALID, 0.9, "valid")

    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    await validator.validate_findings_batch(findings, code_contexts={"A.sol": "x" * 2000})

    assert seen_contexts == [("A", "x" * 1500)]


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


def test_init_defaults_config_like_object_when_attribute_access_raises(monkeypatch):
    monkeypatch.delenv("MIESC_LLM_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    class HostileConfig:
        def __getattribute__(self, name):
            if name in {"model", "ollama_host", "batch_size"}:
                raise RuntimeError("boom")
            return super().__getattribute__(name)

    validator = LLMFindingValidator(HostileConfig())  # type: ignore[arg-type]

    assert validator.config == ValidatorConfig()


def test_init_rejects_environment_overrides_with_control_chars(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.local\nbad")
    monkeypatch.setenv("MIESC_LLM_MODEL", "model\u2028bad")

    validator = LLMFindingValidator(ValidatorConfig())

    assert validator.config.ollama_host == ValidatorConfig().ollama_host
    assert validator.config.model == ValidatorConfig().model


def test_init_caps_extreme_numeric_config_values():
    validator = LLMFindingValidator(
        ValidatorConfig(timeout_seconds=601, max_tokens=20_000, batch_size=500)
    )

    assert validator.config.timeout_seconds == ValidatorConfig().timeout_seconds
    assert validator.config.max_tokens == ValidatorConfig().max_tokens
    assert validator.config.batch_size == ValidatorConfig().batch_size


@pytest.mark.asyncio
async def test_is_available_caps_model_list(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="target:latest"))

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {
                "models": [{"name": f"noise-{i}"} for i in range(250)] + [{"name": "target:latest"}]
            }

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
async def test_call_ollama_rejects_malformed_status_and_text_exception(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def text(self):
            raise RuntimeError("bad text")

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    with pytest.raises(RuntimeError, match="malformed status"):
        await validator._call_ollama("prompt")


@pytest.mark.asyncio
async def test_call_ollama_sanitizes_error_text_exception(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 500

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def text(self):
            raise RuntimeError("bad text")

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    with pytest.raises(RuntimeError) as excinfo:
        await validator._call_ollama("prompt")

    assert str(excinfo.value) == "Ollama API error 500: error"


@pytest.mark.asyncio
async def test_call_ollama_bounds_response_text(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"response": "x" * 60_000}

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == "x" * 50_000


def test_parse_response_rejects_unicode_controls_in_text_fields():
    validator = LLMFindingValidator(ValidatorConfig())
    response = (
        '{"result": "valid", "confidence": "0.\u20289", '
        '"reasoning": "bad\u2029reason", "remediation_hint": "bad\u2028hint"}'
    )

    validation = validator._parse_response(response, "F-1")

    assert validation.result == ValidationResult.VALID
    assert validation.confidence == 0.5
    assert validation.reasoning == "No reasoning provided"
    assert validation.remediation_hint is None


def test_parse_response_defaults_control_char_finding_id_and_conflicting_is_valid():
    validator = LLMFindingValidator(ValidatorConfig())
    response = '{"result": "valid", "is_valid": false, "confidence": 0.8}'

    validation = validator._parse_response(response, "F-1\u2028bad")

    assert validation.finding_id == "unknown"
    assert validation.result == ValidationResult.VALID


def test_parse_response_treats_singleton_non_dict_array_as_object_error():
    validator = LLMFindingValidator(ValidatorConfig())

    validation = validator._parse_response('["valid"]', "F-1")

    assert validation.result == ValidationResult.UNCERTAIN
    assert validation.reasoning == "LLM validation response must be a JSON object"


@pytest.mark.asyncio
async def test_validate_finding_handles_hostile_mapping_get_raising(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileFinding(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    async def fake_call(prompt):
        assert "- **Type**: unknown" in prompt
        return '{"result": "valid", "confidence": 0.8, "reasoning": "ok"}'

    monkeypatch.setattr(validator, "_call_ollama", fake_call)

    validation = await validator.validate_finding(HostileFinding({"severity": "high"}))

    assert validation.finding_id == "unknown"
    assert validation.result == ValidationResult.VALID


@pytest.mark.asyncio
async def test_validate_findings_batch_handles_is_available_exception(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())
    findings = [{"id": "F-1", "severity": "high"}]

    async def unavailable():
        raise RuntimeError("availability failed")

    monkeypatch.setattr(validator, "is_available", unavailable)

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated is findings
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_handles_hostile_code_contexts_and_runtime_batch_size(
    monkeypatch,
):
    validator = LLMFindingValidator(ValidatorConfig())
    validator.config.batch_size = 0
    finding = {"id": "F-1", "severity": "high", "location": {"file": "Vault.sol", "snippet": "s"}}
    seen_contexts = []

    class HostileContexts(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    async def available():
        return True

    async def fake_validate(_finding, code_context):
        seen_contexts.append(code_context)
        return LLMValidation("F-1", ValidationResult.VALID, 0.9, "ok")

    monkeypatch.setattr(validator, "is_available", available)
    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    validated, validations = await validator.validate_findings_batch(
        [finding], code_contexts=HostileContexts({"Vault.sol": "contract Vault {}"})
    )

    assert seen_contexts == [""]
    assert validations[0].result == ValidationResult.VALID
    assert validated[0]["_llm_validation"]["result"] == "valid"


@pytest.mark.asyncio
async def test_validate_findings_batch_caps_findings(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(batch_size=50))
    findings = [{"id": f"F-{i}", "severity": "high"} for i in range(505)]
    seen = []

    async def available():
        return True

    async def fake_validate(finding, _code_context):
        seen.append(finding["id"])
        return LLMValidation(finding["id"], ValidationResult.FALSE_POSITIVE, 0.9, "fp")

    monkeypatch.setattr(validator, "is_available", available)
    monkeypatch.setattr(validator, "validate_finding", fake_validate)

    validated, validations = await validator.validate_findings_batch(findings)

    assert validated == []
    assert len(validations) == 500
    assert seen[-1] == "F-499"


def test_apply_validation_defaults_malformed_validation_object():
    validator = LLMFindingValidator(ValidatorConfig())

    class MalformedValidation:
        result = "valid"
        confidence = "bad"
        reasoning = "bad\u2028reason"
        suggested_severity = "HIGH"
        validation_time_ms = "bad"

    updated = validator._apply_validation(
        {"id": "F-1", "severity": "low", "confidence": 0.7}, MalformedValidation()
    )

    assert updated is not None
    assert updated["_llm_validation"] == {
        "result": "uncertain",
        "confidence": 0.5,
        "reasoning": "No reasoning provided",
        "suggested_severity": "HIGH",
        "validation_time_ms": 0,
        "severity_adjusted": True,
    }
    assert updated["confidence"] == 0.7


def test_get_statistics_handles_config_getattr_exceptions():
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileConfig:
        def __getattribute__(self, name):
            if name in {"model", "min_severity_to_validate", "enabled"}:
                raise RuntimeError("boom")
            return super().__getattribute__(name)

    validator.config = HostileConfig()

    assert validator.get_statistics()["config"] == {
        "model": ValidatorConfig().model,
        "min_severity": ValidatorConfig().min_severity_to_validate,
        "enabled": False,
    }


def test_validate_findings_sync_closes_when_batch_raises(monkeypatch):
    events = []

    class FakeValidator:
        def __init__(self, config):
            events.append(("init", config))

        async def validate_findings_batch(self, _findings, _code_contexts):
            events.append(("validate",))
            raise RuntimeError("batch failed")

        async def close(self):
            events.append(("close",))

    monkeypatch.setattr("src.llm.finding_validator.LLMFindingValidator", FakeValidator)

    with pytest.raises(RuntimeError, match="batch failed"):
        validate_findings_sync([{"id": "F-1"}])

    assert events == [("init", None), ("validate",), ("close",)]


def test_init_rejects_malformed_host_and_model_boundaries(monkeypatch):
    monkeypatch.delenv("MIESC_LLM_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)

    for host in [
        "ftp://ollama.local:11434",
        "http://user:pass@ollama.local:11434",
        "http://ollama.local:11434/proxy?x=1",
        "http://ollama.local:11434/#frag",
        "http://ollama.local:11434\u2028",
    ]:
        validator = LLMFindingValidator(ValidatorConfig(ollama_host=host))
        assert validator.config.ollama_host == ValidatorConfig().ollama_host

    for model in ["bad model", "owner/model", "bad\\model", "x" * 129, "bad\nmodel"]:
        validator = LLMFindingValidator(ValidatorConfig(model=model))
        assert validator.config.model == ValidatorConfig().model


def test_init_rejects_malformed_environment_host_and_model(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama.local:11434/proxy?x=1")
    monkeypatch.setenv("MIESC_LLM_MODEL", "owner/model")

    validator = LLMFindingValidator(ValidatorConfig())

    assert validator.config.ollama_host == ValidatorConfig().ollama_host
    assert validator.config.model == ValidatorConfig().model


@pytest.mark.asyncio
async def test_is_available_returns_false_for_hostile_models_iteration(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="target:latest"))

    class HostileModels(list):
        def __iter__(self):
            raise RuntimeError("hostile models")

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": HostileModels([{"name": "target:latest"}])}

    class FakeSession:
        def get(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is False


@pytest.mark.asyncio
async def test_is_available_uses_normalized_host_after_config_mutation(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="target:latest"))
    validator.config.ollama_host = "http://ollama.local:11434/proxy?x=1"
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"models": [{"name": "target:latest"}]}

    class FakeSession:
        def get(self, url, *_args, **_kwargs):
            captured["url"] = url
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator.is_available() is True
    assert captured["url"] == f"{ValidatorConfig().ollama_host}/api/tags"


@pytest.mark.asyncio
async def test_call_ollama_uses_safe_payload_after_config_mutation(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig(model="target:latest"))
    validator.config.model = "bad/model"
    validator.config.temperature = float("inf")
    validator.config.max_tokens = 20_000
    validator.config.ollama_host = "http://ollama.local:11434/proxy?x=1"
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"response": "ok"}

    class FakeSession:
        def post(self, url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs["json"]
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == "ok"
    assert captured["url"] == f"{ValidatorConfig().ollama_host}/api/generate"
    assert captured["json"]["model"] == ValidatorConfig().model
    assert captured["json"]["options"] == {
        "temperature": ValidatorConfig().temperature,
        "num_predict": ValidatorConfig().max_tokens,
    }


@pytest.mark.asyncio
async def test_call_ollama_rejects_unsafe_response_text(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def json(self):
            return {"response": "bad\u2028response"}

    class FakeSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    async def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(validator, "_get_session", fake_get_session)

    assert await validator._call_ollama("prompt") == ""


def test_parse_response_rejects_oversized_and_too_many_keys(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    monkeypatch.setattr(
        "src.llm.finding_validator.extract_json_from_text",
        lambda _response: pytest.fail("oversized response should not be extracted"),
    )
    validation = validator._parse_response("x" * (MAX_VALIDATION_RESPONSE_CHARS + 1), "F-1")
    assert validation.result == ValidationResult.UNCERTAIN

    many_keys = "{" + ",".join(f'"k{i}": {i}' for i in range(MAX_VALIDATION_JSON_KEYS + 1)) + "}"
    validation = validator._parse_response(many_keys, "F-1")
    assert validation.result == ValidationResult.UNCERTAIN


def test_parse_response_handles_repair_runtime_error(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    monkeypatch.setattr(
        "src.llm.finding_validator.repair_common_json_errors",
        lambda _response: (_ for _ in ()).throw(RuntimeError("repair failed")),
    )

    validation = validator._parse_response('{"result": "valid"}', "F-1")

    assert validation.result == ValidationResult.LIKELY_VALID


@pytest.mark.asyncio
async def test_validate_findings_batch_rejects_hostile_findings_iteration(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileFindings(list):
        def __iter__(self):
            raise RuntimeError("hostile findings")

    async def available():
        raise AssertionError("hostile findings should short-circuit before availability")

    monkeypatch.setattr(validator, "is_available", available)

    validated, validations = await validator.validate_findings_batch(
        HostileFindings([{"id": "F-1", "severity": "high"}])
    )

    assert validated == []
    assert validations == []


@pytest.mark.asyncio
async def test_validate_findings_batch_defaults_hostile_config_enabled(monkeypatch):
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileConfig:
        def __getattribute__(self, name):
            if name == "enabled":
                raise RuntimeError("hostile enabled")
            return super().__getattribute__(name)

    validator.config = HostileConfig()

    validated, validations = await validator.validate_findings_batch(
        [{"id": "F-1", "severity": "high"}]
    )

    assert validated == [{"id": "F-1", "severity": "high"}]
    assert validations == []


def test_apply_validation_defaults_validation_getattr_exceptions():
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileValidation:
        def __getattribute__(self, name):
            if name in {
                "result",
                "confidence",
                "reasoning",
                "suggested_severity",
                "validation_time_ms",
            }:
                raise RuntimeError("hostile validation")
            return super().__getattribute__(name)

    updated = validator._apply_validation(
        {"id": "F-1", "severity": "high", "confidence": 0.7},
        HostileValidation(),
    )

    assert updated is not None
    assert updated["_llm_validation"] == {
        "result": "uncertain",
        "confidence": 0.5,
        "reasoning": "No reasoning provided",
        "suggested_severity": None,
        "validation_time_ms": 0,
    }
    assert updated["confidence"] == 0.7


def test_apply_validation_handles_finding_copy_failure():
    validator = LLMFindingValidator(ValidatorConfig())

    class HostileFinding(dict):
        def copy(self):
            raise RuntimeError("hostile copy")

    updated = validator._apply_validation(
        HostileFinding({"id": "F-1", "severity": "high", "confidence": 0.7}),
        LLMValidation("F-1", ValidationResult.VALID, 0.9, "confirmed"),
    )

    assert updated is not None
    assert updated["_llm_validation"]["result"] == "valid"
    assert updated["confidence"] == 0.85
