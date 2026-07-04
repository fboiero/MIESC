import aiohttp
import pytest

from src.llm.remediation_generator import (
    Remediation,
    RemediationGenerator,
    RemediationResult,
    generate_fix,
    get_quick_fix,
)


@pytest.mark.asyncio
async def test_generate_remediations_sequential_counts_runtime_failures(monkeypatch):
    generator = RemediationGenerator()
    findings = [{"id": "A", "type": "reentrancy"}, {"id": "B", "type": "access-control"}]

    async def fake_generate(finding, _code):
        if finding["id"] == "B":
            raise RuntimeError("LLM unavailable")
        return object()

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    result = await generator.generate_remediations(findings, "contract Test {}", parallel=False)

    assert isinstance(result, RemediationResult)
    assert result.success_count == 1
    assert result.failure_count == 1
    assert len(result.remediations) == 1


@pytest.mark.asyncio
async def test_query_llm_returns_empty_dict_on_client_error(monkeypatch):
    generator = RemediationGenerator()

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            raise aiohttp.ClientError("connection refused")

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{"message": ["not a dict"]}, {"message": {"content": ["not text"]}}])
async def test_query_llm_returns_empty_dict_for_malformed_message_payload(monkeypatch, payload):
    generator = RemediationGenerator()

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return payload

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [["not a dict"], "not a dict", None])
async def test_query_llm_returns_empty_dict_for_non_object_payload(monkeypatch, payload):
    generator = RemediationGenerator()

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return payload

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {}


def test_parse_json_response_repairs_common_llm_json_errors():
    generator = RemediationGenerator()
    response = """
    ```json
    {
        fixed_code: "contract Fixed {}",
        "explanation": "Use CEI before external call",
        "changes": ["state update first",],
    }
    ```
    """

    result = generator._parse_json_response(response)

    assert result["fixed_code"] == "contract Fixed {}"
    assert result["explanation"] == "Use CEI before external call"
    assert result["changes"] == ["state update first"]


def test_parse_json_response_repairs_invalid_backslash_escapes():
    generator = RemediationGenerator()
    response = (
        r'{"fixed_code": "function test() public { require(regex == \d+); }", '
        r'"explanation": "Regex escapes from LLM output should survive."}'
    )

    result = generator._parse_json_response(response)

    assert result["fixed_code"].endswith(r"require(regex == \d+); }")
    assert "Regex escapes" in result["explanation"]


def test_parse_json_response_rejects_non_object_json():
    generator = RemediationGenerator()

    result = generator._parse_json_response('[{"fixed_code": "contract Fixed {}"}]')

    assert result == {}


@pytest.mark.parametrize(
    ("vuln_type", "code", "expected_fragment", "expected_explanation"),
    [
        (
            "reentrancy",
            "function withdraw() public { msg.sender.call(''); }",
            "public nonReentrant",
            "Added nonReentrant modifier",
        ),
        (
            "access-control",
            "function sweep() external { owner.transfer(address(this).balance); }",
            "external onlyOwner",
            "Added onlyOwner modifier",
        ),
        (
            "unchecked-call",
            "function pay(IERC20 token) public { token.transfer(msg.sender, 1); }",
            ".safeTransfer(",
            "Replaced transfer with safeTransfer",
        ),
    ],
)
def test_generate_quick_fix_applies_known_patterns(
    vuln_type, code, expected_fragment, expected_explanation
):
    generator = RemediationGenerator()

    fixed, explanation = generator.generate_quick_fix(vuln_type, code)

    assert expected_fragment in fixed
    assert expected_explanation in explanation


def test_generate_quick_fix_returns_original_for_unknown_pattern():
    generator = RemediationGenerator()
    code = "function noop() public {}"

    fixed, explanation = generator.generate_quick_fix("unknown", code)

    assert fixed == code
    assert explanation == "No known pattern for this vulnerability type"


def test_generate_quick_fix_returns_original_for_non_string_type():
    generator = RemediationGenerator()
    code = "function noop() public {}"

    fixed, explanation = generator.generate_quick_fix(["reentrancy"], code)

    assert fixed == code
    assert explanation == "No known pattern for this vulnerability type"


def test_get_pattern_template_and_info_for_known_and_unknown_types():
    generator = RemediationGenerator()

    template = generator.get_pattern_template("ReEntrancy")
    known_info = generator._get_pattern_info("reentrancy")
    unknown_info = generator._get_pattern_info("unknown")
    malformed_template = generator.get_pattern_template(["reentrancy"])
    malformed_info = generator._get_pattern_info(["reentrancy"])

    assert template["pattern_name"] == "ReentrancyGuard + CEI"
    assert "**Pattern**: ReentrancyGuard + CEI" in known_info
    assert "**Modifier**: nonReentrant" in known_info
    assert unknown_info == "No specific pattern known. Use security best practices."
    assert malformed_template == {}
    assert malformed_info == "No specific pattern known. Use security best practices."


def test_extract_vulnerable_code_prefers_snippet():
    generator = RemediationGenerator()

    extracted = generator._extract_vulnerable_code(
        {"snippet": "function vulnerable() public {}"},
        "contract C { function other() public {} }",
    )

    assert extracted == "function vulnerable() public {}"


def test_extract_vulnerable_code_ignores_non_string_snippet():
    generator = RemediationGenerator()

    extracted = generator._extract_vulnerable_code(
        {"snippet": ["function vulnerable() public {}"]},
        "contract C { function other() public {} }",
    )

    assert extracted == "contract C { function other() public {} }"


def test_extract_vulnerable_code_ignores_non_object_location():
    generator = RemediationGenerator()

    extracted = generator._extract_vulnerable_code(
        {"location": ["line 10"]},
        "contract C { function other() public {} }",
    )

    assert extracted == "contract C { function other() public {} }"


def test_extract_vulnerable_code_ignores_malformed_location_fields():
    generator = RemediationGenerator()
    code = "contract C { function other() public {} }"

    function_extracted = generator._extract_vulnerable_code(
        {"location": {"function": ["other"]}},
        code,
    )
    line_extracted = generator._extract_vulnerable_code(
        {"location": {"line": True}},
        code,
    )

    assert function_extracted == code
    assert line_extracted == code


def test_extract_vulnerable_code_by_function_name():
    generator = RemediationGenerator()
    code = """
contract Vault {
    function deposit() public {}
    function withdraw(uint256 amount) external {
        require(amount > 0);
    }
}
"""

    extracted = generator._extract_vulnerable_code(
        {"location": {"function": "withdraw"}},
        code,
    )

    assert extracted.startswith("function withdraw")
    assert "require(amount > 0);" in extracted


def test_extract_vulnerable_code_by_line_window():
    generator = RemediationGenerator()
    code = "\n".join(f"line {idx}" for idx in range(1, 31))

    extracted = generator._extract_vulnerable_code({"location": {"line": 10}}, code)

    assert extracted.splitlines()[0] == "line 6"
    assert extracted.splitlines()[-1] == "line 20"


def test_extract_vulnerable_code_falls_back_to_first_50_lines():
    generator = RemediationGenerator()
    code = "\n".join(f"line {idx}" for idx in range(1, 80))

    extracted = generator._extract_vulnerable_code({}, code)

    assert len(extracted.splitlines()) == 50
    assert extracted.splitlines()[-1] == "line 50"


@pytest.mark.asyncio
async def test_generate_remediation_uses_llm_result_and_pattern(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-1",
        "type": "reentrancy",
        "severity": "HIGH",
        "title": "Reentrant withdraw",
        "description": "External call before state update",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "ReentrancyGuard + CEI" in prompt
        return {
            "fixed_code": "contract Fixed {}",
            "explanation": "Uses CEI",
            "changes": ["added guard"],
            "imports_needed": ["import {ReentrancyGuard} from 'oz.sol';"],
            "test_suggestions": ["reentrant attacker test"],
            "references": ["OpenZeppelin"],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract Vault {}")

    assert isinstance(remediation, Remediation)
    assert remediation.finding_id == "F-1"
    assert remediation.pattern_used == "ReentrancyGuard + CEI"
    assert remediation.fixed_code.startswith("import {ReentrancyGuard}")
    assert remediation.changes_summary == ["added guard"]
    assert remediation.test_suggestions == ["reentrant attacker test"]


@pytest.mark.asyncio
async def test_generate_remediation_falls_back_to_vulnerable_code(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2",
        "type": "unknown",
        "severity": "LOW",
        "snippet": "// already commented fixed code",
    }

    async def fake_query(_prompt):
        return {"imports_needed": ["import 'unused.sol';"]}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == "// already commented fixed code"
    assert remediation.explanation == ""
    assert remediation.pattern_used is None


@pytest.mark.asyncio
async def test_generate_remediation_defaults_non_string_finding_type(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2b",
        "type": ["reentrancy"],
        "severity": "LOW",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "- **Type**: unknown" in prompt
        return {"fixed_code": "function withdraw() public {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.vulnerability_type == "unknown"
    assert remediation.pattern_used is None


@pytest.mark.asyncio
async def test_generate_remediation_defaults_non_string_severity(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2d",
        "type": "reentrancy",
        "severity": ["HIGH"],
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "- **Severity**: medium" in prompt
        return {"fixed_code": "function withdraw() public {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.severity == "medium"


@pytest.mark.asyncio
async def test_generate_remediation_normalizes_malformed_llm_result_fields(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2c",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": {"code": "contract Fixed {}"},
            "explanation": ["Uses CEI"],
            "changes": ["valid change", {"bad": "shape"}, 7],
            "imports_needed": [
                "import {ReentrancyGuard} from 'oz.sol';",
                {"bad": "import"},
                7,
            ],
            "test_suggestions": ["valid test", None],
            "references": "OpenZeppelin",
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == (
        "import {ReentrancyGuard} from 'oz.sol';\n\nfunction withdraw() public {}"
    )
    assert remediation.explanation == ""
    assert remediation.changes_summary == ["valid change"]
    assert remediation.test_suggestions == ["valid test"]
    assert remediation.references == []


@pytest.mark.asyncio
async def test_generate_remediations_parallel_counts_exceptions(monkeypatch):
    generator = RemediationGenerator()
    findings = [{"id": "A"}, {"id": "B"}, {"id": "C"}]

    async def fake_generate(finding, _code):
        if finding["id"] == "B":
            raise RuntimeError("failed")
        return Remediation(
            finding_id=finding["id"],
            vulnerability_type="unknown",
            severity="medium",
            vulnerable_code="",
            fixed_code="",
            explanation="",
            changes_summary=[],
            test_suggestions=[],
            references=[],
            confidence=0.8,
        )

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    result = await generator.generate_remediations(findings, "contract C {}", parallel=True)

    assert result.success_count == 2
    assert result.failure_count == 1
    assert [rem.finding_id for rem in result.remediations] == ["A", "C"]


@pytest.mark.asyncio
async def test_generate_fix_convenience_function_delegates(monkeypatch):
    async def fake_generate(self, finding, code):
        return Remediation(
            finding_id=finding["id"],
            vulnerability_type="unknown",
            severity="medium",
            vulnerable_code=code,
            fixed_code="fixed",
            explanation="ok",
            changes_summary=[],
            test_suggestions=[],
            references=[],
            confidence=0.8,
        )

    monkeypatch.setattr(RemediationGenerator, "generate_remediation", fake_generate)

    remediation = await generate_fix({"id": "F-3"}, "contract C {}", model="fake")

    assert remediation.finding_id == "F-3"
    assert remediation.fixed_code == "fixed"


def test_get_quick_fix_convenience_function():
    fixed, explanation = get_quick_fix("access-control", "function admin() public {}")

    assert "onlyOwner" in fixed
    assert "Ownable" in explanation
