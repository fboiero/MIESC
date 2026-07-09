import asyncio

import aiohttp
import pytest

from src.llm.remediation_generator import (
    MAX_BATCH_FINDINGS,
    MAX_CONCURRENT_REMEDIATIONS,
    MAX_METADATA_LIST_ITEMS,
    MAX_REMEDIATION_EXPORTS,
    Remediation,
    RemediationGenerator,
    RemediationResult,
    _export_code_or_patch_text,
    _export_confidence,
    _export_explanation,
    _export_generated_test_name,
    _export_generated_test_names,
    _export_level,
    _export_non_negative_float,
    _export_non_negative_int,
    _export_optional_string,
    _export_patch_file_path,
    _export_patch_filename,
    _export_positive_int_list,
    _export_reference,
    _export_reference_url,
    _export_string,
    _export_string_list,
    _export_unique_string_list,
    _safe_text,
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
@pytest.mark.parametrize("findings", ["not a list", {"id": "A"}, None])
async def test_generate_remediations_rejects_malformed_batch_container(monkeypatch, findings):
    generator = RemediationGenerator()

    async def fake_generate(_finding, _code):
        raise AssertionError("malformed batch container should not be processed")

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    result = await generator.generate_remediations(findings, "contract Test {}")

    assert result.success_count == 0
    assert result.failure_count == 1
    assert result.remediations == []


@pytest.mark.asyncio
async def test_generate_remediations_skips_malformed_batch_entries(monkeypatch):
    generator = RemediationGenerator()
    processed_ids = []
    findings = [
        {"id": "A"},
        ["malformed"],
        {"id": "B"},
        "not a finding",
    ]

    async def fake_generate(finding, _code):
        processed_ids.append(finding["id"])
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

    result = await generator.generate_remediations(
        findings,
        "contract Test {}",
        parallel=False,
    )

    assert result.success_count == 2
    assert result.failure_count == 2
    assert processed_ids == ["A", "B"]
    assert [rem.finding_id for rem in result.remediations] == ["A", "B"]


def test_remediation_to_dict_normalizes_malformed_export_metadata():
    remediation = Remediation(
        finding_id=["F-1"],
        vulnerability_type={"type": "reentrancy"},
        severity=" ",
        vulnerable_code={"code": "contract C {}"},
        fixed_code=["contract Fixed {}"],
        explanation=None,
        changes_summary=["  added guard  ", {"bad": "change"}, ""],
        test_suggestions="run tests",
        references=["OpenZeppelin", ["bad reference"], "  "],
        confidence=float("nan"),
        pattern_used=["ReentrancyGuard"],
        implementation_complexity="extreme",
        deployment_risk=" Critical ",
        gas_impact={"impact": "high"},
        affected_lines=["3", 4, 0, -1, True, 2.5, float("inf"), {"line": 7}, 3],
    )

    exported = remediation.to_dict()

    assert exported == {
        "finding_id": "unknown",
        "vulnerability_type": "unknown",
        "severity": "medium",
        "vulnerable_code": "",
        "fixed_code": "",
        "explanation": "",
        "changes_summary": ["added guard"],
        "test_suggestions": [],
        "references": ["OpenZeppelin"],
        "confidence": 0.0,
        "affected_lines": [3, 4],
        "pattern_used": None,
        "implementation_complexity": "medium",
        "deployment_risk": "critical",
        "gas_impact": "medium",
        "validation_notes": [],
    }


@pytest.mark.parametrize(
    ("explanation", "expected"),
    [
        ("  uses CEI before the external call  ", "uses CEI before the external call"),
        (" \n\t ", ""),
        (["uses CEI"], ""),
        ({"why": "uses CEI"}, ""),
        (None, ""),
    ],
)
def test_remediation_to_dict_normalizes_explanation_export_boundary(
    explanation,
    expected,
):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation=explanation,
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["explanation"] == expected


def test_remediation_to_dict_defaults_malformed_explanation_string_export_boundary():
    class MalformedString(str):
        def strip(self, *_args, **_kwargs):
            raise ValueError("malformed explanation")

    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation=MalformedString("uses CEI"),
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["explanation"] == ""


@pytest.mark.parametrize(
    ("fixed_code", "expected"),
    [
        (
            "function withdraw() public nonReentrant {}",
            "function withdraw() public nonReentrant {}",
        ),
        (
            "diff --git a/Vault.sol b/Vault.sol\n"
            "@@ -10,7 +10,8 @@ contract Vault {\n"
            "-    transfer(amount);\n"
            "+    _withdraw(amount);\n",
            "diff --git a/Vault.sol b/Vault.sol\n"
            "@@ -10,7 +10,8 @@ contract Vault {\n"
            "-    transfer(amount);\n"
            "+    _withdraw(amount);",
        ),
        (
            "diff --git a/Vault.sol b/Vault.sol\n"
            "@@ malformed hunk header @@\n"
            "-    transfer(amount);\n"
            "+    _withdraw(amount);\n",
            "",
        ),
        (
            "@@ -not-a-number +10 @@\n-    transfer(amount);\n+    _withdraw(amount);\n",
            "",
        ),
    ],
)
def test_remediation_to_dict_bounds_malformed_diff_hunk_export_boundary(
    fixed_code,
    expected,
):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code=fixed_code,
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["fixed_code"] == expected


@pytest.mark.parametrize(
    ("affected_lines", "expected"),
    [
        ([1, "2", " 3 ", 1], [1, 2, 3]),
        ([0, -1, True, False, 1.5, float("nan"), float("inf"), "bad"], []),
        ("1,2,3", []),
        (None, []),
    ],
)
def test_remediation_to_dict_normalizes_affected_lines_export_boundary(affected_lines, expected):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        affected_lines=affected_lines,
    )

    assert remediation.to_dict()["affected_lines"] == expected


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (1.0, 1.0),
        ("0.25", 0.25),
        (1.01, 0.0),
        (-0.01, 0.0),
        (True, 0.0),
        (float("inf"), 0.0),
    ],
)
def test_remediation_to_dict_bounds_exported_confidence(confidence, expected):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=confidence,
    )

    assert remediation.to_dict()["confidence"] == expected


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (" HIGH ", "high"),
        ("critical", "critical"),
        ("INFO", "info"),
        ("informational", "informational"),
        ("critical<script>", "medium"),
        (["high"], "medium"),
    ],
)
def test_remediation_to_dict_bounds_exported_severity(severity, expected):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity=severity,
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["severity"] == expected


@pytest.mark.parametrize(
    ("field_name", "field_value", "expected"),
    [
        ("severity", "high", "medium"),
        ("deployment_risk", "critical", "medium"),
    ],
)
def test_remediation_to_dict_defaults_malformed_level_export_boundary(
    field_name,
    field_value,
    expected,
):
    class MalformedString(str):
        def strip(self, *_args, **_kwargs):
            raise ValueError("malformed level")

    remediation_kwargs = {
        "finding_id": "F-1",
        "vulnerability_type": "reentrancy",
        "severity": "high",
        "vulnerable_code": "function withdraw() public {}",
        "fixed_code": "function withdraw() public nonReentrant {}",
        "explanation": "uses guard",
        "changes_summary": [],
        "test_suggestions": [],
        "references": [],
        "confidence": 0.8,
    }
    remediation_kwargs[field_name] = MalformedString(field_value)

    remediation = Remediation(**remediation_kwargs)

    assert remediation.to_dict()[field_name] == expected


@pytest.mark.parametrize(
    ("gas_impact", "expected"),
    [
        (" HIGH ", "high"),
        ("none", "none"),
        ("NoNe", "none"),
        ("critical", "medium"),
        ({"impact": "low"}, "medium"),
        (["low"], "medium"),
        (None, "medium"),
    ],
)
def test_remediation_to_dict_bounds_exported_gas_impact(gas_impact, expected):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        gas_impact=gas_impact,
    )

    assert remediation.to_dict()["gas_impact"] == expected


def test_remediation_to_dict_deduplicates_test_suggestions_export_boundary():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[
            "  reentrant attacker test  ",
            "reentrant attacker test",
            {"bad": "test"},
            "",
            "withdraw succeeds for user",
            "withdraw succeeds for user",
        ],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["test_suggestions"] == [
        "reentrant attacker test",
        "withdraw succeeds for user",
    ]


def test_remediation_to_dict_filters_malformed_generated_test_names_export_boundary():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[
            "  reentrant attacker test  ",
            "reentrant attacker test",
            "../test/Reentrant.t.sol",
            "C:\\temp\\Reentrant.t.sol",
            "test_withdraw\ninject",
            ".",
            {"bad": "test"},
            "",
            "withdraw succeeds for user",
        ],
        references=[],
        confidence=0.8,
    )

    assert remediation.to_dict()["test_suggestions"] == [
        "reentrant attacker test",
        "withdraw succeeds for user",
    ]


def test_remediation_to_dict_filters_malformed_reference_link_export_boundary():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[
            "  OpenZeppelin ReentrancyGuard  ",
            "https://docs.openzeppelin.com/contracts/4.x/api/security",
            "[Solidity security](https://docs.soliditylang.org/en/latest/security-considerations.html)",
            "javascript:alert(1)",
            "ftp://example.com/security",
            "https://user:pass@example.com/private",
            "https://example.com/bad path",
            "https://example.com/good\nX-Header: injected",
            "[broken](javascript:alert(1))",
            "[missing close](https://example.com",
            "<a href='https://example.com'>bad</a>",
            "OpenZeppelin ReentrancyGuard",
        ],
        confidence=0.8,
    )

    assert remediation.to_dict()["references"] == [
        "OpenZeppelin ReentrancyGuard",
        "https://docs.openzeppelin.com/contracts/4.x/api/security",
        "[Solidity security](https://docs.soliditylang.org/en/latest/security-considerations.html)",
    ]


def test_remediation_to_dict_skips_malformed_reference_title_export_boundary():
    class MalformedString(str):
        def strip(self, *_args, **_kwargs):
            raise ValueError("malformed reference title")

    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[
            MalformedString("OpenZeppelin ReentrancyGuard"),
            "  OpenZeppelin ReentrancyGuard  ",
            "[Solidity security](https://docs.soliditylang.org/en/latest/security-considerations.html)",
        ],
        confidence=0.8,
    )

    assert remediation.to_dict()["references"] == [
        "OpenZeppelin ReentrancyGuard",
        "[Solidity security](https://docs.soliditylang.org/en/latest/security-considerations.html)",
    ]


@pytest.mark.parametrize(
    ("validation_notes", "expected"),
    [
        (
            [
                "  validated compile path  ",
                {"bad": "note"},
                "",
                "validated compile path",
                "manual review required",
            ],
            ["validated compile path", "manual review required"],
        ),
        ("validated compile path", []),
        (None, []),
    ],
)
def test_remediation_to_dict_deduplicates_validation_notes_export_boundary(
    validation_notes,
    expected,
):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        validation_notes=validation_notes,
    )

    assert remediation.to_dict()["validation_notes"] == expected


def test_remediation_to_dict_caps_nested_export_lists():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[f"change {idx}" for idx in range(MAX_METADATA_LIST_ITEMS + 5)],
        test_suggestions=[f"test_{idx}" for idx in range(MAX_METADATA_LIST_ITEMS + 5)],
        references=[f"Reference {idx}" for idx in range(MAX_METADATA_LIST_ITEMS + 5)],
        confidence=0.8,
        affected_lines=list(range(1, MAX_METADATA_LIST_ITEMS + 6)),
        validation_notes=[f"note {idx}" for idx in range(MAX_METADATA_LIST_ITEMS + 5)],
    )

    exported = remediation.to_dict()

    assert len(exported["changes_summary"]) == MAX_METADATA_LIST_ITEMS
    assert len(exported["test_suggestions"]) == MAX_METADATA_LIST_ITEMS
    assert len(exported["references"]) == MAX_METADATA_LIST_ITEMS
    assert len(exported["affected_lines"]) == MAX_METADATA_LIST_ITEMS
    assert len(exported["validation_notes"]) == MAX_METADATA_LIST_ITEMS


def test_remediation_to_dict_handles_hostile_nested_export_lists():
    class HostileList(list):
        def __iter__(self):
            raise RuntimeError("hostile iterator")

    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=HostileList(["change"]),
        test_suggestions=HostileList(["test_reentrancy"]),
        references=HostileList(["OpenZeppelin"]),
        confidence=0.8,
        affected_lines=HostileList([1]),
        validation_notes=HostileList(["validated"]),
    )

    exported = remediation.to_dict()

    assert exported["changes_summary"] == []
    assert exported["test_suggestions"] == []
    assert exported["references"] == []
    assert exported["affected_lines"] == []
    assert exported["validation_notes"] == []


def test_remediation_to_dict_exports_safe_patch_filename_and_file_path():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        patch_filename="  Vault.fixed.sol  ",
        patch_file_path=" build/remediation/Vault.fixed.sol ",
    )

    exported = remediation.to_dict()

    assert exported["patch_filename"] == "Vault.fixed.sol"
    assert exported["patch_file_path"] == "build/remediation/Vault.fixed.sol"


@pytest.mark.parametrize(
    ("patch_filename", "patch_file_path"),
    [
        ("../Vault.sol", "build/../Vault.sol"),
        ("contracts/Vault.sol", "/tmp/Vault.sol"),
        ("contracts\\Vault.sol", "build\\Vault.sol"),
        ("Vault.sol\nnext", "build/Vault.sol\x00"),
        (["Vault.sol"], {"path": "build/Vault.sol"}),
        (".", "."),
        ("..", ".."),
        ("C:Vault.sol", "C:/tmp/Vault.sol"),
    ],
)
def test_remediation_to_dict_omits_malformed_patch_filename_and_file_path(
    patch_filename,
    patch_file_path,
):
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        patch_filename=patch_filename,
        patch_file_path=patch_file_path,
    )

    exported = remediation.to_dict()

    assert "patch_filename" not in exported
    assert "patch_file_path" not in exported


def test_remediation_to_dict_omits_overlong_patch_paths():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
        patch_filename="a" * 241,
        patch_file_path="patches/" + ("a" * 241),
    )

    exported = remediation.to_dict()

    assert "patch_filename" not in exported
    assert "patch_file_path" not in exported


def test_remediation_result_to_dict_normalizes_malformed_export_metadata():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )
    result = RemediationResult(
        remediations=[remediation, {"bad": "remediation"}],
        success_count=True,
        failure_count=-3,
        execution_time_ms=float("inf"),
    )

    exported = result.to_dict()

    assert len(exported["remediations"]) == 1
    assert exported["remediations"][0]["finding_id"] == "F-1"
    assert exported["success_count"] == 0
    assert exported["failure_count"] == 0
    assert exported["execution_time_ms"] == 0.0


def test_remediation_result_to_dict_skips_malformed_remediation_exports():
    class NonObjectExportRemediation(Remediation):
        def to_dict(self):
            return ["not an export object"]

    class RaisingExportRemediation(Remediation):
        def to_dict(self):
            raise TypeError("malformed export")

    valid = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )
    non_object = NonObjectExportRemediation(**valid.__dict__)
    raising = RaisingExportRemediation(**valid.__dict__)
    result = RemediationResult(
        remediations=[valid, non_object, raising],
        success_count=3,
        failure_count=0,
        execution_time_ms=12.5,
    )

    exported = result.to_dict()

    assert len(exported["remediations"]) == 1
    assert exported["remediations"][0]["finding_id"] == "F-1"
    assert exported["success_count"] == 3


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
@pytest.mark.parametrize(
    "payload", [{"message": ["not a dict"]}, {"message": {"content": ["not text"]}}]
)
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


@pytest.mark.asyncio
async def test_query_llm_normalizes_base_url_trailing_slash(monkeypatch):
    generator = RemediationGenerator(ollama_base_url="http://ollama.local:11434/")
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return {"message": {"content": '{"fixed_code": "contract Fixed {}"}'}}

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, url, **kwargs):
            captured["url"] = url
            captured["timeout"] = kwargs["timeout"].total
            return FakeResponse()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {"fixed_code": "contract Fixed {}"}
    assert captured["url"] == "http://ollama.local:11434/api/chat"
    assert captured["timeout"] == 120


@pytest.mark.asyncio
async def test_query_llm_defaults_malformed_model_prompt_and_timeout_payload(monkeypatch):
    generator = RemediationGenerator(model={"bad": "model"}, timeout=-1)
    generator.model = "bad\nmodel"
    generator.timeout = "bad"
    captured = {}

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return {"message": {"content": '{"fixed_code": "contract Fixed {}"}'}}

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, _url, **kwargs):
            captured["payload"] = kwargs["json"]
            captured["timeout"] = kwargs["timeout"].total
            return FakeResponse()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm(["bad prompt"]) == {"fixed_code": "contract Fixed {}"}
    assert captured["payload"]["model"] == "deepseek-coder:6.7b"
    assert captured["payload"]["messages"][1]["content"] == ""
    assert captured["timeout"] == 120


@pytest.mark.asyncio
async def test_query_llm_sanitizes_http_error_text(monkeypatch):
    generator = RemediationGenerator()

    class FakeResponse:
        status = 500

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def text(self):
            return "bad\n" + ("x" * 500)

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


def test_generate_quick_fix_replaces_transfer_from_even_when_safe_transfer_exists():
    generator = RemediationGenerator()
    code = (
        "function pay(IERC20 token) public { "
        "token.safeTransfer(msg.sender, 1); token.transferFrom(msg.sender, address(this), 2); "
        "}"
    )

    fixed, explanation = generator.generate_quick_fix("unchecked-call", code)

    assert ".safeTransferFrom(" in fixed
    assert ".transferFrom(" not in fixed
    assert "Replaced transfer with safeTransfer" in explanation


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


def test_generate_quick_fix_normalizes_padded_type():
    generator = RemediationGenerator()
    code = "function withdraw() public {}"

    fixed, explanation = generator.generate_quick_fix(" ReEntrancy \n", code)

    assert "public nonReentrant" in fixed
    assert "Added nonReentrant modifier" in explanation


def test_generate_quick_fix_defaults_whitespace_only_type():
    generator = RemediationGenerator()
    code = "function noop() public {}"

    fixed, explanation = generator.generate_quick_fix(" \n\t ", code)

    assert fixed == code
    assert explanation == "No known pattern for this vulnerability type"


@pytest.mark.parametrize(
    "function_code", [None, ["function withdraw() public {}"], {"code": "bad"}]
)
def test_generate_quick_fix_defaults_malformed_function_code(function_code):
    generator = RemediationGenerator()

    fixed, explanation = generator.generate_quick_fix("reentrancy", function_code)

    assert fixed == ""
    assert explanation == "No function code available for quick fix"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            "function withdraw() external payable returns (bool) { return true; }",
            "external payable nonReentrant returns",
        ),
        (
            "function quote() public view returns (uint256) { return 1; }",
            "public view nonReentrant returns",
        ),
        (
            "function quote() public pure returns (uint256) { return 1; }",
            "public pure nonReentrant returns",
        ),
        (
            "function withdraw() external override returns (bool) { return true; }",
            "external override nonReentrant returns",
        ),
    ],
)
def test_generate_quick_fix_preserves_solidity_modifier_order(code, expected):
    generator = RemediationGenerator()

    fixed, explanation = generator.generate_quick_fix("reentrancy", code)

    assert expected in fixed
    assert "Added nonReentrant modifier" in explanation


def test_generate_quick_fix_preserves_returns_clause_for_access_control():
    generator = RemediationGenerator()

    fixed, explanation = generator.generate_quick_fix(
        "access-control",
        "function admin() public payable override returns (bool) { return true; }",
    )

    assert "public payable override onlyOwner returns" in fixed
    assert "Added onlyOwner modifier" in explanation


def test_generate_quick_fix_detects_existing_owner_modifier_with_arguments():
    generator = RemediationGenerator()
    code = "function admin() public onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) { return true; }"

    fixed, explanation = generator.generate_quick_fix("access-control", code)

    assert fixed == code
    assert "Changes made" not in explanation


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


def test_extract_vulnerable_code_defaults_non_string_contract_code():
    generator = RemediationGenerator()

    extracted = generator._extract_vulnerable_code(
        {},
        {"contract_code": "contract C { function other() public {} }"},
    )

    assert extracted == ""


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


def test_extract_vulnerable_code_by_function_name_balances_nested_braces():
    generator = RemediationGenerator()
    code = """
contract Vault {
    function withdraw(uint256 amount) external {
        if (amount > 0) {
            for (uint256 i = 0; i < 2; i++) {
                balances[msg.sender] -= amount;
            }
        }
        (bool ok,) = msg.sender.call("");
        require(ok);
    }
    function deposit() public {}
}
"""

    extracted = generator._extract_vulnerable_code(
        {"location": {"function": "withdraw"}},
        code,
    )

    assert extracted.startswith("function withdraw")
    assert "function deposit" not in extracted
    assert "require(ok);" in extracted
    assert extracted.count("{") == extracted.count("}")


def test_extract_vulnerable_code_by_function_name_ignores_comment_and_string_braces():
    generator = RemediationGenerator()
    code = """
contract Vault {
    function withdraw() external {
        string memory marker = "{not a block}";
        // } comment brace should not close the function
        /* { block comment brace } */
        require(true);
    }
    function deposit() public {}
}
"""

    extracted = generator._extract_vulnerable_code(
        {"location": {"function": "withdraw"}},
        code,
    )

    assert "require(true);" in extracted
    assert "function deposit" not in extracted


def test_extract_vulnerable_code_by_function_name_handles_function_type_parameters():
    generator = RemediationGenerator()
    code = """
contract Vault {
    function configure(function(uint256) external callback, uint256 amount)
        public
        returns (bool)
    {
        callback(amount);
        return true;
    }
}
"""

    extracted = generator._extract_vulnerable_code(
        {"location": {"function": "configure"}},
        code,
    )

    assert extracted.startswith("function configure")
    assert "callback(amount);" in extracted
    assert "returns (bool)" in extracted


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
            "implementation_complexity": " High ",
            "deployment_risk": " low ",
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract Vault {}")

    assert isinstance(remediation, Remediation)
    assert remediation.finding_id == "F-1"
    assert remediation.pattern_used == "ReentrancyGuard + CEI"
    assert remediation.fixed_code.startswith("import {ReentrancyGuard}")
    assert remediation.changes_summary == ["added guard"]
    assert remediation.test_suggestions == ["reentrant attacker test"]
    assert remediation.implementation_complexity == "high"
    assert remediation.deployment_risk == "low"


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
async def test_generate_remediation_normalizes_padded_finding_type(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2g",
        "type": " ReEntrancy \n",
        "severity": "LOW",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "- **Type**: reentrancy" in prompt
        assert "- **Title**: reentrancy" in prompt
        assert "ReentrancyGuard + CEI" in prompt
        return {"fixed_code": "function withdraw() public {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.vulnerability_type == "reentrancy"
    assert remediation.pattern_used == "ReentrancyGuard + CEI"


@pytest.mark.asyncio
async def test_generate_remediation_defaults_whitespace_only_finding_type(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2h",
        "type": " \n\t ",
        "severity": "LOW",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "- **Type**: unknown" in prompt
        assert "- **Title**: Unknown" in prompt
        assert "\n\t" not in prompt
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
async def test_generate_remediation_defaults_malformed_prompt_scalar_fields(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": True,
        "type": "reentrancy",
        "severity": "HIGH",
        "title": ["bad title"],
        "description": {"bad": "description"},
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(prompt):
        assert "- **Title**: reentrancy" in prompt
        assert "- **Description**: \n" in prompt
        assert "bad title" not in prompt
        assert "bad" not in prompt
        return {"fixed_code": "function withdraw() public {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.finding_id == "unknown"


@pytest.mark.asyncio
async def test_generate_remediation_defaults_malformed_contract_code(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2e",
        "type": "reentrancy",
        "severity": "HIGH",
    }

    async def fake_query(prompt):
        assert "contract_code" not in prompt
        assert "```solidity\n\n```" in prompt
        return {}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(
        finding,
        {"contract_code": "contract C { function withdraw() public {} }"},
    )

    assert remediation.vulnerable_code == ""
    assert remediation.fixed_code == ""


@pytest.mark.asyncio
async def test_generate_remediation_defaults_malformed_finding_context(monkeypatch):
    generator = RemediationGenerator()

    async def fake_query(prompt):
        assert "- **Type**: unknown" in prompt
        assert "- **Severity**: medium" in prompt
        assert "- **Title**: Unknown" in prompt
        assert "```solidity\ncontract C {}\n```" in prompt
        return {"fixed_code": "contract Fixed {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(
        ["malformed finding"],
        "contract C {}",
    )

    assert remediation.finding_id == "unknown"
    assert remediation.vulnerability_type == "unknown"
    assert remediation.severity == "medium"
    assert remediation.vulnerable_code == "contract C {}"
    assert remediation.fixed_code == "contract Fixed {}"
    assert remediation.pattern_used is None


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
async def test_generate_remediation_filters_control_char_string_lists(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2d",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "explanation": "Uses CEI",
            "changes": ["  valid change  ", "bad\nchange", {"bad": "shape"}],
            "imports_needed": [],
            "test_suggestions": ["valid test", "bad\ttest"],
            "references": ["OpenZeppelin", "bad\nreference"],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.changes_summary == ["valid change"]
    assert remediation.test_suggestions == ["valid test"]
    assert remediation.references == ["OpenZeppelin"]


def test_export_generated_test_name_strips_and_rejects_control_chars():
    assert _export_generated_test_name("  test_exploit_reentrancy  ") == "test_exploit_reentrancy"
    assert _export_generated_test_name("test\nshadow") is None
    assert _export_generated_test_names(("test_a", "test_a", "bad\nname")) == ["test_a"]
    assert _export_level(" HIGH\t", {"high", "low"}, "low") == "high"
    assert _export_level("high\nrisk", {"high", "low"}, "low") == "low"
    assert _export_confidence("0.75") == 0.75
    assert _export_confidence("1.25") == 0.0


def test_export_string_list_strips_and_rejects_control_chars():
    assert _export_string_list(["  added guard  ", "bad\nchange", 123, "added check"]) == [
        "added guard",
        "added check",
    ]


def test_export_string_helpers_reject_control_chars():
    assert _export_string("  valid value  ", "default") == "valid value"
    assert _export_string("bad\nvalue", "default") == "default"
    assert _export_optional_string("  valid value  ") == "valid value"
    assert _export_optional_string("bad\tvalue") is None
    assert _export_explanation("  uses CEI  ") == "uses CEI"
    assert _export_explanation("uses\nCEI") == ""


def test_export_reference_helpers_strip_and_reject_control_chars():
    assert _export_reference_url("  https://example.com/docs  ") == "https://example.com/docs"
    assert _export_reference_url("https://example.com/doc\ns") is None
    assert (
        _export_reference("[Docs](https://example.com/spec)") == "[Docs](https://example.com/spec)"
    )
    assert _export_reference("[Docs](https://example.com/spec\x7f)") is None


def test_export_patch_helpers_strip_and_reject_control_chars():
    assert _export_code_or_patch_text("  contract C {}  ", "") == "contract C {}"
    assert _export_code_or_patch_text("@@ bad hunk @@\ncontract C {}", "") == ""
    assert _export_patch_filename("  fix.patch  ") == "fix.patch"
    assert _export_patch_filename("bad/name.patch") is None
    assert _export_patch_file_path(" patches/fix.patch ") == "patches/fix.patch"
    assert _export_patch_file_path("patches/fi\nx.patch") is None


def test_export_numeric_and_unique_list_helpers_reject_control_chars():
    assert _export_unique_string_list([" a ", "a", "bad\nx", "b"]) == ["a", "b"]
    assert _export_non_negative_float(" 1.25 ") == 1.25
    assert _export_non_negative_float("1.25\x7f") == 0.0
    assert _export_non_negative_int(" 12 ") == 12
    assert _export_non_negative_int("12\n") == 0
    assert _export_positive_int_list([1, "2", " 3 ", 1, "bad\nx"]) == [1, 2, 3]


@pytest.mark.asyncio
async def test_generate_remediation_defaults_malformed_complexity_and_risk_payloads(
    monkeypatch,
):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2k",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "complexity": {"level": "low"},
            "risk_level": ["critical"],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == "contract Fixed {}"
    assert remediation.implementation_complexity == "medium"
    assert remediation.deployment_risk == "medium"


@pytest.mark.asyncio
async def test_generate_remediation_accepts_bounded_complexity_and_risk_aliases(
    monkeypatch,
):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2l",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "complexity": "LOW",
            "risk_level": "Critical",
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.implementation_complexity == "low"
    assert remediation.deployment_risk == "critical"


@pytest.mark.asyncio
async def test_generate_remediation_drops_blank_llm_list_entries(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2j",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "changes": ["  added guard  ", "", " \n\t "],
            "imports_needed": ["  import {ReentrancyGuard} from 'oz.sol';  ", "  "],
            "test_suggestions": ["  reentrant attacker test  ", "\t"],
            "references": ["  OpenZeppelin ReentrancyGuard  ", ""],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == (
        "import {ReentrancyGuard} from 'oz.sol';\n\ncontract Fixed {}"
    )
    assert remediation.changes_summary == ["added guard"]
    assert remediation.test_suggestions == ["reentrant attacker test"]
    assert remediation.references == ["OpenZeppelin ReentrancyGuard"]


@pytest.mark.asyncio
async def test_generate_remediation_deduplicates_generated_test_and_reference_metadata(
    monkeypatch,
):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2o",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "test_suggestions": [
                "  reentrant attacker test  ",
                "reentrant attacker test",
                {"bad": "test"},
                "",
                "withdraw succeeds for user",
            ],
            "references": [
                "OpenZeppelin ReentrancyGuard",
                ["bad reference"],
                "  OpenZeppelin ReentrancyGuard  ",
                "Solidity security considerations",
            ],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.test_suggestions == [
        "reentrant attacker test",
        "withdraw succeeds for user",
    ]
    assert remediation.references == [
        "OpenZeppelin ReentrancyGuard",
        "Solidity security considerations",
    ]


@pytest.mark.asyncio
async def test_generate_remediation_filters_malformed_generated_test_names(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2p",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "test_suggestions": [
                "  reentrant attacker test  ",
                "reentrant attacker test",
                "/tmp/Reentrant.t.sol",
                "test_withdraw\r\nforge clean",
                "..",
                ["bad test"],
                "withdraw succeeds for user",
            ],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.test_suggestions == [
        "reentrant attacker test",
        "withdraw succeeds for user",
    ]


@pytest.mark.asyncio
async def test_generate_remediation_skips_duplicate_fixed_code_imports(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2m",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }
    import_line = "import {ReentrancyGuard} from 'oz.sol';"

    async def fake_query(_prompt):
        return {
            "fixed_code": f"{import_line}\n\ncontract Fixed {{}}",
            "imports_needed": [import_line, import_line, {"bad": "import"}],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == f"{import_line}\n\ncontract Fixed {{}}"
    assert remediation.fixed_code.count(import_line) == 1


@pytest.mark.asyncio
async def test_generate_remediation_prepends_imports_before_spdx_license(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2m-spdx",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }
    import_line = "import {ReentrancyGuard} from 'oz.sol';"

    async def fake_query(_prompt):
        return {
            "fixed_code": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Fixed {}",
            "imports_needed": [import_line],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code.startswith(import_line)
    assert "// SPDX-License-Identifier: MIT" in remediation.fixed_code


@pytest.mark.asyncio
async def test_generate_remediation_deduplicates_imports_before_prepending(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2n",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }
    import_line = "import {ReentrancyGuard} from 'oz.sol';"

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "imports_needed": [import_line, import_line, ["bad import"]],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == f"{import_line}\n\ncontract Fixed {{}}"
    assert remediation.fixed_code.count(import_line) == 1


@pytest.mark.asyncio
async def test_generate_remediation_ignores_non_import_imports_needed(monkeypatch):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2q",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }
    import_line = "import {ReentrancyGuard} from 'oz.sol';"

    async def fake_query(_prompt):
        return {
            "fixed_code": "contract Fixed {}",
            "imports_needed": [
                import_line,
                "pragma solidity ^0.8.20;",
                "contract Evil {}",
                "// or for role-based:",
                "import 'bad.sol';\ncontract Evil {}",
            ],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == f"{import_line}\n\ncontract Fixed {{}}"


def test_imports_to_prepend_rejects_malformed_import_syntax():
    imports = RemediationGenerator._imports_to_prepend(
        "contract Fixed {}",
        [
            "import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';",
            'import "./Safe.sol";',
            "import * as Math from '@openzeppelin/contracts/utils/math/Math.sol';",
            "import bad syntax",
            "import {Bad} from 'bad.sol'\ncontract Evil {}",
            "pragma solidity ^0.8.20;",
            "contract Evil {}",
        ],
    )

    assert imports == [
        "import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';",
        'import "./Safe.sol";',
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("fixed_code", ["", " \n\t "])
async def test_generate_remediation_defaults_blank_fixed_code_payload(monkeypatch, fixed_code):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2i",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return {
            "fixed_code": fixed_code,
            "imports_needed": ["import {ReentrancyGuard} from 'oz.sol';"],
        }

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == (
        "import {ReentrancyGuard} from 'oz.sol';\n\nfunction withdraw() public {}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("llm_result", [["not", "an", "object"], "not an object", None])
async def test_generate_remediation_defaults_malformed_llm_result_container(
    monkeypatch, llm_result
):
    generator = RemediationGenerator()
    finding = {
        "id": "F-2f",
        "type": "reentrancy",
        "severity": "HIGH",
        "snippet": "function withdraw() public {}",
    }

    async def fake_query(_prompt):
        return llm_result

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(finding, "contract C {}")

    assert remediation.fixed_code == "function withdraw() public {}"
    assert remediation.explanation == ""
    assert remediation.changes_summary == []
    assert remediation.test_suggestions == []
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
@pytest.mark.parametrize("max_concurrent", [0, -1, True, None, "bad"])
async def test_generate_remediations_defaults_malformed_max_concurrent(
    monkeypatch,
    max_concurrent,
):
    generator = RemediationGenerator()
    findings = [{"id": "A"}, {"id": "B"}]

    async def fake_generate(finding, _code):
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

    result = await generator.generate_remediations(
        findings,
        "contract C {}",
        parallel=True,
        max_concurrent=max_concurrent,
    )

    assert result.success_count == 2
    assert result.failure_count == 0


@pytest.mark.asyncio
async def test_generate_remediations_parallel_respects_max_concurrent_limit(monkeypatch):
    generator = RemediationGenerator()
    active = 0
    peak = 0
    findings = [{"id": str(index)} for index in range(5)]

    async def fake_generate(finding, _code):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
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

    result = await generator.generate_remediations(
        findings,
        "contract C {}",
        parallel=True,
        max_concurrent=2,
    )

    assert result.success_count == 5
    assert peak <= 2


@pytest.mark.asyncio
async def test_generate_remediations_parallel_propagates_cancelled_error(monkeypatch):
    generator = RemediationGenerator()
    findings = [{"id": "A"}, {"id": "B"}]

    async def fake_generate(finding, _code):
        if finding["id"] == "B":
            raise asyncio.CancelledError()
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

    with pytest.raises(asyncio.CancelledError):
        await generator.generate_remediations(findings, "contract C {}", parallel=True)


@pytest.mark.asyncio
async def test_generate_remediations_sequential_propagates_cancelled_error(monkeypatch):
    generator = RemediationGenerator()

    async def fake_generate(_finding, _code):
        raise asyncio.CancelledError()

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    with pytest.raises(asyncio.CancelledError):
        await generator.generate_remediations([{"id": "A"}], "contract C {}", parallel=False)


@pytest.mark.asyncio
async def test_generate_remediations_parallel_propagates_non_runtime_base_exception(
    monkeypatch,
):
    generator = RemediationGenerator()

    class FatalBaseException(BaseException):
        pass

    async def fake_generate(_finding, _code):
        raise FatalBaseException()

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    with pytest.raises(FatalBaseException):
        await generator.generate_remediations(
            [{"id": "A"}, {"id": "B"}],
            "contract C {}",
            parallel=True,
        )


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


def test_get_quick_fix_convenience_function_defaults_malformed_code():
    fixed, explanation = get_quick_fix("access-control", {"code": "function admin() public {}"})

    assert fixed == ""
    assert explanation == "No function code available for quick fix"


def test_string_and_code_helpers_normalize_whitespace_and_control_chars():
    assert RemediationGenerator._parse_vuln_type("  ReEntrancy  ") == "reentrancy"
    assert RemediationGenerator._parse_vuln_type("bad\nvalue") == "unknown"
    assert RemediationGenerator._string_or_default("  hello  ", "fallback") == "hello"
    assert RemediationGenerator._string_or_default("hello\x7f", "fallback") == "fallback"
    assert (
        RemediationGenerator._fixed_code_or_default("  contract C {}  ", "fallback")
        == "contract C {}"
    )
    assert (
        RemediationGenerator._fixed_code_or_default("contract\nC {}", "fallback")
        == "contract\nC {}"
    )


def test_unique_string_list_helper_deduplicates_clean_items():
    assert RemediationGenerator._unique_string_list_or_empty(
        ["  alpha  ", "alpha", "beta", "beta", None, {"x": 1}]
    ) == ["alpha", "beta"]


def test_safe_text_and_export_helpers_reject_unicode_separators():
    assert _safe_text("bad\u2028value") == ""
    assert _safe_text("bad\u2029value", allow_multiline=True) == ""
    assert _export_string("bad\u2028value", "default") == "default"
    assert _export_optional_string("bad\u2029value") is None
    assert _export_explanation("bad\u2028value") == ""
    assert RemediationGenerator._parse_vuln_type("reentrancy\u2028bad") == "unknown"


def test_init_caps_timeout_and_rejects_credentialed_base_url():
    generator = RemediationGenerator(
        ollama_base_url="https://user:pass@example.com:11434/",
        timeout=10_000,
    )

    assert generator.base_url == "http://localhost:11434"
    assert generator.timeout == 600


@pytest.mark.parametrize(
    "base_url",
    [
        "http://exa mple.com",
        "http://ollama.local:11434/base?x=1",
        "http://ollama.local:11434/#frag",
        "http://ollama.local:11434/" + ("a" * 2500),
        "http://ollama.local:11434\u2028",
    ],
)
def test_init_rejects_malformed_base_url_boundaries(base_url):
    generator = RemediationGenerator(ollama_base_url=base_url)

    assert generator.base_url == "http://localhost:11434"


@pytest.mark.parametrize(
    "model",
    [
        "bad model",
        "owner/model",
        "bad\\model",
        "x" * 129,
        "bad\nmodel",
    ],
)
def test_init_defaults_malformed_model_ids(model):
    generator = RemediationGenerator(model=model)

    assert generator.model == "deepseek-coder:6.7b"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["200", True, None])
async def test_query_llm_fails_closed_for_malformed_response_status(monkeypatch, status):
    generator = RemediationGenerator()

    class FakeResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    FakeResponse.status = status

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
async def test_query_llm_returns_empty_dict_when_http_error_text_raises(monkeypatch):
    generator = RemediationGenerator()

    class FakeResponse:
        status = 500

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def text(self):
            raise RuntimeError("text failed")

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
async def test_query_llm_returns_empty_dict_when_response_json_raises(monkeypatch):
    generator = RemediationGenerator()

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            raise ValueError("bad json")

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
async def test_query_llm_handles_hostile_payload_get_and_bounds_content(monkeypatch):
    generator = RemediationGenerator()

    class HostileDict(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return HostileDict({"message": {"content": '{"fixed_code": "contract Fixed {}"}'}})

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
async def test_query_llm_handles_hostile_message_get(monkeypatch):
    generator = RemediationGenerator()

    class HostileMessage(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    class FakeResponse:
        status = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def json(self):
            return {"message": HostileMessage({"content": '{"fixed_code": "contract Fixed {}"}'})}

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(aiohttp, "ClientSession", lambda: FakeSession())

    assert await generator._query_llm("fix this") == {}


def test_parse_json_response_rejects_oversized_and_too_many_keys(monkeypatch):
    generator = RemediationGenerator()
    monkeypatch.setattr(
        "src.llm.remediation_generator.extract_json_from_text",
        lambda _content: pytest.fail("oversized content should not be extracted"),
    )

    assert generator._parse_json_response("x" * 100_001) == {}

    many_keys = "{" + ",".join(f'"k{i}": {i}' for i in range(101)) + "}"
    assert generator._parse_json_response(many_keys) == {}


def test_parse_json_response_handles_extraction_and_recursion_errors(monkeypatch):
    generator = RemediationGenerator()

    monkeypatch.setattr(
        "src.llm.remediation_generator.extract_json_from_text",
        lambda _content: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert generator._parse_json_response("wrapped {bad}") == {}

    monkeypatch.setattr(
        "src.llm.remediation_generator.repair_common_json_errors",
        lambda _content: (_ for _ in ()).throw(RecursionError("deep")),
    )
    assert generator._parse_json_response('{"fixed_code": "contract Fixed {}"}') == {}


def test_parse_json_response_rejects_concatenated_json_objects():
    generator = RemediationGenerator()

    assert generator._parse_json_response('{"fixed_code": "a"}{"fixed_code": "b"}') == {}


@pytest.mark.asyncio
async def test_generate_remediation_defaults_when_finding_get_raises(monkeypatch):
    generator = RemediationGenerator()

    class HostileFinding(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    async def fake_query(prompt):
        assert "- **Type**: unknown" in prompt
        assert "- **Severity**: medium" in prompt
        return {"fixed_code": "contract Fixed {}"}

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(
        HostileFinding({"type": "reentrancy", "snippet": "function withdraw() public {}"}),
        "contract C {}",
    )

    assert remediation.finding_id == "unknown"
    assert remediation.vulnerability_type == "unknown"
    assert remediation.fixed_code == "contract Fixed {}"


@pytest.mark.asyncio
async def test_generate_remediation_defaults_when_llm_result_get_raises(monkeypatch):
    generator = RemediationGenerator()

    class HostileResult(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    async def fake_query(_prompt):
        return HostileResult({"fixed_code": "contract Fixed {}"})

    monkeypatch.setattr(generator, "_query_llm", fake_query)

    remediation = await generator.generate_remediation(
        {"id": "F-1", "type": "reentrancy", "snippet": "function withdraw() public {}"},
        "contract C {}",
    )

    assert remediation.fixed_code == "function withdraw() public {}"
    assert remediation.explanation == ""
    assert remediation.changes_summary == []


def test_extract_vulnerable_code_defaults_when_location_get_raises():
    generator = RemediationGenerator()

    class HostileLocation(dict):
        def get(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    extracted = generator._extract_vulnerable_code(
        {"location": HostileLocation({"function": "withdraw", "line": 3})},
        "contract C { function withdraw() public {} }",
    )

    assert extracted == "contract C { function withdraw() public {} }"


@pytest.mark.parametrize("line", [10.0, "10", True, -1])
def test_extract_vulnerable_code_rejects_ambiguous_line_values(line):
    generator = RemediationGenerator()
    code = "\n".join(f"line {idx}" for idx in range(1, 20))

    extracted = generator._extract_vulnerable_code({"location": {"line": line}}, code)

    assert extracted == code


@pytest.mark.asyncio
async def test_generate_remediations_enforces_batch_size_cap(monkeypatch):
    generator = RemediationGenerator()
    findings = [{"id": f"F-{idx}"} for idx in range(MAX_BATCH_FINDINGS + 5)]
    seen = []

    async def fake_generate(finding, _code):
        seen.append(finding["id"])
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

    result = await generator.generate_remediations(findings, "contract C {}", parallel=False)

    assert result.success_count == MAX_BATCH_FINDINGS
    assert result.failure_count == 5
    assert seen[-1] == f"F-{MAX_BATCH_FINDINGS - 1}"


@pytest.mark.asyncio
async def test_generate_remediations_handles_hostile_batch_iteration(monkeypatch):
    generator = RemediationGenerator()

    class HostileFindings(list):
        def __iter__(self):
            raise RuntimeError("hostile iterator")

    async def fake_generate(_finding, _code):
        raise AssertionError("hostile batch should not dispatch work")

    monkeypatch.setattr(generator, "generate_remediation", fake_generate)

    result = await generator.generate_remediations(
        HostileFindings([{"id": "A"}]),
        "contract C {}",
        parallel=False,
    )

    assert result.success_count == 0
    assert result.failure_count == 1
    assert result.remediations == []


@pytest.mark.asyncio
async def test_generate_remediations_handles_hostile_batch_len(monkeypatch):
    generator = RemediationGenerator()

    class HostileLenFindings(list):
        def __len__(self):
            raise RuntimeError("hostile len")

    processed = []

    async def fake_generate(finding, _code):
        processed.append(finding["id"])
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

    result = await generator.generate_remediations(
        HostileLenFindings([{"id": "A"}, {"id": "B"}]),
        "contract C {}",
        parallel=False,
    )

    assert result.success_count == 2
    assert result.failure_count == 0
    assert processed == ["A", "B"]


@pytest.mark.asyncio
async def test_generate_remediations_parallel_caps_extreme_concurrency(monkeypatch):
    generator = RemediationGenerator()
    active = 0
    peak = 0
    findings = [{"id": str(index)} for index in range(MAX_CONCURRENT_REMEDIATIONS + 5)]

    async def fake_generate(finding, _code):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
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

    result = await generator.generate_remediations(
        findings,
        "contract C {}",
        parallel=True,
        max_concurrent=10_000,
    )

    assert result.success_count == len(findings)
    assert peak <= MAX_CONCURRENT_REMEDIATIONS


@pytest.mark.asyncio
async def test_generate_remediations_parallel_accepts_numeric_string_concurrency(monkeypatch):
    generator = RemediationGenerator()
    active = 0
    peak = 0
    findings = [{"id": str(index)} for index in range(4)]

    async def fake_generate(finding, _code):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
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

    result = await generator.generate_remediations(
        findings,
        "contract C {}",
        parallel=True,
        max_concurrent="2",
    )

    assert result.success_count == 4
    assert peak <= 2


def test_remediation_result_to_dict_caps_exported_remediation_list():
    remediation = Remediation(
        finding_id="F-1",
        vulnerability_type="reentrancy",
        severity="high",
        vulnerable_code="function withdraw() public {}",
        fixed_code="function withdraw() public nonReentrant {}",
        explanation="uses guard",
        changes_summary=[],
        test_suggestions=[],
        references=[],
        confidence=0.8,
    )
    result = RemediationResult(
        remediations=[remediation for _ in range(MAX_REMEDIATION_EXPORTS + 3)],
        success_count=MAX_REMEDIATION_EXPORTS + 3,
        failure_count=0,
        execution_time_ms=1.0,
    )

    exported = result.to_dict()

    assert len(exported["remediations"]) == MAX_REMEDIATION_EXPORTS


def test_remediation_result_to_dict_handles_hostile_remediation_list():
    class HostileRemediations(list):
        def __iter__(self):
            raise RuntimeError("hostile iterator")

    result = RemediationResult(
        remediations=HostileRemediations([]),
        success_count=1,
        failure_count=0,
        execution_time_ms=1.0,
    )

    exported = result.to_dict()

    assert exported["remediations"] == []
