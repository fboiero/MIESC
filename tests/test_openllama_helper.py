import json
import subprocess

from src.llm.openllama_helper import (
    MAX_ANALYZE_RESPONSE_CHARS,
    MAX_GENERATE_RESPONSE_BYTES,
    MAX_PRIORITY_RESPONSE_CHARS,
    MAX_PRIORITY_TEXT_CHARS,
    MAX_REMEDIATION_RESPONSE_CHARS,
    LLMConfig,
    OpenLLaMAHelper,
    enhance_findings_with_llm,
    explain_technical_output,
    generate_remediation_advice,
    prioritize_findings,
)


def test_is_available_caches_successful_ollama_check(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="test-model"))
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, stdout="test-model\nother-model")

    monkeypatch.setattr("subprocess.run", fake_run)

    assert helper.is_available() is True
    assert helper.is_available() is True
    assert len(calls) == 1


def test_is_available_returns_false_when_model_missing(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="missing-model"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout="other-model"),
    )

    assert helper.is_available() is False


def test_is_available_matches_exact_ollama_model_name(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="qwen2.5-coder:14b"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout=(
                "NAME                 ID              SIZE      MODIFIED\n"
                "qwen2.5-coder:14b    abc123          9.0 GB    2 days ago\n"
            ),
        ),
    )

    assert helper.is_available() is True


def test_is_available_normalizes_configured_model_name(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="  qwen2.5-coder:14b  "))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout=(
                "NAME                 ID              SIZE      MODIFIED\n"
                "qwen2.5-coder:14b    abc123          9.0 GB    2 days ago\n"
            ),
        ),
    )

    assert helper.is_available() is True


def test_is_available_rejects_partial_ollama_model_name(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="qwen"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout=(
                "NAME                 ID              SIZE      MODIFIED\n"
                "qwen2.5-coder:14b    abc123          9.0 GB    2 days ago\n"
            ),
        ),
    )

    assert helper.is_available() is False


def test_is_available_rejects_malformed_configured_model_name(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="qwen2.5-coder:14b\nother-model"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout="qwen2.5-coder:14b    abc123\nother-model    def456\n",
        ),
    )

    assert helper.is_available() is False


def test_is_available_rejects_non_string_ollama_list_output(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="test-model"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=["test-model"]),
    )

    assert helper.is_available() is False


def test_ollama_list_model_names_rejects_malformed_splitlines():
    class MalformedModelList(str):
        def splitlines(self, *args, **kwargs):
            raise RuntimeError("bad model list")

    assert OpenLLaMAHelper._ollama_list_model_names(MalformedModelList("test-model")) == ()


def test_ollama_list_model_names_skips_malformed_rows():
    class MalformedModelRow(str):
        def split(self, *args, **kwargs):
            raise RuntimeError("bad model row")

    class ModelList(str):
        def splitlines(self, *args, **kwargs):
            return [
                "NAME                 ID",
                MalformedModelRow("valid-model abc123"),
                "valid-model          def456",
            ]

    assert OpenLLaMAHelper._ollama_list_model_names(ModelList("")) == ("valid-model",)


def test_ollama_list_model_names_accepts_bytes_payload():
    payload = b"NAME                 ID\nvalid-model          abc123\n"

    assert OpenLLaMAHelper._ollama_list_model_names(payload) == ("valid-model",)


def test_ollama_model_name_strips_and_rejects_control_chars():
    assert OpenLLaMAHelper._ollama_model_name("  valid-model  ") == "valid-model"
    assert OpenLLaMAHelper._ollama_model_name("valid\nmodel") is None


def test_subprocess_text_rejects_control_chars():
    class Result:
        stdout = "  valid output  "
        stderr = "bad\noutput"

    assert OpenLLaMAHelper._subprocess_text(Result(), "stdout") == "  valid output  "
    assert OpenLLaMAHelper._subprocess_text(Result(), "stderr") == ""


def test_is_available_returns_false_on_malformed_ollama_result(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="test-model"))

    class MalformedResult:
        stdout = "test-model"

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MalformedResult())

    assert helper.is_available() is False


def test_is_available_rejects_bool_returncode(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="test-model"))

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            False,
            stdout="test-model",
        ),
    )

    assert helper.is_available() is False


def test_is_available_handles_malformed_stderr_accessor(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(model="test-model"))

    class MalformedResult:
        returncode = 1
        stdout = ""

        @property
        def stderr(self):
            raise RuntimeError("bad stderr")

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MalformedResult())

    assert helper.is_available() is False


def test_is_available_returns_false_on_runtime_error(monkeypatch):
    helper = OpenLLaMAHelper()

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("ollama")

    monkeypatch.setattr("subprocess.run", raise_file_not_found)

    assert helper.is_available() is False


def test_enhance_findings_returns_original_when_unavailable(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [{"severity": "HIGH", "title": "Reentrancy"}]

    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert helper.enhance_findings(findings, "contract C {}", "slither") is findings


def test_enhance_findings_only_processes_top_severity_items(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [
        {"severity": "LOW", "title": "low"},
        {"severity": "CRITICAL", "title": "critical"},
        {"severity": "MEDIUM", "title": "medium"},
        {"severity": "HIGH", "title": "high"},
        {"severity": "INFO", "title": "info"},
        {"severity": "LOW", "title": "second-low"},
    ]
    enhanced_titles = []

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_generate(finding, context, adapter_name):
        enhanced_titles.append(finding["title"])
        return f"insight for {finding['title']}"

    monkeypatch.setattr(helper, "_generate_insights", fake_generate)

    result = helper.enhance_findings(findings, "contract C {}", "adapter")

    assert result is findings
    assert enhanced_titles == ["critical", "high", "medium", "low", "second-low"]
    assert findings[1]["llm_enhanced"] is True
    assert "llm_insights" not in findings[4]


def test_enhance_findings_handles_non_string_severity(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [
        {"severity": ["HIGH"], "title": "malformed"},
        {"severity": "HIGH", "title": "high"},
    ]
    enhanced_titles = []

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_generate(finding, context, adapter_name):
        enhanced_titles.append(finding["title"])
        return f"insight for {finding['title']}"

    monkeypatch.setattr(helper, "_generate_insights", fake_generate)

    result = helper.enhance_findings(findings, "contract C {}", "adapter")

    assert result is findings
    assert enhanced_titles == ["high", "malformed"]
    assert findings[0]["llm_enhanced"] is True


def test_enhance_findings_returns_malformed_top_level_findings(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = {"severity": "HIGH", "title": "not a list"}

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fail_generate(*args, **kwargs):
        raise AssertionError("malformed top-level findings should not be enhanced")

    monkeypatch.setattr(helper, "_generate_insights", fail_generate)

    assert helper.enhance_findings(findings, "contract C {}", "adapter") is findings


def test_enhance_findings_skips_non_dict_items_and_defaults_prompt_inputs(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [
        ["not", "a", "finding"],
        {"severity": "HIGH", "title": "valid"},
        "malformed",
    ]
    calls = []

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_generate(finding, context, adapter_name):
        calls.append((finding, context, adapter_name))
        return "insight"

    monkeypatch.setattr(helper, "_generate_insights", fake_generate)

    result = helper.enhance_findings(findings, {"source": "contract C {}"}, ["slither"])

    assert result is findings
    assert calls == [({"severity": "HIGH", "title": "valid", "llm_insights": "insight", "llm_enhanced": True}, "", "adapter")]
    assert findings[1]["llm_enhanced"] is True


def test_explain_technical_output_uses_fallback_when_unavailable(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert helper.explain_technical_output("raw output", "tool") == "raw output"


def test_explain_technical_output_returns_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "plain explanation")

    assert helper.explain_technical_output("raw output", "tool") == "plain explanation"


def test_explain_technical_output_falls_back_on_malformed_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: {"response": "plain explanation"})

    assert helper.explain_technical_output("raw output", "tool") == "raw output"


def test_explain_technical_output_sanitizes_malformed_prompt_inputs(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "plain explanation"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    assert (
        helper.explain_technical_output({"stdout": ["raw", "output"]}, ["slither"])
        == "plain explanation"
    )
    assert "technical output from adapter" in captured["prompt"]
    assert "TECHNICAL OUTPUT:\n  # Truncate to fit context" in captured["prompt"]
    assert "{'stdout':" not in captured["prompt"]
    assert "['slither']" not in captured["prompt"]


def test_call_llm_ignores_non_object_generate_payload(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps([{"response": "wrong envelope"}]).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") is None


def test_call_llm_ignores_non_string_generate_response(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": ["not", "text"]}).encode()

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") is None


def test_call_llm_ignores_generate_payload_with_bad_response_accessor(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))
    original_json_loads = json.loads

    class MalformedPayload(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("bad response accessor")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"response": "ignored"}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(
        "json.loads",
        lambda raw, *args, **kwargs: MalformedPayload()
        if raw == b'{"response": "ignored"}'
        else original_json_loads(raw, *args, **kwargs),
    )

    assert helper._call_llm("prompt") is None


def test_call_llm_ignores_generate_payload_with_bad_response_strip(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))
    original_json_loads = json.loads

    class MalformedText(str):
        def strip(self, *args, **kwargs):
            raise RuntimeError("bad response text")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"response": "ignored"}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(
        "json.loads",
        lambda raw, *args, **kwargs: {"response": MalformedText("bad")}
        if raw == b'{"response": "ignored"}'
        else original_json_loads(raw, *args, **kwargs),
    )

    assert helper._call_llm("prompt") is None


def test_call_llm_retries_after_malformed_response_body_read(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=2, retry_delay=0))
    calls = 0

    class MalformedResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            raise RuntimeError("bad body")

    class ValidResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": "recovered"}).encode()

    def fake_urlopen(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return MalformedResponse()
        return ValidResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert helper._call_llm("prompt") == "recovered"
    assert calls == 2


def test_call_llm_ignores_malformed_generate_body(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return None

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") is None


def test_call_llm_ignores_oversized_generate_payload(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"x" * (MAX_GENERATE_RESPONSE_BYTES + 1)

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") is None


def test_call_llm_accepts_bounded_string_generate_payload(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": "bounded text"})

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") == "bounded text"


def test_call_llm_accepts_line_delimited_generate_fragments(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return (
                b'{"response": "hello "}\n'
                b'{"response": ["not", "text"]}\n'
                b"not json\n"
                b'{"response": "world"}\n'
                b'{"done": true}\n'
            )

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    assert helper._call_llm("prompt") == "hello world"


def test_call_llm_ignores_malformed_line_delimited_generate_fragments(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))
    original_json_loads = json.loads

    class MalformedPayload(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("bad fragment accessor")

    class MalformedText(str):
        def strip(self, *args, **kwargs):
            raise RuntimeError("bad fragment text")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return (
                b'{"response": "bad accessor"}\n'
                b'{"response": "bad strip"}\n'
                b'{"response": "bad chunk"}\n'
                b'{"response": "ok"}'
            )

    def fake_json_loads(raw, *args, **kwargs):
        if raw == b'{"response": "bad accessor"}':
            return MalformedPayload()
        if raw == b'{"response": "bad strip"}':
            return {"response": MalformedText("bad")}
        if raw == b'{"response": "bad chunk"}':
            raise RuntimeError("bad streamed chunk")
        return original_json_loads(raw, *args, **kwargs)

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr("json.loads", fake_json_loads)

    assert helper._call_llm("prompt") == "ok"


def test_call_llm_defaults_malformed_timeout_and_retry_config(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(timeout=["slow"], retry_attempts=["many"], retry_delay=False))
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": "bounded text"}).encode()

    def fake_urlopen(req, timeout):
        calls.append((req.full_url, timeout))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert helper._call_llm("prompt") == "bounded text"
    assert calls == [("http://localhost:11434/api/generate", 120.0)]


def test_call_llm_sanitizes_malformed_generate_request_body_fields(monkeypatch):
    helper = OpenLLaMAHelper(
        LLMConfig(
            model=["bad-model"],
            temperature=float("nan"),
            max_tokens={"bad": "tokens"},
            retry_attempts=1,
        )
    )
    bodies = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": "bounded text"}).encode()

    def fake_urlopen(req, timeout):
        bodies.append(json.loads(req.data.decode()))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert helper._call_llm(["bad", "prompt"]) == "bounded text"
    assert bodies == [
        {
            "model": "qwen2.5-coder:14b",
            "prompt": "",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 500,
            },
        }
    ]


def test_call_llm_defaults_malformed_ollama_host(monkeypatch):
    helper = OpenLLaMAHelper(LLMConfig(retry_attempts=1))
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"response": "bounded text"}).encode()

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        return FakeResponse()

    monkeypatch.setenv("OLLAMA_HOST", "https://")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert helper._call_llm("prompt") == "bounded text"
    assert calls == ["http://localhost:11434/api/generate"]


def test_prioritize_findings_applies_valid_indices_only(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [{"title": "A", "severity": "LOW"}, {"title": "B", "severity": "HIGH"}]

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "priorities")
    monkeypatch.setattr(
        helper,
        "_parse_priorities",
        lambda response: {
            1: {"priority": 8, "reason": "reachable"},
            10: {"priority": 9, "reason": "out of range"},
        },
    )

    result = helper.prioritize_findings(findings, "contract C {}")

    assert result is findings
    assert findings[1]["llm_priority"] == 8
    assert findings[1]["llm_reason"] == "reachable"
    assert "llm_priority" not in findings[0]


def test_prioritize_findings_ignores_malformed_parsed_priorities_container(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [{"title": "A", "severity": "LOW"}]

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "priorities")
    monkeypatch.setattr(helper, "_parse_priorities", lambda response: ["not", "a", "mapping"])

    result = helper.prioritize_findings(findings, "contract C {}")

    assert result is findings
    assert "llm_priority" not in findings[0]
    assert "llm_reason" not in findings[0]


def test_prioritize_findings_skips_malformed_parsed_priority_boundaries(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [
        {"title": "A", "severity": "LOW"},
        "not a finding",
        {"title": "C", "severity": "HIGH"},
        {"title": "D", "severity": "MEDIUM"},
    ]

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "priorities")
    monkeypatch.setattr(
        helper,
        "_parse_priorities",
        lambda response: {
            0: ["not", "a", "priority"],
            1: {"priority": 9, "reason": "malformed finding"},
            2: {"priority": True, "reason": {"why": "bad shape"}},
            3: {"priority": 7, "reason": "valid"},
        },
    )

    result = helper.prioritize_findings(findings, "contract C {}")

    assert result is findings
    assert "llm_priority" not in findings[0]
    assert findings[1] == "not a finding"
    assert findings[2]["llm_priority"] == 5
    assert findings[2]["llm_reason"] == ""
    assert findings[3]["llm_priority"] == 7
    assert findings[3]["llm_reason"] == "valid"


def test_prioritize_findings_defaults_out_of_range_parsed_priorities(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [
        {"title": "A", "severity": "LOW"},
        {"title": "B", "severity": "HIGH"},
        {"title": "C", "severity": "MEDIUM"},
    ]

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "priorities")
    monkeypatch.setattr(
        helper,
        "_parse_priorities",
        lambda response: {
            0: {"priority": 0, "reason": "too low"},
            1: {"priority": 11, "reason": "too high"},
            2: {"priority": 10, "reason": "valid"},
        },
    )

    result = helper.prioritize_findings(findings, "contract C {}")

    assert result is findings
    assert findings[0]["llm_priority"] == 5
    assert findings[0]["llm_reason"] == "too low"
    assert findings[1]["llm_priority"] == 5
    assert findings[1]["llm_reason"] == "too high"
    assert findings[2]["llm_priority"] == 10
    assert findings[2]["llm_reason"] == "valid"


def test_prioritize_findings_sanitizes_malformed_contract_prompt(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = [{"title": "A", "severity": "LOW"}]
    captured = {}

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "priorities"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)
    monkeypatch.setattr(
        helper,
        "_parse_priorities",
        lambda response: {0: {"priority": 6, "reason": "reachable"}},
    )

    result = helper.prioritize_findings(findings, {"source": "contract C {}"})

    assert result is findings
    assert findings[0]["llm_priority"] == 6
    assert "CONTRACT CONTEXT:\n  # First 1000 chars" in captured["prompt"]
    assert "{'source':" not in captured["prompt"]


def test_prioritize_findings_returns_malformed_top_level_findings_without_prompt(monkeypatch):
    helper = OpenLLaMAHelper()
    findings = "not a finding list"

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fail_call_llm(*args, **kwargs):
        raise AssertionError("malformed top-level findings should not reach the prompt")

    monkeypatch.setattr(helper, "_call_llm", fail_call_llm)

    assert helper.prioritize_findings(findings, "contract C {}") is findings


def test_generate_remediation_advice_uses_recommendation_when_unavailable(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    advice = helper.generate_remediation_advice(
        {"recommendation": "Use checks-effects-interactions"},
        "contract C {}",
    )

    assert advice == "Use checks-effects-interactions"


def test_generate_remediation_advice_trims_recommendation_fallback(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    advice = helper.generate_remediation_advice(
        {"recommendation": "\n  Use checks-effects-interactions  \t"},
        "contract C {}",
    )

    assert advice == "Use checks-effects-interactions"


def test_generate_remediation_advice_caps_oversized_recommendation_fallback(monkeypatch):
    helper = OpenLLaMAHelper()
    oversized = "x" * (MAX_REMEDIATION_RESPONSE_CHARS + 100)
    monkeypatch.setattr(helper, "is_available", lambda: False)

    advice = helper.generate_remediation_advice(
        {"recommendation": oversized},
        "contract C {}",
    )

    assert advice == "x" * MAX_REMEDIATION_RESPONSE_CHARS


def test_generate_remediation_advice_defaults_for_blank_recommendation(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert (
        helper.generate_remediation_advice({"recommendation": " \n\t "}, "contract C {}")
        == "Review and address the identified issue"
    )


def test_generate_remediation_advice_defaults_when_recommendation_missing(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert (
        helper.generate_remediation_advice({}, "contract C {}")
        == "Review and address the identified issue"
    )


def test_generate_remediation_advice_defaults_for_non_string_recommendation(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert (
        helper.generate_remediation_advice(
            {"recommendation": ["not", "a", "string"]},
            "contract C {}",
        )
        == "Review and address the identified issue"
    )


def test_generate_remediation_advice_defaults_for_non_dict_finding(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: False)

    assert (
        helper.generate_remediation_advice(["not", "a", "finding"], "contract C {}")
        == "Review and address the identified issue"
    )


def test_generate_remediation_advice_returns_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "patch the access check")

    advice = helper.generate_remediation_advice({"title": "Missing auth"}, "contract C {}")

    assert advice == "patch the access check"


def test_generate_remediation_advice_caps_oversized_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    oversized = "x" * (MAX_REMEDIATION_RESPONSE_CHARS + 100)

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: oversized)

    advice = helper.generate_remediation_advice({"title": "Missing auth"}, "contract C {}")

    assert advice == "x" * MAX_REMEDIATION_RESPONSE_CHARS


def test_generate_remediation_advice_falls_back_to_string_recommendation(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "")

    advice = helper.generate_remediation_advice(
        {"recommendation": "Use onlyOwner"},
        "contract C {}",
    )

    assert advice == "Use onlyOwner"


def test_generate_remediation_advice_falls_back_on_malformed_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: ["patch the access check"])

    advice = helper.generate_remediation_advice(
        {"recommendation": "Use onlyOwner"},
        "contract C {}",
    )

    assert advice == "Use onlyOwner"


def test_generate_remediation_advice_sanitizes_malformed_prompt_fields(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "review the vulnerable path"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    advice = helper.generate_remediation_advice(
        {
            "title": ["Missing auth"],
            "severity": {"level": "HIGH"},
            "description": ["not", "text"],
            "location": ["line", 12],
        },
        {"source": "contract C {}"},
    )

    assert advice == "review the vulnerable path"
    assert "Title: Unknown" in captured["prompt"]
    assert "Severity: UNKNOWN" in captured["prompt"]
    assert "Description: \n" in captured["prompt"]
    assert "Location: {}" in captured["prompt"]
    assert "{'source':" not in captured["prompt"]
    assert "['Missing auth']" not in captured["prompt"]


def test_generate_remediation_advice_sanitizes_malformed_location_dict(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "review the vulnerable path"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    advice = helper.generate_remediation_advice(
        {
            "title": "Missing auth",
            "location": {"line": 12, "node": object()},
        },
        "contract C {}",
    )

    assert advice == "review the vulnerable path"
    assert 'Location: {"line": 12, "node": ""}' in captured["prompt"]
    assert "<object object at" not in captured["prompt"]


def test_generate_remediation_advice_defaults_malformed_finding_accessor(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    class MalformedFinding(dict):
        def get(self, key, default=None):
            raise RuntimeError("bad finding access")

    monkeypatch.setattr(helper, "is_available", lambda: True)

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "review the vulnerable path"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    advice = helper.generate_remediation_advice(
        MalformedFinding(
            {
                "title": "Missing auth",
                "description": "reachable owner bypass",
            }
        ),
        "contract C {}",
    )

    assert advice == "review the vulnerable path"
    assert "Title: Unknown" in captured["prompt"]
    assert "Description: \n" in captured["prompt"]
    assert "Missing auth" not in captured["prompt"]


def test_generate_remediation_advice_fallback_defaults_malformed_finding_accessor(monkeypatch):
    helper = OpenLLaMAHelper()

    class MalformedFinding(dict):
        def get(self, key, default=None):
            raise RuntimeError("bad finding access")

    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "")

    assert (
        helper.generate_remediation_advice(
            MalformedFinding({"recommendation": "Use onlyOwner"}),
            "contract C {}",
        )
        == "Review and address the identified issue"
    )


def test_generate_remediation_advice_empty_llm_rejects_non_string_recommendation(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "is_available", lambda: True)
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: "")

    assert (
        helper.generate_remediation_advice(
            {"recommendation": {"text": "Use onlyOwner"}},
            "contract C {}",
        )
        == "Review and address the identified issue"
    )


def test_private_helpers_format_summary_and_severity():
    helper = OpenLLaMAHelper()

    summary = helper._create_findings_summary(
        [
            {
                "severity": "HIGH",
                "title": "Unchecked call",
                "description": "x" * 150,
            }
        ]
    )

    assert helper._severity_score("critical") == 4
    assert helper._severity_score("unknown") == 0
    assert helper._severity_score(["HIGH"]) == 0
    assert summary.startswith("0. [HIGH] Unchecked call - ")
    assert len(summary.split(" - ", 1)[1]) == 100


def test_create_findings_summary_ignores_non_string_description():
    helper = OpenLLaMAHelper()

    summary = helper._create_findings_summary(
        [
            {
                "severity": "LOW",
                "title": "Malformed description",
                "description": ["not", "text"],
            }
        ]
    )

    assert summary == "0. [LOW] Malformed description - "


def test_create_findings_summary_keeps_fields_on_one_line():
    helper = OpenLLaMAHelper()

    summary = helper._create_findings_summary(
        [
            {
                "severity": "HIGH\n1. [CRITICAL]",
                "title": "Unchecked call\r\n2. forged finding",
                "description": "line one\nline two",
            }
        ]
    )

    assert summary == (
        "0. [HIGH 1. [CRITICAL]] Unchecked call 2. forged finding - line one line two"
    )
    assert summary.count("\n") == 0


def test_create_findings_summary_defaults_malformed_title_and_severity():
    helper = OpenLLaMAHelper()

    summary = helper._create_findings_summary(
        [
            {
                "severity": ["HIGH"],
                "title": {"name": "Malformed"},
                "description": "still textual",
            }
        ]
    )

    assert summary == "0. [UNKNOWN] Unknown - still textual"
    assert "['HIGH']" not in summary
    assert "{'name':" not in summary


def test_generate_insights_sorts_finding_keys(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "insight"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    assert helper._generate_insights({"z_key": 1, "a_key": 2}, "contract C {}", "adapter")
    assert captured["prompt"].index('"a_key"') < captured["prompt"].index('"z_key"')


def test_generate_insights_defaults_unsupported_finding_field_shapes(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "insight"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    assert helper._generate_insights(
        {
            "title": "Missing auth",
            "metadata": {"owner": object()},
            "evidence": [object(), "reachable"],
        },
        {"source": "contract C {}"},
        ["slither"],
    )

    assert "Analyze this security finding from adapter" in captured["prompt"]
    assert "CONTRACT CONTEXT:\n\n" in captured["prompt"]
    assert '"title": "Missing auth"' in captured["prompt"]
    assert '"owner": ""' in captured["prompt"]
    assert '"evidence": [\n    "",\n    "reachable"\n  ]' in captured["prompt"]
    assert "<object object at" not in captured["prompt"]
    assert "{'source':" not in captured["prompt"]
    assert "['slither']" not in captured["prompt"]


def test_generate_insights_defaults_cyclic_finding_metadata(monkeypatch):
    helper = OpenLLaMAHelper()
    captured = {}
    metadata = {"source": "adapter"}
    metadata["self"] = metadata

    def fake_call_llm(prompt):
        captured["prompt"] = prompt
        return "insight"

    monkeypatch.setattr(helper, "_call_llm", fake_call_llm)

    assert helper._generate_insights(
        {"title": "Missing auth", "metadata": metadata},
        "contract C {}",
        "adapter",
    )

    assert "FINDING:\n{}" in captured["prompt"]
    assert "'self':" not in captured["prompt"]
    assert "<RecursionError" not in captured["prompt"]


def test_generate_insights_rejects_malformed_llm_response(monkeypatch):
    helper = OpenLLaMAHelper()
    monkeypatch.setattr(helper, "_call_llm", lambda prompt: {"insight": "reachable exploit"})

    assert helper._generate_insights({"title": "Missing auth"}, "contract C {}", "adapter") is None


def test_generate_insights_caps_oversized_analyze_output(monkeypatch):
    helper = OpenLLaMAHelper()
    oversized = "x" * (MAX_ANALYZE_RESPONSE_CHARS + 100)

    monkeypatch.setattr(helper, "_call_llm", lambda prompt: oversized)

    assert (
        helper._generate_insights({"title": "Missing auth"}, "contract C {}", "adapter")
        == "x" * MAX_ANALYZE_RESPONSE_CHARS
    )


def test_convenience_functions_delegate_to_helper(monkeypatch):
    calls = []

    class FakeHelper:
        def __init__(self, config=None):
            calls.append(("init", config))

        def enhance_findings(self, findings, contract_code, adapter_name):
            calls.append(("enhance", findings, contract_code, adapter_name))
            return ["enhanced"]

        def explain_technical_output(self, output, adapter_name):
            calls.append(("explain", output, adapter_name))
            return "explained"

        def prioritize_findings(self, findings, contract_code):
            calls.append(("prioritize", findings, contract_code))
            return ["prioritized"]

        def generate_remediation_advice(self, finding, contract_code):
            calls.append(("remediate", finding, contract_code))
            return "advice"

    monkeypatch.setattr("src.llm.openllama_helper.OpenLLaMAHelper", FakeHelper)

    config = LLMConfig(model="fake")

    assert enhance_findings_with_llm([{"id": 1}], "code", "adapter", config) == ["enhanced"]
    assert explain_technical_output("raw", "adapter", config) == "explained"
    assert prioritize_findings([{"id": 1}], "code", config) == ["prioritized"]
    assert generate_remediation_advice({"id": 1}, "code", config) == "advice"
    assert calls == [
        ("init", config),
        ("enhance", [{"id": 1}], "code", "adapter"),
        ("init", config),
        ("explain", "raw", "adapter"),
        ("init", config),
        ("prioritize", [{"id": 1}], "code"),
        ("init", config),
        ("remediate", {"id": 1}, "code"),
    ]


def test_parse_priorities_accepts_wrapped_json():
    helper = OpenLLaMAHelper()
    response = """
    Priority assessment:
    {
        "priorities": [
            {"index": 0, "priority": 9, "reason": "Critical exploit path"}
        ]
    }
    """

    priorities = helper._parse_priorities(response)

    assert priorities == {0: {"priority": 9, "reason": "Critical exploit path"}}


def test_parse_priorities_repairs_common_llm_json_errors():
    helper = OpenLLaMAHelper()
    response = """
    ```json
    {
        priorities: [
            {index: 2, priority: 7, reason: "Likely reachable",},
        ],
    }
    ```
    """

    priorities = helper._parse_priorities(response)

    assert priorities == {2: {"priority": 7, "reason": "Likely reachable"}}


def test_parse_priorities_repairs_invalid_backslash_escapes():
    helper = OpenLLaMAHelper()
    response = r'{"priorities": [{"index": 1, "priority": 6, "reason": "pattern \d+ matched"}]}'

    priorities = helper._parse_priorities(response)

    assert priorities[1]["priority"] == 6
    assert priorities[1]["reason"] == r"pattern \d+ matched"


def test_parse_priorities_returns_empty_on_unparseable_response():
    helper = OpenLLaMAHelper()

    assert helper._parse_priorities("not json") == {}


def test_parse_priorities_rejects_non_string_response():
    helper = OpenLLaMAHelper()

    assert helper._parse_priorities({"priorities": []}) == {}


def test_parse_priorities_rejects_oversized_response():
    helper = OpenLLaMAHelper()
    response = "x" * (MAX_PRIORITY_RESPONSE_CHARS + 1)

    assert helper._parse_priorities(response) == {}


def test_parse_priorities_rejects_non_object_json():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        '[{"priorities": [{"index": 0, "priority": 9, "reason": "nested object"}]}]'
    )

    assert priorities == {}


def test_parse_priorities_rejects_non_list_priorities():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        '{"priorities": {"index": 0, "priority": 9, "reason": "wrong shape"}}'
    )

    assert priorities == {}


def test_parse_priorities_skips_malformed_priority_items():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        """
        {
            "priorities": [
                "not an object",
                {"index": 1, "priority": 8, "reason": "valid"},
                ["also invalid"]
            ]
        }
        """
    )

    assert priorities == {1: {"priority": 8, "reason": "valid"}}


def test_parse_priorities_skips_non_integer_indexes():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        """
        {
            "priorities": [
                {"index": "1", "priority": 9, "reason": "string index"},
                {"index": true, "priority": 7, "reason": "bool index"},
                {"index": 2, "priority": 8, "reason": "valid index"}
            ]
        }
        """
    )

    assert priorities == {2: {"priority": 8, "reason": "valid index"}}


def test_parse_priorities_defaults_malformed_priority_payload_fields():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        """
        {
            "priorities": [
                {"index": 0, "priority": ["critical"], "reason": {"why": "bad shape"}},
                {"index": 1, "priority": true, "reason": "bool priority"}
            ]
        }
        """
    )

    assert priorities == {
        0: {"priority": 5, "reason": ""},
        1: {"priority": 5, "reason": "bool priority"},
    }


def test_parse_priorities_bounds_priority_reason_text_fields():
    helper = OpenLLaMAHelper()
    oversized_reason = "x" * (MAX_PRIORITY_TEXT_CHARS + 10)

    priorities = helper._parse_priorities(
        json.dumps(
            {
                "priorities": [
                    {"index": 0, "priority": 8, "reason": oversized_reason},
                    {"index": 1, "priority": 6, "reason": ["not", "text"]},
                ]
            }
        )
    )

    assert priorities == {
        0: {"priority": 8, "reason": "x" * MAX_PRIORITY_TEXT_CHARS},
        1: {"priority": 6, "reason": ""},
    }


def test_parse_priorities_defaults_out_of_range_priority_scores():
    helper = OpenLLaMAHelper()

    priorities = helper._parse_priorities(
        """
        {
            "priorities": [
                {"index": 0, "priority": 0, "reason": "too low"},
                {"index": 1, "priority": 11, "reason": "too high"},
                {"index": 2, "priority": 1, "reason": "minimum"},
                {"index": 3, "priority": 10, "reason": "maximum"}
            ]
        }
        """
    )

    assert priorities == {
        0: {"priority": 5, "reason": "too low"},
        1: {"priority": 5, "reason": "too high"},
        2: {"priority": 1, "reason": "minimum"},
        3: {"priority": 10, "reason": "maximum"},
    }
