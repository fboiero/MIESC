"""Tests for FrontierLLMAdapter.converse_with_tools — OpenAI function-calling.

Fully offline: the openai client is mocked (sys.modules injection) so no real
API call is made. Mirrors tests/test_converse_with_tools.py (Anthropic) for the
OpenAI branch: happy path (one tool round → final content) and the
max_iterations cutoff (model keeps requesting tools forever).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import json
import sys
import types
from typing import Any, Dict, List

import pytest

from miesc.adapters.frontier_llm_adapter import (
    ConversationResult,
    FrontierLLMAdapter,
    ToolSpec,
)

# ---------------------------------------------------------------------------
# Minimal stand-ins for the openai SDK response objects. The adapter reads
# response.choices[0].message.{content,tool_calls} and each tool_call's
# .id / .function.name / .function.arguments — plain attribute holders suffice.
# ---------------------------------------------------------------------------


class _Function:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, id: str, name: str, arguments: str) -> None:
        self.id = id
        self.type = "function"
        self.function = _Function(name, arguments)


class _ChatMessage:
    def __init__(self, content: Any, tool_calls: Any = None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _Choice:
    def __init__(self, message: _ChatMessage) -> None:
        self.message = message


class _Usage:
    def __init__(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.completion_tokens_details = None


class _Response:
    def __init__(self, message: _ChatMessage, usage: _Usage) -> None:
        self.choices = [_Choice(message)]
        self.usage = usage


class _FakeCompletions:
    """Serves scripted responses; records the kwargs of every create() call."""

    def __init__(self, scripted: List[_Response], always: _Response = None) -> None:
        self._scripted = list(scripted)
        self._always = always
        self.calls: List[Dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Response:
        self.calls.append(kwargs)
        if self._scripted:
            return self._scripted.pop(0)
        if self._always is not None:
            return self._always
        raise AssertionError("create() called more times than scripted")


class _FakeChat:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.completions = completions


class _FakeClient:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.chat = _FakeChat(completions)


def _install_fake_openai(monkeypatch, fake_completions: _FakeCompletions) -> _FakeClient:
    """Inject a stub `openai` module so `import openai` inside the method
    resolves to our fake, regardless of whether the real SDK is installed."""
    client = _FakeClient(fake_completions)
    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = lambda *a, **k: client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_openai_tool_round_then_final_text(monkeypatch):
    """First response requests a tool_call; second returns final content. The
    loop must parse the JSON args, call on_tool_call, append a role:"tool"
    message with the tool_call_id, and terminate with the correct final text
    and a one-entry trace."""
    scripted = [
        _Response(
            message=_ChatMessage(
                content=None,
                tool_calls=[
                    _ToolCall(
                        id="call_01",
                        name="get_function_body",
                        arguments=json.dumps({"contract": "Wallet", "function": "withdraw"}),
                    )
                ],
            ),
            usage=_Usage(prompt_tokens=100, completion_tokens=50),
        ),
        _Response(
            message=_ChatMessage(
                content="Final answer: reentrancy in withdraw()",
                tool_calls=None,
            ),
            usage=_Usage(prompt_tokens=120, completion_tokens=30),
        ),
    ]
    fake_completions = _FakeCompletions(scripted)
    _install_fake_openai(monkeypatch, fake_completions)

    seen_calls: List[tuple] = []

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        seen_calls.append((name, args))
        return "function withdraw() public { ... }"

    adapter = FrontierLLMAdapter(provider="openai")
    tools = [
        ToolSpec(
            name="get_function_body",
            description="Return the exact source of a function.",
            input_schema={
                "type": "object",
                "properties": {
                    "contract": {"type": "string"},
                    "function": {"type": "string"},
                },
                "required": ["contract", "function"],
            },
        )
    ]

    result = adapter.converse_with_tools(
        system="You are an auditor.",
        messages=[{"role": "user", "content": "Audit this repo."}],
        tools=tools,
        on_tool_call=on_tool_call,
    )

    # on_tool_call was invoked once with the correctly-parsed (JSON) args.
    assert seen_calls == [("get_function_body", {"contract": "Wallet", "function": "withdraw"})]

    # Result shape.
    assert isinstance(result, ConversationResult)
    assert result.final_text == "Final answer: reentrancy in withdraw()"

    # Trace has exactly one entry with name/args/result.
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["name"] == "get_function_body"
    assert result.tool_calls[0]["args"] == {"contract": "Wallet", "function": "withdraw"}
    assert result.tool_calls[0]["result"] == "function withdraw() public { ... }"

    # A role:"tool" message with the tool_call_id + result was appended.
    tool_turns = [m for m in result.messages if isinstance(m, dict) and m.get("role") == "tool"]
    assert len(tool_turns) == 1
    assert tool_turns[0]["tool_call_id"] == "call_01"
    assert tool_turns[0]["content"] == "function withdraw() public { ... }"

    # System prompt was carried as the first message.
    assert result.messages[0] == {"role": "system", "content": "You are an auditor."}

    # Loop terminated after two API calls (one tool round + final).
    assert len(fake_completions.calls) == 2

    # Tools were translated to OpenAI function format on every call.
    first_tools = fake_completions.calls[0]["tools"]
    assert first_tools == [
        {
            "type": "function",
            "function": {
                "name": "get_function_body",
                "description": "Return the exact source of a function.",
                "parameters": tools[0].input_schema,
            },
        }
    ]

    # Default model routed to OpenAI's gpt-4o (max_tokens path).
    assert fake_completions.calls[0]["model"] == "gpt-4o"
    assert fake_completions.calls[0]["max_tokens"] == 8192

    # Usage accumulated across both calls.
    assert result.usage == {"input_tokens": 220, "output_tokens": 80}


def test_openai_max_iterations_cutoff_forces_final_answer(monkeypatch):
    """If the model never stops requesting tools, the loop stops after exactly
    max_iterations rounds and then makes ONE MORE call with tools DISABLED to
    force a final answer. final_text must come from that forced call."""
    tool_round = _Response(
        message=_ChatMessage(
            content=None,
            tool_calls=[
                _ToolCall(
                    id="call_loop",
                    name="list_callers",
                    arguments=json.dumps({"contract": "Wallet", "function": "withdraw"}),
                )
            ],
        ),
        usage=_Usage(prompt_tokens=10, completion_tokens=5),
    )
    forced_final = _Response(
        message=_ChatMessage(content="Forced final: [] no candidates", tool_calls=None),
        usage=_Usage(prompt_tokens=20, completion_tokens=8),
    )
    # First 3 calls loop on tools; the 4th (forced, no tools) returns content.
    fake_completions = _FakeCompletions(scripted=[tool_round, tool_round, tool_round, forced_final])
    _install_fake_openai(monkeypatch, fake_completions)

    call_count = {"n": 0}

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        call_count["n"] += 1
        return "caller: someFunction()"

    adapter = FrontierLLMAdapter(provider="openai")
    tools = [
        ToolSpec(
            name="list_callers",
            description="List callers of a function.",
            input_schema={"type": "object", "properties": {}},
        )
    ]

    result = adapter.converse_with_tools(
        system="You are an auditor.",
        messages=[{"role": "user", "content": "Audit this repo."}],
        tools=tools,
        on_tool_call=on_tool_call,
        max_iterations=3,
    )

    # max_iterations tool rounds + one forced-final call = 4 API calls.
    assert len(fake_completions.calls) == 4
    assert call_count["n"] == 3
    assert len(result.tool_calls) == 3

    # final_text now comes from the forced (no-tools) call.
    assert result.final_text == "Forced final: [] no candidates"

    # The last create() call was made WITHOUT tools.
    assert "tools" not in fake_completions.calls[-1]
    # ...while the tool rounds all carried tools.
    for call in fake_completions.calls[:3]:
        assert "tools" in call

    # Usage accumulated across the 3 tool rounds + the forced-final call.
    assert result.usage == {"input_tokens": 50, "output_tokens": 23}


def test_openai_branch_selected_by_model_id(monkeypatch):
    """Even when the adapter's configured provider is anthropic, an explicit
    gpt-* model id must route to the OpenAI branch (import openai, not
    anthropic)."""
    scripted = [
        _Response(
            message=_ChatMessage(content="done", tool_calls=None),
            usage=_Usage(prompt_tokens=1, completion_tokens=1),
        )
    ]
    fake_completions = _FakeCompletions(scripted)
    _install_fake_openai(monkeypatch, fake_completions)
    # Make `import anthropic` explode so any wrong-branch routing fails loudly.
    monkeypatch.setitem(sys.modules, "anthropic", None)

    adapter = FrontierLLMAdapter(provider="anthropic")
    result = adapter.converse_with_tools(
        system="s",
        messages=[{"role": "user", "content": "go"}],
        tools=[ToolSpec(name="t", description="d", input_schema={"type": "object"})],
        on_tool_call=lambda name, args: "unused",
        model="gpt-4o",
    )

    assert result.final_text == "done"
    assert fake_completions.calls[0]["model"] == "gpt-4o"


def test_openai_tool_call_exception_is_surfaced_to_model(monkeypatch):
    """A raising on_tool_call must not crash the loop; the error string is fed
    back as the tool result so the model can react."""
    scripted = [
        _Response(
            message=_ChatMessage(
                content=None,
                tool_calls=[
                    _ToolCall(
                        id="call_err",
                        name="get_function_body",
                        arguments=json.dumps({"contract": "X", "function": "y"}),
                    )
                ],
            ),
            usage=_Usage(prompt_tokens=10, completion_tokens=5),
        ),
        _Response(
            message=_ChatMessage(content="recovered", tool_calls=None),
            usage=_Usage(prompt_tokens=10, completion_tokens=5),
        ),
    ]
    fake_completions = _FakeCompletions(scripted)
    _install_fake_openai(monkeypatch, fake_completions)

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        raise RuntimeError("boom")

    adapter = FrontierLLMAdapter(provider="openai")
    tools = [ToolSpec(name="get_function_body", description="d", input_schema={"type": "object"})]

    result = adapter.converse_with_tools(
        system="s",
        messages=[{"role": "user", "content": "go"}],
        tools=tools,
        on_tool_call=on_tool_call,
    )

    assert result.final_text == "recovered"
    assert len(result.tool_calls) == 1
    assert "boom" in result.tool_calls[0]["result"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
