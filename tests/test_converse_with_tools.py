"""Tests for FrontierLLMAdapter.converse_with_tools — Anthropic tool-use loop.

Fully offline: the anthropic client is mocked so no real API call is made.
Covers the happy path (one tool round → final text) and the max_iterations
cutoff (model keeps requesting tools forever).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

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
# Minimal stand-ins for the anthropic SDK response objects. The adapter reads
# blocks via getattr(block, "type"/"name"/"input"/"id"/"text") and the message
# via .content / .stop_reason / .usage — so plain attribute holders suffice.
# ---------------------------------------------------------------------------


class _ToolUseBlock:
    def __init__(self, name: str, input: Dict[str, Any], id: str) -> None:
        self.type = "tool_use"
        self.name = name
        self.input = input
        self.id = id


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _Usage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _Message:
    def __init__(self, content: List[Any], stop_reason: str, usage: _Usage) -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage


class _FakeMessages:
    """Serves scripted responses; records the kwargs of every create() call."""

    def __init__(self, scripted: List[_Message], always: _Message = None) -> None:
        self._scripted = list(scripted)
        self._always = always
        self.calls: List[Dict[str, Any]] = []

    def create(self, **kwargs: Any) -> _Message:
        self.calls.append(kwargs)
        if self._scripted:
            return self._scripted.pop(0)
        if self._always is not None:
            return self._always
        raise AssertionError("create() called more times than scripted")


class _FakeClient:
    def __init__(self, messages: _FakeMessages) -> None:
        self.messages = messages


def _install_fake_anthropic(monkeypatch, fake_messages: _FakeMessages) -> _FakeClient:
    """Inject a stub `anthropic` module so `import anthropic` inside the method
    resolves to our fake, regardless of whether the real SDK is installed."""
    client = _FakeClient(fake_messages)
    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = lambda *a, **k: client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_tool_round_then_final_text(monkeypatch):
    """First response requests a tool; second returns final text. The loop
    must parse the tool args, call on_tool_call, append a tool_result turn,
    and terminate with the correct final text and a one-entry trace."""
    scripted = [
        _Message(
            content=[
                _ToolUseBlock(
                    name="get_function_body",
                    input={"contract": "Wallet", "function": "withdraw"},
                    id="toolu_01",
                )
            ],
            stop_reason="tool_use",
            usage=_Usage(input_tokens=100, output_tokens=50),
        ),
        _Message(
            content=[_TextBlock(text="Final answer: reentrancy in withdraw()")],
            stop_reason="end_turn",
            usage=_Usage(input_tokens=120, output_tokens=30),
        ),
    ]
    fake_messages = _FakeMessages(scripted)
    _install_fake_anthropic(monkeypatch, fake_messages)

    seen_calls: List[tuple] = []

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        seen_calls.append((name, args))
        return "function withdraw() public { ... }"

    adapter = FrontierLLMAdapter(provider="anthropic")
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

    # on_tool_call was invoked once with the correctly-parsed args.
    assert seen_calls == [
        ("get_function_body", {"contract": "Wallet", "function": "withdraw"})
    ]

    # Result shape.
    assert isinstance(result, ConversationResult)
    assert result.final_text == "Final answer: reentrancy in withdraw()"

    # Trace has exactly one entry with name/args/result.
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["name"] == "get_function_body"
    assert result.tool_calls[0]["args"] == {"contract": "Wallet", "function": "withdraw"}
    assert result.tool_calls[0]["result"] == "function withdraw() public { ... }"

    # A tool_result user turn was appended to the conversation.
    tool_result_turns = [
        m
        for m in result.messages
        if m.get("role") == "user"
        and isinstance(m.get("content"), list)
        and any(
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in m["content"]
        )
    ]
    assert len(tool_result_turns) == 1
    tr_block = tool_result_turns[0]["content"][0]
    assert tr_block["tool_use_id"] == "toolu_01"
    assert tr_block["content"] == "function withdraw() public { ... }"

    # Loop terminated after two API calls (one tool round + final).
    assert len(fake_messages.calls) == 2

    # Tools were translated to Anthropic format on every call.
    first_tools = fake_messages.calls[0]["tools"]
    assert first_tools == [
        {
            "name": "get_function_body",
            "description": "Return the exact source of a function.",
            "input_schema": tools[0].input_schema,
        }
    ]

    # Usage accumulated across both calls.
    assert result.usage == {"input_tokens": 220, "output_tokens": 80}


def test_max_iterations_cutoff_forces_final_answer(monkeypatch):
    """If the model never stops requesting tools, the loop stops after exactly
    max_iterations rounds and then makes ONE MORE call with tools DISABLED to
    force a final answer. final_text must come from that forced call."""
    tool_round = _Message(
        content=[
            _ToolUseBlock(
                name="list_callers",
                input={"contract": "Wallet", "function": "withdraw"},
                id="toolu_loop",
            )
        ],
        stop_reason="tool_use",
        usage=_Usage(input_tokens=10, output_tokens=5),
    )
    forced_final = _Message(
        content=[_TextBlock(text="Forced final: [] no candidates")],
        stop_reason="end_turn",
        usage=_Usage(input_tokens=20, output_tokens=8),
    )
    # First 3 calls loop on tools; the 4th (forced, no tools) returns text.
    fake_messages = _FakeMessages(
        scripted=[tool_round, tool_round, tool_round, forced_final]
    )
    _install_fake_anthropic(monkeypatch, fake_messages)

    call_count = {"n": 0}

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        call_count["n"] += 1
        return "caller: someFunction()"

    adapter = FrontierLLMAdapter(provider="anthropic")
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
    assert len(fake_messages.calls) == 4
    assert call_count["n"] == 3
    assert len(result.tool_calls) == 3

    # final_text now comes from the forced (no-tools) call.
    assert result.final_text == "Forced final: [] no candidates"

    # The last create() call was made WITHOUT tools.
    assert "tools" not in fake_messages.calls[-1]
    # ...while the tool rounds all carried tools.
    for call in fake_messages.calls[:3]:
        assert "tools" in call

    # Usage accumulated across the 3 tool rounds + the forced-final call.
    assert result.usage == {"input_tokens": 50, "output_tokens": 23}


def test_tool_call_exception_is_surfaced_to_model(monkeypatch):
    """A raising on_tool_call must not crash the loop; the error string is
    fed back as the tool result so the model can react."""
    scripted = [
        _Message(
            content=[
                _ToolUseBlock(
                    name="get_function_body",
                    input={"contract": "X", "function": "y"},
                    id="toolu_err",
                )
            ],
            stop_reason="tool_use",
            usage=_Usage(input_tokens=10, output_tokens=5),
        ),
        _Message(
            content=[_TextBlock(text="done")],
            stop_reason="end_turn",
            usage=_Usage(input_tokens=10, output_tokens=5),
        ),
    ]
    fake_messages = _FakeMessages(scripted)
    _install_fake_anthropic(monkeypatch, fake_messages)

    def on_tool_call(name: str, args: Dict[str, Any]) -> str:
        raise RuntimeError("boom")

    adapter = FrontierLLMAdapter(provider="anthropic")
    tools = [
        ToolSpec(name="get_function_body", description="d", input_schema={"type": "object"})
    ]

    result = adapter.converse_with_tools(
        system="s",
        messages=[{"role": "user", "content": "go"}],
        tools=tools,
        on_tool_call=on_tool_call,
    )

    assert result.final_text == "done"
    assert len(result.tool_calls) == 1
    assert "boom" in result.tool_calls[0]["result"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
