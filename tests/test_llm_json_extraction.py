"""Shared LLM JSON extractor (Product Excellence Plan, wave C4)."""

from __future__ import annotations

import pytest

from miesc.llm.json_extraction import (
    ExtractionResult,
    extract_llm_array,
    extract_llm_json,
    extract_llm_object,
)

FINDING = {"title": "Reentrancy", "severity": "HIGH", "description": "CEI broken"}


@pytest.mark.parametrize(
    ("text", "strategy"),
    [
        ('{"findings": [{"title": "Reentrancy", "severity": "HIGH"}]}', "direct"),
        (
            'Sure! Here is the result:\n```json\n{"findings": [{"title": "R"}]}\n```\nHope it helps',
            "fenced",
        ),
        ('Analysis complete.\n{"findings": [{"title": "R"}]}\nLet me know.', "anchored"),
        ('<think>reasoning...</think>\n{"findings": [{"title": "R"}]}', "direct"),
        ('{"findings": [{"title": "R",},],}', None),  # trailing commas → repaired
        ("{'findings': [{'title': 'R'}]}", None),  # single quotes → repaired
    ],
)
def test_object_strategies(text, strategy):
    res = extract_llm_json(text, want="object", required_keys=("findings",))
    assert res.ok, res.error
    assert isinstance(res.data, dict) and res.data["findings"][0]["title"].startswith("R")
    if strategy:
        assert res.strategy == strategy
    else:
        assert "repair" in res.strategy


def test_braces_inside_code_strings_do_not_break_the_scan():
    text = (
        'Here you go:\n{"findings": [{"title": "Reentrancy", '
        '"snippet": "function f() { (bool ok,) = msg.sender.call{value: amount}(\\"\\"); }"}]}\n'
        "That is all."
    )
    res = extract_llm_json(text, want="object", required_keys=("findings",))
    assert res.ok, res.error
    assert "call{value: amount}" in res.data["findings"][0]["snippet"]


def test_unescaped_quotes_inside_solidity_snippet():
    # The 2026-10 Ollama failure: raw quotes inside a snippet terminate the string.
    text = (
        '[{"title": "Unchecked call", "severity": "HIGH", '
        '"code": "msg.sender.call{value: balance}("")", "description": "d"}]'
    )
    res = extract_llm_json(text, want="array")
    pytest.importorskip("json_repair")
    assert res.ok, res.error
    assert res.strategy == "json_repair"
    assert res.data[0]["title"] == "Unchecked call"


def test_truncated_output_is_recovered_or_reported():
    text = '{"findings": [{"title": "A", "severity": "HIGH"}, {"title": "B", "sev'
    res = extract_llm_json(text, want="object", required_keys=("findings",))
    # json-repair closes the structure; without it we must get a clean error.
    assert res.ok or res.error
    assert isinstance(res, ExtractionResult)


def test_ndjson_lines():
    text = '{"title": "A", "severity": "HIGH"}\n{"title": "B", "severity": "LOW"},\n'
    res = extract_llm_json(text, want="array")
    assert res.ok and res.strategy in ("ndjson", "json_repair", "outermost")
    assert [f["title"] for f in res.data] == ["A", "B"]


def test_prose_only_never_raises():
    res = extract_llm_json("I could not find any vulnerabilities in this contract.", want="object")
    assert not res.ok
    assert res.error
    assert res.raw_excerpt.startswith("I could not")


def test_empty_and_none():
    assert extract_llm_json("", want="object").error == "empty response"
    assert extract_llm_json(None, want="array").error == "empty response"


def test_required_keys_reject_unrelated_objects():
    text = 'Config: {"model": "qwen"}  Result: {"findings": []}'
    res = extract_llm_json(text, want="object", required_keys=("findings",))
    assert res.ok and "findings" in res.data


def test_convenience_wrappers():
    assert extract_llm_object('{"findings": []}', required_keys=("findings",)) == {"findings": []}
    assert extract_llm_object("nothing here") is None
    assert extract_llm_array('{"findings": [{"a": 1}]}') == [{"a": 1}]
    assert extract_llm_array("[1, 2, 3]") == []
    assert extract_llm_array("") == []


def test_as_dict_keeps_raw_only_on_failure():
    ok = extract_llm_json('{"findings": []}', want="object").as_dict()
    assert ok["parsed"] and ok["raw_excerpt"] == ""
    bad = extract_llm_json("nope", want="object").as_dict()
    assert not bad["parsed"] and bad["raw_excerpt"] == "nope"
