"""
Golden-string tests for the agentic auditor turn prompts.

These pin the load-bearing contract of ``src/agents/agentic_prompts.py`` WITHOUT
any API call:
  1. The four AGENT_* constants import and are non-empty strings.
  2. ENUM and VERIFY reference all four tool names the orchestrator registers.
  3. ENUM (and COMPLETENESS) reference the Hypothesis JSON fields the ledger parses.
  4. The remaining {repo_map}/{ledger} placeholders format cleanly, and the
     embedded JSON braces collapse to valid single-brace JSON.

If a prompt is edited in a way that drops the tool set or the structured-output
contract, one of these assertions fails — that is the point.
"""

from __future__ import annotations

from src.agents.agentic_prompts import (
    AGENT_COMPLETENESS_PROMPT,
    AGENT_ENUM_PROMPT,
    AGENT_ENUM_PROMPT_SYSTEMATIC,
    AGENT_EXPLOIT_PROMPT,
    AGENT_VERIFY_PROMPT,
    HYPOTHESIS_JSON_SCHEMA,
    PERSONA_ENUM_PROMPTS,
    PERSONA_ENUM_PROMPTS_SYSTEMATIC,
)

PERSONA_KEYS = (
    "accounting",
    "access_control",
    "arithmetic",
    "reentrancy",
    "state_consistency",
)

TOOL_NAMES = (
    "get_function_body",
    "list_callers",
    "list_callees",
    "get_paths_to",
)

HYPOTHESIS_FIELDS = ("contract", "function", "vuln_class", "claim")


def test_all_prompts_are_nonempty_strings():
    for prompt in (
        AGENT_ENUM_PROMPT,
        AGENT_VERIFY_PROMPT,
        AGENT_COMPLETENESS_PROMPT,
        AGENT_EXPLOIT_PROMPT,
    ):
        assert isinstance(prompt, str)
        assert prompt.strip(), "prompt must not be empty/whitespace"


def test_enum_prompt_references_all_tools():
    for tool in TOOL_NAMES:
        assert tool in AGENT_ENUM_PROMPT, f"ENUM missing tool {tool}"


def test_verify_prompt_references_all_tools():
    for tool in TOOL_NAMES:
        assert tool in AGENT_VERIFY_PROMPT, f"VERIFY missing tool {tool}"


def test_completeness_prompt_references_all_tools():
    for tool in TOOL_NAMES:
        assert tool in AGENT_COMPLETENESS_PROMPT, f"COMPLETENESS missing tool {tool}"


def test_enum_prompt_mentions_hypothesis_fields():
    for field in HYPOTHESIS_FIELDS:
        assert field in AGENT_ENUM_PROMPT, f"ENUM missing hypothesis field {field}"


def test_completeness_prompt_mentions_hypothesis_fields():
    for field in HYPOTHESIS_FIELDS:
        assert field in AGENT_COMPLETENESS_PROMPT, f"COMPLETENESS missing field {field}"


def test_verify_prompt_pins_verdict_contract():
    # VERIFY must ask for a per-hypothesis verdict the orchestrator can parse.
    for token in ("id", "verdict", "confirmed", "ruled_out", "severity"):
        assert token in AGENT_VERIFY_PROMPT, f"VERIFY missing verdict token {token}"


def test_enum_prompt_lists_all_vuln_classes():
    for cls in (
        "arithmetic",
        "access_control",
        "reentrancy",
        "accounting",
        "state_consistency",
        "other",
    ):
        assert cls in AGENT_ENUM_PROMPT, f"ENUM missing vuln_class {cls}"


def test_hypothesis_json_schema_matches_ledger_fields():
    props = HYPOTHESIS_JSON_SCHEMA["items"]["properties"]
    for field in HYPOTHESIS_FIELDS:
        assert field in props, f"schema missing field {field}"
    assert HYPOTHESIS_JSON_SCHEMA["items"]["required"] == list(HYPOTHESIS_FIELDS)


def test_enum_prompt_formats_with_repo_map():
    # The only remaining placeholder is {repo_map}; embedded JSON braces must
    # collapse to a single-brace example without raising.
    rendered = AGENT_ENUM_PROMPT.format(repo_map="ContractA: foo(), bar()")
    assert "ContractA: foo(), bar()" in rendered
    assert '{"contract"' in rendered  # {{...}} collapsed to valid JSON
    assert "{repo_map}" not in rendered


def test_verify_prompt_formats_with_ledger():
    rendered = AGENT_VERIFY_PROMPT.format(ledger="OPEN: A.foo reentrancy")
    assert "OPEN: A.foo reentrancy" in rendered
    assert '{"id"' in rendered
    assert "{ledger}" not in rendered


def test_completeness_prompt_formats_with_ledger():
    rendered = AGENT_COMPLETENESS_PROMPT.format(ledger="RULED OUT: A.bar")
    assert "RULED OUT: A.bar" in rendered
    assert "{ledger}" not in rendered


def test_persona_enum_prompts_have_the_five_keys():
    assert set(PERSONA_ENUM_PROMPTS) == set(PERSONA_KEYS)


def test_persona_enum_prompts_reference_all_tools():
    for persona, prompt in PERSONA_ENUM_PROMPTS.items():
        assert isinstance(prompt, str) and prompt.strip()
        for tool in TOOL_NAMES:
            assert tool in prompt, f"persona {persona} missing tool {tool}"


def test_persona_enum_prompts_mention_hypothesis_fields():
    for persona, prompt in PERSONA_ENUM_PROMPTS.items():
        for field in HYPOTHESIS_FIELDS:
            assert field in prompt, f"persona {persona} missing field {field}"


def test_persona_enum_prompts_format_with_repo_map():
    for persona, prompt in PERSONA_ENUM_PROMPTS.items():
        rendered = prompt.format(repo_map="ContractX: foo(), bar()")
        assert "ContractX: foo(), bar()" in rendered
        assert '{"contract"' in rendered  # embedded JSON braces collapsed
        assert "{repo_map}" not in rendered


def test_persona_enum_prompts_pin_their_own_vuln_class():
    # Each persona pass must emit its OWN class, so the class appears in the prompt.
    for persona, prompt in PERSONA_ENUM_PROMPTS.items():
        assert persona in prompt, f"persona {persona} does not pin its vuln_class"


# ---------------------------------------------------------------------------
# Coverage modes: SAMPLING is the default; SYSTEMATIC is the opt-in variant.
# ---------------------------------------------------------------------------

SAMPLING_PHRASE = "aim for FEWER than ~10 tool calls"
SYSTEMATIC_PHRASE = "SYSTEMATIC COVERAGE"
SYSTEMATIC_EVERY = "EVERY external"


def test_default_enum_prompt_uses_sampling_coverage():
    # The DEFAULT general enum must be the cheap SAMPLING variant.
    assert SAMPLING_PHRASE in AGENT_ENUM_PROMPT
    assert SYSTEMATIC_PHRASE not in AGENT_ENUM_PROMPT


def test_systematic_enum_prompt_uses_systematic_coverage():
    assert SYSTEMATIC_PHRASE in AGENT_ENUM_PROMPT_SYSTEMATIC
    assert SYSTEMATIC_EVERY in AGENT_ENUM_PROMPT_SYSTEMATIC
    assert SAMPLING_PHRASE not in AGENT_ENUM_PROMPT_SYSTEMATIC


def test_default_persona_prompts_use_sampling_coverage():
    for persona, prompt in PERSONA_ENUM_PROMPTS.items():
        assert SAMPLING_PHRASE in prompt, f"persona {persona} not SAMPLING"
        assert SYSTEMATIC_PHRASE not in prompt, f"persona {persona} leaked SYSTEMATIC"


def test_systematic_persona_prompts_use_systematic_coverage():
    assert set(PERSONA_ENUM_PROMPTS_SYSTEMATIC) == set(PERSONA_KEYS)
    for persona, prompt in PERSONA_ENUM_PROMPTS_SYSTEMATIC.items():
        assert SYSTEMATIC_PHRASE in prompt, f"persona {persona} not SYSTEMATIC"
        assert SYSTEMATIC_EVERY in prompt, f"persona {persona} missing EVERY external"
        assert SAMPLING_PHRASE not in prompt, f"persona {persona} leaked SAMPLING"


def test_systematic_enum_prompt_formats_and_keeps_contract():
    # The opt-in variant must survive .format and keep the tools + JSON contract.
    rendered = AGENT_ENUM_PROMPT_SYSTEMATIC.format(repo_map="ContractA: foo()")
    assert "ContractA: foo()" in rendered
    assert '{"contract"' in rendered
    assert "{repo_map}" not in rendered
    for tool in TOOL_NAMES:
        assert tool in rendered
    for field in HYPOTHESIS_FIELDS:
        assert field in rendered


def test_systematic_persona_prompts_format_and_keep_contract():
    for persona, prompt in PERSONA_ENUM_PROMPTS_SYSTEMATIC.items():
        rendered = prompt.format(repo_map="ContractX: foo()")
        assert "ContractX: foo()" in rendered
        assert '{"contract"' in rendered
        assert "{repo_map}" not in rendered
        for tool in TOOL_NAMES:
            assert tool in rendered, f"persona {persona} missing tool {tool}"
        for field in HYPOTHESIS_FIELDS:
            assert field in rendered, f"persona {persona} missing field {field}"


def test_exploit_prompt_is_standalone_phase2():
    # No format placeholders — retained verbatim; execution is Phase 2.
    assert "{" not in AGENT_EXPLOIT_PROMPT
    assert "exploit" in AGENT_EXPLOIT_PROMPT.lower()
