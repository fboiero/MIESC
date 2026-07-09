"""Offline unit tests for the AgenticAuditor orchestration loop (design §7).

No network, no API. A SCRIPTED mock stands in for
``FrontierLLMAdapter.converse_with_tools`` (returning canned ConversationResult
objects) while a REAL ``RepoCallGraph`` is built over inline Solidity fixtures.

The tests drive the full loop — enumerate -> verify -> confirm — and assert the
design §7 stop conditions (n_target reached, convergence on an empty round),
the drop-in finding shape, and that ruled-out hypotheses never reappear.

GOTCHA: fixtures must live under a path WITHOUT "test" in it — RepoCallGraph's
_SKIP_PATH skips '/test'. We use tempfile.mkdtemp(prefix="miesc_aa_").
"""

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from src.adapters.frontier_llm_adapter import ConversationResult, ToolSpec
from src.agents.agentic_auditor import (
    AgenticAuditConfig,
    AgenticAuditor,
    AuditResult,
    _extract_json_array,
    audit_repo_multipersona,
)
from src.agents.hypothesis_ledger import Hypothesis
from src.agents.repo_call_graph import RepoCallGraph

# ---------------------------------------------------------------------------
# Inline Solidity fixtures (cross-contract call: Bank.withdraw -> Token.transfer)
# ---------------------------------------------------------------------------

TOKEN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}
"""

BANK_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bank {
    Token public token;
    mapping(address => uint256) public deposits;

    function withdraw(uint256 amount) external {
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""


@pytest.fixture()
def graph() -> Iterator[RepoCallGraph]:
    # Neutral temp dir: mkdtemp(prefix="miesc_aa_") avoids the "/test" skip rule.
    root = Path(tempfile.mkdtemp(prefix="miesc_aa_"))
    try:
        src = root / "src"
        src.mkdir()
        (src / "Token.sol").write_text(TOKEN_SOL)
        (src / "Bank.sol").write_text(BANK_SOL)
        yield RepoCallGraph.build(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Scripted adapter — returns canned ConversationResult objects, in order.
# ---------------------------------------------------------------------------

class ScriptedAdapter:
    """Mock adapter feeding pre-baked replies to converse_with_tools.

    Each step is a dict: {"final_text": str, "tool_calls": [(name, args), ...],
    "usage": {...}}. Any scripted tool_calls are actually dispatched through the
    orchestrator's ``on_tool_call`` so the real RepoCallGraph tool backend is
    exercised. When the script runs out, an empty "[]" reply is returned.
    """

    def __init__(self, steps: List[Dict[str, Any]]) -> None:
        self.steps = list(steps)
        self.calls: List[Dict[str, Any]] = []

    def converse_with_tools(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[ToolSpec],
        on_tool_call: Callable[[str, Dict[str, Any]], str],
        model: Any = None,
        max_iterations: int = 12,
    ) -> ConversationResult:
        step = self.steps.pop(0) if self.steps else {"final_text": "[]"}
        trace: List[Dict[str, Any]] = []
        for name, args in step.get("tool_calls", []):
            result = on_tool_call(name, args)
            trace.append({"name": name, "args": args, "result": result})
        self.calls.append(
            {
                "user": messages[-1]["content"],
                "tools": [t.name for t in tools],
                "model": model,
                "tool_results": trace,
            }
        )
        return ConversationResult(
            final_text=step.get("final_text", "[]"),
            messages=list(messages),
            tool_calls=trace,
            usage=step.get("usage", {"input_tokens": 10, "output_tokens": 5}),
        )


def _enum(candidates: List[Dict[str, str]], **kw: Any) -> Dict[str, Any]:
    return {"final_text": json.dumps(candidates), **kw}


def _verify(verdicts: List[Dict[str, Any]], **kw: Any) -> Dict[str, Any]:
    return {"final_text": json.dumps(verdicts), **kw}


TRANSFER_CANDIDATE = {
    "contract": "Token",
    "function": "transfer",
    "vuln_class": "arithmetic",
    "claim": "transfer subtracts before checking balance, underflowing to drain",
}
WITHDRAW_CANDIDATE = {
    "contract": "Bank",
    "function": "withdraw",
    "vuln_class": "reentrancy",
    "claim": "withdraw calls token.transfer before zeroing deposits",
}


def _hid(candidate: Dict[str, str]) -> str:
    return Hypothesis.make(
        candidate["contract"], candidate["function"],
        candidate["vuln_class"], candidate["claim"],
    ).id


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------

def test_extract_json_array_handles_prose_and_fences() -> None:
    assert _extract_json_array('[{"a": 1}]') == [{"a": 1}]
    assert _extract_json_array('Here you go:\n```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert _extract_json_array("prose [ {\"a\": 1} ] trailing") == [{"a": 1}]
    assert _extract_json_array('{"a": 1}') == [{"a": 1}]  # lone object -> wrapped
    assert _extract_json_array("no json here") == []
    assert _extract_json_array("") == []
    # Unparseable JSON never crashes.
    assert _extract_json_array("[not valid json,,]") == []


# ---------------------------------------------------------------------------
# Tool dispatch against the real RepoCallGraph
# ---------------------------------------------------------------------------

def test_on_tool_call_routes_to_real_graph(graph: RepoCallGraph) -> None:
    auditor = AgenticAuditor(ScriptedAdapter([]), graph, AgenticAuditConfig())

    body = auditor._on_tool_call("get_function_body",
                                 {"contract": "Token", "function": "transfer"})
    assert "function transfer" in body

    # Cross-contract caller: Bank.withdraw calls Token.transfer.
    callers = auditor._on_tool_call("list_callers",
                                    {"contract": "Token", "function": "transfer"})
    assert "Bank.withdraw" in callers

    callees = auditor._on_tool_call("list_callees",
                                    {"contract": "Bank", "function": "withdraw"})
    assert "Token.transfer" in callees

    # Missing contract/function -> graceful "not found", never an exception.
    assert "not found" in auditor._on_tool_call(
        "get_function_body", {"contract": "Nope", "function": "ghost"}
    )
    assert "not found" in auditor._on_tool_call("get_function_body", {})
    assert "not found" in auditor._on_tool_call("bogus_tool",
                                                {"contract": "Token", "function": "mint"})


# ---------------------------------------------------------------------------
# The loop: enumerate -> verify -> confirm, stop on n_target
# ---------------------------------------------------------------------------

def test_loop_enumerate_verify_confirm_stops_on_n_target(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([
        # Round 0 ENUMERATE — one candidate, with a real tool call exercised.
        _enum([TRANSFER_CANDIDATE],
              tool_calls=[("get_function_body", {"contract": "Token", "function": "transfer"})]),
        # VERIFY — confirm it.
        _verify([{"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
                  "reason": "underflow lets attacker mint balance and drain", "severity": "high"}]),
    ])
    config = AgenticAuditConfig(n_target=1, max_rounds=4)
    auditor = AgenticAuditor(adapter, graph, config)

    result = auditor.audit_repo(Path("/unused"), scope="")

    assert isinstance(result, AuditResult)
    # Enumerate then verify — exactly two adapter turns (n_target met, no completeness).
    assert len(adapter.calls) == 2
    # The enumerate turn actually dispatched a tool to the real graph.
    assert adapter.calls[0]["tool_results"][0]["name"] == "get_function_body"
    assert "function transfer" in adapter.calls[0]["tool_results"][0]["result"]
    # One confirmed hypothesis -> one finding.
    assert len(result.ledger.confirmed()) == 1
    assert len(result.findings) == 1
    assert result.trace["rounds"] == 1
    assert result.trace["confirmed"] == 1


def test_finding_shape_matches_audit_md_consumer(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE]),
        _verify([{"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
                  "reason": "balance underflow", "severity": "high"}]),
    ])
    auditor = AgenticAuditor(adapter, graph, AgenticAuditConfig(n_target=1))
    finding = auditor.audit_repo(Path("/unused")).findings[0]

    # Keys findings_to_audit_md reads (benchmarks/evmbench_official_detect.py:202).
    for key in ("title", "severity", "type", "function", "description",
                "impact", "proof_of_concept", "recommendation"):
        assert key in finding, f"finding missing '{key}': {finding}"
    assert finding["severity"] == "high"
    assert finding["type"] == "arithmetic"
    assert finding["function"] == "transfer"
    assert finding["description"] == "balance underflow"
    # Drop-in: the real harness formatter must consume it without error.
    from benchmarks.evmbench_official_detect import findings_to_audit_md
    md = findings_to_audit_md([finding], "AgenticAuditorTest")
    assert "transfer" in md
    assert "severity: high" in md


# ---------------------------------------------------------------------------
# Convergence: an empty completeness round stops the loop
# ---------------------------------------------------------------------------

def test_loop_stops_on_convergence_empty_round(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE]),           # enumerate
        _verify([{"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
                  "reason": "underflow", "severity": "high"}]),  # verify
        _enum([]),                             # completeness round finds nothing new
    ])
    # n_target far above what will ever confirm -> would loop, but convergence stops it.
    config = AgenticAuditConfig(n_target=5, max_rounds=4)
    auditor = AgenticAuditor(adapter, graph, config)

    result = auditor.audit_repo(Path("/unused"))

    # enum + verify + one completeness turn (empty) = 3 adapter calls, then break.
    assert len(adapter.calls) == 3
    assert result.trace["rounds"] == 2  # enumerate(1) + completeness(1)
    assert len(result.findings) == 1
    # Did NOT exhaust max_rounds — stopped early on convergence.
    assert result.trace["rounds"] < config.max_rounds


# ---------------------------------------------------------------------------
# Ruled-out hypotheses never reappear
# ---------------------------------------------------------------------------

def test_ruled_out_hypotheses_do_not_reappear(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([
        # Enumerate two candidates.
        _enum([TRANSFER_CANDIDATE, WITHDRAW_CANDIDATE]),
        # Verify: confirm transfer, rule out withdraw.
        _verify([
            {"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
             "reason": "underflow drains", "severity": "high"},
            {"id": _hid(WITHDRAW_CANDIDATE), "verdict": "ruled_out",
             "reason": "nonReentrant guard present upstream", "severity": None},
        ]),
        # Completeness re-raises the SAME ruled-out withdraw candidate.
        _enum([WITHDRAW_CANDIDATE]),
    ])
    config = AgenticAuditConfig(n_target=5, max_rounds=4)
    auditor = AgenticAuditor(adapter, graph, config)

    result = auditor.audit_repo(Path("/unused"))

    confirmed = result.ledger.confirmed()
    ruled = result.ledger.ruled_out()
    assert len(confirmed) == 1 and confirmed[0].function == "transfer"
    assert len(ruled) == 1 and ruled[0].function == "withdraw"
    # The re-raised ruled-out candidate was NOT re-opened.
    assert result.ledger.open_ids() == []
    # Only the confirmed hypothesis surfaces as a finding.
    assert len(result.findings) == 1
    assert result.findings[0]["function"] == "transfer"


# ---------------------------------------------------------------------------
# Surviving semantics: an OPEN (unverified) hypothesis IS a finding; a ruled-out
# one is NOT. Verification only DROPS clear false positives, it does not gate.
# ---------------------------------------------------------------------------

def test_open_unverified_hypothesis_surfaces_as_medium_finding(graph: RepoCallGraph) -> None:
    # ENUMERATE surfaces a candidate; VERIFY returns NO verdict for it, so it
    # stays OPEN. Under the new semantics that survivor must still surface as a
    # finding (severity "medium", detail = the enum's specific claim) — the
    # verifier only removes hypotheses it explicitly rules out.
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE]),
        _verify([]),  # verifier gives no verdict -> hypothesis remains OPEN
    ])
    # n_target=0 -> no completeness loop; the single round-0 pass is all we run.
    auditor = AgenticAuditor(adapter, graph, AgenticAuditConfig(n_target=0))

    result = auditor.audit_repo(Path("/unused"))

    # enum + forced verify = 2 turns.
    assert len(adapter.calls) == 2
    # Nothing confirmed, nothing ruled out -> exactly one still-open survivor.
    assert result.ledger.confirmed() == []
    assert result.ledger.ruled_out() == []
    assert len(result.ledger.open_ids()) == 1
    assert result.trace["confirmed"] == 0
    assert result.trace["surviving"] == 1
    # The open survivor becomes a finding: severity "medium", detail = the claim.
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["function"] == "transfer"
    assert finding["severity"] == "medium"
    assert finding["description"] == TRANSFER_CANDIDATE["claim"]
    assert finding["proof_of_concept"] == TRANSFER_CANDIDATE["claim"]


def test_confirmed_and_open_survive_ruled_out_dropped(graph: RepoCallGraph) -> None:
    # Mixed verdicts in one pass: confirm TRANSFER, rule out WITHDRAW, leave a
    # third (mint) OPEN. Findings = confirmed + open (2), ruled-out dropped.
    MINT_CANDIDATE = {
        "contract": "Token", "function": "mint", "vuln_class": "access_control",
        "claim": "mint is unguarded so anyone can inflate balances",
    }
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE, WITHDRAW_CANDIDATE, MINT_CANDIDATE]),
        _verify([
            {"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
             "reason": "underflow drains", "severity": "high"},
            {"id": _hid(WITHDRAW_CANDIDATE), "verdict": "ruled_out",
             "reason": "guard present", "severity": None},
            # MINT gets no verdict -> stays OPEN.
        ]),
    ])
    auditor = AgenticAuditor(adapter, graph, AgenticAuditConfig(n_target=0))

    result = auditor.audit_repo(Path("/unused"))

    assert result.trace["confirmed"] == 1
    assert result.trace["surviving"] == 2  # confirmed transfer + open mint
    funcs = {f["function"]: f["severity"] for f in result.findings}
    assert funcs == {"transfer": "high", "mint": "medium"}
    assert "withdraw" not in funcs  # ruled out -> dropped


# ---------------------------------------------------------------------------
# Token budget short-circuits the loop
# ---------------------------------------------------------------------------

def test_token_budget_halts_completeness_loop(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE], usage={"input_tokens": 100, "output_tokens": 100}),
        _verify([{"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
                  "reason": "underflow", "severity": "high"}],
                usage={"input_tokens": 100, "output_tokens": 100}),
        # Would keep going, but budget (300) is already exceeded by now.
        _enum([{"contract": "Token", "function": "mint", "vuln_class": "access_control",
                "claim": "mint is unguarded"}]),
    ])
    config = AgenticAuditConfig(n_target=5, max_rounds=4, token_budget=300)
    auditor = AgenticAuditor(adapter, graph, config)

    result = auditor.audit_repo(Path("/unused"))

    # enum(200) + verify(200) = 400 tokens >= 300 budget -> no completeness turn.
    assert len(adapter.calls) == 2
    assert result.trace["tokens"] >= config.token_budget


# ---------------------------------------------------------------------------
# Multi-persona: config.persona selects the persona enum prompt; the union of
# several persona passes over the SAME graph combines and dedups findings.
# ---------------------------------------------------------------------------

def test_persona_config_selects_persona_enum_prompt(graph: RepoCallGraph) -> None:
    # With persona set, the ENUMERATE user message must be the access-control
    # persona prompt (focused text), NOT the general enum prompt.
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    config = AgenticAuditConfig(n_target=0, persona="access_control")
    AgenticAuditor(adapter, graph, config).audit_repo(Path("/unused"))

    enum_user = adapter.calls[0]["user"]
    # Persona-specific focus text the general AGENT_ENUM_PROMPT does not carry.
    assert "EXCLUSIVELY on ACCESS CONTROL" in enum_user
    assert "onlyOwner" in enum_user


def test_persona_none_uses_general_enum_prompt(graph: RepoCallGraph) -> None:
    # Backward compatible: persona=None keeps the general enum prompt.
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    AgenticAuditor(adapter, graph, AgenticAuditConfig(n_target=0)).audit_repo(Path("/unused"))
    enum_user = adapter.calls[0]["user"]
    assert "EXCLUSIVELY on" not in enum_user


def test_persona_general_falls_back_to_general_enum_prompt(graph: RepoCallGraph) -> None:
    # "general" is not a PERSONA_ENUM_PROMPTS key -> falls back to the broad enum.
    # The harness uses "general" as a union member for cross-cutting bugs.
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    AgenticAuditor(adapter, graph, AgenticAuditConfig(n_target=0, persona="general")).audit_repo(Path("/unused"))
    enum_user = adapter.calls[0]["user"]
    assert "EXCLUSIVELY on" not in enum_user


# ---------------------------------------------------------------------------
# Systematic coverage flag: opt-in. Default (False) => SAMPLING enum text;
# True => SYSTEMATIC enum text + a bumped enum-pass tool budget.
# ---------------------------------------------------------------------------

def test_default_config_enum_uses_sampling_coverage(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    # Default AgenticAuditConfig => systematic is False.
    config = AgenticAuditConfig(n_target=0)
    assert config.systematic is False
    AgenticAuditor(adapter, graph, config).audit_repo(Path("/unused"))
    enum_user = adapter.calls[0]["user"]
    assert "aim for FEWER than ~10 tool calls" in enum_user
    assert "SYSTEMATIC COVERAGE" not in enum_user


def test_systematic_config_enum_uses_systematic_coverage(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    config = AgenticAuditConfig(n_target=0, systematic=True)
    AgenticAuditor(adapter, graph, config).audit_repo(Path("/unused"))
    enum_user = adapter.calls[0]["user"]
    assert "SYSTEMATIC COVERAGE" in enum_user
    assert "EVERY external" in enum_user
    assert "aim for FEWER than ~10 tool calls" not in enum_user


def test_systematic_persona_config_uses_systematic_persona_prompt(graph: RepoCallGraph) -> None:
    adapter = ScriptedAdapter([_enum([]), _verify([])])
    config = AgenticAuditConfig(n_target=0, persona="access_control", systematic=True)
    AgenticAuditor(adapter, graph, config).audit_repo(Path("/unused"))
    enum_user = adapter.calls[0]["user"]
    assert "EXCLUSIVELY on ACCESS CONTROL" in enum_user  # persona focus kept
    assert "SYSTEMATIC COVERAGE" in enum_user             # systematic coverage on


def test_default_max_tool_calls_is_cheap() -> None:
    # Reverted to the cheap SAMPLING default; systematic callers bump per-pass.
    assert AgenticAuditConfig().max_tool_calls_per_round == 20


def test_systematic_bumps_enum_tool_budget_to_40(graph: RepoCallGraph) -> None:
    # When systematic, the ENUM converse call must request at least 40 iterations,
    # even though the default per-round budget is the cheaper 20.
    captured = {}

    class BudgetAdapter(ScriptedAdapter):
        def converse_with_tools(self, *a: Any, **kw: Any) -> ConversationResult:
            captured.setdefault("max_iterations", []).append(kw.get("max_iterations"))
            return super().converse_with_tools(*a, **kw)

    # A candidate keeps the verify pass alive so we can assert its (default) budget.
    adapter = BudgetAdapter([_enum([TRANSFER_CANDIDATE]), _verify([])])
    config = AgenticAuditConfig(n_target=0, systematic=True)
    AgenticAuditor(adapter, graph, config).audit_repo(Path("/unused"))
    # First converse is the ENUM pass -> bumped to 40.
    assert captured["max_iterations"][0] == 40
    # A later (verify) pass uses the cheap default.
    assert captured["max_iterations"][1] == config.max_tool_calls_per_round


def test_multipersona_unions_findings_and_dedups_duplicates(graph: RepoCallGraph) -> None:
    # Two personas over the SAME graph find DIFFERENT bugs; persona 2 also
    # re-raises persona 1's exact candidate. The union must contain BOTH bugs
    # and collapse the exact duplicate. n_target=0 -> each persona = enum+verify
    # (2 scripted steps), so the shared adapter script is 4 steps in persona order.
    adapter = ScriptedAdapter([
        # persona 1 (access_control): finds TRANSFER only.
        _enum([TRANSFER_CANDIDATE]), _verify([]),
        # persona 2 (reentrancy): finds WITHDRAW + a duplicate TRANSFER.
        _enum([WITHDRAW_CANDIDATE, TRANSFER_CANDIDATE]), _verify([]),
    ])
    base = AgenticAuditConfig(n_target=0)
    result = audit_repo_multipersona(
        adapter, graph, base, ["access_control", "reentrancy"], Path("/unused")
    )

    assert isinstance(result, AuditResult)
    funcs = sorted(f["function"] for f in result.findings)
    # Union of both personas, exact-duplicate transfer collapsed to one.
    assert funcs == ["transfer", "withdraw"]
    # Both personas contributed (findings from multiple personas present).
    assert result.trace["personas"] == ["access_control", "reentrancy"]
    per = {p["persona"]: p["unique_added"] for p in result.trace["per_persona"]}
    assert per["access_control"] == 1  # contributed transfer
    assert per["reentrancy"] == 1      # contributed withdraw (transfer deduped)
    # Merged ledger carries every distinct hypothesis (transfer + withdraw).
    assert len(result.ledger.all()) == 2


def test_multipersona_skips_failing_persona_keeps_union(graph: RepoCallGraph) -> None:
    # A persona that raises is skipped and recorded; the union survives.
    class FlakyAdapter(ScriptedAdapter):
        def converse_with_tools(self, *a: Any, **kw: Any) -> ConversationResult:
            if self._boom:
                self._boom = False
                raise RuntimeError("provider exploded")
            return super().converse_with_tools(*a, **kw)

    adapter = FlakyAdapter([_enum([TRANSFER_CANDIDATE]), _verify([])])
    adapter._boom = True  # first persona's first turn raises
    base = AgenticAuditConfig(n_target=0)
    result = audit_repo_multipersona(
        adapter, graph, base, ["access_control", "reentrancy"], Path("/unused")
    )

    # First persona failed -> recorded; second persona still produced the finding.
    assert len(result.trace["failed"]) == 1
    assert result.trace["failed"][0]["persona"] == "access_control"
    assert sorted(f["function"] for f in result.findings) == ["transfer"]


def test_round0_verify_runs_even_when_enum_alone_exhausts_budget(graph: RepoCallGraph) -> None:
    # Regression: on big repos, enumeration ALONE blows the token budget. The
    # round-0 verify must still run (force=True) or the enumerated hypotheses are
    # silently discarded (the bug that made large audits score 0/N).
    adapter = ScriptedAdapter([
        _enum([TRANSFER_CANDIDATE], usage={"input_tokens": 300, "output_tokens": 200}),
        _verify([{"id": _hid(TRANSFER_CANDIDATE), "verdict": "confirmed",
                  "reason": "underflow", "severity": "high"}],
                usage={"input_tokens": 50, "output_tokens": 50}),
    ])
    config = AgenticAuditConfig(n_target=5, max_rounds=4, token_budget=300)
    auditor = AgenticAuditor(adapter, graph, config)

    result = auditor.audit_repo(Path("/unused"))

    # enum alone (500) already >= budget (300), yet verify STILL ran -> 2 calls,
    # and the enumerated hypothesis was confirmed rather than thrown away.
    assert len(adapter.calls) == 2
    assert result.trace["confirmed"] == 1
    assert len(result.findings) == 1
