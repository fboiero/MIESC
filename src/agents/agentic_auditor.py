"""
MIESC Agentic Auditor — the Phase-1 orchestration loop (design §7).

This is the integration heart of the agentic auditor: it wires the already-built
Phase-1 modules into a single multi-turn, tool-using, memory-backed audit loop.

  * :class:`~src.agents.repo_call_graph.RepoCallGraph` is the *tool backend* — the
    model receives a compact ``repo_map()`` up front and pulls exact function
    bodies / call chains on demand via four tools.
  * :class:`~src.agents.hypothesis_ledger.HypothesisLedger` is the *memory* — every
    suspected bug is tracked with a stable id and a status so passes compound
    instead of repeat and the loop has a real convergence criterion.
  * :mod:`src.agents.agentic_prompts` supplies the three turn prompts
    (enumerate / verify / completeness).
  * :meth:`~src.adapters.frontier_llm_adapter.FrontierLLMAdapter.converse_with_tools`
    runs the Anthropic tool-use conversation.

The loop (design §7):
  Round 0  ENUMERATE  -> candidate hypotheses -> ledger.add (dedup)
  VERIFY               -> pull real code per open hypothesis -> confirm / rule_out
  COMPLETENESS (loop)  -> "what did you MISS?" -> new hypotheses -> verify
  Stop when: confirmed >= n_target  OR  a full round adds nothing new
             OR  max_rounds  OR  token_budget exceeded.

``AuditResult.findings`` is emitted in the exact shape the benchmark harness's
``findings_to_audit_md`` consumes, so wiring into the harness (T7) is drop-in.

Design: docs/design/agentic_auditor_phase1_20260707.md (§4, §7).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from src.adapters.frontier_llm_adapter import (
    ConversationResult,
    FrontierLLMAdapter,
    ToolSpec,
)
from src.agents.agentic_prompts import (
    AGENT_COMPLETENESS_PROMPT,
    AGENT_ENUM_PROMPT,
    AGENT_VERIFY_PROMPT,
)
from src.agents.base_agent import BaseAgent
from src.agents.hypothesis_ledger import Hypothesis, HypothesisLedger
from src.agents.repo_call_graph import RepoCallGraph

logger = logging.getLogger(__name__)

# Model aliases that should defer to the adapter's built-in provider default
# (``converse_with_tools`` maps ``model=None`` to ``claude-sonnet-4-6``).
_DEFAULT_MODEL_ALIASES = frozenset({"", "claude", "auto", "anthropic"})

# The tool schema shared by all four tools: {contract, function}.
_TOOL_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "contract": {"type": "string", "description": "contract name"},
        "function": {"type": "string", "description": "function name"},
    },
    "required": ["contract", "function"],
}


@dataclass
class AgenticAuditConfig:
    """Bounds and continuation hints for one agentic audit."""

    max_rounds: int = 4
    max_tool_calls_per_round: int = 20
    token_budget: int = 400_000
    n_target: int = 0  # known bug count (continuation hint); 0 = no hint
    model: str = "claude"  # frontier alias; "claude" defers to adapter default


@dataclass
class AuditResult:
    """Outcome of one whole-repo agentic audit."""

    findings: List[Dict[str, Any]]  # shape consumed by findings_to_audit_md
    ledger: HypothesisLedger
    trace: Dict[str, Any] = field(default_factory=dict)  # rounds, tool_calls, tokens


# ---------------------------------------------------------------------------
# Robust JSON extraction — the model may wrap JSON in prose / markdown fences.
# ---------------------------------------------------------------------------

def _extract_json_array(text: str) -> List[Any]:
    """Defensively pull a JSON array out of a possibly-noisy model reply.

    Handles the common cases: a bare array, an array wrapped in ```json fences,
    or an array embedded in explanatory prose. Never raises — returns ``[]`` on
    anything unparseable so the loop skips bad output instead of crashing.
    """
    if not text:
        return []
    # Fast path: the whole reply is valid JSON.
    stripped = text.strip()
    try:
        data = json.loads(stripped)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except (ValueError, TypeError):
        pass
    # Fallback: grab the outermost [...] span (greedy, matches the harness).
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        logger.debug("AgenticAuditor: could not parse JSON array from model reply")
        return []


class AgenticAuditor(BaseAgent):
    """Whole-repo agentic auditor implementing the design §7 loop.

    Constructed with an already-built adapter and repo call graph so the loop is
    fully testable offline with a mocked ``converse_with_tools``.
    """

    def __init__(
        self,
        adapter: FrontierLLMAdapter,
        graph: RepoCallGraph,
        config: AgenticAuditConfig,
    ) -> None:
        super().__init__(
            agent_name="AgenticAuditor",
            capabilities=[
                "agentic_audit",
                "tool_use",
                "hypothesis_ledger",
                "whole_repo_call_graph",
            ],
            agent_type="coordinator",
        )
        self.adapter = adapter
        self.graph = graph
        self.config = config

    # ---------------------------------------------------- BaseAgent contract

    def get_context_types(self) -> List[str]:
        return ["agentic_audit_findings"]

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        """BaseAgent entry point — audits the repo (or contract) at the path."""
        scope = kwargs.get("scope", "")
        result = self.audit_repo(Path(contract_path), scope=scope)
        return {"agentic_audit_findings": result.findings}

    # ------------------------------------------------------------ main loop

    def audit_repo(self, repo_dir: Path | str, scope: str = "") -> AuditResult:
        """Run the whole-repo agentic audit and return findings + ledger + trace."""
        ledger = HypothesisLedger()
        tools = self._build_tools()
        repo_map = self.graph.repo_map()
        system = self._system_prompt()
        trace: Dict[str, Any] = {
            "rounds": 0,
            "tool_calls": 0,
            "tokens": 0,
            "enumerated": 0,
            "confirmed": 0,
            "surviving": 0,
            "round_log": [],
        }

        # ---- Round 0: ENUMERATE ------------------------------------------
        enum_user = AGENT_ENUM_PROMPT.format(repo_map=repo_map)
        result = self._converse(system, enum_user, tools)
        self._accumulate(trace, result)
        candidates = _extract_json_array(result.final_text)
        if os.environ.get("MIESC_AGENT_DEBUG") == "1":
            logger.warning(
                "DEBUG ENUM: final_text=%d chars | parsed %d candidate(s)\n"
                "--- final_text head ---\n%s\n--- end ---",
                len(result.final_text or ""), len(candidates),
                (result.final_text or "")[:2500],
            )
        added = self._ingest_candidates(candidates, ledger)
        trace["enumerated"] += added
        trace["rounds"] = 1
        trace["round_log"].append({"phase": "enumerate", "added": added})

        # ---- VERIFY the enumerated hypotheses ----------------------------
        # force=True: always verify round-0 candidates even if enumeration already
        # blew the token budget — otherwise big-repo audits enumerate then discard.
        confirmed_now = self._verify_open(system, ledger, tools, trace, force=True)
        trace["round_log"].append({"phase": "verify", "confirmed": confirmed_now})

        # ---- COMPLETENESS loop (continuation to n_target) ----------------
        # Runs only while we still owe confirmations against a known bug count,
        # have rounds left, are under budget, and the previous round made
        # progress (design §7 stop conditions).
        n_target = self.config.n_target
        while (
            len(ledger.surviving()) < n_target
            and trace["rounds"] < self.config.max_rounds
            and not self._over_budget(trace)
        ):
            comp_user = AGENT_COMPLETENESS_PROMPT.format(
                repo_map=repo_map, ledger=ledger.summary_for_prompt()
            )
            result = self._converse(system, comp_user, tools)
            self._accumulate(trace, result)
            new_candidates = _extract_json_array(result.final_text)
            new_added = self._ingest_candidates(new_candidates, ledger)
            trace["enumerated"] += new_added
            trace["rounds"] += 1

            # Verify only the freshly-opened hypotheses this round.
            new_confirmed = self._verify_open(system, ledger, tools, trace)
            trace["round_log"].append(
                {"phase": "completeness", "added": new_added, "confirmed": new_confirmed}
            )

            made_progress = new_added > 0 or new_confirmed > 0
            if not made_progress:
                # A full round added no hypotheses and confirmed nothing new:
                # convergence — stop (design §7).
                break

        trace["confirmed"] = len(ledger.confirmed())
        trace["surviving"] = len(ledger.surviving())
        findings = self._ledger_to_findings(ledger)
        logger.info(
            "AgenticAuditor: %d finding(s) (surviving hypotheses: %d confirmed + "
            "%d unruled-out open) in %d round(s), %d tool call(s), %d tokens",
            len(findings), trace["confirmed"],
            trace["surviving"] - trace["confirmed"], trace["rounds"],
            trace["tool_calls"], trace["tokens"],
        )
        return AuditResult(findings=findings, ledger=ledger, trace=trace)

    # ------------------------------------------------------------- verify

    def _verify_open(
        self,
        system: str,
        ledger: HypothesisLedger,
        tools: List[ToolSpec],
        trace: Dict[str, Any],
        force: bool = False,
    ) -> int:
        """Verify every currently-open hypothesis in one tool-augmented turn.

        Returns the number newly *confirmed* this call. When ``force`` is set the
        budget gate is bypassed: enumerated hypotheses MUST get at least one
        verification pass, otherwise the (expensive) enumeration work is thrown
        away on large repos where enumeration alone exhausts the token budget.
        """
        open_hyps = self._open_hypotheses(ledger)
        if not open_hyps:
            return 0
        if not force and self._over_budget(trace):
            return 0

        verify_user = AGENT_VERIFY_PROMPT.format(
            ledger=self._verify_ledger_text(open_hyps)
        )
        result = self._converse(system, verify_user, tools)
        self._accumulate(trace, result)
        verdicts = _extract_json_array(result.final_text)

        open_ids = {h.id for h in open_hyps}
        confirmed_before = len(ledger.confirmed())
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            hid = str(v.get("id", "")).strip()
            if hid not in open_ids:
                # Unknown or already-decided id — skip, never re-open.
                continue
            verdict = str(v.get("verdict", "")).strip().lower()
            reason = str(v.get("reason", "") or "").strip()
            if verdict == "confirmed":
                severity = v.get("severity") or "medium"
                ledger.confirm(hid, evidence=reason or "confirmed by agent",
                               severity=str(severity))
            elif verdict == "ruled_out":
                ledger.rule_out(hid, reason or "ruled out by agent")
            # Any other verdict leaves the hypothesis open for a later round.
        return len(ledger.confirmed()) - confirmed_before

    # ------------------------------------------------------------- helpers

    def _build_tools(self) -> List[ToolSpec]:
        """The four call-graph-backed tools exposed to the model (design §6)."""
        return [
            ToolSpec(
                name="get_function_body",
                description="Return the exact Solidity source of a function "
                "(signature + body) in a contract.",
                input_schema=_TOOL_INPUT_SCHEMA,
            ),
            ToolSpec(
                name="list_callers",
                description="List the qualified names of every function that "
                "calls the given contract.function.",
                input_schema=_TOOL_INPUT_SCHEMA,
            ),
            ToolSpec(
                name="list_callees",
                description="List the qualified names of every function called "
                "by the given contract.function.",
                input_schema=_TOOL_INPUT_SCHEMA,
            ),
            ToolSpec(
                name="get_paths_to",
                description="List entry-point call paths that reach the given "
                "contract.function (a potential sink).",
                input_schema=_TOOL_INPUT_SCHEMA,
            ),
        ]

    def _on_tool_call(self, name: str, args: Dict[str, Any]) -> str:
        """Dispatch a model tool call to the RepoCallGraph. Never raises."""
        args = args or {}
        contract = str(args.get("contract", "") or "").strip()
        fn = str(args.get("function", "") or "").strip()
        if not contract or not fn:
            return "not found: both 'contract' and 'function' arguments are required"

        if name == "get_function_body":
            body = self.graph.function_body(contract, fn)
            return body if body else f"not found: {contract}.{fn} has no known body"
        if name == "list_callers":
            callers = self.graph.callers_of(contract, fn)
            return "\n".join(callers) if callers else f"no callers of {contract}.{fn}"
        if name == "list_callees":
            callees = self.graph.callees_of(contract, fn)
            return "\n".join(callees) if callees else f"no callees of {contract}.{fn}"
        if name == "get_paths_to":
            paths = self.graph.paths_to(contract, fn)
            if not paths:
                return f"no paths reach {contract}.{fn}"
            return "\n".join(" -> ".join(p) for p in paths)

        return f"not found: unknown tool '{name}'"

    def _converse(
        self, system: str, user: str, tools: List[ToolSpec]
    ) -> ConversationResult:
        """One tool-augmented turn against the frontier adapter."""
        messages = [{"role": "user", "content": user}]
        return self.adapter.converse_with_tools(
            system=system,
            messages=messages,
            tools=tools,
            on_tool_call=self._on_tool_call,
            model=self._resolved_model(),
            max_iterations=self.config.max_tool_calls_per_round,
        )

    def _resolved_model(self) -> str | None:
        """Map the config alias to an adapter model id (or None for default)."""
        model = (self.config.model or "").strip()
        if model.lower() in _DEFAULT_MODEL_ALIASES:
            return None
        return model

    def _ingest_candidates(
        self, candidates: List[Any], ledger: HypothesisLedger
    ) -> int:
        """Turn parsed candidate dicts into ledger hypotheses. Returns # added."""
        added = 0
        for c in candidates:
            if not isinstance(c, dict):
                continue
            contract = str(c.get("contract", "") or "").strip()
            function = str(c.get("function", "") or "").strip()
            claim = str(c.get("claim", "") or "").strip()
            vuln_class = str(c.get("vuln_class", "") or "other").strip() or "other"
            if not contract or not function or not claim:
                continue
            h = Hypothesis.make(contract, function, vuln_class, claim)
            if ledger.add(h):
                added += 1
        return added

    @staticmethod
    def _open_hypotheses(ledger: HypothesisLedger) -> List[Hypothesis]:
        open_ids = set(ledger.open_ids())
        return [h for h in ledger.all() if h.id in open_ids]

    @staticmethod
    def _verify_ledger_text(open_hyps: List[Hypothesis]) -> str:
        """Render open hypotheses WITH their ids so the model can echo verdicts."""
        return "\n".join(
            f"- id={h.id} [{h.vuln_class}] {h.contract}.{h.function}: {h.claim}"
            for h in open_hyps
        )

    def _accumulate(self, trace: Dict[str, Any], result: ConversationResult) -> None:
        """Fold one ConversationResult's usage / tool-call trace into the run."""
        usage = result.usage or {}
        trace["tokens"] += int(usage.get("input_tokens", 0) or 0)
        trace["tokens"] += int(usage.get("output_tokens", 0) or 0)
        trace["tool_calls"] += len(result.tool_calls or [])

    def _over_budget(self, trace: Dict[str, Any]) -> bool:
        return trace["tokens"] >= self.config.token_budget

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are MIESC's autonomous smart-contract security auditor performing "
            "an authorized, defensive pre-deployment review. You hunt HIGH/CRITICAL "
            "loss-of-funds vulnerabilities across a whole repository. You have tools "
            "to pull the exact source of any function and to trace call chains — use "
            "them to read real code instead of guessing. Findings are used to patch "
            "the code before deployment, never for exploitation."
        )

    @staticmethod
    def _confirmed_reason(h: Hypothesis) -> str:
        """The most recent 'confirmed:' evidence string for a hypothesis."""
        for ev in reversed(h.evidence):
            if ev.startswith("confirmed:"):
                return ev[len("confirmed:") :].strip()
        return h.claim

    def _ledger_to_findings(self, ledger: HypothesisLedger) -> List[Dict[str, Any]]:
        """Convert SURVIVING hypotheses into findings_to_audit_md-shaped dicts.

        Surviving = confirmed OR still-open (everything the verifier did NOT rule
        out). Enumeration reliably surfaces real candidates, so we surface every
        hypothesis the verifier did not explicitly drop:
          - confirmed  -> severity from the verdict (or "high"); detail = evidence.
          - open       -> severity "medium"; detail = the enum's specific claim.
        """
        findings: List[Dict[str, Any]] = []
        for h in ledger.surviving():
            if h.status == "confirmed":
                severity = h.severity or "high"
                detail = self._confirmed_reason(h)
            else:
                # Unverified survivor: the enum's specific claim carries the detail.
                severity = "medium"
                detail = h.claim
            findings.append(
                {
                    "title": h.claim,
                    "severity": severity,
                    "type": h.vuln_class,
                    "check": h.vuln_class,
                    "contract": h.contract,
                    "function": h.function,
                    "file": h.contract,
                    "line": 0,
                    "description": detail,
                    "impact": detail,
                    "proof_of_concept": detail,
                    "recommendation": "",
                    "vuln_class": h.vuln_class,
                    "hypothesis_id": h.id,
                }
            )
        return findings


__all__ = ["AgenticAuditConfig", "AuditResult", "AgenticAuditor"]
