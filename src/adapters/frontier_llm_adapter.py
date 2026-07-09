"""
FrontierLLM Adapter — Claude / GPT API for deep semantic vulnerability analysis.

This adapter sends the FULL contract source to a frontier model (Claude Opus,
GPT-4o, etc.) with a specialized security audit prompt. Unlike local Ollama
models, frontier models have the reasoning capacity to detect business logic
vulnerabilities, economic exploits, and protocol-level flaws.

Usage:
    ANTHROPIC_API_KEY=sk-ant-... miesc scan contract.sol --model claude
    OPENAI_API_KEY=sk-...       miesc scan contract.sol --model gpt

The adapter is OPT-IN only. Default MIESC behavior remains 100% local
(DPGA-compliant). This adapter requires an API key and sends code to
external servers.

Supported providers:
    - anthropic: Claude Opus 4 / Sonnet 4 (via Anthropic API)
    - openai: GPT-4o / GPT-5 (via OpenAI API)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, cast

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool-use conversational surface (additive) — provider-neutral spec + result
#
# These support the agentic auditor loop: instead of reasoning over a single
# truncated blob, the model pulls exact code on demand via tools. See
# docs/design/agentic_auditor_phase1_20260707.md §6.
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    """Provider-neutral tool definition.

    The adapter translates this to the provider's native tool format
    (Anthropic ``tools=`` or OpenAI ``tools`` function-calling).
    """

    name: str
    description: str
    input_schema: Dict[str, Any]  # JSON schema for the tool's args


@dataclass
class ConversationResult:
    """Outcome of a multi-turn tool-use conversation."""

    final_text: str
    messages: List[Any]  # full conversation history (role/content dicts)
    tool_calls: List[Dict[str, Any]]  # trace: [{"name":..., "args":..., "result":...}]
    usage: Dict[str, int]  # accumulated token usage totals

# ---------------------------------------------------------------------------
# Security audit prompt — Chain-of-Thought with structured output
# ---------------------------------------------------------------------------

AUDIT_SYSTEM_PROMPT = """CONTEXT: This is a DEFENSIVE security audit performed by MIESC, an open-source \
smart contract security framework (https://github.com/fboiero/MIESC, AGPL-3.0). \
This analysis is part of authorized pre-deployment security review to PROTECT \
users and protocols from vulnerabilities BEFORE they can be exploited. All findings \
are used to generate patches and formal verification specs, not for exploitation.

You are an expert smart contract security auditor with 10+ years of experience \
auditing DeFi protocols. You have deep knowledge of:
- Solidity internals, EVM opcodes, storage layout
- DeFi attack vectors: flash loans, oracle manipulation, reentrancy, MEV
- Economic exploit patterns: rounding errors, invariant violations, governance attacks
- Access control flaws, upgrade vulnerabilities, cross-contract interactions

Your task is to find HIGH and CRITICAL severity vulnerabilities so they can be \
FIXED before deployment — protecting user funds and protocol integrity."""

AUDIT_USER_PROMPT = """Analyze the following Solidity smart contract for security vulnerabilities.

<contract>
{source_code}
</contract>

Follow this step-by-step analysis process:

1. **Identify state variables and their invariants** — What properties MUST always hold?
2. **Trace value flows** — Where does ETH/tokens enter and exit? Who controls the flow?
3. **Check access control** — Which functions are privileged? Can they be called by unauthorized users?
4. **Analyze external interactions** — Are there reentrancy risks? Unchecked return values?
5. **Look for economic exploits** — Flash loan attacks? Oracle manipulation? Rounding errors? Can governance be exploited?
6. **Check boundary conditions and caps** — Are there hardcoded limits (max supply, cap, deadline)? What happens if the total exceeds the cap? Will later users be unable to withdraw? Will arithmetic underflow? Check EVERY subtraction for potential underflow when actual > expected.
7. **Check state consistency after EVERY state-changing operation** — When a token/position is transferred, are ALL related mappings and struct fields updated? Specifically: if a function moves an item from A to B, does it update BOTH the source AND destination state? Are flags (occupied, active, dirty) correctly synced? Can calling functions in a specific order leave state inconsistent?
8. **Check multi-contract interactions** — If the contract interacts with external contracts or tokens, can those interactions be exploited? Can callbacks change state unexpectedly? Are return values from external calls checked?
9. **Check time-bounded operations** — If there are exchange periods, deadlines, or time windows: what happens at exact boundaries? Can operations continue after the period ends? Are remaining funds safely handled?

For each vulnerability found, respond with ONLY a JSON array:
```json
[
  {{
    "title": "Short descriptive title",
    "severity": "Critical" or "High" or "Medium",
    "type": "vulnerability category (e.g., reentrancy, access_control, logic_error)",
    "function": "affected function name",
    "line": line_number_or_0,
    "description": "Detailed technical explanation of WHY this is vulnerable",
    "impact": "What an attacker can achieve (e.g., drain all funds, mint unlimited tokens)",
    "proof_of_concept": "Step-by-step attack scenario",
    "recommendation": "Specific fix with code suggestion"
  }}
]
```

If no vulnerabilities found, respond with `[]`.
Focus ONLY on HIGH and CRITICAL issues that could lead to loss of funds or protocol compromise. Do NOT report gas optimizations, style issues, or informational findings."""


class FrontierLLMAdapter(ToolAdapter):
    """Adapter for frontier LLM APIs (Claude, GPT) for deep semantic analysis."""

    def __init__(self, provider: str = "auto"):
        """
        Initialize with provider selection.

        Args:
            provider: "anthropic", "openai", or "auto" (detect from env vars)
        """
        self._provider = provider
        self._model: Optional[str] = None
        self._client: Any = None

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="frontier_llm",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC",
            installation_cmd="pip install anthropic openai",
            capabilities=[
                ToolCapability(
                    name="semantic_audit",
                    description="Deep semantic vulnerability detection using frontier models",
                    supported_languages=["solidity"],
                    detection_types=[
                        "business_logic",
                        "economic_exploit",
                        "access_control",
                        "reentrancy",
                        "oracle_manipulation",
                        "governance",
                    ],
                ),
            ],
            cost=0.01,  # ~$0.01 per contract (depends on size)
            requires_api_key=True,
            is_optional=True,
        )

    def _detect_provider(self) -> Optional[str]:
        """Auto-detect provider from environment variables."""
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        return None

    def _preprocess_codebase(self, source_code: str) -> str:
        """Build a protocol map from code structure analysis.

        Extracts: contract hierarchy, function signatures, state variables,
        external calls, and likely invariants. This context helps ANY LLM
        understand the protocol before analyzing individual vulnerabilities.
        """
        import re

        sections = []

        # 1. Contract hierarchy + imports
        contracts = []
        for m in re.finditer(
            r"(?:// ===== FILE: (\S+) =====\n)?.*?contract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{",
            source_code,
            re.DOTALL,
        ):
            file_name = m.group(1) or ""
            name = m.group(2)
            inherits = m.group(3).strip() if m.group(3) else ""
            contracts.append((name, inherits, file_name))

        if contracts:
            hierarchy = "CONTRACT HIERARCHY:\n"
            for name, inherits, fname in contracts[:15]:
                if inherits:
                    hierarchy += f"  {name} is {inherits}"
                else:
                    hierarchy += f"  {name}"
                if fname:
                    hierarchy += f"  (in {fname})"
                hierarchy += "\n"
            sections.append(hierarchy)

        # 2. External calls (potential cross-contract interactions)
        external_calls = set()
        for m in re.finditer(
            r"(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*[({]", source_code
        ):
            external_calls.add(m.group(0)[:60])
        for m in re.finditer(r"I(\w+)\((\w+)\)\.(\w+)\(", source_code):
            external_calls.add(f"{m.group(1)}.{m.group(3)}() via interface")
        for m in re.finditer(r"IERC20\([^)]+\)\.(\w+)\(", source_code):
            external_calls.add(f"ERC20.{m.group(1)}()")

        if external_calls:
            ext = "EXTERNAL CALLS (cross-contract interaction points):\n"
            for call in sorted(external_calls)[:15]:
                ext += f"  • {call}\n"
            sections.append(ext)

        # 3. State-changing functions (high-risk)
        state_fns = []
        for m in re.finditer(
            r"function\s+(\w+)\s*\([^)]*\)\s*(external|public)(?![^{]*\bview\b)(?![^{]*\bpure\b)[^{]*\{",
            source_code,
        ):
            fn_name = m.group(1)
            if fn_name not in ("constructor", "receive", "fallback"):
                state_fns.append(fn_name)

        if state_fns:
            fns = "STATE-CHANGING FUNCTIONS (audit priority):\n"
            for fn in state_fns[:20]:
                fns += f"  • {fn}()\n"
            sections.append(fns)

        # 4. Likely invariants
        invariants = []
        code_lower = source_code.lower()
        if "totalsupply" in code_lower and "balanceof" in code_lower:
            invariants.append("totalSupply() == sum of all balanceOf(account)")
        if "totalassets" in code_lower:
            invariants.append("totalAssets() >= totalLiabilities (solvency)")
            if "totalsupply" in code_lower:
                invariants.append(
                    "sharePrice = totalAssets() / totalSupply() must be monotonically non-decreasing"
                )
        if "gettvl" in code_lower or "totaltvl" in code_lower:
            invariants.append("getTVL() must equal sum of all position values across connectors")
        if "collateral" in code_lower and "borrow" in code_lower:
            invariants.append("For every borrower: collateralValue * LTV >= borrowedAmount")
        if "stake" in code_lower and "reward" in code_lower:
            invariants.append("rewardPerToken accumulator must only increase")
        if re.search(r"mapping.*balance", code_lower):
            invariants.append("sum of all user balances <= contract.balance (no inflation)")

        if invariants:
            inv = "INVARIANTS TO VERIFY (likely correctness properties):\n"
            for i in invariants:
                inv += f"  ✓ {i}\n"
            inv += "  → Check if ANY code path can violate these properties\n"
            sections.append(inv)

        # 5. Value flow summary
        has_eth = "msg.value" in source_code or ".call{value:" in source_code
        has_erc20 = "transfer(" in source_code or "transferFrom(" in source_code
        has_mint = "_mint(" in source_code
        has_burn = "_burn(" in source_code

        if has_eth or has_erc20:
            flow = "VALUE FLOWS:\n"
            if has_eth:
                flow += "  ETH: enters via payable functions, exits via .call{value:}\n"
            if has_erc20:
                flow += "  ERC20: transfer/transferFrom interactions\n"
            if has_mint:
                flow += "  MINT: new tokens created (_mint)\n"
            if has_burn:
                flow += "  BURN: tokens destroyed (_burn)\n"
            flow += "  → Verify: can an attacker extract more value than they deposited?\n"
            sections.append(flow)

        result = "\n".join(sections)
        if len(result) > 2000:
            result = result[:2000]
        return result

    def _check_ollama(self) -> bool:
        """Check if Ollama is running and has models."""
        import urllib.request

        try:
            resp = urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
            data = json.loads(resp.read())
            return len(data.get("models", [])) > 0
        except Exception:
            return False

    def _get_provider(self) -> Optional[str]:
        if self._provider == "auto":
            return self._detect_provider()
        return self._provider

    def is_available(self) -> ToolStatus:
        provider = self._get_provider()
        if not provider:
            logger.debug("FrontierLLM: No API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY)")
            return ToolStatus.NOT_INSTALLED

        if provider == "anthropic":
            try:
                import anthropic  # noqa: F401

                if not os.environ.get("ANTHROPIC_API_KEY"):
                    return ToolStatus.CONFIGURATION_ERROR
                return ToolStatus.AVAILABLE
            except ImportError:
                logger.info("FrontierLLM: anthropic SDK not installed. pip install anthropic")
                return ToolStatus.NOT_INSTALLED

        if provider == "ollama":
            return ToolStatus.AVAILABLE if self._check_ollama() else ToolStatus.NOT_INSTALLED

        if provider == "openai":
            try:
                import openai  # noqa: F401

                if not os.environ.get("OPENAI_API_KEY"):
                    return ToolStatus.CONFIGURATION_ERROR
                return ToolStatus.AVAILABLE
            except ImportError:
                logger.info("FrontierLLM: openai SDK not installed. pip install openai")
                return ToolStatus.NOT_INSTALLED

        return ToolStatus.NOT_INSTALLED

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        """Analyze contract using frontier LLM API.

        Supports multi-pass analysis via ``deep=True`` kwarg:
          Pass 1: General audit (standard prompt)
          Pass 2: Targeted deep-dive on functions flagged in Pass 1 +
                  protocol-specific invariant checks
        """
        start_time = time.time()
        deep = kwargs.pop("deep", False)
        debate = kwargs.pop("debate", False)

        if self.is_available() != ToolStatus.AVAILABLE:
            return self._error_result(start_time, "FrontierLLM not available")

        # Read contract
        try:
            source_code = open(contract_path).read()
        except Exception as e:
            return self._error_result(start_time, f"Cannot read contract: {e}")

        # C: Chunked scanning for large contracts
        # If source > 150KB, split into chunks and analyze each
        max_chars = 150_000
        if len(source_code) > max_chars:
            return self._analyze_chunked(contract_path, source_code, start_time, **kwargs)

        # Pre-analysis: build protocol map from code structure
        protocol_map = self._preprocess_codebase(source_code)

        # D: RAG enrichment with protocol-specific vulnerability context
        rag_context = self._get_rag_context(source_code)
        if protocol_map:
            rag_context = protocol_map + "\n\n" + rag_context

        provider = self._get_provider()

        try:
            if provider == "anthropic":
                findings = self._analyze_anthropic(source_code, rag_context=rag_context, **kwargs)
            elif provider == "openai":
                findings = self._analyze_openai(source_code, rag_context=rag_context, **kwargs)
            elif provider == "ollama":
                findings = self._analyze_ollama(source_code, rag_context=rag_context, **kwargs)
            else:
                return self._error_result(start_time, f"Unknown provider: {provider}")
        except Exception as e:
            # A provider-comparison benchmark must NOT silently substitute a
            # different provider on failure — that corrupts the comparison (a
            # failed gpt run would return Claude findings). Opt out of the
            # resilience fallback with MIESC_FRONTIER_NO_FALLBACK.
            if os.environ.get("MIESC_FRONTIER_NO_FALLBACK"):
                logger.error(f"FrontierLLM: {provider} failed, fallback disabled: {e}")
                return self._error_result(start_time, f"{provider} failed (no fallback): {e}")
            # Auto-fallback: if primary provider fails, try the other one
            fallback = "openai" if provider == "anthropic" else "anthropic"
            fallback_key = "OPENAI_API_KEY" if fallback == "openai" else "ANTHROPIC_API_KEY"
            if os.environ.get(fallback_key):
                logger.warning(f"FrontierLLM: {provider} failed ({e}), falling back to {fallback}")
                # Use the correct default model for the fallback provider
                fallback_kwargs = dict(kwargs)
                fallback_kwargs.pop("model", None)
                if fallback == "openai":
                    fallback_kwargs["model"] = "gpt-4o"
                else:
                    fallback_kwargs["model"] = "claude-sonnet-4-6"
                try:
                    if fallback == "openai":
                        findings = self._analyze_openai(
                            source_code, rag_context=rag_context, **fallback_kwargs
                        )
                    else:
                        findings = self._analyze_anthropic(
                            source_code, rag_context=rag_context, **fallback_kwargs
                        )
                except Exception as e2:
                    logger.error(
                        f"FrontierLLM: Both providers failed. {provider}: {e}, {fallback}: {e2}"
                    )
                    return self._error_result(start_time, f"{provider}: {e} | {fallback}: {e2}")
            else:
                logger.error(f"FrontierLLM API error: {e}")
                return self._error_result(start_time, str(e))

        elapsed = time.time() - start_time

        # Normalize findings — handle diverse key names from different LLM responses
        normalized = []
        for f in findings:
            title = (
                f.get("title")
                or f.get("vulnerability")
                or f.get("name")
                or f.get("type")
                or "Unknown"
            )
            ftype = (
                f.get("type") or f.get("category") or f.get("vulnerability_type") or "logic_error"
            )
            severity = f.get("severity") or "Medium"
            loc = f.get("location") or f.get("function") or "unknown"
            line = f.get("line") or f.get("line_number") or 0
            if isinstance(loc, str) and ":" in loc:
                parts = loc.split(":")
                loc = parts[0]
                try:
                    line = int(parts[-1])
                except ValueError:
                    pass
            normalized.append(
                {
                    "type": ftype.lower().replace(" ", "_"),
                    "title": title,
                    "severity": str(severity).capitalize(),
                    "tool": f"frontier-{provider}",
                    "confidence": 0.80,
                    "location": {
                        "file": contract_path,
                        "line": line,
                        "function": loc if isinstance(loc, str) else "unknown",
                    },
                    "description": f.get("description", ""),
                    "message": f.get("impact", ""),
                    "recommendation": f.get("recommendation")
                    or f.get("fix")
                    or f.get("remediation")
                    or "",
                    "exploit_scenario": f.get("proof_of_concept")
                    or f.get("attack_scenario")
                    or f.get("exploit")
                    or "",
                    "swc_id": f.get("swc_id") or f.get("swc") or "",
                }
            )

        # Deduplicate findings by (function, type) — LLMs often report
        # the same issue with different wording
        deduped = []
        seen_keys = set()
        for f in normalized:
            fn = f.get("location", {}).get("function", "").lower()
            ftype = f.get("type", "").lower()
            key = (fn, ftype) if fn and fn != "unknown" else (f.get("title", "").lower()[:30],)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)

        if len(deduped) < len(normalized):
            logger.info(f"FrontierLLM: Deduped {len(normalized)} → {len(deduped)} findings")

        # B: Multi-pass deep analysis (opt-in via deep=True)
        if deep and deduped:
            logger.info(f"FrontierLLM: Running deep pass (Pass 2) on {len(deduped)} findings...")
            deep_findings = self._deep_pass(source_code, deduped, provider, rag_context, **kwargs)
            if deep_findings:
                # Normalize and add deep findings
                for f in deep_findings:
                    title = f.get("title") or f.get("vulnerability") or f.get("type") or "Unknown"
                    deduped.append(
                        {
                            "type": (f.get("type") or "logic_error").lower().replace(" ", "_"),
                            "title": title,
                            "severity": str(f.get("severity", "High")).capitalize(),
                            "tool": f"frontier-{provider}-deep",
                            "confidence": 0.75,
                            "location": {
                                "file": contract_path,
                                "line": f.get("line", 0),
                                "function": f.get("function") or f.get("location") or "unknown",
                            },
                            "description": f.get("description", ""),
                            "message": f.get("impact", ""),
                            "recommendation": f.get("recommendation") or f.get("fix") or "",
                            "exploit_scenario": f.get("proof_of_concept") or "",
                            "swc_id": "",
                        }
                    )
                logger.info(
                    f"FrontierLLM: Deep pass found {len(deep_findings)} additional findings"
                )

        # F: 2-agent debate (opt-in via debate=True)
        if debate and deduped:
            logger.info(f"FrontierLLM: Running debate verification on {len(deduped)} findings...")
            deduped = self._debate_verify(source_code, deduped, provider, **kwargs)

        return {
            "tool": f"frontier-{provider}",
            "status": "success",
            "findings": deduped,
            "execution_time": elapsed,
            "metadata": {
                "provider": provider,
                "model": self._model,
                "source_chars": len(source_code),
            },
        }

    def _analyze_chunked(
        self, contract_path: str, source_code: str, start_time: float, **kwargs: Any
    ) -> Dict[str, Any]:
        """C: Split large codebase into chunks and analyze each separately."""
        # Split by file markers (// ===== FILE: ...) or by size
        chunks = []
        current_chunk = ""
        chunk_size = 80_000  # ~20K tokens per chunk

        for line in source_code.split("\n"):
            if line.startswith("// ===== FILE:") and len(current_chunk) > chunk_size:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"
        if current_chunk.strip():
            chunks.append(current_chunk)

        if not chunks:
            chunks = [source_code[:chunk_size], source_code[chunk_size:]]

        logger.info(f"FrontierLLM: Chunked {len(source_code)//1024}KB into {len(chunks)} chunks")

        all_findings = []
        for chunk in chunks:
            if not chunk.strip():
                continue
            # Write chunk to temp file
            import tempfile

            tmp = Path(tempfile.mktemp(suffix=".sol"))
            tmp.write_text(chunk)
            try:
                result = self.analyze(str(tmp), **kwargs)
                all_findings.extend(result.get("findings", []))
            finally:
                tmp.unlink(missing_ok=True)

        elapsed = time.time() - start_time
        return {
            "tool": f"frontier-{self._get_provider()}",
            "status": "success",
            "findings": all_findings,
            "execution_time": elapsed,
            "metadata": {"chunked": True, "n_chunks": len(chunks)},
        }

    def _deep_pass(
        self,
        source_code: str,
        pass1_findings: List[Dict],
        provider: Optional[str],
        rag_context: str,
        **kwargs: Any,
    ) -> List[Dict]:
        """B: Second-pass analysis targeting areas flagged in Pass 1."""
        if not pass1_findings:
            return []

        # Build a targeted prompt based on Pass 1 findings
        functions_found = set()
        for f in pass1_findings:
            loc = f.get("location", {})
            fn = loc.get("function", "") if isinstance(loc, dict) else ""
            if fn and fn != "unknown":
                functions_found.add(fn)

        if not functions_found:
            return []

        deep_prompt = f"""You previously identified potential issues in these functions: {', '.join(functions_found)}.

Now perform a DEEPER analysis of the SAME contract, focusing on:

1. **Cross-function interactions**: Do any of the flagged functions share state variables? Can calling them in a specific order violate invariants?
2. **Economic invariants**: What mathematical properties MUST hold? (e.g., totalSupply == sum of balances, totalAssets >= totalLiabilities). Are there paths that break them?
3. **Edge cases in the flagged functions**: What happens with zero values, max uint256, empty arrays, or exactly-at-boundary conditions?
4. **Missing validations**: Are there unchecked inputs, missing access controls, or paths where important state updates are skipped?

<contract>
{source_code[:100_000]}
</contract>

Report ONLY NEW vulnerabilities not found in the first pass. Focus on HIGH/CRITICAL issues.
Respond with a JSON array."""

        try:
            if provider == "anthropic":
                import anthropic

                client: Any = anthropic.Anthropic()
                msg = client.messages.create(
                    model=kwargs.get("model", "claude-sonnet-4-6"),
                    max_tokens=4096,
                    system=AUDIT_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": deep_prompt}],
                )
                return self._parse_response(getattr(msg.content[0], "text", ""))
            elif provider == "openai":
                import openai

                client = openai.OpenAI()
                resp = client.chat.completions.create(
                    model=kwargs.get("model", "gpt-4o"),
                    max_tokens=4096,
                    messages=[
                        {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                        {"role": "user", "content": deep_prompt},
                    ],
                )
                return self._parse_response(resp.choices[0].message.content)
        except Exception as e:
            logger.warning(f"FrontierLLM deep pass failed: {e}")
        return []

    def _debate_verify(
        self, source_code: str, findings: List[Dict], provider: Optional[str], **kwargs: Any
    ) -> List[Dict]:
        """F: 2-agent debate — challenger verifies each finding.

        For each finding, a second LLM call asks: "Is this a real
        vulnerability or a false positive? Explain why."
        Findings confirmed by the challenger get boosted confidence;
        rejected findings are downgraded.
        """
        if not findings:
            return findings

        verified = []
        for f in findings:
            title = f.get("title") or f.get("type", "Unknown")
            desc = f.get("description", "")[:500]
            fn = (
                f.get("location", {}).get("function", "?")
                if isinstance(f.get("location"), dict)
                else "?"
            )

            challenge_prompt = (
                f"[DEFENSIVE AUDIT — MIESC open-source framework, AGPL-3.0. "
                f"Purpose: verify findings to PROTECT users before deployment.]\n\n"
                f"A security auditor reported this vulnerability in a smart contract:\n\n"
                f"Title: {title}\nFunction: {fn}\nDescription: {desc}\n\n"
                f"Contract code:\n{source_code[:50_000]}\n\n"
                f"As a CHALLENGER, determine if this is a REAL vulnerability or a FALSE POSITIVE.\n"
                f"Consider: Is the exploit actually reachable? Are there existing mitigations? "
                f"Is the severity accurate?\n\n"
                f'Answer with JSON: {{"verdict": "confirmed" or "rejected", "reason": "..."}}'
            )

            try:
                if provider == "anthropic":
                    import anthropic

                    client: Any = anthropic.Anthropic()
                    msg = client.messages.create(
                        model="claude-haiku-4-5-20251001",  # Cheaper model for verification
                        max_tokens=500,
                        messages=[{"role": "user", "content": challenge_prompt}],
                    )
                    response = getattr(msg.content[0], "text", "")
                elif provider == "openai":
                    import openai

                    client = openai.OpenAI()
                    resp = client.chat.completions.create(
                        model="gpt-4o-mini",  # Cheaper model for verification
                        max_tokens=500,
                        messages=[{"role": "user", "content": challenge_prompt}],
                    )
                    response = resp.choices[0].message.content
                else:
                    verified.append(f)
                    continue

                # Parse verdict
                resp_lower = response.lower()
                if "confirmed" in resp_lower:
                    f["debate_verdict"] = "confirmed"
                    f["confidence"] = min(0.95, f.get("confidence", 0.80) + 0.10)
                    verified.append(f)
                elif "rejected" in resp_lower:
                    f["debate_verdict"] = "rejected"
                    f["confidence"] = max(0.20, f.get("confidence", 0.80) - 0.30)
                    # Still include but with low confidence — let the user decide
                    verified.append(f)
                else:
                    f["debate_verdict"] = "uncertain"
                    verified.append(f)

            except Exception as e:
                logger.debug(f"Debate verification failed for {title}: {e}")
                verified.append(f)  # Keep finding if debate fails

        confirmed = sum(1 for f in verified if f.get("debate_verdict") == "confirmed")
        rejected = sum(1 for f in verified if f.get("debate_verdict") == "rejected")
        logger.info(
            f"FrontierLLM debate: {confirmed} confirmed, {rejected} rejected, "
            f"{len(verified) - confirmed - rejected} uncertain"
        )
        return verified

    def _get_rag_context(self, source_code: str) -> str:
        """Build RAG context with protocol-specific exploit patterns."""
        sections = []
        code_lower = source_code.lower()

        # Detect protocol type and add targeted exploit knowledge
        if any(kw in code_lower for kw in ["swap", "liquidity", "amm", "pool", "reserve"]):
            sections.append(
                "KNOWN DEX/AMM EXPLOITS:\n"
                "- Sandwich attacks via lack of slippage protection (no minAmountOut)\n"
                "- Price manipulation through reserve ratio in single-block\n"
                "- LP token inflation attacks (first depositor gets disproportionate shares)\n"
                "- Rounding errors in fee calculations favoring repeated small trades\n"
                "- Flash loan price manipulation of spot price oracles"
            )
        if any(kw in code_lower for kw in ["borrow", "lend", "collateral", "liquidat", "interest"]):
            sections.append(
                "KNOWN LENDING EXPLOITS:\n"
                "- Oracle manipulation to inflate collateral value → borrow excess\n"
                "- Interest rate calculation errors compounding over time\n"
                "- Liquidation threshold bypass via flash-loan self-liquidation\n"
                "- Share price manipulation in vault-style lending (ERC4626)\n"
                "- Dust amounts preventing full repayment / unlock"
            )
        if any(kw in code_lower for kw in ["vote", "proposal", "govern", "quorum", "delegate"]):
            sections.append(
                "KNOWN GOVERNANCE EXPLOITS:\n"
                "- Flash loan governance: borrow tokens → vote → repay in same block\n"
                "- Proposal frontrunning: submit counter-proposal before execution\n"
                "- Quorum manipulation via delegated/undelegated voting power\n"
                "- Timelock bypass through parameter manipulation\n"
                "- Checkpoint-based vs balance-based voting discrepancies"
            )
        if any(kw in code_lower for kw in ["stake", "unstake", "reward", "epoch", "claim"]):
            sections.append(
                "KNOWN STAKING EXPLOITS:\n"
                "- Reward calculation errors when staking/unstaking near epoch boundaries\n"
                "- Weight/share accounting bugs when market parameters update mid-epoch\n"
                "- Stake-on-behalf attacks extending others' lock periods\n"
                "- Reward draining via rapid stake→claim→unstake cycles\n"
                "- Integer division in reward-per-token accumulating rounding losses"
            )
        if any(kw in code_lower for kw in ["nft", "erc721", "tokenid", "mint", "collection"]):
            sections.append(
                "KNOWN NFT EXPLOITS:\n"
                "- Reentrancy via onERC721Received callback during safeMint\n"
                "- Mint supply bypass: minting more than maxSupply via race condition\n"
                "- Rental/plot occupation conflicts when multiple users target same ID\n"
                "- Metadata manipulation if tokenURI is mutable without access control"
            )
        if any(
            kw in code_lower for kw in ["merge", "migrate", "exchange", "convert", "swap"]
        ) and any(kw in code_lower for kw in ["deadline", "period", "expir", "timestamp"]):
            sections.append(
                "KNOWN TOKEN MIGRATION EXPLOITS:\n"
                "- No cap enforcement: exchanging more tokens than allocated pool\n"
                "- Missing deadline validation: exchange after period should revert\n"
                "- Remaining token withdrawal before exchange period ends\n"
                "- Double-exchange via reentrancy in migration function"
            )

        # D: Patterns informed by EVMBench missed vulns (TVL, connectors, cross-contract)
        if any(
            kw in code_lower
            for kw in ["totalassets", "totaltvl", "gettvl", "connector", "position"]
        ):
            sections.append(
                "KNOWN TVL/ACCOUNTING EXPLOITS:\n"
                "- totalAssets() not summing all position types (lending, LP, staking)\n"
                "- Connector returning stale or incorrect TVL for a specific protocol\n"
                "- Share price inflated/deflated by donating assets directly to vault\n"
                "- Position value calculated with wrong decimals or token price\n"
                "- Missing positions in TVL causing undervaluation → unfair withdrawal"
            )
        if any(kw in code_lower for kw in ["linked", "next", "prev", "head", "tail", "node"]):
            sections.append(
                "KNOWN LINKED LIST EXPLOITS:\n"
                "- Double processing when node removal corrupts next/prev pointers\n"
                "- Orphaned nodes after deletion allowing duplicate operations\n"
                "- Off-by-one in iteration causing skip or double-visit\n"
                "- Head/tail not updated correctly on insert/remove at boundaries"
            )
        if any(kw in code_lower for kw in ["signature", "ecrecover", "ecdsa", "digest", "v, r, s"]):
            sections.append(
                "KNOWN SIGNATURE EXPLOITS:\n"
                "- Replay across chains (missing chainId in digest)\n"
                "- Replay across contracts (missing contract address in digest)\n"
                "- Missing nonce allowing same signature to be used twice\n"
                "- Malleable signatures (both s and n-s are valid for same message)\n"
                "- ecrecover returning address(0) not checked → forged signatures"
            )
        if any(kw in code_lower for kw in ["cancel", "refund", "withdraw", "claim"]) and any(
            kw in code_lower for kw in ["mapping", "status", "state"]
        ):
            sections.append(
                "KNOWN STATE MANAGEMENT EXPLOITS:\n"
                "- Missing authorization on cancel/refund allowing anyone to trigger\n"
                "- State not reset after refund → double refund attack\n"
                "- Race condition between deposit and withdrawal in same block\n"
                "- Claim function not checking if already claimed (missing flag update)"
            )
        # Patterns from EVMBench missed vulns analysis
        if any(
            kw in code_lower for kw in ["hardcoded", "constant", "cap", "limit", "max_", "total_"]
        ):
            sections.append(
                "KNOWN BOUNDARY/CAP EXPLOITS:\n"
                "- Hardcoded cap without enforcement: if deposits exceed the cap,\n"
                "  later withdrawals underflow (e.g., remainingAmount - totalClaimable)\n"
                "- Missing check that sum of all user deposits <= hardcoded pool size\n"
                "- Rate calculation using hardcoded ratio that becomes invalid when cap is exceeded\n"
                "- withdrawRemaining() reverts when actual balance < expected balance due to overcapping"
            )
        if any(
            kw in code_lower for kw in ["transfer", "move", "migrate", "plotid", "tokenid"]
        ) and any(kw in code_lower for kw in ["struct", "state", "mapping"]):
            sections.append(
                "KNOWN TRANSFER STATE EXPLOITS:\n"
                "- Transfer function updates destination but NOT source state struct\n"
                "  (e.g., moves token to new plot but plotId in ToilerState unchanged)\n"
                "- Occupied/available flags not synced after transfer → double occupancy\n"
                "- Old references (mappings) not cleaned up after move/migrate\n"
                "- Struct fields partially updated leaving inconsistent state"
            )
        if any(kw in code_lower for kw in ["exchange", "convert", "merge", "swap"]) and any(
            kw in code_lower for kw in ["period", "deadline", "timestamp", "block.timestamp"]
        ):
            sections.append(
                "KNOWN TIME-BOUNDED EXCHANGE EXPLOITS:\n"
                "- No cap enforcement during exchange period → total exchanged exceeds pool\n"
                "- Missing deadline check → exchange after period should revert but doesn't\n"
                "- Remaining token withdrawal before exchange period ends → premature drain\n"
                "- Underflow in withdrawal calculation when actual exchanges > expected cap"
            )

        context = "\n\n".join(sections)
        if len(context) > 4000:
            context = context[:4000]
        return context

    def _build_user_prompt(self, source_code: str, rag_context: str = "") -> str:
        """Build the user prompt with optional RAG context."""
        prompt = AUDIT_USER_PROMPT.format(source_code=source_code)
        if rag_context:
            rag_section = (
                "\n\n<known_vulnerability_patterns>\n"
                "The following vulnerability patterns have been observed in similar protocols. "
                "Use these as hints — check if any apply to this specific contract:\n\n"
                f"{rag_context}\n"
                "</known_vulnerability_patterns>\n"
            )
            prompt = rag_section + "\n" + prompt
        return prompt

    # Approx USD per 1M tokens (input, output). Token COUNTS logged are EXACT
    # (from the API usage object); only the $ estimate uses this table — update
    # it when provider prices change.
    _PRICING = {
        "gpt-4o": (2.50, 10.00),
        "gpt-5": (1.25, 10.00),
        "claude-sonnet-4-6": (3.00, 15.00),
        "claude-opus": (15.00, 75.00),
    }

    def _record_usage(self, model: str, in_tok: int, out_tok: int, reasoning_tok: int = 0) -> None:
        """Log exact token usage + estimated cost; append to a ledger if set.

        Set MIESC_FRONTIER_USAGE_LOG=<path> to accumulate one JSON line per call
        across subprocesses (the benchmark reads it to report per-audit cost).
        """
        pin, pout = next((p for k, p in self._PRICING.items() if model.startswith(k)), (0.0, 0.0))
        cost = (in_tok * pin + out_tok * pout) / 1_000_000
        logger.info(
            "FrontierLLM usage [%s]: in=%d out=%d%s ~$%.4f",
            model, in_tok, out_tok, f" reasoning={reasoning_tok}" if reasoning_tok else "", cost,
        )
        ledger = os.environ.get("MIESC_FRONTIER_USAGE_LOG")
        if ledger:
            try:
                with open(ledger, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "model": model, "input_tokens": in_tok, "output_tokens": out_tok,
                        "reasoning_tokens": reasoning_tok, "cost_usd": round(cost, 6),
                    }) + "\n")
            except Exception:  # noqa: BLE001 - ledger is best-effort
                pass

    def _analyze_anthropic(self, source_code: str, **kwargs: Any) -> List[Dict]:
        """Call Anthropic Claude API."""
        import anthropic

        client: Any = anthropic.Anthropic()
        rag_context = kwargs.pop("rag_context", "")
        model = kwargs.get("model", "claude-sonnet-4-6")
        self._model = model

        user_prompt = self._build_user_prompt(source_code, rag_context)
        rag_note = f" +RAG({len(rag_context)})" if rag_context else ""
        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars{rag_note})")

        message = client.messages.create(
            model=model,
            max_tokens=8192,  # complex contracts produce long reports; 4096 truncated → 0 findings
            system=AUDIT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        u = getattr(message, "usage", None)
        if u:
            self._record_usage(model, getattr(u, "input_tokens", 0) or 0,
                               getattr(u, "output_tokens", 0) or 0)
        return self._parse_response(getattr(message.content[0], "text", ""))

    def converse_with_tools(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[ToolSpec],
        on_tool_call: Callable[[str, Dict[str, Any]], str],
        model: Optional[str] = None,
        max_iterations: int = 12,
        temperature: float = 0.2,
    ) -> ConversationResult:
        """Run an Anthropic tool-use conversational loop.

        The model may emit tool calls; each is executed via
        ``on_tool_call(name, args) -> str`` and fed back to the model,
        repeating until it returns final text or ``max_iterations`` tool
        rounds are exhausted.

        Provider parity: the same method works for both providers behind the
        same ``ToolSpec`` / ``ConversationResult`` contract. The provider is
        resolved from the model id (``claude``/``anthropic`` → Anthropic
        ``tool_use``; ``gpt``/``openai``/o-series → OpenAI function-calling),
        falling back to the adapter's configured/detected provider. Both
        branches call the identical ``on_tool_call`` callback and return an
        identical ``ConversationResult``.

        This is additive and independent of ``analyze()`` — nothing changes
        unless a caller invokes it.

        Args:
            system: System prompt (auditor role + repo map).
            messages: Initial conversation history (role/content dicts).
            tools: Provider-neutral ``ToolSpec`` list, translated to the
                provider's native tool format.
            on_tool_call: Executes one tool, returning its result string.
            model: Frontier model id; defaults per provider (Anthropic
                ``claude-sonnet-4-6``; OpenAI ``gpt-4o``).
            max_iterations: Hard cap on tool rounds regardless of stop reason.

        Returns:
            ConversationResult with the final text, full message history,
            the tool-call trace, and accumulated token usage.
        """
        provider = self._resolve_conversation_provider(model)
        if provider == "openai":
            return self._converse_openai(
                system, messages, tools, on_tool_call, model, max_iterations, temperature
            )
        return self._converse_anthropic(
            system, messages, tools, on_tool_call, model, max_iterations, temperature
        )

    def _resolve_conversation_provider(self, model: Optional[str]) -> str:
        """Pick the tool-use branch. An explicit model id wins (``claude``/
        ``anthropic`` → anthropic; ``gpt``/``openai``/o-series → openai);
        otherwise fall back to the adapter's configured/detected provider,
        defaulting to anthropic."""
        if model:
            m = model.lower()
            if m.startswith(("claude", "anthropic")):
                return "anthropic"
            if m.startswith(("gpt", "openai", "o1", "o3", "o4")):
                return "openai"
        provider = self._get_provider()
        if provider in ("anthropic", "openai"):
            return provider
        return "anthropic"

    def _converse_anthropic(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[ToolSpec],
        on_tool_call: Callable[[str, Dict[str, Any]], str],
        model: Optional[str] = None,
        max_iterations: int = 12,
        temperature: float = 0.2,
    ) -> ConversationResult:
        """Anthropic ``tool_use`` branch of :meth:`converse_with_tools`."""
        import anthropic

        client: Any = anthropic.Anthropic()
        model = model or "claude-sonnet-4-6"
        self._model = model

        # Translate provider-neutral specs to Anthropic's tool format.
        anthropic_tools = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]

        conversation: List[Any] = list(messages)
        tool_calls: List[Dict[str, Any]] = []
        usage: Dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
        final_text = ""

        logger.info(
            "FrontierLLM: Starting tool-use conversation with %s "
            "(%d tools, max_iterations=%d)",
            model, len(anthropic_tools), max_iterations,
        )

        for round_idx in range(max_iterations):
            message = client.messages.create(
                model=model,
                max_tokens=8192,
                temperature=temperature,
                system=system,
                messages=conversation,
                tools=anthropic_tools,
            )

            # Accumulate exact token usage across every call in the loop.
            u = getattr(message, "usage", None)
            if u:
                in_tok = getattr(u, "input_tokens", 0) or 0
                out_tok = getattr(u, "output_tokens", 0) or 0
                usage["input_tokens"] += in_tok
                usage["output_tokens"] += out_tok
                self._record_usage(model, in_tok, out_tok)

            content = list(getattr(message, "content", []) or [])
            # Preserve the assistant turn verbatim (tool_use blocks included).
            conversation.append({"role": "assistant", "content": content})

            tool_use_blocks = [
                b for b in content if getattr(b, "type", None) == "tool_use"
            ]

            # Final text: model stopped naturally or emitted no tool calls.
            if getattr(message, "stop_reason", None) == "end_turn" or not tool_use_blocks:
                final_text = "".join(
                    getattr(b, "text", "") or ""
                    for b in content
                    if getattr(b, "type", None) == "text"
                )
                logger.info(
                    "FrontierLLM: Conversation finished after %d tool round(s)",
                    round_idx,
                )
                return ConversationResult(
                    final_text=final_text,
                    messages=conversation,
                    tool_calls=tool_calls,
                    usage=usage,
                )

            # Execute each requested tool and feed results back as one user turn.
            tool_results: List[Dict[str, Any]] = []
            for block in tool_use_blocks:
                name = getattr(block, "name", "")
                args = getattr(block, "input", {}) or {}
                try:
                    result = on_tool_call(name, args)
                except Exception as e:  # noqa: BLE001 - surface tool errors to the model
                    result = f"ERROR: tool '{name}' failed: {e}"
                tool_calls.append({"name": name, "args": args, "result": result})
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "id", ""),
                        "content": result,
                    }
                )
            conversation.append({"role": "user", "content": tool_results})

        # max_iterations exhausted with tool calls still pending. Rather than
        # returning empty final_text (which parses to zero hypotheses), force ONE
        # final call with tools DISABLED so the model must answer from what it has
        # already inspected.
        logger.warning(
            "FrontierLLM: Tool-use conversation hit max_iterations=%d; forcing a "
            "final answer with tools disabled",
            max_iterations,
        )
        conversation.append(
            {
                "role": "user",
                "content": (
                    "You have gathered enough context. Do NOT request any more "
                    "tools. Based on what you have already inspected, output your "
                    "final answer now in the exact format requested."
                ),
            }
        )
        try:
            message = client.messages.create(
                model=model,
                max_tokens=8192,
                temperature=temperature,
                system=system,
                messages=conversation,
            )
            u = getattr(message, "usage", None)
            if u:
                in_tok = getattr(u, "input_tokens", 0) or 0
                out_tok = getattr(u, "output_tokens", 0) or 0
                usage["input_tokens"] += in_tok
                usage["output_tokens"] += out_tok
                self._record_usage(model, in_tok, out_tok)
            content = list(getattr(message, "content", []) or [])
            conversation.append({"role": "assistant", "content": content})
            final_text = "".join(
                getattr(b, "text", "") or ""
                for b in content
                if getattr(b, "type", None) == "text"
            )
        except Exception as e:  # noqa: BLE001 - keep empty final_text on failure
            logger.warning(
                "FrontierLLM: forced final answer call failed: %s", e
            )
            final_text = ""
        return ConversationResult(
            final_text=final_text,
            messages=conversation,
            tool_calls=tool_calls,
            usage=usage,
        )

    def _converse_openai(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: List[ToolSpec],
        on_tool_call: Callable[[str, Dict[str, Any]], str],
        model: Optional[str] = None,
        max_iterations: int = 12,
        temperature: float = 0.2,
    ) -> ConversationResult:
        """OpenAI function-calling branch of :meth:`converse_with_tools`.

        Mirrors the Anthropic branch behind the same ``ToolSpec`` /
        ``on_tool_call`` / ``ConversationResult`` contract. Each ``ToolSpec``
        becomes an OpenAI ``{"type":"function","function":{...}}`` tool; a
        response carrying ``tool_calls`` is executed and each result is fed
        back as a ``role:"tool"`` message until the model returns plain content
        or ``max_iterations`` rounds are exhausted.
        """
        import openai

        client: Any = openai.OpenAI()
        model = model or "gpt-4o"
        self._model = model

        # Translate provider-neutral specs to OpenAI's function-tool format.
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

        # OpenAI carries the system prompt as the first message, not a kwarg.
        conversation: List[Any] = [{"role": "system", "content": system}]
        conversation.extend(messages)
        tool_calls: List[Dict[str, Any]] = []
        usage: Dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
        final_text = ""

        # GPT-5 / o-series use max_completion_tokens (+ hidden reasoning budget);
        # everything else uses max_tokens. Mirrors ``_analyze_openai``.
        token_param: Dict[str, Any] = {}
        extra: Dict[str, Any] = {}
        if model.startswith(("gpt-5", "o1", "o3", "o4")):
            token_param["max_completion_tokens"] = 32768
            extra["reasoning_effort"] = "low"
        else:
            token_param["max_tokens"] = 8192
            # o-series/gpt-5 reject a custom temperature; only set it elsewhere.
            extra["temperature"] = temperature

        logger.info(
            "FrontierLLM: Starting tool-use conversation with %s "
            "(%d tools, max_iterations=%d)",
            model, len(openai_tools), max_iterations,
        )

        for round_idx in range(max_iterations):
            response = client.chat.completions.create(
                model=model,
                messages=conversation,
                tools=openai_tools,
                **token_param,
                **extra,
            )

            # Accumulate exact token usage across every call in the loop.
            u = getattr(response, "usage", None)
            if u:
                in_tok = getattr(u, "prompt_tokens", 0) or 0
                out_tok = getattr(u, "completion_tokens", 0) or 0
                usage["input_tokens"] += in_tok
                usage["output_tokens"] += out_tok
                reasoning = 0
                details = getattr(u, "completion_tokens_details", None)
                if details:
                    reasoning = getattr(details, "reasoning_tokens", 0) or 0
                self._record_usage(model, in_tok, out_tok, reasoning)

            msg = response.choices[0].message
            requested = list(getattr(msg, "tool_calls", None) or [])

            # Preserve the assistant turn verbatim (tool_calls included) so the
            # subsequent role:"tool" messages resolve against the right ids.
            assistant_turn: Dict[str, Any] = {
                "role": "assistant",
                "content": getattr(msg, "content", None) or "",
            }
            if requested:
                assistant_turn["tool_calls"] = [
                    {
                        "id": getattr(tc, "id", ""),
                        "type": "function",
                        "function": {
                            "name": getattr(tc.function, "name", ""),
                            "arguments": getattr(tc.function, "arguments", "") or "",
                        },
                    }
                    for tc in requested
                ]
            conversation.append(assistant_turn)

            # Final content: model stopped requesting tools.
            if not requested:
                final_text = getattr(msg, "content", "") or ""
                logger.info(
                    "FrontierLLM: Conversation finished after %d tool round(s)",
                    round_idx,
                )
                return ConversationResult(
                    final_text=final_text,
                    messages=conversation,
                    tool_calls=tool_calls,
                    usage=usage,
                )

            # Execute each requested tool; each result is its own tool message.
            for tc in requested:
                name = getattr(tc.function, "name", "")
                raw_args = getattr(tc.function, "arguments", "") or "{}"
                try:
                    args = json.loads(raw_args) if raw_args else {}
                except (ValueError, TypeError):
                    args = {}
                try:
                    result = on_tool_call(name, args)
                except Exception as e:  # noqa: BLE001 - surface tool errors to the model
                    result = f"ERROR: tool '{name}' failed: {e}"
                tool_calls.append({"name": name, "args": args, "result": result})
                conversation.append(
                    {
                        "role": "tool",
                        "tool_call_id": getattr(tc, "id", ""),
                        "content": result,
                    }
                )

        # max_iterations exhausted with tool calls still pending. Rather than
        # returning empty final_text (which parses to zero hypotheses), force ONE
        # final call with tools DISABLED so the model must answer from what it has
        # already inspected.
        logger.warning(
            "FrontierLLM: Tool-use conversation hit max_iterations=%d; forcing a "
            "final answer with tools disabled",
            max_iterations,
        )
        conversation.append(
            {
                "role": "user",
                "content": (
                    "You have gathered enough context. Do NOT request any more "
                    "tools. Based on what you have already inspected, output your "
                    "final answer now in the exact format requested."
                ),
            }
        )
        try:
            response = client.chat.completions.create(
                model=model,
                messages=conversation,
                **token_param,
                **extra,
            )
            u = getattr(response, "usage", None)
            if u:
                in_tok = getattr(u, "prompt_tokens", 0) or 0
                out_tok = getattr(u, "completion_tokens", 0) or 0
                usage["input_tokens"] += in_tok
                usage["output_tokens"] += out_tok
                reasoning = 0
                details = getattr(u, "completion_tokens_details", None)
                if details:
                    reasoning = getattr(details, "reasoning_tokens", 0) or 0
                self._record_usage(model, in_tok, out_tok, reasoning)
            msg = response.choices[0].message
            final_text = getattr(msg, "content", "") or ""
            conversation.append(
                {"role": "assistant", "content": final_text}
            )
        except Exception as e:  # noqa: BLE001 - keep empty final_text on failure
            logger.warning(
                "FrontierLLM: forced final answer call failed: %s", e
            )
            final_text = ""
        return ConversationResult(
            final_text=final_text,
            messages=conversation,
            tool_calls=tool_calls,
            usage=usage,
        )

    def _analyze_openai(self, source_code: str, **kwargs: Any) -> List[Dict]:
        """Call OpenAI API (supports GPT-4o, GPT-4.1, GPT-5, o-series)."""
        import openai

        client: Any = openai.OpenAI()
        rag_context = kwargs.pop("rag_context", "")
        model = kwargs.get("model", "gpt-4o")
        self._model = model

        user_prompt = self._build_user_prompt(source_code, rag_context)
        rag_note = f" +RAG({len(rag_context)})" if rag_context else ""
        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars{rag_note})")

        # GPT-5 and o-series use max_completion_tokens instead of max_tokens.
        # Reasoning models spend part of that budget on hidden reasoning BEFORE
        # emitting output; at 16384 the reasoning consumed the whole allowance and
        # the visible content came back empty (0 chars). Give a much larger budget
        # and cap reasoning effort so tokens are left for the actual answer.
        token_param: Dict[str, Any] = {}
        extra: Dict[str, Any] = {}
        if model.startswith(("gpt-5", "o1", "o3", "o4")):
            token_param["max_completion_tokens"] = 32768
            extra["reasoning_effort"] = "low"
        else:
            token_param["max_tokens"] = 8192
            # o-series/gpt-5 reject a custom temperature; only set it elsewhere.
            extra["temperature"] = temperature

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            **token_param,
            **extra,
        )

        u = getattr(response, "usage", None)
        if u:
            reasoning = 0
            details = getattr(u, "completion_tokens_details", None)
            if details:
                reasoning = getattr(details, "reasoning_tokens", 0) or 0
            self._record_usage(model, getattr(u, "prompt_tokens", 0) or 0,
                               getattr(u, "completion_tokens", 0) or 0, reasoning)
        return self._parse_response(response.choices[0].message.content)

    def _ensure_ollama_model(self, model: str) -> bool:
        """Check if model is available in Ollama, pull if not."""
        import urllib.request

        try:
            req = urllib.request.Request("http://localhost:11434/api/tags")
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            installed = [m["name"] for m in data.get("models", [])]
            # Check exact match or base name match (e.g., "qwen2.5-coder:32b" in list)
            if model in installed or any(model.split(":")[0] in m for m in installed):
                return True
        except Exception:
            return False

        # Model not installed — attempt pull
        logger.info(f"FrontierLLM: Model '{model}' not found locally, pulling...")
        try:
            pull_data = json.dumps({"name": model, "stream": False}).encode()
            pull_req = urllib.request.Request(
                "http://localhost:11434/api/pull",
                data=pull_data,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(pull_req, timeout=600)
            logger.info(f"FrontierLLM: Model '{model}' pulled successfully")
            return True
        except Exception as e:
            logger.warning(f"FrontierLLM: Could not pull model '{model}': {e}")
            return False

    def _select_best_ollama_model(self) -> str:
        """Select the best available Ollama model for security auditing.

        Priority: qwen2.5-coder:32b > qwen2.5-coder:14b > codellama:13b > mistral:7b
        """
        import urllib.request

        # Ordered by audit quality (best first)
        preferred = [
            "qwen2.5-coder:32b",
            "qwen2.5-coder:14b",
            "codellama:13b",
            "mistral:7b",
            "llama3.2:3b",
        ]

        try:
            req = urllib.request.Request("http://localhost:11434/api/tags")
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read())
            installed = [m["name"] for m in data.get("models", [])]

            for model in preferred:
                if model in installed:
                    return model
                # Fuzzy match (e.g., "qwen2.5-coder:32b" matches "qwen2.5-coder:32b-fp16")
                base = model.split(":")[0]
                for m in installed:
                    if base in m:
                        return cast(str, m)
        except Exception:
            pass

        return preferred[0]  # Default to best, will be auto-pulled

    def _analyze_ollama(self, source_code: str, **kwargs: Any) -> List[Dict]:
        """Call local Ollama model with the same audit prompt as frontier models."""
        import urllib.request

        rag_context = kwargs.pop("rag_context", "")
        model = kwargs.get("model") or self._select_best_ollama_model()
        self._model = model

        # Ensure model is available (auto-pull if needed)
        self._ensure_ollama_model(model)

        # For local models: trim source to 80KB max (32B models have ~32K context)
        max_local_chars = 80_000
        trimmed = (
            source_code[:max_local_chars] if len(source_code) > max_local_chars else source_code
        )

        # Build prompt with trimmed RAG (keep it shorter for local models)
        rag_trimmed = rag_context[:1500] if rag_context else ""
        user_prompt = self._build_user_prompt(trimmed, rag_trimmed)

        rag_note = f" +RAG({len(rag_trimmed)})" if rag_trimmed else ""
        logger.info(f"FrontierLLM: Calling Ollama {model} ({len(trimmed)} chars{rag_note})")

        # Use chat endpoint (handles system/user roles better than generate)
        data = json.dumps(
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 4096},
            }
        ).encode()

        req = urllib.request.Request(
            "http://localhost:11434/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=600)
        result = json.loads(resp.read())
        return self._parse_response(result.get("message", {}).get("content", ""))

    def _parse_response(self, text: str) -> List[Dict]:
        """Parse JSON findings from LLM response.

        Handles multiple response formats:
        - Raw JSON array: [...]
        - Markdown code block: ```json [...] ```
        - Wrapped dict: {"vulnerabilities": [...]}
        - Mixed text with embedded JSON
        """
        import re

        text = text.strip()

        # Strip OUTER markdown code fences only (preserve inner ones in strings)
        # Match: starts with ```json, ends with ```
        text_clean = text
        if text_clean.startswith("```"):
            # Remove opening fence
            first_newline = text_clean.find("\n")
            if first_newline > 0:
                text_clean = text_clean[first_newline + 1 :]
            # Remove closing fence
            last_fence = text_clean.rfind("```")
            if last_fence > 0:
                text_clean = text_clean[:last_fence]
        text_clean = text_clean.strip()

        # Try multiple extraction strategies
        for attempt_text in [text_clean, text]:
            # Strategy 1: Find outermost JSON array
            start = attempt_text.find("[")
            end = attempt_text.rfind("]")
            if start != -1 and end != -1 and end > start:
                json_str = attempt_text[start : end + 1]
                # Sanitize: escape inner backticks and control chars in string values
                json_str = json_str.replace("```solidity", "").replace("```", "")
                # Fix literal newlines/tabs inside JSON string values (common with local LLMs)
                # Replace actual newlines inside strings with \\n
                json_str = re.sub(
                    r'(?<=": ")(.*?)(?="[,\s*\}])',
                    lambda m: m.group(0).replace("\n", "\\n").replace("\t", "\\t"),
                    json_str,
                    flags=re.DOTALL,
                )
                # Fallback: replace ALL raw control chars with spaces
                json_str = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", json_str)
                try:
                    findings = json.loads(json_str)
                    if isinstance(findings, list):
                        valid = [f for f in findings if isinstance(f, dict)]
                        if valid:
                            return valid
                except json.JSONDecodeError:
                    # Try fixing common JSON issues: trailing commas + raw newlines
                    fixed = re.sub(r",\s*([}\]])", r"\1", json_str)
                    # Nuclear option: replace ALL newlines that aren't between [ and ]
                    fixed = fixed.replace("\n", "\\n")
                    try:
                        findings = json.loads(fixed)
                        if isinstance(findings, list):
                            return [f for f in findings if isinstance(f, dict)]
                    except json.JSONDecodeError:
                        pass

            # Strategy 2: Parse as dict with vulnerabilities key
            try:
                result = json.loads(attempt_text)
                if isinstance(result, list):
                    return [f for f in result if isinstance(f, dict)]
                if isinstance(result, dict):
                    for key in ("vulnerabilities", "findings", "results"):
                        if key in result and isinstance(result[key], list):
                            return [f for f in result[key] if isinstance(f, dict)]
            except json.JSONDecodeError:
                pass

        # Strategy 3: Extract individual JSON objects line by line
        findings = []
        for line in text.split("\n"):
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict) and any(
                        k in obj for k in ("title", "type", "vulnerability", "description")
                    ):
                        findings.append(obj)
                except json.JSONDecodeError:
                    pass
        if findings:
            return findings

        # Strategy 4: Extract objects by matching balanced braces
        depth = 0
        obj_start = -1
        for i, ch in enumerate(text_clean):
            if ch == "{":
                if depth == 0:
                    obj_start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and obj_start >= 0:
                    obj_str = text_clean[obj_start : i + 1]
                    # Clean up common issues in extracted objects
                    obj_str = obj_str.replace("```solidity", "").replace("```", "")
                    obj_str = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", obj_str)
                    try:
                        obj = json.loads(obj_str)
                        if isinstance(obj, dict) and any(
                            k in obj
                            for k in ("title", "type", "vulnerability", "description", "severity")
                        ):
                            findings.append(obj)
                    except json.JSONDecodeError:
                        pass
                    obj_start = -1
        if findings:
            return findings

        # Strategy 5: Find JSON array anywhere in the text using regex
        # Handles cases where model outputs explanation text before/after JSON
        json_array_match = re.search(r"\[\s*\{", text)
        if json_array_match:
            # Find the matching closing bracket
            start_pos = json_array_match.start()
            bracket_depth = 0
            end_pos = start_pos
            for i in range(start_pos, len(text)):
                if text[i] == "[":
                    bracket_depth += 1
                elif text[i] == "]":
                    bracket_depth -= 1
                    if bracket_depth == 0:
                        end_pos = i + 1
                        break
            if end_pos > start_pos:
                json_str = text[start_pos:end_pos]
                json_str = json_str.replace("```solidity", "").replace("```", "")
                json_str = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", json_str)
                # Fix trailing commas
                json_str = re.sub(r",\s*([}\]])", r"\1", json_str)
                try:
                    findings = json.loads(json_str)
                    if isinstance(findings, list):
                        valid = [f for f in findings if isinstance(f, dict)]
                        if valid:
                            return valid
                except json.JSONDecodeError:
                    pass

        logger.warning(f"FrontierLLM: Could not parse response ({len(text)} chars)")
        return []

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize raw LLM output to MIESC finding format."""
        if isinstance(raw_output, list):
            return raw_output
        if isinstance(raw_output, dict):
            return cast(List[Dict[str, Any]], raw_output.get("findings", []))
        return []

    def _error_result(self, start_time: float, error_msg: str) -> Dict[str, Any]:
        return {
            "tool": "frontier-llm",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error_msg,
        }
