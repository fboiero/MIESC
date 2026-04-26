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
from typing import Any, Dict, List, Optional

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security audit prompt — Chain-of-Thought with structured output
# ---------------------------------------------------------------------------

AUDIT_SYSTEM_PROMPT = """You are an expert smart contract security auditor with 10+ years of experience auditing DeFi protocols. You have deep knowledge of:
- Solidity internals, EVM opcodes, storage layout
- DeFi attack vectors: flash loans, oracle manipulation, reentrancy, MEV
- Economic exploit patterns: rounding errors, invariant violations, governance attacks
- Access control flaws, upgrade vulnerabilities, cross-contract interactions

Your task is to find HIGH and CRITICAL severity vulnerabilities that could lead to loss of funds, unauthorized access, or protocol manipulation."""

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
6. **Check edge cases** — What happens with zero values? Max values? Empty arrays? What if a limit or cap is exceeded? What if called at boundary conditions (exact deadlines, exactly full arrays)?
7. **Check state consistency** — Are state variables updated correctly in all paths? Are there dirty flags or counters that could get out of sync? Can state be manipulated by calling functions in unexpected order?
8. **Check multi-contract interactions** — If the contract interacts with external contracts or tokens, can those interactions be exploited? Can callbacks change state unexpectedly?

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
        self._model = None
        self._client = None

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="frontier_llm",
            version="1.0.0",
            description="Frontier LLM security analysis (Claude/GPT API)",
            category=ToolCategory.AI_ANALYSIS,
            capabilities=[
                ToolCapability(
                    name="semantic_audit",
                    description="Deep semantic vulnerability detection using frontier models",
                    detection_types=["business_logic", "economic_exploit", "access_control",
                                     "reentrancy", "oracle_manipulation", "governance"],
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

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Analyze contract using frontier LLM API."""
        start_time = time.time()

        if self.is_available() != ToolStatus.AVAILABLE:
            return self._error_result(start_time, "FrontierLLM not available")

        # Read contract
        try:
            source_code = open(contract_path).read()
        except Exception as e:
            return self._error_result(start_time, f"Cannot read contract: {e}")

        # Truncate very large contracts (frontier models handle ~100K tokens)
        max_chars = 150_000
        if len(source_code) > max_chars:
            source_code = source_code[:max_chars] + "\n// ... (truncated)"
            logger.warning(f"FrontierLLM: Contract truncated to {max_chars} chars")

        # RAG enrichment: inject protocol-specific vulnerability context
        rag_context = self._get_rag_context(source_code)

        provider = self._get_provider()

        try:
            if provider == "anthropic":
                findings = self._analyze_anthropic(source_code, rag_context=rag_context, **kwargs)
            elif provider == "openai":
                findings = self._analyze_openai(source_code, rag_context=rag_context, **kwargs)
            else:
                return self._error_result(start_time, f"Unknown provider: {provider}")
        except Exception as e:
            # Auto-fallback: if primary provider fails, try the other one
            fallback = "openai" if provider == "anthropic" else "anthropic"
            fallback_key = "OPENAI_API_KEY" if fallback == "openai" else "ANTHROPIC_API_KEY"
            if os.environ.get(fallback_key):
                logger.warning(f"FrontierLLM: {provider} failed ({e}), falling back to {fallback}")
                try:
                    if fallback == "openai":
                        findings = self._analyze_openai(source_code, rag_context=rag_context, **kwargs)
                    else:
                        findings = self._analyze_anthropic(source_code, rag_context=rag_context, **kwargs)
                except Exception as e2:
                    logger.error(f"FrontierLLM: Both providers failed. {provider}: {e}, {fallback}: {e2}")
                    return self._error_result(start_time, f"{provider}: {e} | {fallback}: {e2}")
            else:
                logger.error(f"FrontierLLM API error: {e}")
                return self._error_result(start_time, str(e))

        elapsed = time.time() - start_time

        # Normalize findings — handle diverse key names from different LLM responses
        normalized = []
        for f in findings:
            title = f.get("title") or f.get("vulnerability") or f.get("name") or f.get("type") or "Unknown"
            ftype = f.get("type") or f.get("category") or f.get("vulnerability_type") or "logic_error"
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
            normalized.append({
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
                "recommendation": f.get("recommendation") or f.get("fix") or f.get("remediation") or "",
                "exploit_scenario": f.get("proof_of_concept") or f.get("attack_scenario") or f.get("exploit") or "",
                "swc_id": f.get("swc_id") or f.get("swc") or "",
            })

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
        if any(kw in code_lower for kw in ["merge", "migrate", "exchange", "convert", "swap"]) and \
           any(kw in code_lower for kw in ["deadline", "period", "expir", "timestamp"]):
            sections.append(
                "KNOWN TOKEN MIGRATION EXPLOITS:\n"
                "- No cap enforcement: exchanging more tokens than allocated pool\n"
                "- Missing deadline validation: exchange after period should revert\n"
                "- Remaining token withdrawal before exchange period ends\n"
                "- Double-exchange via reentrancy in migration function"
            )

        context = "\n\n".join(sections)
        if len(context) > 3000:
            context = context[:3000]
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

    def _analyze_anthropic(self, source_code: str, **kwargs) -> List[Dict]:
        """Call Anthropic Claude API."""
        import anthropic

        client = anthropic.Anthropic()
        rag_context = kwargs.pop("rag_context", "")
        model = kwargs.get("model", "claude-sonnet-4-20250514")
        self._model = model

        user_prompt = self._build_user_prompt(source_code, rag_context)
        rag_note = f" +RAG({len(rag_context)})" if rag_context else ""
        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars{rag_note})")

        message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=AUDIT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        return self._parse_response(message.content[0].text)

    def _analyze_openai(self, source_code: str, **kwargs) -> List[Dict]:
        """Call OpenAI API."""
        import openai

        client = openai.OpenAI()
        rag_context = kwargs.pop("rag_context", "")
        model = kwargs.get("model", "gpt-4o")
        self._model = model

        user_prompt = self._build_user_prompt(source_code, rag_context)
        rag_note = f" +RAG({len(rag_context)})" if rag_context else ""
        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars{rag_note})")

        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        return self._parse_response(response.choices[0].message.content)

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

        # Strip markdown code fences
        text_clean = re.sub(r"```(?:json)?\s*", "", text)
        text_clean = text_clean.strip()

        # Try multiple extraction strategies
        for attempt_text in [text_clean, text]:
            # Strategy 1: Find outermost JSON array
            start = attempt_text.find("[")
            end = attempt_text.rfind("]")
            if start != -1 and end != -1 and end > start:
                json_str = attempt_text[start:end + 1]
                try:
                    findings = json.loads(json_str)
                    if isinstance(findings, list):
                        valid = [f for f in findings if isinstance(f, dict)]
                        if valid:
                            return valid
                except json.JSONDecodeError:
                    # Try fixing common JSON issues (trailing commas)
                    fixed = re.sub(r",\s*([}\]])", r"\1", json_str)
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
                    if isinstance(obj, dict) and any(k in obj for k in ("title", "type", "vulnerability", "description")):
                        findings.append(obj)
                except json.JSONDecodeError:
                    pass
        if findings:
            return findings

        logger.warning(f"FrontierLLM: Could not parse response ({len(text)} chars)")
        return []

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize raw LLM output to MIESC finding format."""
        if isinstance(raw_output, list):
            return raw_output
        if isinstance(raw_output, dict):
            return raw_output.get("findings", [])
        return []

    def _error_result(self, start_time: float, error_msg: str) -> Dict[str, Any]:
        return {
            "tool": "frontier-llm",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error_msg,
        }
