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
5. **Look for economic exploits** — Flash loan attacks? Oracle manipulation? Rounding errors?
6. **Check edge cases** — What happens with zero values? Max values? Empty arrays?

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

        provider = self._get_provider()

        try:
            if provider == "anthropic":
                findings = self._analyze_anthropic(source_code, **kwargs)
            elif provider == "openai":
                findings = self._analyze_openai(source_code, **kwargs)
            else:
                return self._error_result(start_time, f"Unknown provider: {provider}")
        except Exception as e:
            logger.error(f"FrontierLLM API error: {e}")
            return self._error_result(start_time, str(e))

        elapsed = time.time() - start_time

        # Normalize findings
        normalized = []
        for f in findings:
            normalized.append({
                "type": f.get("type", "logic_error"),
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "Medium").capitalize(),
                "tool": f"frontier-{provider}",
                "confidence": 0.80,
                "location": {
                    "file": contract_path,
                    "line": f.get("line", 0),
                    "function": f.get("function", "unknown"),
                },
                "description": f.get("description", ""),
                "message": f.get("impact", ""),
                "recommendation": f.get("recommendation", ""),
                "exploit_scenario": f.get("proof_of_concept", ""),
                "swc_id": "",
            })

        return {
            "tool": f"frontier-{provider}",
            "status": "success",
            "findings": normalized,
            "execution_time": elapsed,
            "metadata": {
                "provider": provider,
                "model": self._model,
                "source_chars": len(source_code),
            },
        }

    def _analyze_anthropic(self, source_code: str, **kwargs) -> List[Dict]:
        """Call Anthropic Claude API."""
        import anthropic

        client = anthropic.Anthropic()
        model = kwargs.get("model", "claude-sonnet-4-20250514")
        self._model = model

        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars)")

        message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=AUDIT_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": AUDIT_USER_PROMPT.format(source_code=source_code),
            }],
        )

        return self._parse_response(message.content[0].text)

    def _analyze_openai(self, source_code: str, **kwargs) -> List[Dict]:
        """Call OpenAI API."""
        import openai

        client = openai.OpenAI()
        model = kwargs.get("model", "gpt-4o")
        self._model = model

        logger.info(f"FrontierLLM: Calling {model} ({len(source_code)} chars)")

        response = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": AUDIT_USER_PROMPT.format(source_code=source_code)},
            ],
        )

        return self._parse_response(response.choices[0].message.content)

    def _parse_response(self, text: str) -> List[Dict]:
        """Parse JSON findings from LLM response."""
        # Try to extract JSON array from response
        text = text.strip()

        # Find JSON array in the response
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            json_str = text[start:end + 1]
            try:
                findings = json.loads(json_str)
                if isinstance(findings, list):
                    return [f for f in findings if isinstance(f, dict)]
            except json.JSONDecodeError:
                pass

        # Try parsing the whole response as JSON
        try:
            result = json.loads(text)
            if isinstance(result, list):
                return [f for f in result if isinstance(f, dict)]
            if isinstance(result, dict) and "vulnerabilities" in result:
                return result["vulnerabilities"]
        except json.JSONDecodeError:
            pass

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
