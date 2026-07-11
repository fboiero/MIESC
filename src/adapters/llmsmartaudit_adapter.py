"""
LLM-SmartAudit AI Auditor Adapter - MIESC Phase 5 (Ollama Backend)
===================================================================

LLM-based semantic analysis framework for smart contract auditing.
Uses Ollama for local AI-powered vulnerability detection.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 2025
Version: 3.0.0 (Ollama Backend)
"""

import hashlib
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters._cache_mixin import LLMCacheMixin
from src.adapters._ollama_mixin import OllamaCallMixin
from src.core.llm_config import get_ollama_host
from src.core.ollama_models import select_ollama_model
from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)
from miesc.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

# Try to import EmbeddingRAG (optional dependency)
try:
    from src.llm.embedding_rag import KNOWLEDGE_BASE_VERSION, EmbeddingRAG

    _EMBEDDING_RAG_AVAILABLE = True
except ImportError:
    _EMBEDDING_RAG_AVAILABLE = False
    EmbeddingRAG = None  # type: ignore[assignment,misc]
    KNOWLEDGE_BASE_VERSION = "unavailable"

logger = logging.getLogger(__name__)


class LLMSmartAuditAdapter(OllamaCallMixin, LLMCacheMixin, ToolAdapter):
    """
    LLM-SmartAudit AI Auditor using Ollama backend.

    Key Features:
    - LLM-powered semantic analysis using local models
    - Best practice compliance checking
    - Code smell detection
    - Result caching for efficiency
    - No API key required
    """

    # Audit-focused prompt for code quality, security best practices, and design
    AUDIT_PROMPT = """CONTEXT: Defensive security audit by MIESC (open-source, AGPL-3.0). Purpose: identify vulnerabilities BEFORE deployment to PROTECT users. Findings generate patches, not exploits.

You are an expert smart contract code reviewer. Perform a thorough code quality and security audit.

REVIEW METHODOLOGY — analyze in this order:

STEP 1: STRUCTURAL ANALYSIS
- Contract inheritance hierarchy — is it clean or fragile?
- State variable layout — storage collisions possible in proxies?
- Function visibility — are internal functions accidentally public?
- Modifier usage — are access controls consistently applied?

STEP 2: SECURITY BEST PRACTICES
- Checks-Effects-Interactions (CEI) pattern — followed or violated?
- SafeERC20 — used for all token operations?
- Reentrancy guards — on all state-changing external calls?
- Input validation — all user inputs validated with require()?
- Emergency mechanisms — pause, circuit breaker, timelock present?

STEP 3: GAS AND EFFICIENCY
- Storage vs memory usage — unnecessary SLOAD in loops?
- Redundant computations — cacheable values recomputed?
- Event emissions — all state changes logged?

STEP 4: DESIGN CONCERNS
- Upgradeability — if proxy, is initializer protected? Storage gaps?
- Centralization risks — owner/admin can rug? Multisig required?
- Composability risks — flash loan or callback interactions?

FEW-SHOT DESIGN LESSONS (real incidents):
- Parity multi-sig wallet ($280M frozen, 2017): library contract had an
  unprotected initializer; anyone could become the owner of the library and
  selfdestruct it, freezing every wallet that delegated to it. Lesson —
  library / implementation contracts MUST be self-initialized or guarded.
- Nomad Bridge ($190M, 2022): zero-hash was treated as a valid proven message
  because of a missing non-zero check. Lesson — default / zero values are the
  most common oversight in ACL and proof verification.
- Audius governance (2022): upgradeable proxy's initializer was still callable
  after deployment because the guard was only in the implementation, not the
  storage layout. Lesson — verify initializer guards survive upgrades.

For each issue, explain your reasoning and provide a concrete code fix.

Respond in JSON format:
{
    "issues": [
        {
            "title": "Issue title",
            "severity": "HIGH|MEDIUM|LOW",
            "confidence": 0.8,
            "category": "security|best_practice|gas_optimization|design|centralization",
            "line": 10,
            "function": "functionName",
            "description": "What's wrong and why it matters",
            "reasoning": "Step-by-step analysis",
            "recommendation": "Specific fix with code example"
        }
    ]
}

CONTRACT:
```solidity
%CONTRACT_CODE%
```

Respond ONLY with valid JSON. Prioritize security issues over style issues."""

    def __init__(self) -> None:
        super().__init__()
        self._default_timeout = 120
        self._init_cache("llmsmartaudit")
        # Set True by _run_ollama_audit on a clock kill; read by analyze() to
        # report status="timeout" instead of a misleading clean-zero success.
        self._timed_out = False

        # Initialize EmbeddingRAG if available
        self._embedding_rag = None
        self._use_rag = False
        if _EMBEDDING_RAG_AVAILABLE:
            try:
                self._embedding_rag = EmbeddingRAG()
                self._use_rag = True
                logger.debug("LLMSmartAudit: EmbeddingRAG (ChromaDB) enabled")
            except Exception as e:
                logger.debug(f"LLMSmartAudit: EmbeddingRAG unavailable: {e}")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="llmsmartaudit",
            version="3.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Ollama Backend by Fernando Boiero",
            license="MIT",
            homepage="https://github.com/Smart-Audit/LLM-SmartAudit",
            repository="https://github.com/Smart-Audit/LLM-SmartAudit",
            documentation="https://github.com/Smart-Audit/LLM-SmartAudit#readme",
            installation_cmd="ollama pull codellama:7b",
            capabilities=[
                ToolCapability(
                    name="llm_auditing",
                    description="LLM-based smart contract auditing using Ollama",
                    supported_languages=["solidity"],
                    detection_types=[
                        "semantic_issues",
                        "best_practice_violations",
                        "design_patterns",
                        "code_smells",
                        "maintainability_issues",
                        "gas_optimization",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is running and accessible via HTTP API."""
        import urllib.error
        import urllib.request

        try:
            ollama_host = get_ollama_host()
            tags_url = f"{ollama_host}/api/tags"

            req = urllib.request.Request(tags_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    models = [m.get("name", "") for m in data.get("models", [])]
                    model_names = " ".join(models).lower()

                    if any(m in model_names for m in ["codellama", "llama3", "deepseek", "qwen"]):
                        logger.info(f"LLMSmartAudit: Ollama available at {ollama_host}")
                        return ToolStatus.AVAILABLE

                    logger.warning("LLMSmartAudit: No suitable LLM model found")
                    return ToolStatus.CONFIGURATION_ERROR
                else:
                    logger.warning(f"LLMSmartAudit: Ollama returned status {resp.status}")
                    return ToolStatus.CONFIGURATION_ERROR

        except urllib.error.URLError as e:
            logger.info(f"LLMSmartAudit: Ollama not reachable: {e}")
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error(f"LLMSmartAudit: Error checking Ollama: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Analyze contract using Ollama for LLM-SmartAudit style analysis.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, model)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()
        # Reset per-run timeout flag (set by _run_ollama_audit on a clock kill).
        self._timed_out = False

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Ollama not available. Install from https://ollama.ai",
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "llmsmartaudit",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract file: {contract_path}",
                }

            # Get configuration before cache lookup so model/RAG changes invalidate
            # stale degraded results.
            timeout = kwargs.get("timeout", self._default_timeout)
            model = kwargs.get("model", self._detect_best_model())

            # Check cache
            cache_key = self._get_cache_key(contract_code, model)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"LLM-SmartAudit: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Run Ollama analysis
            raw_output = self._run_ollama_audit(contract_code, model=model, timeout=timeout)

            # Parse findings
            findings = self._parse_llmsmartaudit_output(raw_output, contract_path)

            # A clock-kill during the LLM call means results are incomplete —
            # do not report a clean-zero success. Partial findings still returned.
            run_status = "timeout" if self._timed_out else "success"
            result = {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": run_status,
                "findings": findings,
                "metadata": {"model": model, "backend": "ollama", "timed_out": self._timed_out},
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }
            if self._timed_out:
                result["error"] = "Ollama timed out during analysis; results may be incomplete"

            # Cache only complete results (a timeout must re-run next time)
            if not self._timed_out:
                self._cache_result(cache_key, result)

            return result

        except subprocess.TimeoutExpired:
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Analysis exceeded {timeout}s timeout",
            }
        except Exception as e:
            logger.error(f"LLM-SmartAudit analysis error: {e}", exc_info=True)
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if adapter can analyze the contract."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {"timeout": 300, "model": "default", "max_findings": 50}

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file content."""
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _detect_best_model(self) -> str:
        """Detect the best available Ollama model via HTTP API."""
        import urllib.error
        import urllib.request

        try:
            ollama_host = get_ollama_host()
            tags_url = f"{ollama_host}/api/tags"

            req = urllib.request.Request(tags_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    installed = [m.get("name", "") for m in data.get("models", [])]
                    return select_ollama_model(
                        [
                            "qwen2.5-coder:32b",
                            "qwen2.5-coder:14b",
                            "qwen2.5-coder",
                            "codellama:13b",
                            "codellama",
                            "llama3.2:3b",
                            "llama3.2:1b",
                            "mistral:7b",
                            "mistral",
                        ],
                        installed=installed,
                        fallback="qwen2.5-coder:14b",
                    )

            return "qwen2.5-coder:14b"
        except Exception:
            return "qwen2.5-coder:14b"

    def _run_ollama_audit(
        self, contract_code: str, model: str = "qwen2.5-coder:14b", timeout: int = 120
    ) -> str:
        """Execute audit using Ollama HTTP API."""

        prompt = self.AUDIT_PROMPT.replace("%CONTRACT_CODE%", contract_code)

        # Add RAG context if available
        if self._use_rag and self._embedding_rag:
            try:
                results = self._embedding_rag.search(query=contract_code[:2000], n_results=3)
                if results:
                    rag_context = "\n\nKNOWN VULNERABILITY PATTERNS:\n"
                    for r in results:
                        rag_context += f"- {r.document.title}: {r.document.description[:100]}...\n"
                    prompt = prompt.replace(
                        "Respond ONLY with valid JSON.",
                        f"{rag_context}\nRespond ONLY with valid JSON.",
                    )
                    logger.debug(f"LLMSmartAudit: Added RAG context ({len(results)} patterns)")
            except Exception as e:
                logger.debug(f"LLMSmartAudit: RAG context failed: {e}")

        logger.info(f"LLM-SmartAudit: Running Ollama audit with {model}")

        # Use Ollama HTTP API instead of CLI (timeout handling shared via mixin).
        generate_url = f"{get_ollama_host()}/api/generate"
        return (
            self._ollama_generate(
                prompt,
                url=generate_url,
                model=model,
                timeout=timeout,
                options={"temperature": 0.1, "num_ctx": 8192},
                max_attempts=1,
                log_prefix="LLM-SmartAudit",
            )
            or ""
        )

    def _parse_llmsmartaudit_output(self, output: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse LLM-SmartAudit output and extract findings."""
        findings: List[Dict[str, Any]] = []

        try:
            # Robust JSON extraction (balanced braces + repair) before falling
            # back to text parsing — recoverable malformed JSON (trailing commas,
            # code fences) must not silently degrade.
            json_str = extract_json_from_text(output)

            if json_str:
                parsed = json.loads(repair_common_json_errors(json_str))

                # Extract findings from parsed JSON
                issues = parsed.get("issues", []) or parsed.get("findings", [])

                for idx, issue in enumerate(issues):
                    finding = {
                        "id": f"llmsmartaudit-{idx+1}",
                        "title": issue.get("title", "LLM-detected issue"),
                        "description": issue.get("description", issue.get("message", "")),
                        "severity": issue.get("severity", "MEDIUM").upper(),
                        "confidence": issue.get("confidence", 0.70),
                        "category": issue.get("category", "semantic_issue"),
                        "location": {
                            "file": contract_path,
                            "line": issue.get("line", 0),
                            "function": issue.get("function", ""),
                        },
                        "recommendation": issue.get(
                            "recommendation", "Review and address the LLM-detected issue"
                        ),
                        "references": [
                            "https://github.com/Smart-Audit/LLM-SmartAudit",
                            issue.get("reference", ""),
                        ],
                    }
                    findings.append(finding)

            else:
                # Fallback: parse text output
                logger.warning("LLM-SmartAudit: No JSON found, using text parsing fallback")
                findings = self._parse_text_output(output, contract_path)

        except json.JSONDecodeError as e:
            logger.error(f"LLM-SmartAudit: JSON parse error - {e}")
            findings = self._parse_text_output(output, contract_path)
        except Exception as e:
            logger.error(f"LLM-SmartAudit: Parse error - {e}")

        logger.info(f"LLM-SmartAudit: Extracted {len(findings)} findings")
        return findings

    def _parse_text_output(self, output: str, contract_path: str) -> List[Dict[str, Any]]:
        """Fallback text parsing for non-JSON output."""
        findings: List[Dict[str, Any]] = []

        # Look for common patterns in text output
        patterns = {
            "best practice": ("MEDIUM", "best_practice_violation"),
            "code smell": ("LOW", "code_smell"),
            "semantic issue": ("HIGH", "semantic_issue"),
            "maintainability": ("LOW", "maintainability_issue"),
            "readability": ("LOW", "readability_issue"),
            "design pattern": ("MEDIUM", "design_pattern_issue"),
        }

        lines = output.split("\n")
        for _i, line in enumerate(lines):
            for pattern, (severity, category) in patterns.items():
                if pattern.lower() in line.lower():
                    findings.append(
                        {
                            "id": f"llmsmartaudit-text-{len(findings)+1}",
                            "title": f"LLM-detected: {pattern.title()}",
                            "description": line.strip(),
                            "severity": severity,
                            "confidence": 0.65,  # Lower confidence for text parsing
                            "category": category,
                            "location": {"file": contract_path},
                            "recommendation": f"Review potential {pattern} detected by LLM",
                            "references": ["https://github.com/Smart-Audit/LLM-SmartAudit"],
                        }
                    )

        return findings

    def _get_cache_key(self, contract_code: str, model: str) -> str:
        """Generate cache key from contract code, model, and RAG mode."""
        rag_mode = "embedding" if self._use_rag and self._embedding_rag else "keyword"
        return hashlib.sha256(
            f"{model}:{rag_mode}:{KNOWLEDGE_BASE_VERSION}:{contract_code}".encode()
        ).hexdigest()

    # _get_cached_result / _cache_result are provided by LLMCacheMixin.


__all__ = ["LLMSmartAuditAdapter"]
