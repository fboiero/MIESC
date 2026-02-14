"""
Local LLM adapter using Ollama with RAG enhancement and Verificator role.

Enhanced with:
- RAG (Retrieval-Augmented Generation) for ERC-20/721/1155 context
- Verificator role for fact-checking and false positive reduction
- Multi-stage pipeline: Generator → Verificator → Consensus

Based on: "SmartLLM: A Novel LLM-Assisted Verification Framework"
(arXiv:2502.13167, February 2025)

Uses deepseek-coder model for vulnerability pattern detection.
Runs entirely locally (no API keys, DPGA-compliant).

Ollama: https://ollama.com
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-13
"""

import hashlib
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.smartllm_rag_knowledge import (
    get_relevant_knowledge,
    get_vulnerability_context,
)

# LLM Security imports (v5.1.2+)
from src.security.prompt_sanitizer import (
    InjectionRiskLevel,
    detect_prompt_injection,
    sanitize_code_for_prompt,
)
from src.security.llm_output_validator import (
    AnalysisResponse,
    VulnerabilityFinding,
    safe_parse_llm_json,
    validate_vulnerability_finding,
)

# Try to import EmbeddingRAG (optional dependency)
try:
    from src.llm.embedding_rag import (
        EmbeddingRAG,
        get_context_for_finding,
        batch_get_context_for_findings,
    )
    _EMBEDDING_RAG_AVAILABLE = True
except ImportError:
    _EMBEDDING_RAG_AVAILABLE = False
    EmbeddingRAG = None
    get_context_for_finding = None
    batch_get_context_for_findings = None
from src.core.llm_config import (
    ROLE_GENERATOR,
    USE_CASE_CODE_ANALYSIS,
    get_generation_options,
    get_model,
    get_ollama_host,
    get_retry_config,
)
from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


class SmartLLMAdapter(ToolAdapter):
    """
    Ollama-based LLM adapter for local vulnerability analysis.

    Uses deepseek-coder model (8K context). Results cached for 24h.
    Retries on failure (max 3 attempts). No API keys required.
    """

    def __init__(self):
        super().__init__()
        self._cache_dir = Path.home() / ".miesc" / "smartllm_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Load configuration from centralized config
        self._model = get_model(USE_CASE_CODE_ANALYSIS)
        self._ollama_host = get_ollama_host()
        retry_config = get_retry_config()
        self._max_retries = retry_config["attempts"]
        self._retry_delay = retry_config["delay"]

        # Generation options from config
        gen_options = get_generation_options(ROLE_GENERATOR)
        self._max_tokens = gen_options.get("num_ctx", 8192)

        self._use_rag = True  # Enable RAG by default
        self._use_verificator = True  # Enable verificator by default

        # Initialize EmbeddingRAG if available (ChromaDB + sentence-transformers)
        self._embedding_rag = None
        self._use_embedding_rag = False
        if _EMBEDDING_RAG_AVAILABLE:
            try:
                self._embedding_rag = EmbeddingRAG()
                self._use_embedding_rag = True
                logger.info("EmbeddingRAG (ChromaDB) enabled for semantic search")
            except Exception as e:
                logger.warning(f"EmbeddingRAG initialization failed: {e}, using keyword RAG")

        logger.info(
            f"SmartLLMAdapter initialized with model={self._model}, host={self._ollama_host}"
        )

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="smartllm",
            version="3.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (DPGA-compliant sovereign LLM adapter with RAG)",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            documentation="https://github.com/ollama/ollama/blob/main/README.md",
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && " "ollama pull deepseek-coder"
            ),
            capabilities=[
                ToolCapability(
                    name="ai_analysis",
                    description=(
                        "Local LLM-powered analysis using Ollama with RAG "
                        "enhancement (100% sovereign, DPGA-compliant)"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "logic_bugs",
                        "design_issues",
                        "security_patterns",
                        "access_control",
                        "reentrancy",
                        "integer_overflow",
                        "unchecked_calls",
                        "best_practices",
                    ],
                ),
                ToolCapability(
                    name="rag_enhanced",
                    description=(
                        "Retrieval-Augmented Generation with " "ERC-20/721/1155 knowledge base"
                    ),
                    supported_languages=["solidity"],
                    detection_types=["erc_violations", "standard_compliance"],
                ),
                ToolCapability(
                    name="verificator",
                    description=(
                        "Multi-stage analysis with Generator -> "
                        "Verificator -> Consensus pipeline"
                    ),
                    supported_languages=["solidity"],
                    detection_types=["false_positive_reduction", "fact_checking"],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is running and accessible via HTTP API."""
        import urllib.request
        import urllib.error

        try:
            ollama_host = get_ollama_host()
            tags_url = f"{ollama_host}/api/tags"

            req = urllib.request.Request(tags_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    # Check if we have a suitable model
                    data = json.loads(resp.read().decode())
                    models = [m.get("name", "") for m in data.get("models", [])]
                    model_names = " ".join(models).lower()

                    if "deepseek-coder" in model_names or "codellama" in model_names:
                        logger.info(f"SmartLLM: Ollama available at {ollama_host}")
                        return ToolStatus.AVAILABLE
                    else:
                        logger.warning(
                            f"SmartLLM: No suitable model found. Run: ollama pull {self._model}"
                        )
                        return ToolStatus.CONFIGURATION_ERROR
                else:
                    logger.warning(f"SmartLLM: Ollama returned status {resp.status}")
                    return ToolStatus.CONFIGURATION_ERROR

        except urllib.error.URLError as e:
            logger.info(f"SmartLLM: Ollama not reachable: {e}")
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error(f"SmartLLM: Error checking Ollama availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze Solidity contract using local Ollama LLM.

        Args:
            contract_path: Path to the Solidity contract file
            **kwargs: Optional configuration overrides

        Returns:
            Analysis results with findings from LLM
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "smartllm",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": (
                    "SmartLLM (Ollama) not available. Ensure Ollama is "
                    "installed and deepseek-coder model is pulled."
                ),
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "smartllm",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract file: {contract_path}",
                }

            # Check cache
            cache_key = self._get_cache_key(contract_code)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"SmartLLM: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Smart truncation for very large contracts (>50K chars)
            # Smaller contracts handled dynamically in prompt generation
            if len(contract_code) > 50000:
                contract_code = self._truncate_code_smart(contract_code, 50000)

            # STAGE 1: Generator - Initial vulnerability detection with RAG
            logger.info("SmartLLM Stage 1/3: Generator (RAG-enhanced)")
            generator_prompt = self._generate_analysis_prompt(contract_code)
            generator_response = self._call_ollama_with_retry(generator_prompt)

            if not generator_response:
                return {
                    "tool": "smartllm",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": "Failed to get response from Ollama LLM (Generator stage)",
                }

            # Parse initial findings
            initial_findings = self._parse_llm_response(generator_response, contract_path)

            # STAGE 2: Verificator - Fact-checking and false positive reduction
            verified_findings = initial_findings
            if self._use_verificator and initial_findings:
                logger.info(
                    f"SmartLLM Stage 2/3: Verificator (checking {len(initial_findings)} findings)"
                )
                verified_findings = self._verificator_stage(contract_code, initial_findings)

            # STAGE 3: Consensus - Final validation
            logger.info(
                f"SmartLLM Stage 3/3: Consensus ({len(verified_findings)} findings confirmed)"
            )
            final_findings = verified_findings

            # Build result
            result = {
                "tool": "smartllm",
                "version": "3.0.0",
                "status": "success",
                "findings": final_findings,
                "metadata": {
                    "model": self._model,
                    "prompt_tokens": len(generator_prompt.split()),  # Approximate
                    "sovereign": True,
                    "dpga_compliant": True,
                    "rag_enhanced": self._use_rag,
                    "verificator_enabled": self._use_verificator,
                    "initial_findings": len(initial_findings),
                    "verified_findings": len(verified_findings),
                    "false_positives_removed": len(initial_findings) - len(verified_findings),
                },
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"SmartLLM analysis error: {e}", exc_info=True)
            return {
                "tool": "smartllm",
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
        """Check if this adapter can analyze the given contract."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 600,
            "model": "deepseek-coder",
            "max_tokens": 8000,
            "temperature": 0.1,  # Low temperature for precise analysis
            "max_retries": 3,
            "retry_delay": 2,
        }

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

    def _truncate_code(self, code: str, max_tokens: int) -> str:
        """Truncate code to fit within context window (approximate token limit)."""
        # Rough approximation: 1 token ≈ 4 characters
        max_chars = max_tokens * 4
        if len(code) <= max_chars:
            return code

        logger.warning(f"Contract truncated from {len(code)} to {max_chars} chars")
        return code[:max_chars] + "\n// ... (truncated for analysis)"

    def _truncate_code_smart(self, code: str, max_chars: int) -> str:
        """
        Smart code truncation that prioritizes security-critical functions.

        Strategy:
        1. Always include contract header (imports, state variables)
        2. Prioritize functions with security patterns (external calls, admin, etc.)
        3. Include remaining functions in order up to limit
        """
        import re

        if len(code) <= max_chars:
            return code

        # Extract contract structure
        lines = code.split('\n')

        # Phase 1: Always include header (first ~30 lines or until first function)
        header_end = 0
        for i, line in enumerate(lines):
            if 'function ' in line or 'modifier ' in line:
                header_end = i
                break
            header_end = i + 1

        header = '\n'.join(lines[:header_end])

        # Phase 2: Extract and prioritize functions
        function_pattern = re.compile(
            r'(function\s+\w+[^{]*\{)',
            re.MULTILINE
        )

        # Simple function extraction (brace counting)
        functions = []
        current_func = []
        brace_count = 0
        in_function = False

        for line in lines[header_end:]:
            if 'function ' in line and brace_count == 0:
                if current_func:
                    functions.append('\n'.join(current_func))
                current_func = [line]
                in_function = True
                brace_count = line.count('{') - line.count('}')
            elif in_function:
                current_func.append(line)
                brace_count += line.count('{') - line.count('}')
                if brace_count <= 0:
                    functions.append('\n'.join(current_func))
                    current_func = []
                    in_function = False
                    brace_count = 0

        if current_func:
            functions.append('\n'.join(current_func))

        # Score functions by security criticality
        def score_function(func_code: str) -> int:
            score = 0
            func_lower = func_code.lower()
            # High priority: external calls (reentrancy risk)
            if '.call{' in func_code or '.call(' in func_code:
                score += 100
            if '.transfer(' in func_code:
                score += 80
            if 'delegatecall' in func_lower:
                score += 90
            # High priority: admin/owner functions
            if 'onlyowner' in func_lower or 'admin' in func_lower:
                score += 70
            if 'selfdestruct' in func_lower:
                score += 100
            # Medium priority: value handling
            if 'payable' in func_lower:
                score += 50
            if 'withdraw' in func_lower or 'deposit' in func_lower:
                score += 60
            # DeFi patterns
            if any(p in func_lower for p in ['swap', 'borrow', 'lend', 'liquidat', 'price']):
                score += 75
            return score

        # Sort functions by score (highest first)
        scored_functions = [(score_function(f), f) for f in functions]
        scored_functions.sort(key=lambda x: -x[0])

        # Build result within limit
        result_parts = [header]
        current_len = len(header)
        included_count = 0

        for score, func in scored_functions:
            func_with_separator = f"\n\n{func}"
            if current_len + len(func_with_separator) <= max_chars - 50:  # Reserve 50 for truncation note
                result_parts.append(func_with_separator)
                current_len += len(func_with_separator)
                included_count += 1

        if included_count < len(functions):
            omitted = len(functions) - included_count
            result_parts.append(f"\n\n// ... ({omitted} functions omitted, {len(functions)} total)")
            logger.info(f"Smart truncation: included {included_count}/{len(functions)} functions (prioritized by security risk)")

        return ''.join(result_parts)

    def _extract_rag_query(self, contract_code: str, patterns: dict) -> str:
        """
        Extract optimized query for RAG search based on detected patterns.

        Instead of raw code, creates semantic query from:
        - Function signatures with risky patterns
        - Detected vulnerability indicators
        """
        query_parts = []

        # Add pattern-based query terms
        if patterns.get("has_external_calls") or patterns.get("has_state_after_call"):
            query_parts.append("reentrancy external call state update vulnerability")
        if patterns.get("has_delegatecall"):
            query_parts.append("delegatecall proxy storage collision")
        if patterns.get("has_price_oracle"):
            query_parts.append("oracle manipulation price feed attack")
        if patterns.get("has_amm_integration"):
            query_parts.append("flash loan AMM spot price manipulation")
        if patterns.get("has_lending_logic"):
            query_parts.append("lending collateral liquidation attack")
        if patterns.get("has_admin_functions"):
            query_parts.append("access control owner privilege escalation")
        if patterns.get("has_selfdestruct"):
            query_parts.append("selfdestruct arbitrary destruction")

        # Extract function signatures for context
        import re
        func_sigs = re.findall(r'function\s+(\w+)\s*\([^)]*\)', contract_code)
        if func_sigs:
            # Focus on suspicious function names
            suspicious = [f for f in func_sigs if any(
                kw in f.lower() for kw in ['withdraw', 'transfer', 'admin', 'owner', 'mint', 'burn', 'swap', 'borrow']
            )]
            if suspicious:
                query_parts.append(f"security analysis of {' '.join(suspicious[:5])}")

        # Default query if no patterns
        if not query_parts:
            query_parts.append("smart contract security vulnerability analysis")

        return " ".join(query_parts)

    def _generate_analysis_prompt(self, contract_code: str) -> str:
        """Generate RAG-enhanced analysis prompt for Ollama LLM.

        Uses structured prompt engineering with:
        - Code pattern detection first (analyze what the code ACTUALLY does)
        - RAG context for vulnerability pattern matching (keyword or embedding-based)
        - Specific SWC-based vulnerability checks

        Context window optimization (v5.1.0):
        - Smart code truncation prioritizes security-critical functions
        - Optimized RAG query based on detected patterns
        - Dynamic context allocation (more space for complex contracts)
        """
        # Pre-analyze code for key patterns
        code_patterns = self._detect_code_patterns(contract_code)

        # Get relevant knowledge from RAG knowledge base
        rag_context = ""
        if self._use_rag:
            if self._use_embedding_rag and self._embedding_rag:
                # Use ChromaDB embedding-based RAG for semantic search
                try:
                    # Use optimized query instead of raw code
                    rag_query = self._extract_rag_query(contract_code, code_patterns)
                    results = self._embedding_rag.search(
                        query=rag_query,
                        n_results=5
                    )
                    rag_parts = []
                    for r in results:
                        rag_parts.append(
                            f"**{r.document.title}** ({r.document.swc_id or 'Pattern'})\n"
                            f"- Severity: {r.document.severity}\n"
                            f"- {r.document.description[:200]}...\n"
                            f"- Attack: {r.document.attack_scenario[:150]}..."
                        )
                    rag_context = "\n\n".join(rag_parts)
                    logger.debug(f"EmbeddingRAG query: {rag_query[:100]}...")
                    logger.debug(f"EmbeddingRAG returned {len(results)} results")
                except Exception as e:
                    logger.warning(f"EmbeddingRAG search failed: {e}, falling back to keyword RAG")
                    rag_context = get_relevant_knowledge(contract_code)
            else:
                # Fallback to keyword-based RAG
                rag_context = get_relevant_knowledge(contract_code)

        # Get focus areas based on patterns (already computed)
        focus_areas = self._get_focus_areas(code_patterns)

        # Context window optimization: allocate space based on content
        # Total context ~8K tokens (~32K chars), reserve:
        # - ~2K chars for prompt template
        # - ~3K chars for RAG context
        # - ~27K chars for code (or less if smaller)
        max_code_chars = 27000
        if len(contract_code) > max_code_chars:
            # Use smart truncation for large contracts
            contract_code = self._truncate_code_smart(contract_code, max_code_chars)

        # SECURITY: Detect and log prompt injection attempts (v5.1.2+)
        injection_result = detect_prompt_injection(contract_code)
        if injection_result.risk_level in (InjectionRiskLevel.HIGH, InjectionRiskLevel.CRITICAL):
            logger.warning(
                f"Prompt injection detected in contract code: "
                f"risk={injection_result.risk_level.value}, "
                f"patterns={injection_result.patterns_found}"
            )

        # SECURITY: Sanitize contract code before embedding in prompt (v5.1.2+)
        # Uses XML-style tags to clearly separate code from instructions
        safe_code = sanitize_code_for_prompt(
            contract_code,
            max_length=max_code_chars,
            wrap_in_tags=True,
            tag_name="solidity-contract"
        )

        prompt = f"""You are a smart contract security auditor. Find REAL vulnerabilities in this code.

RULES:
- Only report vulnerabilities that EXIST in this code
- Include SWC ID and attack scenario for critical findings
- Output valid JSON only
- IMPORTANT: Analyze ONLY the code within the <solidity-contract> tags below

CONTRACT:
{safe_code}

DETECTED PATTERNS:
{focus_areas}
"""

        # Add RAG context if available (dynamic allocation)
        if rag_context:
            # More RAG context for smaller contracts, less for larger
            rag_chars = min(4000, max(2000, 32000 - len(contract_code) - 2000))
            prompt += f"""
VULNERABILITY PATTERNS (from knowledge base):
{rag_context[:rag_chars]}
"""

        prompt += """
ANALYZE FOR:
1. Reentrancy (SWC-107): external call before state update
2. Access Control (SWC-105): missing modifiers on sensitive functions
3. Unchecked Returns (SWC-104): ignored return values
4. Oracle Manipulation: spot prices without TWAP/Chainlink
5. Precision Loss: division before multiplication

OUTPUT (JSON only):
```json
{"findings": [{"type": "reentrancy", "severity": "CRITICAL", "title": "...", "description": "...", "location": "function:line", "swc_id": "SWC-107", "attack_scenario": "...", "remediation": "..."}]}
```"""

        return prompt

    def _detect_code_patterns(self, code: str) -> dict:
        """Detect key patterns in code to focus LLM analysis."""
        patterns = {
            "has_external_calls": False,
            "has_state_after_call": False,
            "has_transfer": False,
            "has_delegatecall": False,
            "has_selfdestruct": False,
            "has_mapping": False,
            "has_payable": False,
            "solidity_version": "unknown",
            # DeFi patterns
            "has_price_oracle": False,
            "has_amm_integration": False,
            "has_lending_logic": False,
            "has_division": False,
            "has_admin_functions": False,
        }

        code_lower = code.lower()

        # Check for external calls
        if ".call{" in code or ".call(" in code:
            patterns["has_external_calls"] = True
        if ".transfer(" in code:
            patterns["has_transfer"] = True
        if "delegatecall" in code_lower:
            patterns["has_delegatecall"] = True
        if "selfdestruct" in code_lower:
            patterns["has_selfdestruct"] = True
        if "mapping(" in code_lower:
            patterns["has_mapping"] = True
        if "payable" in code_lower:
            patterns["has_payable"] = True

        # DeFi pattern detection
        if any(p in code_lower for p in ["getreserves", "getprice", "latestrounddata", "oracle"]):
            patterns["has_price_oracle"] = True
        if any(p in code_lower for p in ["uniswap", "reserve0", "reserve1", "amm", "swap"]):
            patterns["has_amm_integration"] = True
        if any(p in code_lower for p in ["borrow", "lend", "collateral", "liquidat"]):
            patterns["has_lending_logic"] = True
        if "/" in code and any(p in code for p in ["1e18", "10**18", "1e6", "10**6"]):
            patterns["has_division"] = True
        if any(p in code_lower for p in ["onlyowner", "setowner", "admin", "emergency"]):
            patterns["has_admin_functions"] = True

        # Detect reentrancy pattern: external call before state update
        # Simple heuristic: if we see .call{ before -= or = on a mapping
        call_pos = code.find(".call{")
        if call_pos == -1:
            call_pos = code.find(".call(")

        if call_pos > 0:
            # Check if there's a state update after the call
            after_call = code[call_pos:]
            if "-=" in after_call or ("+=" in after_call and "balances" in after_call.lower()):
                patterns["has_state_after_call"] = True

        # Extract Solidity version
        import re

        version_match = re.search(r"pragma solidity [\^~]?(\d+\.\d+\.\d+)", code)
        if version_match:
            patterns["solidity_version"] = version_match.group(1)

        return patterns

    def _get_focus_areas(self, patterns: dict) -> str:
        """Generate focus areas based on detected patterns."""
        focus = []

        if patterns.get("has_external_calls"):
            focus.append("- EXTERNAL CALLS DETECTED: Check for reentrancy (SWC-107)")
        if patterns.get("has_state_after_call"):
            focus.append(
                "- WARNING: State update AFTER external call detected - likely REENTRANCY!"
            )
        if patterns.get("has_delegatecall"):
            focus.append("- DELEGATECALL DETECTED: Check for storage collision (SWC-112)")
        if patterns.get("has_selfdestruct"):
            focus.append("- SELFDESTRUCT DETECTED: Check for unauthorized destruction (SWC-106)")
        if patterns.get("has_payable"):
            focus.append("- PAYABLE FUNCTIONS: Check for proper fund handling")
        if patterns.get("has_mapping"):
            focus.append("- MAPPINGS DETECTED: Check for balance manipulation vulnerabilities")

        # DeFi-specific focus areas
        if patterns.get("has_price_oracle"):
            focus.append("- PRICE ORACLE DETECTED: Check for oracle manipulation, stale prices")
        if patterns.get("has_amm_integration"):
            focus.append("- AMM INTEGRATION DETECTED: Check for flash loan attacks, spot price manipulation")
        if patterns.get("has_lending_logic"):
            focus.append("- LENDING LOGIC DETECTED: Check for liquidation vulnerabilities, collateral manipulation")
        if patterns.get("has_division"):
            focus.append("- DIVISION OPERATIONS: Check for precision loss (divide before multiply)")
        if patterns.get("has_admin_functions"):
            focus.append("- ADMIN FUNCTIONS DETECTED: Check for missing timelocks, zero address validation")

        version = patterns.get("solidity_version", "unknown")
        if version != "unknown":
            try:
                major, minor, patch = version.split(".")
                if int(minor) < 8:
                    focus.append(
                        f"- SOLIDITY {version}: Check for integer overflow/underflow (SWC-101)"
                    )
            except ValueError:
                pass  # Invalid version format

        if not focus:
            focus.append(
                "- Standard security review: access control, input validation, logic errors"
            )

        return "\n".join(focus)

    def _call_ollama_with_retry(self, prompt: str) -> Optional[str]:
        """Call Ollama HTTP API with retry logic."""
        import urllib.request
        import urllib.error

        generate_url = f"{self._ollama_host}/api/generate"

        payload = json.dumps({
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": self._max_tokens,
            }
        }).encode("utf-8")

        for attempt in range(1, self._max_retries + 1):
            try:
                logger.info(f"SmartLLM: Calling Ollama (attempt {attempt}/{self._max_retries})")

                req = urllib.request.Request(
                    generate_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )

                with urllib.request.urlopen(req, timeout=300) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        response = data.get("response", "")
                        if response:
                            return response.strip()
                        else:
                            logger.warning(f"Ollama returned empty response (attempt {attempt})")
                    else:
                        logger.warning(f"Ollama returned status {resp.status} (attempt {attempt})")

            except urllib.error.URLError as e:
                logger.error(f"Ollama API error (attempt {attempt}): {e}")
            except Exception as e:
                logger.error(f"Ollama call error (attempt {attempt}): {e}")

            # Wait before retry
            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        return None

    def _parse_llm_response(self, llm_response: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse LLM response to extract findings with Pydantic validation (v5.1.2+).

        Uses structured validation to:
        - Ensure response format matches expected schema
        - Sanitize and validate all fields
        - Provide safe fallbacks for malformed data
        """
        findings = []

        try:
            # SECURITY: Use Pydantic validation for LLM output (v5.1.2+)
            validation_result = safe_parse_llm_json(llm_response, AnalysisResponse)

            if validation_result.is_valid and validation_result.data:
                # Successfully validated response
                validated_response = validation_result.data

                # Log any validation warnings
                if validation_result.has_warnings:
                    logger.warning(f"LLM output validation warnings: {validation_result.warnings}")

                # Process validated findings
                for idx, vuln in enumerate(validated_response.vulnerabilities):
                    # Build SWC reference URL if available
                    swc_id = vuln.swc_id or ""
                    swc_url = ""
                    if swc_id and "SWC-" in swc_id:
                        swc_num = swc_id.split("SWC-")[1].split()[0].split("(")[0].strip()
                        swc_url = f"https://swcregistry.io/docs/SWC-{swc_num}"

                    # Get remediation from validated fields
                    remediation = (
                        vuln.remediation
                        or vuln.fixed_code
                        or "Review and address the identified issue"
                    )

                    # Map severity to uppercase
                    severity = vuln.severity.upper() if vuln.severity else "MEDIUM"

                    normalized = {
                        "id": f"smartllm-{idx+1}",
                        "title": vuln.title,
                        "description": vuln.description,
                        "severity": severity,
                        "confidence": vuln.confidence,  # Validated 0-1 range
                        "category": vuln.type,
                        "location": {
                            "file": contract_path,
                            "details": f"{vuln.function or ''}" if vuln.function else "See full contract",
                        },
                        # Enhanced fields for security researchers
                        "swc_id": swc_id,
                        "swc_url": swc_url,
                        "attack_scenario": vuln.attack_scenario or "",
                        "vulnerable_code": vuln.vulnerable_code or "",
                        "remediation_code": remediation,
                        "testing_suggestion": "",
                        "real_world_reference": "",
                        "recommendation": remediation,
                        "references": [
                            "AI-powered analysis using Ollama + deepseek-coder",
                        ],
                    }
                    if swc_url:
                        normalized["references"].append(swc_url)

                    findings.append(normalized)

                logger.info(f"SmartLLM: Validated and parsed {len(findings)} findings")
                return findings

            # Validation failed - fall back to legacy parsing
            logger.warning(f"LLM output validation failed: {validation_result.errors}")

            # Strategy 1: Try direct JSON extraction (legacy)
            parsed = self._extract_json(llm_response)

            if not parsed:
                # Strategy 2: Try to repair common JSON issues
                parsed = self._repair_and_parse_json(llm_response)

            if not parsed:
                # Strategy 3: Extract findings using regex patterns
                parsed = self._extract_findings_regex(llm_response)

            if not parsed:
                logger.warning("Could not parse LLM response as JSON")
                # Return structured finding from raw text analysis
                return self._parse_raw_response(llm_response, contract_path)

            # Extract findings (legacy path)
            llm_findings = parsed.get("findings", [])
            if isinstance(parsed, list):
                llm_findings = parsed

            for idx, finding in enumerate(llm_findings):
                if not isinstance(finding, dict):
                    continue

                # SECURITY: Validate individual finding with Pydantic
                finding_result = validate_vulnerability_finding(finding)
                if finding_result.is_valid and finding_result.data:
                    validated = finding_result.data
                    swc_id = validated.swc_id or ""
                    swc_url = ""
                    if swc_id and "SWC-" in swc_id:
                        swc_num = swc_id.split("SWC-")[1].split()[0].split("(")[0].strip()
                        swc_url = f"https://swcregistry.io/docs/SWC-{swc_num}"

                    remediation = validated.remediation or "Review and address the identified issue"

                    normalized = {
                        "id": f"smartllm-{idx+1}",
                        "title": validated.title,
                        "description": validated.description,
                        "severity": validated.severity.upper(),
                        "confidence": validated.confidence,
                        "category": validated.type,
                        "location": {
                            "file": contract_path,
                            "details": validated.function or "See full contract",
                        },
                        "swc_id": swc_id,
                        "swc_url": swc_url,
                        "attack_scenario": validated.attack_scenario or "",
                        "vulnerable_code": validated.vulnerable_code or "",
                        "remediation_code": remediation,
                        "recommendation": remediation,
                        "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                    }
                    if swc_url:
                        normalized["references"].append(swc_url)
                    findings.append(normalized)
                else:
                    # Fall back to unvalidated parsing with reduced confidence
                    logger.debug(f"Finding {idx} validation failed, using fallback")
                    swc_id = finding.get("swc_id", "")
                    swc_url = ""
                    if swc_id and "SWC-" in swc_id:
                        swc_num = swc_id.split("SWC-")[1].split()[0].split("(")[0].strip()
                        swc_url = f"https://swcregistry.io/docs/SWC-{swc_num}"

                    remediation = (
                        finding.get("remediation")
                        or finding.get("remediation_code")
                        or "Review and address the identified issue"
                    )

                    normalized = {
                        "id": f"smartllm-{idx+1}",
                        "title": str(finding.get("title", "LLM-detected issue"))[:500],
                        "description": str(finding.get("description", ""))[:5000],
                        "severity": str(finding.get("severity", "MEDIUM")).upper()[:20],
                        "confidence": 0.5,  # Reduced confidence for unvalidated
                        "category": str(finding.get("type", "ai_detected_pattern"))[:200],
                        "location": {
                            "file": contract_path,
                            "details": str(finding.get("location", "See full contract"))[:500],
                        },
                        "swc_id": swc_id,
                        "swc_url": swc_url,
                        "attack_scenario": str(finding.get("attack_scenario", ""))[:2000],
                        "vulnerable_code": str(finding.get("vulnerable_code", ""))[:5000],
                        "remediation_code": str(remediation)[:2000],
                        "recommendation": str(remediation)[:2000],
                        "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                    }
                    if swc_url:
                        normalized["references"].append(swc_url)
                    findings.append(normalized)

            logger.info(f"SmartLLM: Parsed {len(findings)} findings from LLM response (legacy path)")

        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return self._parse_raw_response(llm_response, contract_path)

        return findings

    def _extract_json(self, text: str) -> Optional[Dict]:
        """Extract JSON object from text using multiple strategies."""
        import re

        # Strategy 1: Find JSON block between ```json and ```
        json_block_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if json_block_match:
            try:
                return json.loads(json_block_match.group(1))
            except json.JSONDecodeError:
                pass

        # Strategy 2: Find JSON starting with {"findings"
        findings_match = re.search(r'\{\s*"findings"\s*:', text)
        if findings_match:
            start = findings_match.start()
            # Find matching closing brace
            depth = 0
            for i, char in enumerate(text[start:]):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start : start + i + 1])
                        except json.JSONDecodeError:
                            break

        # Strategy 3: Simple extraction between first { and last }
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            try:
                return json.loads(text[json_start:json_end])
            except json.JSONDecodeError:
                pass

        return None

    def _repair_and_parse_json(self, text: str) -> Optional[Dict]:
        """Attempt to repair common JSON issues and parse."""
        import re

        # Find the JSON portion
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start == -1 or json_end <= json_start:
            return None

        json_str = text[json_start:json_end]

        # Repair common issues:
        # 1. Remove trailing commas before ] or }
        json_str = re.sub(r",\s*([}\]])", r"\1", json_str)

        # 2. Fix unescaped newlines in strings (common in code snippets)
        # Replace actual newlines in string values with \n
        def fix_string_newlines(match):
            content = match.group(1)
            # Escape actual newlines
            content = content.replace("\n", "\\n")
            content = content.replace("\r", "\\r")
            content = content.replace("\t", "\\t")
            return f'"{content}"'

        # This regex finds string values and fixes newlines
        # Simple approach: process line by line for key-value pairs
        lines = json_str.split("\n")
        fixed_lines = []
        in_string = False
        string_buffer = ""

        for line in lines:
            # Count quotes to track if we're in a string
            quote_count = line.count('"') - line.count('\\"')

            if in_string:
                string_buffer += "\\n" + line
                if quote_count % 2 == 1:
                    fixed_lines.append(string_buffer)
                    string_buffer = ""
                    in_string = False
            else:
                if quote_count % 2 == 1:
                    in_string = True
                    string_buffer = line
                else:
                    fixed_lines.append(line)

        if string_buffer:
            fixed_lines.append(string_buffer)

        json_str = "\n".join(fixed_lines)

        # 3. Try to parse
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # 4. More aggressive repair: extract just the findings array
        findings_match = re.search(r'"findings"\s*:\s*\[(.*?)\]', json_str, re.DOTALL)
        if findings_match:
            findings_str = findings_match.group(1)
            # Try to extract individual finding objects
            finding_objects = []
            depth = 0
            start = None
            for i, char in enumerate(findings_str):
                if char == "{":
                    if depth == 0:
                        start = i
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0 and start is not None:
                        obj_str = findings_str[start : i + 1]
                        # Clean the object string
                        obj_str = re.sub(r",\s*([}\]])", r"\1", obj_str)
                        try:
                            finding_objects.append(json.loads(obj_str))
                        except json.JSONDecodeError:
                            # Try minimal repair
                            try:
                                obj_str = obj_str.replace("\n", " ")
                                finding_objects.append(json.loads(obj_str))
                            except Exception:
                                pass
                        start = None

            if finding_objects:
                return {"findings": finding_objects}

        return None

    def _extract_findings_regex(self, text: str) -> Optional[Dict]:
        """Extract findings using regex patterns as last resort."""
        import re

        findings = []

        # Pattern to extract vulnerability mentions
        vuln_patterns = [
            (r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Rr]eentrancy[^\n]*)", "CRITICAL", "reentrancy"),
            (
                r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Aa]ccess\s+[Cc]ontrol[^\n]*)",
                "HIGH",
                "access_control",
            ),
            (
                r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Ii]nteger\s+[Oo]verflow[^\n]*)",
                "HIGH",
                "integer_overflow",
            ),
            (
                r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Uu]nchecked\s+[Cc]all[^\n]*)",
                "HIGH",
                "unchecked_call",
            ),
            (r"SWC-107[:\s]+([^\n]+)", "CRITICAL", "reentrancy"),
            (r"SWC-105[:\s]+([^\n]+)", "HIGH", "access_control"),
            (r"SWC-101[:\s]+([^\n]+)", "HIGH", "integer_overflow"),
        ]

        for pattern, severity, category in vuln_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 10:
                    findings.append(
                        {
                            "type": category,
                            "severity": severity,
                            "title": f"{category.replace('_', ' ').title()} Vulnerability",
                            "description": match.strip()[:500],
                        }
                    )

        # Deduplicate by category
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["severity"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        if unique_findings:
            return {"findings": unique_findings}

        return None

    def _parse_raw_response(self, llm_response: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse raw LLM response when JSON parsing fails."""
        findings = []

        # Check for reentrancy mentions
        text_lower = llm_response.lower()
        if "reentrancy" in text_lower or "reentrant" in text_lower or "swc-107" in text_lower:
            findings.append(
                {
                    "id": "smartllm-1",
                    "title": "Potential Reentrancy Vulnerability",
                    "description": (
                        "LLM analysis detected reentrancy-related " "patterns in the contract."
                    ),
                    "severity": "CRITICAL",
                    "confidence": 0.65,
                    "category": "reentrancy",
                    "swc_id": "SWC-107",
                    "swc_url": "https://swcregistry.io/docs/SWC-107",
                    "location": {"file": contract_path, "details": "See LLM analysis"},
                    "recommendation": (
                        "Apply checks-effects-interactions pattern. "
                        "Update state before external calls."
                    ),
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        if (
            "access control" in text_lower
            or "unauthorized" in text_lower
            or "swc-105" in text_lower
        ):
            findings.append(
                {
                    "id": f"smartllm-{len(findings)+1}",
                    "title": "Potential Access Control Issue",
                    "description": (
                        "LLM analysis detected access control " "patterns that may need review."
                    ),
                    "severity": "HIGH",
                    "confidence": 0.60,
                    "category": "access_control",
                    "swc_id": "SWC-105",
                    "swc_url": "https://swcregistry.io/docs/SWC-105",
                    "location": {"file": contract_path, "details": "See LLM analysis"},
                    "recommendation": "Review access control modifiers and function visibility.",
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        # If no patterns found, return raw analysis
        if not findings:
            findings.append(
                {
                    "id": "smartllm-raw",
                    "title": "LLM Analysis Result",
                    "description": llm_response[:1000],
                    "severity": "INFO",
                    "confidence": 0.5,
                    "category": "ai_analysis",
                    "location": {"file": contract_path},
                    "recommendation": "Review full LLM response for insights",
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        return findings

    def _verificator_stage(
        self, contract_code: str, initial_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Stage 2: Verificator - Fact-check findings and reduce false positives.

        Uses a separate LLM call to verify each finding against the contract
        code and RAG knowledge base. Filters out false positives.

        IMPORTANT: For CRITICAL severity findings (reentrancy, etc.), we are
        more conservative and default to keeping the finding unless explicitly
        marked as false positive with clear reasoning.

        Performance: Uses batch_get_context_for_findings to pre-fetch all RAG
        context in a single optimized call (50-75% faster than per-finding).

        Args:
            contract_code: Original contract source code
            initial_findings: Findings from Generator stage

        Returns:
            Verified findings (false positives removed)
        """
        verified_findings = []

        # Pre-fetch RAG context for all findings at once (batch optimization)
        preloaded_contexts: Dict[str, str] = {}
        if (
            self._use_embedding_rag
            and self._embedding_rag
            and batch_get_context_for_findings
            and initial_findings
        ):
            try:
                logger.debug(
                    f"Batch pre-fetching RAG context for {len(initial_findings)} findings"
                )
                preloaded_contexts = batch_get_context_for_findings(
                    initial_findings, contract_code[:1000]
                )
                logger.info(
                    f"Pre-loaded RAG context for {len(preloaded_contexts)} findings "
                    f"(batch optimization)"
                )
            except Exception as e:
                logger.debug(f"Batch RAG context failed, falling back to per-finding: {e}")
                preloaded_contexts = {}

        for finding in initial_findings:
            severity = finding.get("severity", "MEDIUM").upper()
            is_critical = severity in ("CRITICAL", "HIGH")
            finding_type = finding.get("category", finding.get("type", "")).lower()
            finding_title = finding.get("title", "").lower()
            finding_desc = finding.get("description", "").lower()
            combined_text = f"{finding_type} {finding_title} {finding_desc}"

            is_reentrancy = "reentrancy" in finding_type or "reentrant" in finding_type

            # DeFi vulnerabilities should be kept conservatively
            is_defi_vuln = any(kw in combined_text for kw in [
                "oracle", "price", "flash loan", "flashloan", "manipulation",
                "precision", "liquidat", "collateral", "timelock", "admin",
                "zero address", "address(0)", "same block", "same-block"
            ])

            # For known high-risk patterns, verify using code pattern detection
            if is_reentrancy:
                # Double-check reentrancy using pattern detection
                patterns = self._detect_code_patterns(contract_code)
                if patterns.get("has_external_calls") and patterns.get("has_state_after_call"):
                    # Pattern detection confirms reentrancy - keep finding
                    finding["verified"] = True
                    finding["verification_method"] = "pattern_detection"
                    finding["confidence"] = 0.90  # High confidence from pattern match
                    verified_findings.append(finding)
                    logger.info(
                        f"✓ Reentrancy CONFIRMED by pattern detection: {finding.get('title')}"
                    )
                    continue

            # Generate verificator prompt with pre-loaded RAG context
            finding_key = finding.get("title", finding.get("id", ""))
            preloaded_ctx = preloaded_contexts.get(finding_key)
            verificator_prompt = self._generate_verificator_prompt(
                contract_code, finding, preloaded_context=preloaded_ctx
            )

            # Call LLM for verification (single attempt, faster)
            try:
                logger.debug(f"Verificator: Checking finding '{finding.get('title')}'")

                result = subprocess.run(
                    ["ollama", "run", self._model, verificator_prompt],
                    capture_output=True,
                    timeout=60,  # Shorter timeout for verificator
                    text=True,
                )

                if result.returncode == 0 and result.stdout:
                    response = result.stdout.strip()
                    response_lower = response.lower()

                    # Parse chain-of-thought verificator response
                    # Look for explicit verdict markers first
                    if (
                        "verdict: confirmed" in response_lower
                        or "verdict:confirmed" in response_lower
                    ):
                        # Finding explicitly confirmed
                        finding["verified"] = True
                        finding["verification_reasoning"] = response[:500]
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.15, 0.95)
                        verified_findings.append(finding)
                        logger.info(f"✓ Finding confirmed with CoT: {finding.get('title')}")
                    elif (
                        "verdict: false_positive" in response_lower
                        or "verdict:false_positive" in response_lower
                    ):
                        # Explicit false positive - but for CRITICAL/HIGH or DeFi, require clear reasoning
                        if is_critical or is_defi_vuln:
                            # For important findings, keep with lower confidence
                            reason = "severity" if is_critical else "DeFi pattern"
                            finding["verified"] = False
                            finding["verification_note"] = (
                                f"Verificator marked FP but keeping due to {reason}"
                            )
                            finding["confidence"] = max(
                                finding.get("confidence", 0.75) - 0.20, 0.50
                            )
                            verified_findings.append(finding)
                            logger.warning(
                                f"Finding kept despite FP verdict ({reason}): "
                                f"{finding.get('title')}"
                            )
                        else:
                            logger.info(f"✗ False positive (CoT verified): {finding.get('title')}")
                    elif "confirmed" in response_lower and "false_positive" not in response_lower:
                        # Legacy format: implicit confirmation
                        finding["verified"] = True
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.1, 0.95)
                        verified_findings.append(finding)
                        logger.info(f"✓ Finding confirmed: {finding.get('title')}")
                    else:
                        # Ambiguous response - for CRITICAL/HIGH or DeFi vulns, keep; otherwise filter
                        if is_critical or is_defi_vuln:
                            finding["verified"] = False
                            reason = "severity" if is_critical else "DeFi vulnerability pattern"
                            finding["verification_note"] = (
                                f"Ambiguous verification - kept due to {reason}"
                            )
                            finding["confidence"] = max(
                                finding.get("confidence", 0.75) - 0.15, 0.50
                            )
                            verified_findings.append(finding)
                            logger.warning(
                                f"⚠ Finding kept (ambiguous, {reason}): {finding.get('title')}"
                            )
                        else:
                            logger.info(f"✗ False positive removed: {finding.get('title')}")
                else:
                    # Verificator failed - keep finding with lower confidence (conservative)
                    logger.warning("Verificator call failed, keeping finding conservatively")
                    finding["verified"] = False
                    finding["confidence"] = max(finding.get("confidence", 0.75) - 0.15, 0.4)
                    verified_findings.append(finding)

            except subprocess.TimeoutExpired:
                logger.warning("Verificator timeout, keeping finding conservatively")
                finding["verified"] = False
                verified_findings.append(finding)
            except Exception as e:
                logger.error(f"Verificator error: {e}")
                finding["verified"] = False
                verified_findings.append(finding)

        logger.info(
            f"Verificator results: {len(initial_findings)} → {len(verified_findings)} "
            f"({len(initial_findings) - len(verified_findings)} false positives removed)"
        )

        return verified_findings

    def _generate_verificator_prompt(
        self,
        contract_code: str,
        finding: Dict[str, Any],
        preloaded_context: Optional[str] = None,
    ) -> str:
        """
        Generate verificator prompt for fact-checking a finding.

        Uses chain-of-thought prompting to improve verification accuracy.
        Based on: Wei et al. (2022) "Chain-of-Thought Prompting Elicits
        Reasoning in Large Language Models" (arXiv:2201.11903)

        Args:
            contract_code: Contract source code
            finding: Finding to verify
            preloaded_context: Pre-fetched RAG context (for batch optimization)

        Returns:
            Verificator prompt with chain-of-thought structure
        """
        # Get vulnerability context from knowledge base
        vuln_type = finding.get("category", finding.get("type", ""))

        # Use pre-loaded context if available (batch optimization)
        vuln_context_str = ""
        vuln_mitigation = ""
        if preloaded_context:
            vuln_context_str = preloaded_context
            vuln_mitigation = "See context above for mitigation strategies."
        elif self._use_embedding_rag and self._embedding_rag and get_context_for_finding:
            try:
                # EmbeddingRAG returns a formatted string
                vuln_context_str = get_context_for_finding(finding, contract_code[:1000])
                vuln_mitigation = "See context above for mitigation strategies."
            except Exception as e:
                logger.debug(f"EmbeddingRAG context failed: {e}")
                vuln_dict = get_vulnerability_context(vuln_type)
                vuln_context_str = vuln_dict.get('description', 'No reference available')
                vuln_mitigation = vuln_dict.get('mitigation', 'N/A')
        else:
            vuln_dict = get_vulnerability_context(vuln_type)
            vuln_context_str = vuln_dict.get('description', 'No reference available')
            vuln_mitigation = vuln_dict.get('mitigation', 'N/A')

        # Get role-specific system prompt from config
        from src.core.llm_config import ROLE_VERIFICATOR, get_role_system_prompt

        system_prompt = get_role_system_prompt(ROLE_VERIFICATOR)

        return f"""{system_prompt}

TASK: Verify if the following security finding is a TRUE POSITIVE or FALSE POSITIVE.
Think step by step before giving your final verdict.

FINDING TO VERIFY:
- Type: {finding.get('type', 'N/A')}
- Title: {finding.get('title', 'N/A')}
- Description: {finding.get('description', 'N/A')}
- Location: {finding.get('location', {}).get('details', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}

VULNERABILITY REFERENCE (from SWC Registry):
{vuln_context_str}
Mitigation: {vuln_mitigation}

CONTRACT CODE:
```solidity
{contract_code[:2000]}
```

CHAIN-OF-THOUGHT ANALYSIS:
Analyze step by step:

STEP 1 - CODE LOCATION CHECK:
Does the reported location exist in the code? Is it correctly identified?

STEP 2 - VULNERABILITY PATTERN MATCH:
Does the code at this location match the vulnerability pattern described?
Compare against the SWC reference.

STEP 3 - CONTEXT ANALYSIS:
Consider the surrounding code context:
- Are there existing mitigations (checks-effects-interactions, reentrancy guards)?
- Does the control flow actually allow exploitation?
- Are the preconditions for exploitation actually reachable?

STEP 4 - FALSE POSITIVE INDICATORS:
Check for common false positive patterns:
- Safe math libraries in use
- Access control preventing exploitation
- State changes before external calls
- Trusted contract interactions only

STEP 5 - SEVERITY VALIDATION:
If the finding is valid, is the severity level appropriate?
Consider: exploitability, impact, likelihood.

FINAL VERDICT:
Based on your step-by-step analysis, conclude with exactly one of:
- "VERDICT: CONFIRMED" - The finding is a valid true positive
- "VERDICT: FALSE_POSITIVE" - The finding is incorrect or not exploitable

Your analysis:"""

    def _get_cache_key(self, contract_code: str) -> str:
        """Generate cache key from contract code."""
        return hashlib.sha256(contract_code.encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if available."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            # Check if cache is fresh (< 24 hours)
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > 86400:  # 24 hours
                logger.info(f"Cache expired for {cache_key}")
                cache_file.unlink()
                return None

            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Cached result for {cache_key}")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")


__all__ = ["SmartLLMAdapter"]
