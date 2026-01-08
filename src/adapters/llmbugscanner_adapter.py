"""
LLMBugScanner - Multi-LLM Ensemble Adapter for Smart Contract Vulnerability Detection.

Based on: "LLMBugScanner: Leveraging LLM Ensembles for Accurate Smart Contract Bug Detection"
(Georgia Tech, December 2025)

Key Features:
- Multi-LLM ensemble using local Ollama models
- Cross-validation between models for false positive reduction
- Consensus-based confidence scoring
- State-of-the-art for logic bug detection

The ensemble approach uses multiple models and aggregates their findings:
1. Primary: deepseek-coder (specialized for code analysis)
2. Secondary: codellama (general code understanding)
3. Tertiary: mistral (reasoning and verification)

Runs entirely locally via Ollama (DPGA-compliant, no API keys).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-15
"""

import hashlib
import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """Configuration for an ensemble member model."""

    name: str
    weight: float  # Voting weight (0.0-1.0)
    timeout: int  # Seconds
    specialization: str  # What this model is best at


# Default ensemble configuration (local Ollama models)
DEFAULT_ENSEMBLE = [
    ModelConfig(name="deepseek-coder", weight=0.45, timeout=300, specialization="code_analysis"),
    ModelConfig(name="codellama", weight=0.35, timeout=300, specialization="code_understanding"),
    ModelConfig(name="mistral", weight=0.20, timeout=180, specialization="reasoning"),
]

# Vulnerability categories for consensus analysis
VULNERABILITY_CATEGORIES = {
    "reentrancy": ["reentrancy", "re-entrancy", "recursive call", "external call before state"],
    "access_control": ["access control", "authorization", "owner only", "permission", "admin"],
    "integer_overflow": ["overflow", "underflow", "integer", "arithmetic"],
    "unchecked_call": ["unchecked", "return value", "external call", "low-level call"],
    "denial_of_service": ["dos", "denial of service", "gas limit", "loop", "unbounded"],
    "front_running": ["front-run", "frontrun", "mev", "sandwich"],
    "flash_loan": ["flash loan", "flashloan", "price manipulation"],
    "oracle_manipulation": ["oracle", "price feed", "chainlink", "twap"],
    "logic_error": ["logic", "business logic", "incorrect", "wrong", "bug"],
    "timestamp_dependence": ["timestamp", "block.timestamp", "now"],
    "tx_origin": ["tx.origin", "phishing"],
    "delegatecall": ["delegatecall", "proxy", "storage collision"],
}


class LLMBugScannerAdapter(ToolAdapter):
    """
    Multi-LLM ensemble adapter for smart contract vulnerability detection.

    Uses multiple local Ollama models and cross-validates findings
    to achieve higher accuracy and reduce false positives.
    """

    def __init__(self, ensemble: Optional[List[ModelConfig]] = None):
        super().__init__()
        self._cache_dir = Path.home() / ".miesc" / "llmbugscanner_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ensemble = ensemble or DEFAULT_ENSEMBLE
        self._consensus_threshold = 0.5  # Minimum weighted consensus for a finding
        self._max_retries = 2
        self._available_models: Set[str] = set()

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="llmbugscanner",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (Based on Georgia Tech LLMBugScanner research)",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            # LLMBugScanner paper (Georgia Tech, Dec 2025)
            documentation="https://arxiv.org/abs/2512.02069",
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && "
                "ollama pull deepseek-coder && "
                "ollama pull codellama && "
                "ollama pull mistral"
            ),
            capabilities=[
                ToolCapability(
                    name="ensemble_analysis",
                    description="Multi-LLM ensemble vulnerability detection with cross-validation",
                    supported_languages=["solidity"],
                    detection_types=[
                        "logic_bugs",
                        "reentrancy",
                        "access_control",
                        "integer_overflow",
                        "unchecked_calls",
                        "denial_of_service",
                        "front_running",
                        "flash_loan_attacks",
                        "oracle_manipulation",
                    ],
                ),
                ToolCapability(
                    name="consensus_scoring",
                    description="Weighted consensus-based confidence scoring across models",
                    supported_languages=["solidity"],
                    detection_types=["false_positive_reduction"],
                ),
                ToolCapability(
                    name="cross_validation",
                    description="Cross-model validation for finding verification",
                    supported_languages=["solidity"],
                    detection_types=["finding_verification"],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama and at least one ensemble model is available."""
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, timeout=5, text=True)

            if result.returncode != 0:
                logger.warning("Ollama command failed")
                return ToolStatus.CONFIGURATION_ERROR

            # Check which ensemble models are available
            self._available_models.clear()
            for model in self._ensemble:
                if model.name in result.stdout:
                    self._available_models.add(model.name)

            if len(self._available_models) >= 1:
                logger.info(
                    f"LLMBugScanner: {len(self._available_models)} models available: "
                    f"{self._available_models}"
                )
                return ToolStatus.AVAILABLE
            else:
                logger.warning("No ensemble models found. Run: ollama pull deepseek-coder")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Ollama not installed. Install from https://ollama.com")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Ollama command timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Ollama availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze Solidity contract using multi-LLM ensemble.

        Args:
            contract_path: Path to the Solidity contract file
            **kwargs: Optional configuration (consensus_threshold, etc.)

        Returns:
            Analysis results with consensus-validated findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return self._error_result(
                start_time,
                "LLMBugScanner not available. Ensure Ollama is installed with at least one model.",
            )

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return self._error_result(start_time, f"Could not read contract: {contract_path}")

            # Check cache
            cache_key = self._get_cache_key(contract_code)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"LLMBugScanner: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Truncate if too long
            contract_code = self._truncate_code(contract_code)

            # Get available ensemble models
            active_ensemble = [m for m in self._ensemble if m.name in self._available_models]
            logger.info(f"LLMBugScanner: Running ensemble with {len(active_ensemble)} models")

            # STAGE 1: Run each model in parallel (simulated sequential for reliability)
            all_findings: Dict[str, List[Dict[str, Any]]] = {}
            model_results: Dict[str, Dict[str, Any]] = {}

            for model in active_ensemble:
                logger.info(f"LLMBugScanner: Analyzing with {model.name} ({model.specialization})")
                model_findings = self._analyze_with_model(contract_code, contract_path, model)
                all_findings[model.name] = model_findings
                model_results[model.name] = {
                    "findings_count": len(model_findings),
                    "weight": model.weight,
                    "specialization": model.specialization,
                }

            # STAGE 2: Consensus aggregation
            logger.info("LLMBugScanner: Aggregating findings with consensus voting")
            consensus_findings = self._aggregate_with_consensus(
                all_findings,
                active_ensemble,
                kwargs.get("consensus_threshold", self._consensus_threshold),
            )

            # STAGE 3: Cross-validation (verify high-severity findings)
            if kwargs.get("cross_validate", True):
                logger.info("LLMBugScanner: Cross-validating critical findings")
                consensus_findings = self._cross_validate_findings(
                    contract_code, consensus_findings, active_ensemble
                )

            # Build result
            result = {
                "tool": "llmbugscanner",
                "version": "1.0.0",
                "status": "success",
                "findings": consensus_findings,
                "metadata": {
                    "ensemble_size": len(active_ensemble),
                    "models_used": [m.name for m in active_ensemble],
                    "model_results": model_results,
                    "total_raw_findings": sum(len(f) for f in all_findings.values()),
                    "consensus_findings": len(consensus_findings),
                    "consensus_threshold": self._consensus_threshold,
                    "sovereign": True,
                    "dpga_compliant": True,
                },
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"LLMBugScanner analysis error: {e}", exc_info=True)
            return self._error_result(start_time, str(e))

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the given contract."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 900,  # 15 minutes for ensemble
            "consensus_threshold": 0.5,
            "cross_validate": True,
            "max_retries": 2,
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _error_result(self, start_time: float, error: str) -> Dict[str, Any]:
        """Create error result."""
        return {
            "tool": "llmbugscanner",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error,
        }

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file content."""
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _truncate_code(self, code: str, max_chars: int = 24000) -> str:
        """Truncate code to fit within context window."""
        if len(code) <= max_chars:
            return code
        logger.warning(f"Contract truncated from {len(code)} to {max_chars} chars")
        return code[:max_chars] + "\n// ... (truncated for analysis)"

    def _analyze_with_model(
        self, contract_code: str, contract_path: str, model: ModelConfig
    ) -> List[Dict[str, Any]]:
        """Run analysis with a single model."""
        prompt = self._generate_analysis_prompt(contract_code, model.specialization)

        for attempt in range(1, self._max_retries + 1):
            try:
                result = subprocess.run(
                    ["ollama", "run", model.name, prompt],
                    capture_output=True,
                    timeout=model.timeout,
                    text=True,
                )

                if result.returncode == 0 and result.stdout:
                    findings = self._parse_llm_response(
                        result.stdout.strip(), contract_path, model.name
                    )
                    logger.info(f"Model {model.name}: {len(findings)} findings")
                    return findings
                else:
                    logger.warning(
                        f"{model.name} failed (attempt {attempt}): {result.stderr[:200]}"
                    )

            except subprocess.TimeoutExpired:
                logger.warning(f"{model.name} timeout (attempt {attempt})")
            except Exception as e:
                logger.error(f"{model.name} error (attempt {attempt}): {e}")

            time.sleep(1)

        return []

    def _generate_analysis_prompt(self, contract_code: str, specialization: str) -> str:
        """Generate analysis prompt tailored to model specialization."""
        base_prompt = f"""You are an expert smart contract security auditor.

SMART CONTRACT:
```solidity
{contract_code}
```

"""
        # Add specialization-specific instructions
        if specialization == "code_analysis":
            base_prompt += """Focus on:
1. Reentrancy vulnerabilities (external calls before state changes)
2. Integer overflow/underflow (without SafeMath)
3. Unchecked return values from external calls
4. Access control issues (missing modifiers, incorrect permissions)
5. Logic bugs in business logic

"""
        elif specialization == "code_understanding":
            base_prompt += """Focus on:
1. Design pattern issues (antipatterns)
2. State machine vulnerabilities
3. Front-running vulnerabilities
4. Flash loan attack vectors
5. Oracle manipulation risks

"""
        elif specialization == "reasoning":
            base_prompt += """Focus on:
1. Complex logic bugs
2. Edge cases and boundary conditions
3. Economic attack vectors
4. Token economics issues
5. Governance vulnerabilities

"""

        base_prompt += """OUTPUT FORMAT (JSON only):
{
  "findings": [
    {
      "type": "vulnerability_category",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "title": "Short descriptive title",
      "description": "Detailed description of the issue",
      "location": "Function name or line reference",
      "impact": "What could happen if exploited",
      "recommendation": "How to fix"
    }
  ]
}

Respond with ONLY the JSON, no additional text."""

        return base_prompt

    def _parse_llm_response(
        self, llm_response: str, contract_path: str, model_name: str
    ) -> List[Dict[str, Any]]:
        """Parse LLM response to extract findings."""
        findings = []

        try:
            # Extract JSON from response
            json_start = llm_response.find("{")
            json_end = llm_response.rfind("}") + 1

            if json_start == -1 or json_end == 0:
                return []

            json_str = llm_response[json_start:json_end]
            parsed = json.loads(json_str)

            for idx, finding in enumerate(parsed.get("findings", [])):
                normalized = {
                    "id": f"llmbugscanner-{model_name}-{idx+1}",
                    "title": finding.get("title", "Detected issue"),
                    "description": finding.get("description", ""),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "confidence": 0.7,  # Base confidence, will be adjusted by consensus
                    "category": self._categorize_finding(finding),
                    "location": {"file": contract_path, "details": finding.get("location", "")},
                    "impact": finding.get("impact", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "source_model": model_name,
                    "raw_type": finding.get("type", ""),
                }
                findings.append(normalized)

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error from {model_name}: {e}")
        except Exception as e:
            logger.error(f"Error parsing {model_name} response: {e}")

        return findings

    def _categorize_finding(self, finding: Dict[str, Any]) -> str:
        """Categorize finding based on type and description."""
        text = (
            f"{finding.get('type', '')} {finding.get('title', '')} "
            f"{finding.get('description', '')}"
        ).lower()

        for category, keywords in VULNERABILITY_CATEGORIES.items():
            if any(kw in text for kw in keywords):
                return category

        return "other"

    def _aggregate_with_consensus(
        self,
        all_findings: Dict[str, List[Dict[str, Any]]],
        ensemble: List[ModelConfig],
        threshold: float,
    ) -> List[Dict[str, Any]]:
        """Aggregate findings using weighted consensus voting."""
        # Build weight map
        weights = {m.name: m.weight for m in ensemble}
        total_weight = sum(weights.values())

        # Group findings by category + severity + similar location
        finding_groups: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}

        for model_name, findings in all_findings.items():
            for finding in findings:
                key = self._get_finding_key(finding)
                if key not in finding_groups:
                    finding_groups[key] = []
                finding_groups[key].append((model_name, finding))

        # Calculate consensus for each group
        consensus_findings = []
        for _key, group in finding_groups.items():
            # Calculate weighted vote
            models_agreeing = {model_name for model_name, _ in group}
            weighted_vote = sum(weights.get(m, 0) for m in models_agreeing)
            consensus_score = weighted_vote / total_weight if total_weight > 0 else 0

            if consensus_score >= threshold:
                # Merge findings from group
                merged = self._merge_findings(group, consensus_score)
                consensus_findings.append(merged)

        # Sort by severity and confidence
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        consensus_findings.sort(
            key=lambda f: (severity_order.get(f.get("severity", "LOW"), 4), -f.get("confidence", 0))
        )

        return consensus_findings

    def _get_finding_key(self, finding: Dict[str, Any]) -> str:
        """Generate a key for grouping similar findings."""
        category = finding.get("category", "unknown")
        severity = finding.get("severity", "MEDIUM")
        location = finding.get("location", {}).get("details", "")[:50]
        return f"{category}:{severity}:{location}"

    def _merge_findings(
        self, group: List[Tuple[str, Dict[str, Any]]], consensus_score: float
    ) -> Dict[str, Any]:
        """Merge multiple findings from different models into one."""
        # Take the most detailed finding as base
        group.sort(key=lambda x: len(x[1].get("description", "")), reverse=True)
        _, base = group[0]

        models = [model for model, _ in group]

        merged = base.copy()
        merged["id"] = f"llmbugscanner-consensus-{hash(tuple(models)) % 10000}"
        merged["confidence"] = min(0.95, 0.5 + (consensus_score * 0.5))  # Scale confidence
        merged["consensus_score"] = round(consensus_score, 3)
        merged["models_agreeing"] = models
        merged["agreement_count"] = len(models)

        return merged

    def _cross_validate_findings(
        self, contract_code: str, findings: List[Dict[str, Any]], ensemble: List[ModelConfig]
    ) -> List[Dict[str, Any]]:
        """Cross-validate critical/high severity findings."""
        validated = []

        for finding in findings:
            severity = finding.get("severity", "MEDIUM").upper()

            # Only cross-validate critical/high findings
            if severity in ["CRITICAL", "HIGH"] and finding.get("agreement_count", 1) == 1:
                # Single-model finding - verify with another model
                is_valid = self._verify_finding(contract_code, finding, ensemble)
                if is_valid:
                    finding["cross_validated"] = True
                    validated.append(finding)
                else:
                    logger.info(f"Cross-validation rejected: {finding.get('title')}")
            else:
                validated.append(finding)

        return validated

    def _verify_finding(
        self, contract_code: str, finding: Dict[str, Any], ensemble: List[ModelConfig]
    ) -> bool:
        """Verify a finding using a different model."""
        # Find a model that didn't originally report this finding
        source_model = finding.get("source_model", "")
        verifier = None

        for model in ensemble:
            if model.name != source_model and model.name in self._available_models:
                verifier = model
                break

        if not verifier:
            return True  # No other model available, keep finding

        prompt = f"""You are verifying a security finding in a smart contract.

FINDING TO VERIFY:
- Title: {finding.get('title')}
- Description: {finding.get('description')}
- Location: {finding.get('location', {}).get('details', 'N/A')}
- Severity: {finding.get('severity')}

CONTRACT CODE:
```solidity
{contract_code[:3000]}
```

Is this finding VALID (true vulnerability) or FALSE POSITIVE?
Respond with ONLY: VALID or FALSE_POSITIVE"""

        try:
            result = subprocess.run(
                ["ollama", "run", verifier.name, prompt], capture_output=True, timeout=60, text=True
            )

            if result.returncode == 0:
                response = result.stdout.strip().upper()
                return "VALID" in response or "TRUE" in response

        except Exception as e:
            logger.error(f"Cross-validation error: {e}")

        return True  # Conservative: keep on error

    def _get_cache_key(self, contract_code: str) -> str:
        """Generate cache key from contract code."""
        models_str = "_".join(sorted(self._available_models))
        return hashlib.sha256(f"{contract_code}{models_str}".encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if available."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > 86400:  # 24 hours
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
        except Exception as e:
            logger.error(f"Error writing cache: {e}")


__all__ = ["LLMBugScannerAdapter", "ModelConfig", "DEFAULT_ENSEMBLE"]
