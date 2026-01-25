"""
LLM Ensemble Detector for MIESC
================================

Ensemble voting with multiple LLMs for vulnerability detection.
Based on LLMBugScanner paper (2024): 60% top-5 detection rate.

Features:
- Multi-model ensemble voting
- Parallel model execution
- Confidence aggregation
- Vulnerability type consensus

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import asyncio
import json
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class VotingStrategy(Enum):
    """Voting strategies for ensemble."""
    MAJORITY = "majority"  # Finding valid if >= 50% models agree
    UNANIMOUS = "unanimous"  # All models must agree
    WEIGHTED = "weighted"  # Weighted by model expertise
    THRESHOLD = "threshold"  # At least N models must agree


@dataclass
class EnsembleFinding:
    """A finding validated by ensemble voting."""
    type: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    confidence: float
    votes: int
    total_models: int
    supporting_models: List[str]
    attack_vector: Optional[str] = None
    remediation: Optional[str] = None
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    raw_responses: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnsembleResult:
    """Result from ensemble detection."""
    findings: List[EnsembleFinding]
    models_used: List[str]
    models_available: List[str]
    models_failed: List[str]
    execution_time_ms: float
    consensus_threshold: int
    total_raw_findings: int
    filtered_findings: int


class LLMEnsembleDetector:
    """
    Ensemble of LLMs for vulnerability detection.

    Uses multiple models with voting to improve detection accuracy
    and reduce false positives through consensus.

    Supported models (Ollama):
    - deepseek-coder:6.7b  - Excellent code understanding
    - codellama:7b         - Specialized code analysis
    - llama3.1:8b          - Strong general reasoning

    Voting: A finding is valid if >= 2 models independently identify it.
    """

    # Default models for ensemble (ordered by priority)
    DEFAULT_MODELS = [
        "deepseek-coder:6.7b",   # Primary - best for code
        "codellama:7b",           # Secondary - code specialist
        "llama3.1:8b",            # Tertiary - general reasoning
    ]

    # Model weights based on code analysis expertise
    MODEL_WEIGHTS = {
        "deepseek-coder:6.7b": 1.3,
        "deepseek-coder:1.3b": 1.0,
        "codellama:7b": 1.2,
        "codellama:13b": 1.3,
        "llama3.1:8b": 1.0,
        "llama3:8b": 0.9,
        "mistral:7b": 0.8,
    }

    # Vulnerability detection prompt
    DETECTION_PROMPT = """You are an expert Solidity smart contract security auditor.
Analyze the following smart contract code for security vulnerabilities.

IMPORTANT: Only report vulnerabilities you are CONFIDENT about. Do not guess.

For each vulnerability found, provide:
1. Type (reentrancy, access-control, arithmetic, unchecked-call, etc.)
2. Severity (critical, high, medium, low, info)
3. Title (brief description)
4. Description (detailed explanation)
5. Location (function name, approximate line)
6. Attack vector (how it can be exploited)
7. Remediation (how to fix it)
8. Confidence (0.0-1.0)

Respond with a JSON array of findings. If no vulnerabilities found, return [].

Code to analyze:
```solidity
{code}
```

Response (JSON array only):"""

    def __init__(
        self,
        models: Optional[List[str]] = None,
        ollama_base_url: str = "http://localhost:11434",
        voting_strategy: VotingStrategy = VotingStrategy.THRESHOLD,
        consensus_threshold: int = 2,
        timeout: int = 120,
        temperature: float = 0.1,
    ):
        """
        Initialize the ensemble detector.

        Args:
            models: List of model names to use (default: DEFAULT_MODELS)
            ollama_base_url: Ollama API base URL
            voting_strategy: How to aggregate model votes
            consensus_threshold: Minimum votes for THRESHOLD strategy
            timeout: Request timeout in seconds
            temperature: LLM temperature (lower = more deterministic)
        """
        self.models = models or self.DEFAULT_MODELS
        self.base_url = ollama_base_url
        self.voting_strategy = voting_strategy
        self.consensus_threshold = consensus_threshold
        self.timeout = timeout
        self.temperature = temperature

        self._available_models: List[str] = []
        self._initialized = False

        logger.info(
            f"LLMEnsembleDetector initialized with {len(self.models)} models, "
            f"strategy={voting_strategy.value}, threshold={consensus_threshold}"
        )

    async def initialize(self) -> Dict[str, bool]:
        """
        Initialize detector and check model availability.

        Returns:
            Dict mapping model name to availability status
        """
        import aiohttp

        status = {}
        self._available_models = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        installed_models = [m["name"] for m in data.get("models", [])]

                        for model in self.models:
                            # Check exact match or prefix match
                            available = model in installed_models or any(
                                m.startswith(model.split(":")[0]) for m in installed_models
                            )
                            status[model] = available
                            if available:
                                self._available_models.append(model)
                    else:
                        logger.warning(f"Ollama API returned status {resp.status}")
                        for model in self.models:
                            status[model] = False

        except Exception as e:
            logger.warning(f"Failed to check Ollama models: {e}")
            for model in self.models:
                status[model] = False

        self._initialized = True
        logger.info(f"Ensemble detector: {len(self._available_models)}/{len(self.models)} models available")
        return status

    async def detect_vulnerabilities(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> EnsembleResult:
        """
        Execute vulnerability detection with ensemble voting.

        Args:
            code: Solidity source code to analyze
            context: Optional additional context

        Returns:
            EnsembleResult with validated findings
        """
        import time

        start_time = time.time()

        if not self._initialized:
            await self.initialize()

        if not self._available_models:
            logger.error("No LLM models available for ensemble detection")
            return EnsembleResult(
                findings=[],
                models_used=[],
                models_available=[],
                models_failed=self.models,
                execution_time_ms=0,
                consensus_threshold=self.consensus_threshold,
                total_raw_findings=0,
                filtered_findings=0,
            )

        # Query all available models in parallel
        tasks = [
            self._query_model(model, code, context)
            for model in self._available_models
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        model_findings: Dict[str, List[Dict]] = {}
        failed_models: List[str] = []

        for model, result in zip(self._available_models, results):
            if isinstance(result, Exception):
                logger.warning(f"Model {model} failed: {result}")
                failed_models.append(model)
            else:
                model_findings[model] = result

        # Aggregate with voting
        validated_findings = self._ensemble_vote(model_findings)

        execution_time = (time.time() - start_time) * 1000

        # Calculate statistics
        total_raw = sum(len(f) for f in model_findings.values())

        logger.info(
            f"Ensemble detection complete: {len(validated_findings)} findings "
            f"from {total_raw} raw ({len(model_findings)} models)"
        )

        return EnsembleResult(
            findings=validated_findings,
            models_used=list(model_findings.keys()),
            models_available=self._available_models,
            models_failed=failed_models,
            execution_time_ms=execution_time,
            consensus_threshold=self.consensus_threshold,
            total_raw_findings=total_raw,
            filtered_findings=total_raw - len(validated_findings),
        )

    async def _query_model(
        self,
        model: str,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query a single model for vulnerabilities.

        Args:
            model: Model name
            code: Solidity code
            context: Optional context

        Returns:
            List of findings from this model
        """
        import aiohttp

        prompt = self.DETECTION_PROMPT.format(code=code)

        if context:
            prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2)}"

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Respond only with valid JSON."
                },
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": 4096,
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status != 200:
                        raise Exception(f"Ollama error: {await resp.text()}")

                    data = await resp.json()
                    content = data.get("message", {}).get("content", "")

                    return self._parse_model_response(content, model)

        except Exception as e:
            logger.warning(f"Model {model} query failed: {e}")
            raise

    def _parse_model_response(self, content: str, model: str) -> List[Dict[str, Any]]:
        """Parse model response into findings list."""
        try:
            # Extract JSON from response
            json_start = content.find('[')
            json_end = content.rfind(']') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                findings = json.loads(json_str)

                # Normalize findings
                normalized = []
                for f in findings:
                    if isinstance(f, dict) and f.get("type"):
                        # Add source model
                        f["_source_model"] = model
                        normalized.append(f)

                return normalized
            else:
                # Try parsing entire content
                if content.strip().startswith('['):
                    findings = json.loads(content)
                    for f in findings:
                        if isinstance(f, dict):
                            f["_source_model"] = model
                    return findings

        except json.JSONDecodeError as e:
            logger.debug(f"JSON parse error for {model}: {e}")

        return []

    def _ensemble_vote(
        self,
        model_findings: Dict[str, List[Dict]],
    ) -> List[EnsembleFinding]:
        """
        Aggregate findings using voting strategy.

        Findings are grouped by type and location, then validated
        based on the voting strategy.
        """
        if not model_findings:
            return []

        # Group findings by type + location signature
        finding_groups: Dict[str, Dict[str, Any]] = {}

        for model, findings in model_findings.items():
            for finding in findings:
                # Create signature for grouping similar findings
                signature = self._create_finding_signature(finding)

                if signature not in finding_groups:
                    finding_groups[signature] = {
                        "finding": finding,
                        "votes": [],
                        "models": [],
                        "raw_responses": {},
                    }

                finding_groups[signature]["votes"].append(
                    self.MODEL_WEIGHTS.get(model, 1.0)
                )
                finding_groups[signature]["models"].append(model)
                finding_groups[signature]["raw_responses"][model] = finding

        # Apply voting strategy
        validated = []
        total_models = len(model_findings)

        for signature, group in finding_groups.items():
            votes = len(group["votes"])
            weighted_votes = sum(group["votes"])

            # Check if finding passes voting threshold
            passes = False

            if self.voting_strategy == VotingStrategy.MAJORITY:
                passes = votes > total_models / 2

            elif self.voting_strategy == VotingStrategy.UNANIMOUS:
                passes = votes == total_models

            elif self.voting_strategy == VotingStrategy.THRESHOLD:
                passes = votes >= self.consensus_threshold

            elif self.voting_strategy == VotingStrategy.WEIGHTED:
                # Weighted threshold based on available model weights
                max_possible_weight = sum(
                    self.MODEL_WEIGHTS.get(m, 1.0)
                    for m in model_findings.keys()
                )
                passes = weighted_votes >= max_possible_weight * 0.5

            if passes:
                finding = group["finding"]

                # Calculate aggregated confidence
                base_confidence = float(finding.get("confidence", 0.7))
                vote_bonus = min(0.2, votes * 0.05)  # Up to +0.2 for votes
                aggregated_confidence = min(0.99, base_confidence + vote_bonus)

                validated.append(EnsembleFinding(
                    type=finding.get("type", "unknown"),
                    severity=finding.get("severity", "medium").lower(),
                    title=finding.get("title", finding.get("type", "Unknown")),
                    description=finding.get("description", ""),
                    location=finding.get("location", {}),
                    confidence=aggregated_confidence,
                    votes=votes,
                    total_models=total_models,
                    supporting_models=group["models"],
                    attack_vector=finding.get("attack_vector"),
                    remediation=finding.get("remediation"),
                    swc_id=finding.get("swc_id") or finding.get("swc"),
                    cwe_id=finding.get("cwe_id") or finding.get("cwe"),
                    raw_responses=group["raw_responses"],
                ))

        # Sort by severity and confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        validated.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

        return validated

    def _create_finding_signature(self, finding: Dict[str, Any]) -> str:
        """
        Create a unique signature for grouping similar findings.

        Findings are considered similar if they have the same type
        and approximately the same location.
        """
        vuln_type = finding.get("type", "").lower()
        location = finding.get("location", {})

        # Extract location components
        if isinstance(location, dict):
            func = location.get("function", "")
            line = location.get("line", 0)
            # Round line to nearest 5 for approximate matching
            line_group = (int(line) // 5) * 5 if line else 0
        else:
            func = str(location)
            line_group = 0

        # Create signature
        sig_content = f"{vuln_type}:{func}:{line_group}"
        return hashlib.sha256(sig_content.encode()).hexdigest()[:16]

    def get_model_status(self) -> Dict[str, Any]:
        """Get current model status information."""
        return {
            "configured_models": self.models,
            "available_models": self._available_models,
            "voting_strategy": self.voting_strategy.value,
            "consensus_threshold": self.consensus_threshold,
            "model_weights": {
                m: self.MODEL_WEIGHTS.get(m, 1.0)
                for m in self.models
            },
            "initialized": self._initialized,
        }


# Convenience function for simple usage
async def detect_with_ensemble(
    code: str,
    models: Optional[List[str]] = None,
    min_votes: int = 2,
) -> List[EnsembleFinding]:
    """
    Detect vulnerabilities using LLM ensemble.

    Args:
        code: Solidity source code
        models: Models to use (default: deepseek-coder, codellama, llama3.1)
        min_votes: Minimum votes for a finding to be valid

    Returns:
        List of validated findings
    """
    detector = LLMEnsembleDetector(
        models=models,
        consensus_threshold=min_votes,
    )
    result = await detector.detect_vulnerabilities(code)
    return result.findings


# Export
__all__ = [
    "LLMEnsembleDetector",
    "EnsembleFinding",
    "EnsembleResult",
    "VotingStrategy",
    "detect_with_ensemble",
]
