"""
LLM Orchestrator for MIESC

Orchestrates multiple LLM backends for intelligent security analysis.
Supports Ollama (local), OpenAI, Anthropic, and custom models.

Author: Fernando Boiero
License: GPL-3.0
"""

import asyncio
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import time

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers."""
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for LLM backend."""
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 120
    retry_attempts: int = 3
    retry_delay: float = 1.0


@dataclass
class LLMResponse:
    """Response from LLM analysis."""
    content: str
    provider: str
    model: str
    tokens_used: int = 0
    latency_ms: float = 0
    cached: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityAnalysis:
    """Structured vulnerability analysis result."""
    vulnerabilities: List[Dict[str, Any]]
    severity_assessment: Dict[str, int]
    recommendations: List[str]
    confidence_score: float
    analysis_summary: str
    raw_response: str


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.available = False

    @abstractmethod
    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with the LLM."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the backend is available."""
        pass

    def get_system_prompt(self) -> str:
        """Get the security analysis system prompt."""
        return """You are an expert Solidity smart contract security auditor.
Your task is to analyze smart contract code for security vulnerabilities.

When analyzing code, you should:
1. Identify potential vulnerabilities (reentrancy, overflow, access control, etc.)
2. Assess the severity of each finding (critical, high, medium, low, info)
3. Explain the attack vector and potential impact
4. Provide specific remediation recommendations with code examples
5. Reference relevant CWE and SWC identifiers when applicable

Format your response as JSON with the following structure:
{
    "vulnerabilities": [
        {
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low|info",
            "title": "Brief title",
            "description": "Detailed description",
            "location": {"line": number, "function": "name"},
            "attack_vector": "How it can be exploited",
            "impact": "Potential consequences",
            "remediation": "How to fix",
            "cwe": "CWE-XXX",
            "swc": "SWC-XXX",
            "confidence": 0.0-1.0
        }
    ],
    "summary": "Overall security assessment",
    "risk_score": 0-100
}"""


class OllamaBackend(LLMBackend):
    """Ollama backend for local LLM inference."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.base_url or "http://localhost:11434"

    async def health_check(self) -> bool:
        """Check if Ollama is running."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/tags", timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m["name"] for m in data.get("models", [])]
                        self.available = self.config.model in models or any(
                            self.config.model in m for m in models
                        )
                        return self.available
        except Exception as e:
            logger.debug(f"Ollama health check failed: {e}")
        return False

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with Ollama."""
        import aiohttp

        start_time = time.time()

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2)}"

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"Ollama error: {await resp.text()}")

                data = await resp.json()
                content = data.get("message", {}).get("content", "")
                tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

        return LLMResponse(
            content=content,
            provider="ollama",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000
        )


class OpenAIBackend(LLMBackend):
    """OpenAI backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("OPENAI_API_KEY")

    async def health_check(self) -> bool:
        """Check if OpenAI is configured."""
        self.available = bool(self.api_key)
        return self.available

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with OpenAI."""
        try:
            import openai
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

        start_time = time.time()
        client = openai.AsyncOpenAI(api_key=self.api_key)

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2)}"

        response = await client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens
        )

        return LLMResponse(
            content=response.choices[0].message.content or "",
            provider="openai",
            model=self.config.model,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            latency_ms=(time.time() - start_time) * 1000
        )


class AnthropicBackend(LLMBackend):
    """Anthropic Claude backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("ANTHROPIC_API_KEY")

    async def health_check(self) -> bool:
        """Check if Anthropic is configured."""
        self.available = bool(self.api_key)
        return self.available

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with Anthropic."""
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

        start_time = time.time()
        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2)}"

        response = await client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}]
        )

        content = response.content[0].text if response.content else ""
        tokens = response.usage.input_tokens + response.usage.output_tokens if response.usage else 0

        return LLMResponse(
            content=content,
            provider="anthropic",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000
        )


class LLMOrchestrator:
    """
    Orchestrates multiple LLM backends for security analysis.

    Features:
    - Automatic fallback between providers
    - Response caching
    - Retry logic
    - Provider selection based on task
    """

    def __init__(self, configs: Optional[List[LLMConfig]] = None):
        """Initialize orchestrator with backend configurations."""
        self.backends: Dict[str, LLMBackend] = {}
        self.primary_provider: Optional[str] = None
        self.cache: Dict[str, LLMResponse] = {}
        self.cache_ttl: int = 3600  # 1 hour

        # Default configurations if none provided
        if configs is None:
            configs = [
                LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model="deepseek-coder:6.7b",
                    base_url="http://localhost:11434"
                ),
            ]

        # Initialize backends
        for config in configs:
            self._add_backend(config)

    def _add_backend(self, config: LLMConfig) -> None:
        """Add a backend based on configuration."""
        backend: LLMBackend

        if config.provider == LLMProvider.OLLAMA:
            backend = OllamaBackend(config)
        elif config.provider == LLMProvider.OPENAI:
            backend = OpenAIBackend(config)
        elif config.provider == LLMProvider.ANTHROPIC:
            backend = AnthropicBackend(config)
        else:
            logger.warning(f"Unknown provider: {config.provider}")
            return

        key = f"{config.provider.value}:{config.model}"
        self.backends[key] = backend

        if self.primary_provider is None:
            self.primary_provider = key

    async def initialize(self) -> Dict[str, bool]:
        """Initialize all backends and check availability."""
        status = {}
        for key, backend in self.backends.items():
            try:
                available = await backend.health_check()
                status[key] = available
                if available and self.primary_provider is None:
                    self.primary_provider = key
                logger.info(f"Backend {key}: {'available' if available else 'unavailable'}")
            except Exception as e:
                status[key] = False
                logger.warning(f"Backend {key} health check failed: {e}")
        return status

    async def analyze_contract(
        self,
        code: str,
        context: Optional[Dict] = None,
        provider: Optional[str] = None
    ) -> VulnerabilityAnalysis:
        """
        Analyze a smart contract for vulnerabilities.

        Args:
            code: Solidity source code
            context: Additional context (tool results, metadata)
            provider: Specific provider to use (optional)

        Returns:
            Structured vulnerability analysis
        """
        prompt = f"""Analyze the following Solidity smart contract for security vulnerabilities:

```solidity
{code}
```

Provide a comprehensive security analysis in JSON format."""

        # Get LLM response
        response = await self.query(prompt, context, provider)

        # Parse response
        return self._parse_analysis(response)

    async def query(
        self,
        prompt: str,
        context: Optional[Dict] = None,
        provider: Optional[str] = None
    ) -> LLMResponse:
        """
        Send a query to the LLM with automatic fallback.

        Args:
            prompt: The prompt to send
            context: Additional context
            provider: Specific provider to use

        Returns:
            LLM response
        """
        # Check cache
        cache_key = self._get_cache_key(prompt, context)
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            cached.cached = True
            return cached

        # Select backend
        backend_key = provider or self.primary_provider
        if not backend_key:
            raise RuntimeError("No LLM backends available")

        # Try with fallback
        errors = []
        backends_to_try = [backend_key] + [
            k for k in self.backends.keys() if k != backend_key
        ]

        for key in backends_to_try:
            backend = self.backends.get(key)
            if not backend or not backend.available:
                continue

            for attempt in range(backend.config.retry_attempts):
                try:
                    response = await backend.analyze(prompt, context)
                    self.cache[cache_key] = response
                    return response
                except Exception as e:
                    errors.append(f"{key} attempt {attempt + 1}: {e}")
                    if attempt < backend.config.retry_attempts - 1:
                        await asyncio.sleep(backend.config.retry_delay)

        raise RuntimeError(f"All LLM backends failed: {errors}")

    def _get_cache_key(self, prompt: str, context: Optional[Dict]) -> str:
        """Generate cache key from prompt and context."""
        import hashlib
        content = prompt + json.dumps(context or {}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _parse_analysis(self, response: LLMResponse) -> VulnerabilityAnalysis:
        """Parse LLM response into structured analysis."""
        try:
            # Try to extract JSON from response
            content = response.content
            json_start = content.find('{')
            json_end = content.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                data = json.loads(json_str)
            else:
                data = {}

            vulnerabilities = data.get("vulnerabilities", [])
            severity_assessment = {
                "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
                "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
                "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
                "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
                "info": sum(1 for v in vulnerabilities if v.get("severity") == "info"),
            }

            return VulnerabilityAnalysis(
                vulnerabilities=vulnerabilities,
                severity_assessment=severity_assessment,
                recommendations=[v.get("remediation", "") for v in vulnerabilities if v.get("remediation")],
                confidence_score=sum(v.get("confidence", 0.5) for v in vulnerabilities) / max(len(vulnerabilities), 1),
                analysis_summary=data.get("summary", "Analysis completed"),
                raw_response=response.content
            )

        except json.JSONDecodeError:
            # Return unstructured analysis
            return VulnerabilityAnalysis(
                vulnerabilities=[],
                severity_assessment={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                recommendations=[],
                confidence_score=0.5,
                analysis_summary=response.content[:500],
                raw_response=response.content
            )

    def select_model_for_task(self, task: str) -> str:
        """Select the best model for a specific task type."""
        task_preferences = {
            "vulnerability_detection": ["ollama:deepseek-coder:6.7b", "openai:gpt-4"],
            "code_review": ["anthropic:claude-3-opus", "openai:gpt-4"],
            "remediation": ["ollama:codellama:13b", "openai:gpt-4"],
            "explanation": ["anthropic:claude-3-sonnet", "ollama:llama2:13b"],
        }

        preferences = task_preferences.get(task, list(self.backends.keys()))

        for pref in preferences:
            if pref in self.backends and self.backends[pref].available:
                return pref

        return self.primary_provider or list(self.backends.keys())[0]

    def get_available_providers(self) -> List[str]:
        """Get list of available providers."""
        return [k for k, v in self.backends.items() if v.available]

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self.cache.clear()


# Convenience function for simple usage
async def analyze_solidity(code: str, model: str = "deepseek-coder:6.7b") -> VulnerabilityAnalysis:
    """
    Analyze Solidity code for vulnerabilities.

    Args:
        code: Solidity source code
        model: Model to use (default: deepseek-coder:6.7b)

    Returns:
        Vulnerability analysis result
    """
    config = LLMConfig(provider=LLMProvider.OLLAMA, model=model)
    orchestrator = LLMOrchestrator([config])
    await orchestrator.initialize()
    return await orchestrator.analyze_contract(code)


if __name__ == "__main__":
    # Example usage
    async def main():
        code = '''
        pragma solidity ^0.8.0;

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }
        }
        '''

        result = await analyze_solidity(code)
        print(f"Found {len(result.vulnerabilities)} vulnerabilities")
        print(f"Severity: {result.severity_assessment}")
        print(f"Summary: {result.analysis_summary}")

    asyncio.run(main())
