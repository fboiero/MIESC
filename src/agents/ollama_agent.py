"""
Ollama Agent for MIESC

Local LLM integration using Ollama for:
- Privacy-preserving analysis (no data leaves your machine)
- Cost-free unlimited analysis
- Multiple model support (CodeLlama, Mistral, DeepSeek, etc.)
- Fallback for OpenAI/Anthropic when quotas exceeded

Supported Models:
- codellama:13b - Best for code analysis (13B params)
- mistral:7b-instruct - Fast, good explanations (7B params)
- deepseek-coder:6.7b - Specialized in code (6.7B params)
- llama2:13b - General purpose (13B params)

Installation:
    curl https://ollama.ai/install.sh | sh
    ollama pull codellama:13b
"""

import subprocess
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class OllamaAgent(BaseAgent):
    """
    Ollama-based AI agent for local LLM analysis

    Capabilities:
    - Local AI-powered vulnerability detection
    - Zero cost (no API keys required)
    - Complete privacy (data never leaves machine)
    - Multiple model support
    - Structured output with confidence scores

    Context Types Published:
    - ollama_findings: Vulnerabilities found by LLM
    - ollama_analysis: Detailed analysis with reasoning
    - ollama_recommendations: Fix suggestions
    """

    SYSTEM_PROMPT = """You are an expert Solidity smart contract security auditor.
Your task is to analyze smart contracts for vulnerabilities and security issues.

Focus on:
1. Common vulnerabilities (reentrancy, access control, arithmetic issues)
2. Logic bugs and edge cases
3. Gas optimization issues
4. Best practice violations

Respond in JSON format with this structure:
{
  "vulnerabilities": [
    {
      "id": "OLL-001",
      "severity": "High|Medium|Low|Info",
      "category": "vulnerability category",
      "description": "detailed description",
      "location": "function or line reference",
      "recommendation": "how to fix",
      "confidence": 0.0-1.0
    }
  ],
  "summary": "overall assessment",
  "risk_score": 0-100
}"""

    def __init__(
        self,
        model: str = "codellama:13b",
        temperature: float = 0.1,
        max_tokens: int = 2000,
        ollama_host: str = "http://localhost:11434"
    ):
        """
        Initialize Ollama agent

        Args:
            model: Ollama model to use (default: codellama:13b)
            temperature: Sampling temperature 0-1 (default: 0.1)
            max_tokens: Max tokens in response (default: 2000)
            ollama_host: Ollama server URL (default: http://localhost:11434)
        """
        super().__init__(
            agent_name="OllamaAgent",
            capabilities=[
                "local_llm_analysis",
                "privacy_preserving",
                "unlimited_usage",
                "multi_model_support",
                "offline_capable"
            ],
            agent_type="ai"
        )

        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.ollama_host = ollama_host

        # Check if Ollama is installed and running
        self._check_ollama_available()

    def _check_ollama_available(self) -> bool:
        """Check if Ollama is installed and running"""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                logger.info("Ollama is available")

                # Check if model is downloaded
                if self.model not in result.stdout:
                    logger.warning(
                        f"Model {self.model} not found. Download with: "
                        f"ollama pull {self.model}"
                    )
                    return False

                return True
            else:
                logger.error("Ollama is not running. Start with: ollama serve")
                return False

        except FileNotFoundError:
            logger.error(
                "Ollama not installed. Install from: "
                "https://ollama.ai/download"
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("Ollama server not responding")
            return False
        except Exception as e:
            logger.error(f"Error checking Ollama: {e}")
            return False

    def get_context_types(self) -> List[str]:
        return [
            "ollama_findings",
            "ollama_analysis",
            "ollama_recommendations"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract with Ollama LLM

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - max_lines: Max lines to analyze (default: 500)
                - focus_functions: List of functions to focus on

        Returns:
            Dict with findings and analysis
        """
        import time
        start_time = time.time()

        print(f"\n🤖 Ollama Analysis Starting...")
        print(f"   Model: {self.model}")
        print(f"   Contract: {contract_path}")

        # Read contract
        try:
            with open(contract_path, 'r') as f:
                contract_code = f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return {"error": str(e)}

        # Truncate if too long
        max_lines = kwargs.get('max_lines', 500)
        lines = contract_code.split('\n')
        if len(lines) > max_lines:
            contract_code = '\n'.join(lines[:max_lines])
            logger.warning(f"Contract truncated to {max_lines} lines")

        # Build prompt
        prompt = self._build_analysis_prompt(contract_code, **kwargs)

        # Call Ollama
        print("\n[1/2] Sending to Ollama LLM...")
        response = self._call_ollama(prompt)

        if not response:
            return {
                "ollama_findings": [],
                "ollama_analysis": {"error": "Ollama request failed"},
                "ollama_recommendations": []
            }

        # Parse response
        print("[2/2] Parsing LLM response...")
        findings = self._parse_ollama_response(response, contract_path)

        execution_time = time.time() - start_time

        print(f"\n✅ Ollama analysis complete ({execution_time:.2f}s)")
        print(f"   Findings: {len(findings)}")
        print(f"   Model: {self.model}")

        return {
            "ollama_findings": findings,
            "ollama_analysis": {
                "model": self.model,
                "execution_time": execution_time,
                "raw_response": response[:500] + "..." if len(response) > 500 else response,
                "total_findings": len(findings)
            },
            "ollama_recommendations": self._generate_recommendations(findings),
            "execution_time": execution_time
        }

    def _build_analysis_prompt(self, contract_code: str, **kwargs) -> str:
        """Build analysis prompt for LLM"""

        focus_functions = kwargs.get('focus_functions')
        focus_note = ""
        if focus_functions:
            focus_note = f"\nPay special attention to these functions: {', '.join(focus_functions)}"

        prompt = f"""{self.SYSTEM_PROMPT}

{focus_note}

Analyze this Solidity smart contract:

```solidity
{contract_code}
```

Provide a detailed security analysis in JSON format as specified above.
Focus on real vulnerabilities, not style issues."""

        return prompt

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call Ollama API"""
        try:
            # Use ollama run command
            result = subprocess.run(
                ["ollama", "run", self.model],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes timeout
            )

            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"Ollama error: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Ollama request timed out")
            return None
        except Exception as e:
            logger.error(f"Error calling Ollama: {e}")
            return None

    def _parse_ollama_response(
        self,
        response: str,
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """Parse LLM response into structured findings"""

        findings = []

        try:
            # Try to extract JSON from response
            # LLM might wrap JSON in markdown code blocks
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)

                vulnerabilities = data.get('vulnerabilities', [])

                for idx, vuln in enumerate(vulnerabilities):
                    finding = {
                        "id": vuln.get('id', f"OLL-{idx+1:03d}"),
                        "source": "Ollama",
                        "model": self.model,
                        "severity": vuln.get('severity', 'Medium'),
                        "category": vuln.get('category', 'Unknown'),
                        "description": vuln.get('description', ''),
                        "location": vuln.get('location', 'Unknown'),
                        "recommendation": vuln.get('recommendation', ''),
                        "confidence": vuln.get('confidence', 0.7),
                        "contract": contract_path,
                        "swc_id": self._map_to_swc(vuln.get('category', '')),
                        "owasp_category": self._map_to_owasp(vuln.get('category', ''))
                    }
                    findings.append(finding)

                # Add risk score to metadata
                risk_score = data.get('risk_score', 0)
                summary = data.get('summary', '')

                logger.info(
                    f"Parsed {len(findings)} findings from Ollama "
                    f"(risk score: {risk_score})"
                )

            else:
                # Fallback: treat as unstructured text
                logger.warning("Could not parse JSON from Ollama response")
                findings.append({
                    "id": "OLL-001",
                    "source": "Ollama",
                    "model": self.model,
                    "severity": "Info",
                    "category": "Analysis",
                    "description": response[:500],
                    "location": "Full contract",
                    "recommendation": "Manual review recommended",
                    "confidence": 0.5,
                    "contract": contract_path
                })

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            # Return raw response as finding
            findings.append({
                "id": "OLL-ERROR",
                "source": "Ollama",
                "severity": "Info",
                "category": "Parse Error",
                "description": f"Could not parse response: {response[:200]}",
                "location": "N/A",
                "recommendation": "Check Ollama output format",
                "confidence": 0.0,
                "contract": contract_path
            })

        return findings

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate high-level recommendations from findings"""
        recommendations = []

        critical_count = len([f for f in findings if f.get('severity') == 'Critical'])
        high_count = len([f for f in findings if f.get('severity') == 'High'])
        medium_count = len([f for f in findings if f.get('severity') == 'Medium'])

        if critical_count > 0:
            recommendations.append(
                f"⚠️ CRITICAL: {critical_count} critical issues found. "
                "Do not deploy to mainnet."
            )

        if high_count > 0:
            recommendations.append(
                f"⚠️ HIGH: {high_count} high-severity issues require immediate attention."
            )

        if medium_count > 3:
            recommendations.append(
                f"Medium-severity issues detected ({medium_count}). "
                "Review before production deployment."
            )

        if not findings:
            recommendations.append(
                "✅ No vulnerabilities detected by LLM analysis."
            )

        recommendations.append(
            f"🤖 Analysis performed by {self.model} (local, private, cost-free)"
        )

        return recommendations

    def _map_to_swc(self, category: str) -> str:
        """Map vulnerability category to SWC ID"""
        mapping = {
            "reentrancy": "SWC-107",
            "access control": "SWC-105",
            "arithmetic": "SWC-101",
            "unchecked call": "SWC-104",
            "delegatecall": "SWC-112",
            "tx.origin": "SWC-115",
            "timestamp": "SWC-116",
            "denial of service": "SWC-128"
        }

        category_lower = category.lower()
        for key, swc_id in mapping.items():
            if key in category_lower:
                return swc_id

        return "SWC-000"

    def _map_to_owasp(self, category: str) -> str:
        """Map to OWASP Smart Contract Top 10"""
        swc_id = self._map_to_swc(category)

        swc_to_owasp = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            "SWC-101": "SC03-Arithmetic",
            "SWC-104": "SC04-Unchecked-Calls",
            "SWC-112": "SC02-Access-Control",
            "SWC-115": "SC02-Access-Control",
            "SWC-116": "SC08-Time-Manipulation",
            "SWC-128": "SC06-Denial-of-Service"
        }

        return swc_to_owasp.get(swc_id, "SC10-Unknown")

    @staticmethod
    def get_available_models() -> List[str]:
        """Get list of downloaded Ollama models"""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                # Parse output
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                models = [line.split()[0] for line in lines if line.strip()]
                return models
            else:
                return []

        except Exception as e:
            logger.error(f"Error getting Ollama models: {e}")
            return []


# Standalone execution
if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("Ollama Agent - MIESC Integration")
    print("=" * 60)

    # Check available models
    print("\n📦 Checking available models...")
    models = OllamaAgent.get_available_models()

    if models:
        print(f"   Found {len(models)} models:")
        for model in models:
            print(f"   - {model}")
    else:
        print("   ⚠️  No models found. Download with:")
        print("      ollama pull codellama:13b")
        print("      ollama pull mistral:7b-instruct")
        sys.exit(1)

    # Use first available model or specified one
    if len(sys.argv) > 2:
        contract_path = sys.argv[1]
        model = sys.argv[2]
    elif len(sys.argv) > 1:
        contract_path = sys.argv[1]
        model = models[0] if models else "codellama:13b"
    else:
        print("\nUsage: python ollama_agent.py <contract.sol> [model]")
        print(f"\nAvailable models: {', '.join(models)}")
        sys.exit(1)

    # Run analysis
    agent = OllamaAgent(model=model)
    results = agent.run(contract_path)

    # Display results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    findings = results.get("ollama_findings", [])
    analysis = results.get("ollama_analysis", {})

    print(f"\n📊 Analysis Summary:")
    print(f"   Model: {analysis.get('model', 'unknown')}")
    print(f"   Execution Time: {analysis.get('execution_time', 0):.2f}s")
    print(f"   Total Findings: {analysis.get('total_findings', 0)}")

    if findings:
        print(f"\n🚨 Vulnerabilities Detected: {len(findings)}")
        for finding in findings:
            print(f"\n   [{finding['id']}] {finding['severity']}")
            print(f"   Category: {finding['category']}")
            print(f"   Location: {finding['location']}")
            print(f"   {finding['description'][:100]}...")
            print(f"   💡 Fix: {finding['recommendation'][:80]}...")
    else:
        print("\n✅ No vulnerabilities detected")

    recommendations = results.get("ollama_recommendations", [])
    if recommendations:
        print(f"\n📋 Recommendations:")
        for rec in recommendations:
            print(f"   • {rec}")

    print("\n" + "=" * 60)
