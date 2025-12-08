"""
SmartGuard Adapter - RAG + Chain-of-Thought Enhanced Vulnerability Detection.

Based on: "SmartGuard: An LLM-enhanced framework for smart contract vulnerability detection"
(Expert Systems with Applications, 2025 - ScienceDirect)

Key innovations from the paper:
1. Semantic Code Retrieval: Finds similar vulnerable code snippets
2. Chain-of-Thought (CoT) Generation: Produces reasoning chains for each vulnerability
3. In-Context Learning: Uses retrieved examples + CoT for accurate detection

Implementation uses Ollama locally (DPGA-compliant, sovereign execution).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-12-03
"""

from src.core.tool_protocol import (
    ToolAdapter,
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability
)
from typing import Dict, Any, List, Optional, Tuple
import logging
import subprocess
import json
import hashlib
import time
import re
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityExample:
    """A vulnerable code example with CoT reasoning."""
    vuln_type: str
    code_snippet: str
    chain_of_thought: str
    fix_suggestion: str
    severity: str


# Knowledge base of vulnerability examples with Chain-of-Thought reasoning
VULNERABILITY_KNOWLEDGE_BASE: List[VulnerabilityExample] = [
    VulnerabilityExample(
        vuln_type="reentrancy",
        code_snippet="""
function withdraw() public {
    uint256 balance = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success);
    balances[msg.sender] = 0;
}""",
        chain_of_thought="""
Step 1: Identify external call - msg.sender.call{value: balance}("")
Step 2: Check state changes after call - balances[msg.sender] = 0 happens AFTER the call
Step 3: Analyze reentrancy possibility - Attacker can re-enter before balance is zeroed
Step 4: Confirm vulnerability - External call before state update = REENTRANCY
Conclusion: HIGH severity reentrancy vulnerability. State must be updated before external calls.
""",
        fix_suggestion="Use Checks-Effects-Interactions pattern: update balances[msg.sender] = 0 BEFORE the call",
        severity="HIGH"
    ),
    VulnerabilityExample(
        vuln_type="integer_overflow",
        code_snippet="""
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // No overflow check in Solidity < 0.8.0
}""",
        chain_of_thought="""
Step 1: Identify arithmetic operation - a + b
Step 2: Check Solidity version - If < 0.8.0, no automatic overflow check
Step 3: Analyze overflow possibility - uint256 max is 2^256-1, addition can wrap around
Step 4: Check for SafeMath - No SafeMath library used
Conclusion: MEDIUM severity for Solidity < 0.8.0. Use SafeMath or upgrade to 0.8.0+.
""",
        fix_suggestion="Use SafeMath library or Solidity >= 0.8.0 for automatic overflow checks",
        severity="MEDIUM"
    ),
    VulnerabilityExample(
        vuln_type="unchecked_return_value",
        code_snippet="""
function sendEther(address payable recipient) public {
    recipient.send(1 ether);  // Return value not checked
}""",
        chain_of_thought="""
Step 1: Identify external call - recipient.send(1 ether)
Step 2: Check return value handling - No check of the boolean return
Step 3: Analyze failure scenario - send() returns false on failure, execution continues
Step 4: Assess impact - Funds may appear sent but never received
Conclusion: MEDIUM severity. Always check return values of send/call.
""",
        fix_suggestion="Use transfer() which reverts on failure, or check send() return value",
        severity="MEDIUM"
    ),
    VulnerabilityExample(
        vuln_type="access_control",
        code_snippet="""
function setOwner(address newOwner) public {
    owner = newOwner;  // No access control
}""",
        chain_of_thought="""
Step 1: Identify privileged function - setOwner changes contract ownership
Step 2: Check access modifiers - No onlyOwner or msg.sender check
Step 3: Analyze attack vector - Anyone can call and become owner
Step 4: Assess impact - Complete contract takeover possible
Conclusion: CRITICAL severity. Add require(msg.sender == owner) or onlyOwner modifier.
""",
        fix_suggestion="Add onlyOwner modifier or require(msg.sender == owner)",
        severity="CRITICAL"
    ),
    VulnerabilityExample(
        vuln_type="timestamp_dependence",
        code_snippet="""
function play() public payable {
    if (block.timestamp % 2 == 0) {
        msg.sender.transfer(msg.value * 2);
    }
}""",
        chain_of_thought="""
Step 1: Identify randomness source - block.timestamp
Step 2: Check manipulation possibility - Miners can manipulate timestamp ~15 seconds
Step 3: Analyze game mechanics - Even/odd timestamp determines winner
Step 4: Assess exploitability - Miner can wait for favorable timestamp
Conclusion: MEDIUM severity. Don't use block.timestamp for randomness/critical decisions.
""",
        fix_suggestion="Use Chainlink VRF or commit-reveal scheme for randomness",
        severity="MEDIUM"
    ),
    VulnerabilityExample(
        vuln_type="delegatecall_injection",
        code_snippet="""
function forward(address target, bytes memory data) public {
    target.delegatecall(data);  // Arbitrary delegatecall
}""",
        chain_of_thought="""
Step 1: Identify delegatecall - target.delegatecall(data)
Step 2: Check input validation - target and data are user-controlled
Step 3: Analyze attack vector - Attacker can execute any code in contract context
Step 4: Assess impact - Complete storage manipulation, ownership theft
Conclusion: CRITICAL severity. Never allow user-controlled delegatecall targets.
""",
        fix_suggestion="Whitelist allowed targets or remove arbitrary delegatecall functionality",
        severity="CRITICAL"
    ),
    VulnerabilityExample(
        vuln_type="front_running",
        code_snippet="""
function buyToken(uint256 amount) public payable {
    uint256 price = calculatePrice(amount);  // Visible in mempool
    require(msg.value >= price);
    balances[msg.sender] += amount;
}""",
        chain_of_thought="""
Step 1: Identify transaction ordering dependency - Price visible before execution
Step 2: Check for slippage protection - No minimum received amount
Step 3: Analyze MEV opportunity - Attackers can front-run large orders
Step 4: Assess impact - Users may receive worse prices than expected
Conclusion: MEDIUM severity. Add slippage protection and commit-reveal if needed.
""",
        fix_suggestion="Add slippage protection (minReceived parameter) and consider commit-reveal",
        severity="MEDIUM"
    ),
    VulnerabilityExample(
        vuln_type="denial_of_service",
        code_snippet="""
function refundAll() public {
    for (uint i = 0; i < users.length; i++) {
        users[i].transfer(balances[users[i]]);
    }
}""",
        chain_of_thought="""
Step 1: Identify loop - iterates over users array
Step 2: Check external calls in loop - transfer() to each user
Step 3: Analyze failure scenario - One malicious receiver can revert, blocking all refunds
Step 4: Assess gas limits - Large user arrays may hit gas limit
Conclusion: HIGH severity DoS. Use pull-over-push pattern for withdrawals.
""",
        fix_suggestion="Use pull pattern: let users withdraw individually instead of push refunds",
        severity="HIGH"
    ),
]


class SmartGuardAdapter(ToolAdapter):
    """
    SmartGuard: LLM-enhanced vulnerability detection with RAG + Chain-of-Thought.

    Based on Expert Systems with Applications 2025 paper methodology:
    1. Code Embedding: Extract semantic representation of contract functions
    2. Similarity Retrieval: Find similar vulnerable code patterns
    3. CoT Generation: Generate reasoning chain for detected vulnerabilities
    4. In-Context Learning: Use retrieved examples for accurate classification

    Uses Ollama locally (100% sovereign, DPGA-compliant).
    """

    def __init__(self):
        super().__init__()
        self._cache_dir = Path.home() / ".miesc" / "smartguard_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._model = "deepseek-coder"
        self._max_tokens = 8000
        self._similarity_threshold = 0.6

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="smartguard",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (SmartGuard 2025 paper implementation)",
            license="AGPL-3.0",
            homepage="https://www.sciencedirect.com/science/article/abs/pii/S0957417425001010",
            repository="https://github.com/ollama/ollama",
            documentation="SmartGuard: An LLM-enhanced framework (Expert Systems with Applications, 2025)",
            installation_cmd="curl -fsSL https://ollama.com/install.sh | sh && ollama pull deepseek-coder",
            capabilities=[
                ToolCapability(
                    name="cot_analysis",
                    description="Chain-of-Thought reasoning for vulnerability detection",
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "integer_overflow",
                        "access_control",
                        "unchecked_return",
                        "delegatecall_injection",
                        "timestamp_dependence",
                        "front_running",
                        "denial_of_service"
                    ]
                ),
                ToolCapability(
                    name="semantic_retrieval",
                    description="Retrieves similar vulnerable code patterns for in-context learning",
                    supported_languages=["solidity"],
                    detection_types=["pattern_matching", "code_similarity"]
                ),
                ToolCapability(
                    name="icl_detection",
                    description="In-Context Learning with few-shot vulnerability examples",
                    supported_languages=["solidity"],
                    detection_types=["few_shot_classification"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama and required model are available."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode != 0:
                return ToolStatus.CONFIGURATION_ERROR

            if "deepseek-coder" in result.stdout:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Model {self._model} not found. Run: ollama pull {self._model}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"SmartGuard availability check error: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using SmartGuard methodology.

        Pipeline:
        1. Extract functions from contract
        2. For each function, retrieve similar vulnerable patterns
        3. Generate Chain-of-Thought reasoning
        4. Classify using in-context learning
        """
        start_time = time.time()

        if self.is_available() != ToolStatus.AVAILABLE:
            return self._error_result(
                "SmartGuard not available. Ensure Ollama is installed.",
                start_time
            )

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return self._error_result(
                    f"Could not read contract: {contract_path}",
                    start_time
                )

            # Check cache
            cache_key = hashlib.sha256(contract_code.encode()).hexdigest()
            cached = self._get_cached(cache_key)
            if cached:
                cached["from_cache"] = True
                cached["execution_time"] = time.time() - start_time
                return cached

            # Extract functions
            functions = self._extract_functions(contract_code)
            logger.info(f"SmartGuard: Extracted {len(functions)} functions")

            all_findings = []

            for func_name, func_code in functions:
                # Step 1: Semantic similarity retrieval
                similar_vulns = self._retrieve_similar_vulnerabilities(func_code)

                if not similar_vulns:
                    continue

                # Step 2: Generate CoT analysis with in-context examples
                findings = self._analyze_with_cot(
                    func_name,
                    func_code,
                    similar_vulns,
                    contract_path
                )

                all_findings.extend(findings)

            # Deduplicate findings
            unique_findings = self._deduplicate_findings(all_findings)

            result = {
                "tool": "smartguard",
                "version": "1.0.0",
                "status": "success",
                "findings": unique_findings,
                "metadata": {
                    "model": self._model,
                    "methodology": "RAG + Chain-of-Thought (SmartGuard 2025)",
                    "paper_reference": "Expert Systems with Applications, 2025",
                    "functions_analyzed": len(functions),
                    "sovereign": True,
                    "dpga_compliant": True
                },
                "execution_time": time.time() - start_time,
                "from_cache": False
            }

            self._cache_result(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"SmartGuard analysis error: {e}", exc_info=True)
            return self._error_result(str(e), start_time)

    def _extract_functions(self, code: str) -> List[Tuple[str, str]]:
        """Extract function definitions from Solidity code."""
        functions = []

        # Regex to match function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'

        for match in re.finditer(func_pattern, code, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(0)
            functions.append((func_name, func_body))

        # Also extract modifiers
        modifier_pattern = r'modifier\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        for match in re.finditer(modifier_pattern, code, re.DOTALL):
            mod_name = match.group(1)
            mod_body = match.group(0)
            functions.append((f"modifier_{mod_name}", mod_body))

        return functions

    def _retrieve_similar_vulnerabilities(
        self,
        func_code: str
    ) -> List[VulnerabilityExample]:
        """
        Retrieve similar vulnerability patterns from knowledge base.

        Uses keyword-based similarity (simple but effective).
        In production, use embeddings for semantic similarity.
        """
        matches = []

        # Keywords that indicate vulnerability patterns
        vulnerability_indicators = {
            "reentrancy": [".call{value", "msg.sender.call", "external call", "transfer("],
            "integer_overflow": ["+ ", "- ", "* ", "++ ", "-- "],
            "unchecked_return_value": [".send(", ".call("],
            "access_control": ["owner", "admin", "onlyOwner", "require(msg.sender"],
            "timestamp_dependence": ["block.timestamp", "block.number", "now"],
            "delegatecall_injection": ["delegatecall(", ".delegatecall"],
            "front_running": ["price", "swap", "trade", "buy", "sell"],
            "denial_of_service": ["for (", "while (", ".length", "transfer("],
        }

        func_lower = func_code.lower()

        for vuln_example in VULNERABILITY_KNOWLEDGE_BASE:
            indicators = vulnerability_indicators.get(vuln_example.vuln_type, [])
            score = 0

            for indicator in indicators:
                if indicator.lower() in func_lower:
                    score += 1

            # Also check for specific vulnerability patterns
            if vuln_example.vuln_type == "reentrancy":
                # Check for call before state update
                if ".call{" in func_code and "=" in func_code.split(".call{")[1]:
                    score += 2

            if score > 0:
                matches.append((score, vuln_example))

        # Sort by score and return top matches
        matches.sort(key=lambda x: x[0], reverse=True)
        return [m[1] for m in matches[:3]]  # Top 3 matches

    def _analyze_with_cot(
        self,
        func_name: str,
        func_code: str,
        similar_vulns: List[VulnerabilityExample],
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze function using Chain-of-Thought with in-context examples.
        """
        findings = []

        # Build in-context learning prompt
        icl_examples = self._build_icl_examples(similar_vulns)

        prompt = f"""You are a smart contract security expert using Chain-of-Thought reasoning.

{icl_examples}

Now analyze this function using the same Chain-of-Thought methodology:

FUNCTION TO ANALYZE:
```solidity
{func_code}
```

INSTRUCTIONS:
1. Apply Chain-of-Thought reasoning step by step
2. Compare with the vulnerability patterns shown above
3. Identify any security vulnerabilities
4. Provide specific fix recommendations

OUTPUT FORMAT (JSON only):
{{
  "analysis": {{
    "chain_of_thought": "Step 1: ... Step 2: ... Step 3: ... Conclusion: ...",
    "vulnerabilities": [
      {{
        "type": "vulnerability_type",
        "severity": "CRITICAL/HIGH/MEDIUM/LOW",
        "description": "What the vulnerability is",
        "location": "Function or line",
        "fix": "How to fix it"
      }}
    ]
  }}
}}

Output JSON only:"""

        try:
            result = subprocess.run(
                ["ollama", "run", self._model, prompt],
                capture_output=True,
                timeout=180,
                text=True
            )

            if result.returncode == 0 and result.stdout:
                findings = self._parse_cot_response(
                    result.stdout,
                    func_name,
                    contract_path
                )

        except subprocess.TimeoutExpired:
            logger.warning(f"SmartGuard timeout analyzing {func_name}")
        except Exception as e:
            logger.error(f"SmartGuard CoT error: {e}")

        return findings

    def _build_icl_examples(self, similar_vulns: List[VulnerabilityExample]) -> str:
        """Build in-context learning examples from similar vulnerabilities."""
        examples = "EXAMPLE VULNERABILITIES WITH CHAIN-OF-THOUGHT REASONING:\n\n"

        for i, vuln in enumerate(similar_vulns, 1):
            examples += f"""--- Example {i}: {vuln.vuln_type.upper()} ---
Code:
```solidity
{vuln.code_snippet}
```

Chain-of-Thought Analysis:
{vuln.chain_of_thought}

Severity: {vuln.severity}
Fix: {vuln.fix_suggestion}

"""

        return examples

    def _parse_cot_response(
        self,
        response: str,
        func_name: str,
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """Parse Chain-of-Thought response from LLM."""
        findings = []

        try:
            # Extract JSON
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start == -1:
                return []

            json_str = response[json_start:json_end]
            parsed = json.loads(json_str)

            analysis = parsed.get("analysis", {})
            cot = analysis.get("chain_of_thought", "")
            vulns = analysis.get("vulnerabilities", [])

            for idx, vuln in enumerate(vulns):
                finding = {
                    "id": f"smartguard-{func_name}-{idx+1}",
                    "title": f"{vuln.get('type', 'Issue')} in {func_name}",
                    "description": vuln.get("description", ""),
                    "severity": vuln.get("severity", "MEDIUM").upper(),
                    "confidence": 0.80,  # CoT provides good confidence
                    "category": vuln.get("type", "security_issue"),
                    "location": {
                        "file": contract_path,
                        "function": func_name,
                        "details": vuln.get("location", func_name)
                    },
                    "recommendation": vuln.get("fix", "Review and fix the identified issue"),
                    "chain_of_thought": cot,
                    "methodology": "SmartGuard RAG+CoT",
                    "references": [
                        "SmartGuard: Expert Systems with Applications (2025)"
                    ]
                }
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error in CoT response: {e}")
        except Exception as e:
            logger.error(f"Error parsing CoT response: {e}")

        return findings

    def _deduplicate_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on type and location."""
        seen = set()
        unique = []

        for f in findings:
            key = (
                f.get("category", ""),
                f.get("location", {}).get("function", ""),
                f.get("severity", "")
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _read_contract(self, path: str) -> Optional[str]:
        """Read contract file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _error_result(self, error: str, start_time: float) -> Dict[str, Any]:
        """Create error result."""
        return {
            "tool": "smartguard",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "error": error,
            "execution_time": time.time() - start_time
        }

    def _get_cached(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age = time.time() - cache_file.stat().st_mtime
            if age > 86400:  # 24 hours
                cache_file.unlink()
                return None

            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"Cache write error: {e}")

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if adapter can analyze the contract."""
        return Path(contract_path).suffix == '.sol'

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 600,
            "model": "deepseek-coder",
            "max_tokens": 8000,
            "similarity_threshold": 0.6
        }


__all__ = ["SmartGuardAdapter"]
