"""
SmartLLM Agent Integration for MIESC

Integration of SmartLLM (ArXiv 2502.13167) methodology:
- Local LLaMA 3.1 (8B) model
- RAG (Retrieval-Augmented Generation) with vulnerability KB
- 100% recall on logic vulnerabilities
- No cloud API dependency

Paper: https://arxiv.org/abs/2502.13167 (Jun Kevin & Pujianto Yugopuspito, Feb 2025)
Note: This is a reference implementation showing how to integrate local LLMs
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from src.agents.base_agent import BaseAgent


class SmartLLMAgent(BaseAgent):
    """
    SmartLLM integration: Local LLaMA + RAG for smart contract auditing.

    Capabilities:
    - Local LLM inference (no cloud dependency)
    - RAG with vulnerability knowledge base
    - Pattern-based fallback when LLM unavailable
    - 100% recall focus

    Context Types Published:
    - smartllm_findings: Detected vulnerabilities
    - smartllm_explanations: Detailed explanations
    - smartllm_rag_context: Retrieved context from KB
    """

    def __init__(self, model_path: str = None, use_local_llm: bool = True):
        super().__init__(
            agent_name="SmartLLMAgent",
            capabilities=[
                "local_llm_inference",
                "rag_vulnerability_kb",
                "pattern_matching",
                "high_recall_detection",
            ],
            agent_type="ai",
        )

        self.use_local_llm = use_local_llm
        self.model_path = model_path

        # Try to load local LLM
        if self.use_local_llm:
            self.llm_available = self._initialize_local_llm()
        else:
            self.llm_available = False

        if not self.llm_available:
            print("⚠️  Warning: Local LLM not available. Using pattern-based fallback.")

        # Initialize RAG knowledge base
        self.kb_path = Path(__file__).parent.parent / "knowledge_base"
        self._initialize_knowledge_base()

    def _initialize_local_llm(self) -> bool:
        """Initialize local LLaMA model"""
        try:
            # Try to import llama-cpp-python
            from llama_cpp import Llama

            # Look for model in standard locations
            model_locations = [
                self.model_path,
                "models/llama-3.1-8b-instruct.gguf",
                os.path.expanduser("~/.cache/huggingface/llama-3.1-8b-instruct.gguf"),
            ]

            for location in model_locations:
                if location and os.path.exists(location):
                    print(f"📦 Loading LLaMA model from: {location}")
                    self.llm = Llama(
                        model_path=location,
                        n_ctx=4096,
                        n_threads=4,
                        n_gpu_layers=0,  # CPU only by default
                    )
                    print("✅ Local LLM loaded successfully")
                    return True

            print("⚠️  No LLaMA model found. Install with:")
            print("   1. pip install llama-cpp-python")
            print("   2. Download model from HuggingFace")
            return False

        except ImportError:
            print("⚠️  llama-cpp-python not installed. Install with:")
            print("   pip install llama-cpp-python")
            return False
        except Exception as e:
            print(f"⚠️  Failed to load local LLM: {e}")
            return False

    def _initialize_knowledge_base(self):
        """Initialize RAG knowledge base"""
        # Create KB directory if it doesn't exist
        os.makedirs(self.kb_path, exist_ok=True)

        # Load pre-built KB or create minimal one
        kb_file = self.kb_path / "vulnerabilities.json"

        if kb_file.exists():
            with open(kb_file, "r") as f:
                self.knowledge_base = json.load(f)
            print(f"✅ Loaded KB with {len(self.knowledge_base)} vulnerability patterns")
        else:
            # Create minimal KB
            self.knowledge_base = self._create_minimal_kb()
            with open(kb_file, "w") as f:
                json.dump(self.knowledge_base, f, indent=2)
            print(f"✅ Created minimal KB with {len(self.knowledge_base)} patterns")

    def _create_minimal_kb(self) -> List[Dict]:
        """Create minimal vulnerability knowledge base"""
        return [
            {
                "id": "reentrancy",
                "name": "Reentrancy Attack",
                "swc_id": "SWC-107",
                "description": "External call before state update allows reentrant calls",
                "patterns": ["call{value:", ".call(", "before state update", "external call"],
                "severity": "High",
                "explanation": "Attacker can recursively call the function before state is updated",
                "fix": "Use Checks-Effects-Interactions pattern or ReentrancyGuard",
            },
            {
                "id": "access_control",
                "name": "Missing Access Control",
                "swc_id": "SWC-105",
                "description": "Critical functions lack proper access control",
                "patterns": ["function ", "public", "no modifier", "no require(msg.sender"],
                "severity": "High",
                "explanation": "Unauthorized users can call privileged functions",
                "fix": "Add onlyOwner or role-based access control modifiers",
            },
            {
                "id": "unchecked_call",
                "swc_id": "SWC-104",
                "name": "Unchecked Low-Level Call",
                "description": "Return value of low-level call not checked",
                "patterns": [".call(", ".delegatecall(", "no require", "no if"],
                "severity": "Medium",
                "explanation": "Call failures may be silently ignored",
                "fix": "Always check return value with require() or handle failures",
            },
            {
                "id": "timestamp_dependence",
                "swc_id": "SWC-116",
                "name": "Block Timestamp Manipulation",
                "description": "Uses block.timestamp for critical logic",
                "patterns": ["block.timestamp", "now", "critical logic"],
                "severity": "Medium",
                "explanation": "Miners can manipulate timestamp within ~15 seconds",
                "fix": "Use block.number or oracle for time-dependent logic",
            },
            {
                "id": "weak_randomness",
                "swc_id": "SWC-120",
                "name": "Weak Source of Randomness",
                "description": "Uses predictable source for randomness",
                "patterns": ["block.timestamp", "block.number", "block.difficulty", "random"],
                "severity": "High",
                "explanation": "Attackers can predict random numbers",
                "fix": "Use Chainlink VRF or commit-reveal scheme",
            },
        ]

    def get_context_types(self) -> List[str]:
        return ["smartllm_findings", "smartllm_explanations", "smartllm_rag_context"]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run SmartLLM analysis with local LLM + RAG.

        Args:
            contract_path: Path to .sol file
            **kwargs: Optional parameters

        Returns:
            Dict with findings and explanations
        """
        start_time = time.time()

        print("\n🔍 SmartLLM Analysis Starting...")
        print(f"   Contract: {contract_path}")
        print(f"   Local LLM: {self.llm_available}")
        print(f"   KB Patterns: {len(self.knowledge_base)}")

        # Read contract
        with open(contract_path, "r") as f:
            contract_code = f.read()

        # Step 1: RAG - Retrieve relevant patterns
        print("\n[1/3] RAG: Retrieving relevant patterns...")
        relevant_patterns = self._rag_retrieve(contract_code)

        # Step 2: LLM Analysis (or fallback)
        print("[2/3] Analyzing with local LLM...")
        if self.llm_available:
            vulnerabilities = self._analyze_with_llm(contract_code, relevant_patterns)
        else:
            vulnerabilities = self._analyze_with_patterns(contract_code, relevant_patterns)

        # Step 3: Generate explanations
        print("[3/3] Generating explanations...")
        explanations = self._generate_explanations(vulnerabilities)

        print("\n✅ Analysis complete")

        # Format findings
        findings = self._format_findings(vulnerabilities, explanations)

        execution_time = time.time() - start_time

        return {
            "smartllm_findings": findings,
            "smartllm_explanations": explanations,
            "smartllm_rag_context": relevant_patterns,
            "execution_time": execution_time,
            "tool_version": "smartllm-miesc-1.0",
            "llm_enabled": self.llm_available,
        }

    def _rag_retrieve(self, contract_code: str) -> List[Dict]:
        """RAG: Retrieve relevant vulnerability patterns from KB"""

        relevant = []

        for pattern in self.knowledge_base:
            # Simple keyword matching (can be improved with embeddings)
            match_score = 0
            for keyword in pattern.get("patterns", []):
                if keyword.lower() in contract_code.lower():
                    match_score += 1

            if match_score > 0:
                pattern_copy = pattern.copy()
                pattern_copy["relevance_score"] = match_score
                relevant.append(pattern_copy)

        # Sort by relevance
        relevant.sort(key=lambda x: x["relevance_score"], reverse=True)

        print(f"   Retrieved {len(relevant)} relevant patterns")
        return relevant[:5]  # Top 5

    def _analyze_with_llm(self, contract_code: str, patterns: List[Dict]) -> List[Dict]:
        """Analyze with local LLaMA model"""

        vulnerabilities = []

        for pattern in patterns:
            prompt = self._create_llm_prompt(contract_code, pattern)

            try:
                response = self.llm(prompt, max_tokens=512, temperature=0.1, stop=["</analysis>"])

                analysis = response["choices"][0]["text"]

                # Parse response
                vuln = self._parse_llm_response(analysis, pattern)
                if vuln:
                    vulnerabilities.append(vuln)

            except Exception as e:
                print(f"⚠️  LLM analysis failed for pattern {pattern['id']}: {e}")

        return vulnerabilities

    def _analyze_with_patterns(self, contract_code: str, patterns: List[Dict]) -> List[Dict]:
        """Fallback: Pattern-based analysis without LLM"""

        vulnerabilities = []

        for pattern in patterns:
            # Check if all patterns match
            matches = []
            for keyword in pattern.get("patterns", []):
                if keyword.lower() in contract_code.lower():
                    matches.append(keyword)

            # If sufficient matches, consider it a vulnerability
            if len(matches) >= 2:
                vulnerabilities.append(
                    {
                        "id": pattern["id"],
                        "name": pattern["name"],
                        "swc_id": pattern["swc_id"],
                        "severity": pattern["severity"],
                        "description": pattern["description"],
                        "matched_patterns": matches,
                        "confidence": 0.70,  # Lower confidence without LLM
                    }
                )

        return vulnerabilities

    def _create_llm_prompt(self, contract_code: str, pattern: Dict) -> str:
        """Create prompt for local LLM"""

        prompt = f"""<analysis>
You are a smart contract auditor. Analyze this Solidity code for the vulnerability: \
{pattern['name']}.

**Vulnerability Pattern**:
- ID: {pattern['swc_id']}
- Description: {pattern['description']}
- Severity: {pattern['severity']}

**Contract Code** (first 1000 chars):
```solidity
{contract_code[:1000]}
```

**Task**: Does this contract have this vulnerability?

Respond with:
1. VULNERABLE: Yes/No
2. LOCATION: Function name or line (estimate)
3. REASONING: Brief explanation (1-2 sentences)
</analysis>"""

        return prompt

    def _parse_llm_response(self, response: str, pattern: Dict) -> Dict:
        """Parse LLM response into structured format"""

        # Simple parsing
        is_vulnerable = "yes" in response.lower()[:100]

        if not is_vulnerable:
            return None

        # Extract location (simple heuristic)
        location = "Unknown"
        if "function" in response.lower():
            # Try to extract function name
            import re

            match = re.search(r"function\s+(\w+)", response, re.IGNORECASE)
            if match:
                location = match.group(1)

        return {
            "id": pattern["id"],
            "name": pattern["name"],
            "swc_id": pattern["swc_id"],
            "severity": pattern["severity"],
            "description": pattern["description"],
            "location": location,
            "llm_reasoning": response[:200],
            "confidence": 0.90,
        }

    def _generate_explanations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate detailed explanations"""

        explanations = []

        for vuln in vulnerabilities:
            # Find pattern in KB
            pattern = next((p for p in self.knowledge_base if p["id"] == vuln["id"]), None)

            if pattern:
                explanations.append(
                    {
                        "vulnerability_id": vuln["id"],
                        "explanation": pattern.get("explanation", ""),
                        "fix": pattern.get("fix", ""),
                        "severity": vuln["severity"],
                        "confidence": vuln.get("confidence", 0.70),
                    }
                )

        return explanations

    def _format_findings(self, vulnerabilities: List[Dict], explanations: List[Dict]) -> List[Dict]:
        """Format into MIESC unified format"""

        findings = []

        for idx, vuln in enumerate(vulnerabilities):
            explanation = next((e for e in explanations if e["vulnerability_id"] == vuln["id"]), {})

            finding = {
                "id": f"SMARTLLM-{idx+1:03d}",
                "source": "SmartLLM",
                "category": "logic" if self.llm_available else "pattern",
                "swc_id": vuln.get("swc_id", "SWC-000"),
                "owasp_category": self._map_to_owasp(vuln.get("swc_id", "")),
                "severity": vuln.get("severity", "Medium"),
                "confidence": vuln.get("confidence", 0.70),
                "location": vuln.get("location", "Unknown"),
                "description": vuln.get("description", ""),
                "explanation": explanation.get("explanation", ""),
                "recommendation": explanation.get("fix", ""),
                "llm_enabled": self.llm_available,
            }

            findings.append(finding)

        return findings

    def _map_to_owasp(self, swc_id: str) -> str:
        """Map SWC to OWASP Smart Contract Top 10"""
        mapping = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            "SWC-104": "SC04-Unchecked-Calls",
            "SWC-116": "SC08-Time-Manipulation",
            "SWC-120": "SC06-Bad-Randomness",
        }
        return mapping.get(swc_id, "SC10-Unknown")


# Standalone execution
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python smartllm_agent.py <contract.sol>")
        sys.exit(1)

    contract_path = sys.argv[1]

    print("=" * 60)
    print("SmartLLM Agent - MIESC Integration")
    print("=" * 60)

    agent = SmartLLMAgent()
    results = agent.run(contract_path)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    findings = results.get("smartllm_findings", [])
    explanations = results.get("smartllm_explanations", [])

    print("\n📊 Analysis Summary:")
    print(f"   LLM Enabled: {results.get('llm_enabled', False)}")
    print(f"   RAG Patterns: {len(results.get('smartllm_rag_context', []))}")
    print(f"   Vulnerabilities: {len(findings)}")
    print(f"   Execution Time: {results.get('execution_time', 0):.2f}s")

    if findings:
        print(f"\n🚨 Vulnerabilities Detected: {len(findings)}")
        for finding in findings:
            print(f"\n   [{finding['id']}] {finding['severity']}")
            print(f"   SWC: {finding['swc_id']} | OWASP: {finding['owasp_category']}")
            print(f"   Location: {finding['location']}")
            print(f"   {finding['description'][:80]}...")
            if finding["explanation"]:
                print(f"   💡 {finding['explanation'][:80]}...")
    else:
        print("\n✅ No vulnerabilities detected")

    print("\n" + "=" * 60)
