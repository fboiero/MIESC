"""
GPTScan Agent Integration for MIESC

Integration of GPTScan (ICSE 2024) methodology:
- Combines static analysis (Slither-based) with GPT-4
- Detects logic vulnerabilities beyond traditional tools
- High precision (>90%) for token contracts

Repository: https://github.com/MetaTrustLabs/GPTScan
Paper: https://gptscan.github.io/
"""

import json
import os
import subprocess
from typing import Any, Dict, List

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load environment variables from .env
except ImportError:
    pass  # dotenv not installed, environment variables must be set manually

from src.agents.base_agent import BaseAgent

class GPTScanAgent(BaseAgent):
    """
    GPTScan integration: Static analysis + GPT for logic bugs.

    Capabilities:
    - Logic vulnerability detection
    - GPT-assisted pattern analysis
    - Combined static + AI approach

    Context Types Published:
    - gptscan_findings: Unified findings
    - gptscan_logic_vulnerabilities: Logic-specific bugs
    - gptscan_analysis: Detailed GPT analysis
    """

    def __init__(self, openai_api_key: str = None):
        super().__init__(
            agent_name="GPTScanAgent",
            capabilities=[
                "logic_vulnerability_detection",
                "gpt_assisted_analysis",
                "combined_static_ai",
                "token_contract_specialization"
            ],
            agent_type="ai"
        )
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")

        if not self.openai_api_key:
            print("⚠️  Warning: OPENAI_API_KEY not set. GPTScan will run in static-only mode.")
            self.gpt_enabled = False
        else:
            self.gpt_enabled = True
            try:
                import openai
                openai.api_key = self.openai_api_key
                self.openai = openai
            except ImportError:
                print("⚠️  Warning: openai package not installed. Install with: pip install openai")
                self.gpt_enabled = False

    def get_context_types(self) -> List[str]:
        return [
            "gptscan_findings",
            "gptscan_logic_vulnerabilities",
            "gptscan_analysis"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run GPTScan analysis.

        Args:
            contract_path: Path to .sol file
            **kwargs: Optional parameters
                - use_gpt: bool (default True if API key available)
                - timeout: int (default 300s)

        Returns:
            Dict with findings and analysis
        """
        import time
        start_time = time.time()

        print("\n🔍 GPTScan Analysis Starting...")
        print(f"   Contract: {contract_path}")
        print(f"   GPT Enabled: {self.gpt_enabled}")

        # Step 1: Run static analysis (Slither-based)
        print("\n[1/3] Running static analysis...")
        static_results = self._run_static_analysis(contract_path, **kwargs)

        # Step 2: Extract suspicious patterns
        print("[2/3] Extracting patterns...")
        patterns = self._extract_patterns(static_results, contract_path)

        # Step 3: Analyze with GPT (if enabled)
        if self.gpt_enabled and kwargs.get("use_gpt", True):
            print("[3/3] Analyzing with GPT-4...")
            gpt_analysis = self._analyze_with_gpt(patterns, contract_path)
        else:
            print("[3/3] Skipping GPT analysis (not enabled)")
            gpt_analysis = {"patterns_analyzed": len(patterns), "gpt_enabled": False}

        # Step 4: Combine and format results
        print("\n✅ Analysis complete")
        findings = self._combine_results(static_results, patterns, gpt_analysis)

        execution_time = time.time() - start_time

        return {
            "gptscan_findings": findings,
            "gptscan_logic_vulnerabilities": [f for f in findings if f.get("category") == "logic"],
            "gptscan_analysis": {
                "static_issues": len(static_results.get("issues", [])),
                "patterns_extracted": len(patterns),
                "gpt_analyzed": len(gpt_analysis.get("analyses", [])) if self.gpt_enabled else 0,
                "final_findings": len(findings)
            },
            "execution_time": execution_time,
            "tool_version": "gptscan-miesc-1.0"
        }

    def _run_static_analysis(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Run Slither static analysis (GPTScan uses Slither as base)"""
        try:
            timeout = kwargs.get("timeout", 300)
            solc_version = kwargs.get("solc_version", "0.8.0")

            cmd = [
                "slither",
                contract_path,
                "--json", "-",
                "--solc", solc_version,
                "--exclude", "naming-convention,solc-version"  # Reduce noise
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.stdout:
                data = json.loads(result.stdout)

                # Extract relevant detectors (focus on logic bugs)
                issues = []
                for detector in data.get("results", {}).get("detectors", []):
                    # GPTScan focuses on these types
                    if detector.get("check") in [
                        "reentrancy-eth",
                        "arbitrary-send-eth",
                        "controlled-delegatecall",
                        "tx-origin",
                        "suicidal",
                        "unprotected-upgrade"
                    ]:
                        issues.append({
                            "check": detector["check"],
                            "impact": detector["impact"],
                            "confidence": detector["confidence"],
                            "description": detector["description"],
                            "elements": detector.get("elements", [])
                        })

                return {"issues": issues, "success": True}
            else:
                return {"issues": [], "success": False, "error": result.stderr}

        except subprocess.TimeoutExpired:
            return {"issues": [], "success": False, "error": "Timeout"}
        except FileNotFoundError:
            return {"issues": [], "success": False, "error": "Slither not found. Install with: pip install slither-analyzer"}
        except Exception as e:
            return {"issues": [], "success": False, "error": str(e)}

    def _extract_patterns(self, static_results: Dict, contract_path: str) -> List[Dict]:
        """Extract code patterns for GPT analysis"""
        patterns = []

        try:
            with open(contract_path, 'r') as f:
                code_lines = f.readlines()
        except (FileNotFoundError, IOError, PermissionError):
            return patterns

        for issue in static_results.get("issues", []):
            # Extract code context around issue
            for element in issue.get("elements", []):
                if element.get("type") == "function":
                    start_line = element.get("source_mapping", {}).get("start", 0)
                    lines = element.get("source_mapping", {}).get("lines", [])

                    if lines:
                        # Extract function context
                        snippet_start = max(0, min(lines) - 2)
                        snippet_end = min(len(code_lines), max(lines) + 2)
                        code_snippet = ''.join(code_lines[snippet_start:snippet_end])

                        patterns.append({
                            "type": issue["check"],
                            "impact": issue["impact"],
                            "function": element.get("name", "unknown"),
                            "code_snippet": code_snippet,
                            "lines": lines,
                            "description": issue["description"]
                        })

        return patterns

    def _analyze_with_gpt(self, patterns: List[Dict], contract_path: str) -> Dict[str, Any]:
        """Analyze patterns with GPT-4 (GPTScan methodology)"""
        if not self.gpt_enabled:
            return {"analyses": [], "gpt_enabled": False}

        analyses = []

        for pattern in patterns[:5]:  # Limit to 5 patterns to reduce API costs
            try:
                prompt = self._generate_gpt_prompt(pattern, contract_path)

                response = self.openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a smart contract security expert specializing in logic vulnerability detection."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=800
                )

                gpt_response = response.choices[0].message.content

                # Parse GPT response
                analysis = self._parse_gpt_response(gpt_response, pattern)
                analyses.append(analysis)

            except Exception as e:
                print(f"⚠️  GPT analysis failed for pattern: {e}")
                analyses.append({
                    "pattern": pattern["type"],
                    "error": str(e),
                    "is_vulnerability": None
                })

        return {"analyses": analyses, "gpt_enabled": True}

    def _generate_gpt_prompt(self, pattern: Dict, contract_path: str) -> str:
        """Generate GPT-4 prompt (GPTScan style)"""
        prompt = f"""Analyze this Solidity code pattern for logic vulnerabilities.

**Pattern Type**: {pattern['type']}
**Impact**: {pattern['impact']}
**Function**: {pattern['function']}

**Code**:
```solidity
{pattern['code_snippet']}
```

**Static Analysis Description**:
{pattern['description']}

**Task**: Determine if this is a true vulnerability or a false positive.

Provide your analysis in this format:
1. **Is this a real vulnerability?** (Yes/No/Uncertain)
2. **Reasoning**: Explain your analysis
3. **Severity**: If vulnerable (High/Medium/Low)
4. **Attack Scenario**: If vulnerable, describe how to exploit
5. **Fix**: Recommended remediation

Be concise but thorough.
"""
        return prompt

    def _parse_gpt_response(self, gpt_response: str, pattern: Dict) -> Dict:
        """Parse GPT response into structured format"""

        # Simple parsing (could be improved with structured outputs)
        is_vuln = "yes" in gpt_response.lower()[:200]

        # Extract severity if mentioned
        severity = "Medium"
        if "high" in gpt_response.lower():
            severity = "High"
        elif "low" in gpt_response.lower():
            severity = "Low"

        return {
            "pattern_type": pattern["type"],
            "function": pattern["function"],
            "is_vulnerability": is_vuln,
            "severity": severity if is_vuln else None,
            "gpt_analysis": gpt_response,
            "confidence": 0.90 if is_vuln else 0.85  # GPTScan reports >90% precision
        }

    def _combine_results(self, static_results: Dict, patterns: List[Dict], gpt_analysis: Dict) -> List[Dict]:
        """Combine static + GPT into unified findings"""
        findings = []

        # If GPT is enabled, use GPT analysis
        if gpt_analysis.get("gpt_enabled") and gpt_analysis.get("analyses"):
            for idx, analysis in enumerate(gpt_analysis["analyses"]):
                if analysis.get("is_vulnerability"):
                    findings.append({
                        "id": f"GPTSCAN-{len(findings)+1:03d}",
                        "source": "GPTScan",
                        "category": "logic",
                        "swc_id": self._map_to_swc(analysis["pattern_type"]),
                        "owasp_category": self._map_to_owasp(analysis["pattern_type"]),
                        "severity": analysis["severity"],
                        "confidence": analysis["confidence"],
                        "function": analysis["function"],
                        "description": f"Logic vulnerability: {analysis['pattern_type']}",
                        "gpt_reasoning": analysis["gpt_analysis"][:200] + "...",
                        "recommendation": "Review GPT analysis and apply recommended fix"
                    })
        else:
            # Fallback: Use static analysis only
            for idx, issue in enumerate(static_results.get("issues", [])):
                findings.append({
                    "id": f"GPTSCAN-{len(findings)+1:03d}",
                    "source": "GPTScan (Static Only)",
                    "category": "static",
                    "swc_id": self._map_to_swc(issue["check"]),
                    "owasp_category": self._map_to_owasp(issue["check"]),
                    "severity": self._map_severity(issue["impact"]),
                    "confidence": self._map_confidence(issue["confidence"]),
                    "description": issue["description"],
                    "recommendation": "Manual review recommended (GPT analysis not available)"
                })

        return findings

    def _map_to_swc(self, check_type: str) -> str:
        """Map check type to SWC ID"""
        mapping = {
            "reentrancy-eth": "SWC-107",
            "arbitrary-send-eth": "SWC-105",
            "controlled-delegatecall": "SWC-112",
            "tx-origin": "SWC-115",
            "suicidal": "SWC-106",
            "unprotected-upgrade": "SWC-105"
        }
        return mapping.get(check_type, "SWC-000")

    def _map_to_owasp(self, check_type: str) -> str:
        """Map to OWASP Smart Contract Top 10"""
        swc_id = self._map_to_swc(check_type)
        swc_to_owasp = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            "SWC-112": "SC02-Access-Control",
            "SWC-115": "SC02-Access-Control",
            "SWC-106": "SC02-Access-Control"
        }
        return swc_to_owasp.get(swc_id, "SC10-Unknown")

    def _map_severity(self, impact: str) -> str:
        """Map Slither impact to standard severity"""
        mapping = {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Informational"
        }
        return mapping.get(impact, "Medium")

    def _map_confidence(self, confidence: str) -> float:
        """Map Slither confidence to numeric"""
        mapping = {
            "High": 0.90,
            "Medium": 0.70,
            "Low": 0.50
        }
        return mapping.get(confidence, 0.70)


# Standalone execution
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python gptscan_agent.py <contract.sol>")
        sys.exit(1)

    contract_path = sys.argv[1]

    print("=" * 60)
    print("GPTScan Agent - MIESC Integration")
    print("=" * 60)

    agent = GPTScanAgent()
    results = agent.run(contract_path)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    findings = results.get("gptscan_findings", [])
    analysis = results.get("gptscan_analysis", {})

    print("\n📊 Analysis Summary:")
    print(f"   Static Issues Found: {analysis.get('static_issues', 0)}")
    print(f"   Patterns Extracted: {analysis.get('patterns_extracted', 0)}")
    print(f"   GPT Analyzed: {analysis.get('gpt_analyzed', 0)}")
    print(f"   Final Findings: {analysis.get('final_findings', 0)}")
    print(f"   Execution Time: {results.get('execution_time', 0):.2f}s")

    if findings:
        print(f"\n🚨 Vulnerabilities Detected: {len(findings)}")
        for finding in findings:
            print(f"\n   [{finding['id']}] {finding['severity']}")
            print(f"   SWC: {finding['swc_id']} | OWASP: {finding['owasp_category']}")
            print(f"   {finding['description'][:80]}...")
            if 'gpt_reasoning' in finding:
                print(f"   GPT: {finding['gpt_reasoning'][:80]}...")
    else:
        print("\n✅ No vulnerabilities detected")

    print("\n" + "=" * 60)
