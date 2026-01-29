"""
LLM-SmartAudit Agent Integration for MIESC

Integration of LLM-SmartAudit (ArXiv 2410.09381) methodology:
- Multi-agent conversational framework
- Contract analysis, vulnerability identification, comprehensive report
- Uses LLM reasoning for context-aware auditing

Paper: https://arxiv.org/abs/2410.09381
Repository: https://github.com/Marvinmw/LLM-SmartAudit (Not public yet as of Oct 2024)
"""

from src.agents.base_agent import BaseAgent
from typing import List, Dict, Any
import os
import time

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load environment variables from .env
except ImportError:
    pass  # dotenv not installed, environment variables must be set manually

class LLMSmartAuditAgent(BaseAgent):
    """
    LLM-SmartAudit integration: Multi-agent conversational audit framework.

    Capabilities:
    - Contract analysis (structure, logic, patterns)
    - Vulnerability identification (3 sub-agents)
    - Comprehensive report generation

    Context Types Published:
    - llm_smartaudit_findings: Unified findings
    - llm_smartaudit_analysis: Contract analysis
    - llm_smartaudit_report: Comprehensive report
    """

    def __init__(self, openai_api_key: str = None):
        super().__init__(
            agent_name="LLMSmartAuditAgent",
            capabilities=[
                "multi_agent_conversation",
                "contract_analysis",
                "vulnerability_identification",
                "comprehensive_reporting"
            ],
            agent_type="ai"
        )
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")

        if not self.openai_api_key:
            print("⚠️  Warning: OPENAI_API_KEY not set. LLM-SmartAudit will run in demo mode.")
            self.llm_enabled = False
        else:
            self.llm_enabled = True
            try:
                import openai
                openai.api_key = self.openai_api_key
                self.openai = openai
            except ImportError:
                print("⚠️  Warning: openai package not installed. Install with: pip install openai")
                self.llm_enabled = False

    def get_context_types(self) -> List[str]:
        return [
            "llm_smartaudit_findings",
            "llm_smartaudit_analysis",
            "llm_smartaudit_report"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run LLM-SmartAudit multi-agent conversation.

        Args:
            contract_path: Path to .sol file
            **kwargs: Optional parameters
                - use_llm: bool (default True if API key available)

        Returns:
            Dict with findings, analysis, and report
        """
        start_time = time.time()

        print(f"\n🔍 LLM-SmartAudit Analysis Starting...")
        print(f"   Contract: {contract_path}")
        print(f"   LLM Enabled: {self.llm_enabled}")

        # Read contract
        with open(contract_path, 'r') as f:
            contract_code = f.read()

        # Sub-agent 1: Contract Analysis
        print("\n[1/3] Contract Analysis Agent...")
        contract_analysis = self._contract_analysis_agent(contract_code)

        # Sub-agent 2: Vulnerability Identification
        print("[2/3] Vulnerability Identification Agent...")
        vulnerabilities = self._vulnerability_identification_agent(
            contract_code, contract_analysis
        )

        # Sub-agent 3: Comprehensive Report
        print("[3/3] Comprehensive Report Agent...")
        report = self._comprehensive_report_agent(
            contract_code, contract_analysis, vulnerabilities
        )

        print("\n✅ Analysis complete")

        # Format findings
        findings = self._format_findings(vulnerabilities)

        execution_time = time.time() - start_time

        return {
            "llm_smartaudit_findings": findings,
            "llm_smartaudit_analysis": contract_analysis,
            "llm_smartaudit_report": report,
            "execution_time": execution_time,
            "tool_version": "llm-smartaudit-miesc-1.0"
        }

    def _contract_analysis_agent(self, contract_code: str) -> Dict[str, Any]:
        """Sub-agent 1: Analyze contract structure and logic"""

        if self.llm_enabled:
            prompt = f"""You are a smart contract auditor. Analyze this Solidity contract and provide:

1. **Contract Structure**: Main contracts, inheritance, external calls
2. **Key Functions**: Critical functions and their purpose
3. **State Variables**: Important state management
4. **Patterns Used**: Design patterns (e.g., withdraw pattern, checks-effects-interactions)
5. **Potential Risk Areas**: Areas that need deeper analysis

Contract:
```solidity
{contract_code[:2000]}  # Limit to first 2000 chars
```

Be concise. Focus on security-relevant aspects.
"""

            try:
                response = self.openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a smart contract security expert."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=800
                )

                analysis_text = response.choices[0].message.content

                return {
                    "structure": "Analyzed with LLM",
                    "key_functions": "Analyzed with LLM",
                    "state_variables": "Analyzed with LLM",
                    "patterns": "Analyzed with LLM",
                    "risk_areas": "Analyzed with LLM",
                    "raw_analysis": analysis_text
                }
            except Exception as e:
                print(f"⚠️  LLM analysis failed: {e}")
                return self._fallback_contract_analysis(contract_code)
        else:
            return self._fallback_contract_analysis(contract_code)

    def _fallback_contract_analysis(self, contract_code: str) -> Dict[str, Any]:
        """Fallback: Basic pattern matching without LLM"""

        # Simple heuristics
        has_reentrancy_pattern = "call{value:" in contract_code
        has_external_calls = ".call" in contract_code or ".delegatecall" in contract_code
        has_payable = "payable" in contract_code
        has_onlyowner = "onlyOwner" in contract_code or "require(msg.sender == owner" in contract_code

        return {
            "structure": "Basic pattern analysis",
            "key_functions": "Detected external calls" if has_external_calls else "No external calls",
            "state_variables": "Contract has state variables",
            "patterns": {
                "reentrancy_risk": has_reentrancy_pattern,
                "external_calls": has_external_calls,
                "payable_functions": has_payable,
                "access_control": has_onlyowner
            },
            "risk_areas": ["External calls", "State changes"] if has_external_calls else ["State management"]
        }

    def _vulnerability_identification_agent(self, contract_code: str, analysis: Dict) -> List[Dict]:
        """Sub-agent 2: Identify vulnerabilities based on analysis"""

        vulnerabilities = []

        if self.llm_enabled:
            prompt = f"""Based on this contract analysis, identify specific vulnerabilities:

**Contract Analysis**:
{analysis.get('raw_analysis', 'N/A')}

**Contract Code**:
```solidity
{contract_code[:2000]}
```

For each vulnerability found, provide:
1. **Type**: (e.g., Reentrancy, Access Control, Arithmetic, etc.)
2. **Severity**: High/Medium/Low
3. **Location**: Function name and line (estimate)
4. **Description**: Brief description of the issue
5. **Impact**: Potential impact if exploited

Format as a numbered list.
"""

            try:
                response = self.openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are an expert in smart contract vulnerabilities."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=1200
                )

                vuln_text = response.choices[0].message.content

                # Parse vulnerabilities (simple parsing)
                vulnerabilities = self._parse_vulnerabilities(vuln_text)

            except Exception as e:
                print(f"⚠️  Vulnerability identification failed: {e}")
                vulnerabilities = self._fallback_vulnerability_identification(contract_code, analysis)
        else:
            vulnerabilities = self._fallback_vulnerability_identification(contract_code, analysis)

        return vulnerabilities

    def _fallback_vulnerability_identification(self, contract_code: str, analysis: Dict) -> List[Dict]:
        """Fallback: Pattern-based vulnerability detection"""

        vulnerabilities = []

        patterns = analysis.get("patterns", {})

        # Check for reentrancy
        if patterns.get("reentrancy_risk"):
            vulnerabilities.append({
                "type": "Reentrancy",
                "severity": "High",
                "location": "withdraw function (estimated)",
                "description": "External call before state update",
                "impact": "Attacker can drain contract funds"
            })

        # Check for missing access control
        if not patterns.get("access_control"):
            vulnerabilities.append({
                "type": "Missing Access Control",
                "severity": "High",
                "location": "Administrative functions",
                "description": "Functions lack proper access control",
                "impact": "Unauthorized users can call critical functions"
            })

        # Check for unchecked external calls
        if patterns.get("external_calls"):
            vulnerabilities.append({
                "type": "Unchecked Call Return Value",
                "severity": "Medium",
                "location": "External call sites",
                "description": "Return value of external calls not checked",
                "impact": "Silent failures may lead to inconsistent state"
            })

        return vulnerabilities

    def _comprehensive_report_agent(self, contract_code: str, analysis: Dict, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Sub-agent 3: Generate comprehensive audit report"""

        report = {
            "summary": f"Identified {len(vulnerabilities)} vulnerabilities",
            "contract_summary": analysis.get("structure", "N/A"),
            "vulnerabilities": vulnerabilities,
            "recommendations": self._generate_recommendations(vulnerabilities),
            "audit_methodology": "LLM-SmartAudit Multi-Agent Framework",
            "confidence": 0.85 if self.llm_enabled else 0.70
        }

        return report

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate remediation recommendations"""

        recommendations = []

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")

            if "Reentrancy" in vuln_type:
                recommendations.append("Use Checks-Effects-Interactions pattern: update state before external calls")
                recommendations.append("Consider using OpenZeppelin's ReentrancyGuard")

            elif "Access Control" in vuln_type:
                recommendations.append("Implement proper access control with modifiers (onlyOwner, onlyRole)")
                recommendations.append("Consider using OpenZeppelin's Ownable or AccessControl")

            elif "Unchecked" in vuln_type:
                recommendations.append("Always check return values of external calls")
                recommendations.append("Use SafeERC20 for token transfers")

        return list(set(recommendations))  # Remove duplicates

    def _parse_vulnerabilities(self, vuln_text: str) -> List[Dict]:
        """Parse LLM response into structured vulnerabilities"""

        vulnerabilities = []

        # Simple parsing (can be improved)
        lines = vuln_text.split("\n")
        current_vuln = {}

        for line in lines:
            line = line.strip()

            if line.startswith("1.") or line.startswith("2.") or line.startswith("3."):
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {}

            if "Type:" in line:
                current_vuln["type"] = line.split("Type:")[1].strip()
            elif "Severity:" in line:
                severity = line.split("Severity:")[1].strip()
                if "High" in severity:
                    current_vuln["severity"] = "High"
                elif "Medium" in severity:
                    current_vuln["severity"] = "Medium"
                else:
                    current_vuln["severity"] = "Low"
            elif "Location:" in line:
                current_vuln["location"] = line.split("Location:")[1].strip()
            elif "Description:" in line:
                current_vuln["description"] = line.split("Description:")[1].strip()
            elif "Impact:" in line:
                current_vuln["impact"] = line.split("Impact:")[1].strip()

        if current_vuln:
            vulnerabilities.append(current_vuln)

        return vulnerabilities

    def _format_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Format vulnerabilities into MIESC unified format"""

        findings = []

        for idx, vuln in enumerate(vulnerabilities):
            finding = {
                "id": f"LLMAUDIT-{idx+1:03d}",
                "source": "LLM-SmartAudit",
                "category": "logic" if self.llm_enabled else "pattern",
                "swc_id": self._map_to_swc(vuln.get("type", "")),
                "owasp_category": self._map_to_owasp(vuln.get("type", "")),
                "severity": vuln.get("severity", "Medium"),
                "confidence": 0.85 if self.llm_enabled else 0.70,
                "location": vuln.get("location", "Unknown"),
                "description": vuln.get("description", ""),
                "impact": vuln.get("impact", ""),
                "recommendation": self._get_recommendation(vuln.get("type", ""))
            }
            findings.append(finding)

        return findings

    def _map_to_swc(self, vuln_type: str) -> str:
        """Map vulnerability type to SWC ID"""
        mapping = {
            "Reentrancy": "SWC-107",
            "Access Control": "SWC-105",
            "Missing Access Control": "SWC-105",
            "Unchecked Call": "SWC-104",
            "Unchecked Call Return Value": "SWC-104",
            "Arithmetic": "SWC-101",
            "Integer Overflow": "SWC-101",
            "Timestamp Dependence": "SWC-116",
            "Delegatecall": "SWC-112"
        }
        return mapping.get(vuln_type, "SWC-000")

    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map to OWASP Smart Contract Top 10"""
        swc_id = self._map_to_swc(vuln_type)
        swc_to_owasp = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-105": "SC02-Access-Control",
            "SWC-104": "SC04-Unchecked-Calls",
            "SWC-101": "SC03-Arithmetic",
            "SWC-116": "SC08-Time-Manipulation",
            "SWC-112": "SC02-Access-Control"
        }
        return swc_to_owasp.get(swc_id, "SC10-Unknown")

    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            "Reentrancy": "Use Checks-Effects-Interactions pattern and ReentrancyGuard",
            "Access Control": "Implement proper access control with modifiers",
            "Missing Access Control": "Add onlyOwner or role-based access control",
            "Unchecked Call": "Always check return values of external calls",
            "Unchecked Call Return Value": "Use require() or SafeERC20 for safe transfers",
            "Arithmetic": "Use SafeMath or Solidity 0.8+ with overflow checks",
            "Integer Overflow": "Upgrade to Solidity 0.8+ or use SafeMath",
            "Timestamp Dependence": "Avoid using block.timestamp for critical logic",
            "Delegatecall": "Carefully validate delegatecall targets"
        }
        return recommendations.get(vuln_type, "Manual review recommended")


# Standalone execution
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python llm_smartaudit_agent.py <contract.sol>")
        sys.exit(1)

    contract_path = sys.argv[1]

    print("=" * 60)
    print("LLM-SmartAudit Agent - MIESC Integration")
    print("=" * 60)

    agent = LLMSmartAuditAgent()
    results = agent.run(contract_path)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    findings = results.get("llm_smartaudit_findings", [])
    analysis = results.get("llm_smartaudit_analysis", {})
    report = results.get("llm_smartaudit_report", {})

    print(f"\n📊 Analysis Summary:")
    print(f"   Contract Structure: {analysis.get('structure', 'N/A')}")
    print(f"   Risk Areas: {len(analysis.get('risk_areas', []))}")
    print(f"   Vulnerabilities: {len(findings)}")
    print(f"   Confidence: {report.get('confidence', 0)*100:.1f}%")
    print(f"   Execution Time: {results.get('execution_time', 0):.2f}s")

    if findings:
        print(f"\n🚨 Vulnerabilities Detected: {len(findings)}")
        for finding in findings:
            print(f"\n   [{finding['id']}] {finding['severity']}")
            print(f"   SWC: {finding['swc_id']} | OWASP: {finding['owasp_category']}")
            print(f"   Location: {finding['location']}")
            print(f"   {finding['description'][:80]}...")
            print(f"   Impact: {finding['impact'][:80]}...")
    else:
        print("\n✅ No vulnerabilities detected")

    print("\n" + "=" * 60)
