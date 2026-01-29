"""
Recommendation Agent for MCP Architecture

Intelligent agent that analyzes audit results and recommends next steps
Provides actionable guidance for developers, auditors, and security teams
"""
import json
import logging
from typing import Dict, Any, List, Optional

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    openai = None  # type: ignore
    OPENAI_AVAILABLE = False
from datetime import datetime
from src.agents.base_agent import BaseAgent
from src.mcp.context_bus import MCPMessage

logger = logging.getLogger(__name__)


class RecommendationAgent(BaseAgent):
    """
    Recommendation Agent (Strategic Guidance)

    Capabilities:
    - Generate prioritized remediation roadmap
    - Recommend additional security measures
    - Suggest optimal tool combinations for specific issues
    - Provide deployment readiness assessment
    - Recommend testing strategies
    - Generate audit preparation checklist
    - Estimate effort for fixes
    - Suggest prevention strategies

    Subscribes to:
    - "interpreted_findings": From InterpretationAgent
    - "ai_triage": From AIAgent
    - "audit_summary": From CoordinatorAgent

    Published Context Types:
    - "next_steps": Prioritized action items
    - "remediation_roadmap": Detailed fix plan
    - "deployment_readiness": Go/no-go assessment
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        super().__init__(
            agent_name="RecommendationAgent",
            capabilities=[
                "remediation_planning",
                "deployment_readiness_assessment",
                "testing_strategy_recommendation",
                "tool_selection_guidance",
                "effort_estimation",
                "prevention_strategy"
            ],
            agent_type="recommendation"
        )

        self.model = model
        self.api_key = api_key
        if api_key and OPENAI_AVAILABLE:
            openai.api_key = api_key

        # Subscribe to analysis results
        self.subscribe_to(
            context_types=[
                "interpreted_findings",
                "ai_triage",
                "audit_summary"
            ],
            callback=self._handle_analysis_results
        )

    def get_context_types(self) -> List[str]:
        return [
            "next_steps",
            "remediation_roadmap",
            "deployment_readiness",
            "testing_recommendations",
            "prevention_strategy"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Generate comprehensive recommendations based on audit results

        Args:
            contract_path: Path to analyzed contract
            **kwargs: Optional parameters
                - findings: Analysis findings
                - audit_summary: Audit summary
                - project_context: Additional project context
                - target_environment: "mainnet"|"testnet"|"development"
                - value_at_risk: Total value secured by contract
                - timeline: Expected deployment timeline

        Returns:
            Dictionary with recommendations and action items
        """
        results = {
            "next_steps": [],
            "remediation_roadmap": {},
            "deployment_readiness": {},
            "testing_recommendations": [],
            "prevention_strategy": {},
            "estimated_effort": {},
            "risk_assessment": {}
        }

        # Collect analysis data
        findings = kwargs.get("findings", self._collect_findings())
        audit_summary = kwargs.get("audit_summary", self._get_audit_summary())
        project_context = kwargs.get("project_context", {})
        target_env = kwargs.get("target_environment", "mainnet")
        value_at_risk = kwargs.get("value_at_risk", 0)
        timeline = kwargs.get("timeline", "unknown")

        if not findings:
            logger.warning("RecommendationAgent: No findings available")
            results["next_steps"] = [{
                "priority": "High",
                "action": "Run security analysis",
                "reason": "No vulnerability scan results found"
            }]
            return results

        logger.info(f"RecommendationAgent: Generating recommendations for {len(findings)} findings")

        # Phase 1: Prioritized next steps
        next_steps = self._generate_next_steps(
            findings,
            audit_summary,
            target_env,
            value_at_risk
        )
        results["next_steps"] = next_steps

        # Phase 2: Detailed remediation roadmap
        roadmap = self._generate_remediation_roadmap(
            findings,
            timeline,
            project_context
        )
        results["remediation_roadmap"] = roadmap

        # Phase 3: Deployment readiness assessment
        readiness = self._assess_deployment_readiness(
            findings,
            target_env,
            value_at_risk
        )
        results["deployment_readiness"] = readiness

        # Phase 4: Testing recommendations
        testing_recs = self._recommend_testing_strategy(findings)
        results["testing_recommendations"] = testing_recs

        # Phase 5: Prevention strategy
        prevention = self._generate_prevention_strategy(findings)
        results["prevention_strategy"] = prevention

        # Phase 6: Effort estimation
        effort = self._estimate_effort(roadmap)
        results["estimated_effort"] = effort

        # Phase 7: Risk assessment
        risk = self._assess_risks(findings, value_at_risk, target_env)
        results["risk_assessment"] = risk

        # Publish recommendations
        self.publish_findings("next_steps", next_steps)
        self.publish_findings("remediation_roadmap", roadmap)
        self.publish_findings("deployment_readiness", readiness)

        return results

    def _handle_analysis_results(self, message: MCPMessage) -> None:
        """Handle incoming analysis results"""
        logger.info(
            f"RecommendationAgent: Received {message.context_type} "
            f"from {message.agent}"
        )

    def _collect_findings(self) -> List[Dict[str, Any]]:
        """Collect findings from context bus"""
        contexts = self.aggregate_contexts([
            "interpreted_findings",
            "ai_triage"
        ])

        all_findings = []
        for context_type, messages in contexts.items():
            for message in messages:
                if isinstance(message.data, list):
                    all_findings.extend(message.data)

        return all_findings

    def _get_audit_summary(self) -> Dict[str, Any]:
        """Get audit summary from context bus"""
        contexts = self.aggregate_contexts(["audit_summary"])

        for messages in contexts.values():
            if messages:
                return messages[-1].data  # Get latest summary

        return {}

    def _generate_next_steps(self, findings: List[Dict[str, Any]],
                            audit_summary: Dict[str, Any],
                            target_env: str,
                            value_at_risk: float) -> List[Dict[str, Any]]:
        """
        Generate prioritized next steps using LLM

        Args:
            findings: Analyzed findings
            audit_summary: Audit summary
            target_env: Target deployment environment
            value_at_risk: Value at risk

        Returns:
            List of prioritized action items
        """
        if not OPENAI_AVAILABLE or not self.api_key:
            return self._generate_basic_next_steps(findings)

        try:
            prompt = f"""
You are a smart contract security consultant providing actionable recommendations to a development team.

Audit Summary:
{json.dumps(audit_summary, indent=2)[:2000]}

Findings ({len(findings)} total):
{json.dumps(findings[:10], indent=2)}  # First 10 for context

Project Context:
- Target Environment: {target_env}
- Value at Risk: ${value_at_risk:,.2f}
- Total Findings: {len(findings)}
- Critical/High: {sum(1 for f in findings if f.get('severity', '') in ['Critical', 'High'])}

Generate a prioritized list of next steps the development team should take. Be specific, actionable, and practical.

Consider:
1. **Immediate Actions** - Critical fixes that block deployment
2. **Short-term Actions** - High-priority improvements (1-2 weeks)
3. **Medium-term Actions** - Important but not blocking (1 month)
4. **Long-term Actions** - Strategic improvements (ongoing)

For each action, include:
- Priority level (Critical/High/Medium/Low)
- Specific action to take
- Why it's important
- Estimated effort (hours or days)
- Dependencies (if any)
- Success criteria

Respond in JSON format:
{{
  "next_steps": [
    {{
      "priority": "Critical|High|Medium|Low",
      "category": "remediation|testing|audit|deployment|monitoring",
      "action": "Specific action description",
      "reason": "Why this is important",
      "estimated_effort": "2-4 hours|1-2 days|1 week|...",
      "dependencies": ["dependency1", "..."],
      "success_criteria": ["criteria1", "..."],
      "tools_needed": ["tool1", "..."],
      "assignee_role": "developer|security_engineer|auditor|devops"
    }}
  ]
}}
"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert smart contract security consultant who provides "
                            "clear, actionable recommendations to development teams. You understand "
                            "the balance between security, development velocity, and business needs."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=3000
            )

            result = json.loads(response.choices[0].message.content)
            return result["next_steps"]

        except Exception as e:
            logger.error(f"RecommendationAgent: Next steps generation failed: {e}")
            return self._generate_basic_next_steps(findings)

    def _generate_basic_next_steps(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate basic next steps without LLM"""
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")

        steps = []

        if critical_count > 0:
            steps.append({
                "priority": "Critical",
                "category": "remediation",
                "action": f"Fix {critical_count} critical vulnerabilities immediately",
                "reason": "Critical vulnerabilities can lead to fund loss or contract compromise",
                "estimated_effort": f"{critical_count * 4}-{critical_count * 8} hours"
            })

        if high_count > 0:
            steps.append({
                "priority": "High",
                "category": "remediation",
                "action": f"Address {high_count} high-severity issues",
                "reason": "High-severity issues should be fixed before deployment",
                "estimated_effort": f"{high_count * 2}-{high_count * 4} hours"
            })

        steps.append({
            "priority": "Medium",
            "category": "testing",
            "action": "Write exploit tests for identified vulnerabilities",
            "reason": "Verify that fixes actually work",
            "estimated_effort": "1-2 days"
        })

        steps.append({
            "priority": "Medium",
            "category": "audit",
            "action": "Consider professional security audit",
            "reason": "Automated tools cannot catch all vulnerabilities",
            "estimated_effort": "2-4 weeks (external audit)"
        })

        return steps

    def _generate_remediation_roadmap(self, findings: List[Dict[str, Any]],
                                     timeline: str,
                                     project_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed remediation roadmap

        Args:
            findings: Analyzed findings
            timeline: Project timeline
            project_context: Additional context

        Returns:
            Remediation roadmap dictionary
        """
        roadmap = {
            "phases": [],
            "total_findings": len(findings),
            "estimated_completion": timeline,
            "critical_path": []
        }

        # Group findings by severity
        by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
        for finding in findings:
            severity = finding.get("severity", "Medium")
            by_severity[severity].append(finding)

        # Phase 1: Critical fixes
        if by_severity["Critical"]:
            roadmap["phases"].append({
                "phase": 1,
                "name": "Critical Vulnerability Remediation",
                "duration": "1-2 weeks",
                "findings_count": len(by_severity["Critical"]),
                "findings": by_severity["Critical"][:5],  # Top 5
                "blockers": True,
                "deliverables": [
                    "All critical vulnerabilities fixed",
                    "Fix verification tests written",
                    "Re-scan showing no critical issues"
                ]
            })

        # Phase 2: High-severity fixes
        if by_severity["High"]:
            roadmap["phases"].append({
                "phase": 2,
                "name": "High-Severity Issue Resolution",
                "duration": "1-2 weeks",
                "findings_count": len(by_severity["High"]),
                "findings": by_severity["High"][:5],
                "blockers": False,
                "deliverables": [
                    "All high-severity issues addressed",
                    "Code review completed",
                    "Integration tests passing"
                ]
            })

        # Phase 3: Medium/Low improvements
        if by_severity["Medium"] or by_severity["Low"]:
            roadmap["phases"].append({
                "phase": 3,
                "name": "Code Quality Improvements",
                "duration": "2-3 weeks",
                "findings_count": len(by_severity["Medium"]) + len(by_severity["Low"]),
                "findings": (by_severity["Medium"] + by_severity["Low"])[:5],
                "blockers": False,
                "deliverables": [
                    "Medium/low issues resolved",
                    "Code quality improved",
                    "Technical debt reduced"
                ]
            })

        # Phase 4: Validation
        roadmap["phases"].append({
            "phase": len(roadmap["phases"]) + 1,
            "name": "Security Validation",
            "duration": "1 week",
            "findings_count": 0,
            "blockers": False,
            "deliverables": [
                "Full re-scan with all tools",
                "Professional audit (if applicable)",
                "Penetration testing",
                "Deployment readiness review"
            ]
        })

        return roadmap

    def _assess_deployment_readiness(self, findings: List[Dict[str, Any]],
                                    target_env: str,
                                    value_at_risk: float) -> Dict[str, Any]:
        """
        Assess whether contract is ready for deployment

        Args:
            findings: Analyzed findings
            target_env: Target environment
            value_at_risk: Value at risk

        Returns:
            Deployment readiness assessment
        """
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        medium_count = sum(1 for f in findings if f.get("severity") == "Medium")

        # Determine readiness status
        if critical_count > 0:
            status = "NOT_READY"
            blocking_issues = critical_count
            message = f"❌ NOT READY: {critical_count} critical vulnerabilities must be fixed"
        elif high_count > 0 and target_env == "mainnet":
            status = "NOT_READY"
            blocking_issues = high_count
            message = f"⚠️ NOT READY: {high_count} high-severity issues should be fixed before mainnet"
        elif high_count > 3:
            status = "RISKY"
            blocking_issues = high_count
            message = f"⚠️ RISKY: {high_count} high-severity issues detected"
        elif medium_count > 10:
            status = "NEEDS_REVIEW"
            blocking_issues = 0
            message = f"⚠️ NEEDS REVIEW: {medium_count} medium-severity issues should be reviewed"
        else:
            status = "READY"
            blocking_issues = 0
            message = "✅ READY: No blocking issues detected"

        # Risk-based recommendations
        recommendations = []

        if value_at_risk > 1_000_000 and (critical_count > 0 or high_count > 0):
            recommendations.append(
                "⚠️ High value at risk ($1M+): Professional audit STRONGLY recommended"
            )

        if target_env == "mainnet" and status != "READY":
            recommendations.append(
                "🛑 Deploy to testnet first for extensive testing"
            )

        if critical_count == 0 and high_count == 0:
            recommendations.append(
                "✅ Consider additional testing: fuzzing, formal verification, penetration testing"
            )

        return {
            "status": status,
            "blocking_issues_count": blocking_issues,
            "message": message,
            "recommendations": recommendations,
            "checklist": {
                "critical_fixed": critical_count == 0,
                "high_fixed": high_count == 0,
                "tests_written": False,  # External input needed
                "code_reviewed": False,  # External input needed
                "audit_completed": False,  # External input needed
                "testnet_deployed": target_env != "mainnet"
            },
            "risk_level": self._calculate_risk_level(
                critical_count,
                high_count,
                medium_count,
                value_at_risk
            )
        }

    def _recommend_testing_strategy(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recommend testing strategies based on findings"""
        recommendations = []

        # Check for specific vulnerability types
        has_reentrancy = any("reentrancy" in f.get("type", "").lower() for f in findings)
        has_arithmetic = any("overflow" in f.get("type", "").lower() or "underflow" in f.get("type", "").lower() for f in findings)
        has_access_control = any("access" in f.get("type", "").lower() for f in findings)

        if has_reentrancy:
            recommendations.append({
                "test_type": "Exploit Test",
                "tool": "Foundry",
                "target": "Reentrancy vulnerabilities",
                "description": "Write attack contract that attempts reentrancy",
                "priority": "Critical",
                "example_framework": "forge test"
            })

        if has_arithmetic:
            recommendations.append({
                "test_type": "Property-Based Testing",
                "tool": "Echidna",
                "target": "Arithmetic operations",
                "description": "Fuzz test arithmetic to find overflow/underflow",
                "priority": "High",
                "example_framework": "echidna-test"
            })

        if has_access_control:
            recommendations.append({
                "test_type": "Access Control Testing",
                "tool": "Foundry",
                "target": "Permission-restricted functions",
                "description": "Test all access control modifiers with unauthorized accounts",
                "priority": "High",
                "example_framework": "forge test"
            })

        # General recommendations
        recommendations.append({
            "test_type": "Integration Testing",
            "tool": "Hardhat/Foundry",
            "target": "Complete contract workflows",
            "description": "Test realistic user scenarios end-to-end",
            "priority": "Medium",
            "example_framework": "hardhat test"
        })

        recommendations.append({
            "test_type": "Formal Verification",
            "tool": "Certora",
            "target": "Critical invariants",
            "description": "Prove mathematical properties of core logic",
            "priority": "Medium",
            "example_framework": "certoraRun"
        })

        return recommendations

    def _generate_prevention_strategy(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate strategy to prevent similar issues in the future"""
        return {
            "development_practices": [
                "Use OpenZeppelin contracts for standard patterns",
                "Follow Checks-Effects-Interactions pattern",
                "Use Solidity 0.8+ for automatic overflow protection",
                "Implement comprehensive test coverage (>90%)",
                "Use static analysis in CI/CD pipeline"
            ],
            "code_review_checklist": [
                "Review all external calls for reentrancy",
                "Verify access control on privileged functions",
                "Check arithmetic operations for edge cases",
                "Validate input parameters",
                "Ensure proper event emission"
            ],
            "tooling_recommendations": [
                "Slither: Run on every commit (fast)",
                "Echidna: Run weekly (fuzzing)",
                "Mythril: Run before PR merge (symbolic execution)",
                "Certora: Run for critical functions (formal verification)"
            ],
            "training_recommendations": [
                "Study OWASP Smart Contract Top 10",
                "Review historical exploits (The DAO, Parity, etc.)",
                "Practice secure coding patterns",
                "Stay updated on latest vulnerabilities"
            ]
        }

    def _estimate_effort(self, roadmap: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate effort required for remediation"""
        total_hours = 0
        by_phase = []

        for phase in roadmap.get("phases", []):
            # Rough estimation based on findings count
            findings_count = phase.get("findings_count", 0)
            hours = findings_count * 3  # 3 hours per finding average

            total_hours += hours
            by_phase.append({
                "phase": phase["phase"],
                "name": phase["name"],
                "estimated_hours": hours,
                "estimated_days": hours / 8
            })

        return {
            "total_hours": total_hours,
            "total_days": total_hours / 8,
            "total_weeks": total_hours / 40,
            "by_phase": by_phase,
            "team_size_recommendation": "2-3 developers + 1 security engineer",
            "timeline_estimate": f"{int(total_hours / 40)}-{int(total_hours / 20)} weeks"
        }

    def _assess_risks(self, findings: List[Dict[str, Any]],
                     value_at_risk: float,
                     target_env: str) -> Dict[str, Any]:
        """Assess overall security risks"""
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")

        # Calculate risk score
        risk_score = critical_count * 10 + high_count * 5
        if value_at_risk > 10_000_000:
            risk_score *= 1.5
        if target_env == "mainnet":
            risk_score *= 1.3

        risk_level = "Low"
        if risk_score > 50:
            risk_level = "Critical"
        elif risk_score > 30:
            risk_level = "High"
        elif risk_score > 15:
            risk_level = "Medium"

        return {
            "risk_score": int(risk_score),
            "risk_level": risk_level,
            "factors": {
                "critical_vulnerabilities": critical_count,
                "high_vulnerabilities": high_count,
                "value_at_risk": value_at_risk,
                "target_environment": target_env
            },
            "recommendation": self._get_risk_recommendation(risk_level, value_at_risk)
        }

    def _get_risk_recommendation(self, risk_level: str, value_at_risk: float) -> str:
        """Get risk-based recommendation"""
        if risk_level == "Critical":
            return "🛑 CRITICAL RISK: Do NOT deploy. Fix critical issues immediately and conduct professional audit."
        elif risk_level == "High":
            return "⚠️ HIGH RISK: Address high-severity issues before mainnet deployment. Professional audit recommended."
        elif risk_level == "Medium":
            if value_at_risk > 1_000_000:
                return "⚠️ MEDIUM RISK: Consider professional audit given value at risk ($1M+)."
            return "⚠️ MEDIUM RISK: Review and address identified issues. Additional testing recommended."
        else:
            return "✅ LOW RISK: No critical issues detected. Consider additional testing for production readiness."

    def _calculate_risk_level(self, critical: int, high: int,
                             medium: int, value_at_risk: float) -> str:
        """Calculate overall risk level"""
        if critical > 0:
            return "CRITICAL"
        elif high >= 3:
            return "HIGH"
        elif high > 0 or medium > 10:
            return "MEDIUM"
        else:
            return "LOW"
