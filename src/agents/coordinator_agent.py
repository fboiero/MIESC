"""
Coordinator Agent for MCP Architecture

LLM-based orchestrator that coordinates multi-agent audit workflow
Implements intelligent task delegation and workflow optimization
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


class CoordinatorAgent(BaseAgent):
    """
    Coordinator Agent (LLM-based orchestrator)

    Capabilities:
    - Intelligent task delegation to specialized agents
    - Workflow optimization based on contract complexity
    - Adaptive layer prioritization
    - Real-time progress monitoring
    - Audit trail generation for compliance

    Subscribes to:
    - All context types from all agents (monitoring)
    - "agent_error": Error notifications

    Published Context Types:
    - "audit_plan": Execution plan for audit
    - "audit_progress": Real-time progress updates
    - "audit_summary": Final audit report
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        super().__init__(
            agent_name="CoordinatorAgent",
            capabilities=[
                "task_delegation",
                "workflow_optimization",
                "progress_monitoring",
                "audit_orchestration",
                "compliance_reporting",
                "intelligent_agent_selection",
                "adaptive_strategy",
                "resource_optimization"
            ],
            agent_type="coordinator"
        )

        self.model = model  # Updated to GPT-4o for better reasoning
        self.api_key = api_key
        if api_key and OPENAI_AVAILABLE:
            openai.api_key = api_key

        # Track active agents
        self.active_agents = {}
        self.audit_state = {
            "status": "idle",
            "current_phase": None,
            "completed_phases": [],
            "total_findings": 0,
            "contract_complexity": "unknown",
            "risk_level": "unknown",
            "optimization_history": []
        }

        # Learning from previous audits
        self.audit_history = []

        # Subscribe to all agent outputs for monitoring
        self.subscribe_to(
            context_types=[
                "static_findings",
                "dynamic_findings",
                "formal_findings",
                "symbolic_findings",
                "ai_triage",
                "agent_error"
            ],
            callback=self._monitor_agent_output
        )

    def get_context_types(self) -> List[str]:
        return [
            "audit_plan",
            "audit_progress",
            "audit_summary"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Orchestrate complete multi-agent audit workflow

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - solc_version: Solidity compiler version
                - audit_scope: List of layers to execute (default: all)
                - time_budget: Maximum audit time in seconds
                - priority: "fast" | "balanced" | "comprehensive"

        Returns:
            Dictionary with orchestration results and final audit summary
        """
        results = {
            "audit_plan": {},
            "audit_progress": [],
            "audit_summary": {}
        }

        # Phase 1: Generate audit plan
        logger.info(f"CoordinatorAgent: Generating audit plan for {contract_path}")
        audit_plan = self._generate_audit_plan(contract_path, **kwargs)
        results["audit_plan"] = audit_plan
        self.publish_findings("audit_plan", audit_plan)

        # Phase 2: Execute plan and monitor progress
        logger.info("CoordinatorAgent: Executing audit plan")
        execution_log = self._execute_audit_plan(audit_plan, contract_path, **kwargs)
        results["audit_progress"] = execution_log

        # Phase 3: Generate final summary
        logger.info("CoordinatorAgent: Generating audit summary")
        summary = self._generate_audit_summary(contract_path)
        results["audit_summary"] = summary
        self.publish_findings("audit_summary", summary)

        return results

    def _generate_audit_plan(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Generate intelligent audit plan based on contract analysis

        Args:
            contract_path: Path to contract
            **kwargs: Audit parameters

        Returns:
            Audit plan with layer priorities and estimated timeline
        """
        priority = kwargs.get("priority", "balanced")
        audit_scope = kwargs.get("audit_scope", ["static", "dynamic", "ai"])
        time_budget = kwargs.get("time_budget", 3600)  # 1 hour default

        # Basic plan structure
        plan = {
            "contract": contract_path,
            "priority": priority,
            "scope": audit_scope,
            "time_budget": time_budget,
            "phases": [],
            "estimated_duration": 0,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Define phases based on priority
        if priority == "fast":
            plan["phases"] = [
                {"layer": "static", "agent": "StaticAgent", "estimated_time": 60},
                {"layer": "ai", "agent": "AIAgent", "estimated_time": 120}
            ]
            plan["estimated_duration"] = 180  # 3 minutes

        elif priority == "balanced":
            plan["phases"] = [
                {"layer": "static", "agent": "StaticAgent", "estimated_time": 120},
                {"layer": "dynamic", "agent": "DynamicAgent", "estimated_time": 300},
                {"layer": "ai", "agent": "AIAgent", "estimated_time": 180}
            ]
            plan["estimated_duration"] = 600  # 10 minutes

        elif priority == "comprehensive":
            plan["phases"] = [
                {"layer": "static", "agent": "StaticAgent", "estimated_time": 180},
                {"layer": "dynamic", "agent": "DynamicAgent", "estimated_time": 600},
                {"layer": "runtime", "agent": "RuntimeAgent", "estimated_time": 300},
                {"layer": "symbolic", "agent": "SymbolicAgent", "estimated_time": 900},
                {"layer": "formal", "agent": "FormalAgent", "estimated_time": 1200},
                {"layer": "ai", "agent": "AIAgent", "estimated_time": 300}
            ]
            plan["estimated_duration"] = 3480  # ~58 minutes

        # Use LLM to optimize plan if API key available
        if OPENAI_AVAILABLE and self.api_key:
            try:
                optimized_plan = self._llm_optimize_plan(plan, contract_path)
                plan = optimized_plan
            except Exception as e:
                logger.warning(f"CoordinatorAgent: LLM optimization failed: {e}")

        return plan

    def _llm_optimize_plan(self, base_plan: Dict[str, Any],
                          contract_path: str) -> Dict[str, Any]:
        """
        Use LLM to optimize audit plan based on contract characteristics

        Args:
            base_plan: Base audit plan
            contract_path: Path to contract

        Returns:
            Optimized audit plan
        """
        # Read contract for context
        try:
            with open(contract_path, 'r') as f:
                contract_source = f.read()[:2000]  # Truncate
        except Exception as e:
            logger.error(f"CoordinatorAgent: Could not read contract: {e}")
            return base_plan

        prompt = f"""
You are an expert smart contract auditor coordinating a security audit.

Contract Source:
```solidity
{contract_source}
```

Base Audit Plan:
{json.dumps(base_plan, indent=2)}

Analyze the contract and optimize the audit plan:
1. Identify contract complexity and risk factors
2. Prioritize layers based on observed patterns (e.g., if complex state, prioritize formal verification)
3. Suggest optimal tool ordering
4. Estimate realistic execution times

Respond in JSON format with optimized plan:
{{
  "complexity_assessment": "low|medium|high|critical",
  "risk_factors": ["..."],
  "recommended_phases": [
    {{"layer": "static", "agent": "StaticAgent", "estimated_time": 120, "priority": "critical"}}
  ],
  "estimated_duration": 600,
  "justification": "..."
}}
"""

        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a smart contract audit coordinator optimizing audit workflows."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500
            )

            optimized = json.loads(response.choices[0].message.content)

            # Merge optimizations into base plan
            if "recommended_phases" in optimized:
                base_plan["phases"] = optimized["recommended_phases"]
            if "estimated_duration" in optimized:
                base_plan["estimated_duration"] = optimized["estimated_duration"]

            base_plan["complexity_assessment"] = optimized.get("complexity_assessment", "medium")
            base_plan["risk_factors"] = optimized.get("risk_factors", [])
            base_plan["optimization_justification"] = optimized.get("justification", "")

            return base_plan

        except Exception as e:
            logger.error(f"CoordinatorAgent: LLM optimization error: {e}")
            return base_plan

    def _analyze_contract_complexity(self, contract_source: str) -> Dict[str, Any]:
        """
        Analyze contract complexity to guide agent selection

        Args:
            contract_source: Contract source code

        Returns:
            Complexity analysis dictionary
        """
        if not OPENAI_AVAILABLE or not self.api_key:
            return {"complexity": "medium", "risk_factors": []}

        try:
            prompt = f"""
Analyze this smart contract's complexity to guide security analysis strategy:

```solidity
{contract_source[:3000]}
```

Assess:
1. **Complexity Level**: Low/Medium/High/Critical
2. **Risk Factors**: What makes this contract risky?
3. **Recommended Analysis Depth**: Fast/Standard/Comprehensive/Exhaustive
4. **Key Areas of Concern**: What should auditors focus on?
5. **Optimal Tool Selection**: Which security tools are most relevant?

Respond in JSON:
{{
  "complexity": "low|medium|high|critical",
  "risk_score": 0-100,
  "risk_factors": ["factor1", "..."],
  "recommended_depth": "fast|standard|comprehensive|exhaustive",
  "key_concerns": ["concern1", "..."],
  "recommended_tools": [
    {{"tool": "Slither", "priority": "critical", "reason": "..."}},
    {{"tool": "Mythril", "priority": "high", "reason": "..."}}
  ],
  "estimated_analysis_time": "minutes|hours",
  "requires_formal_verification": true|false
}}
"""

            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a smart contract complexity analyzer guiding security audit strategy."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )

            analysis = json.loads(response.choices[0].message.content)

            # Store for adaptive planning
            self.audit_state["contract_complexity"] = analysis["complexity"]
            self.audit_state["risk_level"] = analysis.get("risk_score", 50)

            return analysis

        except Exception as e:
            logger.error(f"CoordinatorAgent: Complexity analysis failed: {e}")
            return {"complexity": "medium", "risk_factors": [], "recommended_depth": "standard"}

    def _adaptive_agent_selection(self, complexity_analysis: Dict[str, Any],
                                  time_budget: int) -> List[Dict[str, Any]]:
        """
        Intelligently select agents based on contract complexity and constraints

        Args:
            complexity_analysis: Result from _analyze_contract_complexity
            time_budget: Available time in seconds

        Returns:
            List of selected agents with priority and rationale
        """
        complexity = complexity_analysis.get("complexity", "medium")
        risk_score = complexity_analysis.get("risk_score", 50)
        recommended_tools = complexity_analysis.get("recommended_tools", [])

        selected_agents = []

        # Always include static analysis (fast)
        selected_agents.append({
            "agent": "StaticAgent",
            "layer": "static",
            "priority": "critical",
            "estimated_time": 120,
            "reason": "Fast baseline analysis required for all contracts"
        })

        # Add agents based on complexity
        if complexity in ["high", "critical"] or risk_score > 70:
            # High-risk contracts need comprehensive analysis
            selected_agents.extend([
                {
                    "agent": "DynamicAgent",
                    "layer": "dynamic",
                    "priority": "critical",
                    "estimated_time": 600,
                    "reason": "High complexity requires dynamic testing"
                },
                {
                    "agent": "SymbolicAgent",
                    "layer": "symbolic",
                    "priority": "high",
                    "estimated_time": 900,
                    "reason": "Symbolic execution for edge case discovery"
                },
                {
                    "agent": "FormalAgent",
                    "layer": "formal",
                    "priority": "high",
                    "estimated_time": 1200,
                    "reason": "Formal verification for high-risk logic"
                }
            ])
        elif complexity == "medium" or 40 <= risk_score <= 70:
            # Medium complexity: standard analysis
            selected_agents.extend([
                {
                    "agent": "DynamicAgent",
                    "layer": "dynamic",
                    "priority": "high",
                    "estimated_time": 300,
                    "reason": "Standard dynamic testing"
                },
                {
                    "agent": "SymbolicAgent",
                    "layer": "symbolic",
                    "priority": "medium",
                    "estimated_time": 600,
                    "reason": "Limited symbolic execution"
                }
            ])
        # Low complexity: fast analysis only (StaticAgent already included)

        # Always add AI triage
        selected_agents.append({
            "agent": "AIAgent",
            "layer": "ai",
            "priority": "critical",
            "estimated_time": 180,
            "reason": "AI triage to reduce false positives"
        })

        # Add InterpretationAgent for better understanding
        selected_agents.append({
            "agent": "InterpretationAgent",
            "layer": "interpretation",
            "priority": "high",
            "estimated_time": 120,
            "reason": "Enhanced finding interpretation and correlation"
        })

        # Add RecommendationAgent for next steps
        selected_agents.append({
            "agent": "RecommendationAgent",
            "layer": "recommendation",
            "priority": "high",
            "estimated_time": 60,
            "reason": "Generate actionable next steps"
        })

        # Filter by time budget
        total_time = sum(a["estimated_time"] for a in selected_agents)
        if total_time > time_budget:
            # Prioritize critical agents
            selected_agents = [a for a in selected_agents if a["priority"] == "critical"]
            logger.warning(
                f"CoordinatorAgent: Time budget exceeded ({total_time}s > {time_budget}s), "
                f"prioritizing critical agents only"
            )

        return selected_agents

    def _learn_from_audit(self, audit_results: Dict[str, Any]) -> None:
        """
        Learn from completed audit to improve future orchestration

        Args:
            audit_results: Complete audit results
        """
        audit_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "complexity": self.audit_state.get("contract_complexity"),
            "risk_level": self.audit_state.get("risk_level"),
            "agents_used": list(self.active_agents.keys()),
            "total_findings": self.audit_state.get("total_findings"),
            "execution_time": audit_results.get("total_time", 0),
            "optimization_success": True  # Could be more sophisticated
        }

        self.audit_history.append(audit_record)

        # Keep only last 100 audits
        if len(self.audit_history) > 100:
            self.audit_history = self.audit_history[-100:]

        logger.info(
            f"CoordinatorAgent: Learned from audit - "
            f"{audit_record['total_findings']} findings in {audit_record['execution_time']:.2f}s"
        )

    def _execute_audit_plan(self, plan: Dict[str, Any], contract_path: str,
                           **kwargs) -> List[Dict[str, Any]]:
        """
        Execute audit plan and track progress

        Args:
            plan: Audit plan from _generate_audit_plan
            contract_path: Path to contract
            **kwargs: Additional parameters

        Returns:
            List of execution events with timestamps
        """
        execution_log = []

        for phase in plan["phases"]:
            phase_start = datetime.utcnow()

            event = {
                "phase": phase["layer"],
                "agent": phase["agent"],
                "status": "started",
                "timestamp": phase_start.isoformat() + "Z"
            }
            execution_log.append(event)

            # Publish progress update
            self.publish_findings("audit_progress", event)

            # Note: Actual agent execution would happen here
            # In POC, we log the intended execution
            logger.info(f"CoordinatorAgent: Executing {phase['agent']} (Layer: {phase['layer']})")

            # Update audit state
            self.audit_state["current_phase"] = phase["layer"]

            # Simulate completion event
            phase_end = datetime.utcnow()
            duration = (phase_end - phase_start).total_seconds()

            completion_event = {
                "phase": phase["layer"],
                "agent": phase["agent"],
                "status": "completed",
                "timestamp": phase_end.isoformat() + "Z",
                "duration": duration
            }
            execution_log.append(completion_event)

            self.audit_state["completed_phases"].append(phase["layer"])
            self.publish_findings("audit_progress", completion_event)

        return execution_log

    def _generate_audit_summary(self, contract_path: str) -> Dict[str, Any]:
        """
        Generate comprehensive audit summary with compliance mapping

        Args:
            contract_path: Path to audited contract

        Returns:
            Audit summary with findings, metrics, and compliance data
        """
        # Aggregate all findings from Context Bus
        all_contexts = self.aggregate_contexts([
            "static_findings",
            "dynamic_findings",
            "formal_findings",
            "symbolic_findings",
            "ai_triage"
        ])

        total_findings = 0
        findings_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        findings_by_layer = {}
        all_vulnerabilities = []

        # Process findings
        for context_type, messages in all_contexts.items():
            layer = context_type.replace("_findings", "").replace("_triage", "")
            findings_by_layer[layer] = 0

            for message in messages:
                findings = message.data if isinstance(message.data, list) else []
                findings_by_layer[layer] += len(findings)
                total_findings += len(findings)

                for finding in findings:
                    severity = finding.get("severity", "Unknown")
                    if severity in findings_by_severity:
                        findings_by_severity[severity] += 1

                    all_vulnerabilities.append(finding)

        # Generate OWASP coverage
        owasp_coverage = self._calculate_owasp_coverage(all_vulnerabilities)

        # Build summary
        summary = {
            "contract": contract_path,
            "audit_timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "findings_by_layer": findings_by_layer,
            "owasp_coverage": owasp_coverage,
            "completed_phases": self.audit_state["completed_phases"],
            "vulnerabilities": all_vulnerabilities,
            "compliance": {
                "iso27001": self._map_to_iso27001(all_vulnerabilities),
                "nist_ssdf": ["PW.8", "RV.1.1", "RV.3"],
                "owasp_sc_top10": list(owasp_coverage.keys())
            },
            "recommendations": self._generate_recommendations(findings_by_severity)
        }

        return summary

    def _calculate_owasp_coverage(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate OWASP SC Top 10 coverage

        Args:
            vulnerabilities: List of all vulnerabilities

        Returns:
            Dictionary mapping OWASP category to count
        """
        owasp_counts = {}

        for vuln in vulnerabilities:
            owasp_cat = vuln.get("owasp_category")
            if owasp_cat:
                owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1

        return owasp_counts

    def _map_to_iso27001(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Map vulnerabilities to ISO/IEC 27001:2022 controls

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            List of applicable ISO 27001 control IDs
        """
        controls = set()

        # All vulnerabilities map to A.8.8 (Technical Vulnerability Management)
        if vulnerabilities:
            controls.add("A.8.8")
            controls.add("A.8.15")  # Logging
            controls.add("A.8.16")  # Monitoring

        # Critical findings map to A.14.2.5 (Secure Engineering)
        critical = [v for v in vulnerabilities if v.get("severity") == "Critical"]
        if critical:
            controls.add("A.14.2.5")

        return sorted(list(controls))

    def _generate_recommendations(self, findings_by_severity: Dict[str, int]) -> List[str]:
        """
        Generate high-level recommendations based on findings

        Args:
            findings_by_severity: Count of findings by severity

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if findings_by_severity["Critical"] > 0:
            recommendations.append(
                "⚠️ CRITICAL: Do NOT deploy to mainnet. Address all critical vulnerabilities immediately."
            )

        if findings_by_severity["High"] > 0:
            recommendations.append(
                "⚠️ HIGH: Resolve high-severity issues before production deployment."
            )

        if findings_by_severity["Medium"] > 3:
            recommendations.append(
                "Medium-severity issues detected. Review and address before mainnet launch."
            )

        if not any(findings_by_severity.values()):
            recommendations.append(
                "✅ No vulnerabilities detected. Contract passed automated security checks."
            )
        else:
            recommendations.append(
                "Conduct manual expert review to validate automated findings."
            )

        recommendations.append(
            "Consider formal verification (Certora) for high-value contracts."
        )

        return recommendations

    def _monitor_agent_output(self, message: MCPMessage) -> None:
        """
        Callback to monitor agent outputs in real-time

        Args:
            message: MCP message from agent
        """
        logger.info(
            f"CoordinatorAgent: Monitoring {message.agent} → {message.context_type} "
            f"(data size: {len(str(message.data))} bytes)"
        )

        # Track findings
        if "_findings" in message.context_type:
            findings_count = len(message.data) if isinstance(message.data, list) else 0
            self.audit_state["total_findings"] += findings_count

        # Handle errors
        if message.context_type == "agent_error":
            logger.error(
                f"CoordinatorAgent: Detected error from {message.agent}: "
                f"{message.data.get('error_message')}"
            )

    def register_agent(self, agent_name: str, agent_instance: BaseAgent) -> None:
        """
        Register specialized agent for coordination

        Args:
            agent_name: Name of agent
            agent_instance: Agent instance
        """
        self.active_agents[agent_name] = agent_instance
        logger.info(f"CoordinatorAgent: Registered {agent_name}")

    def get_audit_status(self) -> Dict[str, Any]:
        """
        Get current audit status

        Returns:
            Dictionary with audit state
        """
        return {
            "status": self.audit_state["status"],
            "current_phase": self.audit_state["current_phase"],
            "completed_phases": self.audit_state["completed_phases"],
            "total_findings": self.audit_state["total_findings"],
            "active_agents": list(self.active_agents.keys())
        }
