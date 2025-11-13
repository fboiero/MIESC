"""
CrewAI Coordinator for MIESC

Advanced multi-agent orchestration using CrewAI framework.
Replaces/enhances the basic CoordinatorAgent with:
- Role-based agent specialization
- Collaborative workflows
- Automatic task delegation
- Hierarchical agent management
- Better result synthesis

Installation:
    pip install crewai crewai-tools
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import os

from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class CrewAICoordinator(BaseAgent):
    """
    CrewAI-based coordinator for intelligent multi-agent orchestration

    Capabilities:
    - Hierarchical agent management
    - Automatic task delegation
    - Role-based specialization
    - Collaborative analysis
    - Result synthesis

    Agents in the crew:
    - Senior Auditor: Performs initial analysis
    - Security Critic: Validates findings
    - Compliance Officer: Maps to standards
    - Report Writer: Synthesizes results

    Context Types Published:
    - crew_audit_plan: Execution plan
    - crew_findings: Aggregated findings
    - crew_summary: Final synthesis
    """

    def __init__(
        self,
        use_local_llm: bool = True,
        llm_model: str = "ollama/codellama:13b",
        verbose: bool = True
    ):
        """
        Initialize CrewAI coordinator

        Args:
            use_local_llm: Use Ollama instead of OpenAI (default: True)
            llm_model: LLM model to use (default: ollama/codellama:13b)
            verbose: Enable verbose logging (default: True)
        """
        super().__init__(
            agent_name="CrewAICoordinator",
            capabilities=[
                "hierarchical_coordination",
                "role_based_agents",
                "collaborative_analysis",
                "automatic_delegation",
                "result_synthesis"
            ],
            agent_type="coordinator"
        )

        self.use_local_llm = use_local_llm
        self.llm_model = llm_model
        self.verbose = verbose

        # Check if CrewAI is installed
        try:
            from crewai import Agent, Task, Crew, Process
            from crewai_tools import FileReadTool, tool
            self.crewai_available = True
            self.Agent = Agent
            self.Task = Task
            self.Crew = Crew
            self.Process = Process
            self.FileReadTool = FileReadTool
            self.tool_decorator = tool
        except ImportError:
            logger.warning(
                "CrewAI not installed. Install with: "
                "pip install crewai crewai-tools"
            )
            self.crewai_available = False

        # Initialize LLM
        if self.crewai_available:
            self._setup_llm()

    def _setup_llm(self):
        """Setup LLM for CrewAI"""
        if self.use_local_llm:
            try:
                from langchain_community.llms import Ollama
                self.llm = Ollama(model=self.llm_model.replace("ollama/", ""))
                logger.info(f"CrewAI using local LLM: {self.llm_model}")
            except ImportError:
                logger.warning(
                    "langchain_community not installed. "
                    "Install with: pip install langchain-community"
                )
                self.llm = None
        else:
            # Use OpenAI (requires API key)
            api_key = os.getenv('OPENAI_API_KEY')
            if api_key:
                from langchain_openai import ChatOpenAI
                self.llm = ChatOpenAI(
                    model="gpt-4",
                    temperature=0.1,
                    api_key=api_key
                )
                logger.info("CrewAI using OpenAI GPT-4")
            else:
                logger.error("OPENAI_API_KEY not set")
                self.llm = None

    def get_context_types(self) -> List[str]:
        return [
            "crew_audit_plan",
            "crew_findings",
            "crew_summary"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Coordinate multi-agent analysis using CrewAI

        Args:
            contract_path: Path to smart contract
            **kwargs: Optional parameters
                - tools_to_use: List of tools (default: ['slither', 'mythril', 'ollama'])
                - priority: 'fast'|'balanced'|'comprehensive'

        Returns:
            Dict with crew analysis results
        """
        if not self.crewai_available:
            return {
                "error": "CrewAI not installed",
                "install_command": "pip install crewai crewai-tools"
            }

        import time
        start_time = time.time()

        print(f"\n🎭 CrewAI Multi-Agent Coordination Starting...")
        print(f"   Contract: {contract_path}")
        print(f"   LLM: {self.llm_model}")

        # Create agents
        print("\n[1/4] Creating specialized agents...")
        agents = self._create_agents(contract_path)

        # Create tasks
        print("[2/4] Defining tasks...")
        tasks = self._create_tasks(agents, contract_path, **kwargs)

        # Create crew
        print("[3/4] Assembling crew...")
        crew = self._create_crew(agents, tasks)

        # Execute crew
        print("[4/4] Executing multi-agent workflow...")
        try:
            result = crew.kickoff()
            execution_time = time.time() - start_time

            print(f"\n✅ CrewAI analysis complete ({execution_time:.2f}s)")

            # Parse and structure results
            structured_results = self._structure_results(result, execution_time)

            return structured_results

        except Exception as e:
            logger.error(f"CrewAI execution error: {e}")
            return {
                "error": str(e),
                "crew_findings": [],
                "execution_time": time.time() - start_time
            }

    def _create_agents(self, contract_path: str) -> Dict[str, Any]:
        """Create specialized agents for the crew"""

        # Senior Security Auditor
        senior_auditor = self.Agent(
            role='Senior Smart Contract Security Auditor',
            goal='Identify all security vulnerabilities in the smart contract',
            backstory="""You are a veteran smart contract security auditor with 10+ years
            of experience. You've audited hundreds of DeFi protocols and have an exceptional
            track record of finding critical vulnerabilities. You use tools like Slither,
            Mythril, and your deep knowledge of Solidity to perform thorough audits.""",
            verbose=self.verbose,
            allow_delegation=True,
            llm=self.llm
        )

        # Security Critic
        security_critic = self.Agent(
            role='Security Validation Specialist',
            goal='Validate findings and eliminate false positives',
            backstory="""You are a meticulous security critic who validates audit findings.
            You have extensive experience in distinguishing real vulnerabilities from false
            positives. You challenge every finding with rigorous analysis and demand proof.""",
            verbose=self.verbose,
            allow_delegation=False,
            llm=self.llm
        )

        # Compliance Officer
        compliance_officer = self.Agent(
            role='Security Compliance Officer',
            goal='Map findings to security standards and compliance frameworks',
            backstory="""You are a compliance expert specializing in blockchain security
            standards. You know ISO 27001, OWASP, NIST, and all relevant smart contract
            security frameworks. You excel at mapping vulnerabilities to compliance requirements.""",
            verbose=self.verbose,
            allow_delegation=False,
            llm=self.llm
        )

        # Report Writer
        report_writer = self.Agent(
            role='Technical Report Writer',
            goal='Synthesize findings into clear, actionable security reports',
            backstory="""You are an expert technical writer who specializes in security
            reports. You transform complex technical findings into clear, actionable
            recommendations for developers and stakeholders.""",
            verbose=self.verbose,
            allow_delegation=False,
            llm=self.llm
        )

        return {
            'senior_auditor': senior_auditor,
            'security_critic': security_critic,
            'compliance_officer': compliance_officer,
            'report_writer': report_writer
        }

    def _create_tasks(
        self,
        agents: Dict,
        contract_path: str,
        **kwargs
    ) -> List:
        """Create tasks for the crew"""

        # Read contract
        try:
            with open(contract_path, 'r') as f:
                contract_code = f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            contract_code = "Error reading contract"

        # Task 1: Initial Audit
        audit_task = self.Task(
            description=f"""Perform a comprehensive security audit of this Solidity smart contract:

```solidity
{contract_code[:2000]}  # Truncate for context
```

Focus on:
1. Reentrancy vulnerabilities
2. Access control issues
3. Arithmetic vulnerabilities
4. Unchecked external calls
5. Logic bugs

Provide a detailed list of vulnerabilities with:
- Severity (Critical/High/Medium/Low)
- Location in code
- Description
- Potential exploit scenario""",
            agent=agents['senior_auditor'],
            expected_output="Detailed list of vulnerabilities with severity, location, and descriptions"
        )

        # Task 2: Validation
        validation_task = self.Task(
            description="""Review the audit findings and validate each vulnerability:

For each finding:
1. Verify if it's a real vulnerability or false positive
2. Assess the actual risk and impact
3. Adjust severity if needed
4. Provide confidence score (0-100%)

Remove any false positives and only report confirmed vulnerabilities.""",
            agent=agents['security_critic'],
            expected_output="Validated list of vulnerabilities with confidence scores",
            context=[audit_task]  # Depends on audit_task
        )

        # Task 3: Compliance Mapping
        compliance_task = self.Task(
            description="""Map the validated vulnerabilities to security standards:

For each vulnerability:
1. Map to SWC ID (Smart Contract Weakness Classification)
2. Map to OWASP Smart Contract Top 10
3. Map to relevant ISO 27001 controls
4. Map to NIST recommendations

Provide compliance impact assessment.""",
            agent=agents['compliance_officer'],
            expected_output="Compliance mapping for each vulnerability",
            context=[validation_task]
        )

        # Task 4: Final Report
        report_task = self.Task(
            description="""Synthesize all findings into a comprehensive security report:

Include:
1. Executive Summary
2. Total vulnerabilities by severity
3. Detailed findings with:
   - Description
   - Location
   - Severity
   - Compliance mapping
   - Remediation steps
4. Overall risk assessment
5. Actionable recommendations

Make it clear and actionable for developers.""",
            agent=agents['report_writer'],
            expected_output="Comprehensive security audit report",
            context=[validation_task, compliance_task]
        )

        return [audit_task, validation_task, compliance_task, report_task]

    def _create_crew(self, agents: Dict, tasks: List) -> Any:
        """Create and configure the crew"""

        crew = self.Crew(
            agents=list(agents.values()),
            tasks=tasks,
            process=self.Process.sequential,  # Sequential execution
            verbose=self.verbose
        )

        return crew

    def _structure_results(self, raw_result: str, execution_time: float) -> Dict[str, Any]:
        """Structure CrewAI results into MIESC format"""

        # CrewAI returns a string with the final task output
        # Parse it into structured format

        findings = self._parse_findings_from_text(raw_result)

        return {
            "crew_audit_plan": {
                "agents": ["Senior Auditor", "Security Critic", "Compliance Officer", "Report Writer"],
                "workflow": "sequential",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "crew_findings": findings,
            "crew_summary": {
                "total_findings": len(findings),
                "execution_time": execution_time,
                "llm_model": self.llm_model,
                "raw_output": raw_result[:500] + "..." if len(raw_result) > 500 else raw_result
            },
            "execution_time": execution_time
        }

    def _parse_findings_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Parse findings from CrewAI text output"""

        findings = []

        # Simple parsing - look for severity indicators
        lines = text.split('\n')

        current_finding = {}
        for line in lines:
            line = line.strip()

            # Look for severity indicators
            if 'critical' in line.lower():
                if current_finding:
                    findings.append(current_finding)
                current_finding = {'severity': 'Critical', 'description': line}
            elif 'high' in line.lower() and 'severity' in line.lower():
                if current_finding:
                    findings.append(current_finding)
                current_finding = {'severity': 'High', 'description': line}
            elif 'medium' in line.lower() and 'severity' in line.lower():
                if current_finding:
                    findings.append(current_finding)
                current_finding = {'severity': 'Medium', 'description': line}
            elif current_finding:
                # Add to current finding description
                current_finding['description'] = current_finding.get('description', '') + ' ' + line

        if current_finding:
            findings.append(current_finding)

        # Add metadata to each finding
        for idx, finding in enumerate(findings):
            finding['id'] = f"CREW-{idx+1:03d}"
            finding['source'] = 'CrewAI'
            finding['category'] = 'Multi-Agent Analysis'
            finding.setdefault('severity', 'Medium')
            finding.setdefault('description', 'Finding detected by multi-agent crew')

        return findings


# Standalone execution
if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("CrewAI Coordinator - MIESC Integration")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python crewai_coordinator.py <contract.sol>")
        sys.exit(1)

    contract_path = sys.argv[1]

    # Create coordinator
    coordinator = CrewAICoordinator(
        use_local_llm=True,
        llm_model="ollama/codellama:13b",
        verbose=True
    )

    # Run analysis
    results = coordinator.run(contract_path)

    # Display results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    findings = results.get("crew_findings", [])
    summary = results.get("crew_summary", {})

    print(f"\n📊 Summary:")
    print(f"   Total Findings: {summary.get('total_findings', 0)}")
    print(f"   Execution Time: {summary.get('execution_time', 0):.2f}s")
    print(f"   LLM Model: {summary.get('llm_model', 'unknown')}")

    if findings:
        print(f"\n🚨 Findings:")
        for finding in findings:
            print(f"\n   [{finding['id']}] {finding['severity']}")
            print(f"   {finding['description'][:100]}...")
    else:
        print("\n✅ No vulnerabilities detected by crew")

    print("\n" + "=" * 60)
