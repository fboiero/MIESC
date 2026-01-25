"""
Autonomous Auditor Agent for MIESC
===================================

Agent that performs complete smart contract audits autonomously.
Inspired by iAudit (2024) - LLM agents for intuitive auditing.

Audit Steps:
1. Understand contract purpose and architecture
2. Identify entry points (public/external functions)
3. Trace value flows (ETH/token movements)
4. Check access control patterns
5. Analyze state changes
6. Detect vulnerabilities
7. Validate findings with LLM
8. Generate recommendations

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Awaitable
from enum import Enum

from src.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class AuditStep(Enum):
    """Audit workflow steps."""
    UNDERSTAND_CONTRACT = "understand_contract"
    IDENTIFY_ENTRY_POINTS = "identify_entry_points"
    TRACE_VALUE_FLOWS = "trace_value_flows"
    CHECK_ACCESS_CONTROL = "check_access_control"
    ANALYZE_STATE_CHANGES = "analyze_state_changes"
    DETECT_VULNERABILITIES = "detect_vulnerabilities"
    VALIDATE_FINDINGS = "validate_findings"
    GENERATE_RECOMMENDATIONS = "generate_recommendations"


class ContractType(Enum):
    """Types of smart contracts."""
    UNKNOWN = "unknown"
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    DEX = "dex"
    LENDING = "lending"
    STAKING = "staking"
    GOVERNANCE = "governance"
    BRIDGE = "bridge"
    VAULT = "vault"
    NFT_MARKETPLACE = "nft_marketplace"
    MULTISIG = "multisig"


@dataclass
class FunctionInfo:
    """Information about a contract function."""
    name: str
    visibility: str  # public, external, internal, private
    modifiers: List[str]
    parameters: List[Dict[str, str]]
    returns: List[str]
    state_mutability: str  # view, pure, payable, nonpayable
    is_entry_point: bool
    handles_value: bool
    changes_state: bool
    code: str
    line_number: int


@dataclass
class ValueFlow:
    """Representation of a value flow in the contract."""
    source: str  # Function or address
    destination: str
    asset_type: str  # ETH, ERC20, etc.
    conditions: List[str]  # Access control conditions
    risk_level: str  # high, medium, low


@dataclass
class AuditFinding:
    """A finding from the audit."""
    id: str
    step: AuditStep
    type: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    attack_vector: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 0.7
    validated: bool = False
    validation_notes: Optional[str] = None


@dataclass
class AuditContext:
    """Context accumulated during audit."""
    contract_path: str
    contract_code: str
    contract_name: Optional[str] = None
    contract_type: ContractType = ContractType.UNKNOWN
    solidity_version: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    entry_points: List[FunctionInfo] = field(default_factory=list)
    value_flows: List[ValueFlow] = field(default_factory=list)
    state_variables: List[Dict[str, Any]] = field(default_factory=list)
    access_control_patterns: List[str] = field(default_factory=list)
    findings: List[AuditFinding] = field(default_factory=list)
    validated_findings: List[AuditFinding] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    current_step: Optional[AuditStep] = None
    completed_steps: List[AuditStep] = field(default_factory=list)
    execution_times: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReport:
    """Final audit report."""
    contract_path: str
    contract_name: str
    contract_type: str
    audit_date: str
    total_functions: int
    entry_points: int
    findings_by_severity: Dict[str, int]
    findings: List[AuditFinding]
    recommendations: List[Dict[str, Any]]
    risk_score: float
    execution_time_ms: float
    steps_completed: List[str]


# Chain of Thought prompts for each step
COT_PROMPTS = {
    AuditStep.UNDERSTAND_CONTRACT: """
Analyze this smart contract step by step:

STEP 1 - IDENTIFY THE CONTRACT TYPE:
What kind of contract is this? (DEX, lending, NFT, governance, token, etc.)

STEP 2 - UNDERSTAND THE PURPOSE:
What is the main purpose of this contract? What problem does it solve?

STEP 3 - IDENTIFY KEY COMPONENTS:
- Main state variables
- Key data structures
- External dependencies/imports

STEP 4 - ESTIMATE RISK PROFILE:
Based on what this contract does, what's the potential financial risk?

Respond in JSON format:
{
    "contract_type": "type",
    "purpose": "description",
    "components": ["component1", "component2"],
    "dependencies": ["dep1", "dep2"],
    "risk_profile": "high|medium|low",
    "risk_factors": ["factor1", "factor2"]
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.IDENTIFY_ENTRY_POINTS: """
Identify all entry points in this smart contract:

STEP 1 - FIND PUBLIC/EXTERNAL FUNCTIONS:
List all functions that can be called externally.

STEP 2 - CATEGORIZE BY PURPOSE:
- Administrative functions (onlyOwner, governance)
- User-facing functions (deposit, withdraw, swap)
- View/Read functions

STEP 3 - IDENTIFY HIGH-RISK FUNCTIONS:
Which functions handle value or change critical state?

Respond in JSON format:
{
    "entry_points": [
        {
            "name": "function_name",
            "visibility": "public|external",
            "modifiers": ["mod1", "mod2"],
            "handles_value": true|false,
            "risk_level": "high|medium|low",
            "purpose": "description"
        }
    ]
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.TRACE_VALUE_FLOWS: """
Trace all value flows (ETH and tokens) in this contract:

STEP 1 - IDENTIFY VALUE SOURCES:
Where does value enter the contract? (deposits, payments, minting)

STEP 2 - TRACE VALUE MOVEMENTS:
How does value move within the contract?

STEP 3 - IDENTIFY VALUE EXITS:
Where does value leave the contract? (withdrawals, transfers)

STEP 4 - CHECK PROTECTIONS:
Are value movements protected by access control?

Respond in JSON format:
{
    "value_flows": [
        {
            "source": "source_description",
            "destination": "destination_description",
            "asset_type": "ETH|ERC20|ERC721|etc",
            "protection": "access_control_description",
            "risk_level": "high|medium|low"
        }
    ],
    "total_value_risk": "high|medium|low"
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.CHECK_ACCESS_CONTROL: """
Analyze access control mechanisms in this contract:

STEP 1 - IDENTIFY ACCESS CONTROL PATTERNS:
What access control mechanisms are used?
- Ownable? AccessControl? Custom modifiers?

STEP 2 - CHECK CRITICAL FUNCTIONS:
Are all critical functions properly protected?

STEP 3 - IDENTIFY MISSING PROTECTIONS:
Which functions should have access control but don't?

STEP 4 - CHECK FOR PRIVILEGE ESCALATION:
Can any account gain elevated privileges unexpectedly?

Respond in JSON format:
{
    "patterns_used": ["pattern1", "pattern2"],
    "protected_functions": ["func1", "func2"],
    "unprotected_critical_functions": ["func1", "func2"],
    "privilege_escalation_risks": ["risk1", "risk2"],
    "overall_assessment": "secure|needs_improvement|vulnerable"
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.ANALYZE_STATE_CHANGES: """
Analyze state changes in critical functions:

STEP 1 - IDENTIFY STATE VARIABLES:
What are the important state variables?

STEP 2 - TRACE STATE MODIFICATIONS:
Which functions modify which state variables?

STEP 3 - CHECK ORDERING:
Are state changes done before or after external calls?
(Checks-Effects-Interactions pattern)

STEP 4 - IDENTIFY RACE CONDITIONS:
Could concurrent transactions cause issues?

Respond in JSON format:
{
    "state_variables": [
        {"name": "var", "type": "type", "critical": true|false}
    ],
    "modifications": [
        {"function": "name", "variables_modified": ["var1", "var2"]}
    ],
    "cei_violations": ["description1", "description2"],
    "race_conditions": ["description1", "description2"]
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.DETECT_VULNERABILITIES: """
Detect security vulnerabilities in this contract:

STEP 1 - CHECK FOR REENTRANCY:
- External calls followed by state changes?
- Missing reentrancy guards?

STEP 2 - CHECK FOR ACCESS CONTROL ISSUES:
- Missing modifiers on critical functions?
- Improper role management?

STEP 3 - CHECK FOR ARITHMETIC ISSUES:
- Unchecked arithmetic in Solidity < 0.8?
- Division by zero possible?

STEP 4 - CHECK FOR INPUT VALIDATION:
- Zero address checks?
- Bounds checking?

STEP 5 - CHECK FOR ORACLE/PRICE MANIPULATION:
- Spot prices used?
- Flash loan attack vectors?

Only report vulnerabilities you are CONFIDENT about.

Respond in JSON format:
{
    "vulnerabilities": [
        {
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low|info",
            "title": "Brief title",
            "description": "Detailed description",
            "location": {"function": "name", "line": number},
            "attack_vector": "How to exploit",
            "impact": "What happens if exploited",
            "confidence": 0.0-1.0
        }
    ]
}

Contract code:
```solidity
{code}
```
""",

    AuditStep.VALIDATE_FINDINGS: """
Validate the following security findings for false positives:

CONTEXT:
- Contract type: {contract_type}
- Access control patterns: {access_control}

FINDINGS TO VALIDATE:
{findings}

For each finding, determine:
1. Is this a true positive or false positive?
2. If FP, why? (safe pattern used, not exploitable, etc.)
3. If TP, confirm severity and add any additional context

Respond in JSON format:
{
    "validated_findings": [
        {
            "id": "original_id",
            "is_valid": true|false,
            "adjusted_severity": "severity",
            "validation_reason": "explanation",
            "additional_context": "any additional notes"
        }
    ]
}

Contract code for reference:
```solidity
{code}
```
""",

    AuditStep.GENERATE_RECOMMENDATIONS: """
Generate remediation recommendations for these validated findings:

FINDINGS:
{findings}

For each finding, provide:
1. Step-by-step fix instructions
2. Code example showing the fix
3. Testing suggestions

Also provide general recommendations for improving the contract's security.

Respond in JSON format:
{
    "finding_remediations": [
        {
            "finding_id": "id",
            "fix_steps": ["step1", "step2"],
            "code_example": "solidity code",
            "test_suggestions": ["test1", "test2"]
        }
    ],
    "general_recommendations": [
        {
            "category": "category",
            "recommendation": "description",
            "priority": "high|medium|low"
        }
    ]
}
""",
}


class AutonomousAuditorAgent(BaseAgent):
    """
    Autonomous agent that performs complete smart contract audits.

    Features:
    - Step-by-step audit workflow
    - Chain-of-Thought reasoning
    - LLM-based analysis at each step
    - Checkpoint/resume capability
    - Multi-layer vulnerability detection
    """

    AUDIT_STEPS = [
        AuditStep.UNDERSTAND_CONTRACT,
        AuditStep.IDENTIFY_ENTRY_POINTS,
        AuditStep.TRACE_VALUE_FLOWS,
        AuditStep.CHECK_ACCESS_CONTROL,
        AuditStep.ANALYZE_STATE_CHANGES,
        AuditStep.DETECT_VULNERABILITIES,
        AuditStep.VALIDATE_FINDINGS,
        AuditStep.GENERATE_RECOMMENDATIONS,
    ]

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder:6.7b",
        checkpoint_dir: Optional[str] = None,
        timeout: int = 120,
        verbose: bool = True,
    ):
        """
        Initialize the autonomous auditor.

        Args:
            ollama_base_url: Ollama API URL
            model: LLM model to use
            checkpoint_dir: Directory for checkpoints (optional)
            timeout: Request timeout in seconds
            verbose: Print progress messages
        """
        super().__init__(
            agent_name="AutonomousAuditor",
            capabilities=["full_audit", "cot_analysis", "vulnerability_detection"],
            agent_type="ai",
        )

        self.base_url = ollama_base_url
        self.model = model
        self.checkpoint_dir = Path(checkpoint_dir) if checkpoint_dir else None
        self.timeout = timeout
        self.verbose = verbose

        # Step handlers
        self._step_handlers: Dict[AuditStep, Callable] = {
            AuditStep.UNDERSTAND_CONTRACT: self._step_understand_contract,
            AuditStep.IDENTIFY_ENTRY_POINTS: self._step_identify_entry_points,
            AuditStep.TRACE_VALUE_FLOWS: self._step_trace_value_flows,
            AuditStep.CHECK_ACCESS_CONTROL: self._step_check_access_control,
            AuditStep.ANALYZE_STATE_CHANGES: self._step_analyze_state_changes,
            AuditStep.DETECT_VULNERABILITIES: self._step_detect_vulnerabilities,
            AuditStep.VALIDATE_FINDINGS: self._step_validate_findings,
            AuditStep.GENERATE_RECOMMENDATIONS: self._step_generate_recommendations,
        }

        if self.checkpoint_dir:
            self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"AutonomousAuditorAgent initialized with model={model}")

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Synchronous wrapper for audit.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Additional options

        Returns:
            Audit results dictionary
        """
        return asyncio.run(self.audit(contract_path, **kwargs))

    def get_context_types(self) -> List[str]:
        """Return context types this agent publishes."""
        return [
            "audit_understanding",
            "entry_points",
            "value_flows",
            "access_control",
            "state_analysis",
            "vulnerabilities",
            "validated_findings",
            "recommendations",
        ]

    async def audit(
        self,
        contract_path: str,
        resume_from: Optional[str] = None,
        skip_steps: Optional[List[AuditStep]] = None,
    ) -> AuditReport:
        """
        Perform a complete audit of the contract.

        Args:
            contract_path: Path to Solidity contract
            resume_from: Checkpoint file to resume from
            skip_steps: Steps to skip (optional)

        Returns:
            Complete audit report
        """
        start_time = time.time()

        # Initialize or restore context
        if resume_from:
            context = await self._load_checkpoint(resume_from)
        else:
            context = await self._initialize_context(contract_path)

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"MIESC Autonomous Auditor - Starting Audit")
            print(f"Contract: {contract_path}")
            print(f"{'='*60}\n")

        # Execute each step
        for step in self.AUDIT_STEPS:
            if step in context.completed_steps:
                if self.verbose:
                    print(f"[SKIP] {step.value} (already completed)")
                continue

            if skip_steps and step in skip_steps:
                if self.verbose:
                    print(f"[SKIP] {step.value} (user requested)")
                continue

            if self.verbose:
                print(f"\n[STEP] {step.value}...")

            step_start = time.time()
            context.current_step = step

            try:
                handler = self._step_handlers[step]
                context = await handler(context)
                context.completed_steps.append(step)
                context.execution_times[step.value] = time.time() - step_start

                # Save checkpoint after each step
                if self.checkpoint_dir:
                    await self._save_checkpoint(context)

                if self.verbose:
                    print(f"[DONE] {step.value} ({time.time() - step_start:.1f}s)")

            except Exception as e:
                logger.error(f"Step {step.value} failed: {e}", exc_info=True)
                if self.verbose:
                    print(f"[ERROR] {step.value}: {e}")
                # Continue with next step on error
                context.metadata[f"{step.value}_error"] = str(e)

        # Generate final report
        report = self._generate_report(context, time.time() - start_time)

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"Audit Complete!")
            print(f"Findings: {sum(report.findings_by_severity.values())}")
            print(f"Risk Score: {report.risk_score:.1f}/100")
            print(f"Time: {report.execution_time_ms/1000:.1f}s")
            print(f"{'='*60}\n")

        return report

    async def _initialize_context(self, contract_path: str) -> AuditContext:
        """Initialize audit context from contract file."""
        path = Path(contract_path)

        if not path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")

        code = path.read_text()

        # Extract basic info
        contract_name = self._extract_contract_name(code)
        solidity_version = self._extract_solidity_version(code)
        imports = self._extract_imports(code)

        return AuditContext(
            contract_path=str(path.absolute()),
            contract_code=code,
            contract_name=contract_name,
            solidity_version=solidity_version,
            imports=imports,
            metadata={
                "audit_started": datetime.utcnow().isoformat(),
                "file_size": len(code),
                "line_count": code.count('\n') + 1,
            },
        )

    async def _query_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query the LLM and parse JSON response."""
        import aiohttp

        if system_prompt is None:
            system_prompt = (
                "You are an expert smart contract security auditor. "
                "Respond only with valid JSON."
            )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096,
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status != 200:
                    raise Exception(f"LLM error: {await resp.text()}")

                data = await resp.json()
                content = data.get("message", {}).get("content", "")

                return self._parse_json_response(content)

    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """Parse JSON from LLM response."""
        try:
            # Find JSON in response
            json_start = content.find('{')
            json_end = content.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                return json.loads(content[json_start:json_end])
        except json.JSONDecodeError:
            pass

        # Return empty dict on parse failure
        return {}

    # =========================================================================
    # STEP HANDLERS
    # =========================================================================

    async def _step_understand_contract(self, context: AuditContext) -> AuditContext:
        """Step 1: Understand contract purpose and type."""
        prompt = COT_PROMPTS[AuditStep.UNDERSTAND_CONTRACT].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        # Update context
        contract_type_str = result.get("contract_type", "unknown").lower()
        try:
            context.contract_type = ContractType(contract_type_str)
        except ValueError:
            context.contract_type = ContractType.UNKNOWN

        context.metadata["purpose"] = result.get("purpose", "")
        context.metadata["components"] = result.get("components", [])
        context.metadata["risk_profile"] = result.get("risk_profile", "unknown")
        context.metadata["risk_factors"] = result.get("risk_factors", [])

        return context

    async def _step_identify_entry_points(self, context: AuditContext) -> AuditContext:
        """Step 2: Identify all entry points."""
        prompt = COT_PROMPTS[AuditStep.IDENTIFY_ENTRY_POINTS].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        for ep in result.get("entry_points", []):
            func_info = FunctionInfo(
                name=ep.get("name", "unknown"),
                visibility=ep.get("visibility", "public"),
                modifiers=ep.get("modifiers", []),
                parameters=[],
                returns=[],
                state_mutability=ep.get("state_mutability", "nonpayable"),
                is_entry_point=True,
                handles_value=ep.get("handles_value", False),
                changes_state=True,
                code="",
                line_number=0,
            )
            context.entry_points.append(func_info)
            context.functions.append(func_info)

        return context

    async def _step_trace_value_flows(self, context: AuditContext) -> AuditContext:
        """Step 3: Trace value movements."""
        prompt = COT_PROMPTS[AuditStep.TRACE_VALUE_FLOWS].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        for vf in result.get("value_flows", []):
            context.value_flows.append(ValueFlow(
                source=vf.get("source", "unknown"),
                destination=vf.get("destination", "unknown"),
                asset_type=vf.get("asset_type", "unknown"),
                conditions=[vf.get("protection", "none")],
                risk_level=vf.get("risk_level", "medium"),
            ))

        context.metadata["total_value_risk"] = result.get("total_value_risk", "unknown")

        return context

    async def _step_check_access_control(self, context: AuditContext) -> AuditContext:
        """Step 4: Check access control patterns."""
        prompt = COT_PROMPTS[AuditStep.CHECK_ACCESS_CONTROL].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        context.access_control_patterns = result.get("patterns_used", [])
        context.metadata["protected_functions"] = result.get("protected_functions", [])
        context.metadata["unprotected_critical"] = result.get("unprotected_critical_functions", [])
        context.metadata["privilege_escalation_risks"] = result.get("privilege_escalation_risks", [])
        context.metadata["access_control_assessment"] = result.get("overall_assessment", "unknown")

        # Create findings for unprotected functions
        for func in result.get("unprotected_critical_functions", []):
            context.findings.append(AuditFinding(
                id=f"access-{len(context.findings)}",
                step=AuditStep.CHECK_ACCESS_CONTROL,
                type="access-control",
                severity="high",
                title=f"Missing access control on {func}",
                description=f"Function {func} appears to be a critical function without proper access control.",
                location={"function": func},
                confidence=0.7,
            ))

        return context

    async def _step_analyze_state_changes(self, context: AuditContext) -> AuditContext:
        """Step 5: Analyze state change patterns."""
        prompt = COT_PROMPTS[AuditStep.ANALYZE_STATE_CHANGES].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        context.state_variables = result.get("state_variables", [])
        context.metadata["state_modifications"] = result.get("modifications", [])

        # Create findings for CEI violations
        for violation in result.get("cei_violations", []):
            context.findings.append(AuditFinding(
                id=f"cei-{len(context.findings)}",
                step=AuditStep.ANALYZE_STATE_CHANGES,
                type="reentrancy",
                severity="high",
                title="Checks-Effects-Interactions violation",
                description=violation,
                location={},
                confidence=0.8,
            ))

        # Create findings for race conditions
        for race in result.get("race_conditions", []):
            context.findings.append(AuditFinding(
                id=f"race-{len(context.findings)}",
                step=AuditStep.ANALYZE_STATE_CHANGES,
                type="race-condition",
                severity="medium",
                title="Potential race condition",
                description=race,
                location={},
                confidence=0.6,
            ))

        return context

    async def _step_detect_vulnerabilities(self, context: AuditContext) -> AuditContext:
        """Step 6: Comprehensive vulnerability detection."""
        prompt = COT_PROMPTS[AuditStep.DETECT_VULNERABILITIES].format(code=context.contract_code)
        result = await self._query_llm(prompt)

        for vuln in result.get("vulnerabilities", []):
            context.findings.append(AuditFinding(
                id=f"vuln-{len(context.findings)}",
                step=AuditStep.DETECT_VULNERABILITIES,
                type=vuln.get("type", "unknown"),
                severity=vuln.get("severity", "medium"),
                title=vuln.get("title", "Unknown vulnerability"),
                description=vuln.get("description", ""),
                location=vuln.get("location", {}),
                attack_vector=vuln.get("attack_vector"),
                impact=vuln.get("impact"),
                confidence=vuln.get("confidence", 0.7),
            ))

        return context

    async def _step_validate_findings(self, context: AuditContext) -> AuditContext:
        """Step 7: Validate findings for false positives."""
        if not context.findings:
            return context

        findings_json = json.dumps([
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
            }
            for f in context.findings
        ], indent=2)

        prompt = COT_PROMPTS[AuditStep.VALIDATE_FINDINGS].format(
            code=context.contract_code,
            contract_type=context.contract_type.value,
            access_control=", ".join(context.access_control_patterns),
            findings=findings_json,
        )

        result = await self._query_llm(prompt)

        # Update findings based on validation
        validation_map = {
            v["id"]: v
            for v in result.get("validated_findings", [])
        }

        for finding in context.findings:
            validation = validation_map.get(finding.id, {})
            finding.validated = validation.get("is_valid", True)
            finding.validation_notes = validation.get("validation_reason", "")

            if validation.get("adjusted_severity"):
                finding.severity = validation["adjusted_severity"]

            if finding.validated:
                context.validated_findings.append(finding)

        return context

    async def _step_generate_recommendations(self, context: AuditContext) -> AuditContext:
        """Step 8: Generate remediation recommendations."""
        if not context.validated_findings:
            return context

        findings_json = json.dumps([
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "title": f.title,
            }
            for f in context.validated_findings
        ], indent=2)

        prompt = COT_PROMPTS[AuditStep.GENERATE_RECOMMENDATIONS].format(
            findings=findings_json,
        )

        result = await self._query_llm(prompt)

        # Update findings with remediations
        remediation_map = {
            r["finding_id"]: r
            for r in result.get("finding_remediations", [])
        }

        for finding in context.validated_findings:
            remediation = remediation_map.get(finding.id, {})
            if remediation:
                finding.remediation = "\n".join(remediation.get("fix_steps", []))

        context.recommendations = result.get("general_recommendations", [])

        return context

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _extract_contract_name(self, code: str) -> Optional[str]:
        """Extract main contract name from code."""
        import re
        match = re.search(r'contract\s+(\w+)', code)
        return match.group(1) if match else None

    def _extract_solidity_version(self, code: str) -> Optional[str]:
        """Extract Solidity version from pragma."""
        import re
        match = re.search(r'pragma\s+solidity\s*[\^~>=<]*\s*([\d.]+)', code)
        return match.group(1) if match else None

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements."""
        import re
        matches = re.findall(r'import\s+["\']([^"\']+)["\']', code)
        return matches

    def _generate_report(self, context: AuditContext, execution_time: float) -> AuditReport:
        """Generate final audit report from context."""
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in context.validated_findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate risk score
        risk_score = (
            severity_counts["critical"] * 25 +
            severity_counts["high"] * 15 +
            severity_counts["medium"] * 8 +
            severity_counts["low"] * 3 +
            severity_counts["info"] * 1
        )
        risk_score = min(100, risk_score)

        return AuditReport(
            contract_path=context.contract_path,
            contract_name=context.contract_name or "Unknown",
            contract_type=context.contract_type.value,
            audit_date=datetime.utcnow().isoformat(),
            total_functions=len(context.functions),
            entry_points=len(context.entry_points),
            findings_by_severity=severity_counts,
            findings=context.validated_findings,
            recommendations=context.recommendations,
            risk_score=risk_score,
            execution_time_ms=execution_time * 1000,
            steps_completed=[s.value for s in context.completed_steps],
        )

    async def _save_checkpoint(self, context: AuditContext) -> None:
        """Save checkpoint for resume capability."""
        if not self.checkpoint_dir:
            return

        checkpoint_file = self.checkpoint_dir / f"checkpoint_{context.contract_name or 'unknown'}.json"

        checkpoint_data = {
            "contract_path": context.contract_path,
            "contract_name": context.contract_name,
            "contract_type": context.contract_type.value,
            "completed_steps": [s.value for s in context.completed_steps],
            "findings_count": len(context.findings),
            "timestamp": datetime.utcnow().isoformat(),
        }

        checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))
        logger.debug(f"Checkpoint saved: {checkpoint_file}")

    async def _load_checkpoint(self, checkpoint_path: str) -> AuditContext:
        """Load context from checkpoint."""
        # For now, just reinitialize
        # Full checkpoint restore would require serializing full context
        checkpoint_data = json.loads(Path(checkpoint_path).read_text())
        context = await self._initialize_context(checkpoint_data["contract_path"])

        # Restore completed steps
        for step_value in checkpoint_data.get("completed_steps", []):
            try:
                context.completed_steps.append(AuditStep(step_value))
            except ValueError:
                pass

        return context


# Export
__all__ = [
    "AutonomousAuditorAgent",
    "AuditStep",
    "AuditContext",
    "AuditReport",
    "AuditFinding",
    "ContractType",
]
