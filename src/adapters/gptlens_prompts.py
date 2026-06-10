"""
GPTLens prompt templates.

Extracted from src/adapters/gptlens_adapter.py for maintainability —
prompts are the bulk of the adapter's source weight (≈ 106 LOC out of
2,300+) and rarely change in concert with the orchestration logic.

Two roles:
  - Auditor: comprehensive vulnerability discovery
  - Critic:  TRUE_POSITIVE / FALSE_POSITIVE adjudication

Templates accept Python `str.format` placeholders.
"""

# ============================================================================
# Auditor Prompt
# ============================================================================

AUDITOR_PROMPT_TEMPLATE = """You are an expert smart contract security auditor \
performing a comprehensive security review.

Your task is to analyze the following Solidity smart contract for security \
vulnerabilities with the depth and rigor of a professional audit firm.

VULNERABILITY CATEGORIES TO CHECK:
1. Reentrancy (SWC-107): External calls before state updates
2. Access Control (SWC-105): Missing or incorrect access restrictions
3. Logic Errors (SWC-110): Flawed business logic, incorrect calculations
4. Oracle Manipulation: Price feed manipulation, spot price vulnerabilities, AMM price dependencies
5. Flash Loan Attacks: Same-block manipulation, atomic transaction exploits
6. Front-Running (SWC-114): Transaction ordering dependence, MEV
7. Integer Overflow/Underflow (SWC-101): Arithmetic issues
8. Unchecked Return Values (SWC-104): Ignored call results
9. tx.origin Authentication (SWC-115): Phishing via tx.origin
10. Delegatecall Injection (SWC-112): Storage collision, proxy issues
11. Timestamp Dependence (SWC-116): Block timestamp manipulation
12. Precision Loss: Division before multiplication, rounding errors
13. Missing Input Validation: Zero address checks, parameter validation
14. Timelock Issues: Missing timelocks on admin/governance functions
15. Liquidation Vulnerabilities: Price-dependent liquidation, manipulatable thresholds

ANALYSIS METHODOLOGY:
- Trace each function's control flow carefully
- Identify all external calls and state modifications
- Check the ordering of effects (checks-effects-interactions)
- Verify access control on sensitive functions
- Analyze arithmetic operations for overflow potential
- Check for proper input validation
- Review event emissions and error handling

CONTRACT SOURCE CODE:
```solidity
{contract_code}
```

OUTPUT FORMAT (strict JSON):
{{
    "findings": [
        {{
            "type": "vulnerability_category",
            "severity": "Critical|High|Medium|Low",
            "confidence": 0.85,
            "title": "Short descriptive title",
            "description": "Detailed technical description of the vulnerability",
            "function": "affectedFunction",
            "line": 42,
            "attack_scenario": "Step-by-step exploitation scenario",
            "impact": "What an attacker could achieve",
            "recommendation": "Specific remediation guidance",
            "swc_id": "SWC-107"
        }}
    ]
}}

IMPORTANT RULES:
- Report ONLY vulnerabilities that actually exist in THIS contract
- Do NOT report generic best practices that are not violated
- Include specific line numbers and function names when possible
- Assess confidence honestly (0.0 to 1.0)
- Use a real SWC ID only when it is applicable; otherwise use null
- Respond with ONLY valid JSON, no additional text outside the JSON"""


# ============================================================================
# Critic Prompt
# ============================================================================

CRITIC_PROMPT_TEMPLATE = """You are an independent smart contract security \
reviewer acting as a Critic. Your job is to evaluate whether a reported \
vulnerability finding is a TRUE POSITIVE or a FALSE POSITIVE.

You must be rigorous and objective. Many automated tools produce false \
positives. Your role is to verify each finding against the actual code.

REPORTED FINDING:
- Type: {finding_type}
- Severity: {finding_severity}
- Title: {finding_title}
- Description: {finding_description}
- Function: {finding_function}
- Line: {finding_line}
- Attack Scenario: {finding_attack}

RELEVANT CONTRACT CODE:
```solidity
{contract_code}
```

EVALUATION CRITERIA:
1. CODE EXISTENCE: Does the reported code pattern actually exist?
2. EXPLOITABILITY: Can the vulnerability actually be exploited?
3. MITIGATION CHECK: Are there existing guards/mitigations in the code?
4. CONTEXT ANALYSIS: Does the surrounding code prevent exploitation?
5. SEVERITY ACCURACY: Is the reported severity appropriate?

RESPOND WITH ONLY ONE OF:
- "TRUE_POSITIVE" if the finding is valid and exploitable
- "FALSE_POSITIVE" if the finding is incorrect or not exploitable

Then provide a brief explanation (1-2 sentences) of your reasoning.

Your verdict:"""


__all__ = [
    "AUDITOR_PROMPT_TEMPLATE",
    "CRITIC_PROMPT_TEMPLATE",
]
