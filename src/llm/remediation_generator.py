"""
Remediation Code Generator for MIESC
=====================================

LLM-based generator for producing fixed code and remediation guidance
for detected vulnerabilities.

Features:
- Context-aware code fixes
- OpenZeppelin pattern suggestions
- Test case generation
- Diff-style output

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Remediation:
    """A remediation suggestion for a vulnerability."""
    finding_id: str
    vulnerability_type: str
    severity: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    changes_summary: List[str]
    test_suggestions: List[str]
    references: List[str]
    confidence: float
    pattern_used: Optional[str] = None


@dataclass
class RemediationResult:
    """Result from remediation generation."""
    remediations: List[Remediation]
    success_count: int
    failure_count: int
    execution_time_ms: float


# Known remediation patterns by vulnerability type
REMEDIATION_PATTERNS = {
    "reentrancy": {
        "pattern_name": "ReentrancyGuard + CEI",
        "imports": ["import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';"],
        "inheritance": "ReentrancyGuard",
        "modifier": "nonReentrant",
        "description": "Use OpenZeppelin ReentrancyGuard and Checks-Effects-Interactions pattern",
    },
    "access-control": {
        "pattern_name": "Ownable or AccessControl",
        "imports": [
            "import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';",
            "// or for role-based:",
            "import {AccessControl} from '@openzeppelin/contracts/access/AccessControl.sol';",
        ],
        "inheritance": "Ownable",
        "modifier": "onlyOwner",
        "description": "Use OpenZeppelin Ownable for single-owner or AccessControl for roles",
    },
    "unchecked-call": {
        "pattern_name": "SafeERC20",
        "imports": ["import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';"],
        "using": "using SafeERC20 for IERC20;",
        "methods": ["safeTransfer", "safeTransferFrom", "safeApprove"],
        "description": "Use SafeERC20 wrapper for all ERC20 operations",
    },
    "arithmetic": {
        "pattern_name": "Solidity 0.8+ or SafeMath",
        "description": "Upgrade to Solidity 0.8+ (built-in overflow checks) or use SafeMath for 0.7.x",
    },
    "flash-loan-attack": {
        "pattern_name": "TWAP Oracle",
        "description": "Use time-weighted average price (TWAP) instead of spot prices",
    },
    "front-running": {
        "pattern_name": "Commit-Reveal",
        "description": "Implement commit-reveal scheme to prevent front-running",
    },
}


# Remediation prompt template
REMEDIATION_PROMPT = """You are an expert Solidity security engineer. Generate a fix for this vulnerability.

## Vulnerability Details
- **Type**: {vuln_type}
- **Severity**: {severity}
- **Title**: {title}
- **Description**: {description}

## Vulnerable Code
```solidity
{vulnerable_code}
```

## Instructions
1. Generate the FIXED version of this code
2. Maintain the same business logic
3. Use OpenZeppelin contracts when applicable
4. Add necessary imports
5. Add comments explaining the fix
6. Suggest test cases to verify the fix

## Known Pattern
{pattern_info}

Respond in JSON format:
{{
    "fixed_code": "// Complete fixed Solidity code",
    "explanation": "Why this fix works",
    "changes": ["Change 1", "Change 2"],
    "imports_needed": ["import1", "import2"],
    "test_suggestions": ["Test case 1", "Test case 2"],
    "references": ["Link or reference 1"]
}}
"""


class RemediationGenerator:
    """
    Generates remediation code for vulnerabilities.

    Uses LLM to produce context-aware fixes with proper
    OpenZeppelin patterns and best practices.
    """

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder:6.7b",
        timeout: int = 120,
    ):
        """
        Initialize the remediation generator.

        Args:
            ollama_base_url: Ollama API URL
            model: Model to use for generation
            timeout: Request timeout
        """
        self.base_url = ollama_base_url
        self.model = model
        self.timeout = timeout

        logger.info(f"RemediationGenerator initialized with model={model}")

    async def generate_remediation(
        self,
        finding: Dict[str, Any],
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Remediation:
        """
        Generate remediation for a single finding.

        Args:
            finding: The vulnerability finding
            code: Full contract code or relevant snippet
            context: Additional context (contract type, etc.)

        Returns:
            Remediation object with fixed code
        """
        vuln_type = finding.get("type", "unknown").lower()
        severity = finding.get("severity", "medium")
        title = finding.get("title", finding.get("type", "Unknown"))
        description = finding.get("description", "")

        # Extract vulnerable code section
        vulnerable_code = self._extract_vulnerable_code(finding, code)

        # Get known pattern info
        pattern_info = self._get_pattern_info(vuln_type)

        # Build prompt
        prompt = REMEDIATION_PROMPT.format(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            vulnerable_code=vulnerable_code,
            pattern_info=pattern_info,
        )

        # Query LLM
        result = await self._query_llm(prompt)

        # Parse result
        fixed_code = result.get("fixed_code", vulnerable_code)
        explanation = result.get("explanation", "")
        changes = result.get("changes", [])
        imports = result.get("imports_needed", [])
        tests = result.get("test_suggestions", [])
        references = result.get("references", [])

        # Add imports to fixed code if not present
        if imports:
            imports_str = "\n".join(imports)
            if not fixed_code.startswith("//"):
                fixed_code = f"{imports_str}\n\n{fixed_code}"

        return Remediation(
            finding_id=finding.get("id", "unknown"),
            vulnerability_type=vuln_type,
            severity=severity,
            vulnerable_code=vulnerable_code,
            fixed_code=fixed_code,
            explanation=explanation,
            changes_summary=changes,
            test_suggestions=tests,
            references=references,
            confidence=0.8,
            pattern_used=REMEDIATION_PATTERNS.get(vuln_type, {}).get("pattern_name"),
        )

    async def generate_remediations(
        self,
        findings: List[Dict[str, Any]],
        code: str,
        parallel: bool = True,
        max_concurrent: int = 3,
    ) -> RemediationResult:
        """
        Generate remediations for multiple findings.

        Args:
            findings: List of vulnerability findings
            code: Full contract code
            parallel: Run in parallel (default: True)
            max_concurrent: Max concurrent requests

        Returns:
            RemediationResult with all remediations
        """
        import time
        start_time = time.time()

        remediations = []
        success_count = 0
        failure_count = 0

        if parallel and len(findings) > 1:
            # Process in batches
            semaphore = asyncio.Semaphore(max_concurrent)

            async def process_with_semaphore(finding):
                async with semaphore:
                    return await self.generate_remediation(finding, code)

            tasks = [process_with_semaphore(f) for f in findings]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Remediation generation failed: {result}")
                    failure_count += 1
                else:
                    remediations.append(result)
                    success_count += 1
        else:
            # Process sequentially
            for finding in findings:
                try:
                    remediation = await self.generate_remediation(finding, code)
                    remediations.append(remediation)
                    success_count += 1
                except Exception as e:
                    logger.warning(f"Remediation generation failed: {e}")
                    failure_count += 1

        execution_time = (time.time() - start_time) * 1000

        return RemediationResult(
            remediations=remediations,
            success_count=success_count,
            failure_count=failure_count,
            execution_time_ms=execution_time,
        )

    def generate_quick_fix(
        self,
        vuln_type: str,
        function_code: str,
    ) -> Tuple[str, str]:
        """
        Generate a quick fix using known patterns (no LLM).

        Args:
            vuln_type: Type of vulnerability
            function_code: The vulnerable function code

        Returns:
            Tuple of (fixed_code, explanation)
        """
        pattern = REMEDIATION_PATTERNS.get(vuln_type.lower())

        if not pattern:
            return function_code, "No known pattern for this vulnerability type"

        fixed = function_code
        changes = []

        # Apply pattern-specific fixes
        if vuln_type.lower() == "reentrancy":
            # Add nonReentrant modifier
            if "nonReentrant" not in fixed:
                # Find function declaration and add modifier
                fixed = re.sub(
                    r'(function\s+\w+\s*\([^)]*\)\s*(?:external|public))',
                    r'\1 nonReentrant',
                    fixed
                )
                changes.append("Added nonReentrant modifier")

        elif vuln_type.lower() == "access-control":
            # Add onlyOwner modifier
            if "onlyOwner" not in fixed and "onlyRole" not in fixed:
                fixed = re.sub(
                    r'(function\s+\w+\s*\([^)]*\)\s*(?:external|public))',
                    r'\1 onlyOwner',
                    fixed
                )
                changes.append("Added onlyOwner modifier")

        elif vuln_type.lower() == "unchecked-call":
            # Replace transfer with safeTransfer
            if "safeTransfer" not in fixed:
                fixed = re.sub(r'\.transfer\s*\(', '.safeTransfer(', fixed)
                fixed = re.sub(r'\.transferFrom\s*\(', '.safeTransferFrom(', fixed)
                changes.append("Replaced transfer with safeTransfer")

        explanation = pattern.get("description", "")
        if changes:
            explanation += "\n\nChanges made:\n" + "\n".join(f"- {c}" for c in changes)

        return fixed, explanation

    def get_pattern_template(self, vuln_type: str) -> Dict[str, Any]:
        """
        Get the remediation pattern template for a vulnerability type.

        Args:
            vuln_type: Type of vulnerability

        Returns:
            Pattern template with imports, modifiers, etc.
        """
        return REMEDIATION_PATTERNS.get(vuln_type.lower(), {})

    async def _query_llm(self, prompt: str) -> Dict[str, Any]:
        """Query the LLM and parse JSON response."""
        import aiohttp

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert Solidity security engineer. "
                        "Generate secure, production-ready code fixes. "
                        "Respond only with valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096,
            },
        }

        try:
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

        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return {}

    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """Parse JSON from LLM response."""
        try:
            json_start = content.find('{')
            json_end = content.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                return json.loads(content[json_start:json_end])
        except json.JSONDecodeError as e:
            logger.debug(f"JSON parse error: {e}")

        return {}

    def _extract_vulnerable_code(
        self,
        finding: Dict[str, Any],
        full_code: str,
    ) -> str:
        """Extract the vulnerable code section from full contract."""
        location = finding.get("location", {})

        # If snippet is provided, use it
        if finding.get("snippet"):
            return finding["snippet"]

        # Try to extract by function name
        func_name = location.get("function")
        if func_name:
            pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*\{{[^}}]*\}}'
            match = re.search(pattern, full_code, re.DOTALL)
            if match:
                return match.group(0)

        # Try to extract by line number
        line = location.get("line")
        if line and isinstance(line, int):
            lines = full_code.split('\n')
            start = max(0, line - 5)
            end = min(len(lines), line + 10)
            return '\n'.join(lines[start:end])

        # Return a relevant section (first 50 lines or contract definition)
        lines = full_code.split('\n')
        return '\n'.join(lines[:min(50, len(lines))])

    def _get_pattern_info(self, vuln_type: str) -> str:
        """Get pattern information for the vulnerability type."""
        pattern = REMEDIATION_PATTERNS.get(vuln_type.lower())

        if not pattern:
            return "No specific pattern known. Use security best practices."

        info_parts = [
            f"**Pattern**: {pattern.get('pattern_name', 'Unknown')}",
            f"**Description**: {pattern.get('description', '')}",
        ]

        if "imports" in pattern:
            info_parts.append(f"**Imports**: {', '.join(pattern['imports'][:2])}")

        if "modifier" in pattern:
            info_parts.append(f"**Modifier**: {pattern['modifier']}")

        return "\n".join(info_parts)


# Convenience functions

async def generate_fix(
    finding: Dict[str, Any],
    code: str,
    model: str = "deepseek-coder:6.7b",
) -> Remediation:
    """
    Generate a fix for a single vulnerability.

    Args:
        finding: The vulnerability finding
        code: Contract code
        model: LLM model to use

    Returns:
        Remediation with fixed code
    """
    generator = RemediationGenerator(model=model)
    return await generator.generate_remediation(finding, code)


def get_quick_fix(vuln_type: str, code: str) -> Tuple[str, str]:
    """
    Get a quick fix without LLM (pattern-based).

    Args:
        vuln_type: Type of vulnerability
        code: Vulnerable code section

    Returns:
        Tuple of (fixed_code, explanation)
    """
    generator = RemediationGenerator()
    return generator.generate_quick_fix(vuln_type, code)


# Export
__all__ = [
    "RemediationGenerator",
    "Remediation",
    "RemediationResult",
    "REMEDIATION_PATTERNS",
    "generate_fix",
    "get_quick_fix",
]
