"""
Formal Specification Generator
===============================

Auto-generates formal verification specifications (Certora CVL, Scribble,
SMTChecker annotations) from MIESC findings.

Given a finding like "reentrancy in withdraw()", this module emits:
  - Certora CVL: `invariant noReentrancy() ...`
  - Scribble annotation: `/// #if_succeeds ...`
  - SMTChecker assertion: `assert(locked == false || ...)`

This bridges the gap between automated detection (MIESC) and formal
verification (Certora Prover, SMTChecker) — one of the weakest areas
of the field per our COMPARISON.md.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SpecFormat(Enum):
    """Supported formal specification formats."""

    CVL = "cvl"              # Certora Verification Language
    SCRIBBLE = "scribble"    # ConsenSys Scribble annotations
    SMTCHECKER = "smtchecker"  # Solidity built-in SMTChecker asserts


@dataclass
class GeneratedSpec:
    """A generated formal specification for a finding."""

    finding_id: str
    finding_type: str
    format: SpecFormat
    spec_code: str
    description: str
    confidence: float = 0.75  # How confident we are the spec is correct
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "format": self.format.value,
            "spec_code": self.spec_code,
            "description": self.description,
            "confidence": self.confidence,
            "references": self.references,
        }


# =============================================================================
# Template library — maps vulnerability types to spec templates
# =============================================================================

CVL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "reentrancy": {
        "description": "No reentrancy: function does not re-enter itself via external call",
        "template": """// @dev Ensures withdraw/transfer is not reentered
rule noReentrancy_{func}(env e, address user) {{
    require balances[user] > 0;
    uint256 balanceBefore = nativeBalances[currentContract];
    {func}(e, user);
    assert nativeBalances[currentContract] == balanceBefore - balances[user],
        "Reentrancy detected: balance decreased more than expected";
}}""",
    },
    "access-control": {
        "description": "Only authorized callers can execute privileged functions",
        "template": """// @dev Only owner can call {func}
rule onlyOwnerCanCall_{func}(env e, address caller) {{
    require caller != owner();
    {func}@withrevert(e);
    assert lastReverted, "Unauthorized caller succeeded";
}}""",
    },
    "overflow": {
        "description": "Arithmetic operations cannot overflow/underflow",
        "template": """// @dev No overflow in {func}
rule noOverflow_{func}(env e, uint256 amount) {{
    uint256 before = totalSupply();
    {func}(e, amount);
    uint256 after = totalSupply();
    assert after >= before, "Underflow in {func}";
    assert after - before == amount, "Overflow in {func}";
}}""",
    },
    "unchecked-call": {
        "description": "Return value of external calls must be checked",
        "template": """// @dev {func} must handle failed external calls
rule checkedReturn_{func}(env e) {{
    bool callResult;
    uint256 stateBefore = contractState();
    callResult = {func}(e);
    uint256 stateAfter = contractState();
    assert callResult || stateBefore == stateAfter,
        "State changed despite failed call";
}}""",
    },
    "timestamp": {
        "description": "Function logic does not depend on block.timestamp for critical decisions",
        "template": """// @dev {func} must not use block.timestamp for access/decisions
invariant timestampIndependence_{func}()
    // This invariant requires manual verification;
    // Certora cannot auto-prove timestamp-independence.
    true""",
    },
    "weak-randomness": {
        "description": "Randomness source is not predictable (block.timestamp, blockhash)",
        "template": """// @dev WARNING: Predictable randomness detected
// Certora cannot verify randomness quality. This spec marks the issue:
rule weakRandomness_{func}(env e) {{
    // Attackers can predict block.timestamp/blockhash/prevrandao.
    // Manual fix required: use Chainlink VRF or commit-reveal.
    assert true, "Manual review required for randomness source";
}}""",
    },
}

SCRIBBLE_TEMPLATES: Dict[str, str] = {
    "reentrancy": "/// #if_succeeds {:msg \"no reentrancy\"} locked == false ==> locked == false;",
    "access-control": "/// #if_succeeds {:msg \"only owner\"} msg.sender == owner;",
    "overflow": "/// #if_succeeds {:msg \"no overflow\"} old(totalSupply) + amount >= old(totalSupply);",
    "unchecked-call": "/// #if_succeeds {:msg \"call succeeded or reverted\"} success == true;",
}

SMTCHECKER_ASSERTIONS: Dict[str, str] = {
    "overflow": "assert(x + y >= x);  // prevent overflow",
    "underflow": "assert(x >= y);  // prevent underflow before subtraction",
    "unchecked-call": "require(success, \"external call failed\");",
}


# =============================================================================
# Generator
# =============================================================================


class SpecGenerator:
    """Generates formal specifications from vulnerability findings."""

    def __init__(self, default_format: SpecFormat = SpecFormat.CVL):
        self.default_format = default_format

    def generate(
        self,
        finding: Dict[str, Any],
        format: Optional[SpecFormat] = None,
    ) -> Optional[GeneratedSpec]:
        """
        Generate a spec for a single finding.

        Args:
            finding: MIESC finding dict with 'type', 'location', 'severity', etc.
            format: Output format (defaults to self.default_format)

        Returns:
            GeneratedSpec or None if no template matches.
        """
        fmt = format or self.default_format
        vuln_type = self._normalize_type(finding.get("type", finding.get("check", "")))
        func_name = self._extract_function(finding)

        if fmt == SpecFormat.CVL:
            return self._generate_cvl(finding, vuln_type, func_name)
        elif fmt == SpecFormat.SCRIBBLE:
            return self._generate_scribble(finding, vuln_type, func_name)
        elif fmt == SpecFormat.SMTCHECKER:
            return self._generate_smtchecker(finding, vuln_type)

        return None

    def generate_batch(
        self,
        findings: List[Dict[str, Any]],
        format: Optional[SpecFormat] = None,
    ) -> List[GeneratedSpec]:
        """Generate specs for multiple findings."""
        specs = []
        for f in findings:
            spec = self.generate(f, format=format)
            if spec:
                specs.append(spec)
        return specs

    def generate_spec_file(
        self,
        findings: List[Dict[str, Any]],
        output_path: Path,
        contract_name: str = "MyContract",
        format: Optional[SpecFormat] = None,
    ) -> int:
        """
        Generate a complete spec file for Certora/Scribble.

        Returns number of specs written.
        """
        fmt = format or self.default_format
        specs = self.generate_batch(findings, format=fmt)

        if fmt == SpecFormat.CVL:
            content = self._assemble_cvl_file(specs, contract_name)
        elif fmt == SpecFormat.SCRIBBLE:
            content = self._assemble_scribble_file(specs)
        elif fmt == SpecFormat.SMTCHECKER:
            content = self._assemble_smtchecker_file(specs)
        else:
            return 0

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        logger.info(f"Generated {len(specs)} {fmt.value} specs → {output_path}")
        return len(specs)

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _normalize_type(self, vuln_type: str) -> str:
        """Map tool-specific types to canonical categories."""
        v = vuln_type.lower()
        if "reentran" in v:
            return "reentrancy"
        if any(k in v for k in ["access", "auth", "owner", "selfdestruct", "suicid", "tx-origin", "unprotected", "initializer"]):
            return "access-control"
        if any(k in v for k in ["overflow", "arithmetic"]):
            return "overflow"
        if "underflow" in v:
            return "underflow"
        if any(k in v for k in ["unchecked", "low-level", "unused-return"]):
            return "unchecked-call"
        if "timestamp" in v or "block-number" in v:
            return "timestamp"
        if any(k in v for k in ["weak-prng", "weak-random", "bad-random"]):
            return "weak-randomness"
        return v

    def _extract_function(self, finding: Dict[str, Any]) -> str:
        """Extract function name from finding location."""
        location = finding.get("location", {})
        if isinstance(location, dict):
            func = location.get("function", "")
            if func and func != "unknown":
                return func
        # Try parsing from message
        msg = finding.get("message", "") or finding.get("description", "")
        m = re.search(r"function[:\s]+(\w+)", msg, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"in\s+(\w+)\(", msg)
        if m:
            return m.group(1)
        return "targetFunction"

    def _generate_cvl(
        self, finding: Dict[str, Any], vuln_type: str, func: str
    ) -> Optional[GeneratedSpec]:
        tmpl = CVL_TEMPLATES.get(vuln_type)
        if not tmpl:
            return None
        spec_code = tmpl["template"].format(func=func)
        return GeneratedSpec(
            finding_id=finding.get("id", f"{vuln_type}-{func}"),
            finding_type=vuln_type,
            format=SpecFormat.CVL,
            spec_code=spec_code,
            description=tmpl["description"],
            confidence=0.75,
            references=[
                "https://docs.certora.com/",
                f"MIESC finding: {finding.get('type', vuln_type)}",
            ],
        )

    def _generate_scribble(
        self, finding: Dict[str, Any], vuln_type: str, func: str
    ) -> Optional[GeneratedSpec]:
        tmpl = SCRIBBLE_TEMPLATES.get(vuln_type)
        if not tmpl:
            return None
        return GeneratedSpec(
            finding_id=finding.get("id", f"{vuln_type}-{func}"),
            finding_type=vuln_type,
            format=SpecFormat.SCRIBBLE,
            spec_code=tmpl,
            description=f"Scribble annotation for {vuln_type}",
            confidence=0.70,
            references=["https://docs.scribble.codes/"],
        )

    def _generate_smtchecker(
        self, finding: Dict[str, Any], vuln_type: str
    ) -> Optional[GeneratedSpec]:
        assertion = SMTCHECKER_ASSERTIONS.get(vuln_type)
        if not assertion:
            return None
        return GeneratedSpec(
            finding_id=finding.get("id", f"{vuln_type}"),
            finding_type=vuln_type,
            format=SpecFormat.SMTCHECKER,
            spec_code=assertion,
            description=f"SMTChecker assertion for {vuln_type}",
            confidence=0.85,
            references=["https://docs.soliditylang.org/en/latest/smtchecker.html"],
        )

    def _assemble_cvl_file(self, specs: List[GeneratedSpec], contract_name: str) -> str:
        """Assemble a Certora .spec file."""
        lines = [
            f"// Auto-generated Certora specification for {contract_name}",
            f"// Generated by MIESC v5.1.2 from {len(specs)} findings",
            "// Review and adapt before running `certoraRun`",
            "",
            "methods {",
            "    // TODO: add function signatures from your contract",
            "}",
            "",
        ]
        for i, spec in enumerate(specs):
            lines.append(f"// ({i+1}/{len(specs)}) {spec.description}")
            lines.append(f"// Confidence: {spec.confidence:.0%}")
            lines.append(spec.spec_code)
            lines.append("")
        return "\n".join(lines)

    def _assemble_scribble_file(self, specs: List[GeneratedSpec]) -> str:
        """Assemble Scribble annotations (insert before function)."""
        lines = [
            "// Scribble annotations — insert each line above the corresponding function",
            "// in your Solidity source, then run `scribble contract.sol --arm`",
            "",
        ]
        for spec in specs:
            lines.append(f"// {spec.description}")
            lines.append(spec.spec_code)
            lines.append("")
        return "\n".join(lines)

    def _assemble_smtchecker_file(self, specs: List[GeneratedSpec]) -> str:
        """Assemble SMTChecker assertions as a Solidity snippet."""
        lines = [
            "// SMTChecker assertions — insert into your functions as shown",
            "// Enable in solc via: solc --model-checker-engine chc contract.sol",
            "",
        ]
        for spec in specs:
            lines.append(f"// {spec.description}")
            lines.append(spec.spec_code)
            lines.append("")
        return "\n".join(lines)
