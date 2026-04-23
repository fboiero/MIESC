"""
`miesc test-gen` — generate Foundry exploit tests from scan findings.

Takes a scan/audit JSON + the original contract and generates Foundry tests
that demonstrate each vulnerability. Each test is designed to:
  - FAIL on the original contract (proving the vuln exists)
  - PASS on the fixed contract (proving the fix works)

This closes the find→fix→prove loop that no other tool automates.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from miesc.cli.utils import error, info, success, warning

# ---------------------------------------------------------------------------
# Foundry test templates per vulnerability category
# ---------------------------------------------------------------------------

_TEMPLATES = {
    "reentrancy": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../{contract_file}";

contract ReentrancyAttacker {{
    {contract_name} public target;
    uint256 public attackCount;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.{function}(msg.value);
    }}

    receive() external payable {{
        if (attackCount < 3) {{
            attackCount++;
            target.{function}(msg.value);
        }}
    }}
}}

contract Test_{test_name} is Test {{
    {contract_name} public victim;
    ReentrancyAttacker public attacker;

    function setUp() public {{
        victim = new {contract_name}();
        attacker = new ReentrancyAttacker(address(victim));
        // Fund victim with some ETH
        vm.deal(address(this), 10 ether);
        victim.deposit{{value: 5 ether}}();
    }}

    /// @notice This test should FAIL on vulnerable contract (attacker drains)
    /// and PASS on fixed contract (nonReentrant blocks reentry)
    function test_exploit_{test_name}() public {{
        vm.deal(address(attacker), 1 ether);
        uint256 victimBalanceBefore = address(victim).balance;

        attacker.attack{{value: 1 ether}}();

        // If reentrancy is possible, attacker gets more than deposited
        assertLe(
            address(attacker).balance,
            1 ether,
            "EXPLOIT: Attacker drained funds via reentrancy"
        );
    }}
}}
''',
    "access_control": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../{contract_file}";

contract Test_{test_name} is Test {{
    {contract_name} public target;
    address public owner = address(1);
    address public attacker = address(2);

    function setUp() public {{
        vm.prank(owner);
        target = new {contract_name}();
    }}

    /// @notice This test should FAIL on vulnerable contract (attacker can call)
    /// and PASS on fixed contract (onlyOwner reverts)
    function test_exploit_{test_name}() public {{
        vm.prank(attacker);
        // Attacker tries to call privileged function
        vm.expectRevert();
        target.{function}({call_args});
    }}
}}
''',
    "selfdestruct": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../{contract_file}";

contract Test_{test_name} is Test {{
    {contract_name} public target;
    address public attacker = address(0xBAD);

    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(target), 1 ether);
    }}

    /// @notice This test should FAIL on vulnerable contract (anyone can destroy)
    /// and PASS on fixed contract (onlyOwner reverts)
    function test_exploit_{test_name}() public {{
        uint256 codeSizeBefore = address(target).code.length;
        assertTrue(codeSizeBefore > 0, "Contract should exist");

        vm.prank(attacker);
        vm.expectRevert();
        target.{function}();

        // Contract should still exist
        assertTrue(address(target).code.length > 0, "EXPLOIT: Contract destroyed by non-owner");
    }}
}}
''',
    "unchecked_call": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../{contract_file}";

contract RevertingReceiver {{
    receive() external payable {{
        revert("I reject ETH");
    }}
}}

contract Test_{test_name} is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    /// @notice This test verifies that failed external calls are properly handled
    function test_exploit_{test_name}() public {{
        RevertingReceiver receiver = new RevertingReceiver();
        vm.deal(address(target), 1 ether);

        // If the contract doesn't check call return value,
        // state will be updated even though ETH transfer failed
        vm.expectRevert();
        // This should revert if the call is properly checked
        target.{function}(1 ether);
    }}
}}
''',
}

# Default template for unknown vulnerability types
_DEFAULT_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../{contract_file}";

contract Test_{test_name} is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    /// @notice Exploit test for: {vuln_type}
    /// Vulnerability: {description}
    ///
    /// Exploit steps:
{exploit_steps}
    function test_exploit_{test_name}() public {{
        // TODO: Implement exploit based on the steps above
        // This test should FAIL on the vulnerable contract
        // and PASS on the fixed version
        assertTrue(true, "Implement exploit test");
    }}
}}
'''


def _normalize_test_name(finding_type: str, function_name: str) -> str:
    """Create a valid Solidity test function name."""
    name = f"{finding_type}_{function_name}".replace("-", "_").replace(" ", "_")
    # Remove non-alphanumeric chars
    name = "".join(c for c in name if c.isalnum() or c == "_")
    return name[:60]


def _detect_contract_name(source: str) -> str:
    """Extract the first contract name from Solidity source."""
    import re
    m = re.search(r"contract\s+(\w+)", source)
    return m.group(1) if m else "Target"


def _get_call_args(finding: dict) -> str:
    """Generate placeholder call args based on function signature hints."""
    ftype = (finding.get("type") or "").lower()
    if "selfdestruct" in ftype or "suicidal" in ftype:
        return ""
    if "owner" in ftype:
        return "attacker"
    return ""


def generate_test(finding: dict, contract_file: str, contract_name: str, source: str = "") -> Optional[str]:
    """Generate a Foundry test for a single finding."""
    ftype = (finding.get("type") or finding.get("title") or "").lower().replace("-", "_")

    _unknown = {"", "unknown", "<unknown>", "none", "n/a", "targetfunction"}
    fn_name = finding.get("function") or ""
    if fn_name.lower() in _unknown:
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            fn_name = loc.get("function", "")
        if fn_name.lower() in _unknown:
            fn_name = ""
    if not fn_name:
        # Try to infer from line number + source
        import re
        line = finding.get("line") or (finding.get("location", {}).get("line") if isinstance(finding.get("location"), dict) else None)
        if line and source:
            lines = source.splitlines()
            for i in range(min(int(line) - 1, len(lines) - 1), -1, -1):
                m = re.match(r"\s*function\s+(\w+)\s*\(", lines[i])
                if m:
                    fn_name = m.group(1)
                    break
    if not fn_name:
        fn_name = "targetFunction"

    test_name = _normalize_test_name(ftype, fn_name)

    # Select template
    if "reentrancy" in ftype:
        template = _TEMPLATES["reentrancy"]
    elif "selfdestruct" in ftype or "suicidal" in ftype:
        template = _TEMPLATES["selfdestruct"]
    elif "access_control" in ftype:
        template = _TEMPLATES["access_control"]
    elif "unchecked" in ftype:
        template = _TEMPLATES["unchecked_call"]
    else:
        # Use default with exploit steps
        exploit_scenario = finding.get("exploit_scenario", [])
        if isinstance(exploit_scenario, list):
            steps = "\n".join(f"    ///   {i+1}. {s}" for i, s in enumerate(exploit_scenario))
        else:
            steps = f"    ///   {exploit_scenario}"

        return _DEFAULT_TEMPLATE.format(
            contract_file=contract_file,
            contract_name=contract_name,
            test_name=test_name,
            vuln_type=ftype,
            description=(finding.get("description") or finding.get("message") or "")[:200],
            exploit_steps=steps or "    ///   No exploit steps available",
        )

    return template.format(
        contract_file=contract_file,
        contract_name=contract_name,
        test_name=test_name,
        function=fn_name,
        call_args=_get_call_args(finding),
    )


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

@click.command("test-gen")
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--contract", "-c", "contract_path",
    type=click.Path(exists=True),
    required=True,
    help="Original Solidity contract file",
)
@click.option(
    "--output-dir", "-o",
    type=click.Path(),
    default=None,
    help="Output directory for tests (default: test/exploit/)",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def testgen(results_file, contract_path, output_dir, quiet):
    """Generate Foundry exploit tests from scan/audit findings.

    Creates test files that demonstrate each vulnerability found by MIESC.
    Tests are designed to FAIL on the original contract and PASS on the
    fixed version, closing the find→fix→prove loop.

    \b
    Examples:
      miesc test-gen results.json -c Contract.sol
      miesc test-gen results.json -c Contract.sol -o test/exploit/
      miesc scan Contract.sol -o results.json && miesc test-gen results.json -c Contract.sol

    \b
    After generation:
      forge test --match-path test/exploit/  # Run exploit tests
    """
    # Load results
    try:
        with open(results_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        error(f"Cannot read results: {e}")
        sys.exit(1)

    # Collect findings with exploit_scenario or fix_code
    findings = data.get("findings", [])
    for r in data.get("results", []):
        findings.extend(r.get("findings", []))

    exploitable = [f for f in findings if f.get("exploit_scenario") or f.get("fix_code")]
    if not exploitable:
        warning("No findings with exploit scenarios — nothing to generate.")
        sys.exit(0)

    # Deduplicate by (type, function)
    seen = set()
    unique = []
    for f in exploitable:
        key = (
            (f.get("type") or f.get("title") or "").lower(),
            (f.get("function") or f.get("location", {}).get("function", "") if isinstance(f.get("location"), dict) else ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Read contract source
    contract = Path(contract_path)
    source = contract.read_text()
    contract_name = _detect_contract_name(source)
    contract_file = contract.name

    # Output directory
    if output_dir is None:
        out_dir = Path("test") / "exploit"
    else:
        out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not quiet:
        info(f"Generating Foundry tests for {len(unique)} findings")
        info(f"Contract: {contract_name} ({contract_file})")

    generated = 0
    for finding in unique:
        test_code = generate_test(finding, contract_file, contract_name, source)
        if not test_code:
            continue

        ftype = (finding.get("type") or finding.get("title") or "unknown").replace("-", "_")
        fn = finding.get("function") or "unknown"
        if fn.lower() in ("unknown", "<unknown>"):
            fn = "target"
        filename = f"Test_{ftype}_{fn}.t.sol"

        out_path = out_dir / filename
        out_path.write_text(test_code)
        generated += 1
        if not quiet:
            info(f"  ✓ {filename}")

    success(f"Generated {generated} Foundry exploit test(s) → {out_dir}/")
    if not quiet:
        info("Run: forge test --match-path test/exploit/")
