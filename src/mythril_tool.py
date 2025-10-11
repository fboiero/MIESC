"""
Mythril Security Analysis Tool Integration
Provides symbolic execution and security analysis of Ethereum smart contracts.
"""
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_mythril(contract_path, timeout=600):
    """
    Run Mythril security analysis on a smart contract.

    Args:
        contract_path (str): Path to the Solidity contract file
        timeout (int): Maximum execution time in seconds (default: 600)

    Returns:
        str: Mythril analysis output or error message
    """
    try:
        logger.info(f"Running Mythril analysis on {contract_path}")
        result = subprocess.run(
            ['myth', 'analyze', '--parallel-solving', contract_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # Mythril returns non-zero for vulnerabilities found
        output = result.stdout if result.stdout else result.stderr
        logger.info("Mythril analysis completed")
        return output
    except subprocess.CalledProcessError as e:
        logger.warning("Mythril completed with errors")
        return e.stderr if e.stderr else e.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Mythril analysis timed out after {timeout} seconds")
        return f"Error: Mythril analysis timed out after {timeout} seconds"
    except FileNotFoundError:
        logger.error("Mythril (myth) not found. Please install it first.")
        return "Error: Mythril not installed"


def audit_contract(contract_path, version):
    """
    Perform a complete security audit using Mythril.

    Args:
        contract_path (str): Path to the Solidity contract file
        version (str): Solidity compiler version (informational)

    Returns:
        str: Complete Mythril analysis output
    """
    logger.info(f"Starting Mythril audit for {contract_path} (Solidity {version})")
    output = run_mythril(contract_path)
    return output
