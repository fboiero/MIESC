"""
Slither Analysis Tool Integration
Provides automated static analysis of Solidity smart contracts using Slither.
"""
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def set_solidity_version(version):
    """
    Set the Solidity compiler version using solc-select.

    Args:
        version (str): Solidity version to install and use

    Returns:
        str: Error message if any, None otherwise
    """
    try:
        logger.info(f"Installing Solidity version {version}")
        subprocess.run(["solc-select", "install", version],
                      capture_output=True, check=True)
        logger.info(f"Using Solidity version {version}")
        subprocess.run(["solc-select", "use", version],
                      capture_output=True, check=True)
        return None
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        logger.error(f"Error setting Solidity version: {error_msg}")
        return error_msg
    except FileNotFoundError:
        logger.error("solc-select not found. Please install it first.")
        return "solc-select not found"


def run_slither(contract_path):
    """
    Run Slither analysis on a smart contract.

    Args:
        contract_path (str): Path to the Solidity contract file

    Returns:
        str: Slither analysis output or error message
    """
    try:
        logger.info(f"Running Slither analysis on {contract_path}")
        result = subprocess.run(
            ["slither", contract_path],
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # 5 minute timeout
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.warning(f"Slither completed with warnings/errors")
        # Slither returns non-zero even for warnings, so return stderr
        return e.stderr if e.stderr else e.stdout
    except subprocess.TimeoutExpired:
        logger.error("Slither analysis timed out")
        return "Error: Slither analysis timed out after 5 minutes"
    except FileNotFoundError:
        logger.error("Slither not found. Please install it first.")
        return "Error: Slither not installed"


def audit_contract(contract_path, version):
    """
    Perform a complete audit of a smart contract using Slither.

    Args:
        contract_path (str): Path to the Solidity contract file
        version (str): Solidity compiler version to use

    Returns:
        str: Complete Slither analysis output
    """
    logger.info(f"Starting Slither audit for {contract_path}")
    version_error = set_solidity_version(version)
    if version_error:
        return f"Failed to set Solidity version: {version_error}"

    output = run_slither(contract_path)
    logger.info("Slither audit completed")
    return output
