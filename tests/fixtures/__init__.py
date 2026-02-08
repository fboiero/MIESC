# MIESC Test Fixtures
# Sample vulnerable contracts for testing security analysis

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent

# Contract paths
REENTRANCY_CONTRACT = FIXTURES_DIR / "reentrancy.sol"
OVERFLOW_CONTRACT = FIXTURES_DIR / "integer_overflow.sol"
ACCESS_CONTROL_CONTRACT = FIXTURES_DIR / "access_control.sol"
FLASH_LOAN_CONTRACT = FIXTURES_DIR / "flash_loan_vulnerable.sol"
ORACLE_MANIPULATION_CONTRACT = FIXTURES_DIR / "oracle_manipulation.sol"
TX_ORIGIN_CONTRACT = FIXTURES_DIR / "tx_origin.sol"

__all__ = [
    "FIXTURES_DIR",
    "REENTRANCY_CONTRACT",
    "OVERFLOW_CONTRACT",
    "ACCESS_CONTROL_CONTRACT",
    "FLASH_LOAN_CONTRACT",
    "ORACLE_MANIPULATION_CONTRACT",
    "TX_ORIGIN_CONTRACT",
]
