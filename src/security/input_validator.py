"""
Input Validation Module

Provides security validation for all user inputs to prevent:
- Path traversal attacks
- Command injection
- Invalid parameter exploitation
"""

import os
import re
from pathlib import Path
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security validation fails"""
    pass


def validate_contract_path(
    contract_path: str,
    allowed_extensions: Optional[List[str]] = None,
    allowed_base_dirs: Optional[List[str]] = None
) -> str:
    """
    Validate and sanitize contract file path to prevent path traversal attacks.

    Security checks:
    1. Resolves to absolute path
    2. Checks if within allowed base directories
    3. Validates file extension
    4. Ensures file exists and is readable

    Args:
        contract_path: User-provided path to contract
        allowed_extensions: List of allowed file extensions (default: ['.sol'])
        allowed_base_dirs: List of allowed base directories (default: CWD and examples/)

    Returns:
        str: Validated absolute path

    Raises:
        SecurityError: If validation fails
        FileNotFoundError: If file doesn't exist

    Examples:
        >>> validate_contract_path("examples/reentrancy.sol")
        '/app/examples/reentrancy.sol'

        >>> validate_contract_path("../../../etc/passwd")
        SecurityError: Path traversal attempt detected
    """
    if allowed_extensions is None:
        allowed_extensions = ['.sol']

    if allowed_base_dirs is None:
        # Default: allow current working directory and examples/
        cwd = os.getcwd()
        allowed_base_dirs = [
            cwd,
            os.path.join(cwd, 'examples'),
            os.path.join(cwd, 'contracts'),
            os.path.join(cwd, 'src', 'contracts'),
            os.path.join(cwd, 'tests'),
            '/app/examples',  # Docker path
            '/app/contracts',
            '/app/tests'
        ]

    try:
        # Resolve to absolute path (follows symlinks)
        abs_path = Path(contract_path).resolve()

        # Check if path is within any allowed base directory
        path_allowed = False
        for base_dir in allowed_base_dirs:
            base_path = Path(base_dir).resolve()
            try:
                # Check if abs_path is relative to base_path
                abs_path.relative_to(base_path)
                path_allowed = True
                break
            except ValueError:
                # Not a subpath of this base
                continue

        if not path_allowed:
            logger.error(f"Path traversal attempt: {contract_path} -> {abs_path}")
            raise SecurityError(
                f"Path traversal attempt detected. Contract must be in allowed directories.\n"
                f"Attempted path: {abs_path}\n"
                f"Allowed directories: {allowed_base_dirs}"
            )

        # Check file extension
        if abs_path.suffix not in allowed_extensions:
            raise SecurityError(
                f"Invalid file extension: {abs_path.suffix}. "
                f"Allowed extensions: {allowed_extensions}"
            )

        # Check file exists
        if not abs_path.exists():
            raise FileNotFoundError(f"Contract file not found: {abs_path}")

        # Check file is actually a file (not directory)
        if not abs_path.is_file():
            raise SecurityError(f"Path is not a file: {abs_path}")

        # Check file is readable
        if not os.access(abs_path, os.R_OK):
            raise SecurityError(f"File is not readable: {abs_path}")

        logger.info(f"Path validation passed: {contract_path} -> {abs_path}")
        return str(abs_path)

    except SecurityError:
        raise
    except FileNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during path validation: {e}")
        raise SecurityError(f"Path validation failed: {str(e)}")


def validate_solc_version(version: str) -> str:
    """
    Validate Solidity compiler version format.

    Prevents command injection by ensuring version follows expected format.

    Args:
        version: Solidity version string (e.g., "0.8.20")

    Returns:
        str: Validated version string

    Raises:
        SecurityError: If version format is invalid

    Examples:
        >>> validate_solc_version("0.8.20")
        '0.8.20'

        >>> validate_solc_version("0.8.20; rm -rf /")
        SecurityError: Invalid Solidity version format
    """
    # Solidity versions follow format: 0.X.Y or 0.X.Y+commit.hash
    # We allow: 0.4.0 through 0.8.99, optionally with build metadata
    pattern = r'^0\.[4-8]\.\d{1,2}(\+commit\.[a-f0-9]{8})?$'

    if not re.match(pattern, version):
        logger.error(f"Invalid Solidity version format: {version}")
        raise SecurityError(
            f"Invalid Solidity version format: {version}. "
            f"Expected format: 0.X.Y (e.g., 0.8.20)"
        )

    logger.debug(f"Solidity version validated: {version}")
    return version


def validate_function_name(function_name: str) -> str:
    """
    Validate Solidity function name.

    Prevents injection attacks by ensuring function name contains only valid characters.

    Args:
        function_name: Function name to validate

    Returns:
        str: Validated function name

    Raises:
        SecurityError: If function name is invalid

    Examples:
        >>> validate_function_name("transfer")
        'transfer'

        >>> validate_function_name("transfer'; DROP TABLE users;--")
        SecurityError: Invalid function name
    """
    # Solidity function names: alphanumeric + underscore, start with letter or underscore
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'

    if not re.match(pattern, function_name):
        logger.error(f"Invalid function name: {function_name}")
        raise SecurityError(
            f"Invalid function name: {function_name}. "
            f"Function names must contain only alphanumeric characters and underscores."
        )

    # Additional check: reasonable length (Solidity allows up to 256, we limit to 100)
    if len(function_name) > 100:
        raise SecurityError(f"Function name too long: {len(function_name)} characters (max 100)")

    logger.debug(f"Function name validated: {function_name}")
    return function_name


def validate_timeout(timeout: int, min_value: int = 1, max_value: int = 3600) -> int:
    """
    Validate timeout value.

    Prevents DoS by ensuring timeout is within reasonable bounds.

    Args:
        timeout: Timeout in seconds
        min_value: Minimum allowed timeout (default: 1s)
        max_value: Maximum allowed timeout (default: 3600s / 1 hour)

    Returns:
        int: Validated timeout value

    Raises:
        SecurityError: If timeout is out of bounds
    """
    try:
        timeout_int = int(timeout)
    except (TypeError, ValueError):
        raise SecurityError(f"Invalid timeout value: {timeout}. Must be an integer.")

    if timeout_int < min_value or timeout_int > max_value:
        raise SecurityError(
            f"Timeout out of bounds: {timeout_int}s. "
            f"Must be between {min_value}s and {max_value}s."
        )

    return timeout_int


def sanitize_command_args(args: List[str], allowed_args: Optional[List[str]] = None) -> List[str]:
    """
    Sanitize command-line arguments to prevent injection.

    Args:
        args: List of command arguments
        allowed_args: Optional whitelist of allowed arguments

    Returns:
        List[str]: Sanitized arguments

    Raises:
        SecurityError: If dangerous patterns detected
    """
    dangerous_patterns = [
        r'[;&|`$]',  # Shell metacharacters
        r'\$\(',      # Command substitution
        r'>\s*/',     # Redirect to absolute path
        r'<\s*/',     # Read from absolute path
    ]

    sanitized = []
    for arg in args:
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, arg):
                raise SecurityError(
                    f"Dangerous pattern detected in argument: {arg}. "
                    f"Pattern: {pattern}"
                )

        # If whitelist provided, check against it
        if allowed_args is not None:
            if arg not in allowed_args and not any(arg.startswith(allowed) for allowed in allowed_args):
                logger.warning(f"Argument not in whitelist: {arg}")
                # Don't raise error, just log warning

        sanitized.append(arg)

    return sanitized


# Convenience function for common validation workflow
def validate_analysis_inputs(
    contract_path: str,
    solc_version: Optional[str] = None,
    timeout: Optional[int] = None,
    functions: Optional[List[str]] = None
) -> dict:
    """
    Validate all common analysis inputs in one call.

    Args:
        contract_path: Path to contract
        solc_version: Solidity version (optional)
        timeout: Analysis timeout (optional)
        functions: List of function names to analyze (optional)

    Returns:
        dict: Validated inputs

    Raises:
        SecurityError: If any validation fails
    """
    validated = {}

    # Always validate contract path
    validated['contract_path'] = validate_contract_path(contract_path)

    # Validate optional parameters
    if solc_version:
        validated['solc_version'] = validate_solc_version(solc_version)

    if timeout:
        validated['timeout'] = validate_timeout(timeout)

    if functions:
        validated['functions'] = [validate_function_name(fn) for fn in functions]

    return validated
