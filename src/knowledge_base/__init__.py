"""
MIESC Vulnerability Knowledge Base

Structured knowledge base for vulnerability patterns,
remediations, and security best practices.
"""

import json
from pathlib import Path

_KB_PATH = Path(__file__).parent / "vulnerability_kb.json"


def load_knowledge_base() -> dict:
    """Load the vulnerability knowledge base."""
    if _KB_PATH.exists():
        with open(_KB_PATH) as f:
            return json.load(f)
    return {}


def get_vulnerability_info(vuln_type: str) -> dict:
    """Get information about a specific vulnerability type."""
    kb = load_knowledge_base()
    return kb.get("vulnerabilities", {}).get(vuln_type, {})


def get_remediation(vuln_type: str) -> str:
    """Get remediation advice for a vulnerability type."""
    info = get_vulnerability_info(vuln_type)
    return info.get("remediation", "No remediation available.")


__all__ = [
    "load_knowledge_base",
    "get_vulnerability_info",
    "get_remediation"
]
