"""
MIESC Security Checks - Self-Assessment Module

Automated security validation that MIESC can run on itself.
Implements "eating your own dog food" principle.

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Run security scans on MIESC codebase"""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)

    def run_all_scans(self) -> Dict[str, Any]:
        """Execute all security scans"""
        results = {
            "bandit": self.run_bandit(),
            "semgrep": self.run_semgrep(),
            "secrets": self.scan_secrets(),
            "dependencies": self.audit_dependencies()
        }
        return results

    def run_bandit(self) -> Dict[str, Any]:
        """Run Bandit SAST scanner"""
        try:
            result = subprocess.run(
                ["bandit", "-r", "src/", "-f", "json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            return json.loads(result.stdout) if result.stdout else {}
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
            return {"error": str(e)}

    def run_semgrep(self) -> Dict[str, Any]:
        """Run Semgrep security scanner"""
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", "src/"],
                capture_output=True,
                text=True,
                timeout=180
            )
            return json.loads(result.stdout) if result.stdout else {}
        except Exception as e:
            logger.error(f"Semgrep scan failed: {e}")
            return {"error": str(e)}

    def scan_secrets(self) -> Dict[str, Any]:
        """Scan for hardcoded secrets"""
        import re
        secrets = []
        patterns = {
            r"(?i)api[_-]?key\s*=\s*['\"][^'\"]+['\"]": "API Key",
            r"(?i)password\s*=\s*['\"][^'\"]+['\"]": "Password",
            r"(?i)secret\s*=\s*['\"][^'\"]+['\"]": "Secret",
        }

        for py_file in Path("src/").rglob("*.py"):
            try:
                content = py_file.read_text()
                for pattern, name in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        secrets.append({
                            "file": str(py_file),
                            "type": name,
                            "line_count": len(matches)
                        })
            except Exception:
                pass

        return {"secrets_found": len(secrets), "details": secrets}

    def audit_dependencies(self) -> Dict[str, Any]:
        """Audit Python dependencies for vulnerabilities"""
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            return json.loads(result.stdout) if result.stdout else {}
        except Exception as e:
            logger.error(f"Dependency audit failed: {e}")
            return {"error": str(e)}


if __name__ == "__main__":
    scanner = SecurityScanner()
    results = scanner.run_all_scans()
    print(json.dumps(results, indent=2))
