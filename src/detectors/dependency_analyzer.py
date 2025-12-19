#!/usr/bin/env python3
"""
MIESC v4.1 - Smart Contract Dependency Analyzer

Layer 9: Dependency Security Analysis
Analyzes imported libraries and dependencies for known vulnerabilities.

Covers:
- OpenZeppelin version vulnerabilities
- Known vulnerable imports
- Deprecated patterns
- Supply chain risks

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from enum import Enum


class DependencyRisk(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


@dataclass
class DependencyFinding:
    """Represents a dependency-related security finding."""
    title: str
    description: str
    severity: DependencyRisk
    package: str
    version: Optional[str] = None
    line: Optional[int] = None
    recommendation: str = ""
    cve: Optional[str] = None
    references: List[str] = field(default_factory=list)


# Known vulnerable OpenZeppelin versions and their issues
OPENZEPPELIN_VULNERABILITIES = {
    # Format: (min_version, max_version, severity, description, cve)
    "ERC20Pausable": [
        ("3.0.0", "4.1.0", DependencyRisk.HIGH,
         "Potential reentrancy in pause mechanism",
         None)
    ],
    "Ownable": [
        ("2.0.0", "4.3.2", DependencyRisk.MEDIUM,
         "transferOwnership can be called by anyone during contract initialization",
         None)
    ],
    "ECDSA": [
        ("4.1.0", "4.7.2", DependencyRisk.CRITICAL,
         "Signature malleability issue - duplicate signatures possible",
         "CVE-2022-35961")
    ],
    "ERC721": [
        ("4.0.0", "4.8.3", DependencyRisk.HIGH,
         "_safeMint callback reentrancy vulnerability",
         None)
    ],
    "GovernorVotesQuorumFraction": [
        ("4.3.0", "4.4.1", DependencyRisk.HIGH,
         "Quorum calculation vulnerability",
         None)
    ],
    "SignatureChecker": [
        ("4.1.0", "4.7.2", DependencyRisk.HIGH,
         "isValidSignatureNow bypass possible",
         None)
    ],
    "MerkleProof": [
        ("4.7.0", "4.9.1", DependencyRisk.MEDIUM,
         "Potential multiproof verification issue",
         None)
    ]
}

# Deprecated/dangerous imports
DANGEROUS_IMPORTS = {
    "SafeMath": (DependencyRisk.INFO,
                 "SafeMath is unnecessary in Solidity 0.8+ (built-in overflow checks)",
                 "Remove SafeMath and use native arithmetic operators"),
    "ReentrancyGuard": (DependencyRisk.INFO,
                        "Ensure nonReentrant modifier is applied to all external functions that modify state",
                        "Audit all external functions for reentrancy"),
    "Counters": (DependencyRisk.LOW,
                 "OpenZeppelin Counters library is deprecated in favor of native increment",
                 "Use unchecked { counter++; } for gas efficiency"),
    "Address.isContract": (DependencyRisk.MEDIUM,
                           "isContract() can return false for contracts being constructed",
                           "Do not rely on isContract() for access control"),
    "ecrecover": (DependencyRisk.HIGH,
                  "Direct ecrecover is vulnerable to signature malleability",
                  "Use OpenZeppelin ECDSA library instead"),
    "selfdestruct": (DependencyRisk.CRITICAL,
                     "selfdestruct is deprecated and may be removed in future forks",
                     "Avoid using selfdestruct; use alternative patterns"),
    "delegatecall": (DependencyRisk.HIGH,
                     "delegatecall can execute arbitrary code in calling contract's context",
                     "Validate target addresses and use proxy patterns carefully"),
    "tx.origin": (DependencyRisk.HIGH,
                  "tx.origin can be spoofed through contract calls",
                  "Use msg.sender for authentication instead"),
}

# Known vulnerable third-party libraries
THIRD_PARTY_VULNERABILITIES = {
    "uniswap-v2-core": {
        "UniswapV2Pair": (DependencyRisk.MEDIUM,
                         "Known price manipulation via getReserves in single block",
                         ["Use TWAP oracle or Chainlink price feeds"])
    },
    "uniswap-v3-core": {
        "UniswapV3Pool": (DependencyRisk.LOW,
                         "Slot0 spot price is manipulable - use observe() for TWAP",
                         ["Implement TWAP using observe() function"])
    },
    "compound-protocol": {
        "CToken": (DependencyRisk.MEDIUM,
                   "Exchange rate manipulation possible during initial mint",
                   ["Initialize with non-zero total supply"])
    }
}


class DependencyAnalyzer:
    """
    Analyzes smart contract dependencies for security vulnerabilities.
    """

    name = "dependency-analyzer"
    layer = 9  # Layer 9: Dependency Analysis (post-thesis extension)
    description = "Dependency and supply chain security analysis"

    def __init__(self):
        self.import_pattern = re.compile(
            r'import\s+[{"]?([^";\s]+)["}]?\s*(?:from\s+["\']([^"\']+)["\'])?',
            re.MULTILINE
        )
        self.pragma_pattern = re.compile(
            r'pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+\.\d+)',
            re.MULTILINE
        )
        self.oz_version_pattern = re.compile(
            r'@openzeppelin/contracts(?:-upgradeable)?(?:@(\d+\.\d+\.\d+))?',
            re.IGNORECASE
        )

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[DependencyFinding]:
        """Analyze source code for dependency vulnerabilities."""
        findings = []
        lines = source_code.split('\n')

        # Extract Solidity version
        solidity_version = self._extract_solidity_version(source_code)

        # Analyze imports
        imports = self._extract_imports(source_code, lines)

        # Check each import
        for import_info in imports:
            import_findings = self._check_import(import_info, solidity_version)
            findings.extend(import_findings)

        # Check for dangerous patterns
        pattern_findings = self._check_dangerous_patterns(source_code, lines)
        findings.extend(pattern_findings)

        return findings

    def analyze_file(self, file_path: Path) -> List[DependencyFinding]:
        """Analyze a Solidity file."""
        with open(file_path, 'r') as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def _extract_solidity_version(self, source_code: str) -> Optional[str]:
        """Extract Solidity version from pragma statement."""
        match = self.pragma_pattern.search(source_code)
        return match.group(1) if match else None

    def _extract_imports(self, source_code: str, lines: List[str]) -> List[Dict]:
        """Extract import statements with line numbers."""
        imports = []

        for i, line in enumerate(lines, 1):
            # Match import statements
            if 'import' in line:
                # Extract import path
                import_match = re.search(r'["\']([^"\']+)["\']', line)
                if import_match:
                    import_path = import_match.group(1)

                    # Parse import details
                    import_info = {
                        'line': i,
                        'path': import_path,
                        'full_line': line.strip(),
                        'package': self._identify_package(import_path),
                        'contract': self._extract_contract_name(import_path)
                    }
                    imports.append(import_info)

        return imports

    def _identify_package(self, import_path: str) -> str:
        """Identify the package from import path."""
        if '@openzeppelin' in import_path:
            return 'openzeppelin'
        elif '@uniswap' in import_path:
            return 'uniswap'
        elif '@chainlink' in import_path:
            return 'chainlink'
        elif '@aave' in import_path:
            return 'aave'
        elif '@compound' in import_path:
            return 'compound'
        else:
            return 'unknown'

    def _extract_contract_name(self, import_path: str) -> str:
        """Extract contract name from import path."""
        # Get filename without extension
        parts = import_path.split('/')
        if parts:
            filename = parts[-1]
            return filename.replace('.sol', '')
        return ''

    def _check_import(self, import_info: Dict, solidity_version: Optional[str]) -> List[DependencyFinding]:
        """Check an import for known vulnerabilities."""
        findings = []
        contract_name = import_info['contract']
        package = import_info['package']

        # Check OpenZeppelin vulnerabilities
        if package == 'openzeppelin' and contract_name in OPENZEPPELIN_VULNERABILITIES:
            for vuln in OPENZEPPELIN_VULNERABILITIES[contract_name]:
                min_ver, max_ver, severity, desc, cve = vuln

                findings.append(DependencyFinding(
                    title=f"Potentially Vulnerable {contract_name} Import",
                    description=f"{desc}. Vulnerable in versions {min_ver} - {max_ver}.",
                    severity=severity,
                    package=f"@openzeppelin/contracts/{contract_name}",
                    version=f"{min_ver}-{max_ver}",
                    line=import_info['line'],
                    cve=cve,
                    recommendation=f"Update to latest OpenZeppelin version and review changes. "
                                  f"Check https://github.com/OpenZeppelin/openzeppelin-contracts/releases",
                    references=[
                        "https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories",
                        f"https://www.cvedetails.com/cve/{cve}" if cve else ""
                    ]
                ))

        # Check dangerous imports
        if contract_name in DANGEROUS_IMPORTS:
            severity, desc, recommendation = DANGEROUS_IMPORTS[contract_name]

            # SafeMath is only a concern in Solidity < 0.8
            if contract_name == 'SafeMath':
                if solidity_version and solidity_version >= '0.8.0':
                    findings.append(DependencyFinding(
                        title="Unnecessary SafeMath Import",
                        description=desc,
                        severity=severity,
                        package=import_info['path'],
                        line=import_info['line'],
                        recommendation=recommendation
                    ))
            else:
                findings.append(DependencyFinding(
                    title=f"Potentially Dangerous {contract_name} Usage",
                    description=desc,
                    severity=severity,
                    package=import_info['path'],
                    line=import_info['line'],
                    recommendation=recommendation
                ))

        return findings

    def _check_dangerous_patterns(self, source_code: str, lines: List[str]) -> List[DependencyFinding]:
        """Check for dangerous patterns in code."""
        findings = []

        dangerous_patterns = [
            (r'\btx\.origin\b', 'tx.origin', DANGEROUS_IMPORTS['tx.origin']),
            (r'\bselfdestruct\s*\(', 'selfdestruct', DANGEROUS_IMPORTS['selfdestruct']),
            (r'\bdelegatecall\s*\(', 'delegatecall', DANGEROUS_IMPORTS['delegatecall']),
            (r'\becrecover\s*\(', 'ecrecover', DANGEROUS_IMPORTS['ecrecover']),
        ]

        for pattern, name, (severity, desc, recommendation) in dangerous_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(DependencyFinding(
                        title=f"Dangerous Pattern: {name}",
                        description=desc,
                        severity=severity,
                        package="builtin",
                        line=i,
                        recommendation=recommendation
                    ))

        return findings

    def get_summary(self, findings: List[DependencyFinding]) -> Dict:
        """Generate summary statistics."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_package': {},
            'cves': []
        }

        for finding in findings:
            # Count by severity
            sev = finding.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            # Count by package
            pkg = finding.package
            summary['by_package'][pkg] = summary['by_package'].get(pkg, 0) + 1

            # Track CVEs
            if finding.cve:
                summary['cves'].append(finding.cve)

        return summary


def main():
    """Example usage."""
    test_contract = '''
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
    import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
    import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
    import "@openzeppelin/contracts/utils/math/SafeMath.sol";
    import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";

    contract VulnerableContract is ERC20, ReentrancyGuard {
        using SafeMath for uint256;  // Unnecessary in 0.8+

        address public owner;

        constructor() ERC20("Test", "TST") {
            owner = tx.origin;  // Dangerous!
        }

        function verify(bytes32 hash, bytes memory sig) public view returns (address) {
            return ecrecover(hash, 0, 0, 0);  // Vulnerable!
        }

        function destroy() external {
            selfdestruct(payable(owner));  // Deprecated!
        }
    }
    '''

    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(test_contract)

    print("\n" + "="*60)
    print("  MIESC Dependency Security Analysis")
    print("="*60 + "\n")

    for i, finding in enumerate(findings, 1):
        print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
        print(f"   Package: {finding.package}")
        if finding.line:
            print(f"   Line: {finding.line}")
        if finding.cve:
            print(f"   CVE: {finding.cve}")
        print(f"   {finding.description}")
        print(f"   Recommendation: {finding.recommendation}")
        print()

    summary = analyzer.get_summary(findings)
    print("-"*60)
    print(f"Total Findings: {summary['total']}")
    print(f"By Severity: {summary['by_severity']}")
    print(f"By Package: {summary['by_package']}")
    if summary['cves']:
        print(f"CVEs: {summary['cves']}")


if __name__ == "__main__":
    main()
