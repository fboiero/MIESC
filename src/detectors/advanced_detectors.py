#!/usr/bin/env python3
"""
MIESC v4.1 - Advanced Vulnerability Detectors

Specialized detectors for modern attack patterns:
- Rug Pull Detection
- Governance Attacks
- Token Security (Honeypot, Fee Manipulation)
- Proxy/Upgrade Vulnerabilities

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class AttackCategory(Enum):
    RUG_PULL = "rug_pull"
    GOVERNANCE = "governance_attack"
    HONEYPOT = "honeypot"
    TOKEN_SECURITY = "token_security"
    PROXY_UPGRADE = "proxy_upgrade"
    CENTRALIZATION = "centralization_risk"


@dataclass
class AdvancedFinding:
    """Represents an advanced vulnerability finding."""
    title: str
    description: str
    severity: Severity
    category: AttackCategory
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = "high"


# =============================================================================
# RUG PULL DETECTOR
# =============================================================================

class RugPullDetector:
    """
    Detects rug pull vulnerability patterns.

    Common rug pull indicators:
    - Hidden mint functions
    - Ownership can drain funds
    - Liquidity can be removed by owner
    - Hidden transfer restrictions
    - Blacklist functionality controlled by owner
    """

    name = "rug-pull-detector"
    description = "Detects potential rug pull patterns"
    category = AttackCategory.RUG_PULL

    # Dangerous owner-only patterns
    OWNER_DRAIN_PATTERNS = [
        (r'function\s+\w*[Ww]ithdraw\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner-only withdrawal function - can drain contract funds"),
        (r'function\s+\w*[Dd]rain\w*\s*\([^)]*\)',
         "Drain function detected - potential rug pull mechanism"),
        (r'function\s+\w*[Rr]emove[Ll]iquidity\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner can remove liquidity - rug pull risk"),
        (r'\.transfer\s*\(\s*address\s*\(\s*this\s*\)\s*\.balance\s*\)',
         "Transfer entire contract balance - potential drain"),
    ]

    # Hidden mint patterns
    HIDDEN_MINT_PATTERNS = [
        (r'function\s+\w*[Mm]int\w*\s*\([^)]*\)\s*(?:external|public|internal)[^{]*(?!view|pure)',
         "Mint function detected - check for access control"),
        (r'_mint\s*\(\s*\w+\s*,\s*\d{10,}',
         "Large mint amount hardcoded - inflation risk"),
        (r'totalSupply\s*\+?=',
         "Direct totalSupply modification - bypasses mint controls"),
    ]

    # Blacklist/whitelist abuse
    BLACKLIST_PATTERNS = [
        (r'mapping\s*\([^)]*\)\s*(?:public|private|internal)?\s*\w*[Bb]lack[Ll]ist',
         "Blacklist mapping - can block user transfers"),
        (r'require\s*\(\s*!\s*\w*[Bb]lack[Ll]ist',
         "Blacklist check in transfer - centralized control"),
        (r'function\s+\w*[Bb]lack[Ll]ist\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner can blacklist addresses - censorship risk"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        findings = []
        lines = source_code.split('\n')

        all_patterns = (
            self.OWNER_DRAIN_PATTERNS +
            self.HIDDEN_MINT_PATTERNS +
            self.BLACKLIST_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = Severity.CRITICAL if 'drain' in description.lower() else Severity.HIGH
                    findings.append(AdvancedFinding(
                        title="Potential Rug Pull Pattern",
                        description=f"{description}. Found at line {i}.",
                        severity=severity,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Review ownership controls. Consider timelocks, "
                                      "multi-sig, or renouncing ownership after launch.",
                        references=[
                            "https://rugdoc.io/education/",
                            "https://www.certik.com/resources/blog/rug-pull-prevention"
                        ]
                    ))

        # Check for renounced ownership (good sign)
        if re.search(r'renounceOwnership|owner\s*=\s*address\(0\)', source_code):
            # This is actually good - reduces rug pull risk
            pass
        elif re.search(r'onlyOwner', source_code):
            findings.append(AdvancedFinding(
                title="Ownership Not Renounced",
                description="Contract has onlyOwner functions but ownership is not renounced. "
                           "Owner retains control over critical functions.",
                severity=Severity.MEDIUM,
                category=self.category,
                recommendation="Consider renouncing ownership after deployment or "
                              "implementing timelock for owner functions.",
                references=["https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable"]
            ))

        return findings


# =============================================================================
# GOVERNANCE ATTACK DETECTOR
# =============================================================================

class GovernanceDetector:
    """
    Detects governance attack vulnerabilities.

    Common issues:
    - Flash loan governance attacks
    - Quorum manipulation
    - Proposal spam
    - Timelock bypass
    - Vote buying
    """

    name = "governance-detector"
    description = "Detects governance attack vulnerabilities"
    category = AttackCategory.GOVERNANCE

    # Flash loan voting patterns
    FLASH_LOAN_VOTE_PATTERNS = [
        (r'function\s+\w*[Vv]ote\w*\s*\([^)]*\)[^{]*{[^}]*balanceOf',
         "Vote uses current balance - vulnerable to flash loan attacks"),
        (r'getVotes\s*\(\s*msg\.sender\s*\)',
         "Voting power from current snapshot may be manipulable"),
    ]

    # Timelock issues
    TIMELOCK_PATTERNS = [
        (r'function\s+execute\w*\s*\([^)]*\)[^{]*(?!require.*delay|require.*timelock)',
         "Execute function without timelock verification"),
        (r'delay\s*=\s*0|minDelay\s*=\s*0',
         "Zero delay in timelock - immediate execution possible"),
    ]

    # Quorum issues
    QUORUM_PATTERNS = [
        (r'quorum\s*[=<>]\s*\d{1,2}[^0-9]',
         "Low quorum value - proposals may pass with minimal support"),
        (r'function\s+\w*[Ss]etQuorum\w*\s*\([^)]*\)\s*(?:external|public)',
         "Quorum can be modified - governance manipulation risk"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check if this is a governance contract
        is_governance = re.search(
            r'Governor|Voting|Proposal|DAO|governance',
            source_code,
            re.IGNORECASE
        )

        if not is_governance:
            return findings

        all_patterns = (
            self.FLASH_LOAN_VOTE_PATTERNS +
            self.TIMELOCK_PATTERNS +
            self.QUORUM_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(AdvancedFinding(
                        title="Governance Vulnerability",
                        description=f"{description}. Found at line {i}.",
                        severity=Severity.HIGH,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Use checkpoint-based voting (ERC20Votes), "
                                      "implement proper timelocks, and set reasonable quorum.",
                        references=[
                            "https://blog.openzeppelin.com/governor-smart-contract-security-audit",
                            "https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest"
                        ]
                    ))

        # Check for missing vote delegation
        if not re.search(r'delegate|checkpoint|getPastVotes', source_code, re.IGNORECASE):
            findings.append(AdvancedFinding(
                title="Missing Vote Checkpointing",
                description="Governance contract lacks vote checkpointing. "
                           "Vulnerable to flash loan voting attacks.",
                severity=Severity.CRITICAL,
                category=self.category,
                recommendation="Implement ERC20Votes or similar checkpoint mechanism "
                              "to prevent flash loan governance attacks.",
                references=["https://eips.ethereum.org/EIPS/eip-5805"]
            ))

        return findings


# =============================================================================
# TOKEN SECURITY DETECTOR (HONEYPOT)
# =============================================================================

class TokenSecurityDetector:
    """
    Detects token security issues including honeypots.

    Common issues:
    - Hidden transfer fees
    - Transfer restrictions
    - Buy/sell asymmetry
    - Hidden max transaction limits
    - Anti-bot measures that trap users
    """

    name = "token-security-detector"
    description = "Detects token security issues and honeypots"
    category = AttackCategory.HONEYPOT

    # Honeypot patterns
    HONEYPOT_PATTERNS = [
        (r'require\s*\(\s*\w+\s*==\s*owner\s*\|\|\s*\w+\s*==\s*owner',
         "Transfer only allowed to/from owner - honeypot indicator"),
        (r'if\s*\(\s*\w+\s*!=\s*owner\s*\)\s*{?\s*revert',
         "Non-owner transfers reverted - honeypot"),
        (r'_transfer[^}]*require\s*\(\s*(?:is[Aa]llowed|can[Ss]ell|can[Tt]ransfer)',
         "Conditional transfer restrictions - potential honeypot"),
    ]

    # Hidden fee patterns
    HIDDEN_FEE_PATTERNS = [
        (r'(?:tax|fee|burn)[Pp]ercent\s*=\s*\d{2,}',
         "High transfer fee percentage detected"),
        (r'function\s+\w*[Ss]et(?:Tax|Fee)\w*\s*\([^)]*\)\s*(?:external|public)',
         "Fee can be changed after deployment - fee manipulation risk"),
        (r'(?:buy|sell)[Ff]ee\s*>\s*(?:sell|buy)[Ff]ee',
         "Asymmetric buy/sell fees detected"),
    ]

    # Max transaction patterns
    MAX_TX_PATTERNS = [
        (r'max[Tt]x[Aa]mount\s*=\s*\d+\s*\*\s*10\s*\*\*\s*\d+',
         "Max transaction limit - may prevent large sells"),
        (r'require\s*\([^)]*<\s*max[Tt]x',
         "Transaction size limited - check if owner can modify"),
        (r'function\s+\w*[Ss]etMax[Tt]x\w*\s*\([^)]*\)\s*(?:external|public)',
         "Max transaction limit can be changed - manipulation risk"),
    ]

    # Anti-bot that can trap users
    ANTIBOT_PATTERNS = [
        (r'require\s*\(\s*!?\s*is[Bb]ot\s*\[',
         "Bot detection mechanism - verify it cannot trap legitimate users"),
        (r'function\s+\w*[Ss]et[Bb]ot\w*\s*\([^)]*\)\s*(?:external|public)',
         "Owner can mark addresses as bots - censorship risk"),
        (r'trading[Ee]nabled|launch[Tt]ime|start[Bb]lock',
         "Trading controls - verify owner cannot disable trading"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check if this is a token contract
        is_token = re.search(r'ERC20|transfer|balanceOf|totalSupply', source_code)
        if not is_token:
            return findings

        all_patterns = (
            self.HONEYPOT_PATTERNS +
            self.HIDDEN_FEE_PATTERNS +
            self.MAX_TX_PATTERNS +
            self.ANTIBOT_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Determine severity based on pattern type
                    if 'honeypot' in description.lower():
                        severity = Severity.CRITICAL
                    elif 'fee' in description.lower() or 'manipulation' in description.lower():
                        severity = Severity.HIGH
                    else:
                        severity = Severity.MEDIUM

                    findings.append(AdvancedFinding(
                        title="Token Security Issue",
                        description=f"{description}. Found at line {i}.",
                        severity=severity,
                        category=AttackCategory.TOKEN_SECURITY,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Review token mechanics for honeypot indicators. "
                                      "Ensure users can always sell tokens.",
                        references=[
                            "https://tokensniffer.com/",
                            "https://honeypot.is/"
                        ]
                    ))

        return findings


# =============================================================================
# PROXY/UPGRADE VULNERABILITY DETECTOR
# =============================================================================

class ProxyUpgradeDetector:
    """
    Detects proxy and upgrade vulnerabilities.

    Common issues:
    - Uninitialized proxy
    - Storage collision
    - Function selector clashing
    - Missing upgrade authorization
    - Delegatecall to untrusted contract
    """

    name = "proxy-upgrade-detector"
    description = "Detects proxy and upgrade vulnerabilities"
    category = AttackCategory.PROXY_UPGRADE

    # Initialization issues
    INIT_PATTERNS = [
        (r'function\s+initialize\s*\([^)]*\)[^{]*{(?![^}]*initialized\s*=\s*true)',
         "Initialize function may be callable multiple times"),
        (r'constructor\s*\([^)]*\)[^{]*{[^}]*_disableInitializers',
         "Good: Using _disableInitializers in constructor"),
    ]

    # Storage collision patterns
    STORAGE_PATTERNS = [
        (r'assembly\s*{[^}]*sstore',
         "Direct storage manipulation - potential storage collision"),
        (r'StorageSlot\.getUint256Slot',
         "Using storage slots - verify no collision with implementation"),
    ]

    # Upgrade authorization
    UPGRADE_AUTH_PATTERNS = [
        (r'function\s+\w*[Uu]pgrade\w*\s*\([^)]*\)\s*(?:external|public)(?![^{]*onlyOwner|[^{]*onlyRole)',
         "Upgrade function without access control - critical vulnerability"),
        (r'_authorizeUpgrade\s*\([^)]*\)\s*(?:internal|private)[^{]*(?:override)?[^{]*{[^}]*}',
         "Empty _authorizeUpgrade - anyone can upgrade"),
    ]

    # Delegatecall issues
    DELEGATECALL_PATTERNS = [
        (r'delegatecall\s*\([^)]*(?:msg\.data|abi\.encode)',
         "Delegatecall with user-controlled data - verify target validation"),
        (r'\.delegatecall\s*\(\s*[^)]*\)',
         "Delegatecall detected - ensure target is trusted"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        findings = []
        lines = source_code.split('\n')

        # Check if this is a proxy/upgradeable contract
        is_proxy = re.search(
            r'Proxy|Upgradeable|UUPS|Transparent|Beacon|delegatecall|implementation',
            source_code,
            re.IGNORECASE
        )

        if not is_proxy:
            return findings

        all_patterns = (
            self.INIT_PATTERNS +
            self.STORAGE_PATTERNS +
            self.UPGRADE_AUTH_PATTERNS +
            self.DELEGATECALL_PATTERNS
        )

        for i, line in enumerate(lines, 1):
            for pattern, description in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip "good" patterns
                    if 'Good:' in description:
                        continue

                    severity = Severity.CRITICAL if 'upgrade' in description.lower() else Severity.HIGH

                    findings.append(AdvancedFinding(
                        title="Proxy/Upgrade Vulnerability",
                        description=f"{description}. Found at line {i}.",
                        severity=severity,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Use OpenZeppelin's upgradeable contracts. "
                                      "Implement proper access control for upgrades. "
                                      "Use initializer modifier and _disableInitializers.",
                        references=[
                            "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable",
                            "https://blog.openzeppelin.com/proxy-patterns"
                        ]
                    ))

        # Check for missing initializer modifier
        has_initialize = re.search(r'function\s+initialize', source_code)
        has_initializer_mod = re.search(r'initializer\s*(?:override)?', source_code)

        if has_initialize and not has_initializer_mod:
            findings.append(AdvancedFinding(
                title="Missing Initializer Modifier",
                description="Initialize function exists but initializer modifier not found. "
                           "Function may be callable multiple times.",
                severity=Severity.CRITICAL,
                category=self.category,
                recommendation="Add 'initializer' modifier from OpenZeppelin to prevent re-initialization.",
                references=["https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable"]
            ))

        return findings


# =============================================================================
# CENTRALIZATION RISK DETECTOR
# =============================================================================

class CentralizationDetector:
    """
    Detects centralization risks.

    Issues detected:
    - Single owner control
    - Missing multi-sig
    - No timelock on critical functions
    - Privileged roles without limits
    """

    name = "centralization-detector"
    description = "Detects centralization risks"
    category = AttackCategory.CENTRALIZATION

    CENTRALIZATION_PATTERNS = [
        (r'onlyOwner[^}]*(?:selfdestruct|suicide)',
         "Owner can destroy contract - total loss risk"),
        (r'onlyOwner[^}]*(?:pause|unpause)',
         "Owner can pause contract - centralization risk"),
        (r'function\s+\w*[Ss]etFee\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner can change fees - user fund risk"),
        (r'function\s+\w*[Mm]int\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner can mint tokens - inflation risk"),
        (r'function\s+\w*[Bb]urn\w*\s*\([^)]*\)\s*(?:external|public)[^{]*onlyOwner',
         "Owner can burn tokens - supply manipulation"),
    ]

    def detect(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        findings = []
        lines = source_code.split('\n')

        # Count owner-only functions
        owner_functions = len(re.findall(r'onlyOwner', source_code))

        if owner_functions > 5:
            findings.append(AdvancedFinding(
                title="High Centralization Risk",
                description=f"Contract has {owner_functions} owner-only functions. "
                           "Significant centralization risk.",
                severity=Severity.MEDIUM,
                category=self.category,
                recommendation="Consider multi-sig wallet, timelocks, or DAO governance "
                              "for critical functions.",
                references=["https://www.certik.com/resources/blog/centralization-risks"]
            ))

        for i, line in enumerate(lines, 1):
            for pattern, description in self.CENTRALIZATION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(AdvancedFinding(
                        title="Centralization Risk",
                        description=f"{description}. Found at line {i}.",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        line=i,
                        code_snippet=line.strip(),
                        recommendation="Add timelock or multi-sig requirement for this function.",
                        references=[]
                    ))

        # Check for timelock
        has_timelock = re.search(r'[Tt]imelock|delay|pending', source_code)
        has_multisig = re.search(r'[Mm]ulti[Ss]ig|[Gg]nosis|[Ss]afe', source_code)

        if owner_functions > 0 and not has_timelock and not has_multisig:
            findings.append(AdvancedFinding(
                title="No Timelock or Multi-sig",
                description="Contract has owner privileges but no timelock or multi-sig. "
                           "Owner actions are immediate and irreversible.",
                severity=Severity.MEDIUM,
                category=self.category,
                recommendation="Implement OpenZeppelin TimelockController or use Gnosis Safe.",
                references=["https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController"]
            ))

        return findings


# =============================================================================
# ADVANCED DETECTOR ENGINE
# =============================================================================

class AdvancedDetectorEngine:
    """Engine to run all advanced detectors."""

    def __init__(self):
        self.detectors = [
            RugPullDetector(),
            GovernanceDetector(),
            TokenSecurityDetector(),
            ProxyUpgradeDetector(),
            CentralizationDetector(),
        ]

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[AdvancedFinding]:
        """Run all detectors on source code."""
        all_findings = []
        for detector in self.detectors:
            findings = detector.detect(source_code, file_path)
            all_findings.extend(findings)
        return all_findings

    def analyze_file(self, file_path: Path) -> List[AdvancedFinding]:
        """Analyze a Solidity file."""
        with open(file_path, 'r') as f:
            source_code = f.read()
        return self.analyze(source_code, file_path)

    def get_summary(self, findings: List[AdvancedFinding]) -> Dict:
        """Generate summary statistics."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_category': {},
        }

        for finding in findings:
            sev = finding.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            cat = finding.category.value
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1

        return summary


def main():
    """Example usage."""
    test_contract = '''
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
    import "@openzeppelin/contracts/access/Ownable.sol";

    contract SuspiciousToken is ERC20, Ownable {
        mapping(address => bool) public blacklist;
        uint256 public buyFee = 5;
        uint256 public sellFee = 25;  // High sell fee!
        uint256 public maxTxAmount = 1000000 * 10**18;
        bool public tradingEnabled = false;

        constructor() ERC20("Suspicious", "SUS") Ownable(msg.sender) {
            _mint(msg.sender, 1000000000 * 10**18);
        }

        function setBlacklist(address account, bool value) external onlyOwner {
            blacklist[account] = value;
        }

        function setSellFee(uint256 fee) external onlyOwner {
            sellFee = fee;  // Can set to 100%!
        }

        function setMaxTx(uint256 amount) external onlyOwner {
            maxTxAmount = amount;
        }

        function enableTrading() external onlyOwner {
            tradingEnabled = true;
        }

        function withdrawAll() external onlyOwner {
            payable(owner()).transfer(address(this).balance);
        }

        function _transfer(address from, address to, uint256 amount) internal override {
            require(!blacklist[from], "Blacklisted");
            require(tradingEnabled || from == owner(), "Trading not enabled");
            require(amount <= maxTxAmount, "Exceeds max tx");

            uint256 fee = from == owner() ? 0 : sellFee;
            uint256 feeAmount = amount * fee / 100;

            super._transfer(from, to, amount - feeAmount);
            if (feeAmount > 0) {
                super._transfer(from, owner(), feeAmount);
            }
        }
    }
    '''

    engine = AdvancedDetectorEngine()
    findings = engine.analyze(test_contract)

    print("\n" + "="*60)
    print("  MIESC Advanced Vulnerability Scanner")
    print("="*60 + "\n")

    for i, finding in enumerate(findings, 1):
        print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
        print(f"   Category: {finding.category.value}")
        if finding.line:
            print(f"   Line: {finding.line}")
        print(f"   {finding.description}")
        print(f"   Recommendation: {finding.recommendation}")
        print()

    summary = engine.get_summary(findings)
    print("-"*60)
    print(f"Total Findings: {summary['total']}")
    print(f"By Severity: {summary['by_severity']}")
    print(f"By Category: {summary['by_category']}")


if __name__ == "__main__":
    main()
