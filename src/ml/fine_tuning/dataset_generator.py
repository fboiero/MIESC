"""
Solidity Security Dataset Generator for LLM Fine-Tuning

Generates training datasets from vulnerability databases, audit reports,
and MIESC analysis results for fine-tuning LLMs on Solidity security.

Author: Fernando Boiero
License: GPL-3.0
"""

import json
import os
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime


@dataclass
class VulnerabilityExample:
    """Represents a single vulnerability training example."""
    id: str
    vulnerability_type: str
    severity: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    detection_pattern: str
    remediation: str
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    source: str = "manual"


@dataclass
class TrainingExample:
    """Training example in instruction-following format."""
    instruction: str
    input: str
    output: str
    metadata: Dict[str, Any]


class SoliditySecurityDatasetGenerator:
    """
    Generates fine-tuning datasets for Solidity security analysis.

    Supports multiple output formats:
    - Alpaca format (instruction, input, output)
    - ChatML format (messages array)
    - ShareGPT format (conversations)
    """

    # Known vulnerability patterns with examples
    VULNERABILITY_TEMPLATES = {
        "reentrancy": {
            "vulnerable": '''
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] -= amount;  // State updated AFTER external call
}
''',
            "fixed": '''
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;  // State updated BEFORE external call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
''',
            "explanation": "Reentrancy vulnerability occurs when external calls are made before state updates, allowing attackers to recursively call back into the contract.",
            "cwe": "CWE-841",
            "swc": "SWC-107"
        },
        "integer_overflow": {
            "vulnerable": '''
function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;  // Can overflow in Solidity < 0.8.0
}
''',
            "fixed": '''
function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    unchecked {
        // Safe: we know balances[to] + amount won't overflow
        // because total supply is bounded
    }
    balances[to] += amount;  // Solidity 0.8+ has built-in overflow checks
}
// OR use OpenZeppelin SafeMath for < 0.8.0
''',
            "explanation": "Integer overflow/underflow occurs when arithmetic operations exceed the maximum or minimum values of the data type.",
            "cwe": "CWE-190",
            "swc": "SWC-101"
        },
        "access_control": {
            "vulnerable": '''
function setOwner(address newOwner) external {
    owner = newOwner;  // Anyone can call this!
}

function withdrawAll() external {
    payable(owner).transfer(address(this).balance);
}
''',
            "fixed": '''
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Invalid address");
    owner = newOwner;
}

function withdrawAll() external onlyOwner {
    payable(owner).transfer(address(this).balance);
}
''',
            "explanation": "Missing access control allows unauthorized users to execute privileged functions.",
            "cwe": "CWE-284",
            "swc": "SWC-105"
        },
        "unchecked_return": {
            "vulnerable": '''
function withdrawToken(address token, uint256 amount) external {
    IERC20(token).transfer(msg.sender, amount);  // Return value ignored
}
''',
            "fixed": '''
function withdrawToken(address token, uint256 amount) external {
    bool success = IERC20(token).transfer(msg.sender, amount);
    require(success, "Transfer failed");
}
// OR use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

function withdrawTokenSafe(address token, uint256 amount) external {
    IERC20(token).safeTransfer(msg.sender, amount);
}
''',
            "explanation": "ERC20 transfer() returns a boolean that must be checked. Some tokens don't revert on failure.",
            "cwe": "CWE-252",
            "swc": "SWC-104"
        },
        "tx_origin": {
            "vulnerable": '''
function transferTo(address to, uint256 amount) external {
    require(tx.origin == owner, "Not owner");  // Vulnerable to phishing
    payable(to).transfer(amount);
}
''',
            "fixed": '''
function transferTo(address to, uint256 amount) external {
    require(msg.sender == owner, "Not owner");  // Use msg.sender
    payable(to).transfer(amount);
}
''',
            "explanation": "Using tx.origin for authentication is vulnerable to phishing attacks where a malicious contract tricks the owner into calling it.",
            "cwe": "CWE-477",
            "swc": "SWC-115"
        },
        "frontrunning": {
            "vulnerable": '''
function claimReward(bytes32 solution) external {
    require(keccak256(abi.encodePacked(solution)) == solutionHash);
    payable(msg.sender).transfer(reward);
}
''',
            "fixed": '''
// Use commit-reveal scheme
mapping(address => bytes32) public commits;
mapping(address => uint256) public commitBlock;

function commit(bytes32 hashedSolution) external {
    commits[msg.sender] = hashedSolution;
    commitBlock[msg.sender] = block.number;
}

function reveal(bytes32 solution) external {
    require(block.number > commitBlock[msg.sender] + 10, "Too early");
    require(keccak256(abi.encodePacked(msg.sender, solution)) == commits[msg.sender]);
    require(keccak256(abi.encodePacked(solution)) == solutionHash);
    payable(msg.sender).transfer(reward);
}
''',
            "explanation": "Frontrunning occurs when attackers observe pending transactions and submit their own with higher gas to execute first.",
            "cwe": "CWE-362",
            "swc": "SWC-114"
        },
        "oracle_manipulation": {
            "vulnerable": '''
function getPrice() public view returns (uint256) {
    // Using spot price from single DEX - easily manipulated
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    return (reserve1 * 1e18) / reserve0;
}

function liquidate(address user) external {
    uint256 price = getPrice();
    require(collateral[user] * price < debt[user], "Healthy");
    // Liquidation logic...
}
''',
            "fixed": '''
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface internal priceFeed;

function getPrice() public view returns (uint256) {
    (
        uint80 roundID,
        int256 price,
        uint256 startedAt,
        uint256 timeStamp,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    require(price > 0, "Invalid price");
    require(timeStamp > block.timestamp - 1 hours, "Stale price");
    require(answeredInRound >= roundID, "Stale round");

    return uint256(price);
}
// OR use TWAP (Time-Weighted Average Price) from Uniswap V3
''',
            "explanation": "Using spot prices from DEXes is vulnerable to flash loan manipulation. Use decentralized oracles like Chainlink or TWAP.",
            "cwe": "CWE-829",
            "swc": "N/A"
        },
        "flash_loan_attack": {
            "vulnerable": '''
// Governance token voting based on current balance
function vote(uint256 proposalId, bool support) external {
    uint256 votes = token.balanceOf(msg.sender);  // Can be inflated via flash loan
    require(votes > 0, "No voting power");
    proposals[proposalId].votes += support ? int256(votes) : -int256(votes);
}
''',
            "fixed": '''
// Use snapshot-based voting
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

function vote(uint256 proposalId, bool support) external {
    uint256 snapshotBlock = proposals[proposalId].snapshotBlock;
    uint256 votes = token.getPastVotes(msg.sender, snapshotBlock);
    require(votes > 0, "No voting power at snapshot");
    require(!hasVoted[proposalId][msg.sender], "Already voted");

    hasVoted[proposalId][msg.sender] = true;
    proposals[proposalId].votes += support ? int256(votes) : -int256(votes);
}
''',
            "explanation": "Flash loans allow attackers to temporarily hold large token balances. Use historical snapshots for voting power.",
            "cwe": "CWE-362",
            "swc": "N/A"
        },
        "dos_gas_limit": {
            "vulnerable": '''
address[] public recipients;

function distributeRewards() external {
    for (uint256 i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(rewards[recipients[i]]);
    }
}
''',
            "fixed": '''
mapping(address => uint256) public pendingRewards;

function claimReward() external {
    uint256 amount = pendingRewards[msg.sender];
    require(amount > 0, "No rewards");
    pendingRewards[msg.sender] = 0;

    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}

// Pull pattern instead of push
function calculateReward(address user) external onlyOwner {
    pendingRewards[user] += calculateUserReward(user);
}
''',
            "explanation": "Unbounded loops can exceed block gas limit. Use pull pattern instead of push for distributions.",
            "cwe": "CWE-400",
            "swc": "SWC-128"
        },
        "signature_replay": {
            "vulnerable": '''
function executeWithSignature(
    address to,
    uint256 amount,
    bytes memory signature
) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = recoverSigner(hash, signature);
    require(signer == owner, "Invalid signature");
    payable(to).transfer(amount);
}
''',
            "fixed": '''
mapping(bytes32 => bool) public usedSignatures;
uint256 public nonce;

function executeWithSignature(
    address to,
    uint256 amount,
    uint256 _nonce,
    uint256 deadline,
    bytes memory signature
) external {
    require(block.timestamp <= deadline, "Expired");
    require(_nonce == nonce++, "Invalid nonce");

    bytes32 hash = keccak256(abi.encodePacked(
        address(this),  // Include contract address
        block.chainid,  // Include chain ID (EIP-155)
        to,
        amount,
        _nonce,
        deadline
    ));

    require(!usedSignatures[hash], "Signature already used");
    usedSignatures[hash] = true;

    address signer = recoverSigner(hash, signature);
    require(signer == owner, "Invalid signature");
    payable(to).transfer(amount);
}
''',
            "explanation": "Signatures without nonces or chain IDs can be replayed across transactions or chains.",
            "cwe": "CWE-294",
            "swc": "SWC-121"
        }
    }

    def __init__(self, output_dir: str = "datasets"):
        """Initialize the dataset generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.examples: List[VulnerabilityExample] = []

    def generate_base_examples(self) -> List[VulnerabilityExample]:
        """Generate vulnerability examples from templates."""
        examples = []

        for i, (vuln_type, template) in enumerate(self.VULNERABILITY_TEMPLATES.items()):
            example = VulnerabilityExample(
                id=f"template_{vuln_type}_{i:04d}",
                vulnerability_type=vuln_type,
                severity=self._get_severity(vuln_type),
                vulnerable_code=template["vulnerable"].strip(),
                fixed_code=template["fixed"].strip(),
                explanation=template["explanation"],
                detection_pattern=self._generate_detection_pattern(vuln_type),
                remediation=self._generate_remediation(vuln_type),
                cwe_id=template.get("cwe"),
                swc_id=template.get("swc"),
                source="miesc_templates"
            )
            examples.append(example)

        return examples

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type."""
        critical = ["reentrancy", "access_control", "oracle_manipulation", "flash_loan_attack"]
        high = ["integer_overflow", "signature_replay", "unchecked_return"]
        medium = ["tx_origin", "frontrunning", "dos_gas_limit"]

        if vuln_type in critical:
            return "critical"
        elif vuln_type in high:
            return "high"
        elif vuln_type in medium:
            return "medium"
        return "low"

    def _generate_detection_pattern(self, vuln_type: str) -> str:
        """Generate regex pattern for detecting vulnerability."""
        patterns = {
            "reentrancy": r"\.call\{.*value.*\}.*\n.*=.*-",
            "integer_overflow": r"\+\=|\-\=|\*\=",
            "access_control": r"function\s+\w+\([^)]*\)\s+(?:external|public)(?!\s+view|\s+pure)",
            "unchecked_return": r"IERC20.*\.transfer\([^)]+\);",
            "tx_origin": r"tx\.origin",
            "frontrunning": r"keccak256.*solution.*transfer",
            "oracle_manipulation": r"getReserves\(\)",
            "dos_gas_limit": r"for\s*\([^)]+\.length",
            "signature_replay": r"recoverSigner.*transfer(?!.*nonce)",
        }
        return patterns.get(vuln_type, r".*")

    def _generate_remediation(self, vuln_type: str) -> str:
        """Generate remediation advice for vulnerability type."""
        remediations = {
            "reentrancy": "Use ReentrancyGuard modifier and follow Checks-Effects-Interactions pattern",
            "integer_overflow": "Use Solidity 0.8+ or OpenZeppelin SafeMath",
            "access_control": "Implement proper access control with onlyOwner or role-based modifiers",
            "unchecked_return": "Use SafeERC20 wrapper or check return values explicitly",
            "tx_origin": "Replace tx.origin with msg.sender for authentication",
            "frontrunning": "Implement commit-reveal scheme or use private mempools",
            "oracle_manipulation": "Use Chainlink oracles or TWAP instead of spot prices",
            "flash_loan_attack": "Use snapshot-based voting or time-weighted mechanisms",
            "dos_gas_limit": "Use pull pattern instead of push for distributions",
            "signature_replay": "Include nonce, chain ID, contract address, and deadline in signed data"
        }
        return remediations.get(vuln_type, "Review and fix the vulnerability")

    def generate_training_examples(self,
                                   examples: List[VulnerabilityExample]) -> List[TrainingExample]:
        """Convert vulnerability examples to training format."""
        training_data = []

        for ex in examples:
            # Task 1: Vulnerability Detection
            training_data.append(TrainingExample(
                instruction="Analyze this Solidity code for security vulnerabilities. Identify any issues and explain their severity.",
                input=ex.vulnerable_code,
                output=f"""**Vulnerability Found: {ex.vulnerability_type.replace('_', ' ').title()}**

**Severity:** {ex.severity.upper()}
**CWE:** {ex.cwe_id or 'N/A'}
**SWC:** {ex.swc_id or 'N/A'}

**Explanation:**
{ex.explanation}

**Detection Pattern:**
{ex.detection_pattern}

**Remediation:**
{ex.remediation}""",
                metadata={
                    "task": "vulnerability_detection",
                    "vuln_type": ex.vulnerability_type,
                    "severity": ex.severity,
                    "source": ex.source
                }
            ))

            # Task 2: Code Fix Generation
            training_data.append(TrainingExample(
                instruction=f"Fix the {ex.vulnerability_type.replace('_', ' ')} vulnerability in this Solidity code.",
                input=ex.vulnerable_code,
                output=ex.fixed_code,
                metadata={
                    "task": "code_fix",
                    "vuln_type": ex.vulnerability_type,
                    "severity": ex.severity,
                    "source": ex.source
                }
            ))

            # Task 3: Explanation Generation
            training_data.append(TrainingExample(
                instruction="Explain why this code is vulnerable and how an attacker could exploit it.",
                input=ex.vulnerable_code,
                output=f"""## Vulnerability Analysis: {ex.vulnerability_type.replace('_', ' ').title()}

### How the Attack Works:
{ex.explanation}

### Exploitation Scenario:
An attacker could exploit this vulnerability by:
1. Deploying a malicious contract that interacts with the vulnerable function
2. Triggering the vulnerable code path
3. Exploiting the flaw before state is properly updated

### Impact:
- Severity: {ex.severity.upper()}
- Potential loss of funds or unauthorized access
- Smart contract compromise

### Secure Alternative:
```solidity
{ex.fixed_code}
```

### References:
- CWE: {ex.cwe_id or 'N/A'}
- SWC: {ex.swc_id or 'N/A'}""",
                metadata={
                    "task": "explanation",
                    "vuln_type": ex.vulnerability_type,
                    "severity": ex.severity,
                    "source": ex.source
                }
            ))

            # Task 4: Secure Code Verification
            training_data.append(TrainingExample(
                instruction="Verify if this Solidity code is secure against common vulnerabilities.",
                input=ex.fixed_code,
                output=f"""**Security Analysis: SECURE**

This code implements proper protection against {ex.vulnerability_type.replace('_', ' ')}:

**Security Measures Applied:**
- {ex.remediation}

**Best Practices Followed:**
- Proper input validation
- Safe state management
- Secure external interactions

**Recommendation:** The code follows security best practices. Continue monitoring for new vulnerability patterns.""",
                metadata={
                    "task": "verification",
                    "vuln_type": ex.vulnerability_type,
                    "is_secure": True,
                    "source": ex.source
                }
            ))

        return training_data

    def export_alpaca_format(self,
                             training_data: List[TrainingExample],
                             filename: str = "solidity_security_alpaca.json") -> str:
        """Export dataset in Alpaca instruction-following format."""
        alpaca_data = [
            {
                "instruction": ex.instruction,
                "input": ex.input,
                "output": ex.output
            }
            for ex in training_data
        ]

        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(alpaca_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def export_chatml_format(self,
                             training_data: List[TrainingExample],
                             filename: str = "solidity_security_chatml.jsonl") -> str:
        """Export dataset in ChatML format (for models like DeepSeek)."""
        output_path = self.output_dir / filename

        with open(output_path, "w", encoding="utf-8") as f:
            for ex in training_data:
                conversation = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are an expert Solidity security auditor specializing in smart contract vulnerability detection and remediation."
                        },
                        {
                            "role": "user",
                            "content": f"{ex.instruction}\n\n```solidity\n{ex.input}\n```"
                        },
                        {
                            "role": "assistant",
                            "content": ex.output
                        }
                    ]
                }
                f.write(json.dumps(conversation, ensure_ascii=False) + "\n")

        return str(output_path)

    def export_sharegpt_format(self,
                               training_data: List[TrainingExample],
                               filename: str = "solidity_security_sharegpt.json") -> str:
        """Export dataset in ShareGPT conversation format."""
        sharegpt_data = []

        for ex in training_data:
            conversation = {
                "conversations": [
                    {
                        "from": "human",
                        "value": f"{ex.instruction}\n\n```solidity\n{ex.input}\n```"
                    },
                    {
                        "from": "gpt",
                        "value": ex.output
                    }
                ]
            }
            sharegpt_data.append(conversation)

        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sharegpt_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def generate_full_dataset(self) -> Dict[str, str]:
        """Generate complete dataset in all formats."""
        # Generate base examples
        vuln_examples = self.generate_base_examples()

        # Convert to training format
        training_data = self.generate_training_examples(vuln_examples)

        # Export in all formats
        paths = {
            "alpaca": self.export_alpaca_format(training_data),
            "chatml": self.export_chatml_format(training_data),
            "sharegpt": self.export_sharegpt_format(training_data)
        }

        # Generate statistics
        stats = {
            "total_examples": len(training_data),
            "vulnerability_types": len(self.VULNERABILITY_TEMPLATES),
            "tasks": ["vulnerability_detection", "code_fix", "explanation", "verification"],
            "formats": list(paths.keys()),
            "generated_at": datetime.now().isoformat()
        }

        stats_path = self.output_dir / "dataset_stats.json"
        with open(stats_path, "w") as f:
            json.dump(stats, f, indent=2)

        paths["stats"] = str(stats_path)

        return paths


def main():
    """Generate Solidity security fine-tuning dataset."""
    generator = SoliditySecurityDatasetGenerator(output_dir="data/fine_tuning")
    paths = generator.generate_full_dataset()

    print("Dataset generated successfully!")
    print(f"Files created:")
    for format_name, path in paths.items():
        print(f"  - {format_name}: {path}")


if __name__ == "__main__":
    main()
