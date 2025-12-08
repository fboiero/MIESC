"""
MIESC Remediation Database
Comprehensive remediation suggestions for Solidity vulnerabilities
"""

from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class Remediation:
    """Remediation suggestion for a vulnerability."""
    swc_id: str
    title: str
    severity: str
    description: str
    fix: str
    example_vulnerable: str
    example_fixed: str
    references: List[str]
    gas_impact: str = "None"
    breaking_change: bool = False


# Comprehensive remediation database based on SWC Registry
REMEDIATIONS: Dict[str, Remediation] = {
    # SWC-100: Function Default Visibility
    "SWC-100": Remediation(
        swc_id="SWC-100",
        title="Function Default Visibility",
        severity="MEDIUM",
        description="Functions without explicit visibility are public by default in older Solidity versions.",
        fix="Always explicitly declare function visibility (public, external, internal, private).",
        example_vulnerable="""// Vulnerable: No visibility specified
function transfer(address to, uint amount) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}""",
        example_fixed="""// Fixed: Explicit visibility
function transfer(address to, uint amount) public {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}""",
        references=["https://swcregistry.io/docs/SWC-100"],
        gas_impact="None"
    ),

    # SWC-101: Integer Overflow and Underflow
    "SWC-101": Remediation(
        swc_id="SWC-101",
        title="Integer Overflow and Underflow",
        severity="HIGH",
        description="Arithmetic operations can overflow/underflow in Solidity <0.8.0.",
        fix="Use Solidity 0.8+ (built-in checks) or OpenZeppelin SafeMath.",
        example_vulnerable="""// Vulnerable: Can overflow
uint256 balance = 0;
balance -= 1;  // Underflows to max uint256!""",
        example_fixed="""// Fixed: Solidity 0.8+ has built-in checks
// Or use SafeMath for older versions:
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;

uint256 balance = 100;
balance = balance.sub(1);  // Reverts on underflow""",
        references=["https://swcregistry.io/docs/SWC-101", "CWE-190"],
        gas_impact="Minimal (~200 gas per operation)"
    ),

    # SWC-102: Outdated Compiler Version
    "SWC-102": Remediation(
        swc_id="SWC-102",
        title="Outdated Compiler Version",
        severity="LOW",
        description="Using an outdated compiler version may miss important security fixes.",
        fix="Use a recent stable Solidity version (0.8.19+ recommended).",
        example_vulnerable="""pragma solidity ^0.4.0;  // Very outdated!""",
        example_fixed="""pragma solidity 0.8.19;  // Recent stable version""",
        references=["https://swcregistry.io/docs/SWC-102"],
        gas_impact="May improve gas efficiency"
    ),

    # SWC-103: Floating Pragma
    "SWC-103": Remediation(
        swc_id="SWC-103",
        title="Floating Pragma",
        severity="LOW",
        description="Contracts should be deployed with the same compiler version used for testing.",
        fix="Lock the pragma to a specific version for production deployments.",
        example_vulnerable="""pragma solidity ^0.8.0;  // Floating - can be 0.8.0 to 0.8.x""",
        example_fixed="""pragma solidity 0.8.19;  // Locked to specific version""",
        references=["https://swcregistry.io/docs/SWC-103"],
        gas_impact="None"
    ),

    # SWC-104: Unchecked Call Return Value
    "SWC-104": Remediation(
        swc_id="SWC-104",
        title="Unchecked Call Return Value",
        severity="HIGH",
        description="Low-level calls (call, send, delegatecall) return false on failure instead of reverting.",
        fix="Always check the return value of low-level calls.",
        example_vulnerable="""// Vulnerable: Return value ignored
payable(recipient).send(amount);
address(target).call(data);""",
        example_fixed="""// Fixed: Check return values
(bool success, ) = payable(recipient).call{value: amount}("");
require(success, "Transfer failed");

// Or use OpenZeppelin's Address library
import "@openzeppelin/contracts/utils/Address.sol";
Address.sendValue(payable(recipient), amount);""",
        references=["https://swcregistry.io/docs/SWC-104", "CWE-252"],
        gas_impact="Minimal"
    ),

    # SWC-105: Unprotected Ether Withdrawal
    "SWC-105": Remediation(
        swc_id="SWC-105",
        title="Unprotected Ether Withdrawal",
        severity="CRITICAL",
        description="Functions that withdraw Ether lack access control.",
        fix="Add access control modifiers (onlyOwner, onlyRole) to sensitive functions.",
        example_vulnerable="""// Vulnerable: Anyone can withdraw
function withdraw() external {
    payable(msg.sender).transfer(address(this).balance);
}""",
        example_fixed="""// Fixed: Access control
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureContract is Ownable {
    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}""",
        references=["https://swcregistry.io/docs/SWC-105", "CWE-284"],
        gas_impact="~2,100 gas for SLOAD",
        breaking_change=True
    ),

    # SWC-106: Unprotected SELFDESTRUCT
    "SWC-106": Remediation(
        swc_id="SWC-106",
        title="Unprotected SELFDESTRUCT",
        severity="CRITICAL",
        description="The selfdestruct function is accessible without proper authorization.",
        fix="Add strong access control or remove selfdestruct entirely.",
        example_vulnerable="""// Vulnerable: Anyone can destroy
function destroy() external {
    selfdestruct(payable(msg.sender));
}""",
        example_fixed="""// Fixed: Protected + time-locked
import "@openzeppelin/contracts/access/Ownable.sol";

uint256 public destructionRequestTime;

function requestDestruction() external onlyOwner {
    destructionRequestTime = block.timestamp;
}

function destroy() external onlyOwner {
    require(destructionRequestTime != 0, "Not requested");
    require(block.timestamp >= destructionRequestTime + 7 days, "Too early");
    selfdestruct(payable(owner()));
}""",
        references=["https://swcregistry.io/docs/SWC-106"],
        gas_impact="None",
        breaking_change=True
    ),

    # SWC-107: Reentrancy
    "SWC-107": Remediation(
        swc_id="SWC-107",
        title="Reentrancy",
        severity="CRITICAL",
        description="External calls can re-enter the contract before state updates complete.",
        fix="Use Checks-Effects-Interactions pattern or ReentrancyGuard.",
        example_vulnerable="""// Vulnerable: State updated after external call
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] = 0;  // Too late!
}""",
        example_fixed="""// Fixed: Checks-Effects-Interactions pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Effects: Update state BEFORE interaction
        balances[msg.sender] = 0;

        // Interactions: External call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}""",
        references=["https://swcregistry.io/docs/SWC-107", "CWE-841", "The DAO Hack"],
        gas_impact="~10,000 gas for ReentrancyGuard"
    ),

    # SWC-108: State Variable Default Visibility
    "SWC-108": Remediation(
        swc_id="SWC-108",
        title="State Variable Default Visibility",
        severity="LOW",
        description="State variables have internal visibility by default.",
        fix="Explicitly declare visibility for all state variables.",
        example_vulnerable="""// Vulnerable: Implicit internal
uint256 secretData;""",
        example_fixed="""// Fixed: Explicit visibility
uint256 private secretData;
uint256 public visibleData;""",
        references=["https://swcregistry.io/docs/SWC-108"],
        gas_impact="None"
    ),

    # SWC-109: Uninitialized Storage Pointer
    "SWC-109": Remediation(
        swc_id="SWC-109",
        title="Uninitialized Storage Pointer",
        severity="HIGH",
        description="Local storage variables can point to unexpected storage slots.",
        fix="Always initialize storage variables or use memory keyword.",
        example_vulnerable="""// Vulnerable: Uninitialized storage pointer
function vulnerable() external {
    Struct storage s;  // Points to slot 0!
    s.value = 123;     // Corrupts storage
}""",
        example_fixed="""// Fixed: Proper initialization
mapping(uint => Struct) private data;

function secure(uint id) external {
    Struct storage s = data[id];  // Properly initialized
    s.value = 123;
}""",
        references=["https://swcregistry.io/docs/SWC-109"],
        gas_impact="None"
    ),

    # SWC-110: Assert Violation
    "SWC-110": Remediation(
        swc_id="SWC-110",
        title="Assert Violation",
        severity="MEDIUM",
        description="Assert should only be used for invariants that should never be false.",
        fix="Use require() for input validation, assert() only for invariants.",
        example_vulnerable="""// Misuse: Assert for input validation
function transfer(uint amount) external {
    assert(amount > 0);  // Consumes all gas on failure
}""",
        example_fixed="""// Fixed: Use require for validation
function transfer(uint amount) external {
    require(amount > 0, "Amount must be positive");
}""",
        references=["https://swcregistry.io/docs/SWC-110"],
        gas_impact="Assert consumes all gas, require refunds remaining"
    ),

    # SWC-111: Use of Deprecated Functions
    "SWC-111": Remediation(
        swc_id="SWC-111",
        title="Use of Deprecated Functions",
        severity="LOW",
        description="Deprecated functions may be removed in future versions.",
        fix="Replace deprecated functions with their modern equivalents.",
        example_vulnerable="""// Deprecated functions
msg.gas        // Use gasleft()
throw;         // Use revert()
sha3(...)      // Use keccak256(...)
suicide(addr)  // Use selfdestruct(addr)
block.blockhash(n) // Use blockhash(n)""",
        example_fixed="""// Modern equivalents
gasleft()
revert("Error message")
keccak256(abi.encodePacked(...))
selfdestruct(payable(addr))
blockhash(n)""",
        references=["https://swcregistry.io/docs/SWC-111"],
        gas_impact="None"
    ),

    # SWC-112: Delegatecall to Untrusted Callee
    "SWC-112": Remediation(
        swc_id="SWC-112",
        title="Delegatecall to Untrusted Callee",
        severity="CRITICAL",
        description="Delegatecall executes code in the caller's context.",
        fix="Only delegatecall to trusted, immutable contracts. Use OpenZeppelin proxy patterns.",
        example_vulnerable="""// Vulnerable: User-controlled delegatecall
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);  // Can modify any storage!
}""",
        example_fixed="""// Fixed: Use established proxy patterns
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Or restrict to trusted implementations
address public immutable trustedImplementation;

function execute(bytes calldata data) external {
    trustedImplementation.delegatecall(data);
}""",
        references=["https://swcregistry.io/docs/SWC-112", "Parity Wallet Hack"],
        gas_impact="None",
        breaking_change=True
    ),

    # SWC-113: DoS with Failed Call
    "SWC-113": Remediation(
        swc_id="SWC-113",
        title="DoS with Failed Call",
        severity="MEDIUM",
        description="A failed external call can block other operations.",
        fix="Use pull-over-push pattern for payments.",
        example_vulnerable="""// Vulnerable: One failed transfer blocks all
function distributeRewards(address[] calldata recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(rewards[recipients[i]]);
    }
}""",
        example_fixed="""// Fixed: Pull pattern - users withdraw themselves
mapping(address => uint256) public pendingWithdrawals;

function claimReward() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "Nothing to claim");
    pendingWithdrawals[msg.sender] = 0;

    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}""",
        references=["https://swcregistry.io/docs/SWC-113", "King of Ether"],
        gas_impact="Slightly higher for individual withdrawals"
    ),

    # SWC-114: Transaction Order Dependence (Front-Running)
    "SWC-114": Remediation(
        swc_id="SWC-114",
        title="Transaction Order Dependence (Front-Running)",
        severity="MEDIUM",
        description="Miners/validators can reorder transactions for profit.",
        fix="Use commit-reveal schemes, submarine sends, or MEV protection.",
        example_vulnerable="""// Vulnerable: Visible before execution
function submitAnswer(bytes32 answer) external {
    if (keccak256(abi.encodePacked(answer)) == secretHash) {
        winner = msg.sender;  // Can be front-run!
    }
}""",
        example_fixed="""// Fixed: Commit-reveal scheme
mapping(address => bytes32) public commitments;

function commit(bytes32 hash) external {
    commitments[msg.sender] = hash;
}

function reveal(bytes32 answer, bytes32 salt) external {
    require(
        keccak256(abi.encodePacked(answer, salt)) == commitments[msg.sender],
        "Invalid reveal"
    );
    if (keccak256(abi.encodePacked(answer)) == secretHash) {
        winner = msg.sender;
    }
}""",
        references=["https://swcregistry.io/docs/SWC-114"],
        gas_impact="Higher due to two transactions"
    ),

    # SWC-115: Authorization through tx.origin
    "SWC-115": Remediation(
        swc_id="SWC-115",
        title="Authorization through tx.origin",
        severity="HIGH",
        description="tx.origin returns the original sender, enabling phishing attacks.",
        fix="Always use msg.sender for authorization.",
        example_vulnerable="""// Vulnerable: Uses tx.origin
function transfer(address to, uint amount) external {
    require(tx.origin == owner);  // Phishing vulnerable!
    balances[to] += amount;
}""",
        example_fixed="""// Fixed: Use msg.sender
function transfer(address to, uint amount) external {
    require(msg.sender == owner, "Not authorized");
    balances[to] += amount;
}""",
        references=["https://swcregistry.io/docs/SWC-115", "CWE-477"],
        gas_impact="None"
    ),

    # SWC-116: Block Timestamp Dependence
    "SWC-116": Remediation(
        swc_id="SWC-116",
        title="Block Timestamp Dependence",
        severity="LOW",
        description="block.timestamp can be manipulated by miners within ~15 seconds.",
        fix="Don't use for precise timing. Use block.number for relative time or oracles.",
        example_vulnerable="""// Vulnerable: Timestamp for lottery
function spin() external {
    if (block.timestamp % 15 == 0) {
        winner = msg.sender;  // Manipulatable!
    }
}""",
        example_fixed="""// Fixed: Use Chainlink VRF for randomness
import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

// Or use commit-reveal + block hash
function reveal(uint256 commitment) external {
    require(block.number > commitBlock + 1, "Too early");
    bytes32 rand = keccak256(abi.encodePacked(
        blockhash(commitBlock + 1),
        commitment
    ));
}""",
        references=["https://swcregistry.io/docs/SWC-116"],
        gas_impact="Varies by solution"
    ),

    # SWC-117: Signature Malleability
    "SWC-117": Remediation(
        swc_id="SWC-117",
        title="Signature Malleability",
        severity="MEDIUM",
        description="ECDSA signatures can be modified to create valid alternate signatures.",
        fix="Use OpenZeppelin ECDSA library and include nonces.",
        example_vulnerable="""// Vulnerable: Basic ecrecover
function verify(bytes32 hash, bytes memory sig) public pure returns (address) {
    bytes32 r; bytes32 s; uint8 v;
    assembly {
        r := mload(add(sig, 32))
        s := mload(add(sig, 64))
        v := byte(0, mload(add(sig, 96)))
    }
    return ecrecover(hash, v, r, s);
}""",
        example_fixed="""// Fixed: Use OpenZeppelin ECDSA
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

using ECDSA for bytes32;

mapping(address => uint256) public nonces;

function verify(bytes32 hash, bytes memory sig) public view returns (address) {
    return hash.toEthSignedMessageHash().recover(sig);
}""",
        references=["https://swcregistry.io/docs/SWC-117"],
        gas_impact="Minimal"
    ),

    # SWC-120: Weak Sources of Randomness
    "SWC-120": Remediation(
        swc_id="SWC-120",
        title="Weak Sources of Randomness from Chain Attributes",
        severity="HIGH",
        description="On-chain data (blockhash, timestamp) is predictable and manipulatable.",
        fix="Use Chainlink VRF or commit-reveal schemes for randomness.",
        example_vulnerable="""// Vulnerable: Predictable randomness
function random() public view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,  // Now always 0 post-merge!
        msg.sender
    )));
}""",
        example_fixed="""// Fixed: Chainlink VRF
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";

function requestRandomWords() external returns (uint256 requestId) {
    requestId = COORDINATOR.requestRandomWords(
        keyHash,
        subscriptionId,
        requestConfirmations,
        callbackGasLimit,
        numWords
    );
}

function fulfillRandomWords(uint256, uint256[] memory randomWords) internal override {
    // Use randomWords[0] for secure randomness
}""",
        references=["https://swcregistry.io/docs/SWC-120", "Chainlink VRF"],
        gas_impact="~200,000 gas for VRF request"
    ),

    # SWC-123: Requirement Violation
    "SWC-123": Remediation(
        swc_id="SWC-123",
        title="Requirement Violation",
        severity="MEDIUM",
        description="A require() statement can be violated.",
        fix="Review business logic and add comprehensive input validation.",
        example_vulnerable="""// May be bypassed
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    // Missing re-entrancy protection
}""",
        example_fixed="""// Comprehensive validation
function withdraw(uint amount) external nonReentrant {
    require(amount > 0, "Zero amount");
    require(amount <= balances[msg.sender], "Insufficient balance");
    require(amount <= address(this).balance, "Contract underfunded");

    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}""",
        references=["https://swcregistry.io/docs/SWC-123"],
        gas_impact="Additional gas per check"
    ),

    # SWC-124: Write to Arbitrary Storage Location
    "SWC-124": Remediation(
        swc_id="SWC-124",
        title="Write to Arbitrary Storage Location",
        severity="CRITICAL",
        description="User input controls storage slot, allowing arbitrary storage writes.",
        fix="Validate array indices, use mappings instead of arrays when possible.",
        example_vulnerable="""// Vulnerable: Arbitrary storage write
uint256[] public data;

function write(uint256 index, uint256 value) external {
    data[index] = value;  // Can write anywhere!
}""",
        example_fixed="""// Fixed: Bounds checking
function write(uint256 index, uint256 value) external {
    require(index < data.length, "Index out of bounds");
    data[index] = value;
}

// Better: Use mapping
mapping(uint256 => uint256) public data;""",
        references=["https://swcregistry.io/docs/SWC-124"],
        gas_impact="Minimal for bounds check"
    ),

    # SWC-126: Insufficient Gas Griefing
    "SWC-126": Remediation(
        swc_id="SWC-126",
        title="Insufficient Gas Griefing",
        severity="MEDIUM",
        description="External calls may fail silently with insufficient gas forwarding.",
        fix="Use call{gas: ...} or ensure sufficient gas forwarding.",
        example_vulnerable="""// Vulnerable: transfer only forwards 2300 gas
function forward(address payable recipient) external payable {
    recipient.transfer(msg.value);  // May fail for contracts
}""",
        example_fixed="""// Fixed: Forward adequate gas
function forward(address payable recipient) external payable {
    (bool success, ) = recipient.call{value: msg.value}("");
    require(success, "Transfer failed");
}""",
        references=["https://swcregistry.io/docs/SWC-126"],
        gas_impact="None"
    ),
}


def get_remediation(swc_id: str) -> Optional[Remediation]:
    """Get remediation by SWC ID."""
    return REMEDIATIONS.get(swc_id.upper())


def get_remediation_by_type(vuln_type: str) -> Optional[Remediation]:
    """Get remediation by vulnerability type name."""
    type_lower = vuln_type.lower().replace('_', '-').replace(' ', '-')

    # Direct mapping of common names to SWC IDs
    type_map = {
        'reentrancy': 'SWC-107',
        'reentrancy-eth': 'SWC-107',
        'reentrancy-benign': 'SWC-107',
        'reentrancy-events': 'SWC-107',
        'reentrancy-no-eth': 'SWC-107',
        'unchecked-call': 'SWC-104',
        'unchecked-lowlevel': 'SWC-104',
        'unchecked-send': 'SWC-104',
        'access-control': 'SWC-105',
        'unprotected-ether': 'SWC-105',
        'integer-overflow': 'SWC-101',
        'integer-underflow': 'SWC-101',
        'overflow': 'SWC-101',
        'underflow': 'SWC-101',
        'tx-origin': 'SWC-115',
        'tx.origin': 'SWC-115',
        'delegatecall': 'SWC-112',
        'controlled-delegatecall': 'SWC-112',
        'floating-pragma': 'SWC-103',
        'pragma': 'SWC-103',
        'solc-version': 'SWC-102',
        'outdated-solc': 'SWC-102',
        'uninitialized-storage': 'SWC-109',
        'uninitialized-local': 'SWC-109',
        'timestamp': 'SWC-116',
        'block-timestamp': 'SWC-116',
        'weak-prng': 'SWC-120',
        'weak-randomness': 'SWC-120',
        'signature-malleability': 'SWC-117',
        'front-running': 'SWC-114',
        'tod': 'SWC-114',
        'dos': 'SWC-113',
        'denial-of-service': 'SWC-113',
        'selfdestruct': 'SWC-106',
        'suicidal': 'SWC-106',
        'arbitrary-write': 'SWC-124',
        'arbitrary-storage': 'SWC-124',
    }

    for key, swc_id in type_map.items():
        if key in type_lower:
            return REMEDIATIONS.get(swc_id)

    return None


def get_all_remediations() -> Dict[str, Remediation]:
    """Get all remediations."""
    return REMEDIATIONS


# Security checklist for pre-audit
SECURITY_CHECKLIST = [
    {
        "category": "Access Control",
        "items": [
            "All admin functions have proper access modifiers (onlyOwner, onlyRole)",
            "Critical state changes are protected",
            "No use of tx.origin for authentication",
            "Multi-sig or timelock for sensitive operations",
        ]
    },
    {
        "category": "Reentrancy",
        "items": [
            "Checks-Effects-Interactions pattern followed",
            "ReentrancyGuard used on external-calling functions",
            "State updated before external calls",
            "No callbacks to untrusted addresses",
        ]
    },
    {
        "category": "Arithmetic",
        "items": [
            "Using Solidity 0.8+ or SafeMath",
            "No unchecked arithmetic in critical paths",
            "Division by zero protected",
            "Percentage calculations handle precision",
        ]
    },
    {
        "category": "External Calls",
        "items": [
            "All low-level call return values checked",
            "No unbounded loops with external calls",
            "Pull-over-push pattern for ETH transfers",
            "Adequate gas forwarded for recipient contracts",
        ]
    },
    {
        "category": "Token Handling",
        "items": [
            "ERC20 approve race condition mitigated",
            "SafeERC20 used for token transfers",
            "Fee-on-transfer tokens handled",
            "Rebasing tokens considered",
        ]
    },
    {
        "category": "Upgradeability",
        "items": [
            "Storage layout documented and stable",
            "Initializers protected from re-initialization",
            "Implementation contracts properly secured",
            "Upgrade authorization restricted",
        ]
    },
    {
        "category": "Oracle & External Data",
        "items": [
            "Oracle data freshness validated",
            "Multiple oracle sources or fallbacks",
            "Flash loan attacks considered",
            "Price manipulation resistance",
        ]
    },
    {
        "category": "Best Practices",
        "items": [
            "No floating pragma in production",
            "Events emitted for state changes",
            "NatSpec documentation complete",
            "Test coverage > 90%",
        ]
    },
]


def get_security_checklist() -> List[Dict]:
    """Get the security checklist."""
    return SECURITY_CHECKLIST
