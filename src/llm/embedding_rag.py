"""
Embedding-based RAG for Vulnerability Analysis - MIESC v5.1.0
==============================================================

ChromaDB-powered semantic search for vulnerability knowledge base.
Uses sentence-transformers for embeddings and ChromaDB for vector storage.

Features:
- Semantic similarity search (not just keyword matching)
- Persistent vector database
- Hybrid retrieval (embeddings + BM25)
- Automatic knowledge base indexing
- Real-time context retrieval for LLM prompts

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: February 2026
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Lazy imports for optional dependencies
_chromadb = None
_sentence_transformers = None


def _get_chromadb():
    """Lazy import for chromadb."""
    global _chromadb
    if _chromadb is None:
        try:
            import chromadb
            _chromadb = chromadb
        except ImportError:
            raise ImportError(
                "ChromaDB is required for embedding RAG. "
                "Install with: pip install chromadb"
            )
    return _chromadb


def _get_sentence_transformer():
    """Lazy import for sentence-transformers."""
    global _sentence_transformers
    if _sentence_transformers is None:
        try:
            from sentence_transformers import SentenceTransformer
            _sentence_transformers = SentenceTransformer
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for embedding RAG. "
                "Install with: pip install sentence-transformers"
            )
    return _sentence_transformers


# =============================================================================
# DATA STRUCTURES
# =============================================================================


@dataclass
class VulnerabilityDocument:
    """A vulnerability document for the knowledge base."""

    id: str
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    title: str = ""
    description: str = ""
    vulnerable_code: str = ""
    fixed_code: str = ""
    attack_scenario: str = ""
    severity: str = "medium"
    category: str = "general"
    real_exploit: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_text(self) -> str:
        """Convert to searchable text representation."""
        parts = [
            f"Title: {self.title}",
            f"Category: {self.category}",
            f"Severity: {self.severity}",
            f"Description: {self.description}",
        ]
        if self.swc_id:
            parts.append(f"SWC: {self.swc_id}")
        if self.cwe_id:
            parts.append(f"CWE: {self.cwe_id}")
        if self.vulnerable_code:
            parts.append(f"Vulnerable Code Pattern:\n{self.vulnerable_code}")
        if self.attack_scenario:
            parts.append(f"Attack Scenario: {self.attack_scenario}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)

    def to_metadata(self) -> Dict[str, Any]:
        """Convert to ChromaDB metadata format."""
        return {
            "swc_id": self.swc_id or "",
            "cwe_id": self.cwe_id or "",
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "tags": ",".join(self.tags),
            "has_exploit": bool(self.real_exploit),
            "has_fix": bool(self.fixed_code),
        }


@dataclass
class RetrievalResult:
    """Result from semantic search."""

    document: VulnerabilityDocument
    similarity_score: float
    relevance_reason: str

    def to_context(self) -> str:
        """Convert to LLM context string."""
        return (
            f"**{self.document.title}** (Score: {self.similarity_score:.2f})\n"
            f"- Category: {self.document.category}\n"
            f"- Severity: {self.document.severity}\n"
            f"- Description: {self.document.description[:300]}...\n"
            f"- Relevance: {self.relevance_reason}\n"
            f"- Real Exploit: {self.document.real_exploit or 'N/A'}"
        )


# =============================================================================
# KNOWLEDGE BASE - SWC Registry + DeFi + Advanced Patterns
# =============================================================================

VULNERABILITY_KNOWLEDGE_BASE: List[VulnerabilityDocument] = [
    # SWC-107: Reentrancy
    VulnerabilityDocument(
        id="SWC-107",
        swc_id="SWC-107",
        cwe_id="CWE-841",
        title="Reentrancy",
        description=(
            "One of the major dangers of calling external contracts is that they can "
            "take over the control flow. In the reentrancy attack, a malicious contract "
            "calls back into the calling contract before the first invocation of the "
            "function is finished. This can lead to unexpected state changes and fund drainage."
        ),
        vulnerable_code="""
function withdraw(uint256 _amount) public {
    require(balances[msg.sender] >= _amount);
    (bool success,) = msg.sender.call{value: _amount}("");
    require(success);
    balances[msg.sender] -= _amount;  // State update AFTER external call - VULNERABLE
}
""",
        fixed_code="""
function withdraw(uint256 _amount) public nonReentrant {
    require(balances[msg.sender] >= _amount);
    balances[msg.sender] -= _amount;  // State update BEFORE external call
    (bool success,) = msg.sender.call{value: _amount}("");
    require(success);
}
""",
        attack_scenario=(
            "1. Attacker deploys malicious contract with receive() that calls withdraw() again. "
            "2. Attacker calls withdraw() with legitimate balance. "
            "3. ETH is sent, triggering attacker's receive(). "
            "4. receive() calls withdraw() again - balance not yet updated. "
            "5. Repeat until contract is drained."
        ),
        severity="critical",
        category="reentrancy",
        real_exploit="The DAO Hack - $60M stolen (2016)",
        tags=["reentrancy", "external-call", "state-update", "cef-pattern", "checks-effects-interactions"],
    ),

    # SWC-107 Variant: Cross-function Reentrancy
    VulnerabilityDocument(
        id="CROSS-FUNC-REENTRANCY",
        swc_id="SWC-107",
        cwe_id="CWE-841",
        title="Cross-function Reentrancy",
        description=(
            "A more subtle form of reentrancy where the attacker re-enters through a different "
            "function that shares state with the vulnerable function. The two functions may "
            "individually appear safe but their interaction creates a vulnerability."
        ),
        vulnerable_code="""
mapping(address => uint) public balances;

function transfer(address to, uint amount) public {
    if (balances[msg.sender] >= amount) {
        balances[to] += amount;
        balances[msg.sender] -= amount;
    }
}

function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success,) = msg.sender.call{value: amount}("");  // Reentrancy point
    require(success);
    balances[msg.sender] = 0;
}
""",
        fixed_code="""
function withdraw() public nonReentrant {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;  // Update state first
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
""",
        attack_scenario=(
            "1. Attacker has balance in contract. "
            "2. Attacker calls withdraw(). "
            "3. In receive(), attacker calls transfer() to move balance to another address. "
            "4. Original balance not yet zeroed, so transfer succeeds. "
            "5. Attacker now has double the funds."
        ),
        severity="critical",
        category="reentrancy",
        real_exploit="Multiple DeFi hacks use this pattern",
        tags=["reentrancy", "cross-function", "state-sharing", "multi-function"],
    ),

    # SWC-107 Variant: Read-only Reentrancy
    VulnerabilityDocument(
        id="READ-ONLY-REENTRANCY",
        swc_id="SWC-107",
        cwe_id="CWE-841",
        title="Read-only Reentrancy",
        description=(
            "A reentrancy attack where the attacker exploits a view function that reads stale "
            "state during an external call. Even though the view function doesn't modify state, "
            "it can be used to manipulate other contracts that rely on accurate price/balance data."
        ),
        vulnerable_code="""
// Vulnerable Oracle
function getPrice() public view returns (uint256) {
    return totalValue / totalShares;  // Can be manipulated during callback
}

// Victim Protocol using the oracle
function borrow(uint256 amount) external {
    uint256 collateralValue = oracle.getPrice() * collateral[msg.sender];
    require(collateralValue >= amount * 150 / 100);  // 150% collateralization
    // ... proceed with borrow
}
""",
        fixed_code="""
// Use reentrancy guards on state-changing functions
// Use TWAP (Time-Weighted Average Price) for oracles
// Add staleness checks and manipulation detection
function getPrice() public view returns (uint256) {
    require(block.timestamp - lastUpdate < MAX_STALENESS);
    return twapPrice;  // Use TWAP instead of spot price
}
""",
        attack_scenario=(
            "1. Attacker triggers callback in pool during withdraw. "
            "2. During callback, pool's totalValue is reduced but totalShares not yet. "
            "3. getPrice() returns stale (inflated) value. "
            "4. Attacker borrows more than they should from victim protocol. "
            "5. Callback completes, price updates, attacker profits."
        ),
        severity="high",
        category="reentrancy",
        real_exploit="Curve/Vyper Read-only Reentrancy - $70M (2023)",
        tags=["reentrancy", "read-only", "oracle", "view-function", "defi"],
    ),

    # SWC-105: Unprotected Ether Withdrawal
    VulnerabilityDocument(
        id="SWC-105",
        swc_id="SWC-105",
        cwe_id="CWE-284",
        title="Unprotected Ether Withdrawal",
        description=(
            "Due to missing or insufficient access controls, malicious parties can "
            "withdraw some or all Ether from the contract account. Functions that send "
            "ETH must have proper authorization checks."
        ),
        vulnerable_code="""
function withdrawAll() public {
    // No access control - anyone can call!
    payable(msg.sender).transfer(address(this).balance);
}
""",
        fixed_code="""
function withdrawAll() public onlyOwner {
    payable(msg.sender).transfer(address(this).balance);
}

// Or use OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";
""",
        attack_scenario=(
            "1. Attacker finds contract with unprotected withdraw function. "
            "2. Attacker calls withdrawAll(). "
            "3. All ETH in contract sent to attacker. "
            "4. Contract is drained."
        ),
        severity="critical",
        category="access-control",
        real_exploit="Parity Multisig Hack - $150M frozen (2017)",
        tags=["access-control", "withdrawal", "authorization", "missing-modifier"],
    ),

    # SWC-115: tx.origin Authentication
    VulnerabilityDocument(
        id="SWC-115",
        swc_id="SWC-115",
        cwe_id="CWE-477",
        title="Authorization through tx.origin",
        description=(
            "tx.origin returns the address that originated the transaction chain. "
            "Using it for authorization is dangerous because if the legitimate owner "
            "interacts with a malicious contract, that contract can call back and "
            "pass the tx.origin check."
        ),
        vulnerable_code="""
function transferTo(address payable dest, uint amount) public {
    require(tx.origin == owner);  // DANGEROUS: uses tx.origin
    dest.transfer(amount);
}
""",
        fixed_code="""
function transferTo(address payable dest, uint amount) public {
    require(msg.sender == owner);  // SAFE: uses msg.sender
    dest.transfer(amount);
}
""",
        attack_scenario=(
            "1. Owner interacts with malicious contract (e.g., fake airdrop). "
            "2. Malicious contract calls victim.transferTo(attacker, balance). "
            "3. tx.origin is still the owner (original transaction sender). "
            "4. Check passes, funds sent to attacker."
        ),
        severity="high",
        category="access-control",
        real_exploit="Common phishing vector in DeFi",
        tags=["tx-origin", "phishing", "authorization", "msg-sender"],
    ),

    # SWC-104: Unchecked Call Return Value
    VulnerabilityDocument(
        id="SWC-104",
        swc_id="SWC-104",
        cwe_id="CWE-252",
        title="Unchecked Call Return Value",
        description=(
            "The return value of low-level calls (call, send, delegatecall) must be checked. "
            "If not checked, execution continues even if the call failed, leading to "
            "inconsistent state and potential fund loss."
        ),
        vulnerable_code="""
function sendEther(address payable _to, uint256 _amount) public {
    _to.call{value: _amount}("");  // Return value not checked!
    // Continues even if call fails
    balances[msg.sender] -= _amount;  // Balance decremented but ETH not sent
}
""",
        fixed_code="""
function sendEther(address payable _to, uint256 _amount) public {
    (bool success,) = _to.call{value: _amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] -= _amount;
}

// Or use OpenZeppelin's Address library
import "@openzeppelin/contracts/utils/Address.sol";
Address.sendValue(_to, _amount);
""",
        attack_scenario=(
            "1. User calls sendEther() to transfer funds. "
            "2. External call fails (recipient rejects or out of gas). "
            "3. Return value not checked, execution continues. "
            "4. User's balance decremented but ETH never sent. "
            "5. Funds effectively lost/locked."
        ),
        severity="medium",
        category="unchecked-call",
        tags=["unchecked-return", "low-level-call", "error-handling", "send", "call"],
    ),

    # SWC-101: Integer Overflow/Underflow
    VulnerabilityDocument(
        id="SWC-101",
        swc_id="SWC-101",
        cwe_id="CWE-190",
        title="Integer Overflow and Underflow",
        description=(
            "Integer overflow occurs when an arithmetic operation exceeds the maximum value "
            "for that type (wraps to 0). Underflow is the opposite (wraps to max value). "
            "Solidity 0.8.0+ has built-in overflow checks, but unchecked blocks and older "
            "versions are still vulnerable."
        ),
        vulnerable_code="""
// Solidity < 0.8.0 - No built-in checks
function transfer(address _to, uint256 _amount) public {
    require(balances[msg.sender] >= _amount);
    balances[msg.sender] -= _amount;  // Can underflow if already 0
    balances[_to] += _amount;  // Can overflow to 0
}
""",
        fixed_code="""
// Solidity 0.8.0+: Built-in overflow checks (reverts on overflow)

// For older versions, use SafeMath:
using SafeMath for uint256;
function transfer(address _to, uint256 _amount) public {
    require(balances[msg.sender] >= _amount);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
}
""",
        attack_scenario=(
            "1. Attacker has 0 tokens but exploits underflow. "
            "2. Calls transfer with amount > 0. "
            "3. Balance wraps: 0 - 1 = 2^256 - 1 (max uint). "
            "4. Attacker now has essentially unlimited tokens."
        ),
        severity="high",
        category="arithmetic",
        real_exploit="BEC Token - $900M theoretical (2018)",
        tags=["overflow", "underflow", "arithmetic", "safemath", "solidity-version"],
    ),

    # SWC-112: Delegatecall to Untrusted Callee
    VulnerabilityDocument(
        id="SWC-112",
        swc_id="SWC-112",
        cwe_id="CWE-829",
        title="Delegatecall to Untrusted Callee",
        description=(
            "delegatecall executes code in another contract using the calling contract's "
            "storage and context. If the target is controlled by an attacker, they can "
            "modify any storage slot, including owner addresses and balances."
        ),
        vulnerable_code="""
function execute(address _target, bytes memory _data) public {
    // DANGEROUS: delegatecall to arbitrary address
    _target.delegatecall(_data);
}
""",
        fixed_code="""
mapping(address => bool) public allowedTargets;

function execute(address _target, bytes memory _data) public onlyOwner {
    require(allowedTargets[_target], "Target not allowed");
    (bool success,) = _target.delegatecall(_data);
    require(success, "Delegatecall failed");
}
""",
        attack_scenario=(
            "1. Attacker deploys malicious implementation contract. "
            "2. Attacker calls execute() with malicious target. "
            "3. delegatecall runs attacker's code with victim's storage. "
            "4. Attacker overwrites owner slot or drains funds."
        ),
        severity="critical",
        category="delegatecall",
        real_exploit="Parity Wallet Hack - $30M (2017)",
        tags=["delegatecall", "proxy", "code-injection", "storage-manipulation"],
    ),

    # Flash Loan Attack Pattern
    VulnerabilityDocument(
        id="FLASH-LOAN-ATTACK",
        swc_id=None,
        cwe_id="CWE-682",
        title="Flash Loan Attack",
        description=(
            "Flash loans allow borrowing large amounts without collateral, as long as "
            "the loan is repaid within the same transaction. Attackers use this to "
            "temporarily manipulate prices, governance, or exploit arithmetic assumptions."
        ),
        vulnerable_code="""
function getPrice() public view returns (uint256) {
    // Spot price from AMM - can be manipulated with flash loan
    return reserve1 / reserve0;
}

function borrow(uint256 amount) external {
    uint256 collateralValue = getPrice() * collateral[msg.sender];
    require(collateralValue >= amount * 150 / 100);
    // Borrow proceeds...
}
""",
        fixed_code="""
// Use TWAP (Time-Weighted Average Price)
function getPrice() public view returns (uint256) {
    return priceCumulativeLast / timeElapsed;
}

// Or use Chainlink oracle
function getPrice() public view returns (uint256) {
    (, int256 price,,,) = priceFeed.latestRoundData();
    return uint256(price);
}

// Add flash loan protection
modifier noFlashLoan() {
    require(block.number > lastActionBlock[msg.sender], "Same block");
    lastActionBlock[msg.sender] = block.number;
    _;
}
""",
        attack_scenario=(
            "1. Attacker takes $100M flash loan from Aave/dYdX. "
            "2. Swaps large amount in AMM, manipulating price. "
            "3. Exploits victim protocol relying on spot price. "
            "4. Swaps back, extracting profit. "
            "5. Repays flash loan + fee in same transaction."
        ),
        severity="critical",
        category="flash-loan",
        real_exploit="bZx Flash Loan Attack - $350K (2020), Cream Finance - $130M (2021)",
        tags=["flash-loan", "price-manipulation", "oracle", "defi", "arbitrage"],
    ),

    # Oracle Manipulation
    VulnerabilityDocument(
        id="ORACLE-MANIPULATION",
        swc_id=None,
        cwe_id="CWE-682",
        title="Price Oracle Manipulation",
        description=(
            "Protocols relying on on-chain price oracles (especially AMM spot prices) "
            "are vulnerable to manipulation. Attackers can use flash loans or large "
            "trades to temporarily move prices and exploit dependent protocols."
        ),
        vulnerable_code="""
// Vulnerable: Using Uniswap spot price
function getTokenPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = uniswapPair.getReserves();
    return (reserve1 * 1e18) / reserve0;
}
""",
        fixed_code="""
// Use Chainlink oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function getTokenPrice() public view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");
    require(price > 0, "Invalid price");
    return uint256(price);
}

// Or use TWAP from Uniswap V3
function getTWAP() public view returns (uint256) {
    (int24 tick,) = oracle.observe([TWAP_PERIOD, 0]);
    return OracleLibrary.getQuoteAtTick(tick, amount, token0, token1);
}
""",
        attack_scenario=(
            "1. Attacker identifies protocol using AMM spot price. "
            "2. Takes flash loan and trades heavily in AMM. "
            "3. Price moves significantly (e.g., 10x). "
            "4. Exploits protocol (borrow at inflated collateral, liquidate at deflated price). "
            "5. Trades back and repays flash loan with profit."
        ),
        severity="critical",
        category="oracle",
        real_exploit="Harvest Finance - $34M (2020), Mango Markets - $114M (2022)",
        tags=["oracle", "price-manipulation", "flash-loan", "twap", "chainlink", "defi"],
    ),

    # Frontrunning / Sandwich Attack
    VulnerabilityDocument(
        id="SANDWICH-ATTACK",
        swc_id=None,
        cwe_id="CWE-362",
        title="Sandwich Attack / Frontrunning",
        description=(
            "MEV (Maximal Extractable Value) attacks where a malicious actor sees a pending "
            "transaction and places their own transactions before and after it. In a sandwich "
            "attack, they buy before a large swap, let the victim's swap push the price up, "
            "then sell at the higher price."
        ),
        vulnerable_code="""
function swap(uint256 amountIn) external {
    // No slippage protection - vulnerable to sandwich
    uint256 amountOut = getAmountOut(amountIn);
    token.transferFrom(msg.sender, address(this), amountIn);
    otherToken.transfer(msg.sender, amountOut);
}
""",
        fixed_code="""
function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
    require(block.timestamp <= deadline, "Transaction expired");
    uint256 amountOut = getAmountOut(amountIn);
    require(amountOut >= minAmountOut, "Slippage too high");  // Slippage protection
    token.transferFrom(msg.sender, address(this), amountIn);
    otherToken.transfer(msg.sender, amountOut);
}

// Or use private transaction services (Flashbots Protect)
""",
        attack_scenario=(
            "1. Victim submits swap for 100 ETH -> USDC. "
            "2. Attacker sees pending tx in mempool. "
            "3. Attacker frontrun: buys USDC, pushing price up. "
            "4. Victim's tx executes at worse price. "
            "5. Attacker backruns: sells USDC at higher price."
        ),
        severity="medium",
        category="mev",
        real_exploit="Common MEV extraction, estimated $1B+ annually",
        tags=["mev", "frontrunning", "sandwich", "slippage", "deadline", "mempool"],
    ),

    # Governance Flash Loan Attack
    VulnerabilityDocument(
        id="GOVERNANCE-FLASH-LOAN",
        swc_id=None,
        cwe_id="CWE-284",
        title="Flash Loan Governance Attack",
        description=(
            "Governance systems that use token balances at transaction time (spot voting) "
            "can be attacked with flash loans. An attacker can borrow tokens, vote, "
            "execute malicious proposal, and repay in same transaction."
        ),
        vulnerable_code="""
function castVote(uint256 proposalId, bool support) external {
    // VULNERABLE: Uses current balance
    uint256 votes = token.balanceOf(msg.sender);
    proposals[proposalId].votes += support ? int256(votes) : -int256(votes);
}
""",
        fixed_code="""
// Use checkpoints (snapshots) for voting power
function castVote(uint256 proposalId, bool support) external {
    Proposal storage proposal = proposals[proposalId];
    // Uses balance at snapshot block, before proposal was created
    uint256 votes = token.getPastVotes(msg.sender, proposal.snapshotBlock);
    require(votes > 0, "No voting power at snapshot");
    proposal.votes += support ? int256(votes) : -int256(votes);
}

// OpenZeppelin ERC20Votes provides this functionality
""",
        attack_scenario=(
            "1. Attacker creates malicious proposal (e.g., drain treasury). "
            "2. Takes flash loan of governance tokens. "
            "3. Votes to pass proposal (now has majority). "
            "4. Executes proposal immediately (if no timelock). "
            "5. Repays flash loan, keeps stolen funds."
        ),
        severity="critical",
        category="governance",
        real_exploit="Beanstalk - $182M (2022)",
        tags=["governance", "flash-loan", "voting", "snapshot", "checkpoint", "defi"],
    ),

    # Proxy Storage Collision
    VulnerabilityDocument(
        id="PROXY-STORAGE-COLLISION",
        swc_id="SWC-112",
        cwe_id="CWE-820",
        title="Proxy Storage Collision",
        description=(
            "Upgradeable proxy contracts can suffer from storage collisions if the proxy "
            "and implementation contracts share storage slots. The implementation's variables "
            "can overwrite critical proxy data like the admin address."
        ),
        vulnerable_code="""
// Proxy contract
contract Proxy {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1

    function upgradeTo(address newImpl) public {
        require(msg.sender == admin);
        implementation = newImpl;
    }
}

// Implementation contract
contract Implementation {
    uint256 public value;  // Slot 0 - COLLIDES with implementation address!
    address public owner;  // Slot 1 - COLLIDES with admin!
}
""",
        fixed_code="""
// Use EIP-1967 storage slots
contract Proxy {
    // Slot: keccak256("eip1967.proxy.implementation") - 1
    bytes32 constant IMPLEMENTATION_SLOT = 0x360894...;
    bytes32 constant ADMIN_SLOT = 0xb53127...;

    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }
}

// Use OpenZeppelin TransparentUpgradeableProxy or UUPS
""",
        attack_scenario=(
            "1. Developer deploys proxy with admin at slot 1. "
            "2. Implementation's first variable maps to slot 0 (implementation address). "
            "3. If implementation's second variable is address type, it maps to slot 1. "
            "4. Setting owner in implementation overwrites proxy admin. "
            "5. Attacker can now upgrade proxy to malicious implementation."
        ),
        severity="critical",
        category="proxy",
        real_exploit="Multiple proxy-related hacks including Wormhole",
        tags=["proxy", "storage-collision", "upgradeable", "eip-1967", "delegatecall"],
    ),

    # Signature Replay Attack
    VulnerabilityDocument(
        id="SIGNATURE-REPLAY",
        swc_id="SWC-121",
        cwe_id="CWE-294",
        title="Signature Replay Attack",
        description=(
            "Signed messages that don't include proper replay protection (nonce, chainId, "
            "contract address) can be reused across transactions, chains, or contracts. "
            "This allows attackers to replay valid signatures in unintended contexts."
        ),
        vulnerable_code="""
function executeWithSig(
    address to,
    uint256 amount,
    bytes memory signature
) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = recoverSigner(hash, signature);
    require(signer == owner, "Invalid signature");
    // No nonce check - signature can be replayed!
    token.transfer(to, amount);
}
""",
        fixed_code="""
mapping(address => uint256) public nonces;

function executeWithSig(
    address to,
    uint256 amount,
    uint256 nonce,
    uint256 deadline,
    bytes memory signature
) external {
    require(block.timestamp <= deadline, "Expired");
    require(nonce == nonces[owner]++, "Invalid nonce");

    bytes32 hash = keccak256(abi.encodePacked(
        address(this),  // Contract address
        block.chainid,  // Chain ID
        to, amount, nonce, deadline
    ));
    address signer = recoverSigner(hash, signature);
    require(signer == owner, "Invalid signature");
    token.transfer(to, amount);
}
""",
        attack_scenario=(
            "1. User signs message to transfer 100 tokens. "
            "2. Transaction executes successfully. "
            "3. Attacker captures the signature. "
            "4. Attacker replays same signature (no nonce protection). "
            "5. Another 100 tokens transferred. Repeat until drained."
        ),
        severity="high",
        category="cryptography",
        real_exploit="Wintermute - $160M (2022, related to signature vulnerability)",
        tags=["signature", "replay", "nonce", "ecrecover", "eip-712", "chainid"],
    ),

    # Denial of Service - Gas Limit
    VulnerabilityDocument(
        id="DOS-GAS-LIMIT",
        swc_id="SWC-128",
        cwe_id="CWE-400",
        title="DoS with Block Gas Limit",
        description=(
            "Functions that iterate over unbounded arrays can exceed the block gas limit, "
            "making them impossible to execute. Attackers can intentionally grow arrays "
            "to cause permanent denial of service."
        ),
        vulnerable_code="""
address[] public recipients;

function distributeRewards() external {
    uint256 reward = address(this).balance / recipients.length;
    // VULNERABLE: Unbounded loop
    for (uint256 i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(reward);
    }
}
""",
        fixed_code="""
// Pull pattern - users withdraw themselves
mapping(address => uint256) public pendingRewards;

function distributeRewards(uint256 startIdx, uint256 batchSize) external {
    uint256 endIdx = min(startIdx + batchSize, recipients.length);
    uint256 reward = address(this).balance / recipients.length;
    for (uint256 i = startIdx; i < endIdx; i++) {
        pendingRewards[recipients[i]] += reward;
    }
}

function claimReward() external {
    uint256 reward = pendingRewards[msg.sender];
    pendingRewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}
""",
        attack_scenario=(
            "1. Attacker adds many addresses to recipients array. "
            "2. distributeRewards() now requires too much gas. "
            "3. Block gas limit exceeded - transaction always fails. "
            "4. No one can ever distribute or receive rewards."
        ),
        severity="medium",
        category="denial-of-service",
        real_exploit="GovernMental - locked funds forever (2016)",
        tags=["dos", "gas-limit", "unbounded-loop", "array", "pull-pattern"],
    ),

    # Uninitialized Storage Pointer
    VulnerabilityDocument(
        id="SWC-109",
        swc_id="SWC-109",
        cwe_id="CWE-824",
        title="Uninitialized Storage Pointer",
        description=(
            "In older Solidity versions (< 0.5.0), local storage variables that are not "
            "initialized point to storage slot 0 by default. This can lead to accidental "
            "overwriting of state variables."
        ),
        vulnerable_code="""
// Solidity < 0.5.0
contract Vulnerable {
    uint256 public secretData;

    function modifyData() public {
        MyStruct data;  // VULNERABLE: Uninitialized storage pointer
        data.value = 123;  // Overwrites slot 0 (secretData)!
    }
}
""",
        fixed_code="""
// Solidity 0.5.0+: Compilation error for uninitialized storage
// Or explicitly use memory:
function modifyData() public {
    MyStruct memory data = MyStruct(123);  // Use memory
    // or
    MyStruct storage data = myStorageStruct;  // Explicit storage reference
}
""",
        attack_scenario=(
            "1. Contract stores owner address in slot 0. "
            "2. Function uses uninitialized local storage variable. "
            "3. Attacker triggers function with crafted input. "
            "4. Storage slot 0 overwritten with attacker's address. "
            "5. Attacker is now the owner."
        ),
        severity="high",
        category="storage",
        real_exploit="OpenAddressLottery (2017)",
        tags=["storage", "uninitialized", "pointer", "solidity-version", "slot-0"],
    ),

    # ERC-777 Hooks Reentrancy
    VulnerabilityDocument(
        id="ERC777-REENTRANCY",
        swc_id="SWC-107",
        cwe_id="CWE-841",
        title="ERC-777 Token Hooks Reentrancy",
        description=(
            "ERC-777 tokens have hooks (tokensReceived, tokensToSend) that are called "
            "during transfers. If a protocol is unaware of these hooks, they can be "
            "exploited for reentrancy attacks even when no ETH is involved."
        ),
        vulnerable_code="""
function deposit(uint256 amount) external {
    require(token.balanceOf(msg.sender) >= amount);
    // Transfer triggers tokensToSend hook - reentrancy point!
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // State update after
}
""",
        fixed_code="""
function deposit(uint256 amount) external nonReentrant {
    require(token.balanceOf(msg.sender) >= amount);
    balances[msg.sender] += amount;  // Update state first
    token.transferFrom(msg.sender, address(this), amount);
}

// Or block ERC-777 tokens entirely
require(!ERC1820Registry.getInterfaceImplementer(
    address(token),
    keccak256("ERC777Token")
) != address(0), "ERC777 not supported");
""",
        attack_scenario=(
            "1. Attacker registers as ERC-777 tokensToSend hook. "
            "2. Attacker calls deposit() with ERC-777 token. "
            "3. transferFrom triggers attacker's hook. "
            "4. Hook calls deposit() again (balance not yet credited). "
            "5. Attacker gets credited multiple times for same deposit."
        ),
        severity="high",
        category="reentrancy",
        real_exploit="imBTC Uniswap Attack - $300K (2020)",
        tags=["erc777", "hooks", "reentrancy", "token", "callback"],
    ),

    # Fee-on-Transfer Token Issues
    VulnerabilityDocument(
        id="FEE-ON-TRANSFER",
        swc_id=None,
        cwe_id="CWE-682",
        title="Fee-on-Transfer Token Incompatibility",
        description=(
            "Some tokens deduct a fee on every transfer. Protocols that assume "
            "transfer(amount) results in exactly `amount` being received will "
            "have accounting errors when used with these tokens."
        ),
        vulnerable_code="""
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    // WRONG: Assumes we received exactly 'amount'
    balances[msg.sender] += amount;
}
""",
        fixed_code="""
function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = token.balanceOf(address(this));
    uint256 actualReceived = balanceAfter - balanceBefore;
    balances[msg.sender] += actualReceived;  // Use actual amount
}
""",
        attack_scenario=(
            "1. Protocol assumes 100 tokens in = 100 tokens credited. "
            "2. Fee-on-transfer token has 1% fee. "
            "3. User deposits 100 tokens, protocol receives 99. "
            "4. User credited with 100 tokens in protocol. "
            "5. Last withdrawer can't withdraw - insufficient funds."
        ),
        severity="medium",
        category="token",
        real_exploit="Multiple DeFi protocols affected",
        tags=["fee-on-transfer", "token", "accounting", "balance-check", "deflationary"],
    ),

    # SWC-106: Unprotected SELFDESTRUCT
    VulnerabilityDocument(
        id="SWC-106",
        swc_id="SWC-106",
        cwe_id="CWE-284",
        title="Unprotected SELFDESTRUCT Instruction",
        description=(
            "A contract with a public or unprotected selfdestruct() function can be "
            "destroyed by anyone. This permanently removes the contract code and sends "
            "all remaining ETH to a specified address."
        ),
        vulnerable_code="""
function destroy() public {
    selfdestruct(payable(msg.sender));  // Anyone can call!
}
""",
        fixed_code="""
function destroy() public onlyOwner {
    selfdestruct(payable(owner));
}

// Better: Remove selfdestruct entirely (deprecated in newer Solidity)
// Use pausable pattern instead
""",
        attack_scenario=(
            "1. Attacker finds contract with unprotected selfdestruct. "
            "2. Attacker calls destroy(). "
            "3. Contract code is erased permanently. "
            "4. All ETH sent to attacker. "
            "5. Dependent contracts/users lose access forever."
        ),
        severity="critical",
        category="access-control",
        real_exploit="Parity Multisig Library - $150M frozen permanently (2017)",
        tags=["selfdestruct", "access-control", "permanent", "destructive"],
    ),

    # SWC-116: Block Timestamp Dependence
    VulnerabilityDocument(
        id="SWC-116",
        swc_id="SWC-116",
        cwe_id="CWE-829",
        title="Block Values as Time Proxy",
        description=(
            "Miners can manipulate block.timestamp within a range (~15 seconds). "
            "Contracts that rely on precise timing or use timestamp for randomness "
            "are vulnerable to manipulation."
        ),
        vulnerable_code="""
function isLotteryWinner() public view returns (bool) {
    return block.timestamp % 2 == 0;  // Manipulable!
}

function timeLock() public {
    require(block.timestamp >= releaseTime);  // ~15s manipulation window
    // Release funds...
}
""",
        fixed_code="""
// For randomness: Use Chainlink VRF
function requestRandomness() external returns (bytes32) {
    return requestRandomness(keyHash, fee);
}

// For time-locks: Add buffer for manipulation
function timeLock() public {
    require(block.timestamp >= releaseTime + 15 minutes);  // Buffer
    // Or use block.number instead for longer periods
}
""",
        attack_scenario=(
            "1. Lottery uses timestamp for winner selection. "
            "2. Miner sees their transaction would lose. "
            "3. Miner adjusts block timestamp slightly. "
            "4. Miner wins the lottery."
        ),
        severity="low",
        category="randomness",
        tags=["timestamp", "block-values", "randomness", "miner-manipulation"],
    ),

    # SWC-120: Weak Sources of Randomness
    VulnerabilityDocument(
        id="SWC-120",
        swc_id="SWC-120",
        cwe_id="CWE-330",
        title="Weak Sources of Randomness from Chain Attributes",
        description=(
            "Using blockhash, block.timestamp, block.difficulty, or block.number as "
            "randomness sources is insecure. Miners can influence these values, and "
            "blockhash is only available for the 256 most recent blocks."
        ),
        vulnerable_code="""
function random() internal view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(
        block.timestamp,
        block.difficulty,
        msg.sender
    )));  // All predictable/manipulable!
}

function flipCoin() external payable {
    require(msg.value == 1 ether);
    if (random() % 2 == 0) {
        payable(msg.sender).transfer(2 ether);
    }
}
""",
        fixed_code="""
// Use Chainlink VRF for secure randomness
import "@chainlink/contracts/src/v0.8/vrf/VRFV2WrapperConsumerBase.sol";

function requestRandomWords() internal returns (uint256 requestId) {
    return requestRandomness(callbackGasLimit, requestConfirmations, numWords);
}

function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
    // Use randomWords[0] for provably fair randomness
    processGameResult(randomWords[0]);
}
""",
        attack_scenario=(
            "1. Attacker predicts 'random' outcome off-chain. "
            "2. Only submits transaction when outcome is favorable. "
            "3. Or miner manipulates block values to win. "
            "4. 'Random' lottery/game is deterministic for attacker."
        ),
        severity="high",
        category="randomness",
        real_exploit="Multiple lottery/gambling contracts exploited",
        tags=["randomness", "blockhash", "timestamp", "chainlink-vrf", "predictable"],
    ),

    # SWC-100: Function Default Visibility
    VulnerabilityDocument(
        id="SWC-100",
        swc_id="SWC-100",
        cwe_id="CWE-710",
        title="Function Default Visibility",
        description=(
            "Functions without explicit visibility default to 'public' in older Solidity. "
            "This can expose internal functions that should be private, allowing attackers "
            "to call sensitive functions directly."
        ),
        vulnerable_code="""
// Solidity < 0.5.0
contract Wallet {
    function transfer(address to, uint amount) {  // No visibility = public!
        // Internal transfer logic exposed
    }

    function _internalHelper() {  // Convention says private, but it's public!
        // Sensitive logic
    }
}
""",
        fixed_code="""
contract Wallet {
    function transfer(address to, uint amount) public {
        // Explicitly public
    }

    function _internalHelper() private {
        // Explicitly private
    }

    function _protectedLogic() internal {
        // Explicitly internal
    }
}
""",
        attack_scenario=(
            "1. Developer assumes underscore prefix means private. "
            "2. Function is actually public (no explicit visibility). "
            "3. Attacker calls _adminFunction() directly. "
            "4. Bypasses intended access control."
        ),
        severity="high",
        category="visibility",
        tags=["visibility", "public", "private", "access-control", "solidity-version"],
    ),

    # SWC-117: Signature Malleability
    VulnerabilityDocument(
        id="SWC-117",
        swc_id="SWC-117",
        cwe_id="CWE-347",
        title="Signature Malleability",
        description=(
            "ECDSA signatures in Ethereum have a malleability property: for any valid "
            "signature (r, s, v), there exists another valid signature (r, -s mod n, v'). "
            "This can be exploited if signatures are used as unique identifiers."
        ),
        vulnerable_code="""
mapping(bytes => bool) public usedSignatures;

function claim(bytes memory signature) external {
    require(!usedSignatures[signature], "Already used");
    // Verify signature...
    address signer = recoverSigner(message, signature);
    require(signer == trustedSigner);
    usedSignatures[signature] = true;
    // Process claim
}
""",
        fixed_code="""
mapping(bytes32 => bool) public usedMessages;  // Track message hash, not signature

function claim(bytes memory signature) external {
    bytes32 messageHash = getMessageHash(msg.sender, amount);
    require(!usedMessages[messageHash], "Already claimed");

    // Use OpenZeppelin ECDSA for safe recovery
    address signer = ECDSA.recover(messageHash, signature);
    require(signer == trustedSigner);

    usedMessages[messageHash] = true;  // Mark message as used
    // Process claim
}
""",
        attack_scenario=(
            "1. User submits valid signature S for claim. "
            "2. Contract marks signature S as used. "
            "3. Attacker computes malleable signature S'. "
            "4. S' is different but recovers same signer. "
            "5. Attacker claims again with S'."
        ),
        severity="medium",
        category="cryptography",
        tags=["signature", "malleability", "ecdsa", "ecrecover", "replay"],
    ),

    # SWC-119: Shadowing State Variables
    VulnerabilityDocument(
        id="SWC-119",
        swc_id="SWC-119",
        cwe_id="CWE-710",
        title="Shadowing State Variables",
        description=(
            "State variable shadowing occurs when a derived contract declares a variable "
            "with the same name as a parent contract. This creates two separate storage "
            "slots and can lead to unexpected behavior."
        ),
        vulnerable_code="""
contract Parent {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}

contract Child is Parent {
    address public owner;  // SHADOWS Parent.owner!

    function setOwner(address newOwner) public {
        owner = newOwner;  // Only sets Child.owner, not Parent.owner
    }
}
""",
        fixed_code="""
contract Parent {
    address public owner;

    constructor() {
        owner = msg.sender;
    }
}

contract Child is Parent {
    // Don't redeclare owner - use inherited variable

    function setOwner(address newOwner) public {
        owner = newOwner;  // Modifies Parent.owner correctly
    }
}
""",
        attack_scenario=(
            "1. Parent contract checks owner for access control. "
            "2. Child shadows owner variable. "
            "3. Child's setOwner updates Child.owner only. "
            "4. Parent's owner check uses Parent.owner (unchanged). "
            "5. Access control behaves unexpectedly."
        ),
        severity="medium",
        category="inheritance",
        tags=["shadowing", "inheritance", "state-variable", "storage"],
    ),

    # SWC-113: DoS with Failed Call
    VulnerabilityDocument(
        id="SWC-113",
        swc_id="SWC-113",
        cwe_id="CWE-400",
        title="DoS with Failed Call",
        description=(
            "External calls can fail intentionally. If a contract iterates through "
            "recipients and one always reverts, the entire function becomes unusable. "
            "Attackers can exploit this to block legitimate operations."
        ),
        vulnerable_code="""
address[] public bidders;

function refundAll() external {
    for (uint i = 0; i < bidders.length; i++) {
        // If any transfer fails, entire function reverts!
        payable(bidders[i]).transfer(bids[bidders[i]]);
    }
}
""",
        fixed_code="""
mapping(address => uint256) public pendingReturns;

function refundAll() external {
    for (uint i = 0; i < bidders.length; i++) {
        pendingReturns[bidders[i]] = bids[bidders[i]];
    }
}

// Pull pattern - users withdraw themselves
function withdraw() external {
    uint256 amount = pendingReturns[msg.sender];
    require(amount > 0);
    pendingReturns[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
""",
        attack_scenario=(
            "1. Attacker bids in auction with contract that reverts on receive. "
            "2. Auction ends, refundAll() called to return funds. "
            "3. When transfer to attacker's contract happens, it reverts. "
            "4. Entire refundAll() reverts - no one gets refund. "
            "5. Funds locked forever."
        ),
        severity="medium",
        category="denial-of-service",
        real_exploit="King of the Ether (2016)",
        tags=["dos", "failed-call", "pull-pattern", "revert", "griefing"],
    ),

    # SWC-126: Insufficient Gas Griefing
    VulnerabilityDocument(
        id="SWC-126",
        swc_id="SWC-126",
        cwe_id="CWE-691",
        title="Insufficient Gas Griefing",
        description=(
            "When a contract makes an external call, the caller controls how much gas "
            "to forward. A malicious relayer can provide just enough gas for the outer "
            "call to succeed but the inner call to fail."
        ),
        vulnerable_code="""
function relay(address target, bytes calldata data) external {
    (bool success,) = target.call(data);  // All remaining gas forwarded
    // But relayer can limit gas to fail inner call
    require(success, "Call failed");
}
""",
        fixed_code="""
function relay(address target, bytes calldata data, uint256 gasLimit) external {
    require(gasleft() >= gasLimit + 10000, "Insufficient gas");
    (bool success,) = target.call{gas: gasLimit}(data);
    require(success, "Call failed");
}

// Or use EIP-150 1/64th rule consideration
function safeRelay(address target, bytes calldata data) external {
    uint256 gasToForward = gasleft() - 5000;
    (bool success,) = target.call{gas: gasToForward}(data);
    require(success, "Call failed");
}
""",
        attack_scenario=(
            "1. User relies on relayer to submit transaction. "
            "2. Relayer forwards minimal gas. "
            "3. Outer call succeeds (enough gas). "
            "4. Inner subcall fails (insufficient gas). "
            "5. User's transaction appears successful but didn't complete."
        ),
        severity="medium",
        category="gas",
        tags=["gas-griefing", "relay", "insufficient-gas", "eip-150"],
    ),

    # SWC-132: Unexpected Ether Balance
    VulnerabilityDocument(
        id="SWC-132",
        swc_id="SWC-132",
        cwe_id="CWE-841",
        title="Unexpected Ether Balance",
        description=(
            "Contracts can receive ETH through selfdestruct (forced) or coinbase "
            "transactions without triggering receive/fallback. Contracts that rely on "
            "address(this).balance == expected_value are vulnerable."
        ),
        vulnerable_code="""
function withdraw() external {
    require(address(this).balance == totalDeposits);  // Can be broken!
    payable(msg.sender).transfer(deposits[msg.sender]);
    totalDeposits -= deposits[msg.sender];
}
""",
        fixed_code="""
// Track balances independently, don't rely on address(this).balance
uint256 public accountedBalance;

function deposit() external payable {
    deposits[msg.sender] += msg.value;
    accountedBalance += msg.value;
}

function withdraw() external {
    uint256 amount = deposits[msg.sender];
    deposits[msg.sender] = 0;
    accountedBalance -= amount;
    payable(msg.sender).transfer(amount);
}
""",
        attack_scenario=(
            "1. Contract checks balance == expected for invariant. "
            "2. Attacker creates contract with some ETH. "
            "3. Attacker selfdestructs, sending ETH to victim. "
            "4. Victim's balance check now fails. "
            "5. Contract functionality broken."
        ),
        severity="low",
        category="balance",
        tags=["selfdestruct", "balance", "unexpected-ether", "invariant"],
    ),

    # SWC-124: Write to Arbitrary Storage
    VulnerabilityDocument(
        id="SWC-124",
        swc_id="SWC-124",
        cwe_id="CWE-123",
        title="Write to Arbitrary Storage Location",
        description=(
            "Dynamic arrays in storage can be manipulated to write to arbitrary slots. "
            "If array length is user-controlled, attacker can overflow array index to "
            "target specific storage slots like owner address."
        ),
        vulnerable_code="""
uint256[] public data;

function write(uint256 index, uint256 value) external {
    // No bounds check!
    data[index] = value;  // Can write to ANY storage slot
}

function expand(uint256 newLength) external {
    data.length = newLength;  // Old Solidity: controllable length
}
""",
        fixed_code="""
uint256[] public data;

function write(uint256 index, uint256 value) external {
    require(index < data.length, "Out of bounds");
    data[index] = value;
}

// Modern Solidity: Use push() for dynamic arrays
function append(uint256 value) external {
    data.push(value);
}
""",
        attack_scenario=(
            "1. Array stored at slot S, length at slot S. "
            "2. Array elements at keccak256(S) + index. "
            "3. Attacker calculates index to hit target slot (e.g., owner). "
            "4. Attacker calls write(malicious_index, attacker_address). "
            "5. Owner slot overwritten, attacker gains control."
        ),
        severity="critical",
        category="storage",
        tags=["arbitrary-write", "storage", "array", "overflow", "solidity-version"],
    ),

    # Permit Function Phishing
    VulnerabilityDocument(
        id="PERMIT-PHISHING",
        swc_id=None,
        cwe_id="CWE-352",
        title="ERC-2612 Permit Function Phishing",
        description=(
            "ERC-2612 permit() allows gasless approvals via signatures. Attackers can "
            "trick users into signing permit messages that approve unlimited spending "
            "to attacker-controlled addresses."
        ),
        vulnerable_code="""
// This is actually standard permit - the vulnerability is in how it's used
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    // Attacker tricks user into signing (owner=user, spender=attacker, value=MAX)
}
""",
        fixed_code="""
// User protection: Always verify permit parameters before signing
// Wallet protection: Show clear permit details to user
// Protocol protection: Limit permit amounts and add time-based restrictions

// For smart contract wallets:
function safePermit(...) external {
    require(value <= dailyLimit[owner], "Exceeds daily limit");
    require(spender != address(0), "Invalid spender");
    // Additional checks...
}
""",
        attack_scenario=(
            "1. Attacker creates phishing site mimicking legitimate dApp. "
            "2. Site requests user to sign 'transaction' (actually permit). "
            "3. User signs permit: spender=attacker, value=MAX_UINT. "
            "4. Attacker calls permit() with user's signature. "
            "5. Attacker now approved for all user's tokens, drains wallet."
        ),
        severity="high",
        category="phishing",
        real_exploit="Multiple permit phishing attacks, millions lost (2023)",
        tags=["permit", "erc2612", "phishing", "signature", "approval", "gasless"],
    ),

    # ERC-4626 Vault Inflation Attack
    VulnerabilityDocument(
        id="ERC4626-INFLATION",
        swc_id=None,
        cwe_id="CWE-682",
        title="ERC-4626 Vault Inflation Attack",
        description=(
            "ERC-4626 vaults can be exploited if the first depositor manipulates the "
            "share/asset ratio. By donating assets directly (not through deposit), "
            "attacker inflates share price, causing later depositors to receive 0 shares."
        ),
        vulnerable_code="""
// Standard ERC-4626 without protection
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    return supply == 0 ? assets : assets * supply / totalAssets();
}

function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = convertToShares(assets);  // Can round to 0!
    // Transfer and mint...
}
""",
        fixed_code="""
// Add virtual shares/assets offset
function convertToShares(uint256 assets) public view returns (uint256) {
    return assets.mulDivDown(totalSupply() + 1, totalAssets() + 1);
}

// Or require minimum deposit on first deposit
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    if (totalSupply() == 0) {
        require(assets >= MIN_DEPOSIT, "Below minimum");
    }
    shares = convertToShares(assets);
    require(shares > 0, "Zero shares");
    // Continue...
}
""",
        attack_scenario=(
            "1. Attacker is first depositor, deposits 1 wei, gets 1 share. "
            "2. Attacker donates 100 ETH directly to vault (not deposit). "
            "3. 1 share = 100 ETH + 1 wei. "
            "4. Victim deposits 99 ETH. "
            "5. convertToShares(99 ETH) = 0 due to rounding. "
            "6. Victim gets 0 shares, attacker profits."
        ),
        severity="high",
        category="vault",
        real_exploit="Multiple ERC-4626 implementations vulnerable",
        tags=["erc4626", "vault", "inflation", "rounding", "first-deposit", "defi"],
    ),

    # UUPS Uninitialized Implementation
    VulnerabilityDocument(
        id="UUPS-UNINITIALIZED",
        swc_id=None,
        cwe_id="CWE-665",
        title="UUPS Proxy Uninitialized Implementation",
        description=(
            "UUPS proxies store upgrade logic in the implementation. If the implementation "
            "is left uninitialized, anyone can call initialize() to become owner and then "
            "call upgradeToAndCall() to destroy or replace the proxy."
        ),
        vulnerable_code="""
// Implementation contract
contract MyContractV1 is UUPSUpgradeable {
    address public owner;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }

    function _authorizeUpgrade(address) internal override {
        require(msg.sender == owner);
    }
}

// DANGER: Implementation deployed but initialize() not called
// Anyone can call initialize() on the implementation directly
""",
        fixed_code="""
contract MyContractV1 is UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();  // Prevent initialization of implementation
    }

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}

// Always call _disableInitializers() in constructor
""",
        attack_scenario=(
            "1. Protocol deploys UUPS implementation without initializing. "
            "2. Attacker calls implementation.initialize(attacker). "
            "3. Attacker is now owner of implementation. "
            "4. Attacker calls upgradeToAndCall with selfdestruct payload. "
            "5. Implementation destroyed, proxy becomes unusable."
        ),
        severity="critical",
        category="proxy",
        real_exploit="Wormhole - Implementation takeover possible (2022)",
        tags=["uups", "proxy", "uninitialized", "upgradeable", "initializer"],
    ),

    # Cross-Contract Reentrancy
    VulnerabilityDocument(
        id="CROSS-CONTRACT-REENTRANCY",
        swc_id="SWC-107",
        cwe_id="CWE-841",
        title="Cross-Contract Reentrancy",
        description=(
            "Reentrancy between different contracts in the same protocol. Contract A "
            "calls Contract B which calls back to Contract A (or C) before A's state "
            "is updated. Each contract may be safe individually but vulnerable together."
        ),
        vulnerable_code="""
// Contract A (Lending Pool)
function borrow(uint amount) external {
    require(collateral[msg.sender] >= amount * 2);
    token.transfer(msg.sender, amount);  // External call
    borrowed[msg.sender] += amount;
}

// Contract B (Collateral Manager) - shares state with A
function withdraw(uint amount) external {
    require(collateral[msg.sender] >= amount);
    collateral[msg.sender] -= amount;  // During reentrancy, this isn't updated yet in A's view
    msg.sender.call{value: amount}("");  // Callback point
}
""",
        fixed_code="""
// Use protocol-wide reentrancy lock
contract ReentrancyGuard {
    uint256 private constant UNLOCKED = 1;
    uint256 private constant LOCKED = 2;
    uint256 private _status = UNLOCKED;

    modifier nonReentrant() {
        require(_status == UNLOCKED);
        _status = LOCKED;
        _;
        _status = UNLOCKED;
    }
}

// Share the lock across all protocol contracts
// Or use a central registry for cross-contract locks
""",
        attack_scenario=(
            "1. Attacker deposits collateral in Contract B. "
            "2. Attacker calls borrow() in Contract A. "
            "3. Before borrow updates state, calls withdraw() in B. "
            "4. B sends ETH, triggering callback to attacker. "
            "5. Attacker re-borrows (collateral still shows as available). "
            "6. Protocol drained across contracts."
        ),
        severity="critical",
        category="reentrancy",
        real_exploit="Fei Protocol Rari Hack - $80M (2022)",
        tags=["reentrancy", "cross-contract", "protocol", "shared-state"],
    ),

    # Rebasing Token Issues
    VulnerabilityDocument(
        id="REBASING-TOKEN",
        swc_id=None,
        cwe_id="CWE-682",
        title="Rebasing Token Incompatibility",
        description=(
            "Rebasing tokens (like stETH, AMPL) automatically adjust all balances. "
            "Protocols that cache balances or use transfer amounts directly will have "
            "accounting errors as the actual balance changes over time."
        ),
        vulnerable_code="""
mapping(address => uint256) public stakedAmount;

function stake(uint256 amount) external {
    rebasingToken.transferFrom(msg.sender, address(this), amount);
    stakedAmount[msg.sender] = amount;  // Cached amount, won't update on rebase
}

function unstake() external {
    uint256 amount = stakedAmount[msg.sender];
    stakedAmount[msg.sender] = 0;
    rebasingToken.transfer(msg.sender, amount);  // May fail if negative rebase occurred
}
""",
        fixed_code="""
// Use shares instead of amounts for rebasing tokens
mapping(address => uint256) public userShares;

function stake(uint256 amount) external {
    uint256 sharesBefore = rebasingToken.sharesOf(address(this));
    rebasingToken.transferFrom(msg.sender, address(this), amount);
    uint256 sharesAfter = rebasingToken.sharesOf(address(this));
    userShares[msg.sender] += sharesAfter - sharesBefore;
}

// Or simply don't support rebasing tokens
require(!isRebasingToken(token), "Rebasing tokens not supported");
""",
        attack_scenario=(
            "1. User stakes 100 stETH, protocol records 100. "
            "2. Positive rebase: user's stake is now worth 110 stETH. "
            "3. User withdraws, only gets 100 stETH (protocol's cached amount). "
            "4. Extra 10 stETH stuck in protocol. "
            "5. Or with negative rebase: protocol may be insolvent."
        ),
        severity="medium",
        category="token",
        real_exploit="Multiple DeFi protocols had rebasing issues",
        tags=["rebasing", "steth", "ampl", "shares", "balance", "defi"],
    ),

    # Merkle Tree Leaf Collision
    VulnerabilityDocument(
        id="MERKLE-LEAF-COLLISION",
        swc_id=None,
        cwe_id="CWE-327",
        title="Merkle Tree Leaf vs Node Collision",
        description=(
            "Merkle trees that don't differentiate between leaf and internal node hashes "
            "are vulnerable to second preimage attacks. An attacker can prove membership "
            "of fabricated data by providing an internal node as a 'leaf'."
        ),
        vulnerable_code="""
function verifyProof(
    bytes32[] memory proof,
    bytes32 root,
    bytes32 leaf
) internal pure returns (bool) {
    bytes32 computedHash = leaf;
    for (uint256 i = 0; i < proof.length; i++) {
        computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
        // No distinction between leaf and internal node hashing!
    }
    return computedHash == root;
}
""",
        fixed_code="""
// Use different hash for leaves vs internal nodes
function verifyProof(...) internal pure returns (bool) {
    // Leaf hash: 0x00 prefix
    bytes32 computedHash = keccak256(abi.encodePacked(hex"00", leaf));

    for (uint256 i = 0; i < proof.length; i++) {
        // Internal node hash: 0x01 prefix + sorted children
        if (computedHash < proof[i]) {
            computedHash = keccak256(abi.encodePacked(hex"01", computedHash, proof[i]));
        } else {
            computedHash = keccak256(abi.encodePacked(hex"01", proof[i], computedHash));
        }
    }
    return computedHash == root;
}

// Or use OpenZeppelin MerkleProof library
""",
        attack_scenario=(
            "1. Merkle tree has leaves: hash(A), hash(B). "
            "2. Internal node = hash(hash(A) || hash(B)). "
            "3. Attacker presents internal node value as 'leaf'. "
            "4. Proof verifies (internal node is in tree). "
            "5. Attacker claims airdrop for fabricated data."
        ),
        severity="high",
        category="cryptography",
        real_exploit="CVE-2012-2459 (Bitcoin), various Merkle airdrops",
        tags=["merkle", "proof", "collision", "airdrop", "cryptography"],
    ),

    # Lack of Access Control on Callback
    VulnerabilityDocument(
        id="CALLBACK-ACCESS-CONTROL",
        swc_id=None,
        cwe_id="CWE-284",
        title="Missing Access Control on Callback Functions",
        description=(
            "Callback functions (like Uniswap's uniswapV3SwapCallback or flash loan callbacks) "
            "must verify the caller. Without proper validation, attackers can call these "
            "functions directly with malicious parameters."
        ),
        vulnerable_code="""
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // NO CALLER VALIDATION!
    // Attacker can call directly
    if (amount0Delta > 0) {
        IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
    }
}
""",
        fixed_code="""
function uniswapV3SwapCallback(
    int256 amount0Delta,
    int256 amount1Delta,
    bytes calldata data
) external {
    // Verify caller is legitimate Uniswap pool
    require(msg.sender == address(pool), "Invalid caller");
    // Or compute expected pool address
    address expectedPool = PoolAddress.computeAddress(
        factory, PoolAddress.getPoolKey(token0, token1, fee)
    );
    require(msg.sender == expectedPool, "Invalid pool");

    // Now safe to proceed
    if (amount0Delta > 0) {
        IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
    }
}
""",
        attack_scenario=(
            "1. Protocol implements swap callback without caller check. "
            "2. Attacker calls callback directly (not through swap). "
            "3. Passes attacker's address for payment. "
            "4. Protocol sends tokens to attacker. "
            "5. Funds drained without actual swap occurring."
        ),
        severity="critical",
        category="access-control",
        real_exploit="Multiple DeFi protocols vulnerable to callback exploits",
        tags=["callback", "access-control", "uniswap", "flash-loan", "verification"],
    ),

    # Precision Loss in Division
    VulnerabilityDocument(
        id="PRECISION-LOSS",
        swc_id=None,
        cwe_id="CWE-682",
        title="Precision Loss in Division",
        description=(
            "Solidity integer division truncates (rounds down). Operations like "
            "(a / b) * c lose precision compared to (a * c) / b. This can be "
            "exploited to extract value through rounding errors."
        ),
        vulnerable_code="""
function calculateFee(uint256 amount) public pure returns (uint256) {
    return (amount / 10000) * 30;  // 0.3% fee - precision loss!
    // For amount = 9999, returns 0 instead of ~3
}

function swap(uint256 amountIn) external returns (uint256) {
    uint256 fee = calculateFee(amountIn);
    uint256 amountOut = (amountIn - fee) * price / 1e18;
    // Multiple division operations compound precision loss
}
""",
        fixed_code="""
function calculateFee(uint256 amount) public pure returns (uint256) {
    return (amount * 30) / 10000;  // Multiply first, then divide
}

// Use higher precision internally
uint256 constant PRECISION = 1e18;

function swap(uint256 amountIn) external returns (uint256) {
    uint256 amountOutPrecise = amountIn * PRECISION * price / 10000 / 1e18;
    return amountOutPrecise / PRECISION;
}

// Or use fixed-point math libraries like PRBMath
""",
        attack_scenario=(
            "1. Protocol charges 0.3% fee with (amount/10000)*30. "
            "2. Attacker sends many small swaps of 9999 wei. "
            "3. Fee calculates to 0 each time (9999/10000 = 0). "
            "4. Attacker avoids all fees. "
            "5. Over time, significant value extracted."
        ),
        severity="medium",
        category="arithmetic",
        tags=["precision", "division", "rounding", "fee", "dust"],
    ),

    # Time-lock Bypass
    VulnerabilityDocument(
        id="TIMELOCK-BYPASS",
        swc_id=None,
        cwe_id="CWE-287",
        title="Governance Timelock Bypass",
        description=(
            "Timelocks protect users by delaying sensitive operations. However, some "
            "functions may bypass the timelock, or the timelock admin might have direct "
            "access, negating the protection entirely."
        ),
        vulnerable_code="""
contract Treasury {
    address public admin;
    address public timelock;

    function executeProposal(bytes calldata data) external {
        require(msg.sender == timelock, "Only timelock");
        // Execute...
    }

    function emergencyWithdraw(address to) external {
        require(msg.sender == admin, "Only admin");
        // BYPASSES TIMELOCK! Admin can drain instantly
        payable(to).transfer(address(this).balance);
    }
}
""",
        fixed_code="""
contract Treasury {
    address public timelock;  // Only timelock can act

    // ALL sensitive functions go through timelock
    function executeProposal(bytes calldata data) external {
        require(msg.sender == timelock, "Only timelock");
        // Execute...
    }

    // Even emergency functions have delay
    function emergencyWithdraw(address to) external {
        require(msg.sender == timelock, "Only timelock");
        // Emergency can have shorter delay, but still has one
        payable(to).transfer(address(this).balance);
    }
}
""",
        attack_scenario=(
            "1. Protocol advertises 48h timelock for governance safety. "
            "2. Admin (multisig) has emergencyWithdraw() bypassing timelock. "
            "3. Multisig keys compromised or malicious. "
            "4. Admin calls emergencyWithdraw() - no delay. "
            "5. Treasury drained before users can react."
        ),
        severity="high",
        category="governance",
        tags=["timelock", "bypass", "governance", "admin", "emergency", "defi"],
    ),

    # Chainlink Stale Price
    VulnerabilityDocument(
        id="CHAINLINK-STALE-PRICE",
        swc_id=None,
        cwe_id="CWE-754",
        title="Chainlink Oracle Stale/Invalid Price",
        description=(
            "Chainlink price feeds can return stale data, incomplete rounds, or zero "
            "prices during network congestion or oracle issues. Contracts must validate "
            "all returned values to avoid using bad price data."
        ),
        vulnerable_code="""
function getPrice() external view returns (uint256) {
    (, int256 price,,,) = priceFeed.latestRoundData();
    return uint256(price);  // No validation!
}
""",
        fixed_code="""
function getPrice() external view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    // Validate round completeness
    require(answeredInRound >= roundId, "Stale price round");

    // Validate freshness
    require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");

    // Validate price is positive
    require(price > 0, "Invalid price");

    // Validate price is within reasonable bounds
    require(price < MAX_PRICE && price > MIN_PRICE, "Price out of bounds");

    return uint256(price);
}
""",
        attack_scenario=(
            "1. Network congestion delays Chainlink updates. "
            "2. Price feed returns 24-hour-old price. "
            "3. Actual market price has moved 50%. "
            "4. Attacker exploits stale price for arbitrage. "
            "5. Protocol loses funds due to mispricing."
        ),
        severity="high",
        category="oracle",
        real_exploit="Multiple DeFi exploits during market volatility",
        tags=["chainlink", "oracle", "stale-price", "validation", "defi"],
    ),

    # Missing Zero Address Validation
    VulnerabilityDocument(
        id="ZERO-ADDRESS-CHECK",
        swc_id=None,
        cwe_id="CWE-20",
        title="Missing Zero Address Validation",
        description=(
            "Functions that accept addresses should validate against the zero address "
            "(address(0)). Sending tokens or ETH to zero address burns them permanently. "
            "Setting owner/admin to zero address removes access permanently."
        ),
        vulnerable_code="""
function setOwner(address newOwner) external onlyOwner {
    owner = newOwner;  // If newOwner is address(0), ownership lost forever
}

function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;
    balances[to] += amount;  // Tokens sent to address(0) are burned
}
""",
        fixed_code="""
function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Invalid address");
    owner = newOwner;
}

function transfer(address to, uint256 amount) external {
    require(to != address(0), "Cannot transfer to zero address");
    balances[msg.sender] -= amount;
    balances[to] += amount;
}

// Or use custom error for gas efficiency (Solidity 0.8.4+)
error ZeroAddress();
if (to == address(0)) revert ZeroAddress();
""",
        attack_scenario=(
            "1. Admin accidentally calls setOwner(address(0)). "
            "2. Or attacker tricks admin into setting zero address. "
            "3. Contract now has no owner. "
            "4. No one can call onlyOwner functions. "
            "5. Contract stuck in current state forever."
        ),
        severity="low",
        category="validation",
        tags=["zero-address", "validation", "burn", "access-control", "input-validation"],
    ),
]


# =============================================================================
# CHROMADB EMBEDDING RAG
# =============================================================================


class EmbeddingRAG:
    """
    ChromaDB-powered Retrieval-Augmented Generation for vulnerability analysis.

    Uses sentence-transformers for embeddings and ChromaDB for vector storage.
    Provides semantic similarity search across the vulnerability knowledge base.
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"  # Fast, good quality embeddings
    COLLECTION_NAME = "miesc_vulnerabilities"

    def __init__(
        self,
        persist_directory: Optional[str] = None,
        embedding_model: str = DEFAULT_MODEL,
        top_k: int = 5,
    ):
        """
        Initialize the embedding RAG system.

        Args:
            persist_directory: Directory for ChromaDB persistence.
                              If None, uses in-memory database.
            embedding_model: Sentence-transformers model name.
            top_k: Number of results to return from searches.
        """
        self.top_k = top_k
        self.embedding_model_name = embedding_model

        # Set up persistence directory
        if persist_directory is None:
            self.persist_dir = Path.home() / ".miesc" / "chromadb"
        else:
            self.persist_dir = Path(persist_directory)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # Lazy-loaded components
        self._embedder = None
        self._client = None
        self._collection = None
        self._initialized = False

        logger.info(f"EmbeddingRAG configured with model={embedding_model}, top_k={top_k}")

    def _ensure_initialized(self) -> None:
        """Lazy initialization of ChromaDB and embeddings."""
        if self._initialized:
            return

        try:
            # Initialize sentence-transformers
            SentenceTransformer = _get_sentence_transformer()
            self._embedder = SentenceTransformer(self.embedding_model_name)
            logger.info(f"Loaded embedding model: {self.embedding_model_name}")

            # Initialize ChromaDB
            chromadb = _get_chromadb()
            self._client = chromadb.PersistentClient(path=str(self.persist_dir))

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"}  # Cosine similarity
            )

            # Check if we need to populate the knowledge base
            if self._collection.count() == 0:
                logger.info("Indexing vulnerability knowledge base...")
                self._index_knowledge_base()
            else:
                logger.info(f"Using existing index with {self._collection.count()} documents")

            self._initialized = True

        except ImportError as e:
            raise ImportError(
                f"Required dependency not found: {e}. "
                "Install with: pip install chromadb sentence-transformers"
            )

    def _index_knowledge_base(self) -> None:
        """Index the vulnerability knowledge base into ChromaDB."""
        documents = []
        metadatas = []
        ids = []

        for vuln in VULNERABILITY_KNOWLEDGE_BASE:
            documents.append(vuln.to_text())
            metadatas.append(vuln.to_metadata())
            ids.append(vuln.id)

        # Generate embeddings
        embeddings = self._embedder.encode(documents, show_progress_bar=True)

        # Add to ChromaDB
        self._collection.add(
            documents=documents,
            embeddings=embeddings.tolist(),
            metadatas=metadatas,
            ids=ids,
        )

        logger.info(f"Indexed {len(documents)} vulnerability documents")

    def search(
        self,
        query: str,
        filter_category: Optional[str] = None,
        filter_severity: Optional[str] = None,
        n_results: Optional[int] = None,
    ) -> List[RetrievalResult]:
        """
        Search for similar vulnerabilities using semantic similarity.

        Args:
            query: Search query (natural language or code snippet)
            filter_category: Filter by vulnerability category
            filter_severity: Filter by severity level
            n_results: Number of results (overrides top_k)

        Returns:
            List of RetrievalResult with matched documents and scores
        """
        self._ensure_initialized()

        n = n_results or self.top_k

        # Build filter conditions
        where_filter = None
        if filter_category or filter_severity:
            conditions = []
            if filter_category:
                conditions.append({"category": filter_category})
            if filter_severity:
                conditions.append({"severity": filter_severity})

            if len(conditions) == 1:
                where_filter = conditions[0]
            else:
                where_filter = {"$and": conditions}

        # Query ChromaDB
        results = self._collection.query(
            query_texts=[query],
            n_results=n,
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )

        # Convert to RetrievalResult objects
        retrieval_results = []

        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                # Find the original document
                original_doc = next(
                    (d for d in VULNERABILITY_KNOWLEDGE_BASE if d.id == doc_id),
                    None
                )

                if original_doc:
                    # ChromaDB returns distance, convert to similarity
                    distance = results["distances"][0][i] if results["distances"] else 0
                    similarity = 1 - distance  # Cosine distance to similarity

                    retrieval_results.append(RetrievalResult(
                        document=original_doc,
                        similarity_score=similarity,
                        relevance_reason=self._explain_relevance(query, original_doc),
                    ))

        return retrieval_results

    def search_by_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
    ) -> List[RetrievalResult]:
        """
        Search for similar vulnerabilities based on a security finding.

        Args:
            finding: A vulnerability finding dictionary
            code_context: Optional code snippet for context

        Returns:
            List of relevant vulnerabilities from knowledge base
        """
        # Build query from finding
        query_parts = []

        if finding.get("type"):
            query_parts.append(f"Vulnerability type: {finding['type']}")
        if finding.get("title"):
            query_parts.append(f"Issue: {finding['title']}")
        if finding.get("description"):
            query_parts.append(finding["description"][:500])
        if finding.get("swc_id"):
            query_parts.append(f"SWC ID: {finding['swc_id']}")
        if code_context:
            query_parts.append(f"Code: {code_context[:500]}")

        query = "\n".join(query_parts)

        # Determine category filter from finding
        category = None
        vuln_type = finding.get("type", "").lower()
        if "reentrancy" in vuln_type:
            category = "reentrancy"
        elif "access" in vuln_type or "auth" in vuln_type:
            category = "access-control"
        elif "oracle" in vuln_type or "price" in vuln_type:
            category = "oracle"

        return self.search(query, filter_category=category)

    def get_context_for_llm(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        max_context_length: int = 2000,
    ) -> str:
        """
        Generate context string for LLM prompt enrichment.

        Args:
            finding: The vulnerability finding to enhance
            code_context: Optional code snippet
            max_context_length: Maximum length of returned context

        Returns:
            Formatted context string for LLM prompt
        """
        results = self.search_by_finding(finding, code_context)

        if not results:
            return "No similar vulnerabilities found in knowledge base."

        context_parts = ["## Similar Known Vulnerabilities\n"]
        current_length = len(context_parts[0])

        for result in results:
            entry = result.to_context()
            if current_length + len(entry) > max_context_length:
                break
            context_parts.append(entry)
            context_parts.append("\n---\n")
            current_length += len(entry) + 5

        return "".join(context_parts)

    def add_custom_vulnerability(
        self,
        vulnerability: VulnerabilityDocument,
    ) -> None:
        """
        Add a custom vulnerability to the knowledge base.

        Args:
            vulnerability: VulnerabilityDocument to add
        """
        self._ensure_initialized()

        # Generate embedding
        embedding = self._embedder.encode([vulnerability.to_text()])[0]

        # Add to ChromaDB
        self._collection.add(
            documents=[vulnerability.to_text()],
            embeddings=[embedding.tolist()],
            metadatas=[vulnerability.to_metadata()],
            ids=[vulnerability.id],
        )

        logger.info(f"Added custom vulnerability: {vulnerability.id}")

    def _explain_relevance(self, query: str, doc: VulnerabilityDocument) -> str:
        """Generate explanation for why a document is relevant."""
        reasons = []

        query_lower = query.lower()

        if doc.swc_id and doc.swc_id.lower() in query_lower:
            reasons.append(f"Matches SWC ID: {doc.swc_id}")

        if doc.category and doc.category.lower() in query_lower:
            reasons.append(f"Matches category: {doc.category}")

        # Check for keyword matches
        keywords = ["reentrancy", "overflow", "access", "oracle", "flash", "signature"]
        for kw in keywords:
            if kw in query_lower and kw in doc.title.lower():
                reasons.append(f"Keyword match: {kw}")
                break

        if doc.real_exploit:
            reasons.append(f"Real-world exploit documented")

        if not reasons:
            reasons.append("Semantic similarity match")

        return "; ".join(reasons)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base."""
        self._ensure_initialized()

        return {
            "total_documents": self._collection.count(),
            "embedding_model": self.embedding_model_name,
            "persist_directory": str(self.persist_dir),
            "categories": list(set(d.category for d in VULNERABILITY_KNOWLEDGE_BASE)),
            "knowledge_base_version": "1.0.0",
        }

    def reindex(self) -> None:
        """Force reindex of the entire knowledge base."""
        self._ensure_initialized()

        # Delete existing collection
        self._client.delete_collection(self.COLLECTION_NAME)

        # Recreate
        self._collection = self._client.create_collection(
            name=self.COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )

        # Reindex
        self._index_knowledge_base()
        logger.info("Knowledge base reindexed")


# =============================================================================
# HYBRID RAG (Embeddings + BM25)
# =============================================================================


class HybridRAG(EmbeddingRAG):
    """
    Hybrid RAG combining semantic embeddings with BM25 lexical search.

    Provides better results by combining:
    - Semantic similarity (understanding meaning)
    - Lexical matching (exact keyword matches)
    """

    def __init__(
        self,
        persist_directory: Optional[str] = None,
        embedding_model: str = EmbeddingRAG.DEFAULT_MODEL,
        top_k: int = 5,
        embedding_weight: float = 0.7,
    ):
        """
        Initialize hybrid RAG.

        Args:
            persist_directory: ChromaDB persistence directory
            embedding_model: Sentence-transformers model
            top_k: Number of results
            embedding_weight: Weight for embedding scores (0-1).
                             BM25 weight = 1 - embedding_weight
        """
        super().__init__(persist_directory, embedding_model, top_k)
        self.embedding_weight = embedding_weight
        self._bm25 = None
        self._corpus = None

    def _ensure_initialized(self) -> None:
        """Initialize both embedding and BM25 indexes."""
        super()._ensure_initialized()

        if self._bm25 is None:
            self._build_bm25_index()

    def _build_bm25_index(self) -> None:
        """Build BM25 index from knowledge base."""
        try:
            from rank_bm25 import BM25Okapi
        except ImportError:
            logger.warning("rank_bm25 not installed, falling back to embeddings only")
            return

        # Tokenize documents
        self._corpus = []
        for doc in VULNERABILITY_KNOWLEDGE_BASE:
            tokens = doc.to_text().lower().split()
            self._corpus.append(tokens)

        self._bm25 = BM25Okapi(self._corpus)
        logger.info("BM25 index built")

    def search(
        self,
        query: str,
        filter_category: Optional[str] = None,
        filter_severity: Optional[str] = None,
        n_results: Optional[int] = None,
    ) -> List[RetrievalResult]:
        """
        Hybrid search combining embeddings and BM25.
        """
        self._ensure_initialized()

        n = n_results or self.top_k

        # Get embedding results (fetch more for reranking)
        embedding_results = super().search(
            query, filter_category, filter_severity, n_results=n * 2
        )

        if self._bm25 is None:
            # Fall back to embedding-only if BM25 not available
            return embedding_results[:n]

        # Get BM25 scores
        query_tokens = query.lower().split()
        bm25_scores = self._bm25.get_scores(query_tokens)

        # Normalize BM25 scores
        max_bm25 = max(bm25_scores) if max(bm25_scores) > 0 else 1
        bm25_scores = [s / max_bm25 for s in bm25_scores]

        # Create ID to BM25 score mapping
        id_to_bm25 = {
            VULNERABILITY_KNOWLEDGE_BASE[i].id: bm25_scores[i]
            for i in range(len(VULNERABILITY_KNOWLEDGE_BASE))
        }

        # Combine scores
        hybrid_results = []
        for result in embedding_results:
            bm25_score = id_to_bm25.get(result.document.id, 0)
            hybrid_score = (
                self.embedding_weight * result.similarity_score +
                (1 - self.embedding_weight) * bm25_score
            )

            hybrid_results.append(RetrievalResult(
                document=result.document,
                similarity_score=hybrid_score,
                relevance_reason=result.relevance_reason +
                    f" (hybrid: emb={result.similarity_score:.2f}, bm25={bm25_score:.2f})",
            ))

        # Sort by hybrid score and return top-k
        hybrid_results.sort(key=lambda x: -x.similarity_score)
        return hybrid_results[:n]


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

_default_rag: Optional[EmbeddingRAG] = None


def get_rag(hybrid: bool = True) -> EmbeddingRAG:
    """
    Get the default RAG instance.

    Args:
        hybrid: Use HybridRAG if True, else EmbeddingRAG

    Returns:
        Configured RAG instance
    """
    global _default_rag

    if _default_rag is None:
        if hybrid:
            _default_rag = HybridRAG()
        else:
            _default_rag = EmbeddingRAG()

    return _default_rag


def search_vulnerabilities(
    query: str,
    top_k: int = 5,
    hybrid: bool = True,
) -> List[RetrievalResult]:
    """
    Search the vulnerability knowledge base.

    Args:
        query: Search query
        top_k: Number of results
        hybrid: Use hybrid search

    Returns:
        List of matching vulnerabilities
    """
    rag = get_rag(hybrid=hybrid)
    return rag.search(query, n_results=top_k)


def get_context_for_finding(
    finding: Dict[str, Any],
    code: str = "",
    hybrid: bool = True,
) -> str:
    """
    Get RAG context for a security finding.

    Args:
        finding: Vulnerability finding dict
        code: Code context
        hybrid: Use hybrid search

    Returns:
        Context string for LLM enhancement
    """
    rag = get_rag(hybrid=hybrid)
    return rag.get_context_for_llm(finding, code)


__all__ = [
    # Data structures
    "VulnerabilityDocument",
    "RetrievalResult",
    # RAG classes
    "EmbeddingRAG",
    "HybridRAG",
    # Convenience functions
    "get_rag",
    "search_vulnerabilities",
    "get_context_for_finding",
    # Knowledge base
    "VULNERABILITY_KNOWLEDGE_BASE",
]
