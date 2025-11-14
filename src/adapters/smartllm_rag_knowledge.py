"""
RAG Knowledge Base for SmartLLM Enhanced Adapter
=================================================

ERC standard specifications and best practices for RAG-enhanced analysis.
Used to provide context to the LLM for more accurate vulnerability detection.

Author: Fernando Boiero
Date: 2025-01-13
"""

# ERC-20 Token Standard Knowledge
ERC20_KNOWLEDGE = """
ERC-20 Token Standard (Ethereum Request for Comment 20)
======================================================

REQUIRED FUNCTIONS:
- totalSupply() → uint256: Returns total token supply
- balanceOf(address account) → uint256: Returns account balance
- transfer(address to, uint256 amount) → bool: Transfers tokens
- allowance(address owner, address spender) → uint256: Returns remaining allowance
- approve(address spender, uint256 amount) → bool: Sets allowance
- transferFrom(address from, address to, uint256 amount) → bool: Transfer via allowance

REQUIRED EVENTS:
- Transfer(address indexed from, address indexed to, uint256 value)
- Approval(address indexed owner, address indexed spender, uint256 value)

COMMON VULNERABILITIES:
1. Missing return value checks (transfer/transferFrom should return bool)
2. No validation of address(0) in transfer/approve
3. Approval race condition (approve should check current allowance or use increaseAllowance/decreaseAllowance)
4. Integer overflow in arithmetic (use SafeMath for Solidity < 0.8.0)
5. Missing events emission after state changes
6. Reentrancy in transfer functions (CEI pattern violation)

BEST PRACTICES:
- Use OpenZeppelin's ERC20 implementation
- Implement SafeERC20 wrapper for external calls
- Add access control for mint/burn functions
- Use Solidity >= 0.8.0 for automatic overflow protection
- Always emit events for Transfer and Approval
- Validate recipient address is not zero
"""

# ERC-721 NFT Standard Knowledge
ERC721_KNOWLEDGE = """
ERC-721 Non-Fungible Token Standard
====================================

REQUIRED FUNCTIONS:
- balanceOf(address owner) → uint256: Returns NFT count
- ownerOf(uint256 tokenId) → address: Returns token owner
- safeTransferFrom(address from, address to, uint256 tokenId, bytes data): Safe transfer
- safeTransferFrom(address from, address to, uint256 tokenId): Safe transfer (no data)
- transferFrom(address from, address to, uint256 tokenId): Unsafe transfer
- approve(address to, uint256 tokenId): Approve token transfer
- setApprovalForAll(address operator, bool approved): Set operator
- getApproved(uint256 tokenId) → address: Get approved address
- isApprovedForAll(address owner, address operator) → bool: Check operator

REQUIRED EVENTS:
- Transfer(address indexed from, address indexed to, uint256 indexed tokenId)
- Approval(address indexed owner, address indexed approved, uint256 indexed tokenId)
- ApprovalForAll(address indexed owner, address indexed operator, bool approved)

COMMON VULNERABILITIES:
1. Missing onERC721Received check in safeTransferFrom
2. No validation that tokenId exists before transfer
3. Missing access control on mint/burn
4. Approval not cleared on transfer
5. Missing _checkOnERC721Received implementation
6. Double-minting same tokenId

BEST PRACTICES:
- Use OpenZeppelin's ERC721 implementation
- Always use safeTransferFrom over transferFrom
- Implement proper access control (Ownable/AccessControl)
- Validate tokenId existence in all functions
- Clear approvals on transfer
- Emit events for all state changes
"""

# ERC-1155 Multi-Token Standard Knowledge
ERC1155_KNOWLEDGE = """
ERC-1155 Multi-Token Standard
==============================

REQUIRED FUNCTIONS:
- balanceOf(address account, uint256 id) → uint256: Balance of token type
- balanceOfBatch(address[] accounts, uint256[] ids) → uint256[]: Batch balance query
- setApprovalForAll(address operator, bool approved): Set operator for all tokens
- isApprovedForAll(address account, address operator) → bool: Check operator
- safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data): Transfer
- safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data): Batch transfer

REQUIRED EVENTS:
- TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value)
- TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values)
- ApprovalForAll(address indexed account, address indexed operator, bool approved)
- URI(string value, uint256 indexed id)

COMMON VULNERABILITIES:
1. Missing onERC1155Received/onERC1155BatchReceived checks
2. Array length mismatch in batch operations (ids.length != amounts.length)
3. Integer overflow in balance updates (Solidity < 0.8.0)
4. Missing access control on mint/burn
5. Reentrancy in batch transfers
6. DoS via unbounded loops in batch operations

BEST PRACTICES:
- Use OpenZeppelin's ERC1155 implementation
- Validate array lengths match in batch operations
- Limit batch operation size (e.g., max 50 items)
- Use nonReentrant modifier on transfer functions
- Implement proper access control
- Validate recipient supports ERC1155Receiver
"""

# General Smart Contract Security Knowledge
SECURITY_BEST_PRACTICES = """
Smart Contract Security Best Practices
=======================================

ACCESS CONTROL:
- Use OpenZeppelin's Ownable or AccessControl
- Implement role-based permissions (RBAC)
- Validate msg.sender in privileged functions
- Never use tx.origin for authorization
- Use two-step ownership transfer (transferOwnership + acceptOwnership)

REENTRANCY PROTECTION:
- Follow Checks-Effects-Interactions (CEI) pattern
- Use OpenZeppelin's ReentrancyGuard
- Update state before external calls
- Avoid state changes after external calls
- Consider using pull over push pattern

INTEGER ARITHMETIC:
- Use Solidity >= 0.8.0 for automatic overflow protection
- For Solidity < 0.8.0, use SafeMath library
- Validate division by zero
- Check for underflow in subtraction
- Validate multiplication overflow

EXTERNAL CALLS:
- Always check return values from .call(), .send(), .transfer()
- Use .transfer() for simple ETH sends (2300 gas limit)
- Prefer .call{value: amount}("") for flexible gas
- Handle failed calls appropriately
- Avoid delegatecall to untrusted contracts

RANDOMNESS:
- NEVER use block.timestamp or blockhash for randomness
- Use Chainlink VRF for secure randomness
- Implement commit-reveal scheme if VRF not available
- Consider off-chain randomness with cryptographic proofs

GAS OPTIMIZATION:
- Use uint256 instead of uint8/uint16 (cheaper)
- Pack storage variables to minimize slots
- Use calldata instead of memory for function parameters
- Avoid unbounded loops (DoS risk)
- Use events for data storage when appropriate
"""

# Vulnerability Pattern Database
VULNERABILITY_PATTERNS = {
    "reentrancy": {
        "description": "State changes after external calls",
        "example": "balance[msg.sender] -= amount; (bool success,) = msg.sender.call{value: amount}(\"\");",
        "fix": "Use CEI pattern: update state before external call",
        "severity": "CRITICAL"
    },
    "integer_overflow": {
        "description": "Arithmetic operations without overflow protection",
        "example": "uint256 total = a + b; (Solidity < 0.8.0 without SafeMath)",
        "fix": "Use Solidity >= 0.8.0 or SafeMath library",
        "severity": "HIGH"
    },
    "unchecked_call": {
        "description": "External call return value not checked",
        "example": "recipient.call{value: amount}(\"\");",
        "fix": "Check return value: (bool success,) = recipient.call{value: amount}(\"\"); require(success);",
        "severity": "MEDIUM"
    },
    "tx_origin": {
        "description": "Using tx.origin for authorization",
        "example": "require(tx.origin == owner);",
        "fix": "Use msg.sender instead of tx.origin",
        "severity": "HIGH"
    },
    "delegatecall": {
        "description": "Delegatecall to untrusted contract",
        "example": "address(target).delegatecall(data);",
        "fix": "Whitelist delegatecall targets and validate addresses",
        "severity": "CRITICAL"
    },
    "timestamp_dependence": {
        "description": "Logic depends on block.timestamp",
        "example": "require(block.timestamp > deadline);",
        "fix": "Use block.number or accept 15-second miner manipulation window",
        "severity": "LOW"
    },
    "uninitialized_storage": {
        "description": "Storage pointer not initialized",
        "example": "struct MyStruct storage s; s.value = 10;",
        "fix": "Initialize storage pointers properly",
        "severity": "HIGH"
    },
    "selfdestruct": {
        "description": "Unprotected selfdestruct",
        "example": "function destroy() public { selfdestruct(payable(msg.sender)); }",
        "fix": "Add access control: function destroy() public onlyOwner",
        "severity": "CRITICAL"
    }
}


def get_relevant_knowledge(contract_code: str) -> str:
    """
    Retrieve relevant knowledge based on contract code analysis.

    Args:
        contract_code: Solidity contract source code

    Returns:
        Concatenated relevant knowledge sections
    """
    knowledge_sections = [SECURITY_BEST_PRACTICES]

    # Detect ERC standards
    if "ERC20" in contract_code or any(func in contract_code for func in ["transfer(", "approve(", "transferFrom("]):
        knowledge_sections.append(ERC20_KNOWLEDGE)

    if "ERC721" in contract_code or "tokenId" in contract_code or "ownerOf(" in contract_code:
        knowledge_sections.append(ERC721_KNOWLEDGE)

    if "ERC1155" in contract_code or "balanceOfBatch(" in contract_code:
        knowledge_sections.append(ERC1155_KNOWLEDGE)

    return "\n\n".join(knowledge_sections)


def get_vulnerability_context(vuln_type: str) -> str:
    """
    Get detailed context about a specific vulnerability type.

    Args:
        vuln_type: Vulnerability identifier

    Returns:
        Detailed vulnerability information
    """
    return VULNERABILITY_PATTERNS.get(vuln_type, {
        "description": "Unknown vulnerability type",
        "example": "N/A",
        "fix": "Review code for security issues",
        "severity": "MEDIUM"
    })
