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

# Vulnerability Pattern Database - Extended SWC Registry Coverage
VULNERABILITY_PATTERNS = {
    # ========== CRITICAL SEVERITY ==========
    "reentrancy": {
        "swc_id": "SWC-107",
        "description": "State changes after external calls allow recursive callbacks",
        "example": 'balance[msg.sender] -= amount; (bool success,) = msg.sender.call{value: amount}("");',
        "fix": "Use CEI pattern: update state before external call. Add ReentrancyGuard.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker contract calls back into vulnerable function during execution",
    },
    "delegatecall": {
        "swc_id": "SWC-112",
        "description": "Delegatecall to untrusted contract preserves caller context",
        "example": "address(target).delegatecall(data);",
        "fix": "Whitelist delegatecall targets and validate addresses. Use proxy patterns safely.",
        "severity": "CRITICAL",
        "attack_vector": "Malicious contract takes over storage via delegatecall",
    },
    "selfdestruct": {
        "swc_id": "SWC-106",
        "description": "Unprotected selfdestruct allows contract destruction",
        "example": "function destroy() public { selfdestruct(payable(msg.sender)); }",
        "fix": "Add access control: function destroy() public onlyOwner. Consider removing selfdestruct.",
        "severity": "CRITICAL",
        "attack_vector": "Anyone can destroy contract and steal funds",
    },
    "unprotected_upgrade": {
        "swc_id": "SWC-105",
        "description": "Upgrade function without access control",
        "example": "function upgrade(address newImpl) public { implementation = newImpl; }",
        "fix": "Add onlyOwner or role-based access. Use OpenZeppelin upgradeable contracts.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker upgrades to malicious implementation",
    },
    "arbitrary_jump": {
        "swc_id": "SWC-127",
        "description": "Jump to arbitrary location in bytecode",
        "example": "assembly { jump(target) }",
        "fix": "Avoid arbitrary jumps. Use structured control flow.",
        "severity": "CRITICAL",
        "attack_vector": "Execution redirected to malicious code",
    },
    # ========== HIGH SEVERITY ==========
    "integer_overflow": {
        "swc_id": "SWC-101",
        "description": "Arithmetic operations without overflow protection (Solidity < 0.8.0)",
        "example": "uint256 total = a + b; // Can wrap around",
        "fix": "Use Solidity >= 0.8.0 or SafeMath library",
        "severity": "HIGH",
        "attack_vector": "Overflow causes unexpected large values, underflow causes near-max values",
    },
    "tx_origin": {
        "swc_id": "SWC-115",
        "description": "Using tx.origin for authorization instead of msg.sender",
        "example": "require(tx.origin == owner);",
        "fix": "Use msg.sender instead of tx.origin",
        "severity": "HIGH",
        "attack_vector": "Phishing attack: user interacts with malicious contract that calls victim",
    },
    "uninitialized_storage": {
        "swc_id": "SWC-109",
        "description": "Storage pointer not initialized properly",
        "example": "struct MyStruct storage s; s.value = 10;",
        "fix": "Initialize storage pointers to specific slots. Use memory for local structs.",
        "severity": "HIGH",
        "attack_vector": "Overwrites critical storage slots like owner",
    },
    "access_control": {
        "swc_id": "SWC-105",
        "description": "Missing or weak access control on sensitive functions",
        "example": "function setOwner(address newOwner) public { owner = newOwner; }",
        "fix": "Add onlyOwner modifier. Use OpenZeppelin AccessControl.",
        "severity": "HIGH",
        "attack_vector": "Anyone can call privileged functions",
    },
    "signature_replay": {
        "swc_id": "SWC-121",
        "description": "Signature can be replayed on same or different chain",
        "example": "ecrecover(hash, v, r, s) without nonce",
        "fix": "Include nonce, chainId, and contract address in signed message",
        "severity": "HIGH",
        "attack_vector": "Attacker replays valid signature multiple times",
    },
    "front_running": {
        "swc_id": "SWC-114",
        "description": "Transaction can be front-run by observing mempool",
        "example": "Revealing winning lottery number in same transaction as claim",
        "fix": "Use commit-reveal scheme. Add time delays. Use private mempools.",
        "severity": "HIGH",
        "attack_vector": "MEV bots extract value by inserting transactions",
    },
    "dos_gas_limit": {
        "swc_id": "SWC-128",
        "description": "Unbounded loops cause out-of-gas",
        "example": "for (uint i = 0; i < users.length; i++) { pay(users[i]); }",
        "fix": "Use pull-over-push pattern. Limit iterations. Paginate operations.",
        "severity": "HIGH",
        "attack_vector": "Attacker adds entries until function exceeds gas limit",
    },
    "write_to_arbitrary_storage": {
        "swc_id": "SWC-124",
        "description": "User input controls storage slot to write",
        "example": "assembly { sstore(userInput, value) }",
        "fix": "Validate storage slot indices. Use mappings safely.",
        "severity": "HIGH",
        "attack_vector": "Overwrite owner or other critical slots",
    },
    # ========== MEDIUM SEVERITY ==========
    "unchecked_call": {
        "swc_id": "SWC-104",
        "description": "External call return value not checked",
        "example": 'recipient.call{value: amount}("");',
        "fix": 'Check return value: (bool success,) = recipient.call{value: amount}(""); require(success);',
        "severity": "MEDIUM",
        "attack_vector": "Silent failure leads to inconsistent state",
    },
    "shadowing": {
        "swc_id": "SWC-119",
        "description": "Local variable shadows state variable",
        "example": "uint256 owner; function setOwner(uint256 owner) { owner = owner; }",
        "fix": "Use different names. Enable compiler warnings.",
        "severity": "MEDIUM",
        "attack_vector": "Accidental use of wrong variable",
    },
    "locked_ether": {
        "swc_id": "SWC-132",
        "description": "Contract can receive ETH but has no withdrawal function",
        "example": "receive() external payable {} // No withdraw function",
        "fix": "Add withdrawal function or remove payable",
        "severity": "MEDIUM",
        "attack_vector": "ETH permanently locked in contract",
    },
    "default_visibility": {
        "swc_id": "SWC-100",
        "description": "Functions without explicit visibility default to public",
        "example": "function sensitiveAction() { ... } // Implicitly public",
        "fix": "Always specify visibility: public, external, internal, private",
        "severity": "MEDIUM",
        "attack_vector": "Internal functions exposed publicly",
    },
    "require_no_message": {
        "swc_id": "SWC-123",
        "description": "require/revert without error message",
        "example": "require(success); // No message",
        "fix": 'Add descriptive message: require(success, "Transfer failed")',
        "severity": "MEDIUM",
        "attack_vector": "Difficult to debug failures",
    },
    # ========== LOW SEVERITY ==========
    "timestamp_dependence": {
        "swc_id": "SWC-116",
        "description": "Logic depends on block.timestamp which miners can manipulate",
        "example": "require(block.timestamp > deadline);",
        "fix": "Use block.number or accept 15-second manipulation window. Use oracles for critical timing.",
        "severity": "LOW",
        "attack_vector": "Miners manipulate timestamp by ~15 seconds",
    },
    "weak_randomness": {
        "swc_id": "SWC-120",
        "description": "Using blockhash or timestamp for randomness",
        "example": "uint random = uint(blockhash(block.number - 1)) % 100;",
        "fix": "Use Chainlink VRF or commit-reveal scheme",
        "severity": "LOW",
        "attack_vector": "Miners/validators can manipulate randomness",
    },
    "floating_pragma": {
        "swc_id": "SWC-103",
        "description": "Pragma allows floating compiler version",
        "example": "pragma solidity ^0.8.0;",
        "fix": "Lock pragma to specific version: pragma solidity 0.8.20;",
        "severity": "LOW",
        "attack_vector": "Different compiler versions may introduce bugs",
    },
    "deprecated_functions": {
        "swc_id": "SWC-111",
        "description": "Using deprecated Solidity functions",
        "example": "sha3(), suicide(), throw",
        "fix": "Use keccak256(), selfdestruct(), revert()",
        "severity": "LOW",
        "attack_vector": "Future compiler versions may break",
    },
}

# ========== DeFi-Specific Vulnerability Patterns ==========
DEFI_VULNERABILITY_PATTERNS = {
    "flash_loan_attack": {
        "description": "Flash loan enables price manipulation within single transaction",
        "example": "Borrow large amount → manipulate price → profit → repay",
        "fix": "Use time-weighted oracles (TWAP). Add flash loan guards. Check price deviation limits.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker borrows millions, manipulates reserves, profits from arbitrage",
        "historical_exploits": ["bZx ($8M)", "Harvest Finance ($34M)", "Pancake Bunny ($45M)"],
    },
    "oracle_manipulation": {
        "description": "Price oracle uses spot price from AMM reserves",
        "example": "price = reserveB / reserveA; // Manipulable",
        "fix": "Use Chainlink oracles. Implement TWAP. Use multiple oracle sources.",
        "severity": "CRITICAL",
        "attack_vector": "Large swap manipulates spot price, affects lending/liquidation",
        "historical_exploits": ["Cream Finance ($130M)", "Mango Markets ($114M)"],
    },
    "sandwich_attack": {
        "description": "MEV bot front-runs and back-runs user transactions",
        "example": "Bot sees large swap → buys before → user gets worse price → bot sells after",
        "fix": "Use private mempools (Flashbots). Set slippage limits. Use limit orders.",
        "severity": "HIGH",
        "attack_vector": "MEV bots extract value from every large swap",
    },
    "infinite_approval": {
        "description": "User approves max uint256 tokens to protocol",
        "example": "token.approve(protocol, type(uint256).max);",
        "fix": "Approve only needed amount. Revoke approvals after use.",
        "severity": "HIGH",
        "attack_vector": "If protocol is compromised, attacker drains all approved tokens",
    },
    "slippage_attack": {
        "description": "No slippage protection on swaps/liquidity operations",
        "example": "swap(tokenA, tokenB, 0); // minAmountOut = 0",
        "fix": "Always set reasonable minAmountOut. Use deadline parameter.",
        "severity": "HIGH",
        "attack_vector": "Attacker manipulates pool, user receives nothing",
    },
    "rug_pull": {
        "description": "Owner can drain pool or disable withdrawals",
        "example": "function emergencyWithdraw() onlyOwner { token.transfer(owner, balance); }",
        "fix": "Use timelocks. Remove owner privileges. Use multisig.",
        "severity": "CRITICAL",
        "attack_vector": "Team drains funds and disappears",
    },
    "liquidation_manipulation": {
        "description": "Attacker triggers unjust liquidation via price manipulation",
        "example": "Flash loan → dump collateral price → liquidate → profit",
        "fix": "Use TWAP for liquidation prices. Add liquidation delay.",
        "severity": "CRITICAL",
        "attack_vector": "Profitable liquidations triggered by temporary price movements",
    },
    "donation_attack": {
        "description": "Direct token transfer affects share calculations",
        "example": "Vault shares = deposits / totalAssets; // Manipulable via donation",
        "fix": "Use virtual assets. Track deposits separately from balance.",
        "severity": "HIGH",
        "attack_vector": "Attacker donates tokens to inflate share value, first depositor gets all",
    },
}

# ========== Governance Vulnerability Patterns ==========
GOVERNANCE_VULNERABILITY_PATTERNS = {
    "flash_loan_governance": {
        "description": "Governance voting power acquired via flash loan",
        "example": "Borrow tokens → vote → return tokens in same block",
        "fix": "Use vote checkpoints. Require tokens held for minimum time.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker passes malicious proposals without capital",
    },
    "timelock_bypass": {
        "description": "Critical actions not protected by timelock",
        "example": "function setFee(uint fee) onlyOwner { ... } // Instant",
        "fix": "All admin functions go through timelock. Use OpenZeppelin TimelockController.",
        "severity": "HIGH",
        "attack_vector": "Malicious admin makes instant changes, users can't react",
    },
    "proposal_griefing": {
        "description": "Anyone can spam proposals, blocking legitimate ones",
        "example": "function propose(...) public { ... } // No threshold",
        "fix": "Require minimum token balance to propose. Add proposal fees.",
        "severity": "MEDIUM",
        "attack_vector": "Attacker fills proposal queue with spam",
    },
    "quorum_manipulation": {
        "description": "Low quorum allows minority to pass proposals",
        "example": "if (votes > totalSupply * 4 / 100) { execute(); }",
        "fix": "Dynamic quorum based on participation. Use quadratic voting.",
        "severity": "HIGH",
        "attack_vector": "Attacker buys 5% tokens and controls governance",
    },
    "emergency_shutdown": {
        "description": "No emergency shutdown mechanism for governance",
        "example": "Malicious proposal passes, no way to stop execution",
        "fix": "Add guardian role with veto power. Implement emergency pause.",
        "severity": "HIGH",
        "attack_vector": "Exploited proposal executes before community can react",
    },
}


def detect_contract_type(contract_code: str) -> str:
    """
    Detect the type of smart contract for specialized RAG context.

    Args:
        contract_code: Solidity contract source code

    Returns:
        Contract type: 'defi', 'nft', 'governance', 'token', or 'general'
    """
    code_lower = contract_code.lower()

    # DeFi patterns (lending, DEX, yield)
    defi_keywords = [
        "flashloan",
        "flash_loan",
        "flashmint",
        "swap",
        "liquidity",
        "pool",
        "amm",
        "borrow",
        "lend",
        "collateral",
        "liquidate",
        "stake",
        "unstake",
        "yield",
        "farm",
        "vault",
        "strategy",
        "deposit",
        "withdraw",
        "oracle",
        "pricefeed",
        "getprice",
        "reserves",
        "getreserves",
        "sync",
    ]
    if any(kw in code_lower for kw in defi_keywords):
        return "defi"

    # Governance patterns
    governance_keywords = [
        "propose",
        "proposal",
        "vote",
        "voting",
        "quorum",
        "timelock",
        "governor",
        "dao",
        "execute",
        "cancel",
        "queue",
        "votingpower",
        "delegate",
        "checkpoint",
    ]
    if any(kw in code_lower for kw in governance_keywords):
        return "governance"

    # NFT patterns
    if "ERC721" in contract_code or "ERC1155" in contract_code:
        return "nft"
    nft_keywords = ["tokenid", "ownerof(", "safetransferfrom", "mint(", "tokenuri"]
    if any(kw in code_lower for kw in nft_keywords):
        return "nft"

    # Token patterns
    if "ERC20" in contract_code:
        return "token"
    token_keywords = ["totalsupply", "balanceof(", "transfer(", "approve(", "allowance"]
    if any(kw in code_lower for kw in token_keywords):
        return "token"

    return "general"


def get_defi_knowledge() -> str:
    """Generate DeFi-specific knowledge section."""
    sections = ["DeFi Security Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in DEFI_VULNERABILITY_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Historical Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def get_governance_knowledge() -> str:
    """Generate governance-specific knowledge section."""
    sections = ["Governance Security Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in GOVERNANCE_VULNERABILITY_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        sections.append("")

    return "\n".join(sections)


def get_relevant_knowledge(contract_code: str) -> str:
    """
    Retrieve relevant knowledge based on contract code analysis.

    Enhanced to detect contract type and include specialized knowledge
    for DeFi, governance, NFT, and token contracts.

    Args:
        contract_code: Solidity contract source code

    Returns:
        Concatenated relevant knowledge sections
    """
    knowledge_sections = [SECURITY_BEST_PRACTICES]

    # Detect contract type for specialized context
    contract_type = detect_contract_type(contract_code)

    # Add type-specific knowledge
    if contract_type == "defi":
        knowledge_sections.append(get_defi_knowledge())

    if contract_type == "governance":
        knowledge_sections.append(get_governance_knowledge())

    # Detect ERC standards
    if "ERC20" in contract_code or any(
        func in contract_code for func in ["transfer(", "approve(", "transferFrom("]
    ):
        knowledge_sections.append(ERC20_KNOWLEDGE)

    if "ERC721" in contract_code or "tokenId" in contract_code or "ownerOf(" in contract_code:
        knowledge_sections.append(ERC721_KNOWLEDGE)

    if "ERC1155" in contract_code or "balanceOfBatch(" in contract_code:
        knowledge_sections.append(ERC1155_KNOWLEDGE)

    return "\n\n".join(knowledge_sections)


def get_vulnerability_context(vuln_type: str) -> dict:
    """
    Get detailed context about a specific vulnerability type.

    Searches across all vulnerability pattern dictionaries:
    - VULNERABILITY_PATTERNS (SWC-based)
    - DEFI_VULNERABILITY_PATTERNS
    - GOVERNANCE_VULNERABILITY_PATTERNS

    Args:
        vuln_type: Vulnerability identifier (e.g., 'reentrancy', 'flash_loan_attack')

    Returns:
        Detailed vulnerability information dictionary
    """
    # Normalize the type for lookup
    vuln_type_normalized = vuln_type.lower().replace("-", "_").replace(" ", "_")

    # Search in SWC patterns first
    if vuln_type_normalized in VULNERABILITY_PATTERNS:
        return VULNERABILITY_PATTERNS[vuln_type_normalized]

    # Search in DeFi patterns
    if vuln_type_normalized in DEFI_VULNERABILITY_PATTERNS:
        return DEFI_VULNERABILITY_PATTERNS[vuln_type_normalized]

    # Search in governance patterns
    if vuln_type_normalized in GOVERNANCE_VULNERABILITY_PATTERNS:
        return GOVERNANCE_VULNERABILITY_PATTERNS[vuln_type_normalized]

    # Fuzzy match: check if vuln_type is substring of any key
    all_patterns = {
        **VULNERABILITY_PATTERNS,
        **DEFI_VULNERABILITY_PATTERNS,
        **GOVERNANCE_VULNERABILITY_PATTERNS,
    }
    for key, value in all_patterns.items():
        if vuln_type_normalized in key or key in vuln_type_normalized:
            return value

    # Default response
    return {
        "description": "Unknown vulnerability type",
        "example": "N/A",
        "fix": "Review code for security issues",
        "severity": "MEDIUM",
    }


def get_all_vulnerability_patterns() -> dict:
    """
    Get all vulnerability patterns combined.

    Returns:
        Combined dictionary of all vulnerability patterns
    """
    return {
        **VULNERABILITY_PATTERNS,
        **DEFI_VULNERABILITY_PATTERNS,
        **GOVERNANCE_VULNERABILITY_PATTERNS,
    }
