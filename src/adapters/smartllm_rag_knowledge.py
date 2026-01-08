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
3. Approval race condition (approve should check current allowance or use
   increaseAllowance/decreaseAllowance)
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
- safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts,
  bytes data): Batch transfer

REQUIRED EVENTS:
- TransferSingle(address indexed operator, address indexed from,
  address indexed to, uint256 id, uint256 value)
- TransferBatch(address indexed operator, address indexed from,
  address indexed to, uint256[] ids, uint256[] values)
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
        "example": (
            "balance[msg.sender] -= amount; "
            '(bool success,) = msg.sender.call{value: amount}("");'
        ),
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
        "fix": (
            "Add access control: function destroy() public onlyOwner. "
            "Consider removing selfdestruct."
        ),
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
        "attack_vector": (
            "Overflow causes unexpected large values, " "underflow causes near-max values"
        ),
    },
    "tx_origin": {
        "swc_id": "SWC-115",
        "description": "Using tx.origin for authorization instead of msg.sender",
        "example": "require(tx.origin == owner);",
        "fix": "Use msg.sender instead of tx.origin",
        "severity": "HIGH",
        "attack_vector": (
            "Phishing attack: user interacts with malicious contract " "that calls victim"
        ),
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
        "fix": (
            'Check return value: (bool success,) = recipient.call{value: amount}(""); '
            "require(success);"
        ),
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
        "fix": (
            "Use block.number or accept 15-second manipulation window. "
            "Use oracles for critical timing."
        ),
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
        "fix": (
            "Use time-weighted oracles (TWAP). Add flash loan guards. "
            "Check price deviation limits."
        ),
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
    "vault_inflation_attack": {
        "description": "First depositor can inflate vault shares via donation",
        "example": "Deposit 1 wei, donate 1M tokens, next depositor gets nothing",
        "fix": "Dead shares, minimum deposit, virtual offset (OpenZeppelin ERC-4626)",
        "severity": "CRITICAL",
        "attack_vector": "First depositor steals from subsequent depositors via share manipulation",
        "historical_exploits": ["Multiple ERC-4626 vaults 2023-2024"],
    },
    "interest_rate_manipulation": {
        "description": "Lending protocol interest rates can be manipulated",
        "example": "Flash loan to max utilization → spike interest → liquidate",
        "fix": "Smoothed interest rate curves, manipulation-resistant formulas",
        "severity": "HIGH",
        "attack_vector": "Attacker manipulates borrow rates to trigger liquidations",
    },
    "collateral_factor_exploit": {
        "description": "Incorrect collateral factor allows excessive borrowing",
        "example": "New asset added with 90% collateral factor before price stable",
        "fix": "Conservative initial collateral factors, gradual increase",
        "severity": "CRITICAL",
        "attack_vector": "Exploit high collateral factor before oracle price stabilizes",
        "historical_exploits": ["Mango Markets style attacks"],
    },
    "withdrawal_queue_griefing": {
        "description": "Attacker blocks legitimate withdrawals in queue",
        "example": "Many small withdrawal requests fill queue, blocking large users",
        "fix": "Prioritized queues, minimum withdrawal amounts, fee-based priority",
        "severity": "MEDIUM",
        "attack_vector": "DoS legitimate withdrawals via queue spam",
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
    for DeFi, governance, NFT, token, proxy, and cross-chain contracts.

    Research-grade RAG with 85+ vulnerability patterns from:
    - SWC Registry (complete coverage)
    - Certora formal verification invariants
    - OpenZeppelin security patterns
    - Trail of Bits audit findings
    - Rekt/Immunefi exploit database

    Args:
        contract_code: Solidity contract source code

    Returns:
        Concatenated relevant knowledge sections
    """
    knowledge_sections = [SECURITY_BEST_PRACTICES]

    # Detect contract type for specialized context
    contract_type = detect_contract_type(contract_code)
    code_lower = contract_code.lower()

    # Add type-specific knowledge
    if contract_type == "defi":
        knowledge_sections.append(get_defi_knowledge())

    if contract_type == "governance":
        knowledge_sections.append(get_governance_knowledge())

    # Always add advanced patterns for production-grade analysis
    knowledge_sections.append(get_advanced_knowledge())

    # Detect proxy/upgradeable patterns
    proxy_keywords = [
        "proxy",
        "upgradeable",
        "upgrade",
        "delegatecall",
        "implementation",
        "beacon",
        "initializable",
        "initialize(",
        "_implementation",
        "upgradeto",
        "uups",
        "transparent",
    ]
    if any(kw in code_lower for kw in proxy_keywords):
        knowledge_sections.append(_get_proxy_knowledge())

    # Detect cross-chain/bridge patterns
    bridge_keywords = [
        "bridge",
        "cross-chain",
        "crosschain",
        "layerzero",
        "chainlink ccip",
        "wormhole",
        "l1",
        "l2",
        "sequencer",
        "message",
        "messenger",
        "relayer",
    ]
    if any(kw in code_lower for kw in bridge_keywords):
        knowledge_sections.append(_get_cross_chain_knowledge())

    # Detect token-specific patterns
    token_keywords = [
        "fee on transfer",
        "rebase",
        "rebasing",
        "permit",
        "permit(",
        "eip2612",
        "erc777",
        "tokensreceived",
        "pausable",
        "blacklist",
    ]
    if any(kw in code_lower for kw in token_keywords):
        knowledge_sections.append(_get_token_knowledge())

    # Detect ERC-4337 Account Abstraction patterns
    aa_keywords = [
        "useroperation",
        "entrypoint",
        "validateuserop",
        "paymaster",
        "bundler",
        "account abstraction",
        "erc4337",
        "erc-4337",
        "iaccountexecute",
        "executefrombundler",
    ]
    if any(kw in code_lower for kw in aa_keywords):
        knowledge_sections.append(_get_account_abstraction_knowledge())

    # Detect Restaking patterns
    restaking_keywords = [
        "restake",
        "restaking",
        "eigenlayer",
        "symbiotic",
        "avs",
        "operator",
        "slashing",
        "withdrawal delay",
        "validator",
        "delegation",
    ]
    if any(kw in code_lower for kw in restaking_keywords):
        knowledge_sections.append(_get_restaking_knowledge())

    # Detect Intent-based patterns
    intent_keywords = [
        "intent",
        "solver",
        "filler",
        "cowswap",
        "1inch fusion",
        "uniswapx",
        "order",
        "settlement",
    ]
    if any(kw in code_lower for kw in intent_keywords):
        knowledge_sections.append(_get_intent_knowledge())

    # Detect L2-specific patterns
    l2_keywords = [
        "sequencer",
        "optimistic",
        "rollup",
        "l2",
        "layer2",
        "layer 2",
        "arbitrum",
        "optimism",
        "base",
        "forced inclusion",
        "state root",
        "fraud proof",
    ]
    if any(kw in code_lower for kw in l2_keywords):
        knowledge_sections.append(_get_l2_knowledge())

    # Detect MEV-related patterns
    mev_keywords = [
        "mev",
        "flashbot",
        "builder",
        "proposer",
        "jit",
        "sandwich",
        "backrun",
        "frontrun",
        "orderflow",
    ]
    if any(kw in code_lower for kw in mev_keywords):
        knowledge_sections.append(_get_mev_advanced_knowledge())

    # Detect ERC standards
    if "ERC20" in contract_code or any(
        func in contract_code for func in ["transfer(", "approve(", "transferFrom("]
    ):
        knowledge_sections.append(ERC20_KNOWLEDGE)

    if "ERC721" in contract_code or "tokenId" in contract_code or "ownerOf(" in contract_code:
        knowledge_sections.append(ERC721_KNOWLEDGE)

    if "ERC1155" in contract_code or "balanceOfBatch(" in contract_code:
        knowledge_sections.append(ERC1155_KNOWLEDGE)

    # Add formal invariants for high-value contracts
    if any(
        kw in code_lower
        for kw in ["vault", "pool", "lend", "borrow", "stake", "governance", "treasury"]
    ):
        knowledge_sections.append(get_formal_invariants())

    return "\n\n".join(knowledge_sections)


def _get_proxy_knowledge() -> str:
    """Generate proxy/upgradeability-specific knowledge section."""
    sections = ["Proxy & Upgradeability Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in PROXY_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def _get_cross_chain_knowledge() -> str:
    """Generate cross-chain/bridge-specific knowledge section."""
    sections = ["Cross-Chain & Bridge Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in CROSS_CHAIN_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def _get_token_knowledge() -> str:
    """Generate token-specific knowledge section."""
    sections = ["Token Mechanics & Edge Cases", "=" * 50, ""]

    for vuln_name, vuln_info in TOKEN_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def _get_account_abstraction_knowledge() -> str:
    """Generate ERC-4337 Account Abstraction knowledge section."""
    sections = ["ERC-4337 Account Abstraction Security", "=" * 50, ""]

    for vuln_name, vuln_info in ACCOUNT_ABSTRACTION_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def _get_restaking_knowledge() -> str:
    """Generate Restaking (EigenLayer, Symbiotic) knowledge section."""
    sections = ["Restaking Protocol Security (EigenLayer/Symbiotic)", "=" * 50, ""]

    for vuln_name, vuln_info in RESTAKING_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        sections.append("")

    return "\n".join(sections)


def _get_intent_knowledge() -> str:
    """Generate Intent-based transaction knowledge section."""
    sections = ["Intent-Based Transaction Security", "=" * 50, ""]

    for vuln_name, vuln_info in INTENT_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        sections.append("")

    return "\n".join(sections)


def _get_l2_knowledge() -> str:
    """Generate L2-specific vulnerability knowledge section."""
    sections = ["Layer 2 (L2) Specific Vulnerabilities", "=" * 50, ""]

    for vuln_name, vuln_info in L2_VULNERABILITIES.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        sections.append("")

    return "\n".join(sections)


def _get_mev_advanced_knowledge() -> str:
    """Generate advanced MEV knowledge section."""
    sections = ["Advanced MEV Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in MEV_ADVANCED_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        sections.append("")

    return "\n".join(sections)


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
        Combined dictionary of all vulnerability patterns (100+ patterns)
    """
    return {
        **VULNERABILITY_PATTERNS,
        **DEFI_VULNERABILITY_PATTERNS,
        **GOVERNANCE_VULNERABILITY_PATTERNS,
        **ADVANCED_VULNERABILITY_PATTERNS,
        **CROSS_CHAIN_PATTERNS,
        **PROXY_PATTERNS,
        **TOKEN_PATTERNS,
        **ACCOUNT_ABSTRACTION_PATTERNS,
        **RESTAKING_PATTERNS,
        **INTENT_PATTERNS,
        **L2_VULNERABILITIES,
        **MEV_ADVANCED_PATTERNS,
    }


# =============================================================================
# ADVANCED VULNERABILITY PATTERNS - Research Level (Certora/OpenZeppelin/ToB)
# =============================================================================
ADVANCED_VULNERABILITY_PATTERNS = {
    # ========== REENTRANCY VARIANTS ==========
    "read_only_reentrancy": {
        "swc_id": "SWC-107-RO",
        "description": "View functions read stale state during reentrancy attack",
        "example": "getPrice() reads pool reserves during callback before state update",
        "fix": "Use reentrancy locks on view functions that return state-dependent values",
        "severity": "HIGH",
        "attack_vector": "Attacker exploits price oracle reading during reentrancy callback",
        "historical_exploits": ["Sentiment ($1M)", "dForce ($3.6M)", "Sturdy Finance ($800K)"],
        "certora_invariant": "inv_no_state_change_during_external_call",
    },
    "cross_function_reentrancy": {
        "swc_id": "SWC-107-CF",
        "description": "Reentrancy between different functions sharing state",
        "example": "withdraw() reenters deposit() before balance update",
        "fix": "Global reentrancy lock or function-level locks with shared mutex",
        "severity": "CRITICAL",
        "attack_vector": "Callback invokes different function that reads uncommitted state",
        "certora_invariant": "rule_mutex_protects_all_state_modifying_functions",
    },
    "cross_contract_reentrancy": {
        "swc_id": "SWC-107-CC",
        "description": "Reentrancy across multiple contracts sharing state",
        "example": "TokenA.transfer() calls TokenB which reenters VaultA",
        "fix": "Cross-contract reentrancy guards or commit-then-execute pattern",
        "severity": "CRITICAL",
        "attack_vector": "Multi-hop callback chain exploits shared state across contracts",
        "historical_exploits": ["Curve/Vyper ($62M)", "Conic Finance ($3.2M)"],
    },
    # ========== PRECISION & ROUNDING ==========
    "precision_loss": {
        "swc_id": "SWC-101-PL",
        "description": "Division before multiplication causes precision loss",
        "example": "reward = (amount / total) * rate; // Should be amount * rate / total",
        "fix": "Multiply before divide. Use higher precision intermediates.",
        "severity": "MEDIUM",
        "attack_vector": "Attacker exploits rounding to extract more value than entitled",
        "certora_invariant": "property_precision_preserved(x * y / z >= (x / z) * y)",
    },
    "rounding_direction": {
        "swc_id": "SWC-101-RD",
        "description": "Rounding should favor protocol in all calculations",
        "example": "shares = assets / pricePerShare; // Should round down for deposits",
        "fix": "Round in protocol's favor: down for minting, up for burning",
        "severity": "MEDIUM",
        "attack_vector": "Repeated deposits/withdrawals extract value via favorable rounding",
        "certora_invariant": "rule_rounding_favors_protocol",
    },
    "first_depositor_attack": {
        "swc_id": "SWC-VAULT-1",
        "description": "First depositor can manipulate share price to steal from others",
        "example": "deposit 1 wei → donate 1M tokens → first depositor gets 99% of pool",
        "fix": "Virtual shares/assets, minimum deposit, or burn initial shares",
        "severity": "CRITICAL",
        "attack_vector": (
            "Attacker is first to deposit, inflates share value, " "steals from next depositors"
        ),
        "historical_exploits": ["Multiple ERC-4626 implementations"],
        "certora_invariant": "property_share_price_manipulation_resistant",
    },
    # ========== ACCESS CONTROL ADVANCED ==========
    "privilege_escalation": {
        "swc_id": "SWC-105-PE",
        "description": "User can gain unauthorized elevated privileges",
        "example": "Anyone can call grantRole() if DEFAULT_ADMIN_ROLE check missing",
        "fix": "Validate caller has required role. Use OpenZeppelin AccessControl.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker calls admin function without proper role check",
        "certora_invariant": "rule_only_admin_can_grant_roles",
    },
    "initialization_frontrun": {
        "swc_id": "SWC-INIT-1",
        "description": "Proxy initialize() can be frontrun to take ownership",
        "example": "Implementation deployed → attacker calls initialize() before owner",
        "fix": "Use initializer modifier. Initialize in same transaction as deploy.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker frontruns initialization to become owner",
        "historical_exploits": ["Wormhole ($320M)"],
    },
    "signature_malleability": {
        "swc_id": "SWC-117",
        "description": "ECDSA signatures can be manipulated to create valid variants",
        "example": "ecrecover accepts both (r, s) and (r, -s mod n)",
        "fix": "Use OpenZeppelin ECDSA library with s-value check",
        "severity": "HIGH",
        "attack_vector": "Attacker modifies valid signature to bypass nonce/hash checks",
    },
    "missing_access_control_internal": {
        "swc_id": "SWC-105-INT",
        "description": "Internal functions assumed safe but callable via public wrapper",
        "example": "public batchTransfer() calls _transfer() without validating array",
        "fix": "Validate all inputs even in internal functions called by public ones",
        "severity": "HIGH",
        "attack_vector": "Attacker exploits validation gap between public and internal functions",
    },
    # ========== ORACLE & PRICE MANIPULATION ==========
    "twap_manipulation": {
        "swc_id": "SWC-ORACLE-1",
        "description": "TWAP oracle can be manipulated over time with sustained pressure",
        "example": "Attacker maintains price manipulation across multiple blocks",
        "fix": "Use longer TWAP windows. Validate price deviation. Use multiple oracles.",
        "severity": "HIGH",
        "attack_vector": "Well-funded attacker sustains manipulation across TWAP window",
    },
    "stale_oracle_data": {
        "swc_id": "SWC-ORACLE-2",
        "description": "Oracle price data not checked for freshness",
        "example": "price = priceFeed.latestRoundData(); // No timestamp check",
        "fix": "Validate updatedAt within acceptable threshold. Check roundId sequence.",
        "severity": "HIGH",
        "attack_vector": "Using outdated prices during market volatility",
        "certora_invariant": "rule_oracle_data_fresh(updatedAt > block.timestamp - MAX_DELAY)",
    },
    "chainlink_sequencer_down": {
        "swc_id": "SWC-ORACLE-3",
        "description": "L2 sequencer down not checked before using Chainlink price",
        "example": "Using Chainlink on Arbitrum without sequencer uptime check",
        "fix": "Check sequencer uptime feed before using price data on L2s",
        "severity": "HIGH",
        "attack_vector": "Exploiting stale prices during L2 sequencer downtime",
    },
    # ========== MEMORY & STORAGE ==========
    "storage_collision": {
        "swc_id": "SWC-STORAGE-1",
        "description": "Proxy storage slots collide with implementation slots",
        "example": "Proxy uses slot 0 for admin, implementation uses slot 0 for balance",
        "fix": "Use EIP-1967 storage slots. Verify storage layout compatibility.",
        "severity": "CRITICAL",
        "attack_vector": "Upgrade overwrites critical storage slots",
        "certora_invariant": "rule_storage_slots_non_overlapping",
    },
    "dirty_storage_reads": {
        "swc_id": "SWC-STORAGE-2",
        "description": "Reading storage in loop without caching causes extra gas",
        "example": "for (uint i; i < array.length; i++) // Reads length each iteration",
        "fix": "Cache storage reads: uint len = array.length; for (uint i; i < len; i++)",
        "severity": "LOW",
        "attack_vector": "Gas griefing by forcing many storage reads",
    },
    "uninitialized_storage_pointer": {
        "swc_id": "SWC-109-USP",
        "description": "Local storage variable points to slot 0 by default",
        "example": "function f() { MyStruct storage s; s.value = 1; } // Overwrites slot 0",
        "fix": "Always initialize storage pointers. Use memory for temporary structs.",
        "severity": "CRITICAL",
        "attack_vector": "Overwrites owner or other critical state in slot 0",
    },
    # ========== CALLBACK & HOOK VULNERABILITIES ==========
    "callback_injection": {
        "swc_id": "SWC-CALLBACK-1",
        "description": "Untrusted contract can inject malicious callback",
        "example": "ERC721 safeTransferFrom to malicious receiver contract",
        "fix": "Limit callback gas. Use nonReentrant. Validate callback source.",
        "severity": "HIGH",
        "attack_vector": "Malicious receiver contract executes attack during callback",
    },
    "hook_manipulation": {
        "swc_id": "SWC-CALLBACK-2",
        "description": "Uniswap V4 style hooks can manipulate pool state",
        "example": "beforeSwap hook front-runs user by manipulating price",
        "fix": "Validate hook behavior. Use hook permissions carefully.",
        "severity": "HIGH",
        "attack_vector": "Malicious hook extracts value during swap",
    },
    # ========== GAS & DOS ADVANCED ==========
    "gas_griefing": {
        "swc_id": "SWC-126",
        "description": "Attacker wastes caller's gas without completing transaction",
        "example": "Forwarding all gas to untrusted contract that burns it",
        "fix": "Limit forwarded gas: addr.call{gas: 50000}(data)",
        "severity": "MEDIUM",
        "attack_vector": "Malicious contract consumes all forwarded gas",
    },
    "return_bomb": {
        "swc_id": "SWC-DOS-1",
        "description": "External call returns huge data causing OOG",
        "example": "(bool s,) = addr.call(data); // Copies all return data",
        "fix": "Limit return data: assembly { pop(call(...)) }",
        "severity": "MEDIUM",
        "attack_vector": "Malicious contract returns megabytes of data",
    },
    "phantom_function": {
        "swc_id": "SWC-DOS-2",
        "description": "Calling non-existent function on contract without fallback reverts",
        "example": "IERC20(notAToken).transfer(to, amt); // Reverts if not ERC20",
        "fix": "Validate contract code exists. Check interface support (ERC165).",
        "severity": "MEDIUM",
        "attack_vector": "DoS by setting token address to contract without transfer()",
    },
}

# =============================================================================
# CROSS-CHAIN & BRIDGE PATTERNS
# =============================================================================
CROSS_CHAIN_PATTERNS = {
    "bridge_message_replay": {
        "description": "Bridge message can be replayed on different chain or time",
        "example": "Message hash doesn't include chainId or nonce",
        "fix": "Include chainId, nonce, timestamp, sender in message hash",
        "severity": "CRITICAL",
        "attack_vector": "Attacker replays valid message to drain bridge on other chain",
        "historical_exploits": ["Ronin ($625M)", "BNB Bridge ($586M)", "Wormhole ($320M)"],
    },
    "bridge_signature_verification": {
        "description": "Insufficient validator signatures or weak threshold",
        "example": "Only 2-of-5 signatures required for billion-dollar bridge",
        "fix": "Use higher threshold (>2/3). Implement time delays for large transfers.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker compromises minimum validators to forge messages",
        "historical_exploits": ["Ronin ($625M)", "Harmony Horizon ($100M)"],
    },
    "l2_message_delay": {
        "description": "L1->L2 message delay not accounted for in logic",
        "example": "Governance on L1 executes before L2 receives warning",
        "fix": "Add sufficient delay for cross-L2 operations. Use L2 native governance.",
        "severity": "HIGH",
        "attack_vector": "Attacker exploits timing gap between L1 and L2",
    },
    "l2_sequencer_centralization": {
        "description": "L2 sequencer can censor or reorder transactions",
        "example": "Single sequencer can front-run all L2 transactions",
        "fix": "Use forced inclusion via L1. Design for sequencer liveness failures.",
        "severity": "MEDIUM",
        "attack_vector": "Sequencer extracts MEV or censors specific users",
    },
    "cross_chain_replay": {
        "description": "Same contract address on different chains leads to replay",
        "example": "Same CREATE2 address on mainnet and fork can be exploited",
        "fix": "Include chainId in all signatures. Use chain-specific deployment.",
        "severity": "HIGH",
        "attack_vector": "Attacker replays mainnet signatures on fork chain",
    },
}

# =============================================================================
# PROXY & UPGRADEABILITY PATTERNS
# =============================================================================
PROXY_PATTERNS = {
    "transparent_proxy_collision": {
        "description": "Admin functions clash with implementation functions",
        "example": "Both proxy and impl have transfer() - which is called?",
        "fix": "Use transparent proxy pattern correctly. Admin cannot call impl functions.",
        "severity": "HIGH",
        "attack_vector": "Attacker triggers wrong function via selector collision",
    },
    "uups_selfdestruct": {
        "description": "UUPS implementation can be selfdestructed directly",
        "example": "Attacker calls implementation.initialize() then selfdestruct",
        "fix": "Disable initialization on implementation. Add selfdestruct guard.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker destroys implementation, bricking all proxies",
        "historical_exploits": ["Wormhole exploit vector"],
    },
    "storage_gap_missing": {
        "description": "Upgradeable contract missing __gap for future variables",
        "example": "Adding new variable in V2 shifts storage layout",
        "fix": "Add uint256[50] __gap; at end of each contract",
        "severity": "HIGH",
        "attack_vector": "Upgrade corrupts storage layout",
        "certora_invariant": "rule_storage_layout_compatible",
    },
    "upgrade_to_malicious": {
        "description": "No validation on new implementation address",
        "example": "upgradeTo(address newImpl) without any checks",
        "fix": "Validate new impl has correct interface. Use timelock for upgrades.",
        "severity": "CRITICAL",
        "attack_vector": "Compromised admin upgrades to malicious implementation",
    },
    "beacon_proxy_takeover": {
        "description": "Beacon can be updated to point all proxies to malicious impl",
        "example": "Single beacon controls 1000 proxies - update affects all",
        "fix": "Strong access control on beacon. Multi-sig + timelock for updates.",
        "severity": "CRITICAL",
        "attack_vector": "Attacker takes over beacon, compromises all proxies at once",
    },
    "initializer_reentrancy": {
        "description": "Initializer can be reentered before isInitialized is set",
        "example": "External call in initializer before _initialized = true",
        "fix": "Set initialized flag at start. Use OpenZeppelin Initializable correctly.",
        "severity": "HIGH",
        "attack_vector": "Attacker reenters initializer to set themselves as owner",
    },
}

# =============================================================================
# TOKEN MECHANICS PATTERNS
# =============================================================================
# =============================================================================
# ERC-4337 ACCOUNT ABSTRACTION PATTERNS
# =============================================================================
ACCOUNT_ABSTRACTION_PATTERNS = {
    "aa_signature_replay": {
        "description": "UserOperation signature can be replayed across chains or accounts",
        "example": "UserOp signature doesn't include chainId or account address",
        "fix": "Include chainId, entryPoint address, and account in signature hash",
        "severity": "CRITICAL",
        "attack_vector": "Attacker replays valid UserOp on different chain/account",
    },
    "aa_bundler_dos": {
        "description": "Malicious UserOp can DoS bundler via gas griefing",
        "example": "validateUserOp consumes all gas without reverting",
        "fix": "Implement gas limits, use simulation before bundling",
        "severity": "HIGH",
        "attack_vector": "Attacker submits ops that waste bundler gas",
    },
    "aa_paymaster_drain": {
        "description": "Paymaster can be drained by malicious UserOps",
        "example": "Paymaster doesn't validate postOp consumption",
        "fix": "Strict gas accounting, whitelist users, rate limiting",
        "severity": "CRITICAL",
        "attack_vector": "Attacker submits expensive ops paid by paymaster",
        "historical_exploits": ["Multiple paymaster drains 2024"],
    },
    "aa_storage_collision_4337": {
        "description": "Account factory creates accounts with predictable storage",
        "example": "CREATE2 salt doesn't include owner, attacker pre-deploys",
        "fix": "Include owner in CREATE2 salt, verify account state post-deploy",
        "severity": "HIGH",
        "attack_vector": "Attacker deploys malicious account at expected address",
    },
    "aa_validation_bypass": {
        "description": "validateUserOp can be bypassed via specific calldata",
        "example": "Validation doesn't check all execution paths",
        "fix": "Comprehensive validation of all calldata combinations",
        "severity": "CRITICAL",
        "attack_vector": (
            "Attacker crafts UserOp that passes validation " "but executes malicious code"
        ),
    },
}

# =============================================================================
# RESTAKING PATTERNS (EigenLayer, Symbiotic, etc.)
# =============================================================================
RESTAKING_PATTERNS = {
    "slashing_manipulation": {
        "description": "Operator can manipulate slashing conditions",
        "example": "Slashing requires off-chain data that operator controls",
        "fix": "On-chain verifiable slashing conditions, multiple attesters",
        "severity": "CRITICAL",
        "attack_vector": "Operator avoids legitimate slashing or triggers false slashing",
        "historical_exploits": ["Theoretical - emerging pattern 2024"],
    },
    "restaking_withdrawal_delay": {
        "description": "Withdrawal delay can be exploited during market volatility",
        "example": "7-day withdrawal but price crashes in 2 days",
        "fix": "Dynamic withdrawal periods, partial instant withdrawals with fee",
        "severity": "HIGH",
        "attack_vector": "Attacker exploits price movements during forced delay",
    },
    "avs_registration_spam": {
        "description": "Operators can register for many AVS without actual stake",
        "example": "Same stake counted for multiple AVS registrations",
        "fix": "Stake allocation accounting, minimum unique stake per AVS",
        "severity": "MEDIUM",
        "attack_vector": "Operator inflates apparent security guarantees",
    },
    "restaking_correlation_risk": {
        "description": "Same validator set across multiple protocols creates systemic risk",
        "example": "Top 10 operators secure 80% of all restaked protocols",
        "fix": "Diversification requirements, correlated slashing limits",
        "severity": "HIGH",
        "attack_vector": "Compromise of few operators affects entire ecosystem",
    },
}

# =============================================================================
# INTENT-BASED TRANSACTION PATTERNS
# =============================================================================
INTENT_PATTERNS = {
    "intent_frontrunning": {
        "description": "Solver can extract value from user intent before fulfillment",
        "example": "User intends to swap, solver front-runs for better price",
        "fix": "Encrypted intents, MEV-protected submission, fair ordering",
        "severity": "HIGH",
        "attack_vector": "Solver extracts MEV from known user intentions",
    },
    "intent_partial_fill": {
        "description": "Solver partially fills intent, leaving user worse off",
        "example": "User wants 100 tokens, solver fills 1, charges full fee",
        "fix": "Minimum fill requirements, all-or-nothing options",
        "severity": "MEDIUM",
        "attack_vector": "Solver cherry-picks profitable partial fills",
    },
    "intent_signature_reuse": {
        "description": "Signed intent can be reused in different contexts",
        "example": "Intent signature doesn't expire or specify exact conditions",
        "fix": "Include deadline, nonce, exact parameters in signature",
        "severity": "HIGH",
        "attack_vector": "Solver replays intent when conditions favor them",
    },
}

# =============================================================================
# L2-SPECIFIC VULNERABILITIES
# =============================================================================
L2_VULNERABILITIES = {
    "sequencer_manipulation": {
        "description": "Sequencer can reorder, censor, or delay transactions",
        "example": "Sequencer front-runs all profitable DeFi transactions",
        "fix": "Forced inclusion via L1, shared sequencing, decentralized sequencer",
        "severity": "HIGH",
        "attack_vector": "Sequencer extracts MEV or censors specific users",
    },
    "l2_state_root_fraud": {
        "description": "Malicious state root submitted to L1 (optimistic rollups)",
        "example": "Sequencer submits invalid state root, no challenger notices",
        "fix": "Multiple independent challengers, fraud proof incentives",
        "severity": "CRITICAL",
        "attack_vector": "Malicious state root drains bridge if unchallenged",
    },
    "forced_inclusion_timing": {
        "description": "Forced L1->L2 inclusion has timing assumptions",
        "example": "Expecting 12 hours inclusion but sequencer delays 7 days",
        "fix": "Account for maximum forced inclusion delay in protocol design",
        "severity": "HIGH",
        "attack_vector": "Protocol assumes fast forced inclusion that doesn't happen",
    },
    "l2_gas_price_manipulation": {
        "description": "L2 gas prices can spike causing liquidation failures",
        "example": "L2 congestion prevents liquidation, protocol becomes insolvent",
        "fix": "L1 fallback liquidations, gas price caps, keeper incentives",
        "severity": "HIGH",
        "attack_vector": "Attacker spams L2 to prevent liquidations",
    },
}

# =============================================================================
# ADVANCED MEV PATTERNS
# =============================================================================
MEV_ADVANCED_PATTERNS = {
    "jit_liquidity": {
        "description": "Just-in-time liquidity added before large swap, removed after",
        "example": "MEV bot sees pending swap, adds LP, captures fees, removes",
        "fix": "Minimum LP duration, fee share with existing LPs",
        "severity": "MEDIUM",
        "attack_vector": "JIT LP extracts swap fees from legitimate LPs",
    },
    "backrunning_arbitrage": {
        "description": "MEV bot backruns large trades for risk-free arbitrage",
        "example": "Large swap moves price, bot immediately arbs back",
        "fix": "Price impact limits, batch auctions, MEV-share",
        "severity": "MEDIUM",
        "attack_vector": "Bot extracts value from every large trade",
    },
    "multi_block_mev": {
        "description": "Proposer controls multiple consecutive blocks for complex MEV",
        "example": "Proposer manipulates oracle over 2 blocks",
        "fix": "TWAP over more blocks, MEV-burn, inclusion lists",
        "severity": "HIGH",
        "attack_vector": "Block builder extracts multi-block MEV strategies",
    },
    "orderflow_auction_manipulation": {
        "description": "Private orderflow auctions can be manipulated",
        "example": "Builder has information advantage in MEV-Share auctions",
        "fix": "Encrypted orderflow, fair auction mechanisms",
        "severity": "HIGH",
        "attack_vector": "Builder extracts more than fair share of MEV",
    },
}

TOKEN_PATTERNS = {
    "fee_on_transfer": {
        "description": "Token takes fee on transfer, breaking assumptions",
        "example": "transfer(100) but recipient only gets 99 due to 1% fee",
        "fix": "Measure actual received: balanceAfter - balanceBefore",
        "severity": "MEDIUM",
        "attack_vector": "Accounting mismatch leads to insolvency or stuck funds",
    },
    "rebasing_token": {
        "description": "Token balance changes without transfers",
        "example": "stETH balance increases from rebasing, breaks share calculations",
        "fix": "Use wstETH (non-rebasing wrapper). Track shares not balances.",
        "severity": "MEDIUM",
        "attack_vector": "Protocol accounting diverges from actual token balances",
    },
    "pausable_token": {
        "description": "Token can be paused, blocking all protocol operations",
        "example": "USDC gets paused, protocol liquidations fail",
        "fix": "Handle transfer failures gracefully. Have emergency procedures.",
        "severity": "MEDIUM",
        "attack_vector": "Token pause causes protocol DoS or insolvency",
    },
    "blacklistable_token": {
        "description": "Token can blacklist addresses, blocking operations",
        "example": "USDC blacklists protocol address, funds stuck forever",
        "fix": "Avoid holding blacklistable tokens long-term. Use escape hatches.",
        "severity": "MEDIUM",
        "attack_vector": "Blacklist causes permanent fund loss",
    },
    "multiple_entry_points": {
        "description": "Token has multiple addresses that manipulate same balance",
        "example": "SNX has multiple entry points for same underlying",
        "fix": "Verify token has single canonical address. Check for proxies.",
        "severity": "HIGH",
        "attack_vector": "Attacker uses alternate entry to bypass protocol checks",
    },
    "permit_replay": {
        "description": "EIP-2612 permit can be replayed if nonce not incremented",
        "example": "permit() without incrementing nonce allows reuse",
        "fix": "Always increment nonce. Include deadline. Check signature validity.",
        "severity": "HIGH",
        "attack_vector": "Attacker replays permit to drain approved tokens",
    },
    "permit_deadline_ignored": {
        "description": "Permit deadline parameter ignored in verification",
        "example": "permit(owner, spender, value, deadline, v, r, s) ignores deadline",
        "fix": "Verify block.timestamp <= deadline in permit function",
        "severity": "MEDIUM",
        "attack_vector": "Old permits used after intended expiry",
    },
    "erc777_hook": {
        "description": "ERC-777 tokensReceived hook enables reentrancy",
        "example": "Protocol doesn't expect ERC-777, gets reentered on receive",
        "fix": "Use nonReentrant on token operations. Be aware of hook tokens.",
        "severity": "HIGH",
        "attack_vector": "Attacker uses ERC-777 token to reenter during transfer",
        "historical_exploits": ["imBTC ($300K)", "Multiple Uniswap V1 pools"],
    },
    "double_spending_permit": {
        "description": "Permit + transferFrom race condition",
        "example": "Permit sets allowance, old allowance not yet spent",
        "fix": "Use increaseAllowance pattern. Check current allowance.",
        "severity": "MEDIUM",
        "attack_vector": "Front-run permit to use old + new allowance",
    },
}


# =============================================================================
# FORMAL VERIFICATION INVARIANTS (Certora Style)
# =============================================================================
FORMAL_INVARIANTS = {
    # ========== GLOBAL STATE INVARIANTS ==========
    "total_supply_consistency": {
        "description": "Sum of all balances equals total supply",
        "invariant": "sum(balanceOf[u]) == totalSupply for all users u",
        "category": "accounting",
        "importance": "CRITICAL",
    },
    "no_free_tokens": {
        "description": "Tokens cannot be created from nothing",
        "invariant": "post.totalSupply <= pre.totalSupply + minted - burned",
        "category": "accounting",
        "importance": "CRITICAL",
    },
    "vault_solvency": {
        "description": "Vault can always pay out all shares",
        "invariant": "totalAssets >= convertToAssets(totalSupply)",
        "category": "solvency",
        "importance": "CRITICAL",
    },
    "share_price_lower_bound": {
        "description": "Share price never drops below initial ratio",
        "invariant": "totalAssets / totalSupply >= INITIAL_RATIO",
        "category": "solvency",
        "importance": "HIGH",
    },
    # ========== ACCESS CONTROL INVARIANTS ==========
    "owner_immutable_on_renounce": {
        "description": "After renouncing ownership, no one is owner",
        "invariant": "renounced => owner == address(0) forever",
        "category": "access_control",
        "importance": "HIGH",
    },
    "admin_role_protected": {
        "description": "Only admin can grant admin role",
        "invariant": "hasRole(ADMIN, x) changed => caller had ADMIN before",
        "category": "access_control",
        "importance": "CRITICAL",
    },
    # ========== STATE MACHINE INVARIANTS ==========
    "state_transitions_valid": {
        "description": "Contract only moves between valid states",
        "invariant": "state in {INITIAL, ACTIVE, PAUSED, FINALIZED}",
        "category": "state_machine",
        "importance": "HIGH",
    },
    "finalized_irreversible": {
        "description": "Once finalized, state cannot change",
        "invariant": "pre.state == FINALIZED => post.state == FINALIZED",
        "category": "state_machine",
        "importance": "HIGH",
    },
    # ========== REENTRANCY INVARIANTS ==========
    "no_state_change_during_callback": {
        "description": "Critical state unchanged during external calls",
        "invariant": "in_callback => (balance, owner, totalSupply unchanged)",
        "category": "reentrancy",
        "importance": "CRITICAL",
    },
    "effects_before_interactions": {
        "description": "All state changes happen before external calls",
        "invariant": "external_call => all_state_updates_complete",
        "category": "reentrancy",
        "importance": "CRITICAL",
    },
    # ========== ORACLE INVARIANTS ==========
    "price_bounded": {
        "description": "Price within reasonable bounds",
        "invariant": "MIN_PRICE <= getPrice() <= MAX_PRICE",
        "category": "oracle",
        "importance": "HIGH",
    },
    "price_deviation_limited": {
        "description": "Price cannot change more than X% in one block",
        "invariant": "abs(newPrice - oldPrice) / oldPrice <= MAX_DEVIATION",
        "category": "oracle",
        "importance": "HIGH",
    },
}


# =============================================================================
# REAL-WORLD EXPLOIT DATABASE (Rekt/Immunefi)
# =============================================================================
HISTORICAL_EXPLOITS = {
    # ========== 2024 EXPLOITS ==========
    "radiant_capital_2024": {
        "date": "2024-10-16",
        "amount": "$50M",
        "chain": "Arbitrum, BSC",
        "vulnerability": "Private key compromise",
        "description": "Attackers compromised 3 of 11 multisig signers via malware",
        "lesson": "Hardware wallets, airgapped signing, key rotation policies",
    },
    "curio_2024": {
        "date": "2024-03-24",
        "amount": "$16M",
        "chain": "Ethereum",
        "vulnerability": "Access control",
        "description": "Voting power manipulation via unlimited minting",
        "lesson": "Validate voting power calculations and minting caps",
    },
    # ========== 2023 EXPLOITS ==========
    "euler_finance_2023": {
        "date": "2023-03-13",
        "amount": "$197M",
        "chain": "Ethereum",
        "vulnerability": "Liquidation logic flaw",
        "description": "Donation attack + self-liquidation led to bad debt",
        "lesson": "Test liquidation edge cases extensively",
    },
    "curve_vyper_2023": {
        "date": "2023-07-30",
        "amount": "$62M",
        "chain": "Ethereum",
        "vulnerability": "Compiler bug (Vyper reentrancy lock)",
        "description": "Vyper 0.2.15-0.3.0 reentrancy guard was broken",
        "lesson": "Verify compiler versions. Use audited compiler versions.",
    },
    "multichain_2023": {
        "date": "2023-07-07",
        "amount": "$126M",
        "chain": "Multiple",
        "vulnerability": "Key compromise / insider",
        "description": "CEO's private keys compromised or insider theft",
        "lesson": "Decentralized key management, no single point of failure",
    },
    # ========== 2022 EXPLOITS ==========
    "ronin_bridge_2022": {
        "date": "2022-03-23",
        "amount": "$625M",
        "chain": "Ronin",
        "vulnerability": "Validator key compromise",
        "description": "5 of 9 validators compromised (4 Axie + 1 Axie DAO)",
        "lesson": "Sufficient validator set, key rotation, MPC",
    },
    "wormhole_2022": {
        "date": "2022-02-02",
        "amount": "$320M",
        "chain": "Solana",
        "vulnerability": "Signature verification bypass",
        "description": "Guardian signature verification could be bypassed",
        "lesson": "Audit bridge signature verification extensively",
    },
    "nomad_2022": {
        "date": "2022-08-02",
        "amount": "$190M",
        "chain": "Multiple",
        "vulnerability": "Message validation bypass",
        "description": "Anyone could forge valid bridge messages",
        "lesson": "Test all message validation paths",
    },
    "beanstalk_2022": {
        "date": "2022-04-17",
        "amount": "$182M",
        "chain": "Ethereum",
        "vulnerability": "Flash loan governance attack",
        "description": "Flash loaned governance tokens to pass malicious proposal",
        "lesson": "Snapshot voting, time delays, vote escrow",
    },
    # ========== 2021 EXPLOITS ==========
    "poly_network_2021": {
        "date": "2021-08-10",
        "amount": "$611M",
        "chain": "Multiple",
        "vulnerability": "Cross-chain message verification",
        "description": "Attacker could forge cross-chain keeper signatures",
        "lesson": "Validate cross-chain messages at all layers",
    },
    "cream_finance_2021": {
        "date": "2021-10-27",
        "amount": "$130M",
        "chain": "Ethereum",
        "vulnerability": "Price oracle manipulation + flash loan",
        "description": "yUSD price manipulated via flash loan",
        "lesson": "TWAP oracles, price deviation limits",
    },
    # ========== 2024/2025 EXPLOITS ==========
    "raft_2024": {
        "date": "2024-11-10",
        "amount": "$6.7M",
        "chain": "Ethereum",
        "vulnerability": "Precision loss rounding",
        "description": "Rounding error in interest calculation allowed profit extraction",
        "lesson": "Use higher precision, multiply before divide",
    },
    "socket_2024": {
        "date": "2024-01-16",
        "amount": "$3.3M",
        "chain": "Ethereum",
        "vulnerability": "Missing input validation",
        "description": "Arbitrary call data injection via bridge aggregator",
        "lesson": "Validate all external input, especially in aggregators",
    },
    "hedgey_2024": {
        "date": "2024-04-19",
        "amount": "$44M",
        "chain": "Ethereum, Arbitrum",
        "vulnerability": "Flash loan + approval manipulation",
        "description": "Token approval not revoked after claim, exploited via flash loan",
        "lesson": "Revoke approvals after use, implement time-locked claims",
    },
    "uwu_lend_2024": {
        "date": "2024-06-10",
        "amount": "$19.4M",
        "chain": "Ethereum",
        "vulnerability": "Oracle manipulation",
        "description": "Price oracle manipulated to liquidate healthy positions",
        "lesson": "Multiple oracle sources, deviation circuit breakers",
    },
}


def get_formal_invariants() -> str:
    """Generate formal invariants section for verification context."""
    sections = [
        "Formal Verification Invariants (Certora/Halmos Style)",
        "=" * 55,
        "",
    ]

    for inv_name, inv_info in FORMAL_INVARIANTS.items():
        sections.append(f"### {inv_name}")
        sections.append(f"Category: {inv_info['category']}")
        sections.append(f"Importance: {inv_info['importance']}")
        sections.append(f"Description: {inv_info['description']}")
        sections.append(f"Invariant: {inv_info['invariant']}")
        sections.append("")

    return "\n".join(sections)


def get_exploit_context(vulnerability_type: str) -> list:
    """
    Get relevant historical exploits for a vulnerability type.

    Args:
        vulnerability_type: Type of vulnerability (e.g., 'reentrancy', 'oracle')

    Returns:
        List of relevant historical exploit dictionaries
    """
    vuln_lower = vulnerability_type.lower()
    relevant = []

    # Keywords mapping
    vuln_keywords = {
        "reentrancy": ["reentrancy", "callback", "hook"],
        "oracle": ["oracle", "price", "manipulation", "twap"],
        "flash_loan": ["flash", "loan", "donation"],
        "governance": ["governance", "voting", "proposal", "flash loan governance"],
        "bridge": ["bridge", "cross-chain", "validator", "message"],
        "access_control": ["access", "key", "compromise", "admin"],
    }

    keywords = vuln_keywords.get(vuln_lower, [vuln_lower])

    for exploit_name, exploit_info in HISTORICAL_EXPLOITS.items():
        for kw in keywords:
            if (
                kw in exploit_info.get("vulnerability", "").lower()
                or kw in exploit_info.get("description", "").lower()
            ):
                relevant.append({**exploit_info, "name": exploit_name})
                break

    return relevant


def get_advanced_knowledge() -> str:
    """Generate advanced patterns section for RAG context."""
    sections = ["Advanced Vulnerability Patterns", "=" * 50, ""]

    for vuln_name, vuln_info in ADVANCED_VULNERABILITY_PATTERNS.items():
        sections.append(f"### {vuln_name.upper()}")
        sections.append(f"Severity: {vuln_info['severity']}")
        sections.append(f"Description: {vuln_info['description']}")
        sections.append(f"Attack Vector: {vuln_info['attack_vector']}")
        sections.append(f"Example: {vuln_info['example']}")
        sections.append(f"Fix: {vuln_info['fix']}")
        if "historical_exploits" in vuln_info:
            sections.append(f"Exploits: {', '.join(vuln_info['historical_exploits'])}")
        if "certora_invariant" in vuln_info:
            sections.append(f"Invariant: {vuln_info['certora_invariant']}")
        sections.append("")

    return "\n".join(sections)


def get_pattern_count() -> dict:
    """Get count of patterns by category."""
    return {
        "swc_patterns": len(VULNERABILITY_PATTERNS),
        "defi_patterns": len(DEFI_VULNERABILITY_PATTERNS),
        "governance_patterns": len(GOVERNANCE_VULNERABILITY_PATTERNS),
        "advanced_patterns": len(ADVANCED_VULNERABILITY_PATTERNS),
        "cross_chain_patterns": len(CROSS_CHAIN_PATTERNS),
        "proxy_patterns": len(PROXY_PATTERNS),
        "token_patterns": len(TOKEN_PATTERNS),
        "account_abstraction_patterns": len(ACCOUNT_ABSTRACTION_PATTERNS),
        "restaking_patterns": len(RESTAKING_PATTERNS),
        "intent_patterns": len(INTENT_PATTERNS),
        "l2_patterns": len(L2_VULNERABILITIES),
        "mev_advanced_patterns": len(MEV_ADVANCED_PATTERNS),
        "formal_invariants": len(FORMAL_INVARIANTS),
        "historical_exploits": len(HISTORICAL_EXPLOITS),
        "total": (
            len(VULNERABILITY_PATTERNS)
            + len(DEFI_VULNERABILITY_PATTERNS)
            + len(GOVERNANCE_VULNERABILITY_PATTERNS)
            + len(ADVANCED_VULNERABILITY_PATTERNS)
            + len(CROSS_CHAIN_PATTERNS)
            + len(PROXY_PATTERNS)
            + len(TOKEN_PATTERNS)
            + len(ACCOUNT_ABSTRACTION_PATTERNS)
            + len(RESTAKING_PATTERNS)
            + len(INTENT_PATTERNS)
            + len(L2_VULNERABILITIES)
            + len(MEV_ADVANCED_PATTERNS)
        ),
    }
