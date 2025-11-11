// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SafeToken
 * @notice SECURE ERC20-like token implementation for MIESC testing
 * @dev For MIESC testing purposes - This contract should produce MINIMAL findings
 *
 * Security Features Implemented:
 * - Proper access control with Ownable pattern
 * - Checks-Effects-Interactions pattern
 * - Safe arithmetic (Solidity 0.8+ automatic checks)
 * - Input validation and zero address checks
 * - Proper event emissions
 * - No unchecked external calls
 * - No delegatecall or selfdestruct
 *
 * Expected Detections:
 * - Slither: Should be mostly clean (maybe low-severity informational)
 * - Mythril: Should be clean
 * - Aderyn: Should be clean
 * - Manticore: No critical paths
 *
 * This serves as a CONTROL CONTRACT to validate that MIESC
 * correctly identifies secure code and doesn't produce false positives.
 */
contract SafeToken {
    // State variables
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) private allowances;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "SafeToken: caller is not the owner");
        _;
    }

    modifier validAddress(address addr) {
        require(addr != address(0), "SafeToken: zero address not allowed");
        _;
    }

    /**
     * @notice Constructor
     * @param _name Token name
     * @param _symbol Token symbol
     * @param _decimals Token decimals
     * @param _initialSupply Initial token supply
     */
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals,
        uint256 _initialSupply
    ) {
        require(bytes(_name).length > 0, "SafeToken: name cannot be empty");
        require(bytes(_symbol).length > 0, "SafeToken: symbol cannot be empty");

        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        owner = msg.sender;

        // Mint initial supply to owner
        if (_initialSupply > 0) {
            totalSupply = _initialSupply;
            balances[msg.sender] = _initialSupply;
            emit Transfer(address(0), msg.sender, _initialSupply);
        }
    }

    /**
     * @notice Get balance of account
     * @param account Address to query
     * @return uint256 Balance
     */
    function balanceOf(address account) external view validAddress(account) returns (uint256) {
        return balances[account];
    }

    /**
     * @notice Transfer tokens
     * @dev Follows Checks-Effects-Interactions pattern
     * @param to Recipient address
     * @param amount Amount to transfer
     * @return bool Success status
     */
    function transfer(address to, uint256 amount)
        external
        validAddress(to)
        returns (bool)
    {
        address from = msg.sender;

        // Checks
        require(balances[from] >= amount, "SafeToken: insufficient balance");
        require(amount > 0, "SafeToken: amount must be positive");

        // Effects (state changes before any external calls)
        balances[from] -= amount;
        balances[to] += amount;

        // Interactions (events)
        emit Transfer(from, to, amount);

        return true;
    }

    /**
     * @notice Approve spender
     * @param spender Address to approve
     * @param amount Amount to approve
     * @return bool Success status
     */
    function approve(address spender, uint256 amount)
        external
        validAddress(spender)
        returns (bool)
    {
        require(spender != msg.sender, "SafeToken: cannot approve self");

        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);

        return true;
    }

    /**
     * @notice Get allowance
     * @param tokenOwner Token owner address
     * @param spender Spender address
     * @return uint256 Allowance amount
     */
    function allowance(address tokenOwner, address spender)
        external
        view
        validAddress(tokenOwner)
        validAddress(spender)
        returns (uint256)
    {
        return allowances[tokenOwner][spender];
    }

    /**
     * @notice Transfer from approved account
     * @param from Source address
     * @param to Destination address
     * @param amount Amount to transfer
     * @return bool Success status
     */
    function transferFrom(address from, address to, uint256 amount)
        external
        validAddress(from)
        validAddress(to)
        returns (bool)
    {
        // Checks
        require(balances[from] >= amount, "SafeToken: insufficient balance");
        require(allowances[from][msg.sender] >= amount, "SafeToken: insufficient allowance");
        require(amount > 0, "SafeToken: amount must be positive");

        // Effects
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;

        // Interactions
        emit Transfer(from, to, amount);

        return true;
    }

    /**
     * @notice Mint new tokens (only owner)
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount)
        external
        onlyOwner
        validAddress(to)
    {
        require(amount > 0, "SafeToken: amount must be positive");

        totalSupply += amount;
        balances[to] += amount;

        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    /**
     * @notice Burn tokens
     * @param amount Amount to burn
     */
    function burn(uint256 amount) external {
        require(amount > 0, "SafeToken: amount must be positive");
        require(balances[msg.sender] >= amount, "SafeToken: insufficient balance");

        balances[msg.sender] -= amount;
        totalSupply -= amount;

        emit Burn(msg.sender, amount);
        emit Transfer(msg.sender, address(0), amount);
    }

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner)
        external
        onlyOwner
        validAddress(newOwner)
    {
        require(newOwner != owner, "SafeToken: same owner");

        address previousOwner = owner;
        owner = newOwner;

        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /**
     * @notice Renounce ownership (set owner to zero address with explicit warning)
     */
    function renounceOwnership() external onlyOwner {
        address previousOwner = owner;
        owner = address(0);
        emit OwnershipTransferred(previousOwner, address(0));
    }
}
