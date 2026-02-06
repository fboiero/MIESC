// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableLending
 * @notice A lending protocol with multiple vulnerabilities for RAG testing
 * @dev Contains: Oracle manipulation, flash loan, precision loss, missing validation
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract VulnerableLending {
    IERC20 public collateralToken;
    IERC20 public borrowToken;
    IUniswapV2Pair public pricePair;

    address public owner;

    mapping(address => uint256) public collateralDeposits;
    mapping(address => uint256) public borrowedAmounts;

    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    uint256 public totalBorrowed;

    event Deposit(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event Liquidate(address indexed user, address indexed liquidator);

    constructor(address _collateral, address _borrow, address _pricePair) {
        collateralToken = IERC20(_collateral);
        borrowToken = IERC20(_borrow);
        pricePair = IUniswapV2Pair(_pricePair);
        owner = msg.sender;
    }

    // VULNERABILITY 1: Oracle Manipulation
    // Uses spot price from AMM - easily manipulated with flash loans
    function getCollateralPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pricePair.getReserves();
        // Spot price calculation - VULNERABLE to manipulation
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralDeposits[msg.sender] += amount;
        emit Deposit(msg.sender, amount);
    }

    // VULNERABILITY 2: No flash loan protection
    // Attacker can manipulate price in same transaction
    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;

        require(borrowedAmounts[msg.sender] + amount <= maxBorrow, "Insufficient collateral");

        borrowedAmounts[msg.sender] += amount;
        totalBorrowed += amount;
        borrowToken.transfer(msg.sender, amount);

        emit Borrow(msg.sender, amount);
    }

    function getCollateralValue(address user) public view returns (uint256) {
        uint256 price = getCollateralPrice();
        // VULNERABILITY 3: Precision loss - divides before multiplying
        return (collateralDeposits[user] / 1e18) * price;
    }

    function repay(uint256 amount) external {
        require(borrowedAmounts[msg.sender] >= amount, "Repaying too much");
        borrowToken.transferFrom(msg.sender, address(this), amount);
        borrowedAmounts[msg.sender] -= amount;
        totalBorrowed -= amount;
        emit Repay(msg.sender, amount);
    }

    // VULNERABILITY 4: Liquidation uses manipulatable price
    function liquidate(address user) external {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debt = borrowedAmounts[user];

        // Check if undercollateralized (price can be manipulated!)
        require(collateralValue < (debt * COLLATERAL_RATIO) / 100, "Position healthy");

        // Transfer collateral to liquidator
        uint256 collateralAmount = collateralDeposits[user];
        collateralDeposits[user] = 0;
        borrowedAmounts[user] = 0;

        collateralToken.transfer(msg.sender, collateralAmount);
        emit Liquidate(user, msg.sender);
    }

    // VULNERABILITY 5: Missing zero address check
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;  // No zero address check!
    }

    // VULNERABILITY 6: Withdrawal without proper checks
    function emergencyWithdraw(address token) external {
        require(msg.sender == owner, "Not owner");
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(owner, balance);
    }
}

/**
 * KNOWN VULNERABILITIES:
 * 1. Oracle Manipulation (getCollateralPrice uses spot price)
 * 2. Flash Loan Attack Vector (no same-block protection)
 * 3. Precision Loss (getCollateralValue divides before multiplying)
 * 4. Price-dependent Liquidation (uses manipulatable price)
 * 5. Missing Zero Address Validation (setOwner)
 * 6. No timelock on admin functions (emergencyWithdraw)
 */
