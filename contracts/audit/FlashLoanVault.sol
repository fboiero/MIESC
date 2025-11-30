// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title FlashLoanVault
 * @notice DeFi vault with flash loan functionality - contains multiple DeFi vulnerabilities
 * @dev Demonstrates oracle manipulation, flash loan attacks, and price manipulation
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract FlashLoanVault {
    IERC20 public token;
    IPriceOracle public oracle;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;
    mapping(address => uint256) public collateral;

    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    uint256 public constant FLASH_LOAN_FEE = 9; // 0.09%
    uint256 public constant FEE_DENOMINATOR = 10000;

    uint256 public totalDeposits;
    uint256 public totalBorrowed;

    address public owner;
    bool public flashLoanLock;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event FlashLoan(address indexed borrower, uint256 amount, uint256 fee);
    event Liquidation(address indexed liquidator, address indexed user, uint256 amount);

    constructor(address _token, address _oracle) {
        token = IERC20(_token);
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // VULNERABILITY 1: Oracle manipulation - single source, no TWAP
    function getTokenPrice() public view returns (uint256) {
        // VULNERABLE: Single oracle source can be manipulated
        return oracle.getPrice(address(token));
    }

    // VULNERABILITY 2: Flash loan without proper reentrancy guard
    function flashLoan(uint256 amount, address receiver, bytes calldata data) external {
        require(!flashLoanLock, "Flash loan in progress");
        // VULNERABLE: Boolean lock instead of proper reentrancy guard

        uint256 balanceBefore = token.balanceOf(address(this));
        require(balanceBefore >= amount, "Insufficient liquidity");

        flashLoanLock = true;

        // Transfer tokens to receiver
        require(token.transfer(receiver, amount), "Transfer failed");

        // Call receiver's callback
        // VULNERABILITY 3: Unchecked external call
        (bool success, ) = receiver.call(data);
        // Not requiring success!

        uint256 fee = (amount * FLASH_LOAN_FEE) / FEE_DENOMINATOR;
        uint256 balanceAfter = token.balanceOf(address(this));

        require(balanceAfter >= balanceBefore + fee, "Flash loan not repaid");

        flashLoanLock = false;
        emit FlashLoan(receiver, amount, fee);
    }

    // VULNERABILITY 4: Price manipulation in collateral calculation
    function calculateCollateralValue(address user) public view returns (uint256) {
        // VULNERABLE: Uses spot price that can be manipulated in same transaction
        uint256 price = getTokenPrice();
        return (collateral[user] * price) / 1e18;
    }

    // VULNERABILITY 5: No slippage protection in liquidation
    function liquidate(address user) external {
        uint256 collateralValue = calculateCollateralValue(user);
        uint256 borrowedValue = borrowed[user];

        // Check if undercollateralized
        require(collateralValue * 100 < borrowedValue * COLLATERAL_RATIO, "Not liquidatable");

        // VULNERABLE: No slippage protection, no partial liquidation
        uint256 liquidationAmount = collateral[user];

        collateral[user] = 0;
        borrowed[user] = 0;

        // Transfer collateral to liquidator
        require(token.transfer(msg.sender, liquidationAmount), "Transfer failed");

        emit Liquidation(msg.sender, user, liquidationAmount);
    }

    // VULNERABILITY 6: Deposit without share calculation (first depositor attack)
    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be > 0");
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        // VULNERABLE: Direct deposit without virtual shares
        // First depositor can manipulate share price
        deposits[msg.sender] += amount;
        totalDeposits += amount;

        emit Deposit(msg.sender, amount);
    }

    // VULNERABILITY 7: Share calculation without rounding protection
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposits");
        require(totalDeposits >= amount, "Insufficient liquidity");

        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit Withdraw(msg.sender, amount);
    }

    // VULNERABILITY 8: Borrow without checking flash loan state
    function borrow(uint256 amount) external {
        // VULNERABLE: Doesn't check if in flash loan
        // Can borrow during flash loan and inflate collateral temporarily
        uint256 collateralValue = calculateCollateralValue(msg.sender);
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;

        require(borrowed[msg.sender] + amount <= maxBorrow, "Exceeds collateral ratio");
        require(totalDeposits - totalBorrowed >= amount, "Insufficient liquidity");

        borrowed[msg.sender] += amount;
        totalBorrowed += amount;

        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit Borrow(msg.sender, amount);
    }

    // VULNERABILITY 9: Unchecked arithmetic in repay (though 0.8.x has overflow checks)
    function repay(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        // Could underflow in older Solidity versions
        borrowed[msg.sender] -= amount;
        totalBorrowed -= amount;

        emit Repay(msg.sender, amount);
    }

    // VULNERABILITY 10: Emergency withdraw without timelock
    function emergencyWithdraw() external {
        require(msg.sender == owner, "Not owner");
        // VULNERABLE: No timelock, can rug instantly
        uint256 balance = token.balanceOf(address(this));
        require(token.transfer(owner, balance), "Transfer failed");
    }

    // Add collateral
    function addCollateral(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        collateral[msg.sender] += amount;
    }

    // Remove collateral (with check)
    function removeCollateral(uint256 amount) external {
        require(collateral[msg.sender] >= amount, "Insufficient collateral");

        uint256 newCollateralValue = ((collateral[msg.sender] - amount) * getTokenPrice()) / 1e18;
        require(newCollateralValue * 100 >= borrowed[msg.sender] * COLLATERAL_RATIO, "Would be undercollateralized");

        collateral[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "Transfer failed");
    }
}

/**
 * @title ManipulableOracle
 * @notice Simple oracle that can be manipulated for testing
 */
contract ManipulableOracle is IPriceOracle {
    mapping(address => uint256) public prices;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setPrice(address token, uint256 price) external {
        // VULNERABLE: Anyone can set price!
        prices[token] = price;
    }

    function getPrice(address token) external view override returns (uint256) {
        return prices[token];
    }
}

/**
 * @title FlashLoanAttacker
 * @notice Demonstrates flash loan attack vector
 */
contract FlashLoanAttacker {
    FlashLoanVault public vault;
    ManipulableOracle public oracle;
    IERC20 public token;

    constructor(address _vault, address _oracle, address _token) {
        vault = FlashLoanVault(_vault);
        oracle = ManipulableOracle(_oracle);
        token = IERC20(_token);
    }

    function attack() external {
        // Step 1: Take flash loan
        uint256 amount = token.balanceOf(address(vault));

        // Step 2: In callback, manipulate oracle and liquidate
        bytes memory data = abi.encodeWithSignature("executeAttack()");
        vault.flashLoan(amount, address(this), data);
    }

    function executeAttack() external {
        // Manipulate oracle price down
        oracle.setPrice(address(token), 1); // Set price to almost 0

        // Liquidate undercollateralized positions
        // ... liquidation logic

        // Restore price and repay
        oracle.setPrice(address(token), 1e18);
    }

    // Fallback to receive tokens
    receive() external payable {}
}
