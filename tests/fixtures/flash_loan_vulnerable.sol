// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FlashLoanVulnerable
 * @dev Test contract with flash loan attack vulnerabilities
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator
    ) external returns (bool);
}

contract FlashLoanVulnerable {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrowed;

    IERC20 public token;
    uint256 public totalDeposits;
    uint256 public exchangeRate = 1e18; // 1:1 initially

    // Price oracle (vulnerable to manipulation)
    address public priceOracle;

    event Deposit(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event FlashLoan(address indexed receiver, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /**
     * @dev VULNERABLE: Price calculated from spot reserves
     * @notice Attackers can manipulate price via flash loan
     */
    function getPrice() public view returns (uint256) {
        // VULNERABILITY: Using spot price from reserves
        // Flash loans can temporarily manipulate this
        if (totalDeposits == 0) return 1e18;
        return (token.balanceOf(address(this)) * 1e18) / totalDeposits;
    }

    /**
     * @dev VULNERABLE: Borrow based on manipulable price
     */
    function borrow(uint256 collateralAmount) external {
        // VULNERABILITY: Price can be manipulated before this call
        uint256 price = getPrice();
        uint256 borrowAmount = (collateralAmount * price) / 1e18;

        require(token.transferFrom(msg.sender, address(this), collateralAmount), "Transfer failed");
        deposits[msg.sender] += collateralAmount;
        borrowed[msg.sender] += borrowAmount;

        require(token.transfer(msg.sender, borrowAmount), "Borrow transfer failed");
        emit Borrow(msg.sender, borrowAmount);
    }

    /**
     * @dev VULNERABLE: Flash loan without proper accounting
     */
    function flashLoan(uint256 amount, address receiver) external {
        uint256 balanceBefore = token.balanceOf(address(this));

        require(token.transfer(receiver, amount), "Flash loan transfer failed");

        // VULNERABILITY: Callback can manipulate contract state
        IFlashLoanReceiver(receiver).executeOperation(
            address(token),
            amount,
            amount / 1000, // 0.1% fee
            msg.sender
        );

        uint256 balanceAfter = token.balanceOf(address(this));
        // VULNERABILITY: Simple balance check can be bypassed
        require(balanceAfter >= balanceBefore, "Flash loan not repaid");

        emit FlashLoan(receiver, amount);
    }

    /**
     * @dev VULNERABLE: Liquidation based on manipulable price
     */
    function liquidate(address user) external {
        // VULNERABILITY: Attacker can manipulate price to trigger liquidations
        uint256 price = getPrice();
        uint256 collateralValue = (deposits[user] * price) / 1e18;

        // If collateral < 150% of borrowed, allow liquidation
        require(collateralValue < (borrowed[user] * 150) / 100, "Not liquidatable");

        // Transfer collateral to liquidator
        uint256 collateral = deposits[user];
        deposits[user] = 0;
        borrowed[user] = 0;

        require(token.transfer(msg.sender, collateral), "Liquidation transfer failed");
    }

    /**
     * @dev Deposit tokens
     */
    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        deposits[msg.sender] += amount;
        totalDeposits += amount;
        emit Deposit(msg.sender, amount);
    }
}

/**
 * @title FlashLoanAttacker
 * @dev Example attacker contract
 */
contract FlashLoanAttacker is IFlashLoanReceiver {
    FlashLoanVulnerable public target;
    IERC20 public token;

    constructor(address _target, address _token) {
        target = FlashLoanVulnerable(_target);
        token = IERC20(_token);
    }

    function attack(uint256 flashAmount) external {
        // 1. Take flash loan
        target.flashLoan(flashAmount, address(this));
    }

    function executeOperation(
        address,
        uint256 amount,
        uint256 premium,
        address
    ) external override returns (bool) {
        // 2. Manipulate price by depositing flash loaned funds
        token.approve(address(target), amount);
        target.deposit(amount);

        // 3. Exploit manipulated price (borrow more than should be allowed)
        // ... attack logic here ...

        // 4. Repay flash loan
        token.transfer(address(target), amount + premium);

        return true;
    }
}
