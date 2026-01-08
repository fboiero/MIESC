// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FlashLoanVulnerable - Oracle Manipulation Pattern
 * @dev Common DeFi vulnerability pattern seen in many exploits
 * Examples: bZx, Harvest Finance, Warp Finance attacks
 */
contract FlashLoanVulnerable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Simple price oracle using pool reserves
    uint256 public reserveA;
    uint256 public reserveB;

    constructor() {
        reserveA = 1000 ether;
        reserveB = 1000 ether;
    }

    // VULNERABILITY: Price calculated from manipulable reserves
    function getPrice() public view returns (uint256) {
        // BUG: Using spot price from reserves
        // Can be manipulated within a single transaction
        return (reserveB * 1e18) / reserveA;
    }

    // VULNERABILITY: Using manipulable price for collateral
    function borrow(uint256 collateralAmount) public {
        // BUG: Price can be manipulated before this call
        uint256 price = getPrice();
        uint256 borrowAmount = (collateralAmount * price) / 1e18;

        // Transfer borrowed tokens
        balances[msg.sender] += borrowAmount;
        totalSupply += borrowAmount;
    }

    // Simulate swap that changes reserves
    function swap(uint256 amountAIn, uint256 amountBOut) public {
        reserveA += amountAIn;
        reserveB -= amountBOut;
    }
}

/**
 * @title ReentrancyWithFlashLoan
 * @dev Combined reentrancy + flash loan attack vector
 */
contract ReentrancyWithFlashLoan {
    mapping(address => uint256) public deposits;
    bool public locked;

    // VULNERABILITY: Reentrancy in flash loan callback
    function flashLoan(uint256 amount) public {
        uint256 balanceBefore = address(this).balance;

        // Send ETH to borrower
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        // BUG: Callback allows reentrancy before balance check
        // Attacker can call deposit() during callback

        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    // VULNERABILITY: Classic reentrancy
    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount);

        (bool success,) = msg.sender.call{value: amount}("");
        require(success);

        deposits[msg.sender] -= amount;
    }
}
