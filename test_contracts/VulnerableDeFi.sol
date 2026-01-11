// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableDeFi
 * @notice Example contract with multiple DeFi vulnerabilities for testing detectors
 * @dev DO NOT USE IN PRODUCTION - intentionally vulnerable for testing
 */
contract VulnerableDeFi {
    address public owner;
    address public router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D; // Hardcoded Uniswap router

    mapping(address => uint256) public balances;
    mapping(address => bool) public blacklisted;
    address[] public holders;

    bool public tradingEnabled = true;
    uint256 public fee = 5; // 5%

    event Swap(address indexed user, uint256 amount);
    event Mint(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // VULNERABILITY: Rug pull - owner can disable trading
    function disableTrading() external onlyOwner {
        tradingEnabled = false;
    }

    // VULNERABILITY: Rug pull - owner can blacklist anyone
    function blacklist(address user) external onlyOwner {
        blacklisted[user] = true;
    }

    // VULNERABILITY: Rug pull - fees can be set to 100%
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee; // No max limit!
    }

    // VULNERABILITY: Missing slippage protection
    function swapTokens(uint256 amount) external {
        require(tradingEnabled, "Trading disabled");
        require(!blacklisted[msg.sender], "Blacklisted");

        // No minAmountOut - vulnerable to sandwich attacks
        IRouter(router).swap(address(this), amount, 0); // 0 = no slippage protection!

        emit Swap(msg.sender, amount);
    }

    // VULNERABILITY: Unlimited minting without cap
    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        emit Mint(to, amount);
    }

    // VULNERABILITY: Unbounded loop - DoS risk
    function distributeRewards(uint256 amount) external onlyOwner {
        uint256 perHolder = amount / holders.length;
        for (uint256 i = 0; i < holders.length; i++) {
            balances[holders[i]] += perHolder;
        }
    }

    // VULNERABILITY: Weak randomness
    function lottery() external returns (uint256) {
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));
        return random % 100;
    }

    // VULNERABILITY: Timestamp dependence
    function isLocked() public view returns (bool) {
        return block.timestamp < 1700000000;
    }

    // VULNERABILITY: Approval race condition
    function approveSpender(address token, address spender, uint256 amount) external {
        IERC20(token).approve(spender, amount);
    }

    // VULNERABILITY: Dangerous delegatecall
    function execute(address target, bytes calldata data) external {
        // No validation of target!
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // VULNERABILITY: selfdestruct without proper protection
    function destroy() external {
        // Missing access control!
        selfdestruct(payable(msg.sender));
    }

    // VULNERABILITY: MEV vulnerable liquidation
    function liquidate(address user, uint256 amount) external {
        require(balances[user] >= amount, "Insufficient balance");
        balances[user] -= amount;
        balances[msg.sender] += amount;
    }

    // VULNERABILITY: Price check before swap (sandwichable)
    function arbitrage(address tokenA, address tokenB) external {
        uint256[] memory amounts = IRouter(router).getAmountsOut(1e18, getPath(tokenA, tokenB));
        if (amounts[1] > 1e18) {
            IRouter(router).swap(tokenA, 1e18, 0);
        }
    }

    function getPath(address a, address b) internal pure returns (address[] memory) {
        address[] memory path = new address[](2);
        path[0] = a;
        path[1] = b;
        return path;
    }
}

interface IRouter {
    function swap(address token, uint256 amount, uint256 minOut) external;
    function getAmountsOut(uint256 amountIn, address[] memory path) external view returns (uint256[] memory);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
