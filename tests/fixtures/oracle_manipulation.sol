// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title OracleManipulationVulnerable
 * @dev Test contract with oracle manipulation vulnerabilities
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

contract OracleManipulationVulnerable {
    IUniswapV2Pair public pair;
    address public token0;
    address public token1;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    uint256 public constant COLLATERAL_RATIO = 150; // 150%

    event Borrow(address indexed user, uint256 amount);
    event Liquidation(address indexed user, address indexed liquidator);

    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
        token0 = pair.token0();
        token1 = pair.token1();
    }

    /**
     * @dev VULNERABLE: Spot price from AMM reserves
     * @notice Can be manipulated via flash loan or large swap
     */
    function getSpotPrice() public view returns (uint256) {
        // VULNERABILITY: Using spot reserves without TWAP
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();

        if (reserve1 == 0) return 0;

        // Price of token0 in terms of token1
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    /**
     * @dev VULNERABLE: Borrow based on manipulable spot price
     */
    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        // VULNERABILITY: Using spot price for collateral valuation
        uint256 price = getSpotPrice();
        uint256 collateralValue = (collateralAmount * price) / 1e18;

        require(
            collateralValue >= (borrowAmount * COLLATERAL_RATIO) / 100,
            "Insufficient collateral"
        );

        collateral[msg.sender] += collateralAmount;
        debt[msg.sender] += borrowAmount;

        emit Borrow(msg.sender, borrowAmount);
    }

    /**
     * @dev VULNERABLE: Liquidation based on spot price
     */
    function liquidate(address user) external {
        // VULNERABILITY: Attacker manipulates price to trigger unfair liquidations
        uint256 price = getSpotPrice();
        uint256 collateralValue = (collateral[user] * price) / 1e18;

        require(
            collateralValue < (debt[user] * COLLATERAL_RATIO) / 100,
            "Position is healthy"
        );

        // Liquidate the position
        uint256 userCollateral = collateral[user];
        collateral[user] = 0;
        debt[user] = 0;

        // Transfer collateral to liquidator (simplified)
        emit Liquidation(user, msg.sender);
    }

    /**
     * @dev VULNERABLE: Swap with spot price slippage check
     */
    function swap(uint256 amountIn, uint256 minAmountOut) external {
        // VULNERABILITY: minAmountOut calculated from manipulable spot price
        uint256 price = getSpotPrice();
        uint256 expectedOut = (amountIn * 1e18) / price;

        require(expectedOut >= minAmountOut, "Slippage too high");

        // ... swap logic
    }
}

/**
 * @title TwapOracle
 * @dev Example of safer TWAP-based oracle (for comparison)
 */
contract TwapOracle {
    IUniswapV2Pair public pair;

    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32 public blockTimestampLast;

    uint256 public price0Average;
    uint256 public price1Average;

    uint256 public constant PERIOD = 10 minutes;

    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
        (uint112 reserve0, uint112 reserve1, uint32 blockTimestamp) = pair.getReserves();
        require(reserve0 != 0 && reserve1 != 0, "No reserves");
        blockTimestampLast = blockTimestamp;
    }

    /**
     * @dev SAFER: Time-weighted average price
     * @notice More resistant to flash loan manipulation
     */
    function update() external {
        (uint112 reserve0, uint112 reserve1, uint32 blockTimestamp) = pair.getReserves();
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;

        require(timeElapsed >= PERIOD, "Period not elapsed");

        // Calculate cumulative prices (simplified)
        price0Average = (uint256(reserve1) * 1e18) / uint256(reserve0);
        price1Average = (uint256(reserve0) * 1e18) / uint256(reserve1);

        blockTimestampLast = blockTimestamp;
    }

    function consult() external view returns (uint256) {
        return price0Average;
    }
}
