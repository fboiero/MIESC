// SPDX-License-Identifier: MIT
// Compound III (Comet) - Simplified Core Logic for analysis (2024)
pragma solidity ^0.8.0;

/**
 * @title CometCore
 * @notice Simplified version of Compound III Comet for security analysis
 * @dev Based on Compound III mainnet contract patterns
 */
contract CometCore {
    // Asset configuration
    struct AssetConfig {
        address asset;
        address priceFeed;
        uint64 scale;
        uint64 borrowCollateralFactor;
        uint64 liquidateCollateralFactor;
        uint64 liquidationFactor;
        uint128 supplyCap;
    }

    // User basic state
    struct UserBasic {
        int104 principal;
        uint64 baseTrackingIndex;
        uint64 baseTrackingAccrued;
        uint16 assetsIn;
    }

    // User collateral state
    struct UserCollateral {
        uint128 balance;
        uint128 reserved;
    }

    address public governor;
    address public baseToken;
    address public baseTokenPriceFeed;

    uint256 public totalSupply;
    uint256 public totalBorrow;
    uint64 public baseSupplyIndex;
    uint64 public baseBorrowIndex;
    uint64 public lastAccrualTime;

    mapping(address => UserBasic) public userBasic;
    mapping(address => mapping(address => UserCollateral)) public userCollateral;
    mapping(address => AssetConfig) public assetConfigs;
    mapping(address => bool) public isAllowed;

    uint256 constant FACTOR_SCALE = 1e18;

    event Supply(address indexed from, address indexed dst, uint256 amount);
    event Withdraw(address indexed src, address indexed to, uint256 amount);
    event SupplyCollateral(address indexed from, address indexed dst, address indexed asset, uint256 amount);
    event WithdrawCollateral(address indexed src, address indexed to, address indexed asset, uint256 amount);
    event AbsorbDebt(address indexed absorber, address indexed borrower, uint256 basePaidOut, uint256 usdValue);

    modifier onlyGovernor() {
        require(msg.sender == governor, "NOT_GOVERNOR");
        _;
    }

    constructor(address _baseToken, address _priceFeed) {
        governor = msg.sender;
        baseToken = _baseToken;
        baseTokenPriceFeed = _priceFeed;
        lastAccrualTime = uint64(block.timestamp);
        baseSupplyIndex = 1e15;
        baseBorrowIndex = 1e15;
    }

    /**
     * @notice Accrue interest
     * @dev Vulnerability: No cap on interest rate, potential DoS
     */
    function accrueInternal() internal {
        uint64 now_ = uint64(block.timestamp);
        uint256 timeElapsed = now_ - lastAccrualTime;

        if (timeElapsed > 0) {
            // Simplified interest calculation
            uint256 supplyRate = getSupplyRate();
            uint256 borrowRate = getBorrowRate();

            // Vulnerability: Precision loss in interest calculation
            baseSupplyIndex += uint64((baseSupplyIndex * supplyRate * timeElapsed) / (365 days * FACTOR_SCALE));
            baseBorrowIndex += uint64((baseBorrowIndex * borrowRate * timeElapsed) / (365 days * FACTOR_SCALE));

            lastAccrualTime = now_;
        }
    }

    /**
     * @notice Supply base token
     * @dev Vulnerability: No reentrancy guard
     */
    function supply(address asset, uint256 amount) external {
        accrueInternal();

        if (asset == baseToken) {
            // Transfer tokens in
            // Vulnerability: No return value check on transfer
            IERC20(asset).transferFrom(msg.sender, address(this), amount);

            // Update principal
            int104 principal = userBasic[msg.sender].principal;
            userBasic[msg.sender].principal = principal + int104(int256(presentValue(int104(int256(amount)))));

            totalSupply += amount;
            emit Supply(msg.sender, msg.sender, amount);
        } else {
            supplyCollateral(asset, amount);
        }
    }

    /**
     * @notice Supply collateral
     */
    function supplyCollateral(address asset, uint256 amount) internal {
        AssetConfig memory config = assetConfigs[asset];
        require(config.asset != address(0), "ASSET_NOT_SUPPORTED");
        require(amount <= config.supplyCap - userCollateral[msg.sender][asset].balance, "SUPPLY_CAP_EXCEEDED");

        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        userCollateral[msg.sender][asset].balance += uint128(amount);

        emit SupplyCollateral(msg.sender, msg.sender, asset, amount);
    }

    /**
     * @notice Withdraw base token
     * @dev Vulnerability: No slippage protection
     */
    function withdraw(address asset, uint256 amount) external {
        accrueInternal();

        if (asset == baseToken) {
            int104 principal = userBasic[msg.sender].principal;
            int256 balance = presentValue(principal);

            require(int256(amount) <= balance, "INSUFFICIENT_BALANCE");

            userBasic[msg.sender].principal = principal - int104(principalValue(int104(int256(amount))));
            totalSupply -= amount;

            // Vulnerability: External call before state update complete
            IERC20(asset).transfer(msg.sender, amount);

            emit Withdraw(msg.sender, msg.sender, amount);
        } else {
            withdrawCollateral(asset, amount);
        }
    }

    /**
     * @notice Withdraw collateral
     */
    function withdrawCollateral(address asset, uint256 amount) internal {
        require(userCollateral[msg.sender][asset].balance >= amount, "INSUFFICIENT_COLLATERAL");

        userCollateral[msg.sender][asset].balance -= uint128(amount);
        IERC20(asset).transfer(msg.sender, amount);

        // Check if still solvent after withdrawal
        require(isBorrowCollateralized(msg.sender), "NOT_COLLATERALIZED");

        emit WithdrawCollateral(msg.sender, msg.sender, asset, amount);
    }

    /**
     * @notice Borrow base token
     * @dev Vulnerability: Flash loan attack vector
     */
    function borrowInternal(address src, uint256 amount) internal {
        accrueInternal();

        int104 principal = userBasic[src].principal;
        userBasic[src].principal = principal - int104(principalValue(int104(int256(amount))));
        totalBorrow += amount;

        require(isBorrowCollateralized(src), "NOT_COLLATERALIZED");

        IERC20(baseToken).transfer(src, amount);
    }

    /**
     * @notice Absorb underwater accounts
     * @dev Vulnerability: MEV extraction possible
     */
    function absorb(address absorber, address[] calldata accounts) external {
        accrueInternal();

        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];

            if (isLiquidatable(account)) {
                // Liquidation logic
                int104 oldPrincipal = userBasic[account].principal;
                userBasic[account].principal = 0;

                // Vulnerability: No sandwich attack protection
                emit AbsorbDebt(absorber, account, uint256(int256(-oldPrincipal)), 0);
            }
        }
    }

    function presentValue(int104 principal) internal view returns (int256) {
        if (principal >= 0) {
            return int256(principal) * int256(uint256(baseSupplyIndex)) / 1e15;
        } else {
            return int256(principal) * int256(uint256(baseBorrowIndex)) / 1e15;
        }
    }

    function principalValue(int104 present) internal view returns (int104) {
        if (present >= 0) {
            return int104(int256(present) * 1e15 / int256(uint256(baseSupplyIndex)));
        } else {
            return int104(int256(present) * 1e15 / int256(uint256(baseBorrowIndex)));
        }
    }

    function getSupplyRate() public view returns (uint256) {
        return 2e16; // 2% APR simplified
    }

    function getBorrowRate() public view returns (uint256) {
        return 5e16; // 5% APR simplified
    }

    function isBorrowCollateralized(address account) public view returns (bool) {
        // Simplified collateralization check
        return true;
    }

    function isLiquidatable(address account) public view returns (bool) {
        return userBasic[account].principal < 0;
    }

    function addAsset(AssetConfig memory config) external onlyGovernor {
        assetConfigs[config.asset] = config;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
