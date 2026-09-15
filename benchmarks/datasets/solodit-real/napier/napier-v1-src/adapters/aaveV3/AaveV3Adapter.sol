// SPDX-License-Identifier: AGPL-3.0
pragma solidity 0.8.19;

import {IWETH9} from "../../interfaces/IWETH9.sol";
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IPool} from "./interfaces/IPool.sol";
import {ILendingPoolAddressesProvider} from "./interfaces/ILendingPoolAddressesProvider.sol";
import {IRewardsController} from "./interfaces/IRewardsController.sol";

import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {AAVEV3_POOL_ADDRESSES_PROVIDER} from "../../Constants.sol";
import {BaseAdapter, IBaseAdapter} from "../../BaseAdapter.sol";
import {ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/ERC4626.sol";

/// @title AaveV3Adapter
/// @author Mauro Liu
/// @notice aTokens are interest-bearing tokens that represent a user's share in a specific
/// asset deposited into the Aave protocol.
/// Tranche doesn't support elastic supply tokens like aToken because Tranche stores accumulated fee in storage variable but balances of aTokens
/// held by users increase as they earn interest on their deposited assets.
/// AaveV3Adapter introduced wrapping aToken as target by using ERC4626.
/// @dev AaveV3Adapter is NOT compatible with EIP4626 standard. We don't expect it to be used by other contracts other than Tranche.
contract AaveV3Adapter is ERC4626, BaseAdapter {
    /// -----------------------------------------------------------------------
    /// Libraries usage
    /// -----------------------------------------------------------------------

    using SafeERC20 for IWETH9;
    using SafeERC20 for IERC20;

    /// @notice The address that will receive the liquidity mining rewards (if any)
    address public rewardRecipient;

    /// -----------------------------------------------------------------------
    /// Immutable params
    /// -----------------------------------------------------------------------

    /// @notice The Aave aToken contract
    IERC20 public immutable aToken;

    /// @notice The Aave Pool contract
    IPool public immutable lendingPool;

    /// @notice The Aave RewardsController contract
    IRewardsController public immutable rewardsController;

    /// -----------------------------------------------------------------------
    /// Constants
    /// -----------------------------------------------------------------------

    uint256 internal constant ONE_WRAPPED_ATOKEN = 1e18;

    //events
    event RewardClaimed(address[] rewardAddress, uint256[] amount);

    //errors
    error NotImplemented();

    constructor(
        address asset_,
        address aToken_,
        address rewardRecipient_,
        address rewardsController_
    )
        BaseAdapter(asset_, address(this))
        ERC4626(IERC20(asset_))
        ERC20(
            string.concat("ERC4626-Wrapped Aave v3 ", ERC20(asset_).symbol()),
            string.concat("wa", ERC20(asset_).symbol())
        )
    {
        aToken = IERC20(aToken_);
        /// Retrieve LendingPool address
        lendingPool = IPool(ILendingPoolAddressesProvider(AAVEV3_POOL_ADDRESSES_PROVIDER).getPool());
        rewardRecipient = rewardRecipient_;
        rewardsController = IRewardsController(rewardsController_);
    }

    /// @inheritdoc IBaseAdapter
    function prefundedDeposit() external override returns (uint256, uint256) {
        uint256 assets = IERC20(underlying).balanceOf(address(this));
        uint256 shares = previewDeposit(assets);
        if (assets == 0) {
            return (0, 0);
        }

        // Check for rounding error since we round down in previewDeposit.
        require(shares != 0, "ZERO_SHARES");

        _mint(msg.sender, shares);

        // approve to lendingPool
        IERC20(underlying).forceApprove(address(lendingPool), assets);

        // deposit into lendingPool
        lendingPool.supply(underlying, assets, address(this), 0);

        return (assets, shares);
    }

    /// @inheritdoc IBaseAdapter
    function prefundedRedeem(address to) external override returns (uint256, uint256) {
        uint256 shares = balanceOf(address(this));
        uint256 assets = previewRedeem(shares);
        if (shares == 0) {
            return (0, 0);
        }

        // Check for rounding error since we round down in previewRedeem.
        require(assets != 0, "ZERO_ASSETS");

        _burn(address(this), shares);
        // withdraw assets directly from Aave
        lendingPool.withdraw(asset(), assets, to);
        return (assets, shares);
    }

    /// @notice Claims liquidity mining rewards from Aave and sends it to rewardRecipient
    function claimRewards() external {
        address[] memory assets = new address[](1);
        assets[0] = address(aToken);
        (address[] memory rewardsList, uint256[] memory claimedAmounts) = rewardsController.claimAllRewards(
            assets,
            rewardRecipient
        );
        emit RewardClaimed(rewardsList, claimedAmounts);
    }

    /// @inheritdoc IBaseAdapter
    function scale() external view override returns (uint256) {
        return convertToAssets(ONE_WRAPPED_ATOKEN);
    }

    /// @dev only owner can change reward recipient
    /// @param _newRecipient Note Be careful. can be zero address
    function changeRewardRecipient(address _newRecipient) public onlyOwner {
        rewardRecipient = _newRecipient;
    }

    /// @notice direct deposit,mint,redeem,withdraw should be reverted.
    function deposit(uint256, address) public virtual override returns (uint256) {
        revert NotImplemented();
    }

    function mint(uint256, address) public virtual override returns (uint256) {
        revert NotImplemented();
    }

    function withdraw(uint256, address, address) public virtual override returns (uint256) {
        revert NotImplemented();
    }

    function redeem(uint256, address, address) public virtual override returns (uint256) {
        revert NotImplemented();
    }

    function totalAssets() public view virtual override returns (uint256) {
        // aTokens use rebasing to accrue interest, so the total assets is just the aToken balance
        return aToken.balanceOf(address(this));
    }
}
