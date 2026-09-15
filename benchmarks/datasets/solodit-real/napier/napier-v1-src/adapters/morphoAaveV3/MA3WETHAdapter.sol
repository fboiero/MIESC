// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IWETH9} from "../../interfaces/IWETH9.sol";
import {IMa3WETH} from "./interfaces/IMa3WETH.sol";
import {IMorpho} from "./interfaces/IMorpho.sol";
import {IRewardsDistributor} from "./interfaces/IRewardsDistributor.sol";
// libs
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";
import {BaseAdapter, IBaseAdapter} from "../../BaseAdapter.sol";
import {WETH, MA3WETH, MORPHO_AAVE_V3, AWETH} from "../../Constants.sol";

/// @notice Morpho Aave V3 WETH adapter
/// https://developers-aavev3.morpho.org/src/extensions/SupplyVault.sol/contract.SupplyVault.html
contract MA3WETHAdapter is BaseAdapter, ERC20 {
    using SafeERC20 for IWETH9;
    using SafeERC20 for IERC20;

    /// @notice reward recipient
    address public rewardRecipient;

    /// -----------------------------------------------------------------------
    /// immutables
    /// -----------------------------------------------------------------------

    IRewardsDistributor public immutable morphoRewardsDistributor;

    /// -----------------------------------------------------------------------
    /// Constants
    /// -----------------------------------------------------------------------

    uint256 internal constant ONE_MA3WETH = 1e18;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event RewardClaimed(address[] rewardAddress, uint256[] amount);

    constructor(
        address _rewardRecipient,
        address _morphoRewardsDistributor
    ) BaseAdapter(WETH, address(this)) ERC20("Wrapped MA3WETH", "WMA3WETH") {
        rewardRecipient = _rewardRecipient;
        morphoRewardsDistributor = IRewardsDistributor(_morphoRewardsDistributor);
        IERC20(WETH).forceApprove(MA3WETH, type(uint256).max);
    }

    /// @inheritdoc IBaseAdapter
    function prefundedDeposit() external override returns (uint256, uint256) {
        uint256 uBal = IERC20(WETH).balanceOf(address(this));
        if (uBal == 0) {
            return (0, 0);
        }
        uint256 sharesMinted = IMa3WETH(MA3WETH).deposit(uBal, address(this));
        // mint same shares as MA3WETH minted
        _mint(msg.sender, sharesMinted);
        return (uBal, sharesMinted);
    }

    /// @inheritdoc IBaseAdapter
    function prefundedRedeem(address to) external override returns (uint256, uint256) {
        uint256 tBal = balanceOf(address(this));
        if (tBal == 0) {
            return (0, 0);
        }
        uint256 assetsRedeemed = IMa3WETH(MA3WETH).redeem(tBal, to, address(this));
        // burn shares
        _burn(address(this), tBal);
        return (assetsRedeemed, tBal);
    }

    function claimMorpho(uint256 claimable, bytes32[] memory proof) public {
        morphoRewardsDistributor.claim(address(this), claimable, proof);
    }

    function claimRewards() public {
        address[] memory assets = new address[](1);
        assets[0] = AWETH;
        (address[] memory rewardsList, uint256[] memory claimedAmounts) = IMorpho(MORPHO_AAVE_V3).claimRewards(
            assets,
            rewardRecipient
        );
        emit RewardClaimed(rewardsList, claimedAmounts);
    }

    /// @dev only owner can change reward recipient
    /// @param _newRecipient Note Be careful. can be zero address
    function changeRewardRecipient(address _newRecipient) public onlyOwner {
        rewardRecipient = _newRecipient;
    }

    /// @inheritdoc IBaseAdapter
    function scale() public view override returns (uint256) {
        return IMa3WETH(MA3WETH).convertToAssets(ONE_MA3WETH);
    }

    ///@notice MA3WETH has 18 decimals
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}
