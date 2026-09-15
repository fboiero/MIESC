// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";
import {IWETH9} from "../../interfaces/IWETH9.sol";
import {ICETHToken} from "./interfaces/ICETHToken.sol";
import {ICToken} from "./interfaces/ICToken.sol";
import {IComptroller} from "./interfaces/IComptroller.sol";
import {IBaseAdapter} from "../../interfaces/IBaseAdapter.sol";
// libs
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {WETH, CETH, COMPTROLLER, COMP} from "../../Constants.sol";
import {FixedPointMathLib} from "src/utils/FixedPointMathLib.sol";
// inherits
import {CompoundV2BaseAdapter} from "./CompoundV2BaseAdapter.sol";

/// @dev This Adapter itself is tokenized as ERC20 token and represents CETH positions
/// because Tranche itself can't claim COMP token distributed as reward to depositors and borrowers.
/// This wrapper holds CETH, which makes it possible for adapter to accrue COMP instead of Tranche.
/// Tranche of this adapter returns WrappedCETHAdapter token when Tranche.target() is called.
contract WrappedCETHAdapter is ERC20, CompoundV2BaseAdapter {
    using SafeERC20 for IWETH9;
    using SafeERC20 for IERC20;
    using FixedPointMathLib for uint256;

    /// @notice COMP reward recipient
    address public rewardRecipient;

    event ClaimRewards(uint256 amount);

    /// @notice Initialize the adapter for the underlying asset
    /// @dev `underlying` token is WETH
    /// @dev `target` token is this contract itself instead of CETH
    constructor(address _rewardRecipient) CompoundV2BaseAdapter(WETH, address(this)) ERC20("Wrapped CETH", "WCETH") {
        rewardRecipient = _rewardRecipient;
    }

    receive() external payable {}

    /// @inheritdoc IBaseAdapter
    function prefundedDeposit() external override returns (uint256, uint256) {
        uint256 uBal = IERC20(underlying).balanceOf(address(this));
        if (uBal == 0) {
            return (0, 0);
        }
        IWETH9(WETH).withdraw(uBal); // unwrap WETH into ETH

        uint256 tBalBefore = IERC20(CETH).balanceOf(address(this));
        // mint CETH in Cether
        // check: slither "arbitrary-send-eth"
        // if mint failed, revert inside of mint(). CEther.mint() does not return any value.
        ICETHToken(CETH).mint{value: uBal}();
        uint256 tBalAfter = IERC20(CETH).balanceOf(address(this));
        uint256 sharesMinted = tBalAfter - tBalBefore;
        // mint same shares as CETH minted
        _mint(msg.sender, sharesMinted);
        return (uBal, sharesMinted);
    }

    /// @inheritdoc IBaseAdapter
    function prefundedRedeem(address to) external override returns (uint256, uint256) {
        uint256 tBal = balanceOf(address(this));
        if (tBal == 0) {
            return (0, 0);
        }
        // redeem CETH
        uint256 uBalBefore = address(this).balance;
        if (ICToken(CETH).redeem(tBal) != 0) revert RedeemFailed();
        uint256 uBalAfter = address(this).balance;
        uint256 uBal;
        unchecked {
            uBal = uBalAfter - uBalBefore;
        }
        // burn shares
        _burn(address(this), tBal);
        // transfer WETH to recipient
        IWETH9(WETH).deposit{value: uBal}();
        IWETH9(WETH).safeTransfer(to, uBal);
        return (uBal, tBal);
    }

    function scale() external view override returns (uint256) {
        return viewExchangeRate(ICToken(CETH));
    }

    /// @notice Claim COMP reward and send it to recipient.
    /// @dev Anyone can call this function
    function claimRewards() public override {
        address[] memory holders = new address[](1);
        holders[0] = address(this);
        address[] memory cTokens = new address[](1);
        cTokens[0] = CETH;
        IComptroller(COMPTROLLER).claimComp(holders, cTokens, false, true); // 4th parameter should be true.
        uint256 amount = IERC20(COMP).balanceOf(address(this));
        IERC20(COMP).safeTransfer(rewardRecipient, amount);
        emit ClaimRewards(amount);
    }

    /// @dev only owner can change reward recipient
    /// @param _newRecipient Note Be careful. can be zero address
    function changeRewardRecipient(address _newRecipient) public onlyOwner {
        rewardRecipient = _newRecipient;
    }

    /// @notice CETH has 8 decimals
    function decimals() public pure override returns (uint8) {
        return 8;
    }
}
