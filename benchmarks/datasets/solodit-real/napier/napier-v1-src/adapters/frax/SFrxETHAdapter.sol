// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IWETH9} from "../../interfaces/IWETH9.sol";
import {IERC4626} from "@openzeppelin/contracts@4.9.3/interfaces/IERC4626.sol";
import {IFrxETHMinter} from "./interfaces/IFrxETHMinter.sol";
import {IFraxEtherRedemptionQueue} from "./interfaces/IFraxEtherRedemptionQueue.sol";
import {IERC721Receiver} from "@openzeppelin/contracts@4.9.3/token/ERC721/IERC721Receiver.sol";

import {ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";
import {BaseLSTAdapter} from "../BaseLSTAdapter.sol";

import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import "../../Constants.sol" as Constants;

/// @title SFrxETHAdapter - esfrxETH
/// @dev Important security note:
/// 1. The vault share price (esfrxETH / WETH) increases as sfrxETH accrues staking rewards.
/// However, the share price decreases when frxETH (sfrxETH) is withdrawn.
/// Withdrawals are processed by the FraxEther redemption queue contract.
/// Frax takes a fee at the time of withdrawal requests, which temporarily reduces the share price.
/// This loss is pro-rated among all esfrxETH holders.
/// As a mitigation measure, we allow only authorized rebalancers to request withdrawals.
///
/// 2. This contract doesn't independently keep track of the sfrxETH balance, so it is possible
/// for an attacker to directly transfer sfrxETH to this contract, increase the share price.
contract SFrxETHAdapter is BaseLSTAdapter, IERC721Receiver {
    using SafeCast for uint256;

    error InvariantViolation();

    /// @notice frxETH
    IERC20 constant FRXETH = IERC20(Constants.FRXETH);

    /// @notice sfrxETH
    IERC4626 constant STAKED_FRXETH = IERC4626(Constants.STAKED_FRXETH);

    /// @dev FraxEther redemption queue contract https://etherscan.io/address/0x82bA8da44Cd5261762e629dd5c605b17715727bd
    IFraxEtherRedemptionQueue constant REDEMPTION_QUEUE =
        IFraxEtherRedemptionQueue(0x82bA8da44Cd5261762e629dd5c605b17715727bd);

    /// @dev FraxEther minter contract
    IFrxETHMinter constant FRXETH_MINTER = IFrxETHMinter(0xbAFA44EFE7901E04E39Dad13167D089C559c1138);

    receive() external payable {}

    constructor(address _rebalancer) BaseLSTAdapter(_rebalancer) ERC20("Napier FrxETH Adapter", "eFrxETH") {
        FRXETH.approve(address(STAKED_FRXETH), type(uint256).max);
        FRXETH.approve(address(REDEMPTION_QUEUE), type(uint256).max);
    }

    function claimWithdrawal() external override {
        uint256 _requestId = requestId;
        uint256 _withdrawalQueueEth = withdrawalQueueEth;
        if (_requestId == 0) revert NoPendingWithdrawal();

        /// WRITE ///
        delete withdrawalQueueEth;
        delete requestId;
        bufferEth += _withdrawalQueueEth.toUint128();

        /// INTERACT ///
        uint256 balanceBefore = address(this).balance;
        REDEMPTION_QUEUE.burnRedemptionTicketNft(_requestId, payable(this));
        if (address(this).balance < balanceBefore + _withdrawalQueueEth) revert InvariantViolation();

        IWETH9(Constants.WETH).deposit{value: _withdrawalQueueEth}();
    }

    /// @notice Mint sfrxETH using WETH
    function _stake(uint256 stakeAmount) internal override returns (uint256) {
        IWETH9(Constants.WETH).withdraw(stakeAmount);
        FRXETH_MINTER.submit{value: stakeAmount}();
        uint256 received = STAKED_FRXETH.deposit(stakeAmount, address(this));
        if (received == 0) revert InvariantViolation();

        return stakeAmount;
    }

    function requestWithdrawalAll() external override nonReentrant onlyRebalancer {
        if (requestId != 0) revert WithdrawalPending();
        uint256 _requestId = REDEMPTION_QUEUE.redemptionQueueState().nextNftId;
        /// INTERACT ///
        // Redeem all sfrxETH for frxETH
        uint256 balance = STAKED_FRXETH.balanceOf(address(this));
        uint256 withdrawAmount = STAKED_FRXETH.redeem(balance, address(this), address(this));

        REDEMPTION_QUEUE.enterRedemptionQueue({amountToRedeem: withdrawAmount.toUint120(), recipient: address(this)});

        /// WRITE ///
        withdrawalQueueEth = REDEMPTION_QUEUE.nftInformation(_requestId).amount; // cast uint120 to uint128
        requestId = _requestId;
    }

    /// @notice Request about `withdrawAmount` of ETH to be unstaked from sfrxETH.
    /// @param withdrawAmount Amount of ETH to withdraw
    function _requestWithdrawal(uint256 withdrawAmount) internal override returns (uint256, uint256) {
        uint256 _requestId = REDEMPTION_QUEUE.redemptionQueueState().nextNftId; // Dev: Ensure id is not 0
        /// INTERACT ///
        uint256 frxEthBalanceBefore = FRXETH.balanceOf(address(this)); // 0 is expected if no one has donated frxETH to this contract
        STAKED_FRXETH.withdraw(withdrawAmount, address(this), address(this));
        uint256 frxEthWithdrawn = FRXETH.balanceOf(address(this)) - frxEthBalanceBefore;
        // Transfer frxETH and mint redemption ticket.
        // note: `amountToRedeem` is an amount in frxETH, not ETH.
        // However, frxETH would be soft-pegged to ETH, so we treat them as 1:1 for simplicity here.
        // Also, actual ETH amount to withdraw would be slightly less than `withdrawAmount` due to the redemption fee.
        REDEMPTION_QUEUE.enterRedemptionQueue({amountToRedeem: frxEthWithdrawn.toUint120(), recipient: address(this)});
        /// WRITE ///
        // Note: The redemption queue contract returns the exact amount of ETH to withdraw.
        uint256 queueEth = REDEMPTION_QUEUE.nftInformation(_requestId).amount; // cast uint120 to uint128
        return (queueEth, _requestId);
    }

    function totalAssets() public view override returns (uint256) {
        uint256 balance = STAKED_FRXETH.balanceOf(address(this));
        uint256 balanceInFrxEth = STAKED_FRXETH.convertToAssets(balance);
        return withdrawalQueueEth + bufferEth + balanceInFrxEth; // 1 frxEth = 1 ETH
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return 0x150b7a02; // bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))
    }
}
