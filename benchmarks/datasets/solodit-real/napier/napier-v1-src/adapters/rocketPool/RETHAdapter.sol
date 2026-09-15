// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IWETH9} from "../../interfaces/IWETH9.sol";
import {IBaseAdapter} from "../../interfaces/IBaseAdapter.sol";
import {IRocketStorage} from "./interfaces/IRocketStorage.sol";
import {IRocketDepositPool} from "./interfaces/IRocketDepositPool.sol";
import {IRocketTokenRETH as IRocketETH} from "./interfaces/IRocketTokenRETH.sol";
// libs
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";

import {RETH, WETH} from "../../Constants.sol";
import {BaseAdapter} from "../../BaseAdapter.sol";

contract RETHAdapter is BaseAdapter {
    using SafeERC20 for IRocketETH;
    using SafeERC20 for IWETH9;

    /// @notice Rocket Pool Deposit Pool key
    bytes32 immutable ROCKET_DEPOSIT_POOL_KEY = keccak256(abi.encodePacked("contract.address", "rocketDepositPool"));

    /// @notice registry contract address
    IRocketStorage immutable rocketStorage;

    error OnlyWETHOrRETH();
    error SendETHFailed();

    /// @notice _rocketStorageAddress is the address of the RocketStorage contract
    constructor(address _rocketStorageAddress) BaseAdapter(WETH, RETH) {
        rocketStorage = IRocketStorage(_rocketStorageAddress);
    }

    receive() external payable {
        // WETH or rETH contract can send ETH
        // though it is possible to forcefully send ETH to this contract
        if (msg.sender != WETH && msg.sender != RETH) {
            revert OnlyWETHOrRETH();
        }
    }

    /// @inheritdoc IBaseAdapter
    /// @notice deposit Underlying in return for Target.
    /// @dev NOTE: This may fail if the deposit amount is too small to be accepted by Rocket Pool.
    /// Rocket Pool requires a minimum deposit of some amount of ETH.
    /// Rocket Pool takes deposit fees from the deposit amount.
    /// If the deposit amount is too large and deposit cap is reached, Rocket Pool will reject the deposit.
    /// See IRocketDAOProtocolSettingsDeposit.sol for more details.
    /// https://github.com/rocket-pool/rocketpool/blob/9710596d82189c54f0dc35be3501cda13a155f4d/contracts/contract/deposit/RocketDepositPool.sol#L119
    /// @return underlyingUsed The amount of underlying used
    /// @return sharesMinted The amount of shares minted
    function prefundedDeposit() external override returns (uint256, uint256) {
        uint256 wethBal = IWETH9(WETH).balanceOf(address(this));
        // Return early if zero balance
        if (wethBal == 0) {
            return (0, 0);
        }
        // Unwrap WETH to ETH
        IWETH9(WETH).withdraw(wethBal);
        // Forward deposit to RP & get amount of rETH minted
        uint256 rethbalBefore = IRocketETH(RETH).balanceOf(address(this));
        IRocketDepositPool rocketDepositPool = IRocketDepositPool(rocketStorage.getAddress(ROCKET_DEPOSIT_POOL_KEY));
        // Deposit ETH to Rocket Pool
        // check: slither "arbitrary-send-eth"
        rocketDepositPool.deposit{value: wethBal}();
        uint256 sharesMinted = IRocketETH(RETH).balanceOf(address(this)) - rethbalBefore;

        IRocketETH(RETH).safeTransfer(msg.sender, sharesMinted);

        return (wethBal, sharesMinted);
    }

    /// @inheritdoc IBaseAdapter
    /// @notice redeem Target and receive Underlying in return.
    /// @dev NOTE: This may fail if Rocket Pool does not have enough ETH to burn rETH.
    /// Error: "Insufficient ETH balance for exchange"
    /// If this happens, users should try again later after Rocket Pool has unstaked more ETH.
    /// Until then, redeeming rETH for ETH is not possible.
    /// @param to recipient of Underlying
    /// @return underlyingWithdrawn amount of Underlying returned
    /// @return sharesRedeemed amount of Target redeemed
    function prefundedRedeem(address to) external override returns (uint256, uint256) {
        // Load contracts
        uint256 rethBal = IRocketETH(RETH).balanceOf(address(this));
        if (rethBal == 0) {
            return (0, 0);
        }
        // Burn rETH for ETH
        IRocketETH(RETH).burn(rethBal);
        // Wrap ETH to WETH
        uint256 ethValue = address(this).balance;
        IWETH9(WETH).deposit{value: ethValue}();
        // Transfer WETH to recipient
        IWETH9(WETH).safeTransfer(to, ethValue);

        return (ethValue, rethBal);
    }

    /// @notice Recover ETH from contract
    /// @dev However ETH is swept at the time of `prefundedRedeem` call
    /// Warning: Can be front-run
    /// @param to recipient of ETH (zero-check is NOT performed)
    function recoverETH(address to) external onlyOwner {
        uint256 amount = address(this).balance;
        (bool success, ) = to.call{value: amount}("");
        if (!success) {
            revert SendETHFailed();
        }
    }

    /// @inheritdoc IBaseAdapter
    function scale() public view override returns (uint256) {
        return IRocketETH(RETH).getExchangeRate();
    }
}
