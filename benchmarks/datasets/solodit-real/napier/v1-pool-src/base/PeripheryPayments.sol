// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
// libraries
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {Errors} from "../libs/Errors.sol";
// inherits
import {PeripheryImmutableState} from "./PeripheryImmutableState.sol";

/// @notice Payments utility contract for periphery contracts
/// @dev Taken and modified from Uniswap v3 periphery PeripheryPayments: https://github.com/Uniswap/v3-periphery/blob/main/contracts/base/PeripheryPayments.sol
abstract contract PeripheryPayments is PeripheryImmutableState {
    using SafeERC20 for IERC20;

    receive() external payable {
        if (msg.sender != address(WETH9)) revert Errors.NotWETH();
    }

    /// @notice Unwraps the contract's WETH9 balance and sends it to recipient as ETH.
    /// @dev The amountMinimum parameter prevents malicious contracts from stealing WETH9 from users.
    /// @notice Unwrap WETH9 and send to recipient
    /// @param amountMinimum The minimum amount of WETH9 to unwrap
    /// @param recipient The entity that will receive the ether
    function unwrapWETH9(uint256 amountMinimum, address recipient) external payable {
        uint256 balanceWETH9 = WETH9.balanceOf(address(this));
        if (balanceWETH9 < amountMinimum) revert Errors.RouterInsufficientWETH();

        if (balanceWETH9 > 0) {
            WETH9.withdraw(balanceWETH9);
            _safeTransferETH(recipient, balanceWETH9);
        }
    }

    /// @notice Transfers the full amount of a token held by this contract to recipient
    /// @dev The amountMinimum parameter prevents malicious contracts from stealing the token from users
    /// @param token The contract address of the token which will be transferred to `recipient`
    /// @param amountMinimum The minimum amount of token required for a transfer
    /// @param recipient The destination address of the token
    function sweepToken(address token, uint256 amountMinimum, address recipient) public payable {
        uint256 balanceToken = IERC20(token).balanceOf(address(this));
        if (balanceToken < amountMinimum) revert Errors.RouterInsufficientTokenBalance();

        if (balanceToken > 0) {
            IERC20(token).safeTransfer(recipient, balanceToken);
        }
    }

    /// @notice Transfers the full amount of multiple tokens held by this contract to recipient
    /// @dev Batched version of `sweepToken`
    function sweepTokens(address[] calldata tokens, uint256[] calldata amountMinimums, address recipient)
        external
        payable
    {
        require(tokens.length == amountMinimums.length);
        for (uint256 i; i < tokens.length;) {
            // Not caching length saves gas in this case.
            sweepToken(tokens[i], amountMinimums[i], recipient);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Refund ether to sender
    function refundETH() external payable {
        if (address(this).balance > 0) _safeTransferETH(msg.sender, address(this).balance);
    }

    /// @notice transfer ether safely
    function _safeTransferETH(address to, uint256 value) internal {
        (bool success,) = to.call{value: value}(new bytes(0));
        if (!success) revert Errors.FailedToSendEther();
    }

    /// @dev Pay with token or WEH9 if the contract has enough ether
    /// @param token The token to pay
    /// @param payer The entity that must pay
    /// @param recipient The entity that will receive payment
    /// @param value The amount to pay
    function _pay(address token, address payer, address recipient, uint256 value) internal {
        if (token == address(WETH9) && address(this).balance >= value) {
            // pay with WETH9
            WETH9.deposit{value: value}(); // wrap only what is needed to pay
            WETH9.transfer(recipient, value);
        } else if (payer == address(this)) {
            IERC20(token).safeTransfer(recipient, value);
        } else {
            // pull payment

            // note: Check value sent to this contract is zero if token is WETH9
            // Corner case: A situation where the `msg.value` sent is not enough to satisfy `address(this).balance >= value`.
            // In such conditions, if we wouldn't revert, `IERC20(WETH).safeTransferFrom(payer, recipient, value)` will be executed,
            // and the `msg.value` will remain in the Router, potentially allowing the attacker to claim it.
            // This is why we ensure that the `msg.value` is zero for pulling WETH.

            // note: NapierRouter inherits from PeripheryPayments and Multicallable.
            // Basically, using `msg.value` in a loop can be dangerous but in this case, `msg.value` is not used for accounting purposes.
            if (token == address(WETH9) && msg.value > 0) revert Errors.RouterInconsistentWETHPayment();
            IERC20(token).safeTransferFrom(payer, recipient, value);
        }
    }
}
