// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/// @notice Interface for the Frax Ether Minter contract
/// @dev https://docs.frax.finance/frax-ether/overview
/// @dev https://github.com/FraxFinance/frxETH-public
interface IFrxETHMinter {
    /**
     * @dev Could try using EIP-712 / EIP-2612 here in the future if you replace this contract,
     *     but you might run into msg.sender vs tx.origin issues with the ERC4626
     */
    function submitAndDeposit(address recipient) external payable returns (uint256 shares);

    /// @notice Mint frxETH to the sender depending on the ETH value sent
    function submit() external payable;

    /// @notice Mint frxETH to the recipient using sender's funds
    function submitAndGive(address recipient) external payable;
}
