// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/// @title Tranche Router Interface
/// @notice Tranche router provides a single entry point for issuing and redeeming PT and YT.
interface ITrancheRouter {
    /// @notice Deposit `underlyingAmount` of underlying token and receive PT and YT.
    /// @dev Accepts native ETH.
    /// @param adapter The adapter to deposit to
    /// @param maturity The maturity of the tranche
    /// @param underlyingAmount The amount of underlying token to deposit
    /// @param recipient The address that will receive PT and YT
    /// @return principalAmount The amount of PT and YT issued
    function issue(address adapter, uint256 maturity, uint256 underlyingAmount, address recipient)
        external
        payable
        returns (uint256 principalAmount);

    /// @notice Withdraws underlying token from the caller in exchange for `pyAmount` of PT and YT.
    /// @dev If caller wants to withdraw ETH, specify `recipient` as this contract's address and use `unwrapWETH9` with Multicall.
    /// @param adapter The adapter of the tranche
    /// @param maturity The maturity of the tranche
    /// @param pyAmount The amount of principal token (and yield token) to redeem in units of underlying token
    /// @param recipient The address designated to receive the redeemed underlying token
    /// @return The amount of underlying token redeemed
    function redeemWithYT(address adapter, uint256 maturity, uint256 pyAmount, address recipient)
        external
        returns (uint256);

    /// @notice Redeems underlying token in exchange for `principalAmount` of PT.
    /// @dev If caller wants to withdraw ETH, specify `recipient` as this contract's address and use `unwrapWETH9` with Multicall.
    /// @param adapter The adapter of the tranche
    /// @param maturity The maturity of the tranche
    /// @param principalAmount The amount of principal token to redeem in units of underlying token
    /// @param recipient The address that will receive the redeemed underlying token
    /// @return The amount of underlying token redeemed
    function redeem(address adapter, uint256 maturity, uint256 principalAmount, address recipient)
        external
        returns (uint256);

    /// @notice Withdraws underlying token in exchange for `underlyingAmount`.
    /// @dev If caller wants to withdraw ETH, specify `recipient` as this contract's address and use `unwrapWETH9` with Multicall.
    /// @param adapter The adapter of the tranche
    /// @param maturity The maturity of the tranche
    /// @param underlyingAmount The amount of underlying token to redeem in units of underlying token
    /// @param recipient The address that will receive the redeemed underlying token
    /// @return The amount of principal token redeemed
    function withdraw(address adapter, uint256 maturity, uint256 underlyingAmount, address recipient)
        external
        returns (uint256);
}
