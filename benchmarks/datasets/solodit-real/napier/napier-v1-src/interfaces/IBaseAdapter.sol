// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

interface IBaseAdapter {
    /* ============== MUTATIVE METHODS =============== */

    /// @notice update adapter's scale value and return it
    ///         Underlying decimals: `u`, Target decimals: `t`, Target conversion rate: 10^u / 10^t
    ///         => Scale = 10^(u-t) * 10^18 = 10^(u-t+18)
    ///         e.g. WstETH (t=18,u=18) price: 1.2 WETH => scale = 1.2*10^18
    ///              eUSDC (t=18,u=6) price: 1.01 USDC => scale = 1.01*10^(6-18+18) = 1.01*10^6
    /// @dev For interest-bearing token, such as cTokens, this is simply the conversion rate
    /// @dev For other Targets, such as AMM LP shares, specialized logic will be required
    /// @return scale in units of underlying token
    function scale() external view returns (uint256);

    /// @notice deposit Underlying in return for Target.
    /// @dev no funds should be left in the contract after this call.
    ///      the caller must transfer Underlying to this contract before calling this function.
    /// @return underlyingUsed amount of Underlying used
    /// @return sharesMinted amount of Target minted
    function prefundedDeposit() external returns (uint256 underlyingUsed, uint256 sharesMinted);

    /// @notice redeem Target and receive Underlying in return.
    /// @dev no funds should be left in the contract after this call
    ///      the caller must transfer Target to this contract before calling this function.
    /// @param to recipient of Underlying
    /// @return underlyingWithdrawn amount of Underlying returned
    /// @return sharesRedeemed amount of Target redeemed
    function prefundedRedeem(address to) external returns (uint256 underlyingWithdrawn, uint256 sharesRedeemed);

    /* =============== VIEW METHODS ================ */

    /// @notice return Underlying token address (eg USDC, DAI)
    /// @return Underlying address
    function underlying() external view returns (address);

    /// @notice return yield-bearing token address (eg cUSDC, wstETH, AMM LP shares)
    /// @return Target address (yield-bearing token)
    function target() external view returns (address);
}
