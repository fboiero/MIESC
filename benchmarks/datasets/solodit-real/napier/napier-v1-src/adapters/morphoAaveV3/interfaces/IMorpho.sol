// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

// interface of main Morpho contract exposing all user entry points.

interface IMorpho {
    /// @notice Supplies `amount` of `underlying` on behalf of `onBehalf`.
    ///         The supplied amount cannot be used as collateral but is eligible for the peer-to-peer matching.
    /// @param underlying The address of the underlying asset to supply.
    /// @param amount The amount of `underlying` to supply.
    /// @param onBehalf The address that will receive the supply position.
    /// @param maxIterations The maximum number of iterations allowed during the matching process. Using 4 was shown to be efficient in Morpho Labs' simulations.
    /// @return supplied The amount supplied (in underlying).
    function supply(
        address underlying,
        uint256 amount,
        address onBehalf,
        uint256 maxIterations
    ) external returns (uint256 supplied);

    /// @notice Claims rewards for the given assets.
    /// @param assets The assets to claim rewards from (aToken or variable debt token).
    /// @param onBehalf The address for which rewards are claimed and sent to.
    /// @return rewardTokens The addresses of each reward token.
    /// @return claimedAmounts The amount of rewards claimed (in reward tokens).
    function claimRewards(
        address[] calldata assets,
        address onBehalf
    ) external returns (address[] memory rewardTokens, uint256[] memory claimedAmounts);
}
