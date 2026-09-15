// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

//interface of RewardsDistributor in  in Morpho protocol.
interface IRewardsDistributor {
    /// @notice Claims rewards.
    /// @param user The address of the claimer.
    /// @param claimable The overall claimable amount of token rewards.
    /// @param proof The merkle proof that validates this claim.
    function claim(address user, uint256 claimable, bytes32[] memory proof) external;

    /// @notice Updates the current merkle tree's root.
    /// @param _newRoot The new merkle tree's root.
    function updateRoot(bytes32 _newRoot) external;
}
