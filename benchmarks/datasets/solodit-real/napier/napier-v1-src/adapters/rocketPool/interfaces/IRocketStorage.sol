// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

/// @notice Interface for Rocket Pool
/// @dev RocketStorage contract is responsible for storing addresses of modules.
/// Because of Rocket Pool's architecture, the addresses of other contracts should not be used directly but retrieved from the blockchain before use.
/// Network upgrades may have occurred since the previous interaction, resulting in outdated addresses.
/// @author Taken from https://github.com/rocket-pool/rocketpool/blob/9710596d82189c54f0dc35be3501cda13a155f4d/contracts/interface/RocketStorageInterface.sol
interface IRocketStorage {
    // Getters
    function getAddress(bytes32 _key) external view returns (address);

    function getUint(bytes32 _key) external view returns (uint256);
}
