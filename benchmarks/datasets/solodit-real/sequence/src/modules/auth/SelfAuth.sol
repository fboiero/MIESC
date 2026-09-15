// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title SelfAuth
/// @author Agustin Aguilar, Michael Standen
/// @notice Modifier for checking if the caller is the same as the contract
abstract contract SelfAuth {

  /// @notice Error thrown when the caller is not the same as the contract
  error OnlySelf(address _sender);

  modifier onlySelf() {
    if (msg.sender != address(this)) {
      revert OnlySelf(msg.sender);
    }
    _;
  }

}
