// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/// @title IERC223Receiver
/// @notice Interface for the ERC223 receiver module
interface IERC223Receiver {

  /// @notice Called when ERC223 tokens are received by this contract
  /// @param from The address which previously owned the tokens
  /// @param value The amount of tokens being transferred
  /// @param data Transaction metadata
  /// @return signature The signature of the function to be called
  function tokenReceived(address from, uint256 value, bytes calldata data) external returns (bytes4 signature);

}
