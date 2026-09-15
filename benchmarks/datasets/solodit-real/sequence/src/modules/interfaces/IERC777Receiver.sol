// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/// @title IERC777Receiver
/// @notice Interface for the ERC777 receiver module
interface IERC777Receiver {

  /// @notice Called when tokens are received by this contract
  /// @param operator The address which initiated the transfer
  /// @param from The address which previously owned the tokens
  /// @param to The address which is receiving the tokens
  /// @param amount The amount of tokens being transferred
  /// @param data Additional data with no specified format
  /// @param operatorData Additional data with no specified format
  function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata data,
    bytes calldata operatorData
  ) external;

}
