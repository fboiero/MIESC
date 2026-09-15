// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/// @title IERC1155Receiver
/// @notice Interface for the ERC1155 receiver module
interface IERC1155Receiver {

  /// @notice Called when a single ERC1155 token is transferred to this contract
  /// @param operator The address which initiated the transfer
  /// @param from The address which previously owned the token
  /// @param tokenId The ID of the token being transferred
  /// @param value The amount of token being transferred
  /// @param data Additional data with no specified format
  /// @return magicValue On a success, the selector of the function that was called
  function onERC1155Received(
    address operator,
    address from,
    uint256 tokenId,
    uint256 value,
    bytes calldata data
  ) external returns (bytes4 magicValue);

  /// @notice Called when multiple ERC1155 tokens are transferred to this contract
  /// @param operator The address which initiated the transfer
  /// @param from The address which previously owned the token
  /// @param ids The list of token IDs being transferred
  /// @param values The amounts of each token being transferred
  /// @param data Additional data with no specified format
  /// @return magicValue On a success, the selector of the function that was called
  function onERC1155BatchReceived(
    address operator,
    address from,
    uint256[] calldata ids,
    uint256[] calldata values,
    bytes calldata data
  ) external returns (bytes4 magicValue);

}
