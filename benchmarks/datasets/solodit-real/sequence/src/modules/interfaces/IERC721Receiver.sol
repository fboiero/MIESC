// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/// @title IERC721Receiver
/// @notice Interface for the ERC721 receiver module
interface IERC721Receiver {

  /// @notice Called when a single ERC721 token is transferred to this contract
  /// @param operator The address which initiated the transfer
  /// @param from The address which previously owned the token
  /// @param tokenId The ID of the token being transferred
  /// @param data Additional data with no specified format
  /// @return magicValue On a success, the selector of the function that was called
  function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
  ) external returns (bytes4 magicValue);

}
