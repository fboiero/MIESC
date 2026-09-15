// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

bytes4 constant IERC1271_MAGIC_VALUE_HASH = 0x1626ba7e;
bytes4 constant IERC1271_MAGIC_VALUE_BYTES = 0x20c13b0b;

/// @title IERC1271
/// @notice Interface for ERC1271
interface IERC1271 {

  /// @notice Verifies whether the provided signature is valid with respect to the provided hash
  /// @dev MUST return the correct magic value if the signature provided is valid for the provided hash
  ///   > The bytes4 magic value to return when signature is valid is 0x1626ba7e : bytes4(keccak256("isValidSignature(bytes32,bytes)")
  ///   > This function MAY modify Ethereum's state
  /// @param _hash keccak256 hash that was signed
  /// @param _signature Signature byte array associated with _data
  /// @return magicValue Magic value 0x1626ba7e if the signature is valid and 0x0 otherwise
  function isValidSignature(bytes32 _hash, bytes calldata _signature) external view returns (bytes4 magicValue);

}

/// @title IERC1271Data
/// @notice Deprecated interface for ERC1271 using bytes instead of bytes32
interface IERC1271Data {

  /// @notice Verifies whether the provided signature is valid with respect to the provided hash
  /// @dev MUST return the correct magic value if the signature provided is valid for the provided hash
  ///   > The bytes4 magic value to return when signature is valid is 0x20c13b0b : bytes4(keccak256("isValidSignature(bytes,bytes)")
  ///   > This function MAY modify Ethereum's state
  /// @param _data Data that was signed
  /// @param _signature Signature byte array associated with _data
  /// @return magicValue Magic value 0x20c13b0b if the signature is valid and 0x0 otherwise
  function isValidSignature(bytes calldata _data, bytes calldata _signature) external view returns (bytes4 magicValue);

}
