// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title IDelegatedExtension
/// @author Agustin Aguilar
/// @notice Interface for the delegated extension module
interface IDelegatedExtension {

  /// @notice Handle a sequence delegate call
  /// @param _opHash The operation hash
  /// @param _startingGas The starting gas
  /// @param _index The index
  /// @param _numCalls The number of calls
  /// @param _space The space
  /// @param _data The data
  function handleSequenceDelegateCall(
    bytes32 _opHash,
    uint256 _startingGas,
    uint256 _index,
    uint256 _numCalls,
    uint256 _space,
    bytes calldata _data
  ) external;

}
