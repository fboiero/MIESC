// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/// @title IPartialAuth
/// @author Agustin Aguilar
/// @notice Interface for the partial auth module
interface IPartialAuth {

  /// @notice Recover the partial signature
  /// @param _payload The payload
  /// @param _signature The signature to recover
  /// @return threshold The signature threshold
  /// @return weight The derived weight
  /// @return isValidImage Whether the image hash is valid
  /// @return imageHash The derived image hash
  /// @return checkpoint The checkpoint identifier
  /// @return opHash The hash of the payload
  function recoverPartialSignature(
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  )
    external
    view
    returns (
      uint256 threshold,
      uint256 weight,
      bool isValidImage,
      bytes32 imageHash,
      uint256 checkpoint,
      bytes32 opHash
    );

}
