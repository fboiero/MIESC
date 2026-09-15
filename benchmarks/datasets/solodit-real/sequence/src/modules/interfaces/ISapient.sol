// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/// @title ISapient
/// @author Agustin Aguilar, Michael Standen
/// @notice Sapient signers take an explicit payload and return their own "imageHash" as result
/// @dev The consumer of this signer must validate if the imageHash is valid or not, for the desired configuration
interface ISapient {

  /// @notice Recovers the image hash of a given signature
  /// @param payload The payload to recover the signature from
  /// @param signature The signature to recover the image hash from
  /// @return imageHash The recovered image hash
  function recoverSapientSignature(
    Payload.Decoded calldata payload,
    bytes calldata signature
  ) external view returns (bytes32 imageHash);

}

/// @title ISapientCompact
/// @author Agustin Aguilar, Michael Standen
/// @notice Sapient signers take a compacted payload and return their own "imageHash" as result
/// @dev The consumer of this signer must validate if the imageHash is valid or not, for the desired configuration
interface ISapientCompact {

  /// @notice Recovers the image hash of a given signature, using a hashed payload
  /// @param digest The digest of the payload
  /// @param signature The signature to recover the image hash from
  /// @return imageHash The recovered image hash
  function recoverSapientSignatureCompact(
    bytes32 digest,
    bytes calldata signature
  ) external view returns (bytes32 imageHash);

}
