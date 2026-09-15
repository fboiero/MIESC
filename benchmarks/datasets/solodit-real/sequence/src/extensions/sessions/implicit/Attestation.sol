// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../../../utils/LibBytes.sol";
import { ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX } from "./ISignalsImplicitMode.sol";

using LibBytes for bytes;

/// @notice Attestation for a specific session
/// @param approvedSigner Address of the approved signer
/// @param identityType Identity type
/// @param issuerHash Hash of the issuer
/// @param audienceHash Hash of the audience
/// @param applicationData Unspecified application data
/// @param authData Auth data
struct Attestation {
  address approvedSigner;
  bytes4 identityType;
  bytes32 issuerHash;
  bytes32 audienceHash;
  bytes applicationData;
  AuthData authData;
}

/// @notice Auth data for an attestation
/// @param redirectUrl Authorization redirect URL
/// @param issuedAt Timestamp of the attestation issuance
struct AuthData {
  string redirectUrl;
  uint64 issuedAt;
}

/// @title LibAttestation
/// @author Michael Standen
/// @notice Library for attestation management
library LibAttestation {

  /// @notice Hashes an attestation
  function toHash(
    Attestation memory attestation
  ) internal pure returns (bytes32) {
    return keccak256(toPacked(attestation));
  }

  /// @notice Decodes an attestation from a packed bytes array
  /// @param encoded The packed bytes array
  /// @param pointer The pointer to the start of the attestation
  /// @return attestation The decoded attestation
  /// @return newPointer The new pointer to the end of the attestation
  function fromPacked(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Attestation memory attestation, uint256 newPointer) {
    newPointer = pointer;
    (attestation.approvedSigner, newPointer) = encoded.readAddress(newPointer);
    (attestation.identityType, newPointer) = encoded.readBytes4(newPointer);
    (attestation.issuerHash, newPointer) = encoded.readBytes32(newPointer);
    (attestation.audienceHash, newPointer) = encoded.readBytes32(newPointer);
    // Application data (arbitrary bytes)
    uint256 dataSize;
    (dataSize, newPointer) = encoded.readUint24(newPointer);
    attestation.applicationData = encoded[newPointer:newPointer + dataSize];
    newPointer += dataSize;
    // Auth data
    (attestation.authData, newPointer) = fromPackedAuthData(encoded, newPointer);
    return (attestation, newPointer);
  }

  /// @notice Decodes the auth data from a packed bytes
  /// @param encoded The packed bytes containing the auth data
  /// @param pointer The pointer to the start of the auth data within the encoded data
  /// @return authData The decoded auth data
  /// @return newPointer The pointer to the end of the auth data within the encoded data
  function fromPackedAuthData(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (AuthData memory authData, uint256 newPointer) {
    uint24 redirectUrlLength;
    (redirectUrlLength, pointer) = encoded.readUint24(pointer);
    authData.redirectUrl = string(encoded[pointer:pointer + redirectUrlLength]);
    pointer += redirectUrlLength;
    (authData.issuedAt, pointer) = encoded.readUint64(pointer);
    return (authData, pointer);
  }

  /// @notice Encodes an attestation into a packed bytes array
  /// @param attestation The attestation to encode
  /// @return encoded The packed bytes array
  function toPacked(
    Attestation memory attestation
  ) internal pure returns (bytes memory encoded) {
    return abi.encodePacked(
      attestation.approvedSigner,
      attestation.identityType,
      attestation.issuerHash,
      attestation.audienceHash,
      uint24(attestation.applicationData.length),
      attestation.applicationData,
      toPackAuthData(attestation.authData)
    );
  }

  /// @notice Encodes the auth data into a packed bytes array
  /// @param authData The auth data to encode
  /// @return encoded The packed bytes array
  function toPackAuthData(
    AuthData memory authData
  ) internal pure returns (bytes memory encoded) {
    return abi.encodePacked(uint24(bytes(authData.redirectUrl).length), bytes(authData.redirectUrl), authData.issuedAt);
  }

  /// @notice Generates the implicit request magic return value
  /// @param attestation The attestation
  /// @param wallet The wallet
  /// @return magic The expected implicit request magic
  function generateImplicitRequestMagic(Attestation memory attestation, address wallet) internal pure returns (bytes32) {
    return keccak256(
      abi.encodePacked(ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX, wallet, attestation.audienceHash, attestation.issuerHash)
    );
  }

}
