// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { LibBytes } from "../../utils/LibBytes.sol";
import { LibOptim } from "../../utils/LibOptim.sol";
import { SessionErrors } from "./SessionErrors.sol";
import { SessionPermissions } from "./explicit/IExplicitSessionManager.sol";
import { LibPermission, Permission } from "./explicit/Permission.sol";
import { Attestation, LibAttestation } from "./implicit/Attestation.sol";

using LibBytes for bytes;
using LibAttestation for Attestation;

/// @title SessionSig
/// @author Michael Standen, Agustin Aguilar
/// @notice Library for session signatures
library SessionSig {

  uint256 internal constant FLAG_PERMISSIONS = 0;
  uint256 internal constant FLAG_NODE = 1;
  uint256 internal constant FLAG_BRANCH = 2;
  uint256 internal constant FLAG_BLACKLIST = 3;
  uint256 internal constant FLAG_IDENTITY_SIGNER = 4;

  uint256 internal constant MIN_ENCODED_PERMISSION_SIZE = 94;

  /// @notice Call signature for a specific session
  /// @param isImplicit If the call is implicit
  /// @param sessionSigner Address of the session signer
  /// @param sessionPermission Session permission for explicit calls
  /// @param attestation Attestation for implicit calls
  struct CallSignature {
    bool isImplicit;
    address sessionSigner;
    uint8 sessionPermission;
    Attestation attestation;
  }

  /// @notice Decoded signature for a specific session
  /// @param imageHash Derived configuration image hash
  /// @param identitySigner Identity signer address
  /// @param implicitBlacklist Implicit blacklist addresses
  /// @param sessionPermissions Session permissions for each explicit signer
  /// @param callSignatures Call signatures for each call in the payload
  struct DecodedSignature {
    bytes32 imageHash;
    address identitySigner;
    address[] implicitBlacklist;
    SessionPermissions[] sessionPermissions;
    CallSignature[] callSignatures;
  }

  /// @notice Recovers the decoded signature from the encodedSignature bytes.
  /// @dev The encoded layout is conceptually separated into three parts:
  ///  1) Session Configuration
  ///  2) A reusable list of Attestations + their identity signatures (if any implicit calls exist)
  ///  3) Call Signatures (one per call in the payload)
  ///
  /// High-level layout:
  ///  - session_configuration: [uint24 size, <Session Configuration encoded>]
  ///  - attestation_list: [uint8 attestationCount, (Attestation + identitySig) * attestationCount]
  ///    (new section to allow reusing the same Attestation across multiple calls)
  ///  - call_signatures: [<CallSignature encoded>] - Size is payload.calls.length
  ///    - call_signature: [uint8 call_flags, <session_signature>]
  ///      - call_flags: [bool is_implicit (MSB), 7 bits encoded]
  ///      - if call_flags.is_implicit.MSB == 1:
  ///         - attestation_index: [uint8 index into the attestation list (7 bits of the call_flags)]
  ///         - session_signature: [r, s, v (compact)]
  ///      - if call_flags.is_implicit.MSB == 0:
  ///         - session_permission: [uint8 (7 bits of the call_flags)]
  ///         - session_signature: [r, s, v (compact)]
  function recoverSignature(
    Payload.Decoded calldata payload,
    bytes calldata encodedSignature
  ) internal view returns (DecodedSignature memory sig) {
    uint256 pointer = 0;
    bool hasBlacklistInConfig;

    // ----- Session Configuration -----
    {
      // First read the length of the session configuration bytes (uint24)
      uint256 dataSize;
      (dataSize, pointer) = encodedSignature.readUint24(pointer);

      // Recover the session configuration
      (sig, hasBlacklistInConfig) = recoverConfiguration(encodedSignature[pointer:pointer + dataSize]);
      pointer += dataSize;

      // Identity signer must be set
      if (sig.identitySigner == address(0)) {
        revert SessionErrors.InvalidIdentitySigner();
      }
    }

    // ----- Attestations for implicit calls -----
    Attestation[] memory attestationList;
    {
      uint8 attestationCount;
      (attestationCount, pointer) = encodedSignature.readUint8(pointer);
      attestationList = new Attestation[](attestationCount);
      // Parse each attestation and its identity signature, store in memory
      for (uint256 i = 0; i < attestationCount; i++) {
        Attestation memory att;
        (att, pointer) = LibAttestation.fromPacked(encodedSignature, pointer);

        // Read the identity signature that approves this attestation
        {
          bytes32 r;
          bytes32 s;
          uint8 v;
          (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

          // Recover the identity signer from the attestation identity signature
          bytes32 attestationHash = att.toHash();
          address recoveredIdentitySigner = ecrecover(attestationHash, v, r, s);
          if (recoveredIdentitySigner != sig.identitySigner) {
            revert SessionErrors.InvalidIdentitySigner();
          }
        }

        attestationList[i] = att;
      }

      // If we have any implicit calls, we must have a blacklist in the configuration
      if (attestationCount > 0 && !hasBlacklistInConfig) {
        revert SessionErrors.InvalidBlacklist();
      }
    }

    // ----- Call Signatures -----
    {
      uint256 callsCount = payload.calls.length;
      sig.callSignatures = new CallSignature[](callsCount);

      for (uint256 i = 0; i < callsCount; i++) {
        CallSignature memory callSignature;

        // Determine signature type
        {
          uint8 flag;
          (flag, pointer) = encodedSignature.readUint8(pointer);
          callSignature.isImplicit = (flag & 0x80) != 0;

          if (callSignature.isImplicit) {
            // Read attestation index from the call_flags
            uint8 attestationIndex = uint8(flag & 0x7f);

            // Check if the attestation index is out of range
            if (attestationIndex >= attestationList.length) {
              revert SessionErrors.InvalidAttestation();
            }

            // Set the attestation
            callSignature.attestation = attestationList[attestationIndex];
          } else {
            // Session permission index is the entire byte, top bit is 0 => no conflict
            callSignature.sessionPermission = flag;
          }
        }

        // Read session signature and recover the signer
        {
          bytes32 r;
          bytes32 s;
          uint8 v;
          (r, s, v, pointer) = encodedSignature.readRSVCompact(pointer);

          bytes32 callHash = hashCallWithReplayProtection(payload, i);
          callSignature.sessionSigner = ecrecover(callHash, v, r, s);
          if (callSignature.sessionSigner == address(0)) {
            revert SessionErrors.InvalidSessionSigner(address(0));
          }
        }

        sig.callSignatures[i] = callSignature;
      }
    }

    return sig;
  }

  /// @notice Recovers the session configuration from the encoded data.
  /// The encoded layout is:
  /// - permissions_count: [uint8]
  /// - permissions_tree_element: [flag, <data>]
  ///   - flag: [uint8]
  ///   - data: [data]
  ///     - if flag == FLAG_PERMISSIONS: [SessionPermissions encoded]
  ///     - if flag == FLAG_NODE: [bytes32 node]
  ///     - if flag == FLAG_BRANCH: [uint256 size, nested encoding...]
  ///     - if flag == FLAG_BLACKLIST: [uint24 blacklist_count, blacklist_addresses...]
  ///     - if flag == FLAG_IDENTITY_SIGNER: [address identity_signer]
  /// @dev A valid configuration must have exactly one identity signer and at most one blacklist.
  function recoverConfiguration(
    bytes calldata encoded
  ) internal pure returns (DecodedSignature memory sig, bool hasBlacklist) {
    uint256 pointer;
    uint256 permissionsCount;

    // Guess maximum permissions size by bytes length
    {
      uint256 maxPermissionsSize = encoded.length / MIN_ENCODED_PERMISSION_SIZE;
      sig.sessionPermissions = new SessionPermissions[](maxPermissionsSize);
    }

    while (pointer < encoded.length) {
      // First byte is the flag (top 4 bits) and additional data (bottom 4 bits)
      uint256 firstByte;
      (firstByte, pointer) = encoded.readUint8(pointer);
      // The top 4 bits are the flag
      uint256 flag = (firstByte & 0xf0) >> 4;

      // Permissions configuration (0x00)
      if (flag == FLAG_PERMISSIONS) {
        SessionPermissions memory nodePermissions;
        uint256 pointerStart = pointer;

        // Read signer
        (nodePermissions.signer, pointer) = encoded.readAddress(pointer);

        // Read chainId
        (nodePermissions.chainId, pointer) = encoded.readUint256(pointer);

        // Read value limit
        (nodePermissions.valueLimit, pointer) = encoded.readUint256(pointer);

        // Read deadline
        (nodePermissions.deadline, pointer) = encoded.readUint64(pointer);

        // Read permissions array
        (nodePermissions.permissions, pointer) = _decodePermissions(encoded, pointer);

        // Update root
        {
          bytes32 permissionHash = _leafHashForPermissions(encoded[pointerStart:pointer]);
          sig.imageHash =
            sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, permissionHash) : permissionHash;
        }

        // Push node permissions to the permissions array
        sig.sessionPermissions[permissionsCount++] = nodePermissions;
        continue;
      }

      // Node (0x01)
      if (flag == FLAG_NODE) {
        // Read pre-hashed node
        bytes32 node;
        (node, pointer) = encoded.readBytes32(pointer);

        // Update root
        sig.imageHash = sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, node) : node;

        continue;
      }

      // Branch (0x02)
      if (flag == FLAG_BRANCH) {
        // Read branch size
        uint256 size;
        {
          uint256 sizeSize = uint8(firstByte & 0x0f);
          (size, pointer) = encoded.readUintX(pointer, sizeSize);
        }
        // Process branch
        uint256 nrindex = pointer + size;
        (DecodedSignature memory branchSig, bool branchHasBlacklist) = recoverConfiguration(encoded[pointer:nrindex]);
        pointer = nrindex;

        // Store the branch blacklist
        if (branchHasBlacklist) {
          if (hasBlacklist) {
            // Blacklist already set
            revert SessionErrors.InvalidBlacklist();
          }
          hasBlacklist = true;
          sig.implicitBlacklist = branchSig.implicitBlacklist;
        }

        // Store the branch identity signer
        if (branchSig.identitySigner != address(0)) {
          if (sig.identitySigner != address(0)) {
            // Identity signer already set
            revert SessionErrors.InvalidIdentitySigner();
          }
          sig.identitySigner = branchSig.identitySigner;
        }

        // Push all branch permissions to the permissions array
        for (uint256 i = 0; i < branchSig.sessionPermissions.length; i++) {
          sig.sessionPermissions[permissionsCount++] = branchSig.sessionPermissions[i];
        }

        // Update root
        sig.imageHash =
          sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, branchSig.imageHash) : branchSig.imageHash;

        continue;
      }

      // Blacklist (0x03)
      if (flag == FLAG_BLACKLIST) {
        if (hasBlacklist) {
          // Blacklist already set
          revert SessionErrors.InvalidBlacklist();
        }
        hasBlacklist = true;

        // Read the blacklist count from the first byte's lower 4 bits
        uint256 blacklistCount = uint256(firstByte & 0x0f);
        if (blacklistCount == 0x0f) {
          // If it's max nibble, read the next 2 bytes for the actual size
          (blacklistCount, pointer) = encoded.readUint16(pointer);
        }
        uint256 pointerStart = pointer;

        // Read the blacklist addresses
        sig.implicitBlacklist = new address[](blacklistCount);
        address previousAddress;
        for (uint256 i = 0; i < blacklistCount; i++) {
          (sig.implicitBlacklist[i], pointer) = encoded.readAddress(pointer);
          if (sig.implicitBlacklist[i] < previousAddress) {
            revert SessionErrors.InvalidBlacklistUnsorted();
          }
          previousAddress = sig.implicitBlacklist[i];
        }

        // Update the root
        bytes32 blacklistHash = _leafHashForBlacklist(encoded[pointerStart:pointer]);
        sig.imageHash = sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, blacklistHash) : blacklistHash;

        continue;
      }

      // Identity signer (0x04)
      if (flag == FLAG_IDENTITY_SIGNER) {
        if (sig.identitySigner != address(0)) {
          // Identity signer already set
          revert SessionErrors.InvalidIdentitySigner();
        }
        (sig.identitySigner, pointer) = encoded.readAddress(pointer);

        // Update the root
        bytes32 identitySignerHash = _leafHashForIdentitySigner(sig.identitySigner);
        sig.imageHash =
          sig.imageHash != bytes32(0) ? LibOptim.fkeccak256(sig.imageHash, identitySignerHash) : identitySignerHash;

        continue;
      }

      revert SessionErrors.InvalidNodeType(flag);
    }

    {
      // Update the permissions array length to the actual count
      SessionPermissions[] memory permissions = sig.sessionPermissions;
      assembly {
        mstore(permissions, permissionsCount)
      }
    }

    return (sig, hasBlacklist);
  }

  /// @notice Decodes an array of Permission objects from the encoded data.
  function _decodePermissions(
    bytes calldata encoded,
    uint256 pointer
  ) internal pure returns (Permission[] memory permissions, uint256 newPointer) {
    uint256 length;
    (length, pointer) = encoded.readUint8(pointer);
    permissions = new Permission[](length);
    for (uint256 i = 0; i < length; i++) {
      (permissions[i], pointer) = LibPermission.readPermission(encoded, pointer);
    }
    return (permissions, pointer);
  }

  /// @notice Hashes the encoded session permissions into a leaf node.
  function _leafHashForPermissions(
    bytes calldata encodedPermissions
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_PERMISSIONS), encodedPermissions));
  }

  /// @notice Hashes the encoded blacklist into a leaf node.
  function _leafHashForBlacklist(
    bytes calldata encodedBlacklist
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_BLACKLIST), encodedBlacklist));
  }

  /// @notice Hashes the identity signer into a leaf node.
  function _leafHashForIdentitySigner(
    address identitySigner
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(uint8(FLAG_IDENTITY_SIGNER), identitySigner));
  }

  /// @notice Hashes a call with replay protection.
  /// @dev The replay protection is based on the chainId, space, nonce and index in the payload.
  /// @param payload The payload to hash
  /// @param callIdx The index of the call to hash
  /// @return callHash The hash of the call with replay protection
  function hashCallWithReplayProtection(
    Payload.Decoded calldata payload,
    uint256 callIdx
  ) public view returns (bytes32 callHash) {
    return keccak256(
      abi.encodePacked(
        payload.noChainId ? 0 : block.chainid,
        payload.space,
        payload.nonce,
        callIdx,
        Payload.hashCall(payload.calls[callIdx])
      )
    );
  }

}
