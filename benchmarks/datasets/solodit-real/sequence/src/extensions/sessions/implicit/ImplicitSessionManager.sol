// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";

import { SessionErrors } from "../SessionErrors.sol";
import { Attestation, LibAttestation } from "./Attestation.sol";
import { ISignalsImplicitMode } from "./ISignalsImplicitMode.sol";

using LibAttestation for Attestation;

/// @title ImplicitSessionManager
/// @author Agustin Aguilar, Michael Standen
/// @notice Manager for implicit sessions
abstract contract ImplicitSessionManager {

  /// @notice Validates a call in implicit mode
  /// @param call The call to validate
  /// @param wallet The wallet's address
  /// @param sessionSigner The session signer's address
  /// @param attestation The session attestation
  function _validateImplicitCall(
    Payload.Call calldata call,
    address wallet,
    address sessionSigner,
    Attestation memory attestation,
    address[] memory blacklist
  ) internal view {
    // Validate the session signer is attested
    if (sessionSigner != attestation.approvedSigner) {
      revert SessionErrors.InvalidSessionSigner(sessionSigner);
    }

    // Delegate calls are not allowed
    if (call.delegateCall) {
      revert SessionErrors.InvalidDelegateCall();
    }
    // Check if the signer is blacklisted
    if (_isAddressBlacklisted(sessionSigner, blacklist)) {
      revert SessionErrors.BlacklistedAddress(sessionSigner);
    }
    // Check if the target address is blacklisted
    if (_isAddressBlacklisted(call.to, blacklist)) {
      revert SessionErrors.BlacklistedAddress(call.to);
    }
    // No value
    if (call.value > 0) {
      revert SessionErrors.InvalidValue();
    }

    // Validate the implicit request
    bytes32 result = ISignalsImplicitMode(call.to).acceptImplicitRequest(wallet, attestation, call);
    bytes32 attestationMagic = attestation.generateImplicitRequestMagic(wallet);
    if (result != attestationMagic) {
      revert SessionErrors.InvalidImplicitResult();
    }
  }

  /// @notice Checks if an address is in the blacklist using binary search
  /// @param target The address to check
  /// @param blacklist The sorted array of blacklisted addresses
  /// @return bool True if the address is blacklisted, false otherwise
  function _isAddressBlacklisted(address target, address[] memory blacklist) internal pure returns (bool) {
    int256 left = 0;
    int256 right = int256(blacklist.length) - 1;

    while (left <= right) {
      int256 mid = left + (right - left) / 2;
      address currentAddress = blacklist[uint256(mid)];

      if (currentAddress == target) {
        return true;
      } else if (currentAddress < target) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }

    return false;
  }

}
