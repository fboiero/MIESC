// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { LibBytes } from "../../../utils/LibBytes.sol";

import { SessionErrors } from "../SessionErrors.sol";
import { IExplicitSessionManager, SessionPermissions, SessionUsageLimits } from "./IExplicitSessionManager.sol";
import { Permission, UsageLimit } from "./Permission.sol";
import { PermissionValidator } from "./PermissionValidator.sol";

abstract contract ExplicitSessionManager is IExplicitSessionManager, PermissionValidator {

  using LibBytes for bytes;

  /// @notice Special address used for tracking native token value limits
  address public constant VALUE_TRACKING_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

  /// @inheritdoc IExplicitSessionManager
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external {
    address wallet = msg.sender;
    for (uint256 i = 0; i < limits.length; i++) {
      if (limits[i].usageAmount < getLimitUsage(wallet, limits[i].usageHash)) {
        // Cannot decrement usage limit
        revert SessionErrors.InvalidLimitUsageIncrement();
      }
      setLimitUsage(wallet, limits[i].usageHash, limits[i].usageAmount);
    }
  }

  /// @notice Validates an explicit call
  /// @param payload The decoded payload containing calls
  /// @param callIdx The index of the call to validate
  /// @param wallet The wallet's address
  /// @param sessionSigner The session signer's address
  /// @param allSessionPermissions All sessions' permissions
  /// @param permissionIdx The index of the permission to validate
  /// @param sessionUsageLimits The session usage limits
  /// @return newSessionUsageLimits The updated session usage limits
  function _validateExplicitCall(
    Payload.Decoded calldata payload,
    uint256 callIdx,
    address wallet,
    address sessionSigner,
    SessionPermissions[] memory allSessionPermissions,
    uint8 permissionIdx,
    SessionUsageLimits memory sessionUsageLimits
  ) internal view returns (SessionUsageLimits memory newSessionUsageLimits) {
    // Find the permissions for the given session signer
    SessionPermissions memory sessionPermissions;
    for (uint256 i = 0; i < allSessionPermissions.length; i++) {
      if (allSessionPermissions[i].signer == sessionSigner) {
        sessionPermissions = allSessionPermissions[i];
        break;
      }
    }
    if (sessionPermissions.signer == address(0)) {
      revert SessionErrors.InvalidSessionSigner(sessionSigner);
    }

    // Check if session chainId is valid
    if (sessionPermissions.chainId != 0 && sessionPermissions.chainId != block.chainid) {
      revert SessionErrors.InvalidChainId(sessionPermissions.chainId);
    }

    // Check if session has expired.
    if (sessionPermissions.deadline != 0 && block.timestamp > sessionPermissions.deadline) {
      revert SessionErrors.SessionExpired(sessionPermissions.deadline);
    }

    // Delegate calls are not allowed
    Payload.Call calldata call = payload.calls[callIdx];
    if (call.delegateCall) {
      revert SessionErrors.InvalidDelegateCall();
    }

    // Calls to incrementUsageLimit are the only allowed calls to this contract
    if (call.to == address(this)) {
      if (callIdx != 0) {
        // IncrementUsageLimit call is only allowed as the first call
        revert SessionErrors.InvalidLimitUsageIncrement();
      }
      if (call.value > 0) {
        revert SessionErrors.InvalidValue();
      }
      // No permissions required for the increment call
      return sessionUsageLimits;
    }

    // Get the permission for the current call
    if (permissionIdx >= sessionPermissions.permissions.length) {
      revert SessionErrors.MissingPermission();
    }
    Permission memory permission = sessionPermissions.permissions[permissionIdx];

    // Validate the permission for the current call
    (bool isValid, UsageLimit[] memory limits) =
      validatePermission(permission, call, wallet, sessionSigner, sessionUsageLimits.limits);
    if (!isValid) {
      revert SessionErrors.InvalidPermission();
    }
    sessionUsageLimits.limits = limits;

    // Increment the total value used
    if (call.value > 0) {
      sessionUsageLimits.totalValueUsed += call.value;
    }
    if (sessionUsageLimits.totalValueUsed > sessionPermissions.valueLimit) {
      // Value limit exceeded
      revert SessionErrors.InvalidValue();
    }

    return sessionUsageLimits;
  }

  /// @notice Verifies the limit usage increment
  /// @param call The first call in the payload, which is expected to be the increment call
  /// @param sessionUsageLimits The session usage limits
  /// @dev Reverts if the required increment call is missing or invalid
  /// @dev If no usage limits are used, this function does nothing
  function _validateLimitUsageIncrement(
    Payload.Call calldata call,
    SessionUsageLimits[] memory sessionUsageLimits
  ) internal view {
    // Limits call is only required if there are usage limits used
    if (sessionUsageLimits.length > 0) {
      // Verify the first call is the increment call and cannot be skipped
      if (call.to != address(this) || call.behaviorOnError != Payload.BEHAVIOR_REVERT_ON_ERROR || call.onlyFallback) {
        revert SessionErrors.InvalidLimitUsageIncrement();
      }

      // Construct expected limit increments
      uint256 totalLimitsLength = 0;
      for (uint256 i = 0; i < sessionUsageLimits.length; i++) {
        totalLimitsLength += sessionUsageLimits[i].limits.length;
        if (sessionUsageLimits[i].totalValueUsed > 0) {
          totalLimitsLength++;
        }
      }
      UsageLimit[] memory limits = new UsageLimit[](totalLimitsLength);
      uint256 limitIndex = 0;
      for (uint256 i = 0; i < sessionUsageLimits.length; i++) {
        for (uint256 j = 0; j < sessionUsageLimits[i].limits.length; j++) {
          limits[limitIndex++] = sessionUsageLimits[i].limits[j];
        }
        if (sessionUsageLimits[i].totalValueUsed > 0) {
          limits[limitIndex++] = UsageLimit({
            usageHash: keccak256(abi.encode(sessionUsageLimits[i].signer, VALUE_TRACKING_ADDRESS)),
            usageAmount: sessionUsageLimits[i].totalValueUsed
          });
        }
      }

      // Verify the increment call data
      bytes memory expectedData = abi.encodeWithSelector(this.incrementUsageLimit.selector, limits);
      bytes32 expectedDataHash = keccak256(expectedData);
      bytes32 actualDataHash = keccak256(call.data);
      if (actualDataHash != expectedDataHash) {
        revert SessionErrors.InvalidLimitUsageIncrement();
      }
    } else {
      // Do not allow self calls if there are no usage limits
      if (call.to == address(this)) {
        revert SessionErrors.InvalidLimitUsageIncrement();
      }
    }
  }

}
