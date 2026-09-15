// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Permission, UsageLimit } from "./Permission.sol";

/// @notice Permissions configuration for a specific session signer
/// @param signer Address of the session signer these permissions apply to
/// @param chainId Chain ID of the session (0 = any chain)
/// @param valueLimit Maximum native token value this signer can send
/// @param deadline Deadline for the session. (0 = no deadline)
/// @param permissions Array of encoded permissions granted to this signer
struct SessionPermissions {
  address signer;
  uint256 chainId;
  uint256 valueLimit;
  uint64 deadline;
  Permission[] permissions;
}

/// @notice Usage limits configuration for a specific session signer
/// @param signer Address of the session signer these limits apply to
/// @param limits Array of usage limits
/// @param totalValueUsed Total native token value used
struct SessionUsageLimits {
  address signer;
  UsageLimit[] limits;
  uint256 totalValueUsed;
}

/// @title IExplicitSessionManager
/// @author Agustin Aguilar, Michael Standen
/// @notice Interface for the explicit session manager
interface IExplicitSessionManager {

  /// @notice Increment usage for a caller's given session and target
  /// @param limits Array of limit/session/target combinations
  function incrementUsageLimit(
    UsageLimit[] calldata limits
  ) external;

}
