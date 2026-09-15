// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title SessionErrors
/// @author Michael Standen
/// @notice Errors for the session manager
library SessionErrors {

  /// @notice Invalid session signer
  error InvalidSessionSigner(address invalidSigner);
  /// @notice Invalid chainId
  error InvalidChainId(uint256 invalidChainId);
  /// @notice Invalid self call
  error InvalidSelfCall();
  /// @notice Invalid delegate call
  error InvalidDelegateCall();
  /// @notice Invalid call behavior
  error InvalidBehavior();
  /// @notice Invalid value
  error InvalidValue();
  /// @notice Invalid node type in session configuration
  error InvalidNodeType(uint256 flag);
  /// @notice Error thrown when the payload kind is invalid
  error InvalidPayloadKind();
  /// @notice Error thrown when the calls length is invalid
  error InvalidCallsLength();
  /// @notice Error thrown when the payload space is invalid
  error InvalidSpace(uint256 space);

  // ---- Explicit session errors ----

  /// @notice Missing permission for explicit session
  error MissingPermission();
  /// @notice Invalid permission for explicit session
  error InvalidPermission();
  /// @notice Session expired
  error SessionExpired(uint256 deadline);
  /// @notice Invalid limit usage increment
  error InvalidLimitUsageIncrement();

  // ---- Implicit session errors ----

  /// @notice Blacklisted address
  error BlacklistedAddress(address target);
  /// @notice Invalid implicit result
  error InvalidImplicitResult();
  /// @notice Invalid identity signer
  error InvalidIdentitySigner();
  /// @notice Invalid blacklist
  error InvalidBlacklist();
  /// @notice Invalid attestation
  error InvalidAttestation();
  /// @notice The blacklist was not sorted
  error InvalidBlacklistUnsorted();

}
