// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../../modules/Payload.sol";
import { Attestation } from "./Attestation.sol";

/// @dev Magic prefix for the implicit request
bytes32 constant ACCEPT_IMPLICIT_REQUEST_MAGIC_PREFIX = keccak256(abi.encodePacked("acceptImplicitRequest"));

/// @title ISignalsImplicitMode
/// @author Agustin Aguilar, Michael Standen
/// @notice Interface for the contracts that support implicit mode validation
interface ISignalsImplicitMode {

  /// @notice Determines if an implicit request is valid
  /// @param wallet The wallet's address
  /// @param attestation The attestation data
  /// @param call The call to validate
  /// @return magic The hash of the implicit request if valid
  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    Payload.Call calldata call
  ) external view returns (bytes32 magic);

}
