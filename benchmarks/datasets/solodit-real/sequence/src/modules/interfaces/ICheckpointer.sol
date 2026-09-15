// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../Payload.sol";

/// @notice Snapshot for a specific wallet
/// @param imageHash Image hash of the wallet
/// @param checkpoint Checkpoint identifier
struct Snapshot {
  bytes32 imageHash;
  uint256 checkpoint;
}

/// @title ICheckpointer
/// @author Agustin Aguilar
/// @notice Interface for the checkpointer module
interface ICheckpointer {

  /// @notice Get the snapshot for a specific wallet
  /// @param _wallet The wallet address
  /// @param _proof The proof
  /// @return snapshot The snapshot
  function snapshotFor(address _wallet, bytes calldata _proof) external view returns (Snapshot memory snapshot);

}
