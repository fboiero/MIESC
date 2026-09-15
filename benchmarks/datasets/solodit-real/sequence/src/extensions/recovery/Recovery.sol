// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Payload } from "../../modules/Payload.sol";
import { IERC1271, IERC1271_MAGIC_VALUE_HASH } from "../../modules/interfaces/IERC1271.sol";
import { ISapientCompact } from "../../modules/interfaces/ISapient.sol";
import { LibBytes } from "../../utils/LibBytes.sol";
import { LibOptim } from "../../utils/LibOptim.sol";

using LibBytes for bytes;

/// @title Recovery
/// @author Agustin Aguilar, William Hua, Michael Standen
/// @notice A recovery mode sapient signer
contract Recovery is ISapientCompact {

  bytes32 private constant EIP712_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

  bytes32 private constant EIP712_DOMAIN_NAME_SEQUENCE = keccak256("Sequence Wallet - Recovery Mode");
  bytes32 private constant EIP712_DOMAIN_VERSION_SEQUENCE = keccak256("1");

  // Make them similar to the flags in BaseSig.sol
  uint256 internal constant FLAG_RECOVERY_LEAF = 1;
  uint256 internal constant FLAG_NODE = 3;
  uint256 internal constant FLAG_BRANCH = 4;

  /// @notice Emitted when a new payload is queued
  event NewQueuedPayload(address _wallet, address _signer, bytes32 _payloadHash, uint256 _timestamp);

  /// @notice Error thrown when the signature is invalid
  error InvalidSignature(address _wallet, address _signer, Payload.Decoded _payload, bytes _signature);
  /// @notice Error thrown when the payload is already queued
  error AlreadyQueued(address _wallet, address _signer, bytes32 _payloadHash);
  /// @notice Error thrown when the queue is not ready
  error QueueNotReady(address _wallet, bytes32 _payloadHash);
  /// @notice Error thrown when the signature flag is invalid
  error InvalidSignatureFlag(uint256 _flag);

  function domainSeparator(bool _noChainId, address _wallet) internal view returns (bytes32 _domainSeparator) {
    return keccak256(
      abi.encode(
        EIP712_DOMAIN_TYPEHASH,
        EIP712_DOMAIN_NAME_SEQUENCE,
        EIP712_DOMAIN_VERSION_SEQUENCE,
        _noChainId ? uint256(0) : uint256(block.chainid),
        _wallet
      )
    );
  }

  /// @notice Mapping of queued timestamps
  /// @dev wallet -> signer -> payloadHash -> timestamp
  mapping(address => mapping(address => mapping(bytes32 => uint256))) public timestampForQueuedPayload;

  /// @notice Mapping of queued payload hashes
  /// @dev wallet -> signer -> payloadHash[]
  mapping(address => mapping(address => bytes32[])) public queuedPayloadHashes;

  /// @notice Get the total number of queued payloads
  /// @param _wallet The wallet to get the total number of queued payloads for
  /// @param _signer The signer to get the total number of queued payloads for
  /// @return The total number of queued payloads
  function totalQueuedPayloads(address _wallet, address _signer) public view returns (uint256) {
    return queuedPayloadHashes[_wallet][_signer].length;
  }

  function _leafForRecoveryLeaf(
    address _signer,
    uint256 _requiredDeltaTime,
    uint256 _minTimestamp
  ) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked("Sequence recovery leaf:\n", _signer, _requiredDeltaTime, _minTimestamp));
  }

  function _recoverBranch(
    address _wallet,
    bytes32 _payloadHash,
    bytes calldata _signature
  ) internal view returns (bool verified, bytes32 root) {
    uint256 rindex;

    while (rindex < _signature.length) {
      // The first byte is the flag, it determines if we are reading
      uint256 flag;
      (flag, rindex) = _signature.readUint8(rindex);

      if (flag == FLAG_RECOVERY_LEAF) {
        // Read the signer and requiredDeltaTime
        address signer;
        uint256 requiredDeltaTime;
        uint256 minTimestamp;

        (signer, rindex) = _signature.readAddress(rindex);
        (requiredDeltaTime, rindex) = _signature.readUint24(rindex);
        (minTimestamp, rindex) = _signature.readUint64(rindex);

        // Check if we have a queued payload for this signer
        uint256 queuedAt = timestampForQueuedPayload[_wallet][signer][_payloadHash];
        if (queuedAt != 0 && queuedAt >= minTimestamp && block.timestamp - queuedAt >= requiredDeltaTime) {
          verified = true;
        }

        bytes32 node = _leafForRecoveryLeaf(signer, requiredDeltaTime, minTimestamp);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      if (flag == FLAG_NODE) {
        // Read node hash
        bytes32 node;
        (node, rindex) = _signature.readBytes32(rindex);
        root = root != bytes32(0) ? LibOptim.fkeccak256(root, node) : node;
        continue;
      }

      if (flag == FLAG_BRANCH) {
        // Read size
        uint256 size;
        (size, rindex) = _signature.readUint24(rindex);

        // Enter a branch of the signature merkle tree
        uint256 nrindex = rindex + size;

        (bool nverified, bytes32 nroot) = _recoverBranch(_wallet, _payloadHash, _signature[rindex:nrindex]);
        rindex = nrindex;

        verified = verified || nverified;
        root = LibOptim.fkeccak256(root, nroot);
        continue;
      }

      revert InvalidSignatureFlag(flag);
    }

    return (verified, root);
  }

  /// @notice Get the recovery payload hash
  /// @param _wallet The wallet to get the recovery payload hash for
  /// @param _payload The payload to get the recovery payload hash for
  /// @return The recovery payload hash
  function recoveryPayloadHash(address _wallet, Payload.Decoded calldata _payload) public view returns (bytes32) {
    bytes32 domain = domainSeparator(_payload.noChainId, _wallet);
    bytes32 structHash = Payload.toEIP712(_payload);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

  /// @inheritdoc ISapientCompact
  function recoverSapientSignatureCompact(
    bytes32 _payloadHash,
    bytes calldata _signature
  ) external view returns (bytes32) {
    (bool verified, bytes32 root) = _recoverBranch(msg.sender, _payloadHash, _signature);
    if (!verified) {
      revert QueueNotReady(msg.sender, _payloadHash);
    }

    return root;
  }

  /// @notice Queue a payload for recovery
  /// @param _wallet The wallet to queue the payload for
  /// @param _signer The signer to queue the payload for
  /// @param _payload The payload to queue
  /// @param _signature The signature to queue the payload for
  function queuePayload(
    address _wallet,
    address _signer,
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) external {
    if (!isValidSignature(_wallet, _signer, _payload, _signature)) {
      revert InvalidSignature(_wallet, _signer, _payload, _signature);
    }

    bytes32 payloadHash = Payload.hashFor(_payload, _wallet);
    if (timestampForQueuedPayload[_wallet][_signer][payloadHash] != 0) {
      revert AlreadyQueued(_wallet, _signer, payloadHash);
    }

    timestampForQueuedPayload[_wallet][_signer][payloadHash] = block.timestamp;
    queuedPayloadHashes[_wallet][_signer].push(payloadHash);

    emit NewQueuedPayload(_wallet, _signer, payloadHash, block.timestamp);
  }

  function isValidSignature(
    address _wallet,
    address _signer,
    Payload.Decoded calldata _payload,
    bytes calldata _signature
  ) internal view returns (bool) {
    bytes32 rPayloadHash = recoveryPayloadHash(_wallet, _payload);

    if (_signature.length == 64) {
      // Try an ECDSA signature
      bytes32 r;
      bytes32 s;
      uint8 v;
      (r, s, v,) = _signature.readRSVCompact(0);

      address addr = ecrecover(rPayloadHash, v, r, s);
      if (addr == _signer) {
        return true;
      }
    }

    if (_signer.code.length != 0) {
      // ERC1271
      return IERC1271(_signer).isValidSignature(rPayloadHash, _signature) == IERC1271_MAGIC_VALUE_HASH;
    }

    return false;
  }

}
