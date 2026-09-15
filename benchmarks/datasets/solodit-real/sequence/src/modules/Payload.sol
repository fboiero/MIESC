// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { LibBytes } from "../utils/LibBytes.sol";

using LibBytes for bytes;

/// @title Payload
/// @author Agustin Aguilar, Michael Standen, William Hua
/// @notice Library for encoding and decoding payloads
library Payload {

  /// @notice Error thrown when the kind is invalid
  error InvalidKind(uint8 kind);

  /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
  bytes32 private constant EIP712_DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

  /// @dev keccak256("Sequence Wallet")
  bytes32 private constant EIP712_DOMAIN_NAME_SEQUENCE =
    0x4aa45ca7ad825ceb1bf35643f0a58c295239df563b1b565c2485f96477c56318;

  /// @dev keccak256("3")
  bytes32 private constant EIP712_DOMAIN_VERSION_SEQUENCE =
    0x2a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de;

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

  /// @dev keccak256("Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool onlyFallback,uint256 behaviorOnError)")
  bytes32 private constant CALL_TYPEHASH = 0x0603985259a953da1f65a522f589c17bd1d0117ec1d3abb7c0788aef251ef437;

  /// @dev keccak256("Calls(Call[] calls,uint256 space,uint256 nonce,address[] wallets)Call(address to,uint256 value,bytes data,uint256 gasLimit,bool delegateCall,bool onlyFallback,uint256 behaviorOnError)")
  bytes32 private constant CALLS_TYPEHASH = 0x11e1e4079a79a66e4ade50033cfe2678cdd5341d2dfe5ef9513edb1a0be147a2;

  /// @dev keccak256("Message(bytes message,address[] wallets)")
  bytes32 private constant MESSAGE_TYPEHASH = 0xe19a3b94fc3c7ece3f890d98a99bc422615537a08dea0603fa8425867d87d466;

  /// @dev keccak256("ConfigUpdate(bytes32 imageHash,address[] wallets)")
  bytes32 private constant CONFIG_UPDATE_TYPEHASH = 0x11fdeb7e8373a1aa96bfac8d0ea91526b2c5d15e5cee20e0543e780258f3e8e4;

  /// @notice Kind of transaction
  uint8 public constant KIND_TRANSACTIONS = 0x00;
  /// @notice Kind of digest
  uint8 public constant KIND_MESSAGE = 0x01;
  /// @notice Kind of config update
  uint8 public constant KIND_CONFIG_UPDATE = 0x02;
  /// @notice Kind of message
  uint8 public constant KIND_DIGEST = 0x03;

  /// @notice Behavior on error: ignore error
  uint8 public constant BEHAVIOR_IGNORE_ERROR = 0x00;
  /// @notice Behavior on error: revert on error
  uint8 public constant BEHAVIOR_REVERT_ON_ERROR = 0x01;
  /// @notice Behavior on error: abort on error
  uint8 public constant BEHAVIOR_ABORT_ON_ERROR = 0x02;

  /// @notice Payload call information
  /// @param to Address of the target contract
  /// @param value Value to send with the call
  /// @param data Data to send with the call
  /// @param gasLimit Gas limit for the call
  /// @param delegateCall If the call is a delegate call
  /// @param onlyFallback If the call should only be executed in an error scenario
  /// @param behaviorOnError Behavior on error
  struct Call {
    address to;
    uint256 value;
    bytes data;
    uint256 gasLimit;
    bool delegateCall;
    bool onlyFallback;
    uint256 behaviorOnError;
  }

  /// @notice Decoded payload
  /// @param kind Kind of payload
  /// @param noChainId If the chain ID should be omitted
  /// @param calls Array of calls (transaction kind)
  /// @param space Nonce space for the calls (transaction kind)
  /// @param nonce Nonce value for the calls (transaction kind)
  /// @param message Message to validate (message kind)
  /// @param imageHash Image hash to update to (config update kind)
  /// @param digest Digest to validate (digest kind)
  /// @param parentWallets Parent wallets
  struct Decoded {
    uint8 kind;
    bool noChainId;
    // Transaction kind
    Call[] calls;
    uint256 space;
    uint256 nonce;
    // Message kind
    bytes message;
    // Config update kind
    bytes32 imageHash;
    // Digest kind for 1271
    bytes32 digest;
    // Parent wallets
    address[] parentWallets;
  }

  function fromMessage(
    bytes memory message
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_MESSAGE;
    _decoded.message = message;
  }

  function fromConfigUpdate(
    bytes32 imageHash
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_CONFIG_UPDATE;
    _decoded.imageHash = imageHash;
  }

  function fromDigest(
    bytes32 digest
  ) internal pure returns (Decoded memory _decoded) {
    _decoded.kind = KIND_DIGEST;
    _decoded.digest = digest;
  }

  function fromPackedCalls(
    bytes calldata packed
  ) internal view returns (Decoded memory _decoded) {
    _decoded.kind = KIND_TRANSACTIONS;

    // Read the global flag
    (uint256 globalFlag, uint256 pointer) = packed.readFirstUint8();

    // First bit determines if space is zero or not
    if (globalFlag & 0x01 == 0x01) {
      _decoded.space = 0;
    } else {
      (_decoded.space, pointer) = packed.readUint160(pointer);
    }

    // Next 3 bits determine the size of the nonce
    uint256 nonceSize = (globalFlag >> 1) & 0x07;

    if (nonceSize > 0) {
      // Read the nonce
      (_decoded.nonce, pointer) = packed.readUintX(pointer, nonceSize);
    }

    uint256 numCalls;

    // Bit 5 determines if the batch contains a single call
    if (globalFlag & 0x10 == 0x10) {
      numCalls = 1;
    } else {
      // Bit 6 determines if the number of calls uses 1 byte or 2 bytes
      if (globalFlag & 0x20 == 0x20) {
        (numCalls, pointer) = packed.readUint16(pointer);
      } else {
        (numCalls, pointer) = packed.readUint8(pointer);
      }
    }

    // Read the calls
    _decoded.calls = new Call[](numCalls);

    for (uint256 i = 0; i < numCalls; i++) {
      uint8 flags;
      (flags, pointer) = packed.readUint8(pointer);

      // First bit determines if this is a call to self
      // or a call to another address
      if (flags & 0x01 == 0x01) {
        // Call to self
        _decoded.calls[i].to = address(this);
      } else {
        // Call to another address
        (_decoded.calls[i].to, pointer) = packed.readAddress(pointer);
      }

      // Second bit determines if the call has value or not
      if (flags & 0x02 == 0x02) {
        (_decoded.calls[i].value, pointer) = packed.readUint256(pointer);
      }

      // Third bit determines if the call has data or not
      if (flags & 0x04 == 0x04) {
        // 3 bytes determine the size of the calldata
        uint256 calldataSize;
        (calldataSize, pointer) = packed.readUint24(pointer);
        _decoded.calls[i].data = packed[pointer:pointer + calldataSize];
        pointer += calldataSize;
      }

      // Fourth bit determines if the call has a gas limit or not
      if (flags & 0x08 == 0x08) {
        (_decoded.calls[i].gasLimit, pointer) = packed.readUint256(pointer);
      }

      // Fifth bit determines if the call is a delegate call or not
      _decoded.calls[i].delegateCall = (flags & 0x10 == 0x10);

      // Sixth bit determines if the call is fallback only
      _decoded.calls[i].onlyFallback = (flags & 0x20 == 0x20);

      // Last 2 bits are directly mapped to the behavior on error
      _decoded.calls[i].behaviorOnError = (flags & 0xC0) >> 6;
    }
  }

  function hashCall(
    Call memory c
  ) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(
        CALL_TYPEHASH, c.to, c.value, keccak256(c.data), c.gasLimit, c.delegateCall, c.onlyFallback, c.behaviorOnError
      )
    );
  }

  function hashCalls(
    Call[] memory calls
  ) internal pure returns (bytes32) {
    // In EIP712, an array is often hashed as the keccak256 of the concatenated
    // hashes of each item. So we hash each Call, pack them, and hash again.
    bytes32[] memory callHashes = new bytes32[](calls.length);
    for (uint256 i = 0; i < calls.length; i++) {
      callHashes[i] = hashCall(calls[i]);
    }
    return keccak256(abi.encodePacked(callHashes));
  }

  function toEIP712(
    Decoded memory _decoded
  ) internal pure returns (bytes32) {
    bytes32 walletsHash = keccak256(abi.encodePacked(_decoded.parentWallets));

    if (_decoded.kind == KIND_TRANSACTIONS) {
      bytes32 callsHash = hashCalls(_decoded.calls);
      // The top-level struct for Calls might be something like:
      // Calls(bytes32 callsHash,uint256 space,uint256 nonce,bytes32 walletsHash)
      return keccak256(abi.encode(CALLS_TYPEHASH, callsHash, _decoded.space, _decoded.nonce, walletsHash));
    } else if (_decoded.kind == KIND_MESSAGE) {
      // If you define your top-level as: Message(bytes32 messageHash,bytes32 walletsHash)
      return keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(_decoded.message), walletsHash));
    } else if (_decoded.kind == KIND_CONFIG_UPDATE) {
      // Top-level: ConfigUpdate(bytes32 imageHash,bytes32 walletsHash)
      return keccak256(abi.encode(CONFIG_UPDATE_TYPEHASH, _decoded.imageHash, walletsHash));
    } else if (_decoded.kind == KIND_DIGEST) {
      // Top-level: Use MESSAGE_TYPEHASH but assume the digest is already the hashed message
      return keccak256(abi.encode(MESSAGE_TYPEHASH, _decoded.digest, walletsHash));
    } else {
      // Unknown kind
      revert InvalidKind(_decoded.kind);
    }
  }

  function hash(
    Decoded memory _decoded
  ) internal view returns (bytes32) {
    bytes32 domain = domainSeparator(_decoded.noChainId, address(this));
    bytes32 structHash = toEIP712(_decoded);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

  function hashFor(Decoded memory _decoded, address _wallet) internal view returns (bytes32) {
    bytes32 domain = domainSeparator(_decoded.noChainId, _wallet);
    bytes32 structHash = toEIP712(_decoded);
    return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
  }

}
