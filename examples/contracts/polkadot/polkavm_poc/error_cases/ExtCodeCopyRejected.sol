// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Difference class (A): resolc REJECTS EXTCODECOPY at compile time
// ("LLVM IR generator: The EXTCODECOPY instruction is not supported", exit 1).
// This file is EXPECTED TO FAIL compilation with resolc — it documents the
// compiler's job, NOT a MIESC finding. It must NOT be put on the normal scan path.
contract ExtCodeCopyRejected {
    function copy(address a) external view returns (bytes32 h) {
        assembly {
            extcodecopy(a, 0, 0, 32)
            h := mload(0)
        }
    }
}
