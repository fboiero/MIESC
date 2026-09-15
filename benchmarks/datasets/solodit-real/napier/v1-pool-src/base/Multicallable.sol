// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.10;

/// @title Multicallable
/// @notice Enables calling multiple methods in a single call to the contract
/// @dev Forked from Uniswap v3 periphery: https://github.com/Uniswap/v3-periphery/blob/main/contracts/base/Multicallable.sol
/// @dev Apply `DELEGATECALL` with the current contract to each calldata in `data`,
/// and store the `abi.encode` formatted results of each `DELEGATECALL` into `results`.
/// If any of the `DELEGATECALL`s reverts, the entire context is reverted,
/// and the error is bubbled up.
///
// Combining Multicallable with msg.value can cause double spending issues.
/// (See: https://www.paradigm.xyz/2021/08/two-rights-might-make-a-wrong)
abstract contract Multicallable {
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length;) {
            (bool success, bytes memory returndata) = address(this).delegatecall(data[i]);

            if (!success) {
                // Bubble up the revert message.
                // https://github.com/dragonfly-xyz/useful-solidity-patterns/tree/main/patterns/error-handling
                // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/36bf1e46fa811f0f07d38eb9cfbc69a955f300ce/contracts/utils/Address.sol#L151-L154
                assembly {
                    revert(
                        // Start of revert data bytes.
                        add(returndata, 0x20),
                        // Length of revert data.
                        mload(returndata)
                    )
                }
            }

            results[i] = returndata;

            unchecked {
                ++i;
            }
        }
    }
}
