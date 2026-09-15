// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

/**
 * @title ILendingPoolAddressesProvider interface
 * @notice provides the interface to fetch the LendingPool address
 */

interface ILendingPoolAddressesProvider {
    /**
     * @notice Returns the address of the Pool proxy.
     * @return The Pool proxy address
     */
    function getPool() external view returns (address);
}
