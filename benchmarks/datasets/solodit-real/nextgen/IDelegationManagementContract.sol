// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;

/**
 * @dev Interface module which provides a basic access control mechanism of the NFT Delegation Smart Contract
 */

interface IDelegationManagementContract {
    
    /**
     * @notice Returns an array of all delegation addresses (active AND inactive) assigned by a delegator for a specific use case on a specific NFT collection
     */

    function retrieveDelegationAddresses(address _delegatorAddress, address _collectionAddress, uint256 _useCase) external view returns (address[] memory);
    
    /**
     * @notice Returns an array of all delegators (active AND inactive) that delegated to a delegationAddress for a specific use case on a specific NFT collection
     */

     function retrieveDelegators(address _delegationAddress, address _collectionAddress, uint256 _useCase) external view returns (address[] memory);

    /**
     * @notice Returns an array of all active delegators on a certain date for a specific use case on a specific NFT collection given a delegation Address
    */

     function retrieveActiveDelegators(address _delegationAddress, address _collectionAddress, uint256 _date, uint256 _useCase) external view returns (address[] memory);

     /**
     * @notice Returns the most recent delegation address delegated for a specific use case on a specific NFT collection
     */

    function retrieveMostRecentDelegation(address _delegatorAddress, address _collectionAddress, uint256 _useCase) external view returns (address);

    /**
     * @notice Returns the most recent delegator for a specific use case on a specific NFT collection given a delegation Address
     */

    function retrieveMostRecentDelegator(address _delegationAddress, address _collectionAddress, uint256 _useCase) external view returns (address);

    /**
     * @notice Returns the status of a delegation given the delegator address as well as the delegation address
     */

    function retrieveGlobalStatusOfDelegation(address _delegatorAddress, address _collectionAddress, address _delegationAddress, uint256 _useCase) external view returns (bool);

    /**
     * @notice Returns the status of a delegation given the delegator address, the collection address, the delegation address as well as a specific token id
     */

    function retrieveTokenStatus(address _delegatorAddress, address _collectionAddress, address _delegationAddress, uint256 _useCase, uint256 _tokenId) external view returns (bool);

    /**
     * @notice Checks if the delegation address performing actions is the most recent delegated by the specific delegator
     */

    function retrieveStatusOfMostRecentDelegation(address _delegatorAddress, address _collectionAddress, address _delegationAddress, uint256 _useCase) external view returns (bool);

     /**
     * @notice Checks if a delegator granted subdelegation status to an Address
     */

    function retrieveSubDelegationStatus(address _delegatorAddress, address _collectionAddress, address _delegationAddress) external view returns (bool);

     /**
     * @notice Checks the status of an active delegator for a delegation Address
     */

    function retrieveStatusOfActiveDelegator(address _delegatorAddress, address _collectionAddress, address _delegationAddress, uint256 _date, uint256 _useCase) external view returns (bool);

    /**
     * @notice This function checks the Consolidation status between 2 addresses
     */

    function checkConsolidationStatus(address _wallet1, address _wallet2, address _collectionAddress) external view returns (bool);

}