// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

interface INextGenAdmins {

    // retrieve global admin
    function retrieveGlobalAdmin(address _address) external view returns(bool);

    // retrieve function admin
    function retrieveFunctionAdmin(address _address, bytes4 _selector) external view returns(bool);

    // retrieve collection admin
    function retrieveCollectionAdmin(address _address, uint256 _collectionID) external view returns(bool);

    // retrieve if the contract is admin contract
    function isAdminContract() external view returns (bool);

    // retrieve owner
    function owner() external view returns (address);

}