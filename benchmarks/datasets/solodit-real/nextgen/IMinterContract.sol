// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

interface IMinterContract {

    // retrieve if the contract is minter contract
    function isMinterContract() external view returns (bool);

    // retrieve the public end time of a sale
    function getEndTime(uint256 _collectionID) external view returns (uint);

    // retrieve auction end time
    function getAuctionEndTime(uint256 _tokenId) external view returns (uint);

    // retrieve auction status
    function getAuctionStatus(uint256 _tokenId) external view  returns (bool);
    
}