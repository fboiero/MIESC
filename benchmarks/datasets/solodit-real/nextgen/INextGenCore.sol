// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

interface INextGenCore {

    function retrievewereDataAdded(uint256 _collectionID) external view returns(bool);

    function viewTokensIndexMin(uint256 _collectionID) external view returns (uint256);

    function viewTokensIndexMax(uint256 _collectionID) external view returns (uint256);

    function viewCirSupply(uint256 _collectionID) external view returns (uint256);

    function airDropTokens(uint256 mintIndex, address _recipient, string memory _tokenData, uint256 _saltfun_o, uint256 _collectionID) external;

    function mint(uint256 mintIndex, address _mintingAddress , address _mintTo, string memory _tokenData, uint256 _saltfun_o, uint256 _collectionID, uint256 phase) external;

    function collectionFreezeStatus(uint256 _collectionID) external view returns(bool);

    function viewMaxAllowance(uint256 _collectionID) external view returns (uint256);

    function retrieveTokensMintedALPerAddress(uint256 _collectionID, address _address) external view returns(uint256);

    function retrieveTokensMintedPublicPerAddress(uint256 _collectionID, address _address) external view returns(uint256);

    function viewColIDforTokenID(uint256 _tokenid) external view returns (uint256);

    function burnToMint(uint256 mintIndex, uint256 _burnCollectionID, uint256 _tokenId, uint256 _mintCollectionID, uint256 _saltfun_o, address burner) external;

    function retrieveArtistAddress(uint256 _collectionID) external view returns(address);

    function setTokenHash(uint256 _collectionID, uint256 _mintIndex, bytes32 _hash) external;

    function retrieveTokenHash(uint256 _tokenid) external view returns(bytes32);

}