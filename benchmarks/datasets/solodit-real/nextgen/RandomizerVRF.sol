// SPDX-License-Identifier: MIT

/**
 *
 *  @title: NextGen Randomizer Contract VRF
 *  @date: 18-October-2023 
 *  @version: 1.8
 *  @author: 6529 team
 */

pragma solidity ^0.8.19;

import "./VRFCoordinatorV2Interface.sol";
import "./VRFConsumerBaseV2.sol";
import "./Ownable.sol";
import "./INextGenCore.sol";
import "./INextGenAdmins.sol";

contract NextGenRandomizerVRF is VRFConsumerBaseV2, Ownable {
    event RequestFulfilled(uint256 requestId, uint256[] randomWords);

    VRFCoordinatorV2Interface public COORDINATOR;

    // chainlink data
    uint64 s_subscriptionId;
    bytes32 public keyHash = 0x79d3d8832d904592c0bf9818b621522c988bb8b0c05cdc3b15aea1b6e8db0c15;
    uint32 public callbackGasLimit = 40000;
    uint16 public requestConfirmations = 3;
    uint32 public numWords = 1;

    mapping(uint256 => uint256) public tokenIdToCollection;
    mapping(uint256 => uint256) public tokenToRequest;
    mapping(uint256 => uint256) public requestToToken;

    address gencore;
    INextGenCore public gencoreContract;
    INextGenAdmins private adminsContract;

    constructor(uint64 subscriptionId, address vrfCoordinator, address _gencore, address _adminsContract) VRFConsumerBaseV2(vrfCoordinator) {
        COORDINATOR = VRFCoordinatorV2Interface(vrfCoordinator);
        s_subscriptionId = subscriptionId;
        gencore = _gencore;
        gencoreContract = INextGenCore(_gencore);
        adminsContract = INextGenAdmins(_adminsContract);
    }

    modifier FunctionAdminRequired(bytes4 _selector) {
      require(adminsContract.retrieveFunctionAdmin(msg.sender, _selector) == true || adminsContract.retrieveGlobalAdmin(msg.sender) == true , "Not allowed");
      _;
    }

    function requestRandomWords(uint256 tokenid) public {
        require(msg.sender == gencore);
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,  
            numWords
        );
        tokenToRequest[tokenid] = requestId;
        requestToToken[requestId] = tokenid;
    }

    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        gencoreContract.setTokenHash(tokenIdToCollection[requestToToken[_requestId]], requestToToken[_requestId], bytes32(abi.encodePacked(_randomWords,requestToToken[_requestId])));
        emit RequestFulfilled(_requestId, _randomWords);
    }

    // function that calculates the random hash and returns it to the gencore contract
    function calculateTokenHash(uint256 _collectionID, uint256 _mintIndex, uint256 _saltfun_o) public {
        require(msg.sender == gencore);
        tokenIdToCollection[_mintIndex] = _collectionID;
        requestRandomWords(_mintIndex);
    }

    // function to update callbackGasLimit & keyHash

    function updatecallbackGasLimitAndkeyHash(uint32 _callbackGasLimit, bytes32 _keyHash) public FunctionAdminRequired(this.updatecallbackGasLimitAndkeyHash.selector){
        callbackGasLimit = _callbackGasLimit;
        keyHash = _keyHash;
    }

    // function to change the requests other data

    function updateAdditionalData(uint64 _s_subscriptionId, uint32 _numWords, uint16 _requestConfirmations) public FunctionAdminRequired(this.updateAdditionalData.selector){
        s_subscriptionId = _s_subscriptionId;
        numWords = _numWords;
        requestConfirmations = _requestConfirmations;
    }

     // function to update contracts

    function updateAdminContract(address _newadminsContract) public FunctionAdminRequired(this.updateAdminContract.selector) {
        require(INextGenAdmins(_newadminsContract).isAdminContract() == true, "Contract is not Admin");
        adminsContract = INextGenAdmins(_newadminsContract);
    }

    function updateCoreContract(address _gencore) public FunctionAdminRequired(this.updateCoreContract.selector) { 
        gencore = _gencore;
        gencoreContract = INextGenCore(_gencore);
    }

    // get randomizer contract status
    function isRandomizerContract() external view returns (bool) {
        return true;
    }

}