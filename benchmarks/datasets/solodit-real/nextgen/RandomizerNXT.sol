// SPDX-License-Identifier: MIT

/**
 *
 *  @title: NextGen Randomizer Contract
 *  @date: 18-October-2023 
 *  @version: 1.4
 *  @author: 6529 team
 */

pragma solidity ^0.8.19;

import "./IXRandoms.sol";
import "./INextGenAdmins.sol";
import "./Ownable.sol";
import "./INextGenCore.sol";

contract NextGenRandomizerNXT {

    IXRandoms public randoms;
    INextGenAdmins private adminsContract;
    INextGenCore public gencoreContract;
    address gencore;

    constructor(address _randoms, address _admin, address _gencore) {
        randoms = IXRandoms(_randoms);
        adminsContract = INextGenAdmins(_admin);
        gencore = _gencore;
        gencoreContract = INextGenCore(_gencore);
    }

    // certain functions can only be called by a global or function admin

    modifier FunctionAdminRequired(bytes4 _selector) {
      require(adminsContract.retrieveFunctionAdmin(msg.sender, _selector) == true || adminsContract.retrieveGlobalAdmin(msg.sender) == true , "Not allowed");
      _;
    }

    // update contracts if needed

    function updateRandomsContract(address _randoms) public FunctionAdminRequired(this.updateRandomsContract.selector) {
        randoms = IXRandoms(_randoms);
    }

    function updateAdminsContract(address _admin) public FunctionAdminRequired(this.updateAdminsContract.selector) {
        adminsContract = INextGenAdmins(_admin);
    }

    function updateCoreContract(address _gencore) public FunctionAdminRequired(this.updateCoreContract.selector) { 
        gencore = _gencore;
        gencoreContract = INextGenCore(_gencore);
    }

    // function that calculates the random hash and returns it to the gencore contract
    function calculateTokenHash(uint256 _collectionID, uint256 _mintIndex, uint256 _saltfun_o) public {
        require(msg.sender == gencore);
        bytes32 hash = keccak256(abi.encodePacked(_mintIndex, blockhash(block.number - 1), randoms.randomNumber(), randoms.randomWord()));
        gencoreContract.setTokenHash(_collectionID, _mintIndex, hash);
    }

    // get randomizer contract status
    function isRandomizerContract() external view returns (bool) {
        return true;
    }
    
}