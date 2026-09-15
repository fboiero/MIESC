pragma solidity ^0.8.0;

contract Base {
    mapping(address => uint256) public balances;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
