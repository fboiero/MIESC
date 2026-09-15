pragma solidity ^0.8.0;
import "./Base.sol";
contract Derived is Base {
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.call{value: amount}("");
    }
}
