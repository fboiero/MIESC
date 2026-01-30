// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SafeCounter - A simple counter with basic access control
 * @notice This contract demonstrates a reasonably secure implementation
 */
contract SafeCounter {
    uint256 private _count;
    address public owner;
    
    event CountIncremented(uint256 newCount);
    event CountDecremented(uint256 newCount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function increment() external onlyOwner {
        _count += 1;
        emit CountIncremented(_count);
    }
    
    function decrement() external onlyOwner {
        require(_count > 0, "Counter at zero");
        _count -= 1;
        emit CountDecremented(_count);
    }
    
    function getCount() external view returns (uint256) {
        return _count;
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
