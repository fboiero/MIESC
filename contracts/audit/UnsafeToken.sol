// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title UnsafeToken
 * @notice ERC20-like token with multiple vulnerabilities
 * @dev Contains integer issues, unchecked returns, and logic flaws
 */
contract UnsafeToken {
    string public name = "Unsafe Token";
    string public symbol = "UNSAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;
    bool public paused;
    uint256 public maxSupply = 1000000 * 10**18;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        owner = msg.sender;
        // VULNERABILITY: Initial mint to deployer without event
        balanceOf[msg.sender] = 100000 * 10**18;
        totalSupply = 100000 * 10**18;
    }

    // VULNERABILITY 1: Missing zero address check
    function transfer(address to, uint256 amount) public returns (bool) {
        // Missing: require(to != address(0), "Transfer to zero address");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // VULNERABILITY 2: Approve race condition (no decrease then increase pattern)
    function approve(address spender, uint256 amount) public returns (bool) {
        // VULNERABLE: Classic approve race condition
        // Should first set to 0, then to new value
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // VULNERABILITY 3: Missing return value check on transferFrom
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    // VULNERABILITY 4: Unrestricted mint function
    function mint(address to, uint256 amount) public {
        // Missing: require(msg.sender == owner, "Not owner");
        // ANYONE can mint tokens!
        require(totalSupply + amount <= maxSupply, "Exceeds max supply");

        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // VULNERABILITY 5: Unrestricted burn from any address
    function burnFrom(address from, uint256 amount) public {
        // Missing proper authorization!
        // Should check allowance or ownership
        require(balanceOf[from] >= amount, "Insufficient balance");

        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    // VULNERABILITY 6: Unsafe external call in token transfer hook
    function transferWithCallback(address to, uint256 amount, bytes calldata data) public returns (bool) {
        require(transfer(to, amount), "Transfer failed");

        // VULNERABLE: Arbitrary external call
        if (data.length > 0) {
            (bool success, ) = to.call(data);
            // Not checking success! And allows arbitrary code execution
        }

        return true;
    }

    // VULNERABILITY 7: Block gas limit DoS in batch transfer
    function batchTransfer(address[] calldata recipients, uint256 amount) public {
        // VULNERABLE: Unbounded loop can exceed gas limit
        for (uint256 i = 0; i < recipients.length; i++) {
            transfer(recipients[i], amount);
        }
    }

    // VULNERABILITY 8: Timestamp manipulation dependency
    function timeLock() public view returns (bool) {
        // VULNERABLE: block.timestamp can be manipulated by miners
        return block.timestamp % 2 == 0;
    }

    // VULNERABILITY 9: Weak randomness
    function lottery(uint256 guess) public view returns (bool) {
        // VULNERABLE: Predictable "randomness"
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao,
            msg.sender
        ))) % 100;

        return guess == random;
    }

    // Admin functions
    function pause() public {
        require(msg.sender == owner, "Not owner");
        paused = true;
    }

    function unpause() public {
        require(msg.sender == owner, "Not owner");
        paused = false;
    }

    // VULNERABILITY 10: Ether locked in contract with no withdraw
    receive() external payable {
        // Contract accepts ETH but has no way to withdraw it!
    }
}
