// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title UncheckedMath - Demonstrates unchecked block risks
/// @notice Educational example of potential overflow issues
/// @dev While Solidity 0.8+ has built-in overflow checks, unchecked blocks bypass them
contract UncheckedMath {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        totalSupply = 1000000 * 10**18;
        balances[msg.sender] = totalSupply;
    }

    /// @notice VULNERABLE: Unchecked arithmetic can overflow
    /// @dev Missing validation allows balance manipulation
    function transfer(address to, uint256 amount) external {
        unchecked {
            // VULNERABILITY: No overflow check
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
    }

    /// @notice Batch transfer with unchecked loop
    /// @dev Gas optimization gone wrong
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        uint256 total;
        unchecked {
            // VULNERABILITY: total can overflow
            total = recipients.length * amount;
        }

        require(balances[msg.sender] >= total, "Insufficient balance");

        for (uint256 i = 0; i < recipients.length; ) {
            unchecked {
                balances[recipients[i]] += amount;
                ++i;
            }
        }

        unchecked {
            balances[msg.sender] -= total;
        }
    }
}
