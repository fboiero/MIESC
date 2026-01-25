// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title IntegerVulnerabilities - Overflow/Underflow Examples
 * @dev Pre-Solidity 0.8 vulnerabilities (still relevant for legacy code)
 * Note: Using ^0.7.0 to demonstrate pre-SafeMath issues
 */
contract IntegerVulnerabilities {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // VULNERABILITY 1: Integer overflow
    function mint(address _to, uint256 _amount) public {
        // BUG: No overflow check pre-0.8
        // If totalSupply + _amount > 2^256, wraps to small number
        totalSupply += _amount;
        balances[_to] += _amount;
    }

    // VULNERABILITY 2: Integer underflow
    function burn(uint256 _amount) public {
        // BUG: If balance < _amount, underflows to huge number
        balances[msg.sender] -= _amount;
        totalSupply -= _amount;
    }

    // VULNERABILITY 3: Multiplication overflow
    function calculateReward(uint256 _stake, uint256 _rate) public pure returns (uint256) {
        // BUG: stake * rate can overflow
        return _stake * _rate / 100;
    }

    // VULNERABILITY 4: Array length manipulation
    uint256[] public values;

    function popValue() public {
        // BUG: Underflow if array is empty
        values.length--;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @title TimestampDependence - Block manipulation vulnerabilities
 */
contract TimestampDependence {
    uint256 public lastAction;
    mapping(address => uint256) public rewards;

    // VULNERABILITY: Miner-manipulable timestamp
    function claimDailyReward() public {
        // BUG: block.timestamp can be manipulated by miners (~15 seconds)
        require(block.timestamp >= lastAction + 1 days, "Too early");
        rewards[msg.sender] += 1 ether;
        lastAction = block.timestamp;
    }

    // VULNERABILITY: Weak randomness from block data
    function lottery() public payable {
        require(msg.value == 1 ether);

        // BUG: Predictable "randomness" - miners can manipulate
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.difficulty,
            msg.sender
        )));

        if (random % 10 == 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
