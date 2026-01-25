// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/**
 * @title ParityMultisig - Based on Parity Wallet Hack (2017)
 * @dev Recreation of the vulnerability that led to $30M+ ETH theft
 * Source: Historical vulnerability from Parity multisig wallet
 */
contract ParityMultisig {
    address public owner;
    mapping(address => bool) public isOwner;
    uint256 public required;
    address[] public owners;

    // VULNERABILITY 1: Unprotected initialization
    // Anyone can call initWallet and become owner
    function initWallet(address[] _owners, uint256 _required) public {
        // BUG: No check if already initialized!
        require(_required <= _owners.length);
        required = _required;

        for (uint i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
        }
        owner = _owners[0];
    }

    // VULNERABILITY 2: delegatecall to user-supplied address
    function execute(address _to, uint256 _value, bytes _data)
        public
        returns (bool)
    {
        require(isOwner[msg.sender]);
        // BUG: delegatecall preserves context, can modify storage
        return _to.delegatecall(_data);
    }

    function deposit() public payable {}

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title ParityKillLibrary - The second Parity bug
 * @dev Someone called kill() on the library, freezing $280M
 */
contract ParityWalletLibrary {
    address public owner;
    bool public initialized;

    // VULNERABILITY: Anyone could initialize the library contract
    function initWallet(address _owner) public {
        require(!initialized);
        owner = _owner;
        initialized = true;
    }

    // VULNERABILITY: kill function was public
    function kill(address _to) public {
        require(msg.sender == owner);
        selfdestruct(_to);
    }
}
