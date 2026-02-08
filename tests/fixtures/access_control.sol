// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControlVulnerable
 * @dev Test contract with SWC-105/SWC-106 access control vulnerabilities
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */
contract AccessControlVulnerable {
    address public owner;
    mapping(address => bool) public admins;
    mapping(address => uint256) public balances;
    bool public paused;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AdminAdded(address indexed admin);
    event Withdrawal(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    /**
     * @dev VULNERABLE: Missing access control on sensitive function
     * @notice Anyone can call this function and become owner
     */
    function setOwner(address newOwner) external {
        // VULNERABILITY: No access control - anyone can become owner
        owner = newOwner;
        emit OwnershipTransferred(msg.sender, newOwner);
    }

    /**
     * @dev VULNERABLE: tx.origin for authorization (SWC-115)
     * @notice tx.origin can be manipulated via phishing attacks
     */
    function transferOwnership(address newOwner) external {
        // VULNERABILITY: Using tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    /**
     * @dev VULNERABLE: Unprotected self-destruct (SWC-106)
     */
    function destroy() external {
        // VULNERABILITY: No access control on selfdestruct
        selfdestruct(payable(msg.sender));
    }

    /**
     * @dev VULNERABLE: Initialize function can be called multiple times
     */
    bool private initialized;

    function initialize(address _owner) external {
        // VULNERABILITY: Missing initialized check
        owner = _owner;
        initialized = true;
    }

    /**
     * @dev VULNERABLE: Default visibility (should be external/public explicit)
     */
    function withdrawAll() public {
        // VULNERABILITY: No access control on withdrawal
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
        emit Withdrawal(msg.sender, balance);
    }

    /**
     * @dev VULNERABLE: Weak admin check
     */
    function addAdmin(address admin) external {
        // VULNERABILITY: Any admin can add more admins without owner approval
        require(admins[msg.sender], "Not admin");
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    /**
     * @dev VULNERABLE: Signature replay (SWC-121)
     */
    function executeWithSignature(
        address to,
        uint256 amount,
        bytes memory signature
    ) external {
        // VULNERABILITY: No nonce, signature can be replayed
        bytes32 message = keccak256(abi.encodePacked(to, amount));
        address signer = recoverSigner(message, signature);
        require(signer == owner, "Invalid signature");
        payable(to).transfer(amount);
    }

    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }

    receive() external payable {}
}
