// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice CONTRATO VULNERABLE - Solo para demostración académica
 * @dev Contiene múltiples vulnerabilidades intencionales:
 *      - Reentrancy
 *      - Integer overflow/underflow (pre-0.8.0 logic)
 *      - Acceso no restringido
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Depósito de fondos
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice VULNERABLE: Reentrancy clásica
    /// @dev State change DESPUÉS de external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: External call antes de actualizar estado
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // VULNERABLE: Estado actualizado DESPUÉS del call
        balances[msg.sender] -= amount;
    }

    /// @notice VULNERABLE: Función administrativa sin restricción
    /// @dev Cualquiera puede llamar esta función
    function emergencyWithdraw() external {
        // VULNERABLE: Sin modifier onlyOwner
        payable(msg.sender).transfer(address(this).balance);
    }

    /// @notice VULNERABLE: Delegatecall a dirección controlada por usuario
    function delegateExecute(address target, bytes calldata data) external {
        // VULNERABLE: Delegatecall permite sobrescribir storage
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    /// @notice Balance del contrato
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
