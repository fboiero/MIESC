// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank - Ejemplo de contrato con múltiples vulnerabilidades
/// @notice Este contrato contiene vulnerabilidades intencionales para demostración
/// @dev NO USAR EN PRODUCCIÓN
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /// @notice Depositar fondos en el contrato
    function deposit() external payable {
        require(msg.value > 0, "Debe depositar algun valor");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice VULNERABLE: Reentrancy attack en withdraw
    /// @dev El balance se actualiza DESPUES de la transferencia
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Saldo insuficiente");

        // VULNERABILIDAD: external call antes de actualizar estado
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transferencia fallida");

        // El balance se actualiza DESPUES del call - VULNERABLE a reentrancy
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    /// @notice VULNERABLE: Sin control de acceso
    /// @dev Cualquiera puede llamar esta función
    function emergencyWithdraw() external {
        uint256 balance = address(this).balance;

        // VULNERABILIDAD: No hay verificación de que sea el owner
        payable(msg.sender).transfer(balance);
    }

    /// @notice VULNERABLE: Uso de tx.origin
    /// @dev Susceptible a phishing attacks
    function withdrawWithOrigin(uint256 amount) external {
        // VULNERABILIDAD: Usa tx.origin en lugar de msg.sender
        require(balances[tx.origin] >= amount, "Saldo insuficiente");

        balances[tx.origin] -= amount;
        payable(tx.origin).transfer(amount);
    }

    /// @notice VULNERABLE: Integer overflow (aunque Solidity 0.8+ tiene checks automáticos)
    /// @dev Con versiones anteriores esto causaría overflow
    function unsafeMint(address to, uint256 amount) external {
        // En Solidity < 0.8.0 esto podría causar overflow
        balances[to] += amount;
    }

    /// @notice VULNERABLE: Delegatecall a dirección controlada por usuario
    /// @dev Permite ejecutar código arbitrario en el contexto del contrato
    function delegateExecute(address target, bytes calldata data) external {
        // VULNERABILIDAD CRITICA: delegatecall con dirección no confiable
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall fallido");
    }

    /// @notice VULNERABLE: Timestamp dependency
    /// @dev Los mineros pueden manipular el timestamp
    function timeLock(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Saldo insuficiente");

        // VULNERABILIDAD: Depende del timestamp del bloque
        require(block.timestamp % 2 == 0, "Solo en bloques pares");

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /// @notice Ver balance del contrato
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Ver balance de un usuario
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /// @notice Versión SEGURA de withdraw (para comparación)
    function withdrawSecure(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Saldo insuficiente");

        // Checks-Effects-Interactions pattern
        balances[msg.sender] -= amount; // Update state FIRST

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transferencia fallida");

        emit Withdrawal(msg.sender, amount);
    }
}
