# CAPÍTULO 3 – MARCO TEÓRICO TÉCNICO

## 3.1 Arquitectura de la Máquina Virtual de Ethereum (EVM)

### 3.1.1 Fundamentos de la EVM

La **Ethereum Virtual Machine (EVM)** es una máquina de estados cuasi-Turing completa que ejecuta bytecode en un entorno determinístico y aislado. Diseñada por Gavin Wood en 2014, la EVM constituye el runtime environment para smart contracts en Ethereum y cadenas compatibles.

**Características Fundamentales:**

- **Modelo de stack-based**: Máquina de pila con profundidad máxima de 1024 elementos
- **Word size**: 256 bits (32 bytes) para operaciones nativas
- **Memoria volátil**: Expansion dinámica durante ejecución (costo cuadrático en gas)
- **Storage persistente**: Key-value store de 256 bits mapeado a la blockchain
- **Determinismo**: Mismos inputs producen idénticos outputs en cualquier nodo

### 3.1.2 Ciclo de Ejecución

```
┌──────────────────────────────────────────────────────────────┐
│                   CICLO DE EJECUCIÓN EVM                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. TRANSACTION SUBMISSION                                    │
│     └─> EOA firma transacción con private key               │
│                                                               │
│  2. TRANSACTION VALIDATION                                    │
│     └─> Verificación de nonce, saldo, signature             │
│                                                               │
│  3. GAS CALCULATION                                           │
│     └─> gas_limit * gas_price reservado del sender          │
│                                                               │
│  4. CODE EXECUTION                                            │
│     ├─> Cargar bytecode del contract address                │
│     ├─> Inicializar stack, memory, storage                  │
│     └─> Ejecutar opcodes secuencialmente                    │
│                                                               │
│  5. STATE CHANGES                                             │
│     └─> Modificaciones committed a state trie               │
│                                                               │
│  6. GAS REFUND                                                │
│     └─> Gas no consumido devuelto al sender                 │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 3.1.3 Componentes de la EVM

**Stack (Pila de Ejecución):**
- Estructura LIFO (Last-In-First-Out)
- Tamaño máximo: 1024 elementos de 256 bits
- Operaciones: PUSH, POP, DUP, SWAP
- Stack too deep error: Limitación crítica para compiladores

**Memory (Memoria Volátil):**
- Byte-array lineal direccionable
- Expansión dinámica con costo cuadrático
- Limpiada al finalizar la transacción
- Operaciones: MLOAD, MSTORE, MSTORE8

**Storage (Almacenamiento Persistente):**
- Mapping 256-bit → 256-bit persistente en blockchain
- Costo de escritura: 20,000 gas (primera escritura), 5,000 gas (modificación)
- Operaciones: SLOAD, SSTORE
- **Storage slots**: Cada variable ocupa un slot de 32 bytes

**Calldata:**
- Datos de entrada de la transacción (inmutables)
- Acceso read-only con bajo costo de gas
- Operaciones: CALLDATALOAD, CALLDATACOPY

### 3.1.4 Modelo de Gas

El gas es la unidad de medida computacional en Ethereum, diseñado para:
1. Prevenir denial-of-service mediante loops infinitos
2. Compensar a mineros/validadores por computación
3. Priorizar transacciones (fee market)

**Categorías de Costo:**

| Operación | Gas | Ejemplo |
|-----------|-----|---------|
| Aritmética básica | 3-5 gas | ADD, MUL, SUB |
| Criptografía | 2,000+ gas | KECCAK256 |
| Storage write | 20,000 gas | SSTORE (cold) |
| Storage read | 2,100 gas | SLOAD (cold) |
| Call externo | 2,600+ gas | CALL, DELEGATECALL |
| Contract creation | 32,000 gas | CREATE, CREATE2 |

**EIP-2929 (Berlin) - Access Lists:**
- Introducción de **warm** vs **cold** storage access
- Cold: Primera lectura/escritura en transacción (costo completo)
- Warm: Accesos subsiguientes (costo reducido ~100 gas)

### 3.1.5 Opcodes Relevantes para Seguridad

**Opcodes de Control de Flujo:**

```solidity
// JUMP / JUMPI - Saltos incondicionales/condicionales
// Vulnerabilidad: Jump-to-arbitrary-location (mitigado en Solidity)
JUMPDEST     // Destino válido de salto
JUMP         // Salto incondicional
JUMPI        // Salto condicional
```

**Opcodes de Llamadas Externas:**

```solidity
CALL         // Llamada con gas forwarding
DELEGATECALL // Ejecutar código externo en contexto actual (storage collision risk)
STATICCALL   // Llamada read-only (no state changes)
CALLCODE     // Deprecado (usar DELEGATECALL)
```

**Opcodes de Contexto:**

```solidity
CALLER       // msg.sender
ORIGIN       // tx.origin (phishing risk)
ADDRESS      // address(this)
BALANCE      // address.balance
SELFBALANCE  // balance of current contract
```

## 3.2 Evolución de Estándares ERC

### 3.2.1 ERC-20: Fungible Tokens

**Especificación:** EIP-20 (2015)
**Propósito:** Interfaz estándar para tokens intercambiables

**Funciones Esenciales:**

```solidity
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
```

**Vulnerabilidades Históricas:**

1. **approve() race condition (SWC-114):**
   ```solidity
   // Alice aprueba 100 tokens a Bob
   token.approve(bob, 100);
   // Alice cambia aprobación a 50
   // Bob front-runs y gasta 100, luego gasta 50 adicionales
   token.approve(bob, 50);
   ```
   **Mitigación:** `increaseAllowance()` / `decreaseAllowance()`

2. **Missing return value check:**
   ```solidity
   // Algunos tokens no retornan bool (ej: USDT)
   token.transfer(recipient, amount); // Puede fallar silenciosamente
   ```
   **Mitigación:** SafeERC20 wrapper (OpenZeppelin)

### 3.2.2 ERC-721: Non-Fungible Tokens (NFTs)

**Especificación:** EIP-721 (2018)
**Propósito:** Tokens únicos con identificador individual

**Funciones Clave:**

```solidity
interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}
```

**Patrón de Seguridad: onERC721Received**

```solidity
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
```

**Vulnerabilidades Comunes:**

1. **Reentrancy en safeTransferFrom:**
   ```solidity
   // safeTransferFrom llama a onERC721Received en el receptor
   // Si receptor es malicioso, puede re-entrar antes de state update
   function safeTransferFrom(address from, address to, uint256 tokenId) external {
       _transfer(from, to, tokenId); // State update ANTES de call externo
       _checkOnERC721Received(from, to, tokenId, "");
   }
   ```

2. **Missing ownership validation:**
   ```solidity
   // Permitir transfer sin verificar ownerOf
   function transferFrom(address from, address to, uint256 tokenId) external {
       require(ownerOf(tokenId) == from, "Not owner"); // CRITICAL
   }
   ```

### 3.2.3 ERC-1155: Multi-Token Standard

**Especificación:** EIP-1155 (2018)
**Propósito:** Batch operations para fungibles + non-fungibles

**Ventajas:**

- Reducción de gas mediante batch transfers
- Mixto de fungibles (cantidad) y NFTs (ID único)
- Ampliamente usado en gaming y metaversos

```solidity
interface IERC1155 {
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
    function balanceOf(address account, uint256 id) external view returns (uint256);
    function balanceOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (uint256[] memory);
}
```

### 3.2.4 ERC-4626: Tokenized Vault Standard

**Especificación:** EIP-4626 (2022)
**Propósito:** Interfaz estandarizada para yield-bearing vaults

**Arquitectura:**

```solidity
interface IERC4626 is IERC20 {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);

    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);

    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function mint(uint256 shares, address receiver) external returns (uint256 assets);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
}
```

**Vulnerabilidad Crítica: Inflation Attack**

```solidity
// Atacante deposita 1 wei, obtiene 1 share
vault.deposit(1, attacker);

// Atacante dona directamente al vault (bypass de deposit)
asset.transfer(address(vault), 10000e18);

// Siguiente depositor deposita 5000e18
// Shares calculadas: (5000e18 * 1) / 10000e18 = 0 shares (redondeado)
vault.deposit(5000e18, victim); // Victim recibe 0 shares!
```

**Mitigación:**

```solidity
// OpenZeppelin ERC4626 con virtual shares
constructor() {
    _mint(address(0), 1e6); // Burn initial shares para evitar inflación
}
```

### 3.2.5 ERC-4337: Account Abstraction

**Especificación:** EIP-4337 (2023)
**Propósito:** Smart contract wallets sin cambios de consenso

**Componentes:**

1. **UserOperation:** Pseudo-transacción con intención del usuario
2. **Bundler:** Nodo que agrupa UserOps en transacción única
3. **EntryPoint:** Contract singleton que ejecuta UserOps
4. **Smart Account:** Wallet contract del usuario
5. **Paymaster:** Sponsor de gas fees (opcional)

**Vectores de Ataque:**

- **Griefing attacks:** UserOps que pasan validation pero fallan execution
- **Storage access violations:** Acceso a storage no autorizado en validation
- **DoS via unbounded gas:** Validation phase con consumo excesivo

## 3.3 Patrones de Seguridad y Vulnerabilidades

### 3.3.1 Reentrancy (SWC-107)

**Descripción:** Llamadas externas antes de actualizar estado permiten re-entrada.

**Patrón Vulnerable:**

```solidity
mapping(address => uint256) public balances;

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");

    // VULNERABLE: External call antes de state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");

    // State update DESPUÉS de external call
    balances[msg.sender] -= amount;
}
```

**Exploit:**

```solidity
contract Attacker {
    VulnerableContract victim;
    uint256 public attackCount;

    receive() external payable {
        if (attackCount < 10) {
            attackCount++;
            victim.withdraw(1 ether); // Re-entra antes de state update
        }
    }

    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw(1 ether);
    }
}
```

**Mitigaciones:**

1. **Checks-Effects-Interactions Pattern:**
   ```solidity
   function withdraw(uint256 amount) external {
       require(balances[msg.sender] >= amount); // Checks
       balances[msg.sender] -= amount;          // Effects
       payable(msg.sender).transfer(amount);    // Interactions
   }
   ```

2. **Reentrancy Guard (OpenZeppelin):**
   ```solidity
   uint256 private _status;
   modifier nonReentrant() {
       require(_status != 2, "ReentrancyGuard: reentrant call");
       _status = 2;
       _;
       _status = 1;
   }
   ```

3. **Pull over Push:**
   ```solidity
   mapping(address => uint256) public pendingWithdrawals;

   function initiateWithdrawal(uint256 amount) external {
       balances[msg.sender] -= amount;
       pendingWithdrawals[msg.sender] += amount;
   }

   function claimWithdrawal() external {
       uint256 amount = pendingWithdrawals[msg.sender];
       pendingWithdrawals[msg.sender] = 0;
       payable(msg.sender).transfer(amount);
   }
   ```

### 3.3.2 Access Control (SWC-105)

**Descripción:** Funciones privilegiadas sin restricciones de autorización.

**Patrón Vulnerable:**

```solidity
address public owner;

function withdrawAll() external {
    // VULNERABLE: Sin validación de caller
    payable(msg.sender).transfer(address(this).balance);
}

function emergencyStop() external {
    // VULNERABLE: Cualquiera puede pausar el contrato
    paused = true;
}
```

**Mitigaciones:**

```solidity
// OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureContract is Ownable {
    function withdrawAll() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}

// OpenZeppelin AccessControl (Role-Based)
import "@openzeppelin/contracts/access/AccessControl.sol";

contract MultiRoleContract is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function criticalOperation() external onlyRole(ADMIN_ROLE) {
        // Solo admins
    }
}
```

### 3.3.3 Integer Overflow/Underflow (SWC-101)

**Contexto Histórico:**

- **Solidity <0.8.0:** Sin protección automática contra overflows
- **Solidity ≥0.8.0:** Reverts automáticos en overflow/underflow

**Patrón Vulnerable (Solidity 0.7.x):**

```solidity
function transfer(address to, uint256 amount) external {
    // Sin SafeMath: overflow silencioso
    balances[msg.sender] -= amount; // Underflow si amount > balance
    balances[to] += amount;          // Overflow posible
}
```

**Vulnerabilidad en Unchecked Blocks (Solidity 0.8+):**

```solidity
function unsafeTransfer(address to, uint256 amount) external {
    unchecked {
        // VULNERABLE: Overflow explícitamente permitido
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

### 3.3.4 Uninitialized Proxy Storage (SWC-109)

**Descripción:** Proxies con constructor sin inicialización permiten takeover.

**Patrón Vulnerable:**

```solidity
// Implementation contract
contract LogicV1 {
    address public owner;

    // VULNERABLE: Constructor no se ejecuta en proxy
    constructor() {
        owner = msg.sender;
    }
}

// Proxy contract
contract Proxy {
    address public implementation;

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

**Exploit:**

```solidity
// Atacante puede inicializar el logic contract directamente
LogicV1 logic = LogicV1(proxyAddress);
logic.initialize(attacker); // Owner ahora es attacker
```

**Mitigación:**

```solidity
// OpenZeppelin Initializable
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract LogicV1 is Initializable {
    address public owner;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // Previene inicialización del implementation
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

### 3.3.5 Delegatecall Storage Collision

**Descripción:** DELEGATECALL ejecuta código en contexto del caller, compartiendo storage slots.

**Patrón Vulnerable:**

```solidity
// Proxy storage layout
contract Proxy {
    address public implementation; // Slot 0
    address public owner;          // Slot 1

    function upgrade(address newImpl) external {
        require(msg.sender == owner);
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// Malicious implementation
contract MaliciousLogic {
    address public attacker;  // Slot 0 - colisiona con implementation!
    address public dummy;     // Slot 1 - colisiona con owner!

    function attack() external {
        attacker = msg.sender; // Sobrescribe implementation en proxy
    }
}
```

**Exploit:**

```solidity
// 1. Deployer llama upgrade(maliciousLogic)
// 2. Attacker llama proxy.attack() via delegatecall
// 3. attacker variable sobrescribe implementation en proxy
// 4. Proxy ahora apunta a dirección controlada por attacker
```

**Mitigación:**

```solidity
// EIP-1967: Standard Proxy Storage Slots
// Usa hash de string para slots no colisionables
bytes32 private constant _IMPLEMENTATION_SLOT =
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
```

### 3.3.6 Oracle Manipulation

**Descripción:** Precios de oráculos manipulables mediante flash loans.

**Patrón Vulnerable:**

```solidity
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract VulnerableLending {
    IUniswapV2Pair public priceOracle;

    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = priceOracle.getReserves();
        // VULNERABLE: Spot price manipulable en single block
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = userCollateral[msg.sender] * getPrice();
        require(collateralValue >= amount * 1.5e18, "Insufficient collateral");
        // ...
    }
}
```

**Exploit con Flash Loan:**

```solidity
1. Attacker toma flash loan de 10M USDC
2. Attacker compra masivamente tokenA en Uniswap (manipula ratio reserves)
3. getPrice() ahora retorna precio inflado
4. Attacker deposita poco collateral pero borrow masivo (debido a precio inflado)
5. Attacker repaga flash loan con ganancias del borrow
```

**Mitigaciones:**

```solidity
// 1. TWAP (Time-Weighted Average Price)
contract SecureLending {
    uint256 public priceAccumulator;
    uint256 public lastUpdateTime;
    uint256 public constant PERIOD = 1 hours;

    function updatePrice() external {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 timeElapsed = block.timestamp - lastUpdateTime;
        priceAccumulator += (reserve1 * 1e18 / reserve0) * timeElapsed;
        lastUpdateTime = block.timestamp;
    }

    function getPrice() public view returns (uint256) {
        return priceAccumulator / PERIOD;
    }
}

// 2. Chainlink Price Feeds (Descentralizado)
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract ChainlinkOracle {
    AggregatorV3Interface internal priceFeed;

    function getLatestPrice() public view returns (int) {
        (
            /*uint80 roundID*/,
            int price,
            /*uint startedAt*/,
            uint timeStamp,
            /*uint80 answeredInRound*/
        ) = priceFeed.latestRoundData();

        require(timeStamp > block.timestamp - 1 hours, "Stale price");
        return price;
    }
}
```

## 3.4 Frameworks de Auditoría y Técnicas de Análisis

### 3.4.1 Análisis Estático

**Definición:** Inspección de código fuente sin ejecutar, mediante análisis sintáctico y semántico.

**Técnicas:**

1. **Abstract Syntax Tree (AST) Analysis:**
   - Parseo de código Solidity a representación en árbol
   - Identificación de patrones sintácticos peligrosos

2. **Control Flow Graph (CFG):**
   - Modelado de flujos de ejecución posibles
   - Detección de unreachable code y dead branches

3. **Data Flow Analysis:**
   - Taint tracking: propagación de datos no confiables
   - Reaching definitions: análisis de asignaciones

4. **Symbolic Execution:**
   - Exploración de paths con variables simbólicas
   - Generación de constraints para SMT solvers

**Ventajas:**
- Cobertura completa del código
- Rápido (segundos a minutos)
- No requiere deployment

**Limitaciones:**
- Falsos positivos elevados (30-50%)
- No valida lógica de negocio
- Dificultad con código obfuscado

### 3.4.2 Análisis Dinámico (Fuzzing)

**Definición:** Ejecución de código con inputs generados automáticamente para encontrar bugs.

**Tipos:**

1. **Property-Based Fuzzing:**
   - Definición de invariantes que deben cumplirse
   - Generación de secuencias de transacciones
   - Detección de violaciones de propiedades

2. **Coverage-Guided Fuzzing:**
   - Instrumentación de código para medir cobertura
   - Mutación de inputs para maximizar paths explorados
   - Basado en feedback de ejecución

**Ventajas:**
- Encuentra bugs reales (no falsos positivos)
- Descubre vulnerabilidades de lógica compleja
- No requiere especificación formal completa

**Limitaciones:**
- Cobertura limitada por tiempo de ejecución
- Difícil alcanzar estados complejos (deep states)
- No garantiza ausencia de bugs

### 3.4.3 Verificación Formal

**Definición:** Prueba matemática de correctitud mediante lógicas formales.

**Técnicas:**

1. **Model Checking:**
   - Exploración exhaustiva de espacio de estados finito
   - Verificación de temporal logic properties (LTL, CTL)

2. **Theorem Proving:**
   - Demostración interactiva de propiedades
   - Requiere anotaciones y lemmas del usuario

3. **Symbolic Execution con SMT:**
   - Generación de fórmulas lógicas para cada path
   - Resolución mediante SMT solvers (Z3, CVC5)

**Ventajas:**
- Garantías matemáticas de correctitud
- Cobertura completa de casos edge
- Encuentra bugs sutiles indetectables por testing

**Limitaciones:**
- Costo computacional alto (horas a días)
- Requiere especificaciones formales detalladas
- Expertise especializada necesaria

## 3.5 Clasificación SWC y CWE

### 3.5.1 Smart Contract Weakness Classification (SWC)

**Origen:** Iniciativa de Consensys para estandarizar clasificación de vulnerabilidades EVM.

**Categorías Principales:**

| SWC ID | Nombre | Descripción | Severidad |
|--------|--------|-------------|-----------|
| SWC-101 | Integer Overflow/Underflow | Aritmética sin bounds checking | Alta |
| SWC-105 | Unprotected Ether Withdrawal | Funciones de retiro sin access control | Crítica |
| SWC-107 | Reentrancy | External calls antes de state updates | Crítica |
| SWC-109 | Uninitialized Storage Pointer | Variables storage sin inicializar | Alta |
| SWC-114 | Transaction Order Dependence | Race conditions en approve() | Media |
| SWC-115 | Authorization through tx.origin | Uso de tx.origin para auth | Alta |
| SWC-120 | Weak Sources of Randomness | Uso de block.timestamp o blockhash | Media |
| SWC-131 | Presence of Unused Variables | Dead code que indica refactor incompleto | Baja |

**Mapeo SWC → Herramientas de Detección:**

- **SWC-107 (Reentrancy):** Slither `reentrancy-eth`, Mythril, Echidna properties
- **SWC-105 (Access Control):** Slither `unprotected-functions`, Certora CVL rules
- **SWC-101 (Overflow):** Slither `overflow` (pre-0.8), Foundry fuzz tests

### 3.5.2 Common Weakness Enumeration (CWE)

**Origen:** MITRE, clasificación general de debilidades de software.

**CWEs Relevantes para Smart Contracts:**

| CWE ID | Nombre | Relación con Smart Contracts |
|--------|--------|------------------------------|
| CWE-284 | Improper Access Control | SWC-105, funciones sin restricciones |
| CWE-362 | Concurrent Execution (Race Condition) | SWC-114, front-running |
| CWE-369 | Divide by Zero | Validaciones faltantes en divisiones |
| CWE-400 | Uncontrolled Resource Consumption | Gas griefing, DoS |
| CWE-665 | Improper Initialization | SWC-109, proxies sin inicializar |
| CWE-682 | Incorrect Calculation | Errores de redondeo, precision loss |
| CWE-703 | Improper Check of Exceptional Conditions | Unchecked return values |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | DELEGATECALL a addresses no confiables |

## 3.6 Síntesis del Capítulo

Este capítulo establece los fundamentos técnicos para comprender:

1. **Arquitectura EVM:** Stack-based machine, gas model, opcodes críticos
2. **Estándares ERC:** De ERC-20 a ERC-4337, con vulnerabilidades específicas
3. **Patrones de Vulnerabilidades:** Reentrancy, access control, overflow, proxy issues, oracle manipulation
4. **Técnicas de Análisis:** Estático, dinámico (fuzzing), verificación formal
5. **Clasificaciones:** SWC Registry y CWE mapping

Estos conceptos son la base para entender el estado del arte (Capítulo 4) y la metodología propuesta (Capítulo 5).

---

**Referencias del Capítulo**

1. Wood, G. (2014). "Ethereum: A Secure Decentralised Generalised Transaction Ledger"
2. Buterin, V. (2021). "EIP-4337: Account Abstraction Using Alt Mempool"
3. Consensys. (2020). "Smart Contract Weakness Classification (SWC) Registry"
4. MITRE. (2023). "Common Weakness Enumeration (CWE)"
5. OpenZeppelin. (2023). "Contracts Documentation"
6. Trail of Bits. (2023). "Building Secure Contracts"
7. Atzei, N. et al. (2017). "A Survey of Attacks on Ethereum Smart Contracts (SoK)"
8. Luu, L. et al. (2016). "Making Smart Contracts Smarter"
