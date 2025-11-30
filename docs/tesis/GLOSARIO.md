# Glosario de Términos

---

## A

**Address (Dirección)**
Identificador único de 20 bytes (40 caracteres hexadecimales) que representa una cuenta de usuario o un smart contract en la blockchain Ethereum. Las direcciones comienzan con el prefijo "0x".

**Adapter (Adaptador)**
Patrón de diseño estructural que permite que interfaces incompatibles trabajen juntas. En MIESC, cada herramienta de seguridad se integra mediante un adaptador que normaliza su interfaz.

**Airdrop**
Distribución gratuita de tokens de criptomoneda a múltiples direcciones de billetera, generalmente como estrategia de marketing o distribución inicial.

**Análisis Estático**
Técnica de análisis de código que examina el programa sin ejecutarlo, identificando patrones potencialmente vulnerables mediante inspección del código fuente o bytecode.

**Arbitrage (Arbitraje)**
Práctica de aprovechar diferencias de precio de un activo entre diferentes mercados o exchanges para obtener ganancias.

**Auditoría de Smart Contract**
Proceso de revisión sistemática del código de un smart contract para identificar vulnerabilidades de seguridad, errores lógicos y posibles mejoras antes del despliegue.

---

## B

**Blockchain**
Estructura de datos distribuida que consiste en una cadena de bloques enlazados criptográficamente, donde cada bloque contiene un conjunto de transacciones verificadas.

**Block Explorer**
Aplicación web que permite visualizar información de la blockchain, incluyendo transacciones, bloques, direcciones y smart contracts.

**Bridge (Puente)**
Protocolo que permite la transferencia de activos digitales entre diferentes blockchains.

**Bytecode**
Código de bajo nivel resultante de la compilación de un smart contract en Solidity, ejecutado por la EVM.

---

## C

**Call**
Función de bajo nivel en Solidity que permite invocar funciones de otro contrato o enviar Ether, retornando un booleano indicando éxito o fracaso.

**Calldata**
Área de memoria de solo lectura donde se almacenan los datos de entrada de una función externa en Solidity.

**CEI Pattern (Checks-Effects-Interactions)**
Patrón de seguridad que establece el orden correcto de operaciones: primero verificar condiciones, luego modificar estado, y finalmente interactuar con contratos externos.

**Ciberdefensa**
Conjunto de capacidades, procesos y tecnologías para proteger sistemas informáticos, redes y datos contra ciberataques, con énfasis en infraestructuras críticas y defensa nacional.

**Consenso**
Mecanismo por el cual los nodos de una red blockchain acuerdan el estado válido del sistema.

---

## D

**DAO (Decentralized Autonomous Organization)**
Organización representada por reglas codificadas como smart contracts, donde las decisiones se toman mediante votación de los poseedores de tokens de gobernanza.

**DeFi (Decentralized Finance)**
Ecosistema de aplicaciones financieras construidas sobre blockchains que permiten servicios como préstamos, intercambios y derivados sin intermediarios tradicionales.

**Defense-in-Depth**
Estrategia de seguridad que implementa múltiples capas de controles defensivos independientes, de modo que si una capa falla, las demás continúan proporcionando protección.

**Delegatecall**
Función de bajo nivel en Solidity que ejecuta código de otro contrato en el contexto del contrato llamador, preservando msg.sender y el almacenamiento.

**Deploy (Despliegue)**
Proceso de publicar un smart contract en la blockchain, haciéndolo accesible para interacción.

---

## E

**EOA (Externally Owned Account)**
Cuenta controlada por una clave privada, a diferencia de las cuentas de contrato. Las transacciones solo pueden ser iniciadas por EOAs.

**ERC (Ethereum Request for Comments)**
Propuesta de estándar técnico para Ethereum que define interfaces comunes para tokens y contratos.

**ERC-20**
Estándar para tokens fungibles en Ethereum, definiendo funciones como transfer, approve y balanceOf.

**ERC-721**
Estándar para tokens no fungibles (NFTs) en Ethereum, donde cada token tiene un identificador único.

**Ether (ETH)**
Criptomoneda nativa de la red Ethereum, utilizada para pagar gas y como medio de intercambio.

**EVM (Ethereum Virtual Machine)**
Máquina virtual que ejecuta bytecode de smart contracts en todos los nodos de la red Ethereum, garantizando ejecución determinista.

**Event (Evento)**
Mecanismo en Solidity para emitir logs que son almacenados en la blockchain y pueden ser consultados por aplicaciones externas.

**Exploit**
Código o técnica que aprovecha una vulnerabilidad para comprometer la seguridad de un sistema.

---

## F

**Fallback Function**
Función especial en Solidity que se ejecuta cuando un contrato recibe Ether sin datos o cuando se llama una función inexistente.

**Flash Loan (Préstamo Flash)**
Préstamo sin colateral que debe ser devuelto dentro de la misma transacción blockchain. Usado legítimamente para arbitraje, pero también en ataques.

**Front-running**
Práctica de observar transacciones pendientes en el mempool y ejecutar una transacción propia antes para obtener ventaja económica.

**Fuzzing**
Técnica de testing que genera entradas aleatorias o semi-aleatorias para descubrir errores y vulnerabilidades en software.

---

## G

**Gas**
Unidad de medida del trabajo computacional requerido para ejecutar operaciones en la EVM. El costo en gas previene ataques de denegación de servicio.

**Gas Limit**
Cantidad máxima de gas que un usuario está dispuesto a pagar por una transacción.

**Gas Price**
Precio por unidad de gas que un usuario ofrece pagar, expresado en gwei (10^-9 ETH).

**Governance (Gobernanza)**
Sistema de reglas y procesos para la toma de decisiones en protocolos descentralizados, generalmente mediante votación de tokens.

---

## H

**Hallazgo**
Resultado de un análisis de seguridad que identifica una vulnerabilidad, debilidad o área de mejora en el código.

**Hash**
Función criptográfica que convierte datos de cualquier tamaño en una salida de tamaño fijo, utilizada extensivamente en blockchain para integridad y direccionamiento.

**Honeypot**
Contrato malicioso diseñado para parecer vulnerable y atraer víctimas que intentan explotarlo, pero que en realidad atrapa sus fondos.

---

## I

**Immutable (Inmutable)**
Propiedad de los smart contracts que indica que su código no puede ser modificado después del despliegue.

**Invariante**
Propiedad que debe mantenerse verdadera en todos los estados posibles del contrato, utilizada en verificación formal.

---

## L

**Layer 1 (L1)**
Blockchain base que procesa y finaliza transacciones en su propia red, como Ethereum mainnet.

**Layer 2 (L2)**
Solución de escalabilidad construida sobre una L1 que procesa transacciones fuera de la cadena principal para mayor throughput.

**LLM (Large Language Model)**
Modelo de inteligencia artificial entrenado en grandes cantidades de texto, capaz de generar y analizar lenguaje natural y código.

**Liquidity Pool**
Reserva de tokens bloqueados en un smart contract que facilita el trading descentralizado.

---

## M

**Mainnet**
Red principal de una blockchain donde se realizan transacciones con valor económico real.

**Mempool**
Área de memoria donde se almacenan transacciones pendientes antes de ser incluidas en un bloque.

**MEV (Maximal Extractable Value)**
Valor que los validadores/mineros pueden extraer reordenando, incluyendo o excluyendo transacciones en un bloque.

**Mint (Acuñar)**
Proceso de crear nuevos tokens o NFTs.

**Modifier**
Construcción en Solidity que modifica el comportamiento de funciones, comúnmente usada para verificaciones de acceso.

---

## N

**NFT (Non-Fungible Token)**
Token único e indivisible que representa propiedad de un activo digital o físico.

**Nonce**
Número secuencial asociado a una cuenta que previene el replay de transacciones.

**Normalización**
En MIESC, proceso de convertir hallazgos de diferentes herramientas a un formato común y mapearlos a taxonomías estándar.

---

## O

**Opcode**
Instrucción de bajo nivel de la EVM, como PUSH, POP, CALL, SSTORE.

**Oracle**
Servicio que proporciona datos externos a smart contracts, como precios de activos o resultados de eventos.

**Overflow/Underflow**
Vulnerabilidad aritmética donde un cálculo excede el valor máximo (overflow) o mínimo (underflow) representable.

---

## P

**Proxy**
Patrón de diseño que permite actualizar la lógica de un smart contract separando el almacenamiento de la implementación.

**Pull Payment**
Patrón donde los usuarios retiran fondos en lugar de que el contrato los envíe, mitigando reentrancy.

---

## R

**Reentrancy**
Vulnerabilidad donde un contrato externo puede llamar de vuelta al contrato vulnerable antes de que complete su ejecución, permitiendo manipular estado.

**Revert**
Operación que cancela una transacción y revierte todos los cambios de estado, típicamente debido a una condición fallida.

**Rug Pull**
Estafa donde los desarrolladores abandonan un proyecto y retiran la liquidez después de atraer inversores.

---

## S

**Sandwich Attack**
Ataque MEV donde se colocan transacciones antes y después de la transacción de una víctima para extraer valor.

**Slippage**
Diferencia entre el precio esperado y el precio real de una transacción de intercambio.

**Smart Contract**
Programa autónomo almacenado en blockchain que se ejecuta automáticamente cuando se cumplen condiciones predefinidas.

**SMT Solver**
Solver de satisfacibilidad módulo teorías, utilizado en verificación formal y ejecución simbólica.

**Solidity**
Lenguaje de programación principal para escribir smart contracts en Ethereum.

**Staking**
Proceso de bloquear tokens para participar en el consenso de la red o obtener recompensas.

**Storage**
Almacenamiento persistente de un smart contract en la blockchain.

**SWC (Smart Contract Weakness Classification)**
Taxonomía estándar de vulnerabilidades de smart contracts mantenida por la comunidad Ethereum.

---

## T

**Testnet**
Red de prueba donde se pueden experimentar sin usar fondos reales.

**Token**
Activo digital creado y gestionado por un smart contract.

**Transaction (Transacción)**
Mensaje firmado enviado a la blockchain que puede transferir valor o invocar funciones de contratos.

**TVL (Total Value Locked)**
Valor total de activos depositados en un protocolo DeFi.

---

## V

**Verificación Formal**
Técnica que utiliza métodos matemáticos para demostrar la corrección de un programa respecto a una especificación.

**View Function**
Función en Solidity que lee pero no modifica el estado del contrato.

**Vulnerability (Vulnerabilidad)**
Debilidad en el diseño o implementación de un sistema que puede ser explotada para comprometer su seguridad.

---

## W

**Wallet (Billetera)**
Software o hardware que gestiona claves privadas y permite interactuar con la blockchain.

**Wei**
La unidad más pequeña de Ether (1 ETH = 10^18 wei).

**Whitelist**
Lista de direcciones autorizadas para realizar ciertas acciones en un smart contract.

---

## Y

**Yield Farming**
Estrategia de maximizar retornos moviendo activos entre diferentes protocolos DeFi.

---

## Z

**Zero-Knowledge Proof**
Prueba criptográfica que permite demostrar conocimiento de información sin revelar la información misma.

---

**Total de términos definidos:** 95

---

*Nota: Este glosario incluye los términos técnicos más relevantes utilizados en el documento. Para acrónimos específicos, consultar la Lista de Acrónimos.*
