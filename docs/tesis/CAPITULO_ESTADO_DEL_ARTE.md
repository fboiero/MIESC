# Capítulo 3: Estado del Arte

## Análisis de Seguridad en Contratos Inteligentes: Una Revisión de la Literatura

## 3.1 Introducción

La seguridad de los contratos inteligentes representa uno de los desafíos más significativos en el ecosistema blockchain contemporáneo. Según Atzei et al. (2017), los contratos inteligentes son "programas que se ejecutan en una blockchain y que, una vez desplegados, son inmutables y públicamente verificables" (p. 164). Esta inmutabilidad, si bien garantiza la integridad del código, implica que cualquier vulnerabilidad presente en el momento del despliegue permanecerá explotable indefinidamente, a menos que se implementen mecanismos de actualización específicos (Chen et al.,2017).

El presente capítulo realiza una revisión narrativa del estado del arte en herramientas y metodologías de análisis de seguridad para contratos inteligentes, informada por las directrices de Kitchenham y Charters (2007) para revisiones en ingeniería de software, aunque sin un protocolo formal de búsqueda y selección. Se identifican las principales brechas existentes que fundamentan el desarrollo de MIESC como contribución al campo.

## 3.2 Contexto y Relevancia del Problema

### 3.2.1 Impacto Económico de las Vulnerabilidades

Las vulnerabilidades en contratos inteligentes han ocasionado pérdidas económicas sustanciales en el ecosistema de finanzas descentralizadas (DeFi). Según el informe de Chainalysis (2024), las pérdidas acumuladas por exploits en protocolos DeFi superaron los 3.800 millones de dólares estadounidenses entre 2020 y 2023. La Tabla 3.1 presenta los incidentes más significativos documentados en la literatura.

**Tabla 3.1.** Incidentes de seguridad históricos en contratos inteligentes

| Año | Incidente | Pérdida (USD) | Vulnerabilidad | Referencia |
|-----|-----------|---------------|----------------|------------|
| 2016 | The DAO | $60M | Reentrancy | Mehar et al. (2019) |
| 2017 | Parity Wallet | $150M (fondos congelados) | Access Control | Destefanis et al. (2018) |
| 2018 | Beauty Chain (BEC) | Colapso de la cotización del token | Integer Overflow | NVD (2018), CVE-2018-10299 |
| 2020 | bZx Protocol | $350K | Flash Loan | Qin et al. (2021) |
| 2021 | Poly Network | $610M | Cross-chain | Zhou et al. (2023) |
| 2022 | Ronin Bridge | $625M | Key Compromise | Chainalysis (2024) |
| 2023 | Euler Finance | $197M | Flash Loan + Logic | Chainalysis (2024) |

Estos incidentes evidencian la necesidad crítica de herramientas automatizadas de detección de vulnerabilidades, dado que las auditorías manuales, aunque exhaustivas, presentan limitaciones de escalabilidad y costo (Durieux et al., 2020).

### 3.2.2 Taxonomía de Vulnerabilidades

La comunidad académica y la industria han desarrollado múltiples taxonomías para clasificar las vulnerabilidades en contratos inteligentes. El Smart Contract Weakness Classification Registry (SWC Registry), mantenido por la Ethereum Foundation, constituye el estándar de facto con 37 categorías de debilidades documentadas (SCSVS, 2023).

Perez y Livshits (2021) proponen una clasificación según el origen de las vulnerabilidades, que distingue las de nivel de lenguaje, derivadas de características específicas de Solidity; las de nivel de EVM, relacionadas con la semántica de la máquina virtual; las de nivel de blockchain, asociadas a la naturaleza distribuida del sistema; y las de lógica de negocio, errores en la implementación de la lógica del protocolo.

La Tabla 3.2 presenta la distribución de frecuencia de vulnerabilidades según el estudio empírico de Durieux et al. (2020) sobre 47,587 contratos desplegados en Ethereum mainnet.

**Tabla 3.2.** Distribución de vulnerabilidades en contratos Ethereum (Durieux et al., 2020)

| SWC-ID | Vulnerabilidad | Frecuencia | Impacto Potencial |
|--------|----------------|------------|-------------------|
| SWC-107 | Reentrancy | 23.4% | Crítico |
| SWC-101 | Integer Overflow/Underflow | 18.2% | Alto |
| SWC-104 | Unchecked Return Value | 15.1% | Medio |
| SWC-105 | Unprotected Ether Withdrawal | 12.3% | Alto |
| SWC-115 | Authorization through tx.origin | 8.7% | Alto |
| SWC-116 | Block Timestamp Dependence | 7.2% | Bajo |
| Otros | Diversas | 15.1% | Variable |

## 3.3 Técnicas de Análisis de Seguridad

La literatura identifica cuatro categorías principales de técnicas para el análisis de seguridad en contratos inteligentes (Rameder et al., 2022); las secciones siguientes las caracterizan por sus ventajas, sus limitaciones y sus herramientas representativas.

### 3.3.1 Análisis Estático

El análisis estático examina el código fuente o el bytecode sin ejecutarlo e identifica patrones potencialmente vulnerables mediante técnicas de análisis de flujo de datos y de control (Feist et al., 2019). Según Grech et al. (2018), ofrece una cobertura completa del código analizado, con un tiempo de ejecución predecible y en general breve, y no requiere casos de prueba. Sus limitaciones, sin embargo, son conocidas: presenta un alto índice de falsos positivos —Durieux et al. (2020) observan que las nueve herramientas evaluadas marcan como vulnerable el 93% de 47,518 contratos desplegados—, no puede detectar vulnerabilidades que dependen del estado de ejecución y encuentra dificultades para analizar llamadas dinámicas y patrones de proxy. Dos herramientas son representativas de esta técnica.

*Slither* (Feist et al., 2019): Framework desarrollado por Trail of Bits que implementa más de 80 detectores de vulnerabilidades. Utiliza un modelo intermedio (SlithIR) que facilita el análisis de flujo de datos. Según sus autores, alcanza una precisión del 82% en su propio benchmark; en la evaluación independiente de Durieux et al. (2020) detecta el 17% de las vulnerabilidades anotadas de SmartBugs-curated, con la mayor cantidad de detecciones exclusivas entre las nueve herramientas (Tabla 3.3).

*Securify2* (Tsankov et al., 2018): Desarrollado por ETH Zurich, emplea análisis basado en Datalog para verificar propiedades de seguridad. Su enfoque declarativo permite definir propiedades de forma composicional.

### 3.3.2 Ejecución Simbólica

La ejecución simbólica representa los valores de entrada como símbolos matemáticos, explorando sistemáticamente los caminos de ejecución mediante solvers de satisfacibilidad (SMT) (Luu et al., 2016). King (1976) estableció los fundamentos teóricos de esta técnica, que ha sido adaptada para el análisis de contratos inteligentes.

Su principal ventaja es la capacidad de generar entradas que desencadenan las vulnerabilidades, junto con un análisis exhaustivo de los caminos de ejecución y una alta precisión en la detección de vulnerabilidades aritméticas. Como contrapartida, sufre la explosión de caminos (*path explosion*) en contratos complejos (Baldoni et al., 2018), demanda un alto consumo de recursos computacionales y tiene dificultades para manejar operaciones criptográficas. Tres herramientas la representan en este dominio.

*Mythril* (Mueller, 2018): Herramienta de ConsenSys que utiliza el solver Z3 para ejecución simbólica. Según Durieux et al. (2020), detecta 5 de las 8 vulnerabilidades de reentrancy anotadas (62%) y es la herramienta con mayor detección global (27%, Tabla 3.3).

*Manticore* (Mossberg et al., 2019): Framework de Trail of Bits que combina ejecución simbólica y concólica. Permite análisis tanto de contratos como de binarios nativos.

*Oyente* (Luu et al., 2016): Primera herramienta de ejecución simbólica para Ethereum, presentada en CCS 2016. Aunque actualmente desactualizada, estableció las bases metodológicas para herramientas posteriores.

### 3.3.3 Fuzzing

El fuzzing genera entradas aleatorias o semi-dirigidas para explorar el comportamiento del programa en tiempo de ejecución (Miller et al., 1990). En el contexto de contratos inteligentes, Grieco et al. (2020) proponen el *property-based fuzzing*, donde el usuario especifica propiedades (invariantes) que deben mantenerse.

El fuzzing presenta un bajo índice de falsos positivos, ya que las vulnerabilidades que encuentra son reproducibles; puede hallar fallas en código complejo y escala a contratos de gran tamaño. Requiere, no obstante, que las propiedades se especifiquen manualmente, su cobertura depende de la calidad de las entradas generadas y puede no explorar todos los caminos de ejecución.

*Echidna* (Grieco et al., 2020): Fuzzer basado en propiedades desarrollado por Trail of Bits. Utiliza generación de entradas basada en gramática y estrategias de cobertura guiada.

*Foundry/Forge* (Paradigm, 2021): Framework de desarrollo que incluye capacidades de fuzzing integradas. Su adopción ha crecido significativamente en la industria por su rendimiento y experiencia de desarrollo.

### 3.3.4 Verificación Formal

La verificación formal proporciona garantías matemáticas sobre el comportamiento del programa mediante técnicas de demostración de teoremas o model checking (Clarke et al., 2018). Según Bhargavan et al. (2016), es la única técnica que puede garantizar la ausencia de ciertas clases de vulnerabilidades.

La verificación formal ofrece garantías matemáticas de corrección, detecta errores sutiles de lógica y permite verificar propiedades de seguridad complejas. Estas ventajas tienen como contrapartida la necesidad de una especificación formal del comportamiento esperado, un alto costo de implementación y mantenimiento, y una curva de aprendizaje pronunciada.

*Certora Prover* (Certora, 2024): Herramienta comercial que utiliza el lenguaje CVL (Certora Verification Language) para especificaciones formales. Empleada por protocolos de alto valor como Aave y Compound.

*SMTChecker* (Alt & Reitwiessner, 2018): Verificador integrado en el compilador de Solidity que aplica model checking con dos motores —*bounded model checking* (BMC) y cláusulas de Horn restringidas (CHC)— para verificar aserciones y propiedades.

## 3.4 Análisis Comparativo de Herramientas Existentes

Durieux et al. (2020) realizaron el estudio empírico más exhaustivo hasta la fecha, evaluando 9 herramientas sobre un benchmark de 47,587 contratos. La Tabla 3.3 sintetiza sus hallazgos sobre el subconjunto etiquetado (SmartBugs-curated), donde se conoce el conjunto de vulnerabilidades anotadas.

**Tabla 3.3.** Vulnerabilidades anotadas detectadas por herramienta según Durieux et al. (2020, Tabla 5), sobre las 115 vulnerabilidades etiquetadas del subconjunto SmartBugs-curated

| Herramienta | Técnica | Detectadas (de 115) | Proporción |
|-------------|---------|---------------------|------------|
| Mythril | Simbólico | 31 | 27% |
| Slither | Estático | 20 | 17% |
| Oyente | Simbólico | 17 | 15% |
| Osiris | Simbólico | 16 | 14% |
| Manticore | Simbólico | 13 | 11% |
| SmartCheck | Estático | 13 | 11% |
| Securify | Estático | 10 | 9% |
| HoneyBadger | Simbólico | 2 | 2% |
| Maian | Simbólico | 0 | 0% |
| Combinación de las nueve herramientas | — | 48 | 42% |
| Mythril + Slither (mejor par) | — | 42 | 37% |

Los autores no reportan precisión ni F1 por herramienta; la métrica es la fracción de vulnerabilidades anotadas que cada una detecta. Ninguna herramienta individual supera el 27% (Mythril, la mejor); Slither, herramienta principal de la capa 1 de MIESC, detecta el 17%, y la combinación de las nueve alcanza el 42%. Durieux et al. (2020) concluyen que ninguna herramienta individual logra una cobertura satisfactoria de los tipos de vulnerabilidad y que la combinación de herramientas es el camino para mejorarla, lo que motiva los enfoques combinados como el de MIESC. Estas cifras son la referencia habitual de la literatura, pero no son directamente comparables con las de MIESC (86% en el corpus propio con ensemble de LLMs; 92.5% en EVMBench bajo matcher laxo, que cae a 27.4% con el juez oficial), porque difieren el corpus, el protocolo de emparejamiento y la naturaleza de los componentes (herramientas estáticas frente a modelos de lenguaje frontier).

### 3.4.1 Análisis con Inteligencia Artificial

En los últimos años, la aplicación de modelos de lenguaje de gran escala (LLM) al análisis de seguridad ha emergido como un área de investigación prometedora. Sun et al. (2024) presentaron GPTScan en ICSE 2024 y mostraron que GPT-4 puede detectar vulnerabilidades de lógica que escapan a las herramientas tradicionales, mediante un enfoque híbrido en el que el LLM complementa el análisis estático y reduce los falsos positivos gracias al razonamiento semántico. De Baets et al. (2024), sin embargo, advierten sobre tres limitaciones: las alucinaciones, que se traducen en vulnerabilidades inexistentes; la dependencia del contexto y del diseño de los prompts; y el costo operativo de las APIs comerciales, aspecto que retoma la Brecha 4.

## 3.5 Identificación de Brechas en el Estado del Arte

A partir de la revisión realizada, se identifican las siguientes brechas que fundamentan el desarrollo de MIESC:

### 3.5.1 Brecha 1: Fragmentación de Herramientas

Las herramientas existentes operan de forma aislada y con formatos de salida incompatibles (Rameder et al., 2022). La falta de interoperabilidad queda en evidencia en el propio estudio de Durieux et al. (2020), que debió desarrollar un parser específico para cada herramienta evaluada. Para el auditor, la consecuencia es la necesidad de ejecutar múltiples herramientas manualmente y consolidar sus resultados, con el consiguiente incremento del tiempo invertido y del riesgo de error (Di Angelo & Salzer, 2019). El patrón Adapter, documentado por Gamma et al. (1994), ofrece una respuesta de diseño a este problema, ya que permite "convertir la interfaz de una clase en otra interfaz que los clientes esperan" (p. 139; traducción propia); MIESC lo adopta para unificar las interfaces heterogéneas de las herramientas que integra.

### 3.5.2 Brecha 2: Ausencia de Enfoque Multi-Técnica

Las herramientas existentes implementan, en general, una única técnica de análisis, lo que limita su cobertura. La Tabla 3.3 muestra que ninguna herramienta individual detecta más del 27% de las vulnerabilidades anotadas y que ni siquiera la combinación de las nueve supera el 42%; Ghaleb y Pattabiraman (2020) confirman que ninguna herramienta estática única cubre todas las clases de vulnerabilidades y que la combinación de técnicas amplía materialmente la cobertura. Las vulnerabilidades detectables solo mediante la combinación de técnicas permanecen, por lo tanto, sin identificar. El modelo de defensa en profundidad (*Defense-in-Depth*), originado en la doctrina militar y adaptado a la seguridad informática por el NIST (Ross et al., 2016), propone múltiples capas de controles independientes como respuesta a esta limitación; en palabras de Schneier (2000), "la seguridad es un proceso, no un producto" (p. 12; traducción propia). El Capítulo 5 matiza, sin embargo, esta expectativa: la combinación de herramientas estáticas no superó a la mejor de ellas, y la ganancia medida provino del razonamiento semántico (§5.3.3).

### 3.5.3 Brecha 3: Falta de Normalización

No existe un formato estándar para reportar hallazgos de seguridad en contratos inteligentes (Zhou et al., 2023). Cada herramienta utiliza una nomenclatura propia —Slither reporta "reentrancy-eth" y Mythril "State change after external call" para la misma vulnerabilidad—, lo que dificulta comparar resultados entre herramientas y generar métricas agregadas. La taxonomía del SWC Registry, desarrollada por consenso de la comunidad Ethereum (SCSVS, 2023), proporciona un vocabulario común, y su integración con CWE (MITRE, 2024) y el OWASP Smart Contract Top 10 (OWASP, 2023) permite la trazabilidad hacia estándares de seguridad generales.

### 3.5.4 Brecha 4: Dependencia de Servicios Comerciales

Las herramientas de análisis con IA dependen, en general, de APIs comerciales con costos considerables. GPTScan (Sun et al., 2024), por ejemplo, utiliza GPT-4, con un costo aproximado de $0.03-0.12 por análisis según el tamaño del contrato, mientras que Certora Prover requiere una licencia comercial cuyos costos no se publican. Estos montos constituyen una barrera de entrada para proyectos con recursos limitados, en especial en países en desarrollo (DPGA, 2023). Los principios de Digital Public Goods (DPGA, 2023) establecen que el software de interés público debe estar "libre de barreras de costo"; en esa línea, el uso de modelos de lenguaje locales mediante Ollama (Ollama, 2024) elimina la dependencia de APIs comerciales, con el costo en capacidad que el Capítulo 6 cuantifica.

### 3.5.5 Brecha 5: Obsolescencia y Compatibilidad

Múltiples herramientas presentan problemas de mantenimiento o de incompatibilidad con entornos modernos: Oyente no recibe actualizaciones desde 2019 y Manticore es incompatible con Python 3.10 y posteriores por cambios en la biblioteca estándar (Python, 2022), lo que reduce el conjunto de herramientas disponibles para la auditoría. El principio de encapsulación (Parnas, 1972) permite aislar las dependencias problemáticas, y la containerización mediante Docker (Merkel, 2014) proporciona ambientes reproducibles para herramientas legacy.

### 3.5.6 Brecha 6: Ausencia de Orquestación

No existe un sistema que coordine la ejecución de múltiples herramientas y consolide sus resultados. SmartBugs (Ferreira et al., 2020) es el antecedente más directo de orquestación, pero se limita a la ejecución secuencial sin normalización de resultados, de modo que el proceso de auditoría sigue siendo manual, lento y propenso a errores humanos. Los patrones de orquestación de microservicios (Newman, 2015) permiten coordinar servicios heterogéneos, y la deduplicación de hallazgos se fundamenta en las técnicas de record linkage (Fellegi & Sunter, 1969).

## 3.6 Síntesis y Justificación de MIESC

La Tabla 3.4 sintetiza las brechas identificadas y las soluciones propuestas por MIESC, con sus respectivas fundamentaciones teóricas.

**Tabla 3.4.** Brechas identificadas y soluciones de MIESC

| # | Brecha | Solución MIESC | Fundamentación |
|---|--------|----------------|----------------|
| 1 | Fragmentación | Protocolo ToolAdapter | Gamma et al. (1994) |
| 2 | Mono-técnica | Arquitectura 7 capas | Ross et al. (2016) |
| 3 | Sin normalización | Mapeo SWC/CWE/OWASP | SCSVS (2023) |
| 4 | Costo APIs | Backend Ollama local | DPGA (2023) |
| 5 | Obsolescencia | Docker + parches | Parnas (1972), Merkel (2014) |
| 6 | Sin orquestación | Pipeline automatizado | Newman (2015) |

## 3.7 Referencias del Capítulo

Alt, L., & Reitwiessner, C. (2018). SMT-based verification of Solidity smart contracts. En T. Margaria & B. Steffen (Eds.), *Leveraging applications of formal methods, verification and validation. Industrial practice (ISoLA 2018)* (Lecture Notes in Computer Science, Vol. 11247, pp. 376-388). Springer. https://doi.org/10.1007/978-3-030-03427-6_28

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). *Lecture Notes in Computer Science, 10204*, 164-186. https://doi.org/10.1007/978-3-662-54455-6_8

Baldoni, R., Coppa, E., D'Elia, D. C., Demetrescu, C., & Finocchi, I. (2018). A survey of symbolic execution techniques. *ACM Computing Surveys, 51*(3), 1-39. https://doi.org/10.1145/3182657

Bhargavan, K., Delignat-Lavaud, A., Fournet, C., Gollamudi, A., Gonthier, G., Kobeissi, N., ... & Zanella-Béguelin, S. (2016). Formal verification of smart contracts: Short paper. *Proceedings of the 2016 ACM Workshop on Programming Languages and Analysis for Security*, 91-96. https://doi.org/10.1145/2993600.2993611

Chainalysis. (2024). *The 2024 Crypto Crime Report*. https://www.chainalysis.com/reports/

Clarke, E. M., Henzinger, T. A., Veith, H., & Bloem, R. (Eds.). (2018). *Handbook of model checking*. Springer. https://doi.org/10.1007/978-3-319-10575-8

De Baets, C., Suleiman, B., Chitizadeh, A., & Razzak, I. (2024). Vulnerability detection in smart contracts: A comprehensive survey. *arXiv preprint arXiv:2407.07922*. https://arxiv.org/abs/2407.07922

Destefanis, G., Marchesi, M., Ortu, M., Tonelli, R., Bracciali, A., & Hierons, R. (2018). Smart contracts vulnerabilities: A call for blockchain software engineering? *Proceedings of the International Workshop on Blockchain Oriented Software Engineering*, 19-25. https://doi.org/10.1109/IWBOSE.2018.8327567

Di Angelo, M., & Salzer, G. (2019). A survey of tools for analyzing Ethereum smart contracts. *Proceedings of the IEEE International Conference on Decentralized Applications and Infrastructures*, 69-78. https://doi.org/10.1109/DAPPCON.2019.00018

Digital Public Goods Alliance. (2023). *Digital Public Goods Standard*. https://digitalpublicgoods.net/standard/

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering*, 530-541. https://doi.org/10.1145/3377811.3380364

Feist, J., Grieco, G., & Groce, A. (2019). Slither: A static analysis framework for smart contracts. *Proceedings of the 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain*, 8-15. https://doi.org/10.1109/WETSEB.2019.00008

Fellegi, I. P., & Sunter, A. B. (1969). A theory for record linkage. *Journal of the American Statistical Association, 64*(328), 1183-1210. https://doi.org/10.1080/01621459.1969.10501049

Ferreira, J. F., Cruz, P., Durieux, T., & Abreu, R. (2020). SmartBugs: A framework to analyze Solidity smart contracts. *Proceedings of the 35th IEEE/ACM International Conference on Automated Software Engineering*, 1349-1352. https://doi.org/10.1145/3324884.3415298

Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994). *Design patterns: Elements of reusable object-oriented software*. Addison-Wesley.

Ghaleb, A., & Pattabiraman, K. (2020). How effective are smart contract analysis tools? Evaluating smart contract static analysis tools using bug injection. *Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis*, 415-427. https://doi.org/10.1145/3395363.3397385

Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., & Smaragdakis, Y. (2018). MadMax: Surviving out-of-gas conditions in Ethereum smart contracts. *Proceedings of the ACM on Programming Languages, 2*(OOPSLA), 1-27. https://doi.org/10.1145/3276486

Grieco, G., Song, W., Cygan, A., Feist, J., & Groce, A. (2020). Echidna: Effective, usable, and fast fuzzing for smart contracts. *Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis*, 557-560. https://doi.org/10.1145/3395363.3404366

King, J. C. (1976). Symbolic execution and program testing. *Communications of the ACM, 19*(7), 385-394. https://doi.org/10.1145/360248.360252

Kitchenham, B., & Charters, S. (2007). *Guidelines for performing systematic literature reviews in software engineering* (Technical Report EBSE-2007-01). Keele University.

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security*, 254-269. https://doi.org/10.1145/2976749.2978309

Mehar, M. I., Shier, C. L., Giambattista, A., Gong, E., Fletcher, G., Sanayhie, R., ... & Laskowski, M. (2019). Understanding a revolutionary and flawed grand experiment in blockchain: The DAO attack. *Journal of Cases on Information Technology, 21*(1), 19-32. https://doi.org/10.4018/JCIT.2019010102

Merkel, D. (2014). Docker: Lightweight Linux containers for consistent development and deployment. *Linux Journal, 2014*(239), 2.

Miller, B. P., Fredriksen, L., & So, B. (1990). An empirical study of the reliability of UNIX utilities. *Communications of the ACM, 33*(12), 32-44. https://doi.org/10.1145/96267.96279

MITRE. (2024). *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/

Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Dinaburg, A. (2019). Manticore: A user-friendly symbolic execution framework for binaries and smart contracts. *Proceedings of the 34th IEEE/ACM International Conference on Automated Software Engineering*, 1186-1189. https://doi.org/10.1109/ASE.2019.00133

Mueller, B. (2018). Smashing Ethereum smart contracts for fun and real profit. *Proceedings of the 9th HITB Security Conference*.

National Vulnerability Database. (2018). *CVE-2018-10299: Integer overflow in the batchTransfer function of the BeautyChain (BEC) token contract*. National Institute of Standards and Technology. https://nvd.nist.gov/vuln/detail/CVE-2018-10299

Newman, S. (2015). *Building microservices: Designing fine-grained systems*. O'Reilly Media.

Ollama. (2024). *Ollama: Get up and running with large language models locally*. https://ollama.ai/

OWASP. (2023). *OWASP Smart Contract Top 10*. https://owasp.org/www-project-smart-contract-top-10/

Paradigm. (2021). *Foundry: A blazing fast, portable and modular toolkit for Ethereum application development*. https://github.com/foundry-rs/foundry

Parnas, D. L. (1972). On the criteria to be used in decomposing systems into modules. *Communications of the ACM, 15*(12), 1053-1058. https://doi.org/10.1145/361598.361623

Perez, D., & Livshits, B. (2021). Smart contract vulnerabilities: Vulnerable does not imply exploited. *Proceedings of the 30th USENIX Security Symposium*, 1325-1341.

Python. (2022). *What's new in Python 3.11*. https://docs.python.org/3/whatsnew/3.11.html

Qin, K., Zhou, L., Livshits, B., & Gervais, A. (2021). Attacking the DeFi ecosystem with flash loans for fun and profit. *Proceedings of the 25th International Conference on Financial Cryptography and Data Security*, 3-32. https://doi.org/10.1007/978-3-662-64322-8_1

Rameder, H., Di Angelo, M., & Salzer, G. (2022). Review of automated vulnerability analysis of smart contracts on Ethereum. *Frontiers in Blockchain, 5*, 814977. https://doi.org/10.3389/fbloc.2022.814977

Ross, R., McEvilley, M., & Oren, J. C. (2016). *Systems security engineering: Considerations for a multidisciplinary approach in the engineering of trustworthy secure systems* (NIST Special Publication 800-160, Vol. 1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-160v1

Schneier, B. (2000). *Secrets and lies: Digital security in a networked world*. John Wiley & Sons.

SCSVS. (2023). *Smart Contract Security Verification Standard*. https://github.com/securing/SCSVS

Sun, Y., Wu, D., Xue, Y., Liu, H., Wang, H., Xu, Z., Xie, X., & Liu, Y. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. En *Proceedings of the IEEE/ACM 46th International Conference on Software Engineering (ICSE '24)* (pp. 1-13). ACM. https://doi.org/10.1145/3597503.3639117

Tsankov, P., Dan, A., Drachsler-Cohen, D., Gervais, A., Bünzli, F., & Vechev, M. (2018). Securify: Practical security analysis of smart contracts. *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*, 67-82. https://doi.org/10.1145/3243734.3243780

Werner, S., Perez, D., Gudgeon, L., Klages-Mundt, A., Harz, D., & Knottenbelt, W. (2022). SoK: Decentralized finance (DeFi). En *Proceedings of the 4th ACM Conference on Advances in Financial Technologies (AFT '22)* (pp. 30-46). ACM. https://doi.org/10.1145/3558535.3559780

Zhou, L., Xiong, X., Ernstberger, J., Chaliasos, S., Wang, Z., Wang, Y., Qin, K., Wattenhofer, R., Song, D., & Gervais, A. (2023). SoK: Decentralized finance (DeFi) attacks. En *2023 IEEE Symposium on Security and Privacy (SP)* (pp. 2444-2461). IEEE. https://doi.org/10.1109/SP46215.2023.10179435

*Nota: Las referencias siguen el formato APA 7ma edición.*
