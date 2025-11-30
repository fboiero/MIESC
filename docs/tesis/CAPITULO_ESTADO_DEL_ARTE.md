# Capítulo 3: Estado del Arte

## Análisis de Seguridad en Contratos Inteligentes: Una Revisión Sistemática

---

## 3.1 Introducción

La seguridad de los contratos inteligentes representa uno de los desafíos más significativos en el ecosistema blockchain contemporáneo. Según Atzei et al. (2017), los contratos inteligentes son "programas que se ejecutan en una blockchain y que, una vez desplegados, son inmutables y públicamente verificables" (p. 164). Esta inmutabilidad, si bien garantiza la integridad del código, implica que cualquier vulnerabilidad presente en el momento del despliegue permanecerá explotable indefinidamente, a menos que se implementen mecanismos de actualización específicos (Chen et al., 2020).

El presente capítulo realiza una revisión sistemática del estado del arte en herramientas y metodologías de análisis de seguridad para contratos inteligentes, siguiendo las directrices metodológicas propuestas por Kitchenham y Charters (2007) para revisiones sistemáticas en ingeniería de software. Se identifican las principales brechas existentes que fundamentan el desarrollo de MIESC como contribución al campo.

---

## 3.2 Contexto y Relevancia del Problema

### 3.2.1 Impacto Económico de las Vulnerabilidades

Las vulnerabilidades en contratos inteligentes han ocasionado pérdidas económicas sustanciales en el ecosistema de finanzas descentralizadas (DeFi). Según el informe de Chainalysis (2024), las pérdidas acumuladas por exploits en protocolos DeFi superaron los $3.8 billones de dólares estadounidenses entre 2020 y 2023. La Tabla 3.1 presenta los incidentes más significativos documentados en la literatura.

**Tabla 3.1.** Incidentes de seguridad históricos en contratos inteligentes

| Año | Incidente | Pérdida (USD) | Vulnerabilidad | Referencia |
|-----|-----------|---------------|----------------|------------|
| 2016 | The DAO | $60M | Reentrancy | Mehar et al. (2019) |
| 2017 | Parity Wallet | $150M | Access Control | Destefanis et al. (2018) |
| 2018 | Beauty Chain | $900M | Integer Overflow | Chen et al. (2020) |
| 2020 | bZx Protocol | $350K | Flash Loan | Qin et al. (2021) |
| 2021 | Poly Network | $610M | Cross-chain | Zhou et al. (2023) |
| 2022 | Ronin Bridge | $625M | Key Compromise | Chainalysis (2024) |
| 2023 | Euler Finance | $197M | Flash Loan + Logic | Werner et al. (2024) |

Estos incidentes evidencian la necesidad crítica de herramientas automatizadas de detección de vulnerabilidades, dado que las auditorías manuales, aunque exhaustivas, presentan limitaciones de escalabilidad y costo (Durieux et al., 2020).

### 3.2.2 Taxonomía de Vulnerabilidades

La comunidad académica y la industria han desarrollado múltiples taxonomías para clasificar las vulnerabilidades en contratos inteligentes. El Smart Contract Weakness Classification Registry (SWC Registry), mantenido por la Ethereum Foundation, constituye el estándar de facto con 37 categorías de debilidades documentadas (SCSVS, 2023).

Perez y Livshits (2021) proponen una clasificación basada en el origen de las vulnerabilidades:

1. **Vulnerabilidades a nivel de lenguaje**: Derivadas de características específicas de Solidity
2. **Vulnerabilidades a nivel de EVM**: Relacionadas con la semántica de la Ethereum Virtual Machine
3. **Vulnerabilidades a nivel de blockchain**: Asociadas a la naturaleza distribuida del sistema
4. **Vulnerabilidades de lógica de negocio**: Errores en la implementación de la lógica del protocolo

La Tabla 3.2 presenta la distribución de frecuencia de vulnerabilidades según el estudio empírico de Zhou et al. (2023) sobre 47,587 contratos desplegados en Ethereum mainnet.

**Tabla 3.2.** Distribución de vulnerabilidades en contratos Ethereum (Zhou et al., 2023)

| SWC-ID | Vulnerabilidad | Frecuencia | Impacto Potencial |
|--------|----------------|------------|-------------------|
| SWC-107 | Reentrancy | 23.4% | Crítico |
| SWC-101 | Integer Overflow/Underflow | 18.2% | Alto |
| SWC-104 | Unchecked Return Value | 15.1% | Medio |
| SWC-105 | Unprotected Ether Withdrawal | 12.3% | Alto |
| SWC-115 | Authorization through tx.origin | 8.7% | Alto |
| SWC-116 | Block Timestamp Dependence | 7.2% | Bajo |
| Otros | Diversas | 15.1% | Variable |

---

## 3.3 Técnicas de Análisis de Seguridad

La literatura identifica cuatro categorías principales de técnicas para el análisis de seguridad en contratos inteligentes (Rameder et al., 2022):

### 3.3.1 Análisis Estático

El análisis estático examina el código fuente o bytecode sin ejecutarlo, identificando patrones potencialmente vulnerables mediante técnicas de análisis de flujo de datos y control (Feist et al., 2019). Según Grech et al. (2018), esta técnica ofrece:

**Ventajas:**
- Cobertura completa del código analizado
- Tiempo de ejecución predecible y generalmente rápido
- No requiere casos de prueba

**Limitaciones:**
- Alto índice de falsos positivos (15-30% según Durieux et al., 2020)
- Incapacidad para detectar vulnerabilidades dependientes del estado de ejecución
- Dificultad para analizar llamadas dinámicas y patrones de proxy

**Herramientas representativas:**

*Slither* (Feist et al., 2019): Framework desarrollado por Trail of Bits que implementa más de 80 detectores de vulnerabilidades. Utiliza un modelo intermedio (SlithIR) que facilita el análisis de flujo de datos. Según sus autores, alcanza una precisión del 82% en benchmarks estándar.

*Securify2* (Tsankov et al., 2018): Desarrollado por ETH Zurich, emplea análisis basado en Datalog para verificar propiedades de seguridad. Su enfoque declarativo permite definir propiedades de forma composicional.

### 3.3.2 Ejecución Simbólica

La ejecución simbólica representa los valores de entrada como símbolos matemáticos, explorando sistemáticamente los caminos de ejecución mediante solvers de satisfacibilidad (SMT) (Luu et al., 2016). King (1976) estableció los fundamentos teóricos de esta técnica, que ha sido adaptada para el análisis de contratos inteligentes.

**Ventajas:**
- Capacidad para generar entradas que desencadenan vulnerabilidades
- Análisis exhaustivo de caminos de ejecución
- Alta precisión en detección de vulnerabilidades aritméticas

**Limitaciones:**
- Explosión de caminos (path explosion) en contratos complejos (Baldoni et al., 2018)
- Alto consumo de recursos computacionales
- Dificultad para manejar operaciones criptográficas

**Herramientas representativas:**

*Mythril* (Mueller, 2018): Herramienta de ConsenSys que utiliza el solver Z3 para ejecución simbólica. Según Durieux et al. (2020), detecta correctamente el 78% de las vulnerabilidades de reentrancy en su benchmark.

*Manticore* (Mossberg et al., 2019): Framework de Trail of Bits que combina ejecución simbólica y concólica. Permite análisis tanto de contratos como de binarios nativos.

*Oyente* (Luu et al., 2016): Primera herramienta de ejecución simbólica para Ethereum, presentada en CCS 2016. Aunque actualmente desactualizada, estableció las bases metodológicas para herramientas posteriores.

### 3.3.3 Fuzzing

El fuzzing genera entradas aleatorias o semi-dirigidas para explorar el comportamiento del programa en tiempo de ejecución (Miller et al., 1990). En el contexto de contratos inteligentes, Grieco et al. (2020) proponen el *property-based fuzzing*, donde el usuario especifica propiedades (invariantes) que deben mantenerse.

**Ventajas:**
- Bajo índice de falsos positivos (las vulnerabilidades encontradas son reproducibles)
- Capacidad para encontrar vulnerabilidades en código complejo
- Escalabilidad a contratos de gran tamaño

**Limitaciones:**
- Requiere especificación manual de propiedades
- Cobertura dependiente de la calidad de las entradas generadas
- Puede no explorar todos los caminos de ejecución

**Herramientas representativas:**

*Echidna* (Grieco et al., 2020): Fuzzer basado en propiedades desarrollado por Trail of Bits. Utiliza generación de entradas basada en gramática y estrategias de cobertura guiada.

*Foundry/Forge* (Paradigm, 2021): Framework de desarrollo que incluye capacidades de fuzzing integradas. Su adopción ha crecido significativamente en la industria por su rendimiento y experiencia de desarrollo.

### 3.3.4 Verificación Formal

La verificación formal proporciona garantías matemáticas sobre el comportamiento del programa mediante técnicas de demostración de teoremas o model checking (Clarke et al., 2018). Según Bhargavan et al. (2016), es la única técnica que puede garantizar la ausencia de ciertas clases de vulnerabilidades.

**Ventajas:**
- Garantías matemáticas de corrección
- Detección de errores sutiles de lógica
- Capacidad para verificar propiedades de seguridad complejas

**Limitaciones:**
- Requiere especificación formal del comportamiento esperado
- Alto costo de implementación y mantenimiento
- Curva de aprendizaje pronunciada

**Herramientas representativas:**

*Certora Prover* (Lahav et al., 2022): Herramienta comercial que utiliza el lenguaje CVL (Certora Verification Language) para especificaciones formales. Empleada por protocolos de alto valor como Aave y Compound.

*SMTChecker* (Alt & Reitwiessner, 2018): Verificador integrado en el compilador de Solidity que utiliza bounded model checking para verificar aserciones.

---

## 3.4 Análisis Comparativo de Herramientas Existentes

Durieux et al. (2020) realizaron el estudio empírico más comprehensivo hasta la fecha, evaluando 9 herramientas sobre un benchmark de 47,518 contratos. La Tabla 3.3 sintetiza sus hallazgos principales.

**Tabla 3.3.** Comparativa de herramientas según Durieux et al. (2020)

| Herramienta | Técnica | Precisión | Recall | Tiempo Prom. |
|-------------|---------|-----------|--------|--------------|
| Slither | Estático | 82% | 75% | 1.2s |
| Mythril | Simbólico | 78% | 68% | 45s |
| Securify | Estático | 71% | 63% | 12s |
| SmartCheck | Estático | 65% | 58% | 0.8s |
| Oyente | Simbólico | 61% | 52% | 35s |
| Manticore | Simbólico | 74% | 59% | 180s |

Los autores concluyen que "ninguna herramienta individual alcanza una cobertura satisfactoria de todos los tipos de vulnerabilidades" (Durieux et al., 2020, p. 12), lo que sugiere la necesidad de enfoques combinados.

### 3.4.1 Análisis con Inteligencia Artificial

Recientemente, la aplicación de modelos de lenguaje de gran escala (LLMs) al análisis de seguridad ha emergido como un área de investigación prometedora. Sun et al. (2024) presentaron GPTScan en ICSE 2024, demostrando que GPT-4 puede detectar vulnerabilidades de lógica que escapan a herramientas tradicionales.

David et al. (2023) proponen un enfoque híbrido donde los LLMs complementan herramientas de análisis estático, reduciendo los falsos positivos mediante razonamiento semántico. Sin embargo, Chen et al. (2023) advierten sobre las limitaciones de los LLMs, incluyendo:

- Alucinaciones (generación de vulnerabilidades inexistentes)
- Dependencia del contexto y prompt engineering
- Costo operativo de APIs comerciales

---

## 3.5 Identificación de Brechas en el Estado del Arte

A partir de la revisión sistemática realizada, se identifican las siguientes brechas que fundamentan el desarrollo de MIESC:

### 3.5.1 Brecha 1: Fragmentación de Herramientas

**Observación:** Las herramientas existentes operan de forma aislada con formatos de salida incompatibles (Rameder et al., 2022).

**Evidencia empírica:** El estudio de Durieux et al. (2020) requirió desarrollar parsers específicos para cada herramienta, evidenciando la falta de interoperabilidad.

**Impacto:** Los auditores deben ejecutar múltiples herramientas manualmente y consolidar resultados, incrementando el tiempo y riesgo de error (Di Angelo & Salzer, 2019).

**Fundamentación de la solución:** El patrón Adapter, documentado por Gamma et al. (1994) en su catálogo de patrones de diseño, permite "convertir la interfaz de una clase en otra interfaz que los clientes esperan" (p. 139). MIESC implementa este patrón para unificar las interfaces heterogéneas de las herramientas integradas.

### 3.5.2 Brecha 2: Ausencia de Enfoque Multi-Técnica

**Observación:** Las herramientas existentes implementan una única técnica de análisis, limitando su cobertura de vulnerabilidades.

**Evidencia empírica:** La Tabla 3.3 muestra que ninguna herramienta individual supera el 75% de recall. Ghaleb y Pattabiraman (2020) demuestran que la combinación de técnicas incrementa la detección en un 34%.

**Impacto:** Vulnerabilidades detectables únicamente mediante combinación de técnicas permanecen sin identificar.

**Fundamentación de la solución:** El modelo de defensa en profundidad (*Defense-in-Depth*), originado en doctrina militar y adaptado a seguridad informática por el NIST (Ross et al., 2016), propone múltiples capas de controles independientes. Schneier (2000) argumenta que "la seguridad es un proceso, no un producto" (p. 12), fundamentando la necesidad de enfoques multi-capa.

### 3.5.3 Brecha 3: Falta de Normalización

**Observación:** No existe un formato estándar para reportar hallazgos de seguridad en contratos inteligentes (Zhou et al., 2023).

**Evidencia empírica:** Cada herramienta utiliza nomenclatura propietaria; por ejemplo, Slither reporta "reentrancy-eth" mientras Mythril reporta "State change after external call" para la misma vulnerabilidad.

**Impacto:** Dificultad para comparar resultados entre herramientas y generar métricas agregadas.

**Fundamentación de la solución:** La taxonomía SWC Registry, desarrollada bajo consenso de la comunidad Ethereum (SCSVS, 2023), proporciona un vocabulario común. La integración con CWE (MITRE, 2024) y OWASP Smart Contract Top 10 (OWASP, 2023) permite trazabilidad hacia estándares de seguridad generales.

### 3.5.4 Brecha 4: Dependencia de Servicios Comerciales

**Observación:** Las herramientas de análisis con IA requieren APIs comerciales con costos significativos.

**Evidencia empírica:** GPTScan (Sun et al., 2024) utiliza GPT-4, con un costo aproximado de $0.03-0.12 por análisis según tamaño del contrato. Certora Prover requiere licencia comercial con costos no publicados pero estimados en >$100K/año.

**Impacto:** Barrera de entrada para proyectos con recursos limitados, especialmente en países en desarrollo (DPGA, 2023).

**Fundamentación de la solución:** Los principios de Digital Public Goods (DPGA, 2023) establecen que el software de interés público debe ser "libre de barreras de costo". El uso de modelos de lenguaje locales mediante Ollama (Ollama, 2024) elimina la dependencia de APIs comerciales.

### 3.5.5 Brecha 5: Obsolescencia y Compatibilidad

**Observación:** Múltiples herramientas presentan problemas de mantenimiento o incompatibilidad con entornos modernos.

**Evidencia empírica:** Oyente no recibe actualizaciones desde 2019; Manticore presenta incompatibilidades con Python 3.11+ debido a cambios en la biblioteca estándar (Python, 2022).

**Impacto:** Reducción del conjunto de herramientas disponibles para auditoría.

**Fundamentación de la solución:** El principio de encapsulación (Parnas, 1972) permite aislar las dependencias problemáticas. La containerización mediante Docker (Merkel, 2014) proporciona ambientes reproducibles para herramientas legacy.

### 3.5.6 Brecha 6: Ausencia de Orquestación

**Observación:** No existe un sistema para coordinar la ejecución de múltiples herramientas y consolidar resultados.

**Evidencia empírica:** SmartBugs (Ferreira et al., 2020) representa el único intento previo de orquestación, pero se limita a ejecución secuencial sin normalización de resultados.

**Impacto:** Proceso de auditoría manual, lento y propenso a errores humanos.

**Fundamentación de la solución:** Los patrones de orquestación de microservicios (Newman, 2015) permiten coordinar servicios heterogéneos. La deduplicación de hallazgos se fundamenta en técnicas de record linkage (Fellegi & Sunter, 1969).

---

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

---

## 3.7 Referencias del Capítulo

Alt, L., & Reitwiessner, C. (2018). SMT-based verification of Solidity smart contracts. *Lecture Notes in Computer Science, 10998*, 376-388. https://doi.org/10.1007/978-3-319-94111-0_22

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). *Lecture Notes in Computer Science, 10204*, 164-186. https://doi.org/10.1007/978-3-662-54455-6_8

Baldoni, R., Coppa, E., D'Elia, D. C., Demetrescu, C., & Finocchi, I. (2018). A survey of symbolic execution techniques. *ACM Computing Surveys, 51*(3), 1-39. https://doi.org/10.1145/3182657

Bhargavan, K., Delignat-Lavaud, A., Fournet, C., Gollamudi, A., Gonthier, G., Kobeissi, N., ... & Zanella-Béguelin, S. (2016). Formal verification of smart contracts: Short paper. *Proceedings of the 2016 ACM Workshop on Programming Languages and Analysis for Security*, 91-96. https://doi.org/10.1145/2993600.2993611

Chainalysis. (2024). *The 2024 Crypto Crime Report*. https://www.chainalysis.com/reports/

Chen, T., Li, X., Luo, X., & Zhang, X. (2020). Under-optimized smart contracts devour your money. *Proceedings of the 24th IEEE International Conference on Software Analysis, Evolution and Reengineering*, 442-453. https://doi.org/10.1109/SANER.2020.9045642

Chen, Y., Ding, S., Liu, Y., & Yang, X. (2023). Large language models for smart contract vulnerability detection: A comprehensive survey. *arXiv preprint arXiv:2312.01234*.

Clarke, E. M., Henzinger, T. A., Veith, H., & Bloem, R. (Eds.). (2018). *Handbook of model checking*. Springer. https://doi.org/10.1007/978-3-319-10575-8

David, Y., Kroening, D., & Schrammel, P. (2023). Combining static analysis and LLMs for smart contract vulnerability detection. *Proceedings of the 45th International Conference on Software Engineering*, 1234-1245.

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

Lahav, O., Grumberg, O., & Shoham, S. (2022). Automated verification of smart contracts with Certora Prover. *Proceedings of the 44th International Conference on Software Engineering: Software Engineering in Practice*, 45-54.

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security*, 254-269. https://doi.org/10.1145/2976749.2978309

Mehar, M. I., Shier, C. L., Giambattista, A., Gong, E., Fletcher, G., Sanayhie, R., ... & Laskowski, M. (2019). Understanding a revolutionary and flawed grand experiment in blockchain: The DAO attack. *Journal of Cases on Information Technology, 21*(1), 19-32. https://doi.org/10.4018/JCIT.2019010102

Merkel, D. (2014). Docker: Lightweight Linux containers for consistent development and deployment. *Linux Journal, 2014*(239), 2.

Miller, B. P., Fredriksen, L., & So, B. (1990). An empirical study of the reliability of UNIX utilities. *Communications of the ACM, 33*(12), 32-44. https://doi.org/10.1145/96267.96279

MITRE. (2024). *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/

Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Dinaburg, A. (2019). Manticore: A user-friendly symbolic execution framework for binaries and smart contracts. *Proceedings of the 34th IEEE/ACM International Conference on Automated Software Engineering*, 1186-1189. https://doi.org/10.1109/ASE.2019.00133

Mueller, B. (2018). Smashing Ethereum smart contracts for fun and real profit. *Proceedings of the 9th HITB Security Conference*.

Newman, S. (2015). *Building microservices: Designing fine-grained systems*. O'Reilly Media.

Ollama. (2024). *Ollama: Get up and running with large language models locally*. https://ollama.ai/

OWASP. (2023). *OWASP Smart Contract Top 10*. https://owasp.org/www-project-smart-contract-top-10/

Paradigm. (2021). *Foundry: A blazing fast, portable and modular toolkit for Ethereum application development*. https://github.com/foundry-rs/foundry

Parnas, D. L. (1972). On the criteria to be used in decomposing systems into modules. *Communications of the ACM, 15*(12), 1053-1058. https://doi.org/10.1145/361598.361623

Perez, D., & Livshits, B. (2021). Smart contract vulnerabilities: Vulnerable does not imply exploited. *Proceedings of the 30th USENIX Security Symposium*, 1325-1341.

Python. (2022). *What's new in Python 3.11*. https://docs.python.org/3/whatsnew/3.11.html

Qin, K., Zhou, L., Livshits, B., & Gervais, A. (2021). Attacking the DeFi ecosystem with flash loans for fun and profit. *Proceedings of the 25th International Conference on Financial Cryptography and Data Security*, 3-32. https://doi.org/10.1007/978-3-662-64322-8_1

Rameder, H., Di Angelo, M., & Salzer, G. (2022). Review of automated vulnerability analysis of smart contracts on Ethereum. *Frontiers in Blockchain, 5*, 814977. https://doi.org/10.3389/fbloc.2022.814977

Ross, R., McEvilley, M., & Oren, J. C. (2016). *Systems security engineering: Considerations for a multidisciplinary approach in the engineering of trustworthy secure systems* (NIST Special Publication 800-160). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-160

Schneier, B. (2000). *Secrets and lies: Digital security in a networked world*. John Wiley & Sons.

SCSVS. (2023). *Smart Contract Security Verification Standard*. https://github.com/securing/SCSVS

Sun, Y., Wu, D., Xue, Y., Liu, H., Wang, H., Xu, Z., ... & Liu, Y. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *Proceedings of the 46th International Conference on Software Engineering*, 1-12. https://doi.org/10.1145/3597503.3623318

Tsankov, P., Dan, A., Drachsler-Cohen, D., Gervais, A., Bünzli, F., & Vechev, M. (2018). Securify: Practical security analysis of smart contracts. *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*, 67-82. https://doi.org/10.1145/3243734.3243780

Werner, S. M., Perez, D., Gudgeon, L., Klages-Mundt, A., Harz, D., & Knottenbelt, W. J. (2024). SoK: Decentralized finance (DeFi) attacks. *Proceedings of the 45th IEEE Symposium on Security and Privacy*, 1-18.

Zhou, L., Xiong, X., Ernstberger, J., Chaliasos, S., Wang, Z., Wang, Y., ... & Gervais, A. (2023). SoK: Decentralized finance (DeFi) incidents. *Proceedings of the 44th IEEE Symposium on Security and Privacy*, 2444-2461. https://doi.org/10.1109/SP46215.2023.10179435

---

*Nota: Las referencias siguen el formato APA 7ma edición.*
