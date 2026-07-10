# Fuentes de datos — MIESC (para tesis y papers)

Descripción rigurosa de los corpus de evaluación. Cada benchmark se caracteriza
por su **procedencia**, **escala**, **calidad de ground-truth** y **criterio de
grading**, porque la validez de todo resultado depende de la validez de su
benchmark. Los corpus difieren deliberadamente en el tipo de vulnerabilidad que
ejercitan (patrón clásico vs. lógica de negocio DeFi).

---

## 1. SmartBugs-curated — patrones clásicos

- **Procedencia**: SmartBugs-curated (Durieux et al., ICSE 2020; Ferreira et al.),
  benchmark estándar de la comunidad. 143 contratos Solidity anotados.
- **Escala**: 143 contratos, 10 categorías de vulnerabilidad (reentrancy,
  arithmetic, access control, unchecked calls, bad randomness, DoS, front-running,
  time manipulation, short addresses, "other").
- **Ground-truth**: por-directorio — el contrato reside en la carpeta de su
  categoría. Etiqueta de clase, no de línea. Calidad: alta para las clases con
  firma sintáctica; la categoría "other" no define un patrón único.
- **Grading (este trabajo)**: type-aware por-contrato — un finding cuenta si su
  tipo normalizado coincide con la categoría del directorio.
- **Rol**: mide detección de **patrones clásicos**, donde el análisis estático es
  competitivo. Corpus grande → intervalos de confianza angostos.

## 2. Corpus de exploits reales — validez externa

- **Procedencia**: incidentes DeFi confirmados on-chain, fixtures externas de
  DeFiHackLabs (`github.com/SunWeb3Sec/DeFiHackLabs`). No se bundlean; se
  transcriben clase y pérdida.
- **Escala**: 11 exploits evaluados ($1.59B en pérdidas), subconjunto de 25.
- **Ground-truth**: la clase de vulnerabilidad del incidente real (reentrancy,
  access control, oracle, flash-loan governance, etc.), con la pérdida on-chain.
- **Rol**: evidencia de **validez externa** (¿detecta lo que rompió en producción?).
  n=11 → CI ancho ([52%, 95%] Wilson), reportado como indicativo.

## 3. EVMBench — lógica de negocio DeFi (exploit-verified)

Este es el corpus de **mayor calidad de ground-truth** y el más relevante para la
frontera de la detección automatizada.

- **Procedencia**: la *detect evaluation* de **OpenAI `frontier-evals`**
  (`github.com/openai/frontier-evals`), empaquetada por **Paradigm** como
  `evmbench` (`github.com/paradigmxyz/evmbench`, submódulo pinneado). Son hallazgos
  reales de **auditorías de contratos DeFi de producción** (estilo Code4rena;
  p.ej. PoolTogether, NextGen, Ethereum Credit Guild), atribuidos a auditores
  nombrados.
- **Escala**: **41 auditorías, 118 vulnerabilidades de severidad HIGH**
  (pérdida-de-fondos). Todas de lógica de negocio: manipulación de oráculo/precio,
  inflación de shares/first-depositor, flash-loans, governance, contabilidad
  cross-contract — exactamente lo que los scanners de patrones no ven.
- **Ground-truth (por qué es el mejor)**: cada vulnerabilidad viene con
  **(a)** el writeup de auditoría real (`findings/H-XX.md` con enlaces al código),
  **(b)** un **exploit PoC ejecutable** (test de Foundry que la explota),
  **(c)** un **patch** que la corrige, y **(d)** el `config.yaml` con el commit
  base y el scope. La vulnerabilidad es **exploit-verified**: existe demostrablemente
  en el código porque hay un test que la explota. Esto elimina el riesgo de
  etiqueta-fantasma que sí encontramos en corpus transcritos a mano.
- **Grading (oficial)**: la evaluación oficial usa un **juez LLM** que decide si el
  reporte del modelo describe la MISMA vulnerabilidad que la del ground-truth
  (coincidencia semántica, no de keyword/línea) — más riguroso y menos frágil que
  el matching por texto.
- **Rol**: mide la **frontera real** — detección de lógica económica DeFi. Es donde
  los modelos divergen y donde el valor del razonamiento LLM se hace visible.
- **Nota de reproducibilidad**: la extracción local de este trabajo reporta ~120
  hallazgos de alta severidad sobre 40 audits (vs. 118/41 en la copia clonada); se
  reporta como *extracción local*, no como score de leaderboard oficial. El corpus
  se obtiene con `git clone --recurse https://github.com/paradigmxyz/evmbench`.

---

## Comparación (por qué usar los tres)

| Corpus | Tipo de vuln | n | Calidad de GT | Rol |
|---|---|---|---|---|
| SmartBugs-curated | patrón clásico | 143 | directorio (clase) | robustez estadística |
| Exploits reales | DeFi on-chain | 11 | incidente confirmado | validez externa |
| **EVMBench** | **lógica DeFi** | **118** | **exploit-verified (PoC+patch+test)** | **frontera de capacidad** |

Los tres son complementarios: SmartBugs da n grande en lo clásico; los exploits
dan validez externa; **EVMBench da la frontera de lógica de negocio con el
ground-truth más defendible que existe** (verificado por exploit, de una fuente
reputada — OpenAI/Paradigm). Reportar los tres, con su grading y sus límites, es
lo que hace la evaluación periciable.

---

*Procedencia técnica y comandos de reproducción en
[`../evidence/detection_optimization_20260710/PERITAJE_REPRODUCIBILIDAD.md`](../evidence/detection_optimization_20260710/PERITAJE_REPRODUCIBILIDAD.md).*
