# Plan: PoC Polkadot — auditoría de contratos PolkaVM / `pallet-revive` (Solidity vía `resolc`)

> Creado: 2026-11-10 · Owner: Fernando Boiero · Estado: **listo para ejecutar tras resolver las Decisiones Abiertas #1 y #2**
> Contexto: extender MIESC hacia Polkadot siguiendo el molde del PoC Cairo/Caracal (su plan + ADR):
> integración aditiva, nivel **Experimental**,
> EVM intacto. **Target primario decidido por el owner: PolkaVM / `pallet-revive`** — a donde se
> movió la comunidad Polkadot tras la discontinuación de ink!. ink!/Scout queda como track
> secundario documentado (§9). MIESC sigue siendo EVM-full; Polkadot entra como future-work
> experimental.

---

## 0. Qué investigamos antes de escribir este plan (evidencia verificada)

Todo está verificado contra fuentes primarias (GitHub API read-only, el *revive compiler book*
oficial, docs de Polkadot, foro). Lo sin verificar está marcado y es ítem del gate F0.

### 0.1 "Contrato de Polkadot" tiene TRES modelos — por qué PolkaVM es el target

| Modelo | Lenguaje → target | Runtime | Estado (nov-2026) | ¿Superficie nueva? |
|---|---|---|---|---|
| ink! v5 | Rust → WASM | `pallet-contracts` (legacy) | **lenguaje descontinuado** (ene-2026) | Sí, pero ecosistema en sunset |
| Solidity en parachains EVM | Solidity → EVM | Frontier / `pallet-evm` (Moonbeam, Astar EVM) | estable | **No** — es EVM puro, MIESC ya lo cubre |
| **PolkaVM / `pallet-revive`** ★ | **Solidity → PolkaVM/RISC-V** (vía `resolc`) | `pallet-revive` en **Asset Hub** | **el presente/futuro oficial** de los contratos en Polkadot | **Sí** (nueva semántica, no-EVM-bytecode) |

Hechos duros (verificados):

- **ink! fue descontinuado como lenguaje.** Doc oficial use.ink: *desde enero de 2026 el equipo no
  puede mantener ni desarrollar ink!*. Foro Polkadot: W3F y Parity lo confirmaron el 23-ene-2026;
  la recomendación oficial a los devs es **usar `pallet-revive` (API de bajo nivel) o reescribir en
  Solidity**. Por eso ink! es track secundario, no primario.
- **Las parachains EVM (Moonbeam, Astar EVM) son EVM a secas** (Frontier/`pallet-evm`, motor
  **SputnikVM**, bytecode EVM estándar; corren dapps Ethereum sin modificar, cuentas H160 —
  verificado). El análisis Solidity/EVM que MIESC **ya** tiene aplica tal cual → **no hay superficie
  nueva**. Se menciona como fortaleza de posicionamiento, no es PoC.
- **PolkaVM/`pallet-revive` es a donde se movió la comunidad.** Verificado: `pallet-revive` ejecuta
  los contratos vía **PolkaVM (RISC-V)**, *no* un intérprete EVM (ese es el stack viejo Frontier/
  `pallet-evm`). Solidity → YUL → **`resolc`** (`paritytech/revive`: frontend `solc` + backend LLVM)
  → bytecode PolkaVM. La "compatibilidad Ethereum" es a **nivel JSON-RPC** (proxy
  `pallet-revive-eth-rpc`, para MetaMask/Hardhat), no a nivel de ejecución. `pallet-revive` sigue
  **experimental** (cambios que rompen; la doc de Asset Hub lo marca early-stage). *Caveat F0:*
  existe `src/vm/evm.rs` en `pallet-revive` → puede estar emergiendo un camino de input EVM;
  confirmarlo (si aparece, ahí sí aplicarían tools de bytecode EVM).

### 0.2 El insight que hace viable el PoC — y lo diferencia de Cairo/ink!

Los contratos PolkaVM que vamos a auditar **son Solidity de código fuente** (compilado después por
`resolc`). Eso significa:

1. **MIESC ya los analiza parcialmente, a nivel fuente.** Los analizadores source-level que MIESC
   tiene en su Layer 1 (verificado en `constants.py`: **`slither`, `aderyn`, `solhint`, `semgrep`,
   `wake`**) + detectores por patrones + intelligence engine aplican de entrada a cualquier `.sol`.
   `QUICK_TOOLS = ["slither", "aderyn", "solhint"]` es la base. No arrancamos de cero.
2. **Lo que NO aplica:** las tools de **bytecode/símbolico EVM** (Layer 3: `mythril`, `manticore`,
   `halmos`, `oyente`, `pakala`) y el **fuzzing de ejecución EVM** (Layer 2: `echidna`, `medusa`,
   `foundry`), porque el target es **RISC-V, no EVM** — no hay opcodes EVM en el artefacto final.
3. **El valor nuevo del PoC** es una **capa de "diferencias con EVM"**: flaggear lo que es válido en
   EVM pero rompe (o cambia de semántica) en PolkaVM — exactamente lo que el análisis EVM genérico
   **pasa por alto o interpreta mal**.

### 0.3 Diferencias PolkaVM ↔ EVM — qué chequea la capa nueva (fuente: *revive compiler book*)

Leído en `paritytech.github.io/revive/user_guide/differences.html` (+ README de `paritytech/revive`,
tabla OpenGuild). **Hay que distinguir dos clases**, y esto define el valor del PoC:

**(A) Rechazadas en tiempo de compilación por `resolc`** (error, no compilan) — es trabajo del
compilador, **bajo valor de auditoría** (MIESC no necesita re-flaggearlas, un fixture que las use
*no compila* con resolc): `EXTCODECOPY`, `PC`, `BLOBHASH`, `BLOBBASEFEE`, `SLOTNUM`.

**(B) Diferencias SILENCIOSAS de runtime** (compilan igual, se comportan distinto) — **éste es el
alto valor**: código que pasa un análisis EVM y es correcto en EVM, pero inseguro/roto en PolkaVM.
La capa nueva de MIESC chequea esto (grounded, no inventado):

| Diferencia silenciosa (compila igual) | Enforcement | Impacto de seguridad | Chequeo MIESC |
|---|---|---|---|
| **No aplica la regla 63/64 del gas** al llamar a otros contratos (lo dice el README de revive; el libro aconseja limitar gas al llamar untrusted) | silent runtime | **vector de DoS** en llamadas externas | flag: `call`/`delegatecall` a untrusted sin gas limitado |
| **Memoria = buffer fijo de 128kb**; acceder más allá **trapea** (`OutOfBound`); punteros de 32-bit → `OutOfGas` | runtime trap | DoS por memoria | flag: buffers/arrays de memoria no acotados |
| **Calldata/returndata capadas (~128kb)** | runtime | llamadas con payload grande fallan | flag: payloads potencialmente grandes |
| **`CREATE`/`CREATE2`**: el runtime toma *code hash* + buffer de args, no deploy-code concatenado; `address.creationCode` devuelve el **keccak256 del bytecode**, no el bytecode; assembly de deploy hecho a mano "might fall apart" | silent runtime | assumptions de factory/precompute de address rotas | flag: `CREATE2`/`creationCode`/assembly de deploy |
| **`PREVRANDAO`/`DIFFICULTY` → constante** `2500000000000000` | silent runtime | randomness basada en ellos es **predecible/constante** | flag: uso de `block.prevrandao`/`difficulty` como entropía |
| **Orden de init con via-ir**: constructores base corren antes de inicializar state vars derivadas (ej. del libro: devuelve `0` en vez de `1`) | silent runtime | lógica de inicialización distinta | flag: dependencia de orden base↔derivada en constructor |
| En constructor: `calldataload`/`calldatacopy` offset ignorado (→0); `codesize` devuelve calldata size | silent runtime | lógica de constructor distinta | flag: esos opcodes en constructor |
| **`SELFDESTRUCT`**: *no* figura en differences.html (sí en la tabla OpenGuild como no soportado) | **sin verificar** | lógica rota si se usa | **confirmar en F0** antes de incluirlo |

### 0.4 Tooling existente (el análogo a Caracal) — verificado con licencia

| Herramienta | Qué hace | Entrada | Licencia | AGPL-3.0 compat | Salida | Estado | Fuente |
|---|---|---|---|---|---|---|---|
| **PolkaGuard** (`rtb-12/polkaguard`) | checks PolkaVM sobre **Solidity source** | `.sol` (+ `solc`+`resolc`) | **MIT** | Sí | **text / JSON** (no SARIF) | **Débil**: 0★, push 2025-06-15, origen hackathon, "production ready" junto a "in active development" | GitHub API, README |
| **`resolc`** (`paritytech/revive`) | compilador Solidity → PolkaVM (no es analizador) | `.sol` | **Apache-2.0** | Sí | bytecode PVM | **Activo** (push 2026-11-09, v1.5.0) | GitHub API |
| Scout (`CoinFabrik/scout-audit`) | detectores **ink! v5** | proyecto Cargo/ink! | MIT | Sí | SARIF/JSON | activo, pero **ink! v5/`pallet-contracts`** (legacy) | GitHub API |
| pallet-verifier | FRAME pallets (no contratos) | — | — | — | MIRAI | para runtime, fuera de alcance | Foro Polkadot |

**PolkaGuard** es el único analizador que apunta a PolkaVM, y sus checks son **justo** la capa de
diferencias (§0.3): compatibilidad (`selfdestruct`, `extcodesize`/opcodes EVM-incompat), seguridad
(reentrancy, unchecked calls, access control) y recursos (ref_time, proof_size, storage). CLI:
`polkaguard --path X.sol --checks security,compatibility --format json analyze`. **Pero su
procedencia es floja** (0★, stale, grado-hackathon) — mismo riesgo que shadowhare en la saga Cairo.
De ahí la Decisión Abierta #2 (tool externo vs capa nativa propia).

### 0.5 Cómo resolvió el routing el PoC Cairo (molde) y por qué PolkaVM es más difícil

El PoC Cairo agregó `_is_cairo_target(path)` en `miesc/cli/commands/scan.py` **antes** de la rama
`.sol`, `CAIRO_TOOLS` en `constants.py`, y `_cairo_corroborate()` (confianza +0.15 cuando dos
señales coinciden). Disparó por **extensión `.cairo`** / `Scarb.toml`.

**El problema de routing de PolkaVM es más difícil que Cairo e ink!:** un contrato Solidity para
PolkaVM **es un `.sol` idéntico** a uno para EVM — no hay extensión ni dependencia que lo distinga
a nivel de archivo. Hay que disparar por **señal explícita**: una flag `--target polkavm` /
`--chain polkadot`, o un marcador de proyecto (config de `foundry-polkadot` / `hardhat-resolc`,
`resolc` en el toolchain). `scan.py` en `main` **no tiene** flag `--chain` hoy. Esto es la
**Decisión Abierta #1**.

> Nota: los adaptadores `solana`/`near`/`stellar` declaran `.rs` pero **no están registrados en
> `ADAPTER_MAP`** (no hay colisión viva). El PoC Cairo (en una rama aparte, aún sin mergear a
> `main`) toca `scan.py`/`constants.py`/`doctor.py`/`finding_taxonomy.py` → coordinar merge
> (Decisión Abierta #5).

---

## 1. Objetivo

Que MIESC audite **contratos Solidity destinados a PolkaVM / `pallet-revive`** (los que se compilan
con `resolc` y corren en Asset Hub), combinando:

1. **El análisis Solidity source-level que MIESC ya tiene** (reusado tal cual: Slither-sobre-fuente,
   patrones, intelligence engine).
2. **Una capa nueva de "diferencias con EVM"** (§0.3) que flaggea lo específico de PolkaVM que el
   análisis EVM pasa por alto o interpreta mal.
3. **Supresión/ajuste** de findings EVM-only que **no aplican** en PolkaVM (y marcar que las tools
   de bytecode EVM no corren sobre este target).

Todo **aditivo**, nivel **Experimental**, **sin romper el camino EVM**. Salida **SARIF 2.1.0**
válida (MIESC la genera; PolkaGuard no emite SARIF, así que su parser es JSON — ver F2).

"Soporte PolkaVM" en el PoC significa:
- Routing de un target PolkaVM (por flag o marcador — Decisión Abierta #1) al set de tools correcto
  (Solidity source + capa PolkaVM), **sin** correr tools de bytecode EVM.
- La capa de diferencias (§0.3) implementada y disparando en fixtures que compilan con `resolc`.
- Mapeo por hallazgo a `type`/`severity`/`confidence`/`cwe_id`/`owasp_category`/`recommendation`.
- **Errores honestos**: si una tool externa (PolkaGuard/`resolc`) no corre o falla, `status: "error"`
  con mensaje claro, **nunca** "success" con 0 findings.

---

## 2. Restricciones del repo (obligatorias)

- **No tocar** PDFs/LaTeX de papers, notas de reproducibilidad, claims matrices ni artefactos
  canónicos de benchmark (`docs/tesis/**`, `docs/thesis*.md`). Todo lo nuevo es **aditivo** (archivos
  nuevos y fechados).
- Antes de cualquier commit que toque benchmarks o material público, correr la validación de freeze
  del proyecto.
- Autor de commits: `Fernando Boiero <fboiero@frvm.utn.edu.ar>`. Conventional commits en inglés.
  **Sin** `Co-Authored-By` ni atribución de IA.
- README **sin cambios de estado**. Al cierre, `docs/MULTICHAIN.md` puede listar Polkadot como
  **Experimental**, igual que Cairo. Nada de claims de recall/precisión sin benchmark.
- Respetar el patrón: `ToolAdapter` en `miesc/core/tool_protocol.py`, registro en `ADAPTER_MAP`
  (`miesc/cli/constants.py`). Referencia de adaptador CLI externo: `aderyn_adapter.py`.
- **No modificar `docs/MULTICHAIN.md` ni `CHANGELOG.md` hasta F6.**

---

## 3. Fases

### F0 — Spike de viabilidad PolkaVM (BLOQUEANTE, ~1–1,5 días)

1. Instalar `resolc` (`paritytech/revive` v1.5.0: npm `@parity/resolc` o binario) y `solc`.
   Compilar un `.sol` mínimo a PolkaVM para confirmar el toolchain end-to-end en este host.
2. **Confirmar la lista de diferencias de §0.3 contra el *revive compiler book* actual** (la fuente
   de opcodes faltantes/precompiles puede haber cambiado). Fijar la lista definitiva de chequeos.
3. Evaluar **PolkaGuard**: instalarlo, correr `polkaguard --path X.sol --checks
   security,compatibility --format json analyze` sobre un `.sol` con `selfdestruct` y confirmar que
   dispara; capturar su **JSON** y sus exit codes (para el parser F2). Medir madurez real (¿los
   checks andan? ¿falsos positivos?).
4. **Decidir la estrategia de tool (Decisión Abierta #2)** con evidencia: (a) capa nativa MIESC
   sola, (b) capa nativa + PolkaGuard opcional, (c) PolkaGuard primero. Recomendación por defecto:
   **(b)**.
5. Escribir el ADR `docs/plans/2026-11-10_POLKADOT_POLKAVM_POC_ADR.md`: versión de `resolc`,
   estrategia de tool, lista de diferencias confirmada, formato de salida de PolkaGuard, y mecanismo
   de routing elegido (Decisión Abierta #1).

**DoD F0 / gate:** `resolc` compila un `.sol` a PolkaVM en este host; la lista de diferencias §0.3
está confirmada contra la doc actual; si se usa PolkaGuard, corre end-to-end y dispara sobre un
contrato vulnerable conocido (exit 0 con 0 findings sobre algo que debería fallar **no es pass**).
**Si `resolc` no es instalable o PolkaGuard no sirve, FRENAR y reportar** (capa nativa sola, o
posponer). Ejecutar binarios externos puede requerir permiso explícito del owner: resolverlo con él,
nunca bypassear.

### F1 — Fixtures de prueba (~1 día)

- `examples/contracts/polkadot/polkavm_poc/`: contratos Solidity que **compilan con `resolc`**
  (verificado en F0), uno por cada diferencia **silenciosa** de §0.3(B) — las que compilan y por
  eso tienen valor de auditoría:
  - llamada externa a untrusted sin límite de gas (vector DoS por la regla 63/64 ausente).
  - buffer/array de memoria no acotado (posible trap por el buffer fijo de 128kb).
  - factory con `CREATE2` / uso de `address.creationCode` (assumptions de address rotas).
  - randomness con `block.prevrandao`/`difficulty` (constante en PolkaVM → predecible).
  - dependencia del orden de init base↔derivada en el constructor (via-ir).
- Un contrato **limpio** (compila y no dispara High/Critical).
- (Opcional) un fixture con un opcode de §0.3(A) (ej. `EXTCODECOPY`) **sólo** para documentar que
  `resolc` lo rechaza en compilación — no es un caso de la capa MIESC, es el error del compilador.
- `expected_findings.json` con ground truth por contrato.
- Capturar la salida cruda de PolkaGuard (si se usa) en `tests/fixtures/polkaguard/` para que los
  tests no dependan del binario.

### F2 — Adaptador(es) (~2 días)

- **`PolkaVMDiffAdapter`** (capa nativa, `miesc/adapters/polkavm_diff_adapter.py`): implementa
  `ToolAdapter`, análisis source-level sobre `.sol` (patrones/AST, reusa utilidades existentes) para
  las reglas de §0.3. `is_optional=True`, `requires_llm=False`. Usa `create_finding`/`create_result`/
  `normalize_severity` del protocolo. Mapeo por regla → `type`/`severity`/`cwe_id`/`owasp_category`/
  `recommendation`.
- **`PolkaGuardAdapter`** (si Decisión Abierta #2 = b/c, `miesc/adapters/polkaguard_adapter.py`):
  invoca `polkaguard ... --format json analyze`, parsea el **JSON** (testeado con fixtures F1),
  **error honesto** mapeando exit codes capturados en F0. Timeout propio.
- Ambos documentan que MIESC **no** corre tools de bytecode EVM sobre un target PolkaVM.

### F3 — Integración al pipeline (~2 días)

- Registrar los adaptadores en `ADAPTER_MAP` y un `POLKAVM_TOOLS` en `constants.py` (análogo a
  `CAIRO_TOOLS`): Solidity source-level existentes + capa PolkaVM (+ PolkaGuard opcional).
- **Routing explícito (Decisión Abierta #1):** agregar una flag `--target polkavm` (o `--chain
  polkadot`) y/o detección por marcador de proyecto (`foundry-polkadot`/`hardhat-resolc`/`resolc` en
  toolchain). Sin la señal, un `.sol` sigue el camino **EVM** normal (no-regresión).
- **Supresión/ajuste EVM-only:** cuando el target es PolkaVM, no correr tools de bytecode EVM y
  marcar/ajustar findings que asumen semántica EVM que no aplica.
- Taxonomía: agregar categorías **nuevas y específicas de PolkaVM** en `finding_taxonomy.py`
  (aditivo — no pisar claves que ya emiten los adaptadores EVM). Corroboración +0.15 cuando la capa
  nativa y PolkaGuard coinciden (replica `_cairo_corroborate`), p.ej. en reentrancy.
- Verificar que JSON, **SARIF 2.1.0** y reportes renderizan findings PolkaVM sin romperse.

### F4 — Instalación y operación (~1 día)

- `miesc doctor` muestra `resolc` (y PolkaGuard si aplica) con versión y estado.
- `scripts/bootstrap_researcher_tools.sh`: instalar `resolc` (y PolkaGuard) con versión fijada en el
  ADR.
- Docker: capa **opt-in** con `resolc`/PolkaGuard en la imagen full.
- CI: job **opcional** que corra los tests de integración PolkaVM; no bloquea el CI principal.

### F5 — Tests (~1–2 días)

- **Unitarios** (sin binario): reglas de la capa nativa (§0.3) sobre fixtures; parsing del JSON de
  PolkaGuard; manejo de errores (resolc/PolkaGuard ausente, no compila, timeout) → nunca "success"
  vacío.
- **Integración** (marcados, skip si falta el toolchain): correr sobre
  `examples/contracts/polkadot/polkavm_poc/` vs `expected_findings.json`.
- **E2E CLI**: `miesc scan examples/contracts/polkadot/polkavm_poc --target polkavm` devuelve
  findings de la capa PolkaVM (+ source-level), SARIF válido. **No-regresión**: el mismo `.sol` sin
  la señal PolkaVM sigue el camino EVM intacto; `pytest tests/ --no-cov` en verde.

### F6 — Documentación (~0,5 día)

- `docs/MULTICHAIN.md`: sección **Polkadot** con estado **Experimental**, los tres modelos de
  contrato, qué cubre el PoC (PolkaVM/`pallet-revive` vía Solidity source + capa de diferencias),
  limitaciones (no bytecode EVM; `pallet-revive` experimental; ink! descontinuado → track
  secundario), y nota de que las parachains EVM ya están cubiertas por el análisis EVM existente.
- Guía corta `docs/guides/POLKADOT.md`: uso con `--target polkavm`.
- `CHANGELOG.md` → `[Unreleased]`: "Experimental Polkadot/PolkaVM support (pallet-revive, resolc)".
- README: **sin cambios de estado**; a lo sumo, link a la guía.

---

## 4. Criterios de aceptación (Definition of Done)

- [ ] El ADR de F0 está escrito: `resolc` verificado, estrategia de tool decidida, lista de
      diferencias §0.3 confirmada, mecanismo de routing elegido.
- [ ] La capa de diferencias PolkaVM dispara en sus fixtures (que compilan con `resolc`).
- [ ] El contrato limpio no tiene findings High/Critical.
- [ ] `miesc scan --target polkavm` enruta a las tools correctas y **no** corre tools de bytecode
      EVM; sin la señal, un `.sol` sigue el camino EVM (no-regresión verificada con test).
- [ ] Si se integra PolkaGuard: corre, se parsea su JSON, y la corroboración sube la confianza
      cuando coincide con la capa nativa.
- [ ] La salida **SARIF 2.1.0** es válida y los reportes renderizan.
- [ ] `miesc doctor`, bootstrap y Docker instalan y detectan `resolc` (+ PolkaGuard si aplica).
- [ ] Tests unitarios y de integración nuevos; suite completa en verde; camino EVM intacto.
- [ ] Ningún archivo de paper/benchmark canónico fue modificado; la validación de freeze pasa.

---

## 5. Fuera de alcance (milestones futuros / grant)

- Corpus de benchmark Polkadot etiquetado + métricas recall/FP.
- Análisis a nivel **bytecode PolkaVM/RISC-V** (sólo hacemos source-level + capa de diferencias).
- Verificación formal sobre PolkaVM; plugin/GitHub Action específicos.
- ink! v6/`pallet-revive` nativo (Rust) como target de primera clase.
- Extender el routing PolkaVM a `miesc audit` (el PoC cubre el entry point `miesc scan`; `audit`
  reusa el mismo routing como follow-up).

---

## 6. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| `pallet-revive` es experimental (cambios que rompen) | Pinnear `resolc` en el ADR; posicionar Experimental; lista de diferencias versionada |
| PolkaGuard es grado-hackathon (0★, stale, "production ready" dudoso) | No depender de él: **capa nativa propia** como base (Decisión Abierta #2); PolkaGuard opcional/corroboración |
| Routing: un `.sol` PolkaVM es idéntico a uno EVM | Señal explícita (`--target polkavm`/marcador de proyecto); sin señal → camino EVM; test de no-regresión (Decisión Abierta #1) |
| Falsos "no aplica": suprimir findings EVM que **sí** aplican | Suprimir sólo lo type-determinístico que PolkaVM cambia (opcodes no soportados, address derivation); el resto se marca, no se dropea (recall-safe, criterio MIESC) |
| Lista de diferencias desactualizada | Confirmarla contra el *revive book* en F0; versionarla en el ADR |
| Las tools de bytecode EVM no aplican a PolkaVM | Documentarlo explícitamente; no correrlas en el routing PolkaVM |
| Romper el camino EVM | Routing por señal explícita no toca el `.sol` EVM por defecto; suite + no-regresión deben pasar |

---

## 7. Secuencia de commits sugerida

1. `docs(plans): Polkadot/PolkaVM PoC plan + ADR skeleton`
2. `docs(plans): resolc + PolkaVM diff compatibility ADR (F0 gate)`
3. `test(fixtures): PolkaVM Solidity PoC contracts + expected findings`
4. `feat(adapters): PolkaVMDiffAdapter (EVM-difference checks) [+ PolkaGuardAdapter]`
5. `feat(pipeline): route --target polkavm to source-level + PolkaVM layer; taxonomy + corroboration`
6. `chore(tooling): doctor, bootstrap, Docker and optional CI for resolc/PolkaGuard`
7. `docs: MULTICHAIN + Polkadot guide + CHANGELOG`

---

## 8. Decisiones abiertas (requieren al owner — marcadas como tales)

### Decisión de target — RESUELTA (owner, 2026-11-10)

El target primario se decidió con el owner en sesión: **PolkaVM / `pallet-revive`**. Alternativas
consideradas y descartadas:
- **ink! v5 + Scout** (era la recomendación inicial del plan): tool maduro (MIT, SARIF nativo, 34
  detectores), pero ink! fue **descontinuado** (ene-2026) → se baja a track secundario (§9).
- **Parachains EVM (Moonbeam/Astar EVM)**: EVM puro, MIESC ya lo cubre → **no es PoC**.
Tradeoff aceptado de PolkaVM: superficie nueva y alineada con el futuro de Polkadot, a cambio de
tooling externo inmaduro (de ahí la capa nativa propia, Decisión Abierta #2).

### Decisión Abierta #1 — Mecanismo de routing — **RESUELTA (owner): flag `--target polkavm`**

Resuelta a favor de (a): flag explícita `--target polkavm` en `scan.py` (no existía `--chain`).
Implementada en F3 — sin la flag, el camino EVM queda intacto. El marcador de proyecto (b) se
descartó por frágil. Un `.sol` PolkaVM es indistinguible de uno EVM por contenido, de ahí la señal
explícita.

### Decisión Abierta #2 — Estrategia de tool — **RESUELTA: (b) capa nativa + PolkaGuard opcional**

Resuelta a favor de (b): la **capa nativa `polkavm_diff`** (reglas de §0.3, grounded en el *revive
book*) es el motor; **PolkaGuard queda opcional** (no se integró en el PoC por procedencia floja —
0★/stale). (a) y (c) descartadas. Evidencia en el ADR F0 §5–§6.

### Decisión Abierta #3 — Alcance de la supresión EVM-only

¿Qué findings del pipeline EVM suprimimos/ajustamos para un target PolkaVM? Mínimo seguro: lo
type-determinístico que PolkaVM cambia (opcodes no soportados, address derivation). El resto se
**marca** (needs_review), no se dropea, respetando el criterio recall-safe de MIESC.

### Decisión Abierta #4 — ink! como track secundario

ink!/Scout (v5/`pallet-contracts`) queda documentado (§9). ¿Lo dejamos sólo documentado, o metemos
un `ScoutAdapter` mínimo en el mismo PoC para cubrir también contratos ink! ya desplegados? (Scout es
MIT, SARIF nativo, 34 detectores — barato de sumar, pero es ecosistema en sunset.)

### Decisión Abierta #5 — Merge order con el PoC Cairo

El PoC Cairo (rama aparte, aún sin mergear a `main`) toca los mismos archivos (`scan.py`,
`constants.py`, `doctor.py`, `finding_taxonomy.py`, `MULTICHAIN.md`, `CHANGELOG.md`). Definir orden
de merge y si generalizamos el routing (`_is_cairo_target`/target PolkaVM) a un dispatcher
multichain común.

---

## 9. Track secundario documentado — ink! v5 + Scout

No es el target primario (ink! está descontinuado), pero es barato de sumar y hay contratos ink! ya
desplegados que siguen siendo auditables:

- **Scout** (`CoinFabrik/scout-audit`, MIT, activo): detectores ink!, **SARIF/JSON nativo**, 34 casos
  de test en `test-cases/ink/`, motor Dylint (`nightly-2025-09-18`). **Fija `ink = "5.0.0"`** → cubre
  **ink! v5 sobre `pallet-contracts`**, no v6. Corre `cargo scout-audit --output-format sarif` desde
  el dir del proyecto (que debe compilar); setear `SCOUT_OFFLINE=1`; el build nightly+Dylint puede
  exceder el timeout de 300s de `run_tool`.
- **Routing ink!:** por **dependencia `ink` en `Cargo.toml`** (no por `.rs`, que colisiona latente con
  Solana/NEAR/Stellar).
- Si el owner lo quiere en este PoC, es la Decisión Abierta #4 (un `ScoutAdapter` análogo al
  `CaracalAdapter` de Cairo).

---

## 10. Posicionamiento (resumen)

- **Polkadot entra como Experimental** en `docs/MULTICHAIN.md`, igual que Cairo. MIESC sigue siendo
  **EVM-full**; el resto es future-work.
- **Target primario: PolkaVM/`pallet-revive`** (Solidity vía `resolc`) — a donde se movió la
  comunidad. MIESC lo cubre reusando su análisis Solidity source-level + una capa de diferencias con
  EVM.
- **Parachains EVM (Moonbeam, Astar EVM): ya cubiertas** por el análisis EVM existente — fortaleza,
  no PoC.
- **ink!: track secundario** (lenguaje descontinuado ene-2026; Scout cubre v5 legacy).
- Nada de claims de recall/precisión sin benchmark. README sin cambios de estado.

---

## 11. Fuentes (verificadas, read-only)

- Diferencias PolkaVM↔EVM: *revive compiler book* (`paritytech.github.io/revive/user_guide/differences.html`),
  README de `paritytech/revive` (regla 63/64 ausente = DoS; heap fijo; calldata capada; address por
  hash), tabla OpenGuild (EXTCODECOPY/CODECOPY/PC/SELFDESTRUCT).
- `resolc`/revive: `paritytech/revive` (GitHub API: Apache-2.0, push 2026-11-09, v1.5.0; solc
  frontend + LLVM).
- PolkaGuard: `rtb-12/polkaguard` (GitHub API: MIT, 0★, push 2025-06-15; README: checks, CLI, JSON).
- ink! descontinuado: use.ink docs ("since January 2026… unable to actively maintain"); foro
  "Discontinuation of ink!" (W3F/Parity, 23-ene-2026).
- `pallet-revive`/Asset Hub: docs.polkadot.com, crates.io `pallet-revive` (experimental).
- Scout: `CoinFabrik/scout-audit` (GitHub API: MIT; README: `--output-format sarif,json`, Dylint,
  nightly-2025-09-18; `ink = "5.0.0"` en test-cases; 34 detectores ink!).
- Routing MIESC: `miesc/cli/commands/scan.py`, `constants.py`, adaptadores `solana`/`near`/`stellar`
  (`.rs`, no registrados), y el diff del PoC Cairo.

---

## Prompt para pasarle a la sesión de MIESC (cuando el owner apruebe Decisiones #1 y #2)

> Ejecutá el plan `docs/plans/2026-11-10_POLKADOT_POLKAVM_POC.md` fase por fase, target **PolkaVM /
> pallet-revive** (Solidity vía resolc). Empezá por F0 y **no avances a F2** hasta tener el ADR con
> `resolc` verificado compilando a PolkaVM, la estrategia de tool decidida (Decisión #2), la lista
> de diferencias §0.3 confirmada contra el revive book, y el mecanismo de routing elegido (Decisión
> #1); si algo no es viable, frená y reportame las opciones. Respetá la §2 (sin tocar
> papers/benchmarks canónicos, cambios aditivos, corré la validación de freeze antes de commitear,
> autor Fernando Boiero <fboiero@frvm.utn.edu.ar>, conventional commits en inglés, sin
> Co-Authored-By). Routing **por señal explícita** (`--target polkavm`/marcador), nunca cambiando el
> camino EVM por defecto; test de no-regresión EVM. Al terminar cada fase, corré los tests y dame un
> resumen corto. Al final verificá cada ítem de la §4 con evidencia (comando + salida).
