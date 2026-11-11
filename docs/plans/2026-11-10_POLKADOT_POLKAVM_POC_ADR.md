# ADR: viabilidad F0 del PoC PolkaVM (`resolc` + capa de diferencias + PolkaGuard)

> Creado: 2026-11-11 · Owner: Fernando Boiero
> Fase: **F0 — Spike de viabilidad (BLOQUEANTE)** de `docs/plans/2026-11-10_POLKADOT_POLKAVM_POC.md`
> Estado: **GATE PASADO ✅ (2026-11-11).** El owner habilitó la ejecución de `resolc`; el compile
> end-to-end se verificó en este host y las diferencias clave se confirmaron empíricamente (§3).
> **ACCEPTED — estrategia de tool: (b) capa nativa + PolkaGuard opcional** (§6). Listo para F1.

---

## 1. Contexto

F0 debe verificar, end-to-end en este host, que (a) `resolc` compila un contrato Solidity a PolkaVM,
(b) la lista de diferencias PolkaVM↔EVM que chequea la capa nativa está confirmada contra la doc
actual, y (c) si se usa PolkaGuard, corre y dispara. (a) y (c) requieren **ejecutar binarios
externos**; (b) es read-only y está hecho.

## 2. Toolchain del host (verificado, read-only)

| Componente | Estado | Nota |
|---|---|---|
| node / npm / npx | **v22.13.1 / 10.9.2 / presente** | vía para `@parity/resolc` |
| rustc / cargo | **1.90.0 / 1.90.0** | PolkaGuard (cargo) podría pedir rustc más nuevo — verificar |
| rustup | 1.28.2 | overrides per-dir disponibles |
| **solc** | **0.8.24** (`/usr/local/bin/solc`) | frontend que `resolc` necesita; compatible con `^0.8.0` |
| **resolc** | **NO instalado** | npm `@parity/resolc` alcanzable (HTTP 200); último release v1.5.0 (`paritytech/revive`) |
| **polkaguard** | **NO instalado** | se construiría con cargo desde `rtb-12/polkaguard` |
| registro npm | alcanzable (200) | descarga factible |

## 3. Gate — PASADO ✅ (evidencia local)

El owner habilitó la regla de permiso `Bash` para `resolc`/`npx` (en F0 el auto-mode lo había
denegado con `[Code from External]`, mismo muro que Caracal; no se bypasseó — se escaló y el owner
lo habilitó). Evidencia corrida en este host:

- **`resolc` versión:** `1.5.0+commit.2942b3a.llvm-23.1.3` (vía `npx @parity/resolc@latest`). Backend
  LLVM → PolkaVM. Usa `solc 0.8.24` (`/usr/local/bin/solc`) como frontend.
- **Compile OK → PolkaVM:** `resolc --bin Storage.sol` → **exit 0**, emite
  `Storage_sol_Storage.polkavm` (**1.5 kB**, bytecode PolkaVM; `--bin` escribe el artefacto a archivo,
  por eso stdout vacío). Gate principal **PASADO**.
- **Clase (A) confirmada empíricamente:** un contrato con `extcodecopy` en assembly →
  `resolc --bin ExtCode.sol` **falla en compilación**, **exit 1**:
  `Error: LLVM IR generator: The EXTCODECOPY instruction is not supported`. Confirma que los opcodes
  de clase (A) los rechaza `resolc` (no son trabajo de MIESC).
- **`SELFDESTRUCT` — RESUELTO (corrige §4):** un contrato con `selfdestruct(to)` **COMPILA**
  (`resolc --bin Destruct.sol` → exit 0, `.polkavm` emitido). O sea **no** es un error de compilación;
  es un caso de clase (B) **silencioso** (compila, pero su semántica en PolkaVM difiere de EVM) →
  la capa MIESC lo flaggea como patrón, no lo trata como opcode rechazado.

**Toolchain fijado para F4 (bootstrap/Docker):** `@parity/resolc@1.5.0` + `solc 0.8.24`.

## 4. Diferencias PolkaVM ↔ EVM — CONFIRMADAS (read-only, sin ejecución)

Leído directamente en `paritytech.github.io/revive/user_guide/differences.html` (revive compiler
book) + README de `paritytech/revive`. Esta parte de F0 **está hecha** y confirma §0.3 del plan, con
una corrección importante: hay **dos clases**, y sólo una tiene valor de auditoría.

**(A) Rechazadas en compilación por `resolc`** (error, no compilan) → trabajo del compilador, la capa
MIESC **no** las re-flaggea: `EXTCODECOPY`, `PC`, `BLOBHASH`, `BLOBBASEFEE`, `SLOTNUM`.

**(B) Diferencias SILENCIOSAS de runtime** (compilan igual, se comportan distinto) → **esto es lo que
chequea la capa nativa** (código correcto en EVM, inseguro/roto en PolkaVM):

| Diferencia silenciosa | Enforcement | Impacto | Chequeo MIESC |
|---|---|---|---|
| No aplica la regla 63/64 del gas al llamar contratos (README de revive; el libro aconseja limitar gas al llamar untrusted) | silent runtime | **DoS** en llamadas externas | `call`/`delegatecall` a untrusted sin gas limitado |
| Memoria = buffer fijo 128kb; fuera de rango **trapea** (`OutOfBound`); punteros 32-bit → `OutOfGas` | runtime trap | DoS por memoria | buffers/arrays no acotados |
| Calldata/returndata capadas (~128kb) | runtime | payloads grandes fallan | payloads potencialmente grandes |
| `CREATE`/`CREATE2`: code-hash + buffer de args (no deploy-code); `address.creationCode` → keccak256 del bytecode, no el bytecode; assembly de deploy "might fall apart" | silent runtime | assumptions de factory/precompute de address rotas | `CREATE2`/`creationCode`/assembly de deploy |
| `PREVRANDAO`/`DIFFICULTY` → constante `2500000000000000` | silent runtime | randomness predecible/constante | `block.prevrandao`/`difficulty` como entropía |
| Orden de init con via-ir: constructores base antes de inicializar state vars derivadas (ej. del libro: `0` en vez de `1`) | silent runtime | lógica de init distinta | dependencia de orden base↔derivada en constructor |
| En constructor: `calldataload`/`calldatacopy` offset ignorado (→0); `codesize` → calldata size | silent runtime | lógica de constructor distinta | esos opcodes en constructor |
| `SELFDESTRUCT`: **COMPILA** con resolc (verificado en F0, exit 0) — no es error de compilación; su comportamiento en runtime en PolkaVM **podría** diferir de EVM (compila verificado; runtime sin confirmar) | silent runtime | lógica/semántica distinta | flag: uso de `selfdestruct`/`suicide` |

## 5. PolkaGuard — evaluación (read-only, sin ejecución)

| Señal | Valor |
|---|---|
| Licencia | MIT (compatible AGPL-3.0) |
| Stars / forks / issues | **0 / 0 / 0** |
| Último push | **2025-06-15** (~17 meses stale) |
| Commits | ~48 (proyecto chico, single-author) |
| Módulos (`src/`) | `analyzer`, `cli`, `config`, `deployment`, `linter`, `models`, `zk`, `fork.rs` |
| Checks (README) | compatibility (opcodes EVM-incompat), security (reentrancy/unchecked/access), resources (ref_time/proof_size/storage) |
| Salida | text / JSON (**no SARIF**) |

**Veredicto:** es un proyecto real pero **grado-hackathon, procedencia floja** (0★, stale, sin
auditar, un autor) — riesgo tipo shadowhare (saga Cairo). **Apto para corroboración opcional, no como
motor primario.** Además, sus checks de "compatibility" apuntan sobre todo a la clase (A) de §4
(opcodes que `resolc` ya rechaza en compilación) → solapamiento bajo con el valor real (clase B).

## 6. Estrategia de tool (Decisión Abierta #2) — recomendación con evidencia

**Recomendado: (b) capa nativa MIESC + PolkaGuard opcional.**
- **Base: capa nativa** que implementa las reglas de §4(B), *grounded* en la doc oficial de revive
  (no en un tool de terceros flojo). Máximo control, reproducible, sin dep externa frágil.
- **PolkaGuard: opcional/corroboración** (opt-in, como cualquier tool externo), para subir confianza
  donde coincida (p.ej. reentrancy). No es dependencia del PoC.
- Se descarta (c) "PolkaGuard primero" por la procedencia; (a) "sólo nativa" es el fallback si en el
  gate PolkaGuard resulta inusable.

## 7. Checklist de cierre de F0 — estado

1. [x] Owner habilitó la ejecución de `resolc` (regla `Bash`).
2. [x] `resolc` 1.5.0 vía `npx @parity/resolc`, encuentra `solc 0.8.24`.
3. [x] `Storage.sol` → `Storage_sol_Storage.polkavm` (1.5 kB), exit 0. **Gate PASADO.**
4. [x] `SELFDESTRUCT` compila (clase B silent); `EXTCODECOPY` rechazado en compilación (clase A).
5. [ ] **Diferido (no bloqueante):** correr PolkaGuard. Por la Decisión #2 = (b), PolkaGuard es
   corroboración **opcional**; además construirlo (cargo, repo 0★/sin auditar) es código externo
   pesado. Se evalúa su ejecución más adelante si se decide activarlo; no es parte del gate.
6. [x] Estado de este ADR: **ACCEPTED**. → Proceder a F1 con el OK del owner.

---

### Apéndice — comandos de reproducción

```bash
# read-only (hechos sin bloqueo):
node --version; cargo --version; solc --version
gh api repos/rtb-12/polkaguard --jq '{stars:.stargazers_count,pushed_at}'
# diferencias: paritytech.github.io/revive/user_guide/differences.html

# BLOQUEADO por [Code from External] (requiere permiso del owner):
npx --yes @parity/resolc@latest --bin \
  <scratchpad>/polkavm_spike/Storage.sol
```
