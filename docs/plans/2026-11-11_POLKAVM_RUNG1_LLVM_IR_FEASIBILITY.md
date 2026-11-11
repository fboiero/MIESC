# PolkaVM Rung 1 — LLVM IR feasibility (measured)

**Date:** 2026-11-11 · **Status:** Feasibility findings (additive, no code shipped) ·
**Scope:** PolkaVM / `pallet-revive` class-(B) detection via the revive compiler's LLVM IR

## Context

MIESC's PolkaVM support splits the EVM↔PolkaVM differences into two classes (see the
[PoC plan](./2026-11-10_POLKADOT_POLKAVM_POC.md) and [ADR](./2026-11-10_POLKADOT_POLKAVM_POC_ADR.md)):

- **Class (A)** — opcodes `resolc` rejects at compile time (`EXTCODECOPY`, `BLOBHASH`, …).
  **Shipped** as the `polkavm_resolc` adapter (PR #337): it runs `resolc` and reports the
  compiler's rejection as an authoritative finding.
- **Class (B)** — *silent runtime differences*: code that compiles and is correct on the EVM
  but behaves differently on PolkaVM. Covered **heuristically at source level** by
  `polkavm_diff`. The open question: can we do better by analysing the compiler's
  intermediate representation?

The "Rung" ladder for bytecode-level analysis:

- **Rung 0** — capture `resolc` compile diagnostics (class A). *Shipped.*
- **Rung 1** — analyse the **LLVM IR** the revive compiler emits. *This document.*
- **Rung 2** — differential EVM-vs-PolkaVM execution. *Future.*
- **Rung 3** — disassemble the RISC-V blob. *Skipped (lowest value).*

A prior spike established that the `npx @parity/resolc` (`resolcjs`) wrapper does **not** expose
IR emission (only `--bin`/`--abi`/`--diff-stats`). Rung 1 therefore needs the **native** resolc.

## Setup (reproduce)

The native compiler ships as a prebuilt, checksummed binary — no local LLVM build required:

```bash
# paritytech/revive release v1.5.0, universal macOS binary (~234 MB)
gh release download v1.5.0 --repo paritytech/revive \
  --pattern 'resolc-universal-apple-darwin' --pattern 'checksums.txt'
shasum -a 256 -c <(grep resolc-universal-apple-darwin checksums.txt)   # must pass
chmod +x resolc-universal-apple-darwin

# Dump the full IR pipeline for a contract:
./resolc-universal-apple-darwin Contract.sol -O0 \
  --debug-output-dir ./ir --base-path .
```

Measured with `resolc 1.5.0+commit.2942b3a.llvm-23.1.3`, `solc 0.8.24`, macOS arm64.

## Finding 1 — the IR is reachable

`--debug-output-dir` dumps the whole pipeline per contract:

| File | Content |
|---|---|
| `*.yul` | Yul intermediate (~2–3 KB) |
| `*.unoptimized.ll` | LLVM IR before optimisation (~85–90 KB) |
| `*.optimized.ll` | LLVM IR after `-O` |
| `*.pvmasm` | PolkaVM (RISC-V) assembly |
| `*.o` | ELF object |

The npx wrapper exposed none of this. **Rung 1 is unblocked by the native binary.**

## Finding 2 — the PolkaVM host ABI is fully named

Every PolkaVM host operation appears as a **named** symbol, both in the IR
(`define internal void @<name>(…)` with an inline-asm `ecalli` body + `IMPORT_METADATA`) and in
the assembly (`ecalli N // 'name'`). The vocabulary (~30 functions):

```
address  balance  balance_of  base_fee  block_author  block_hash  block_number
call  call_evm  caller  chain_id  code_hash  consume_all_gas  deploy  deposit_event
get_immutable_data  get_storage_or_zero  hash_keccak_256  instantiate  now  origin
return_data_copy  return_data_size  seal_return  set_immutable_data
set_storage_or_clear  terminate  value_transferred  ref_time_left
```

This is a clean, tractable analysis surface — far better than raw RISC-V bytecode. It is the
real infrastructure value of Rung 1.

## Finding 3 — only `prevrandao`/`difficulty` fold to a constant

The one thing the IR shows that **source analysis cannot** is compile-time *constant folding* of
environment values. Measured with a probe reading several `block.*` values:

| Source value | Lowering in IR | Source-invisible? |
|---|---|---|
| `block.prevrandao` | **constant `2500000000000000`** (survives `-O`) | **yes** |
| `block.difficulty` | **constant `2500000000000000`** (alias of prevrandao) | **yes** |
| `block.basefee` | runtime host-call `base_fee` | no |
| `block.chainid` | runtime host-call `chain_id` | no |
| `block.gaslimit` | runtime host-call `gas_limit` | no |
| `block.coinbase` | runtime host-call `block_author` | no |
| `block.timestamp` | runtime host-call `now` | no |

So exactly **one** divergence — predictable randomness via `prevrandao`/`difficulty` — reduces to
a clean, source-invisible IR fingerprint (the magic constant `2500000000000000`, which is
PolkaVM's fixed prevrandao value). Everything else stays a runtime host-call.

> Caveat: `2500000000000000` is also `0.0025 ETH` in wei, so the constant alone is a strong but
> not bulletproof fingerprint — pair it with "source uses `block.prevrandao`/`difficulty`".

## Coverage of the six class-(B) cases (measured)

| Case | IR signal | Verdict |
|---|---|---|
| **prevrandao / difficulty** | folds to constant `2500000000000000` | **Strong — clean, source-invisible win** |
| `selfdestruct` | lowers to the `terminate` host-call | Named, but source already sees `selfdestruct` — marginal |
| Unlimited-gas call | external call is `call_evm`; `consume_all_gas` appears in **every** contract (global, not a discriminator) | Weak — the 63/64 rule is host-side, not in the lowering |
| Unbounded memory | the 128 KB limit (`Stack size = 131072`) is **global**, not per-contract | Weak–moderate — the unbounded alloc needs dataflow |
| CREATE2 address | `instantiate` + `hash_keccak_256` + `code_hash` are named | Moderate — the divergence needs source↔IR correlation |
| Constructor init-order | init sequence lives in the deploy/constructor code | Moderate–hard — needs sequence modelling |

## Verdict

Rung 1 is **feasible**, and the named host ABI is **excellent infrastructure**. But the honest
coverage is narrow:

1. Of the six class-(B) cases, exactly **one** (prevrandao/difficulty randomness) is a clean,
   source-invisible IR detector.
2. That one case **overlaps** the existing source heuristic `polkavm-predictable-prevrandao` in
   `polkavm_diff` — so the cheap Rung 1 win is a *higher-confidence corroboration of a check we
   already have*, not new coverage.
3. The genuinely **new** class-(B) coverage (CREATE2, unbounded memory, constructor order)
   requires building **dataflow / semantic analysis on top of the host ABI** — a real project,
   not a spike follow-up.

In short: Rung 1 works and the IR surface is good, but the ripe fruit is a single check we
already flag with more confidence; new coverage is genuine analysis work. This is **not** the
leap the name "Rung 1" implies, and the result is recorded here rather than built.

## Semantic-analysis spike (the "genuine analysis work" cases)

The verdict above claims CREATE2 / unbounded-memory / constructor-order need real dataflow on the
host ABI. That claim was itself spiked — with a throwaway prototype — to measure which case yields
an *extractable, reliable* detector versus a general program-analysis rabbit hole.

### Constructor init-order — extractable, but a false-positive machine without source

The `@__deploy` (constructor) IR shows the via-ir ordering divergence **explicitly**. For
`Derived is Base` (where `Base`'s constructor sets `startId = _firstId()` and `Derived` overrides
`_firstId()` to return its `offset = 1`):

```
load_storage_word(slot 1)        ; read offset — still 0, its initializer has not run
store_storage_word(slot 0, …)    ; startId = (that 0)
store_storage_word(slot 1, 1)    ; offset = 1  — only now
```

A ~40-line prototype parsed `@__deploy`, recovered each storage slot (from the `store i256 N`
into the pointer passed to `__revive_load/store_storage_word`), and flagged any slot **read before
it is written**:

| Contract | `__deploy` storage ops | Flag |
|---|---|---|
| `CleanCtor` (`a = 7; b = a + 1`) | store 0, store 1 | clean ✓ |
| `ConstructorOrder` / `Derived` | **load 1**, store 0, store 1 | **flag slot 1** ✓ (the real bug) |
| `SelfDestructUse` | load 0, store 0 | **flag slot 0** ✗ (false positive) |

So the IR read-before-init pattern is **necessary but not sufficient**: `SelfDestructUse` reads a
slot before writing it for an ordinary reason, not the ordering bug. Precision requires
**source↔IR correlation** — the flagged slot must map to a source state variable with a *declared
non-zero initializer that runs after the read*. That (IR dataflow on `@__deploy` + source
initializer correlation) is the real detector: buildable and scoped, not a rabbit hole, but not a
free pattern either.

### CREATE2 address — the IR does not beat source

The IR faithfully shows the named `code_hash`, `hash_keccak_256` and `instantiate` host calls, but
the divergence (a developer assumed the EVM CREATE2 address formula; on PolkaVM the address derives
from the code hash and `creationCode` returns a hash) is a mismatch between **developer intent** and
PolkaVM semantics. Neither source nor IR can know the developer intended EVM semantics without
modelling intent. No IR advantage here.

### Net

Of the "analysis work" cases, **constructor init-order is the only one where IR analysis genuinely
adds power and is extractable** (prototype-proven on real IR) — and even it needs source correlation
for precision. CREATE2 / unbounded-memory are source-equivalent or intent-modelling problems. The
measured value of this spike is the *knowledge* of exactly what is buildable and why, not a build.

## If Rung 1 is picked up later

- **Minimal first deliverable:** a `prevrandao`/`difficulty` magic-constant detector that runs
  native resolc with `--debug-output-dir`, parses `*.optimized.ll` for `2500000000000000`, and
  reports it (correlated with the source using `block.prevrandao`/`difficulty`) as a
  higher-confidence corroboration of `polkavm-predictable-prevrandao`.
- **The one analysis-worth-it target:** a **constructor init-order** detector — intra-procedural
  dataflow over `@__deploy`'s `__revive_load/store_storage_word` (read-before-write per slot),
  correlated with source state variables that carry a declared non-zero initializer (to drop the
  `SelfDestructUse`-style false positives measured above). Scoped as its own effort.
- **Not worth it via IR:** CREATE2 (intent mismatch) and unbounded-memory (the 128 KB limit is
  global) — source heuristics do as well or better.
- **Dependency:** the native resolc binary (≈234 MB), not the npx wrapper. Weigh this against the
  value: one narrow bug class that still needs source correlation.
