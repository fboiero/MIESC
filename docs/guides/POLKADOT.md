# Polkadot / PolkaVM support (Experimental)

MIESC can audit Solidity contracts targeting **PolkaVM / `pallet-revive`** — the
smart-contract engine on Polkadot's Asset Hub, where Solidity is compiled with
**`resolc`** to PolkaVM (RISC-V) bytecode rather than the EVM.

> **Experimental.** Source-level heuristics plus compile-level checks (no RISC-V
> bytecode analysis), not yet benchmark-validated. Not for production security
> decisions. See [`../MULTICHAIN.md`](../MULTICHAIN.md).

## The three Polkadot contract models

| Model | How MIESC handles it |
|---|---|
| **EVM parachains** (Moonbeam, Astar EVM, Frontier / `pallet-evm`) | Already covered by the production **EVM** analysis — run a normal scan, no flag needed. |
| **PolkaVM / `pallet-revive`** (Solidity → `resolc` → RISC-V) | This guide — `miesc scan --target polkavm`. |
| **ink!** (Rust → WASM, `pallet-contracts`) | Language discontinued (Jan 2026); secondary future work. |

## Usage

```bash
# single contract
miesc scan contract.sol --target polkavm

# a directory of contracts
miesc scan contracts/ --target polkavm --recursive

# with a JSON report
miesc scan contract.sol --target polkavm -o report.json
```

With `--target polkavm`, MIESC runs the Solidity **source-level** tools (Slither,
Aderyn, Solhint) plus two built-in PolkaVM adapters — **`polkavm_diff`** (class-B
heuristics) and **`polkavm_resolc`** (class-A, runs the compiler) — and **skips**
EVM bytecode / symbolic / fuzzing tools (Mythril, Manticore, Echidna, …) — the
compiled target is RISC-V, not EVM, so those do not apply. Without the flag, the
normal EVM path is used unchanged.

## What `polkavm_diff` checks

These are **class-(B) "silent runtime differences"** from the
[revive compiler book](https://paritytech.github.io/revive/user_guide/differences.html):
code that compiles under `resolc` and is correct on the EVM, but is insecure or
behaves differently on PolkaVM.

| Check | Difference |
|---|---|
| `polkavm-unlimited-gas-call` | No 63/64 gas rule on PolkaVM → forwarding all gas to an untrusted callee is a DoS vector |
| `polkavm-unbounded-memory` | Fixed 128kb memory buffer → unbounded allocation traps at runtime |
| `polkavm-create2-address-assumption` | Addresses derive from the code hash; `creationCode` returns a hash → EVM `CREATE2` precomputation breaks |
| `polkavm-predictable-prevrandao` | `block.prevrandao` / `difficulty` is a constant on PolkaVM → predictable randomness |
| `polkavm-constructor-init-order` | Under via-ir, base constructors run before derived state-variable initializers |
| `polkavm-selfdestruct-semantics` | `selfdestruct` compiles under `resolc` (verified); flagged because its runtime behaviour on `pallet-revive` may differ from the EVM (runtime semantics not independently confirmed) |

## What `polkavm_resolc` checks

The **class-(A)** differences the heuristics above deliberately skip — opcodes
`resolc` **rejects at compile time**. Measured against resolc 1.5.0, `EXTCODECOPY`
and `BLOBHASH` are rejected by the LLVM-IR phase ("instruction is not supported")
and become findings; `PC` is rejected earlier by `solc` itself ("disallowed in
strict assembly"), so it surfaces as an honest error, not a finding. The
`polkavm_resolc` adapter runs `resolc` and reports each IR-phase rejection as one
`polkavm-unsupported-opcode` finding (**High**, confidence 0.99): the compiler is
the oracle, so this is a confirmed deployability blocker, not a heuristic.

- **Exit 0 → no finding.** The contract compiles for PolkaVM. (This says nothing
  about class-B; that is `polkavm_diff`'s job.)
- **A rejection → one finding**, anchored to the opcode in source. `resolc` aborts
  at the *first* unsupported opcode, so the finding is worded "at least" — more may
  remain. (`resolc`'s own `L:C` is a compiler-internal offset, not a source line, so
  it is kept only in metadata.)
- **Any other compile failure** (a `solc` parse error, a rejected import) is an
  **honest error**, never a finding and never a false "clean". The `npx` wrapper
  rejects relative imports, so multi-file contracts are not reliably supported.

`polkavm_resolc` is skipped (never a false "clean") when `resolc` is unresolvable:
its availability probe checks PATH only (`resolc`, else `node` + `npx` + `solc`)
and never downloads. The `npx` on-demand path may fetch the compiler on first use.

## Compiling for PolkaVM (optional, to reproduce the target)

`polkavm_diff` is source-level and needs no toolchain. To actually compile a
contract for PolkaVM (e.g. to confirm it is a valid target):

```bash
# resolc ships as an npm package; it uses solc as its frontend
npx @parity/resolc@1.5.0 --bin -o out/ contract.sol
```

Verified with `resolc 1.5.0` and `solc 0.8.24`.

## Limitations

- **No PolkaVM (RISC-V) bytecode analysis.** Class-B is source-level heuristics;
  class-A uses the compiler's own compile-time rejection, not analysis of the
  produced `.polkavm` blob.
- **`polkavm_resolc` handles single-file contracts.** The `npx` wrapper rejects
  relative imports, so a multi-file contract surfaces as an honest error (never a
  false "clean"); when the rejected opcode is in an imported file the finding
  reports `line=0`.
- `pallet-revive` is experimental upstream and changes between releases.
- No recall/precision benchmark yet.
- The optional external analyzer **PolkaGuard** can be added as a corroboration
  tool, but it is hackathon-grade and not a dependency of this support.
