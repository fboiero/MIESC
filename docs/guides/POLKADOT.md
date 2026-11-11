# Polkadot / PolkaVM support (Experimental)

MIESC can audit Solidity contracts targeting **PolkaVM / `pallet-revive`** — the
smart-contract engine on Polkadot's Asset Hub, where Solidity is compiled with
**`resolc`** to PolkaVM (RISC-V) bytecode rather than the EVM.

> **Experimental.** Source-level only, not yet benchmark-validated. Not for
> production security decisions. See [`../MULTICHAIN.md`](../MULTICHAIN.md).

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
Aderyn, Solhint) plus the built-in **`polkavm_diff`** checks, and **skips** EVM
bytecode / symbolic / fuzzing tools (Mythril, Manticore, Echidna, …) — the
compiled target is RISC-V, not EVM, so those do not apply. Without the flag, the
normal EVM path is used unchanged.

## What `polkavm_diff` checks

These are **class-(B) "silent runtime differences"** from the
[revive compiler book](https://paritytech.github.io/revive/user_guide/differences.html):
code that compiles under `resolc` and is correct on the EVM, but is insecure or
behaves differently on PolkaVM. (Class-(A) differences — `EXTCODECOPY`, `PC`,
`BLOBHASH` … — are rejected by `resolc` at compile time, so they are the
compiler's job, not MIESC's.)

| Check | Difference |
|---|---|
| `polkavm-unlimited-gas-call` | No 63/64 gas rule on PolkaVM → forwarding all gas to an untrusted callee is a DoS vector |
| `polkavm-unbounded-memory` | Fixed 128kb memory buffer → unbounded allocation traps at runtime |
| `polkavm-create2-address-assumption` | Addresses derive from the code hash; `creationCode` returns a hash → EVM `CREATE2` precomputation breaks |
| `polkavm-predictable-prevrandao` | `block.prevrandao` / `difficulty` is a constant on PolkaVM → predictable randomness |
| `polkavm-constructor-init-order` | Under via-ir, base constructors run before derived state-variable initializers |
| `polkavm-selfdestruct-semantics` | `selfdestruct` compiles but its semantics differ from the EVM |

## Compiling for PolkaVM (optional, to reproduce the target)

`polkavm_diff` is source-level and needs no toolchain. To actually compile a
contract for PolkaVM (e.g. to confirm it is a valid target):

```bash
# resolc ships as an npm package; it uses solc as its frontend
npx @parity/resolc@1.5.0 --bin -o out/ contract.sol
```

Verified with `resolc 1.5.0` and `solc 0.8.24`.

## Limitations

- **Source-level only** — no PolkaVM (RISC-V) bytecode analysis.
- `pallet-revive` is experimental upstream and changes between releases.
- No recall/precision benchmark yet.
- The optional external analyzer **PolkaGuard** can be added as a corroboration
  tool, but it is hackathon-grade and not a dependency of this support.
