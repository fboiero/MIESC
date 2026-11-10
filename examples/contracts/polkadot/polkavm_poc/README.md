# PolkaVM / `pallet-revive` PoC fixtures

Fixtures for the experimental Polkadot/PolkaVM support in MIESC
(`docs/plans/2026-11-10_POLKADOT_POLKAVM_POC.md`, phase F1). These are Solidity
contracts meant to be compiled with **`resolc`** (the Parity revive compiler) and
run on **`pallet-revive`** (PolkaVM / RISC-V) on Asset Hub — *not* the EVM.

License: MIT (same as MIESC's own examples). These contracts are original to this
repository.

## What they demonstrate

The audit value of PolkaVM support is the **"difference-with-EVM" layer**: code
that is correct on the EVM but insecure or semantically different on PolkaVM. Per
the revive compiler book ("Differences to EVM"), differences split into two classes:

- **Class (A) — rejected by `resolc` at compile time** (e.g. `EXTCODECOPY`, `PC`,
  `BLOBHASH`): the compiler's job, not MIESC's. See `error_cases/`.
- **Class (B) — silent runtime differences** (compile fine, behave differently):
  the real audit target. Each `vulnerable/` contract isolates one.

| Fixture | Class-(B) difference | Severity |
|---|---|---|
| `vulnerable/UnlimitedGasCall.sol` | No 63/64 gas rule → DoS forwarding all gas to untrusted callee | High |
| `vulnerable/UnboundedMemory.sol` | Fixed 128kb memory buffer → unbounded alloc traps (OutOfBound) | Medium |
| `vulnerable/Create2Address.sol` | Address derived by code hash; `creationCode` returns a hash → CREATE2 precompute wrong | Medium |
| `vulnerable/PredictableRandomness.sol` | `block.prevrandao` is a constant on PolkaVM → predictable randomness | High |
| `vulnerable/ConstructorOrder.sol` | via-ir: base ctor runs before derived state-var init → value differs vs EVM | Medium |
| `vulnerable/SelfDestructUse.sol` | `selfdestruct` compiles but its semantics differ on pallet-revive | Low |
| `clean/Counter.sol` | none — must raise no High/Critical | — |
| `error_cases/ExtCodeCopyRejected.sol` | Class (A): resolc **rejects** at compile time (documented, off scan path) | — |

Ground truth per contract is in [`expected_findings.json`](./expected_findings.json).

## Reproduce the compile status (F0/F1 gate)

All `vulnerable/` + `clean/` contracts compile; the `error_cases/` one is rejected:

```bash
# compiles (exit 0, emits a .polkavm artifact):
npx --yes @parity/resolc@1.5.0 --bin -o /tmp/out vulnerable/UnlimitedGasCall.sol

# rejected (exit 1): "The `EXTCODECOPY` instruction is not supported"
npx --yes @parity/resolc@1.5.0 --bin -o /tmp/out error_cases/ExtCodeCopyRejected.sol
```

Verified on 2026-11-11 with `resolc 1.5.0+commit.2942b3a.llvm-23.1.3` and
`solc 0.8.24`.
