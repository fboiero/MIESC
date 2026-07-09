# SDD: EIP-1153 Transient Storage Detection

Date: 2026-07-09
Owner lane: Codex
Status: implemented and wired into the SmartBugs detector adapter

## 1. Signal

Recent Solidity and EVM changes added a new bug surface that MIESC did not
explicitly model: EIP-1153 transient storage through `TLOAD`, `TSTORE`, and
Solidity `transient` state variables.

The security-relevant change is not simply "new storage syntax". It changes
old reentrancy assumptions:

- EIP-1153 defines transaction-scoped storage that is discarded at transaction
  end and notes that `TSTORE` is not subject to the same gas stipend check as
  `SSTORE`.
- ChainSecurity documented a low-gas reentrancy class where `transfer()` and
  `send()` no longer provide the old 2300-gas storage-write boundary when the
  re-entered path can use transient storage.
- Dedaub observed real-world EIP-1153 usage after Cancun, especially inline
  assembly `TSTORE`/`TLOAD`, and called out the higher risk while usage is still
  early.
- Solidity 0.8.28 added full support for transient storage state variables of
  value types, making source-level `transient` syntax relevant for scanners.

## 2. Spec

Add a detector that flags Solidity functions where transient storage interacts
with external control flow.

Detection inputs:

- Inline assembly `tstore(...)` or `tload(...)`.
- Solidity source syntax containing the `transient` qualifier.
- External calls: `.call`, `.delegatecall`, `.staticcall`, `.transfer`,
  `.send`, and Yul `call(...)`.
- Low-gas assumptions: `.transfer(...)`, `.send(...)`, `gas: 2300`, or Yul
  `call(..., 2300, ...)`.
- Lock cleanup evidence: `tstore(slot, 0)`, `tstore(slot, false)`, `delete lock`,
  or assignment to `false`/`0` for source-level transient variables.

Expected findings:

- `transient-low-gas-reentrancy`, severity high:
  transient storage appears in a function that performs `transfer`, `send`, or
  another explicit 2300-gas call.
- `transient-lock-not-cleared`, severity medium:
  a transient lock-like value is set before/around an external call without an
  obvious clear in the same function.
- `transient-external-call-review`, severity medium:
  transient storage and external calls coexist but cleanup is visible or the
  exact lock semantics are not proven.
- `transient-storage-review`, severity low:
  transient storage is used without an external call; review lifetime intent.

Non-goals for this checkpoint:

- Full Solidity AST integration.
- Whole-program call graph expansion.
- Slither IR integration.
- Claiming benchmark uplift before running a controlled benchmark.

## 3. Design

The first implementation is a pure static detector under
`src/detectors/transient_storage_detector.py`.

It uses the existing `BaseDetector` and `Finding` API, not a separate output
schema. It masks comments and string literals before pattern matching to reduce
cheap false positives, then scans balanced Solidity function bodies so findings
can point to a function-level location.

This is deliberately additive:

- No changes to frozen paper artifacts.
- No changes to canonical benchmark outputs.
- The SmartBugs adapter now runs this detector as a complementary generic
  detector and normalizes both `SmartBugsFinding` and detector API `Finding`
  objects into the existing MIESC finding schema.

## 4. Validation

Focused tests added in `tests/test_transient_storage_detector.py` cover:

- high severity for `tstore` plus `.transfer`;
- high severity for `tstore` plus `.send`;
- high severity for explicit `gas: 2300`;
- medium severity for missing transient lock cleanup around `.call`;
- downgrade to review when cleanup is visible;
- Solidity `transient` keyword handling with `delete`;
- low severity review when no external call exists;
- comment and string masking;
- empty/non-string boundaries;
- wrapper API and line mapping.

Required commands for this checkpoint:

```bash
pytest tests/test_transient_storage_detector.py -q
ruff check src/detectors/transient_storage_detector.py tests/test_transient_storage_detector.py
```

## 5. Integration Plan

Implemented integration:

1. `SmartBugsDetectorAdapter.analyze()` now adds transient storage findings for
   file scans.
2. `SmartBugsDetectorAdapter.analyze_source()` now adds transient storage
   findings for source-string scans.
3. The adapter conversion path normalizes category, severity, location,
   references, recommendation, and metadata for both legacy SmartBugs findings
   and generic detector API findings.
4. Focused adapter tests prove the finding survives file/source conversion and
   summary generation.

Next bounded SDD step:

1. Run a small non-canonical benchmark slice and record results under a dated,
   Codex-specific filename only.
2. Add a fixture contract with Solidity 0.8.28 `transient` state-variable syntax
   if the benchmark corpus needs fixture-driven evidence.

## 6. References

- EIP-1153: https://eips.ethereum.org/EIPS/eip-1153
- ChainSecurity, TSTORE Low Gas Reentrancy:
  https://www.chainsecurity.com/blog/tstore-low-gas-reentrancy
- Dedaub, Transient Storage in the Wild:
  https://dedaub.com/blog/transient-storage-in-the-wild-an-impact-study-on-eip-1153/
- Solidity 0.8.28 Release Announcement:
  https://www.soliditylang.org/blog/2024/10/09/solidity-0.8.28-release-announcement/
