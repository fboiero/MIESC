# Paper 2 v-next — Remediation Evidence (2026-06-21)

ADDITIVE dated measurement. Does NOT modify the frozen `paper2-remediation.tex`, PDF, or
canonical artifacts, and does NOT modify the remediation source (Codex lane). Measurement
only, to give Codex/Fernando the current baseline.

Reproduce: `python3 benchmarks/fix_eval.py --skip-rescan` on SmartBugs-curated.
Artifact: `benchmarks/results/paper2_vnext_compile_20260621.json`.

## ⚠️ CRITICAL: compile-rate REGRESSION vs frozen Paper 2

| Metric | Frozen Paper 2 | Current code (2026-06-21) |
|--------|----------------|----------------------------|
| Compilation rate | **64%** | **28% (33/119)** |

The current `miesc fix` patcher compiles **less than half** of what the frozen Paper 2
reports. Paper 2 v-next CANNOT claim improvement until this is restored — first priority
is to **recover the patcher**, not to add new numbers.

### Per-category compile (current, --skip-rescan)
| Category | applied | compiles |
|----------|---------|----------|
| access_control | 16 | 9 |
| reentrancy | 30 | 8 |
| unchecked_low_level_calls | 47 | 11 |
| front_running | 4 | 2 |
| arithmetic | 5 | 1 |
| bad_randomness | 7 | 1 |
| denial_of_service | 3 | 1 |
| time_manipulation | 3 | 0 |
| other | 3 | 0 |
| short_addresses | 1 | 0 |
| **TOTAL** | **119** | **33 (28%)** |

(eliminated/no-regression not measured here — `--skip-rescan`.)

## Root-cause hypothesis (for Codex)
Regression most likely from removing the inline SafeMath / guard injection (the patcher
emits fixes that reference symbols no longer in scope → `undeclared identifier` /
`undefined symbol` compile failures). The fix is a **self-contained patcher**: inline the
guards/imports it depends on so each patched contract compiles standalone.

## Codex lane — required before Paper 2 v-next
1. **Restore + harden patcher → self-contained** (recover ≥64% compile, target higher).
2. **Independent verification** (Slither/SMTChecker/Foundry on patched-that-compile) to
   kill the re-scan circularity (threat #2) — the central validity improvement.
3. Re-run `fix_eval` (full, with rescan) for the real eliminate/no-regression numbers.

`.tex` sections (when Fernando approves baseline): §Stage 2 Patch Quality, §Compilation
Rate Analysis, §Limitations of Text-Level Patching.
