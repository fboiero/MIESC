# Cairo / Starknet analysis (experimental)

MIESC analyzes Cairo (Starknet) contracts by running **Caracal** — Trail of Bits'
Sierra-level static analyzer — as a first-class adapter, correlated with a
built-in pattern analyzer. This is **experimental**: it is tool-backed (not just
patterns), but recall/precision are not yet benchmark-validated. See
[`docs/MULTICHAIN.md`](../MULTICHAIN.md) for status and limitations.

## Install Caracal

Caracal is pinned to a fork that upgrades its compiler front-end to **Cairo
2.20**, so it analyzes current Cairo. Building it compiles the Cairo compiler
from source and needs **rustc ≥ 1.94**.

```bash
cargo install --git https://github.com/adrienlacombe/caracal --profile release --force
```

Or let the bootstrap script do it (it skips gracefully if Rust is missing/old):

```bash
scripts/bootstrap_researcher_tools.sh
```

Confirm it is detected (shows version + compatibility):

```bash
miesc doctor      # see the "Cairo / Starknet (experimental)" section
```

If your `caracal` is not on `PATH`, point MIESC at it:

```bash
export CARACAL_BIN=/path/to/caracal
```

## Analyze a loose `.cairo` file

No Scarb needed — Caracal compiles the file with its bundled compiler and
embedded corelib:

```bash
miesc scan contract.cairo
miesc scan contract.cairo -o report.json          # JSON report
miesc scan contract.cairo --min-confidence 0.5    # high-signal only (drops low-confidence pattern hits)
```

## Analyze a Scarb project

Point MIESC at the directory that contains `Scarb.toml`:

```bash
miesc scan path/to/scarb_project
```

Caracal reads `scarb metadata` and then compiles the project **in-process with
its own bundled Cairo 2.20 compiler**, so any Scarb **2.x** on `PATH` works — you
do **not** need to match Scarb to Cairo 2.20. Scarb is only required for Scarb
*projects*; loose `.cairo` files need no Scarb at all.

## What runs, and how findings are scored

- **Caracal** (semantic, Sierra-level) is the primary analyzer: ~20 detectors
  (reentrancy family, `tx-origin`, controlled class-hash / deploy / replace-class,
  unprotected upgrade, L1↔L2 messaging, `felt252` arithmetic, unchecked transfer /
  return, array misuse, …).
- The built-in **pattern analyzer** (`cairo`) runs alongside as a low-confidence
  correlation pair. When both tools flag the same class in the same file, the
  finding is marked `cross_tool_corroborated` and its confidence is raised.
- Findings normalize to the MIESC schema (type, severity, confidence, CWE, OWASP,
  recommendation) and export to JSON and **SARIF 2.1.0**:

```bash
miesc scan contract.cairo -o report.json
miesc export report.json -f sarif -o report.sarif.json
```

## Honest errors

If Caracal cannot compile or run a target, MIESC reports the result as an
**error** (with the exit code and stderr) — never a silent "0 findings". A clean
contract returns 0 findings; a broken or unsupported input returns an error. When
Caracal is unavailable, the scan says so and falls back to the pattern analyzer
only, with a clear warning that a `0 findings` result is not a clean verdict.

## Known limitations

- No recall/precision numbers for Cairo yet (benchmark is grant milestone M2) —
  do not cite detection rates.
- Caracal is a maintained fork of an unmaintained upstream, capped at Cairo 2.20.
- No symbolic execution or formal verification for Cairo.
- `dead-code` is inert on Cairo 2.x (the compiler removes unreachable code before
  Sierra); `unenforced-view` is Cairo-1 only. Both are documented, not bugs.
