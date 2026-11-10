# Attribution — Cairo/Caracal PoC fixtures

The vulnerable Cairo contracts under `vulnerable/` are **reused from the Caracal
detector test suite** and carry its license and authorship:

- Upstream: [crytic/caracal](https://github.com/crytic/caracal) — Trail of Bits.
- Cairo 2.20.0 fork used here: [adrienlacombe/caracal](https://github.com/adrienlacombe/caracal)
  (v0.3.0), which upgraded the compiler 2.5.0 → 2.20.0 and restored/added detectors.
- License: **MIT** (SPDX: `MIT`), per the upstream project.

These files are included unmodified as analysis fixtures (they are *inputs* to the
analyzer, never executed). `clean/counter_clean.cairo` is original to MIESC and is
the negative fixture (expected: zero findings).

Ground-truth findings for each fixture are recorded in `expected_findings.json`,
captured with `caracal detect --format json`. Raw per-fixture analyzer output is
stored under `tests/fixtures/caracal/`.
