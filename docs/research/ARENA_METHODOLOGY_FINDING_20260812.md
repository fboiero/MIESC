# Arena Benchmark Methodology Finding — access-control under-measurement (2026-08-12)

## Summary

The real-world arena benchmark reported **access-control 0/3** recall. Investigation
shows this was **partly a measurement artifact, not a capability gap**: the arena
harness scored on **Slither run directly** (the deterministic static sub-layer),
not on the full `miesc scan` pipeline. The full pipeline's intelligence engine
already flags access-control that raw Slither misses.

## Evidence

Re-fetching a real arena victim and running the actual `miesc scan`:

- **landNFT** (BSC `0x1a62fe08…`, exploit: "lack of permission control on mint"):
  - Arena (Slither-only): **MISS**.
  - Full `miesc scan`: **CATCH** — `access_control_newowner_public` (Critical,
    `miesc-intelligence`). Reproduced on `origin/main` **without** the Tier-1
    wiring, i.e. the intelligence engine already carried the signal.

- LocalTrader2 and DEPUSDT/LEVUSDC could not be cleanly re-scored: address
  extraction resolved to proxy/infra contracts (Chainlink `EACAggregatorProxy`,
  a transparent proxy) rather than the vulnerable implementation. Proxy→
  implementation resolution is the open victim-identification problem; DEPUSDT
  (proxy-based) may be a genuine Tier-3 gap.

Honest bound: **≥1/3 of the arena access-control cases is caught by the full
pipeline** (not 0/3), and 2/3 are inconclusive pending proper victim-ID. This is
NOT a claim of 3/3.

## What changed (Tier-1 wiring, merged in #116)

A source-level `AccessControlSemanticDetector` was wired into `miesc scan`
(commit `7960c471`). Measured delta on SmartBugs-curated `access_control`
(academic, ground-truth):

- Recall 17/18 → **18/18** (+1: `parity_wallet_bug_1`, which every external tool
  fails to compile → recovered by the source-level detector).
- Precision cost: **+4 findings** with the 0.75 confidence gate on a 16-contract
  non-AC sample (+9 ungated). Small; the recall-safe FP-filter/confidence layer
  absorbs it.

## Recommendation

The highest-leverage fix is **not** new detectors — it is **re-scoring the arena
through `miesc scan` (full pipeline), not Slither**, mirroring the earlier
0/96 → repaired-arena correction. Doing so will likely raise access-control
(and other classes) well above the Slither-only floor. The arena harness should
invoke the shipped solution, not a single sub-layer.

Separately noted for cleanup: a prior session wired the same detector into
`miesc/core/quick_scanner.py`, which is dead code (no CLI/package importer) — it
never affected `miesc scan` and can be removed.
