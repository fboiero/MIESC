# Paper 1 v-next — Detection Evidence (2026-06-21)

ADDITIVE dated evidence for a potential Paper 1 new baseline. Does NOT modify the
frozen `miesc-paper.tex`, PDF, or canonical artifacts. Baseline change requires
Fernando's explicit approval.

Reproduce: `python3 scripts/precision_check.py --run --layers 1` on
`benchmarks/datasets/smartbugs-curated/dataset` (143 contracts, 10 categories).

## 1. Headline improvement (vs frozen v5.4.0)

| Profile | Frozen Paper 1 (v5.4.0, 2026-05-06) | v-next (2026-06-21, measured) |
|---------|--------------------------------------|-------------------------------|
| static + intelligence, layer 1 | 95.8% recall (137/143) | **99.3% recall (142/143)** |

Cause (recall-safe, ΔFP=0, harness-gated): two new intelligence detectors added this
cycle —
- `front_running`: 2/4 → 4/4 (implicit-visibility ordering + reward-transfer patterns)
- `uninitialized_storage_pointer` (`other` category): 0/3 → 3/3 (SWC-109; struct-typed
  local without explicit data location = storage pointer at slot 0)

## 2. Per-category recall (layer 1, v-next)

| Category | Recall |
|----------|--------|
| access_control | 18/18 (1.00) |
| arithmetic | 15/15 (1.00) |
| bad_randomness | 8/8 (1.00) |
| denial_of_service | 6/6 (1.00) |
| front_running | 4/4 (1.00) |
| other | 3/3 (1.00) |
| reentrancy | 31/31 (1.00) |
| time_manipulation | 5/5 (1.00) |
| unchecked_low_level_calls | 52/52 (1.00) |
| short_addresses | 0/1 (0.00) |

**9 of 10 categories at 100% recall.** Aggregate: recall 0.993, precision ~0.26
(static-tool noise; the safe precision floor — further FP suppression measured to drop
recall).

## 3. Multi-layer recall ablation (NEW — for §Layer Contribution Analysis)

Question: do the offline ML (layer 6) and specialized (layer 7) layers raise recall
over static+intelligence (layer 1)?

| Config | Recall | Cost |
|--------|--------|------|
| Layer 1 (static + intelligence) | **0.993** (142/143) | safe ceiling |
| + Layer 6 (ML: smartbugs_detector) | 1.000 (143/143) | **+42 false positives / +1 TP** |
| + Layer 7 (specialized) | 0.993 (no change) | adds no recall |

Layer 1 already reaches 100% on 9/10 categories, so the only reachable gain is the single
`short_addresses` FN. Layer 6's ShortAddressDetector closes it but flags ~every
`function(address, uint)` token contract (42 FP across the 142 non-short_addresses
contracts). **Conclusion: layer 1 is the recall-safe configuration; the precision/recall
tradeoff makes layer 6 unjustified for the default profile.**

## 4. Missed exploit (for §Analysis of Missed Exploits)

`short_addresses` (1 contract) is the sole layer-1 FN and a **measured structural limit**:
the single labeled example is indistinguishable from 42 other `(address, uint)` token
contracts, so no precise pattern separates them (1 TP / 5 FP for a tight pattern; 1 TP /
42 FP for the ML detector). Honest threat-to-validity, not a tuning gap.

## Status
Evidence ready. `.tex` edits (new baseline) pending Fernando's approval. Remediation
(Paper 2) numbers are Codex's lane.
