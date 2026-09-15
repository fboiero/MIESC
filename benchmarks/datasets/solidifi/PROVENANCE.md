# SolidiFI — Provenance & Ground Truth Methodology

Bug-injection corpus, complementary to `../solodit-real/` and `../vyper-real/`. Those
two are real audited protocols with real audit findings as ground truth — high
realism, but not reproducible (a different curator picks different findings) and
not comparable release-over-release (the corpus itself changes as new protocols get
added). This one is the opposite trade: synthetic, but a fixed, third-party,
citable ground truth that never moves — the same 350 contracts score the same way
every time, so a precision/recall number here is reproducible by anyone, unlike a
number computed only against curated real-audit findings.

## Upstream source

Vendored from https://github.com/DependableSystemsLab/SolidiFI-benchmark (master,
pulled 2026-09-01). SolidiFI (ICSE 2020) takes clean, real-world contracts and
injects known-location bugs of 7 SWC-style categories via automated code
transformation, recording the exact injected `(line, length, bug_type)` in a
`BugLog_<n>.csv` per contract — 50 contracts × 7 categories = 350 total.

## Directory layout

Re-mapped from SolidiFI's own category names to MIESC's canonical taxonomy
(`SMARTBUGS_CATEGORIES` in `miesc/cli/commands/evaluate.py`), so `miesc evaluate
corpus benchmarks/datasets/solidifi` works with the same folder-name-is-category
loader (`_load_ground_truth`) already used for `smartbugs-curated` — no ground_truth.json,
no new code:

| MIESC folder | SolidiFI category | Contracts |
|---|---|---|
| `reentrancy/` | Re-entrancy | 50 |
| `arithmetic/` | Overflow-Underflow | 50 |
| `front_running/` | TOD (transaction-order dependence) | 50 |
| `time_manipulation/` | Timestamp-Dependency | 50 |
| `access_control/` | tx.origin | 50 |
| `unchecked_low_level_calls/` | Unchecked-Send + Unhandled-Exceptions (merged — same canonical category, files prefixed `unchecked_send_*` / `unhandled_exceptions_*` to avoid the identical `buggy_<n>.sol` filenames colliding) | 100 |

Total: 350 contracts, matching the upstream count exactly (verified by count, not
assumed).

Each `.sol` ships with its original `BugLog_<n>.csv` (renamed to match, for the
merged category) — **not read by `evaluate corpus` today** (that pipeline only
does file+category matching, same as every other corpus here), but kept for a
future line-precision benchmark: the CSV has the exact injected `(line, length)`
per bug, so it could score line-level TP/FN instead of just per-file/category.

## Known limitations (stated, not hidden)

- **Category-mapping judgment calls**: `tx.origin` → `access_control` and `TOD` →
  `front_running` are reasonable but not literal renames — SolidiFI's own category
  names don't exist in MIESC's taxonomy. Same call a since-deleted v4.6/4.7
  standalone script (`benchmarks/solidifi_benchmark.py`, broken by the `src/` →
  `miesc/` unification and removed 2026-09-01) made with its own
  `CATEGORY_TO_VULN_TYPES`.
- **No coverage for `denial_of_service`, `bad_randomness`, `short_addresses`** —
  SolidiFI has no injection category for these, so this corpus cannot move the
  0%-recall categories already tracked in the private roadmap; it only helps the
  5 categories above.
- **Injected bugs, not organic ones**: a detector tuned to spot SolidiFI's specific
  injection pattern could overfit to this corpus without generalizing — treat a
  good SolidiFI score as a floor, not a substitute for the real-audit corpora.
- **`BugLog_*.csv`'s `bug type` column is mojibake** (upstream encodes it in
  modified UTF-7, e.g. `Re+AC0-erntrancy` for `Re-entrancy`) — harmless here since
  category comes from the folder name, not that column, but don't parse that
  column without decoding it first if the line-precision follow-up gets built.
