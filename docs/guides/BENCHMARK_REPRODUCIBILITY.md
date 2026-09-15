# Benchmark Reproducibility: the Unloaded-Machine Protocol

Why this exists: two external static tools MIESC shells out to in Layer 1 —
`aderyn` (Rust) and `slither` — crash on certain Solidity AST shapes under CPU
contention, and a crash silently drops that tool's findings for the affected
contract. When the intelligence engine doesn't independently cover the same
category, recall on the SmartBugs-curated corpus measurably drops. This has
already been observed directly:

| Run condition | aderyn crashes (of 143) | Aggregate recall |
|---|---|---|
| Unloaded machine | 36 | **0.993** (142/143) |
| Concurrent CPU load | up to 66 | 0.972 (139/143) |

(Source: `paper/paper1_vnext_evidence_20260621.md` §5.) The gap is not a bug in
MIESC's detectors — the intelligence-engine gains (`front_running`,
`uninitialized_storage_pointer`) are deterministic and reproduce every run
regardless of tool crashes. It's measurement noise from a flaky dependency,
and it's large enough (2 percentage points of recall) to change which number
gets reported. This protocol makes "unloaded" a checkable precondition
instead of an unverifiable claim.

---

## 1. Before you run: confirm the machine is actually unloaded

"Unloaded" means: no other process is competing for CPU while the benchmark
runs. Check, don't assume:

```bash
uptime          # look at the 1-minute load average
nproc           # number of logical cores
```

The 1-minute load average should be **below `nproc`** immediately before
starting the run. If it isn't, something else is using the CPU — find it
(`top`/`htop`) and either stop it or wait.

Also close/pause anything that predictably spikes CPU in bursts: another
MIESC scan, a second `slither`/`aderyn` invocation, a local Ollama model
generating, a test suite running in another terminal, a build/compile job.

## 2. Run with crash counting on

`scripts/precision_check.py --run` streams the underlying `miesc evaluate
corpus` output and regex-matches it for the two known crash signatures live,
printing a summary line at the end:

```bash
python scripts/precision_check.py --run --layers 1
# ...
# tool stability: aderyn_crashes=N slither_crashes=M (higher under CPU load — run unloaded for the authoritative number)
```

**Scope note:** this crash-counting is currently wired into
`precision_check.py` only, which runs layer 1 (the fast iteration loop for
FP/recall tuning). It is not built into `miesc evaluate corpus` directly, so
a full multi-layer run (e.g. the paper's `--layers 1,6,7` profile) does not
print a crash count today — if you need one for a multi-layer run, capture
stdout the same way `_run_eval()` in `precision_check.py` does, or extend
that counting into `evaluate.py` if this becomes a recurring need.

## 3. Report the crash count alongside the recall number

A recall number without its crash count is not reproducible — a reader can't
tell whether it's the clean-run figure or a degraded one. When recording a
benchmark result for the paper or an evidence doc, include the tool-stability
line next to the metrics, the way `paper1_vnext_evidence_20260621.md` §5
does. As a rule of thumb from the one measured comparison above: an unloaded
layer-1 run over the 143-contract SmartBugs-curated corpus should land in the
**30s of aderyn crashes**, not the 60s — if you see crash counts noticeably
higher than that on a fresh run, treat the machine as loaded, re-check `top`,
and re-run before reporting the number as canonical.

## 4. If you can't get a clean run

Some environments (shared CI runners, laptops with background sync/indexing)
never settle below `nproc` load. In that case:

- Run the benchmark 2–3 times and report the **range**, not a single number
  (as §5 of the v-next evidence doc already does: 0.972–0.993).
- Do not cherry-pick the best of several runs as "the" number — report
  whichever run has the *lowest* crash count you observed, and say so.
- Prefer running late at night or on a machine with nothing else scheduled
  over trying to average out the noise statistically; the crash mechanism is
  a hard failure per contract, not a smooth distribution.

## References

- `paper/paper1_vnext_evidence_20260621.md` §5 — the measured clean-vs-loaded
  comparison this protocol is built on.
- `scripts/precision_check.py` — the crash-counting harness (`_run_eval()`).
- `paper/PAPER1_REPRODUCIBILITY.md` — full command reference for reproducing
  the canonical Paper 1 artifacts.
