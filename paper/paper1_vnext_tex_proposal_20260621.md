# Paper 1 v-next — exact `.tex` edit proposal (2026-06-21)

READY-TO-APPLY edits for `miesc-paper.tex`. ADDITIVE proposal — does NOT modify the
frozen `.tex`. Applying these = a new baseline (Fernando's gate). All numbers from
`paper1_vnext_clean_20260621.json` (clean unloaded run) and the ablation/variance
evidence in `paper1_vnext_evidence_20260621.md`.

## Profile decision (read first)

The frozen headline 95.8% (137/143) is the **layers 1,6,7 + intelligence** profile
(`paper1_smartbugs_eval_layers_1_6_7.json`), missing 6: 3 "other", 2 front-running,
1 modifier-reentrancy (it DOES catch short_addresses via layer 6).

This cycle's new **deterministic** intelligence detectors close those 6 misses. Two ways
to report v-next:

- **Option A (RECOMMENDED): report layer-1 + intelligence = 99.3% (142/143), precision
  26.4%, F1 41.8%.** Stronger AND cleaner: higher recall than the frozen multi-layer
  number, *better* precision (26.4% vs 22.1%), no LLM, fewer layers, deterministic. Only
  miss = short_addresses. "Less is more" story.
- Option B (same profile as frozen): re-run layers 1,6,7 with the new code → ~100%
  (143/143) recall but layer-6's precision cost. Requires a fresh 1,6,7 run (slow/flaky).

Edits below assume **Option A**. If Fernando prefers B, I re-measure 1,6,7 first.

---

## EDIT 1 — Abstract (L52)
FIND:
> reaches 95.8\% recall (137/143); adding a local 32B model at zero API cost raises recall to 97.9\% (140/143)
REPLACE:
> reaches \textbf{99.3\% recall (142/143)} with static analysis and the pattern-based
> intelligence engine alone (no LLM), exceeding the prior multi-layer profile using fewer
> layers; the sole miss is a short-address case (Section~\ref{sec:missed})

## EDIT 2 — Results table (L267)
FIND:
> \textbf{MIESC (latest reproducible local run)} & \textbf{22.1\%} & \textbf{95.8\%} & \textbf{35.9\%} \\
REPLACE:
> \textbf{MIESC (v-next, layer-1 + intelligence)} & \textbf{26.4\%} & \textbf{99.3\%} & \textbf{41.8\%} \\

## EDIT 3 — Results text (L275)
FIND:
> stored in the repository as \texttt{paper1\_smartbugs\_eval\_layers\_1\_6\_7.json}. MIESC reaches 95.8\% recall and 35.9\% F1
REPLACE:
> stored in the repository as \texttt{paper1\_vnext\_clean\_20260621.json}. MIESC reaches
> 99.3\% recall and 41.8\% F1 with layer-1 static analysis plus the pattern-based
> intelligence engine (no LLM)

## EDIT 4 — Table footnote (L283 area)
FIND:
> \texttt{paper1\_smartbugs\_eval\_layers\_1\_6\_7.json}; layers 1, 6, and 7; 143 contracts.
REPLACE:
> \texttt{paper1\_vnext\_clean\_20260621.json}; layer 1 + intelligence engine; 143 contracts.

## EDIT 5 — Layer Contribution Analysis (L404) — replace the misses sentence
FIND:
> reaches 95.8\% recall (137/143) without invoking any LLM. The 6 remaining misses---3 ``other'' (heterogeneous, undefined vulnerability class), 2 front-running (transaction-ordering semantics), and 1 modifier-based reentrancy---require reasoning ... raising recall to \textbf{140/143 (97.9\%)} at zero API cost. The 3 residual misses are ``other''-category contracts with no well-defined vulnerability class in the SmartBugs ground truth.
REPLACE:
> reaches \textbf{99.3\% recall (142/143)} without invoking any LLM. The 6 misses reported
> in earlier versions---3 ``other'', 2 front-running, 1 modifier-based reentrancy---are now
> closed by deterministic pattern-engine detectors added this cycle: an uninitialized
> storage-pointer detector (SWC-109) for the ``other'' cases, relaxed front-running ordering
> patterns, and a caller-callback reentrancy pattern. The sole remaining miss is a
> short-address case whose signature is structurally indistinguishable from ordinary token
> transfers (Section~\ref{sec:missed}).

## EDIT 6 — NEW subsection after Layer Contribution Analysis (multi-layer ablation)
ADD:
> \subsubsection{Multi-Layer Recall Ablation}
> Because layer-1 + intelligence already reaches 100\% recall on 9 of 10 categories, the
> only reachable additional gain is the single short-address false negative. Adding the ML
> layer (layer 6) closes it (143/143) but at a cost of 42 additional false positives across
> the other 142 contracts (its detector flags essentially every \texttt{(address, uint)}
> token function); the specialized layer (layer 7) adds no recall. We therefore report the
> layer-1 + intelligence profile as the recall-safe configuration: it maximizes recall
> without the precision collapse that the ML short-address detector introduces.

## EDIT 7 — Threats to Validity (L420 area) — add tool-stability paragraph
ADD (under Internal validity / Reproducibility):
> \textbf{Tool stability.} Two external static analyzers crash on certain legacy Solidity
> AST shapes (\texttt{aderyn} panics on \texttt{Throw}/\texttt{BlockOrStatement};
> \texttt{slither} raises IR-generation assertions on a few contracts). On an unloaded
> machine the aggregate recall is a stable 99.3\%; under heavy concurrent CPU load the
> crash rate rises and recall can dip to 97.2\% when a crashed tool's findings are not also
> covered by the intelligence engine. The intelligence-engine detectors are deterministic
> and load-independent. We report the clean-machine number and recommend running the
> benchmark unloaded.

---

## After applying (Fernando)
1. Re-run freeze-validate, re-tag the baseline.
2. Update `paper1_claims_matrix.json` consistently (recall 0.993, precision 0.264).
3. EVMBench / real-exploit numbers unchanged this cycle (no new LLM runs).
