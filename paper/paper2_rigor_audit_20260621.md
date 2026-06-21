# Paper 2 (Remediation) — Rigor Audit Findings (2026-06-21)

Read-only audit of `paper/paper2-remediation.tex` against
`benchmarks/results/paper2_claims_matrix.json` and underlying artifacts, using the
same methodology applied to Paper 1. **No paper files were edited** — Paper 2's
corpus-wide numbers are being actively reworked in the remediation lane (fix_eval),
so fixes are intentionally deferred to the post-rework Paper 2 baseline.

## Verdict

- **Corpus-wide patch metrics (Tables 1 & 2, taxonomy, experiment audit): fully
  BACKED.** Every value (applied 141/143, compile 90/141=64%, eliminated 93/141=66%,
  no-regression 91/141=65%, per-category, taxonomy 42+9=51) matches the matrix and
  artifacts exactly. This is the rigorous core and is internally consistent.
- **External numbers (ACFIX 94.9%, SCPatcher 81.5%, sGuard, Elysium): properly
  cited**, presented as prior work, with a cross-criterion caveat. No "external-as-own".
- **No cross-paper leakage**: the inherited Paper 1 detection figures (95.8%, 92.5%,
  120 findings, four-provider ensemble) are consistent with `paper1_claims_matrix.json`.

## Gaps to fix at the next Paper 2 baseline

| # | Gap | Location | Action |
|---|-----|----------|--------|
| A | **ORPHAN**: "only 23 of 143 (16%) produce definitive CHC results" — corpus-wide SMTChecker claim with no matrix entry and no artifact | Stage 4 ~L387, L514 | Generate an SMT/CHC results artifact + matrix entry, or downgrade to qualitative |
| B | **ORPHAN**: Stage 3 (tests 6/6/6/6), Stage 5 (compliance 4/11 MiCA…), E2E table (11 findings, HIGH 3→0, 3060 lines, <10s) all rest on `AuditTarget.sol` and `paper/evidence/paper2_e2e/` — **neither exists** | Tables 3 & 6, L314-411 | Commit the illustrative contract + an e2e evidence artifact, or label clearly as a non-reproducible single-contract walkthrough |
| C | **MISMATCH (internal)**: "18 failures to miscellaneous compiler errors" contradicts the taxonomy artifact (9) and L448/L470 | Discussion L462 | `18` → `9` (Paper-1-style .tex drift from a correct artifact) |
| D | Formatting: `3,060` (L391) vs `3060` (L409) for the same report-size figure (also unbacked) | L391, L409 | Unify + back or soften |
| E | Statistical fragility: small-n per-category rates (arithmetic 1/15, AC on n=17, other=3) without CIs/n-disclosure | Table 2 | Add n-caveats |

## CRITICAL: paper vs. live (in-flux) fix_eval data

The paper cites the **frozen/canonical** `fix_eval_results.json` (2026-05-07): applied
141, compile 90, eliminated 93, no-regression 91. The remediation lane's **in-flux**
runs (`fix_eval_full_dry_verify_20260621_codex.json`, `paper2_vnext_compile_20260621`)
tell a materially different story under changed methodology:

| Metric | Paper (canonical, May-07) | Live dry-verify (Jun-21) | Note |
|--------|---------------------------|--------------------------|------|
| fix_applied | 141 | ~122–123 | new run skips `no_high` (18) + `scan_empty` (2) |
| fix_compiles | 90 (64% of 141) | 123 (100% of applied) | **different denominator/method** — not comparable |
| vuln_eliminated | 93 (66%) | 84 (and 0 in vnext `skip_rescan`) | rescan disabled in vnext |
| arithmetic applied | 15/15 | 4/15 | scan now classifies most arithmetic as not-HIGH |

The "~28% compile regression" referenced earlier is **not found in any artifact**; the
unchecked regression probe (Jun-21) notes the prior instability **did not reproduce**
and attributes it to "scan/rescan instability or environmental contention rather than a
deterministic patcher class".

**Implication:** if the Jun-21 runs become canonical, **every corpus-wide number in
Tables 1–2, the abstract, the conclusion, and the SCPatcher comparison (64% vs 91%)
must be re-derived.** The Paper 2 baseline (paper + matrix + freeze) should be redone
in one consistent pass **after** the remediation lane finalizes fix_eval — not piecemeal.

## Recommended sequence (for Fernando / remediation lane)

1. Finalize the fix_eval rework (restore/confirm the compile path and rescan semantics).
2. Regenerate `fix_eval_results.json` + the four derived paper2 artifacts as the new canonical set.
3. Re-derive Tables 1–2 and the abstract/conclusion from the new artifacts.
4. Fix gaps A–E above in the same baseline pass.
5. Rebuild the PDF, regenerate the freeze manifest (PDF first), validate, tag, merge.
