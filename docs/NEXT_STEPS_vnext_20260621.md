# MIESC v-next — Next Steps Checklist (2026-06-21)

> **Status: SUPERSEDED by later `main` checkpoints.** This file is retained as
> a dated handoff, not as the current source of truth. The public/current Paper
> 1 baseline remains the conservative 95.8% SmartBugs recall plus 97.9% local
> follow-up unless Fernando approves a new 99.3% baseline. The Paper 2
> remediation regression described below was later closed by Codex; see
> `benchmarks/results/fix_eval_full_external_slither_20260621_codex.json` and
> `paper/paper2_rigor_audit_20260621.md` for the current v-next evidence.

Consolidated action list after the v-next session. Everything below is the remaining
work; all autonomous/safe work is already integrated to `main`.

## Historical notes from the original handoff
- Detection v-next candidate: SmartBugs recall 0.972 -> **0.993** was measured
  as a deterministic-intelligence candidate, but it is not the current public
  baseline on `main`.
- Quality: coverage 87% → **89%** (6391 tests green); 3 real bugs fixed (RAG ImportError,
  format_instruction, result_aggregator silent-drop).
- Harness: reports external-tool crash counts per run (reproducibility).
- Security: 6/8 MED backlog items verified-fixed; Ollama exposure (MED-004) fixed; backlog
  corrected.
- Adoption: `miesc doctor` shows per-tool install commands for missing tools.
- Docs hygiene from that session: ROADMAP/CHANGELOG/CONTRIBUTING fixed, docs/
  decluttered, 5.x release notes, tool count standardized to 50. Any temporary
  99.3% non-frozen doc alignment from that branch is historical, not the current
  public baseline on `main`.

## ACTION — Fernando

### 1. Finalize Paper 1 baseline (historical branch note)
The branch had v-next content for `miesc-paper.tex`, `paper1_claims_matrix.json`,
and `README.md` around the 99.3% candidate. Treat it as stale until rebased on
the current conservative 95.8% public baseline:
```bash
cd <repo>
git checkout paper1-vnext-baseline-draft
# 1. COMMIT the 99.3% evidence artifact (benchmarks/results/ is gitignored, so force-add)
#    so the number is BACKED in-repo, then add it to the freeze manifest path list.
git add -f benchmarks/results/paper1_vnext_clean_20260621.json
# 2. Flip the governance docs on this branch to 99.3% (main keeps 95.8% until merge):
#    docs/policies/DPG-COMPLIANCE{,_ES}.md, SDG_RELEVANCE.md, DPGA CSV, ROADMAP, RELEASE_NOTES.
# 3. Rebuild the PDF, regenerate the freeze manifest (PDF FIRST), validate, tag, merge:
pdflatex -output-directory=paper paper/miesc-paper.tex   # x2-3 for refs/cite
m=.paper-freeze-local/PAPER_REPRODUCIBILITY_FREEZE.sha256
awk '{print $2}' "$m" | xargs shasum -a 256 > "$m.new" && mv "$m.new" "$m"   # PDF FIRST, then this
sh .paper-freeze-local/validate_paper_reproducibility_freeze.sh
git tag -a paper-reproducibility-baseline-2026-06-21 -m "Paper 1 v-next: recall 99.3%"
git checkout main && git merge --no-ff paper1-vnext-baseline-draft
git -c pack.threads=1 -c pack.windowMemory=32m -c pack.packSizeLimit=64m push origin main --tags
```
> Rigor note: until the merge, MAIN deliberately states 95.8% (backed by
> `paper1_smartbugs_eval_layers_1_6_7.json`) everywhere; 99.3% lives only on this branch
> and flips in atomically at merge. Don't put 99.3% on main before step 1 lands the artifact.

### 2. DPGA review
The historical branch aligned DPGA docs to the 99.3% candidate. On current
`main`, DPGA-facing claims should remain aligned to the conservative public
baseline unless Fernando opens a new Paper 1 baseline.
Advance the DPGA review / respond to any reviewer observations.

### 3. Decisions still open
- Tool count: standardized on **50** (verified in LAYERS); confirm this is the intended
  marketing number (alternative was the paper's 35 "analysis modules").
- Optional: embed `demo/miesc-demo.cast` (asciinema) in the README for a live demo.

## ACTION — Codex (Paper 2 / remediation lane)
Superseded: Codex later restored the compile path and added independent Slither
external validation as dated, noncanonical v-next evidence. The remaining action
is Fernando-gated: either keep the frozen 141/90/93/91 Paper 2 baseline, or open
a new baseline and re-derive the paper from
`fix_eval_full_external_slither_20260621_codex.json`.

## Known remaining (low-tractability, documented)
- MED-003 (curl-to-shell hash): rustup/foundry installers are rolling; TLS-mitigated.
- MED-005 (base-image digest pin): tag-pinned; digest pin adds maintenance burden.
- Tool-crash variance (aderyn/slither on legacy AST): external; harness now reports counts.
